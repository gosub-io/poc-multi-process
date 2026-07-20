//! The engine: an event loop that owns the cookie jar and all policy, spawns
//! the net component and per-origin renderers, and brokers every privileged
//! operation. This is the `GosubEngine (parent)` box from issue #1080's
//! diagram, shaped like the real gosub engine: commands in via an
//! [`EngineHandle`], events out via a channel.
//!
//! ```text
//!  EngineHandle ── EngineCommand ──▶ ┌────────────┐ ──▶ EngineEvent
//!                                    │ event loop │
//!  renderer/net reader threads ────▶ └────────────┘ ──▶ replies to components
//! ```
//!
//! Every message source (user commands, each renderer, the net component)
//! is funneled into one inbox by cheap reader threads, so the loop itself is
//! single-threaded and processes one message at a time — the std-only
//! equivalent of the real engine's `tokio::select!` worker loop.
//!
//! Components run in one of two modes:
//! - `Mode::Multi`  — separate sandboxable processes (issue #1080)
//! - `Mode::Single` — threads in this process (classic engine)
//!
//! The broker protocol and all policy checks are identical in both modes;
//! only the transport and the spawning differ. What single-process mode
//! cannot offer is the hard boundary: a compromised renderer *thread* shares
//! this address space, so the policy checks are only a real barrier when a
//! process boundary stands behind them.

use crate::events::{EngineCommand, EngineEvent, TabCommand, TabId, Tile, TilePixels, ZoneId};
use crate::ipc::{
    self, Endpoint, EndpointTx, FetchOutcome, FromRenderer, NetRequest, NetResponse, ToRenderer,
};
use crate::{net_daemon, renderer};
use std::collections::HashMap;
use std::io;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Condvar, Mutex};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    Single,
    #[cfg(feature = "multi-process")]
    Multi,
}

/// Control interface for a running engine (the PoC's `TabHandle`/engine
/// handle equivalent). Cloneable; commands are answered by [`EngineEvent`]s
/// on the receiver returned from [`start`].
#[derive(Clone)]
pub struct EngineHandle {
    inbox: Sender<LoopMsg>,
}

impl EngineHandle {
    pub fn send(&self, cmd: EngineCommand) -> io::Result<()> {
        self.inbox
            .send(LoopMsg::Command(cmd))
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "engine loop gone"))
    }

    pub fn open_tab(&self, zone: ZoneId, url: impl Into<String>) -> io::Result<()> {
        self.send(EngineCommand::OpenTab { zone, url: url.into() })
    }

    pub fn navigate(&self, tab_id: TabId, url: impl Into<String>) -> io::Result<()> {
        self.send(EngineCommand::Tab { tab_id, cmd: TabCommand::Navigate { url: url.into() } })
    }

    pub fn close_tab(&self, tab_id: TabId) -> io::Result<()> {
        self.send(EngineCommand::Tab { tab_id, cmd: TabCommand::Close })
    }

    pub fn set_cookie(
        &self,
        zone: ZoneId,
        origin: impl Into<String>,
        name: impl Into<String>,
        value: impl Into<String>,
        http_only: bool,
    ) -> io::Result<()> {
        self.send(EngineCommand::SetCookie {
            zone,
            origin: origin.into(),
            name: name.into(),
            value: value.into(),
            http_only,
        })
    }

    pub fn shutdown(&self) -> io::Result<()> {
        self.send(EngineCommand::Shutdown)
    }
}

/// Start an engine in the given mode. Returns the command handle and the
/// event stream; the event loop runs on its own thread until
/// [`EngineCommand::Shutdown`].
pub fn start(mode: Mode) -> (EngineHandle, Receiver<EngineEvent>) {
    // The engine is the highest-value target on the machine: it is the only
    // process holding the cookie jar. Do this before the loop starts, and so
    // before any jar is loaded, so the secrets are never in a readable process.
    crate::sandbox::deny_debugger_attach();
    let (inbox_tx, inbox_rx) = mpsc::channel();
    let (event_tx, event_rx) = mpsc::channel();
    let handle = EngineHandle { inbox: inbox_tx.clone() };
    std::thread::spawn(move || EngineLoop::new(mode, inbox_tx, event_tx).run(inbox_rx));
    (handle, event_rx)
}

/// Everything that can wake the event loop, from any source.
enum LoopMsg {
    /// A command from an [`EngineHandle`].
    Command(EngineCommand),
    /// A renderer sent a message (forwarded by its reader thread).
    FromTab { tab_id: TabId, msg: FromRenderer },
    /// A renderer delivered a tile via shared memory; its reader thread
    /// already received the fd, validated it (seals + real size) and mapped
    /// it, so what reaches the loop is a ready, immutable tile.
    #[cfg(all(feature = "multi-process", target_os = "linux"))]
    ShmTile { tab_id: TabId, tile: Tile },
    /// A renderer's link died without a shutdown — crash, most likely.
    TabGone { tab_id: TabId },
    /// The net component answered a fetch.
    NetReply(NetResponse),
    /// The net component answered a fetch with a *streamed* body: the header
    /// to route, plus the ring fd (already received by the net reader thread)
    /// to forward to the requesting renderer. The engine never maps the ring.
    #[cfg(all(feature = "multi-process", target_os = "linux"))]
    NetStream { resp: NetResponse, fd: std::os::fd::OwnedFd },
}

/// A running child component, however it is hosted.
enum ChildHandle {
    Thread(std::thread::JoinHandle<()>),
    #[cfg(feature = "multi-process")]
    Process(std::process::Child),
    /// A renderer `fork()`ed by the fork server, which owns and reaps it. The
    /// engine has no `Child` for it; it detects death via IPC-socket EOF.
    #[cfg(all(feature = "multi-process", target_os = "linux"))]
    ForkServed,
}

/// Per-tab cap on outstanding brokered fetches. Bounds the engine memory a
/// single (possibly compromised) renderer can pin by spamming `NeedFetch`
/// without waiting for replies. The 16 MiB frame cap only bounds one message;
/// this bounds how many can be in flight at once.
const MAX_INFLIGHT_FETCHES: usize = 32;

/// Per-source cap on messages queued-but-unprocessed in the shared inbox. All
/// sources funnel into one inbox, so without this a single renderer flooding
/// *any* message type would grow it without bound. See [`Gate`].
const MAX_QUEUED_PER_SOURCE: usize = 64;

/// A tiny counting semaphore with a terminal `close`, giving each message
/// source (a renderer, or the net component) its own bounded slice of the
/// shared inbox. A source's reader thread must `acquire` a permit before
/// forwarding a message, and the event loop `release`s one after handling it.
/// When a source's permits run out its reader blocks — it stops draining that
/// component's socket, so the OS backpressures the component itself. So one
/// compromised renderer can pin at most `MAX_QUEUED_PER_SOURCE` messages of
/// engine memory and, because the bound is per-source rather than a shared
/// queue limit, it cannot crowd the inbox against other tabs or the net
/// component. This is the std-only stand-in for the real engine's per-channel
/// bounded async queues.
struct Gate {
    state: Mutex<GateState>,
    ready: Condvar,
}

struct GateState {
    permits: usize,
    closed: bool,
}

impl Gate {
    fn new(cap: usize) -> Arc<Gate> {
        Arc::new(Gate {
            state: Mutex::new(GateState { permits: cap, closed: false }),
            ready: Condvar::new(),
        })
    }

    /// Take a permit, blocking while none are free. Returns `false` if the gate
    /// was closed (its tab is gone), signalling the reader thread to stop.
    fn acquire(&self) -> bool {
        let mut s = self.state.lock().unwrap();
        loop {
            if s.closed {
                return false;
            }
            if s.permits > 0 {
                s.permits -= 1;
                return true;
            }
            s = self.ready.wait(s).unwrap();
        }
    }

    /// Return a permit after the loop has processed the message it guarded.
    fn release(&self) {
        let mut s = self.state.lock().unwrap();
        s.permits += 1;
        self.ready.notify_one();
    }

    /// Permanently unblock the reader (its tab was torn down); further
    /// `acquire`s fail so the thread exits instead of leaking.
    fn close(&self) {
        let mut s = self.state.lock().unwrap();
        s.closed = true;
        self.ready.notify_all();
    }
}

struct Tab {
    /// The `(zone, origin)` this tab's renderer was created for. This pair is
    /// the *authoritative* identity — policy decisions use it, never claims
    /// made over IPC. The zone selects the cookie/storage partition; the
    /// origin selects same-origin access within it.
    zone: ZoneId,
    origin: String,
    tx: EndpointTx,
    handle: ChildHandle,
    /// Number of this tab's fetches awaiting a reply from the net component.
    inflight_fetches: usize,
    /// Bounds this renderer's queued-but-unprocessed messages in the inbox.
    gate: Arc<Gate>,
}

enum Role<'a> {
    Net,
    Renderer(&'a str),
}

/// A cookie in the engine's jar. `http_only` cookies are attached to network
/// requests by the net component but withheld from renderers — the browser
/// property that keeps session tokens out of a compromised renderer.
struct Cookie {
    name: String,
    value: String,
    http_only: bool,
}

struct EngineLoop {
    spawner: Spawner,
    /// Cloned into every reader thread so all sources feed one inbox.
    inbox: Sender<LoopMsg>,
    events: Sender<EngineEvent>,
    net_tx: EndpointTx,
    net_handle: ChildHandle,
    /// Bounds the net component's queued-but-unprocessed replies in the inbox.
    net_gate: Arc<Gate>,
    tabs: HashMap<TabId, Tab>,
    /// The engine's private state, keyed by `(zone, origin)` so the same
    /// origin has independent cookies per zone (the profile/container
    /// partition). Renderers reach it only through the broker — in
    /// multi-process mode it never lives in their address space, and HttpOnly
    /// cookies never reach them at all.
    cookies: HashMap<(ZoneId, String), Vec<Cookie>>,
    /// In-flight fetches: request id -> the tab awaiting the reply.
    pending_fetches: HashMap<u64, TabId>,
    next_tab_id: u64,
    next_request_id: u64,
}

impl EngineLoop {
    fn new(mode: Mode, inbox: Sender<LoopMsg>, events: Sender<EngineEvent>) -> EngineLoop {
        let mut spawner = Spawner::new(mode);

        // Bring up the net component and a reader thread that forwards its
        // replies into the inbox, bounded by the net component's gate.
        let (net_handle, ep) = spawner.spawn(Role::Net);
        let (net_tx, mut net_rx) = ep.split();
        let net_gate = Gate::new(MAX_QUEUED_PER_SOURCE);
        {
            let inbox = inbox.clone();
            let net_gate = Arc::clone(&net_gate);
            std::thread::spawn(move || loop {
                match net_rx.recv::<NetResponse>() {
                    Ok(resp) => {
                        // A streaming response's ring fd follows on the same
                        // socket; this thread is its only reader, so take the
                        // fd here and route both together.
                        #[cfg(all(feature = "multi-process", target_os = "linux"))]
                        if matches!(resp.outcome, FetchOutcome::OkStreaming { .. }) {
                            let Ok(fd) = net_rx.recv_fd() else { break };
                            if !net_gate.acquire() {
                                break;
                            }
                            if inbox.send(LoopMsg::NetStream { resp, fd }).is_err() {
                                break;
                            }
                            continue;
                        }
                        if !net_gate.acquire() {
                            break;
                        }
                        if inbox.send(LoopMsg::NetReply(resp)).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            });
        }

        EngineLoop {
            spawner,
            inbox,
            events,
            net_tx,
            net_handle,
            net_gate,
            tabs: HashMap::new(),
            cookies: HashMap::new(),
            pending_fetches: HashMap::new(),
            next_tab_id: 0,
            next_request_id: 0,
        }
    }

    fn emit(&self, event: EngineEvent) {
        let _ = self.events.send(event);
    }

    /// The event loop: one inbox, one message at a time.
    fn run(mut self, inbox_rx: Receiver<LoopMsg>) {
        for msg in inbox_rx {
            match msg {
                LoopMsg::Command(EngineCommand::OpenTab { zone, url }) => {
                    self.open_tab(zone, &url)
                }
                LoopMsg::Command(EngineCommand::Tab { tab_id, cmd }) => {
                    self.tab_command(tab_id, cmd)
                }
                LoopMsg::Command(EngineCommand::SetCookie { zone, origin, name, value, http_only }) => {
                    self.cookies
                        .entry((zone, origin))
                        .or_default()
                        .push(Cookie { name, value, http_only });
                }
                LoopMsg::Command(EngineCommand::Shutdown) => {
                    self.shutdown();
                    return;
                }
                LoopMsg::FromTab { tab_id, msg } => {
                    // Release the permit this message consumed *after* handling
                    // it, so the source can queue one more (grab the gate up
                    // front in case handling ends up touching the tab).
                    let gate = self.tabs.get(&tab_id).map(|t| Arc::clone(&t.gate));
                    self.tab_request(tab_id, msg);
                    if let Some(gate) = gate {
                        gate.release();
                    }
                }
                #[cfg(all(feature = "multi-process", target_os = "linux"))]
                LoopMsg::ShmTile { tab_id, tile } => {
                    let gate = self.tabs.get(&tab_id).map(|t| Arc::clone(&t.gate));
                    if gate.is_some() {
                        // Zero-copy hand-off: the event carries the mapping
                        // itself, and the mapping (+ pages) is freed when the
                        // consumer drops the Tile.
                        self.emit(EngineEvent::FrameReady { tab_id, tile });
                    }
                    if let Some(gate) = gate {
                        gate.release();
                    }
                }
                LoopMsg::TabGone { tab_id } => {
                    // Only a crash if we didn't remove the tab ourselves
                    // (close/shutdown also end the link, after removal).
                    if let Some(tab) = self.tabs.remove(&tab_id) {
                        tab.gate.close();
                        join(tab.handle);
                        self.pending_fetches.retain(|_, t| *t != tab_id);
                        self.emit(EngineEvent::TabCrashed { tab_id });
                    }
                }
                LoopMsg::NetReply(resp) => {
                    self.net_reply(resp);
                    self.net_gate.release();
                }
                #[cfg(all(feature = "multi-process", target_os = "linux"))]
                LoopMsg::NetStream { resp, fd } => {
                    self.net_stream(resp, fd);
                    self.net_gate.release();
                }
            }
        }
    }

    fn open_tab(&mut self, zone: ZoneId, url: &str) {
        let Some(origin) = origin_of(url) else {
            self.emit(EngineEvent::OpenTabFailed {
                url: url.to_string(),
                reason: "unparseable URL".into(),
            });
            return;
        };

        let tab_id = TabId(self.next_tab_id);
        self.next_tab_id += 1;

        // The renderer process is bound to this (zone, origin): a separate
        // process from the same origin in another zone, so it can never touch
        // that zone's partition.
        let (handle, ep) = self.spawner.spawn(Role::Renderer(&origin));
        let (tx, mut rx) = ep.split();
        let gate = Gate::new(MAX_QUEUED_PER_SOURCE);

        // Reader thread: forward everything this renderer says into the
        // inbox, tagged with the tab it belongs to; report EOF as TabGone.
        // Acquiring a gate permit before each forward bounds how many of this
        // renderer's messages can sit unprocessed — and blocks (backpressuring
        // the renderer's socket) if it floods. A closed gate means the tab was
        // torn down, so the thread exits without a spurious TabGone.
        {
            let inbox = self.inbox.clone();
            let gate = Arc::clone(&gate);
            std::thread::spawn(move || {
                loop {
                    match rx.recv::<FromRenderer>() {
                        // A shared-memory tile: the fd follows the message on
                        // the same socket, so this thread — the socket's only
                        // reader — receives and validates it here. The message
                        // dimensions are a claim; map_sealed_tile refuses an
                        // fd that isn't sealed or can't actually hold them. A
                        // tile that fails validation is a protocol violation:
                        // drop the link and report the tab gone.
                        #[cfg(all(feature = "multi-process", target_os = "linux"))]
                        Ok(FromRenderer::TileShm { width, height }) => {
                            let mapped = rx
                                .recv_fd()
                                .and_then(|fd| crate::shm::map_sealed_tile(fd, width, height));
                            match mapped {
                                Ok(mapping) => {
                                    if !gate.acquire() {
                                        return;
                                    }
                                    let tile =
                                        Tile { width, height, pixels: TilePixels::Shared(mapping) };
                                    if inbox.send(LoopMsg::ShmTile { tab_id, tile }).is_err() {
                                        return;
                                    }
                                }
                                Err(e) => {
                                    eprintln!("[engine] {tab_id}: rejected shm tile: {e}");
                                    break;
                                }
                            }
                        }
                        Ok(msg) => {
                            if !gate.acquire() {
                                return;
                            }
                            if inbox.send(LoopMsg::FromTab { tab_id, msg }).is_err() {
                                return;
                            }
                        }
                        Err(_) => break,
                    }
                }
                let _ = inbox.send(LoopMsg::TabGone { tab_id });
            });
        }

        self.tabs.insert(
            tab_id,
            Tab { zone, origin: origin.clone(), tx, handle, inflight_fetches: 0, gate },
        );
        self.emit(EngineEvent::TabOpened { tab_id, zone, origin });
    }

    fn tab_command(&mut self, tab_id: TabId, cmd: TabCommand) {
        if !self.tabs.contains_key(&tab_id) {
            return; // tab already gone; the Crashed/Closed event said so
        }
        match cmd {
            TabCommand::Navigate { url } => {
                // Site isolation: this tab's renderer only ever handles its
                // own origin. A real engine swaps in a renderer for the new
                // origin here; the PoC refuses.
                let tab_origin = &self.tabs[&tab_id].origin;
                if origin_of(&url).as_deref() != Some(tab_origin.as_str()) {
                    let reason = format!("{url} is outside this renderer's origin {tab_origin}");
                    self.emit(EngineEvent::NavigationFailed { tab_id, reason });
                    return;
                }
                let tab = self.tabs.get_mut(&tab_id).unwrap();
                // On failure the renderer is gone; its reader thread will
                // report TabGone.
                let _ = tab.tx.send(&ToRenderer::RenderPage { url });
            }
            TabCommand::Close => {
                let mut tab = self.tabs.remove(&tab_id).unwrap();
                tab.gate.close(); // unblock the reader thread if it's flooding
                let _ = tab.tx.send(&ToRenderer::Shutdown);
                join(tab.handle);
                self.pending_fetches.retain(|_, t| *t != tab_id);
                self.emit(EngineEvent::TabClosed { tab_id });
            }
        }
    }

    /// A renderer asked for something privileged. This dispatch *is* the
    /// security boundary — and it is the same code in both modes.
    fn tab_request(&mut self, tab_id: TabId, msg: FromRenderer) {
        let Some(tab) = self.tabs.get_mut(&tab_id) else {
            return; // late message from a tab we already closed
        };
        match msg {
            FromRenderer::NeedFetch { url } => {
                // Site isolation for fetches: a renderer may only fetch its own
                // origin. Without this a compromised renderer could name an
                // attacker-controlled URL and the engine would attach *this*
                // origin's cookies — including HttpOnly — to it, exfiltrating
                // the session token the renderer is never allowed to see. Same
                // rule the engine already applies to cross-origin navigation.
                if !may_fetch(&tab.origin, &url) {
                    let reason = format!("{url} is outside this renderer's origin {}", tab.origin);
                    let _ = tab.tx.send(&ToRenderer::FetchDenied { reason });
                    return;
                }
                // Backpressure: refuse a renderer that floods fetches without
                // consuming replies, so it can't grow the engine unbounded.
                if tab.inflight_fetches >= MAX_INFLIGHT_FETCHES {
                    let _ = tab.tx.send(&ToRenderer::FetchDenied {
                        reason: "too many in-flight fetches".into(),
                    });
                    return;
                }
                // Forward to the net component, stamped with the identity
                // the engine knows for this tab — the renderer cannot spoof
                // it. The reply is matched back via the request id.
                let request_id = self.next_request_id;
                self.next_request_id += 1;
                // Attach this (zone, origin)'s cookies — *including HttpOnly* —
                // for the net component to put on the request. The zone selects
                // the partition, so a fetch in one zone never carries another
                // zone's cookies. These values go to the network process,
                // never back to the renderer.
                let cookies = attachable_cookies(&self.cookies, tab.zone, &tab.origin);
                self.pending_fetches.insert(request_id, tab_id);
                tab.inflight_fetches += 1;
                let req = NetRequest::Fetch {
                    request_id,
                    for_zone: tab.zone.0,
                    for_origin: tab.origin.clone(),
                    url,
                    cookies,
                };
                if self.net_tx.send(&req).is_err() {
                    self.pending_fetches.remove(&request_id);
                    tab.inflight_fetches -= 1;
                    let _ = tab.tx.send(&ToRenderer::FetchDenied {
                        reason: "net component unavailable".into(),
                    });
                }
            }
            FromRenderer::NeedCookies { origin: requested } => {
                // Same-origin check against the tab's authoritative identity,
                // not the message contents. The renderer receives only the
                // *non-HttpOnly* cookies — the `document.cookie` view — so an
                // exploited renderer never sees its origin's session token.
                let reply = if requested == tab.origin {
                    ToRenderer::Cookies(Some(visible_cookies(&self.cookies, tab.zone, &requested)))
                } else {
                    ToRenderer::Cookies(None)
                };
                let _ = tab.tx.send(&reply);
            }
            FromRenderer::Tile { width, height, pixels } => {
                self.emit(EngineEvent::FrameReady {
                    tab_id,
                    tile: Tile { width, height, pixels: TilePixels::Inline(pixels) },
                });
            }
            // Consumed (fd received, validated, mapped) by the reader thread;
            // never reaches the loop as a FromTab message.
            #[cfg(all(feature = "multi-process", target_os = "linux"))]
            FromRenderer::TileShm { .. } => {}
        }
    }

    fn net_reply(&mut self, resp: NetResponse) {
        let Some(tab_id) = self.pending_fetches.remove(&resp.request_id) else {
            return; // requester disappeared while the fetch was in flight
        };
        let Some(tab) = self.tabs.get_mut(&tab_id) else {
            return;
        };
        tab.inflight_fetches = tab.inflight_fetches.saturating_sub(1);
        let reply = match resp.outcome {
            FetchOutcome::Ok { status, body } => ToRenderer::FetchResult { status, body },
            FetchOutcome::Denied { reason } => ToRenderer::FetchDenied { reason },
            // Streamed outcomes arrive as LoopMsg::NetStream, never here.
            #[cfg(all(feature = "multi-process", target_os = "linux"))]
            FetchOutcome::OkStreaming { .. } => return,
        };
        let _ = tab.tx.send(&reply);
    }

    /// Route a streamed fetch body: same bookkeeping as [`net_reply`], but
    /// the payload is a ring fd the engine *forwards* to the renderer without
    /// ever mapping it — the bytes flow net → renderer directly; the broker
    /// only decides who gets the handle. If the tab is gone the fd just
    /// drops, and the net component's stall timeout reclaims its ring.
    ///
    /// [`net_reply`]: Self::net_reply
    #[cfg(all(feature = "multi-process", target_os = "linux"))]
    fn net_stream(&mut self, resp: NetResponse, fd: std::os::fd::OwnedFd) {
        use std::os::fd::AsRawFd;
        let Some(tab_id) = self.pending_fetches.remove(&resp.request_id) else {
            return; // requester disappeared while the fetch was in flight
        };
        let Some(tab) = self.tabs.get_mut(&tab_id) else {
            return;
        };
        tab.inflight_fetches = tab.inflight_fetches.saturating_sub(1);
        let FetchOutcome::OkStreaming { status, body_len } = resp.outcome else {
            return;
        };
        // Header first, fd right behind it — the renderer consumes them as
        // one exchange (the tile path's discipline, direction reversed).
        if tab.tx.send(&ToRenderer::FetchBodyStream { status, body_len }).is_ok() {
            let _ = tab.tx.send_fd(fd.as_raw_fd());
        }
    }

    fn shutdown(&mut self) {
        for (_, mut tab) in self.tabs.drain() {
            tab.gate.close();
            let _ = tab.tx.send(&ToRenderer::Shutdown);
            join(tab.handle);
        }
        self.net_gate.close();
        let _ = self.net_tx.send(&NetRequest::Shutdown);
        join(std::mem::replace(&mut self.net_handle, ChildHandle::Thread(dummy_thread())));
        self.spawner.shutdown_forkserver();
        self.emit(EngineEvent::EngineShutdown);
    }
}

/// Placeholder so `shutdown` can move the real net handle out of the loop
/// struct without wrapping the field in an `Option`.
fn dummy_thread() -> std::thread::JoinHandle<()> {
    std::thread::spawn(|| {})
}

fn join(handle: ChildHandle) {
    match handle {
        ChildHandle::Thread(t) => {
            let _ = t.join();
        }
        #[cfg(feature = "multi-process")]
        ChildHandle::Process(mut child) => {
            let _ = child.wait();
        }
        // Reaped by the fork server; the engine has nothing to wait on.
        #[cfg(all(feature = "multi-process", target_os = "linux"))]
        ChildHandle::ForkServed => {}
    }
}

/// Canonical origin of a URL: `scheme://host[:port]`, with the scheme's
/// default port folded away — so `https://example.com:443` and
/// `https://example.com` are the same origin, while a different scheme or a
/// nonstandard port is a *different* origin. That full tuple is what the
/// origin model is defined over, and everything downstream keys on it: the
/// same-origin navigation check, and the cookie jar's `(zone, origin)`
/// partition — so an HTTPS page's cookies can never be attached to an HTTP
/// fetch (no secure-cookie downgrade), and an `https:` renderer can't be
/// navigated to `http:`. Still a PoC parser, not a URL library: no IDNA and
/// no userinfo handling (`ip_utils::host_of` is the deliberately-hostile
/// one; a real engine shares one implementation).
fn origin_of(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    if scheme.is_empty() || !scheme.chars().all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c))
    {
        return None;
    }
    let authority = rest.split(['/', '?', '#']).next()?;

    let (host, port) = if let Some(bracketed) = authority.strip_prefix('[') {
        // [IPv6] or [IPv6]:port
        let (host, after) = bracketed.split_once(']')?;
        (host, after.strip_prefix(':'))
    } else if let Some((host, port)) = authority.rsplit_once(':') {
        (host, Some(port))
    } else {
        (authority, None)
    };
    if host.is_empty() {
        return None;
    }

    let scheme = scheme.to_ascii_lowercase();
    let host = host.to_ascii_lowercase();
    let port: Option<u16> = match port {
        Some(p) => Some(p.parse().ok()?), // a non-numeric port is not a URL
        None => None,
    };
    let default_port = match scheme.as_str() {
        "http" => Some(80),
        "https" => Some(443),
        _ => None,
    };
    Some(match port {
        Some(p) if Some(p) != default_port => format!("{scheme}://{host}:{p}"),
        _ => format!("{scheme}://{host}"),
    })
}

/// Site-isolation gate for fetches: a renderer bound to `tab_origin` may only
/// fetch its own origin. This is what makes attaching `tab_origin`'s cookies
/// (below) safe — the destination is guaranteed to be that same origin, so a
/// compromised renderer can't redirect its origin's (HttpOnly) cookies to an
/// attacker-controlled host. Mirrors the cross-origin navigation refusal.
fn may_fetch(tab_origin: &str, url: &str) -> bool {
    origin_of(url).as_deref() == Some(tab_origin)
}

/// The `(zone, origin)` partition's cookies (name, value) to attach to an
/// outbound request — **including HttpOnly**. Keyed by the pair, so one zone's
/// cookies never travel on another zone's request. Safe to attach by
/// `tab.origin` only because [`may_fetch`] has already confirmed the request's
/// destination *is* `tab.origin`.
fn attachable_cookies(
    jar: &HashMap<(ZoneId, String), Vec<Cookie>>,
    zone: ZoneId,
    origin: &str,
) -> Vec<(String, String)> {
    jar.get(&(zone, origin.to_string()))
        .map(|cs| cs.iter().map(|c| (c.name.clone(), c.value.clone())).collect())
        .unwrap_or_default()
}

/// The `document.cookie` view of a partition: its **non-HttpOnly** cookies
/// only, so an exploited renderer never sees its origin's session token.
fn visible_cookies(
    jar: &HashMap<(ZoneId, String), Vec<Cookie>>,
    zone: ZoneId,
    origin: &str,
) -> Vec<(String, String)> {
    jar.get(&(zone, origin.to_string()))
        .map(|cs| {
            cs.iter()
                .filter(|c| !c.http_only)
                .map(|c| (c.name.clone(), c.value.clone()))
                .collect()
        })
        .unwrap_or_default()
}

/// Knows how to bring up a child component in the selected mode. The mode
/// decision lives entirely here; everything above deals in `Endpoint`s and
/// `ChildHandle`s.
enum Spawner {
    Single,
    #[cfg(feature = "multi-process")]
    Multi {
        exe: std::path::PathBuf,
        /// The engine's end of the control channel to the fork server, and the
        /// fork-server process itself. Renderers are `fork()`ed from it; the
        /// net component is still spawned directly (it's a one-off).
        #[cfg(target_os = "linux")]
        fork_control: std::os::unix::net::UnixStream,
        #[cfg(target_os = "linux")]
        fork_child: std::process::Child,
    },
}

impl Spawner {
    fn new(mode: Mode) -> Spawner {
        match mode {
            Mode::Single => Spawner::Single,
            #[cfg(all(feature = "multi-process", target_os = "linux"))]
            Mode::Multi => {
                let exe = std::env::current_exe().unwrap();
                // Bring up the fork server now — before the engine loads the
                // cookie jar — so it starts secret-free. It is itself spawned
                // via fork+exec (one exec); renderers are then fork()ed from it
                // without exec.
                let (fork_control, fs_end) =
                    std::os::unix::net::UnixStream::pair().expect("socketpair");
                // The fork server needs no network of its own, and every
                // renderer it forks inherits the empty netns — which is how
                // renderers get network isolation without ever passing through
                // `spawn_inherited` themselves.
                let fork_child = spawn_inherited(
                    &exe,
                    &["fork-server"],
                    crate::channel::Channel::from_stream(fs_end),
                    true,
                );
                Spawner::Multi { exe, fork_control, fork_child }
            }
            #[cfg(all(feature = "multi-process", not(target_os = "linux")))]
            Mode::Multi => Spawner::Multi { exe: std::env::current_exe().unwrap() },
        }
    }

    fn spawn(&mut self, role: Role) -> (ChildHandle, Endpoint) {
        match self {
            // Single-process: the component's serve loop runs on a thread,
            // wired up with an in-process channel pair.
            Spawner::Single => {
                let (mine, theirs) = ipc::local_pair();
                let handle = match role {
                    Role::Net => std::thread::spawn(move || net_daemon::serve(theirs)),
                    Role::Renderer(origin) => {
                        let origin = origin.to_string();
                        std::thread::spawn(move || renderer::serve(theirs, &origin))
                    }
                };
                (ChildHandle::Thread(handle), mine)
            }

            // Multi-process on Linux: the net component is spawned directly
            // (fork+exec), but renderers are requested from the fork server,
            // which fork()s them without exec.
            #[cfg(all(feature = "multi-process", target_os = "linux"))]
            Spawner::Multi { exe, fork_control, .. } => match role {
                Role::Net => {
                    let (parent_end, child_end) =
                        crate::channel::Channel::pair().expect("channel pair");
                    // The one role that keeps its network namespace: it is the
                    // component whose entire job is outbound fetching.
                    let child = spawn_inherited(exe, &["net-daemon"], child_end, false);
                    let ep = Endpoint::from_channel(parent_end).expect("wrap parent end");
                    (ChildHandle::Process(child), ep)
                }
                Role::Renderer(origin) => {
                    use std::os::fd::AsRawFd;
                    // The engine creates the renderer's socketpair, keeps one
                    // end, and hands the other to the fork server via
                    // SCM_RIGHTS — so the renderer talks straight to the engine
                    // even though the fork server is its OS parent.
                    let (parent_end, child_end) =
                        std::os::unix::net::UnixStream::pair().expect("socketpair");
                    ipc::send_msg(fork_control, &ipc::ForkRequest::Renderer { origin: origin.to_string() })
                        .expect("fork request");
                    // SCM_RIGHTS duplicates the fd into the fork server; the
                    // engine then drops its copy of the child's end so it sees
                    // EOF (→ TabCrashed) when the renderer dies.
                    unsafe { ipc::send_fd(fork_control.as_raw_fd(), child_end.as_raw_fd()) }
                        .expect("send fd");
                    drop(child_end);
                    let ep = Endpoint::from_channel(crate::channel::Channel::from_stream(parent_end))
                        .expect("wrap parent end");
                    (ChildHandle::ForkServed, ep)
                }
            },

            // Multi-process elsewhere: no fork server; both roles are spawned
            // directly via fork+exec of an inherited-fd child.
            #[cfg(all(feature = "multi-process", not(target_os = "linux")))]
            Spawner::Multi { exe } => {
                let role_args: Vec<&str> = match role {
                    Role::Net => vec!["net-daemon"],
                    Role::Renderer(origin) => vec!["renderer", origin],
                };
                let (parent_end, child_end) =
                    crate::channel::Channel::pair().expect("channel pair");
                // No-op off Linux (no namespaces), but kept truthful per role.
                let isolate_network = matches!(role, Role::Renderer(_));
                let child = spawn_inherited(exe, &role_args, child_end, isolate_network);
                let ep = Endpoint::from_channel(parent_end).expect("wrap parent end");
                (ChildHandle::Process(child), ep)
            }
        }
    }

    /// Shut down the fork server (Linux). No-op otherwise.
    fn shutdown_forkserver(&mut self) {
        #[cfg(all(feature = "multi-process", target_os = "linux"))]
        if let Spawner::Multi { fork_control, fork_child, .. } = self {
            let _ = ipc::send_msg(fork_control, &ipc::ForkRequest::Shutdown);
            let _ = fork_child.wait();
        }
    }
}

/// Spawn a child role via fork+exec, handing it one end of a `socketpair(2)`
/// as an *inherited file descriptor*.
///
/// An inherited fd is unforgeable, so there is no rendezvous path on disk, no
/// auth token on argv (which any local user could read via
/// `/proc/<pid>/cmdline`), and no `accept()` race. Only the fd *number*
/// travels on argv, which is not a secret. Resource ceilings are imposed in
/// `pre_exec`, before the child runs its own code, and are inherited across
/// exec (and, for the fork server, across its later `fork()`s).
///
/// `isolate_network` additionally drops the child into an empty network
/// namespace. Like the rlimits, it is inherited across exec *and* across the
/// fork server's later `fork()`s — which is precisely how renderers get it,
/// since they are forked rather than spawned through this function. The net
/// component is the one role that must not have it.
#[cfg(feature = "multi-process")]
fn spawn_inherited(
    exe: &std::path::Path,
    args: &[&str],
    child_end: crate::channel::Channel,
    isolate_network: bool,
) -> std::process::Child {
    let mut cmd = std::process::Command::new(exe);
    cmd.args(args).arg(child_end.to_argv());
    // Strip the dynamic-loader injection vectors from the child's environment
    // before it execs: DYLD_INSERT_LIBRARIES (macOS) and LD_PRELOAD/LD_* (glibc)
    // are the runtime-linker's "load this code into every new process" knobs. A
    // child inheriting one would run attacker-supplied library code *before* it
    // reaches its own lockdown, sidestepping the sandbox entirely. The OS ignores
    // these for signed/hardened binaries, but scrubbing them is cheap defense in
    // depth and keeps the guarantee from depending on how the engine was signed.
    for (key, _) in std::env::vars_os() {
        let drop = key.to_str().is_some_and(|k| k.starts_with("DYLD_") || k.starts_with("LD_"));
        if drop {
            cmd.env_remove(&key);
        }
    }
    // --- Unix: cap privileges in `pre_exec`, between fork and exec ---
    //
    // Everything here runs in the forked child, which is both why the rlimits
    // and netns land on the child alone, and why the channel's inheritance is
    // granted here rather than in the parent: clearing FD_CLOEXEC in the
    // parent would expose that fd to every other concurrent spawn as well.
    #[cfg(unix)]
    unsafe {
        use std::os::unix::process::CommandExt;
        let raw = child_end.raw();
        cmd.pre_exec(move || {
            crate::sandbox::apply_child_rlimits()?;
            // Fail-closed, matching the seccomp precedent: a child that was
            // meant to be network-isolated and silently isn't is worse than an
            // honest refusal to start. Environments without unprivileged user
            // namespaces use `--single-process` / `--no-default-features`.
            // Platform-neutral: on Linux this enters an empty netns for
            // renderers; where there are no namespaces it defers to the
            // lockdown profile and is a no-op here.
            crate::sandbox::isolate_network(isolate_network)?;
            crate::channel::Channel::make_inheritable(raw)?;
            Ok(())
        });
    }

    // --- Windows: no `pre_exec`, so inheritance is granted here ---
    //
    // Safe with this spawner because it is driven only by the single-threaded
    // engine loop, so no other `CreateProcess` can be in flight to pick the
    // handles up (see `channel/windows.rs`).
    //
    // Note what is *missing* relative to the Unix path: there is no hook in
    // which to apply `apply_child_rlimits` or `isolate_network`. Windows caps
    // a child with a job object, a restricted token and an AppContainer, all
    // attached by the parent at creation time — which the sandbox contract has
    // no place for yet (see `sandbox/mod.rs`). Until it does, Windows children
    // run under the `unsupported` backend: unconfined, and saying so.
    #[cfg(windows)]
    {
        let _ = isolate_network;
        crate::channel::Channel::make_inheritable(child_end.raw())
            .expect("grant handle inheritance");
    }

    let child = cmd.spawn().expect("spawn child process");
    // Parent-side confinement, for the mechanisms a child cannot apply to
    // itself. A no-op outside Windows, where everything is self-applied.
    if let Err(e) = crate::sandbox::confine_spawned_child(&child) {
        // Fail closed, matching the lockdown precedent: a child that was meant
        // to be capped and silently is not is worse than an honest refusal.
        panic!("could not confine spawned child: {e}");
    }
    // The child holds its own copy now; drop ours so a dead child is seen as
    // EOF rather than a link the engine is itself holding open.
    drop(child_end);
    child
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::EngineEvent;
    use std::time::Duration;

    fn cookie(name: &str, value: &str, http_only: bool) -> Cookie {
        Cookie { name: name.into(), value: value.into(), http_only }
    }

    fn pair(a: &str, b: &str) -> (String, String) {
        (a.to_string(), b.to_string())
    }

    #[test]
    fn origin_extraction() {
        assert_eq!(origin_of("https://example.com/a/b").as_deref(), Some("https://example.com"));
        assert_eq!(origin_of("https://example.com").as_deref(), Some("https://example.com"));
        // Default port folds into the schemeful origin; a nonstandard port —
        // or a different scheme — is a different origin.
        assert_eq!(origin_of("https://example.com:443/x").as_deref(), Some("https://example.com"));
        assert_eq!(
            origin_of("https://example.com:8443/x").as_deref(),
            Some("https://example.com:8443")
        );
        assert_eq!(origin_of("http://example.com/").as_deref(), Some("http://example.com"));
        assert_ne!(origin_of("http://example.com/"), origin_of("https://example.com/"));
        // Case-insensitive scheme/host, IPv6 hosts keep their port handling.
        assert_eq!(origin_of("HTTPS://Example.COM/x").as_deref(), Some("https://example.com"));
        assert_eq!(origin_of("http://[::1]:8080/x").as_deref(), Some("http://::1:8080"));
        assert_eq!(origin_of("not-a-url"), None);
        assert_eq!(origin_of("https://"), None);
        assert_eq!(origin_of("https://example.com:notaport/"), None);
    }

    #[test]
    fn fetch_confined_to_own_origin() {
        // A renderer may fetch its own origin: any path/query on the same
        // scheme://host, with the default port folding away.
        assert!(may_fetch("https://example.com", "https://example.com/index.html"));
        assert!(may_fetch("https://example.com", "https://example.com/a/b?c#d"));
        assert!(may_fetch("https://example.com", "https://example.com:443/x"));
        // ...but not another host. This is the guard that stops a compromised
        // renderer from having the engine attach example.com's (HttpOnly)
        // cookies to a request aimed at an attacker-controlled server.
        assert!(!may_fetch("https://example.com", "https://attacker.com/collect"));
        assert!(!may_fetch("https://example.com", "https://evil.example.com/"));
        // Origins are schemeful: the same host over plain http (or another
        // port) is a *different* origin — no secure-cookie downgrade.
        assert!(!may_fetch("https://example.com", "http://example.com/"));
        assert!(!may_fetch("https://example.com", "https://example.com:8443/"));
        // Userinfo confusion must not fool the gate into treating the
        // authority as same-origin.
        assert!(!may_fetch("https://example.com", "https://example.com@attacker.com/"));
        // An unparseable URL is not the tab's origin → refused.
        assert!(!may_fetch("https://example.com", "not-a-url"));
    }

    #[test]
    fn cookies_partitioned_by_zone_and_httponly_hidden() {
        let mut jar: HashMap<(ZoneId, String), Vec<Cookie>> = HashMap::new();
        jar.insert(
            (ZoneId(0), "example.com".into()),
            vec![cookie("session", "work", true), cookie("theme", "dark", false)],
        );
        jar.insert((ZoneId(1), "example.com".into()), vec![cookie("session", "personal", true)]);

        // Attached to the network = ALL cookies (incl HttpOnly), per partition.
        assert_eq!(
            attachable_cookies(&jar, ZoneId(0), "example.com"),
            vec![pair("session", "work"), pair("theme", "dark")]
        );
        assert_eq!(
            attachable_cookies(&jar, ZoneId(1), "example.com"),
            vec![pair("session", "personal")]
        );

        // document.cookie view = non-HttpOnly only → the session token is hidden.
        assert_eq!(visible_cookies(&jar, ZoneId(0), "example.com"), vec![pair("theme", "dark")]);
        assert!(visible_cookies(&jar, ZoneId(1), "example.com").is_empty());

        // Wrong zone / absent origin → nothing crosses the partition.
        assert!(attachable_cookies(&jar, ZoneId(2), "example.com").is_empty());
        assert!(attachable_cookies(&jar, ZoneId(0), "other.com").is_empty());
    }

    #[test]
    fn gate_bounds_release_and_close() {
        let g = Gate::new(2);
        assert!(g.acquire());
        assert!(g.acquire()); // permits exhausted
        g.release();
        assert!(g.acquire()); // a release frees one
        g.close();
        assert!(!g.acquire()); // a closed gate refuses immediately
    }

    #[test]
    fn gate_close_unblocks_blocked_reader() {
        let g = Gate::new(1);
        assert!(g.acquire()); // 0 permits left
        let g2 = Arc::clone(&g);
        let waiter = std::thread::spawn(move || g2.acquire());
        std::thread::sleep(Duration::from_millis(50));
        g.close();
        assert!(!waiter.join().unwrap()); // was blocked, woke to `false`
    }

    #[test]
    fn single_process_tab_lifecycle() {
        let (engine, events) = start(Mode::Single);
        engine.open_tab(ZoneId(0), "https://example.com").unwrap();

        let (mut opened, mut framed) = (false, false);
        for ev in events {
            match ev {
                EngineEvent::TabOpened { tab_id, origin, .. } => {
                    opened = true;
                    assert_eq!(origin, "https://example.com");
                    engine.navigate(tab_id, "https://example.com/x").unwrap();
                }
                EngineEvent::FrameReady { tab_id, tile } => {
                    framed = true;
                    assert_eq!((tile.width, tile.height), (512, 512));
                    engine.close_tab(tab_id).unwrap();
                }
                EngineEvent::TabClosed { .. } => engine.shutdown().unwrap(),
                EngineEvent::EngineShutdown => break,
                EngineEvent::NavigationFailed { reason, .. } => panic!("nav failed: {reason}"),
                EngineEvent::TabCrashed { .. } => panic!("unexpected crash"),
                _ => {}
            }
        }
        assert!(opened && framed);
    }

    #[test]
    fn cross_origin_navigation_refused() {
        let (engine, events) = start(Mode::Single);
        engine.open_tab(ZoneId(0), "https://example.com").unwrap();

        let mut refused = false;
        for ev in events {
            match ev {
                EngineEvent::TabOpened { tab_id, .. } => {
                    engine.navigate(tab_id, "https://evil.com/").unwrap();
                }
                EngineEvent::NavigationFailed { .. } => {
                    refused = true;
                    engine.shutdown().unwrap();
                }
                EngineEvent::FrameReady { .. } => panic!("must not render cross-origin"),
                EngineEvent::EngineShutdown => break,
                _ => {}
            }
        }
        assert!(refused);
    }

    #[test]
    fn unparseable_url_reported() {
        let (engine, events) = start(Mode::Single);
        engine.open_tab(ZoneId(0), "not-a-url").unwrap();

        let mut failed = false;
        for ev in events {
            match ev {
                EngineEvent::OpenTabFailed { .. } => {
                    failed = true;
                    engine.shutdown().unwrap();
                }
                EngineEvent::TabOpened { .. } => panic!("must not open an unparseable URL"),
                EngineEvent::EngineShutdown => break,
                _ => {}
            }
        }
        assert!(failed);
    }
}
