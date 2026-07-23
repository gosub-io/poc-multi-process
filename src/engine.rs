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
    self, DecodeOutcome, Endpoint, EndpointTx, FetchOutcome, FontRequest, FontResponse, FromDecoder,
    FromRenderer, NetRequest, NetResponse, ServiceControl, StorageRequest, StorageResponse,
    SubresourceOutcome, ToDecoder, ToRenderer,
};
use crate::{net_daemon, renderer};
use std::collections::HashMap;
use std::io;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

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
    std::thread::spawn(move || {
        // Broker thread: arm its own crash-reporter altstack (the reporter's
        // altstack is per-thread; see `install_thread_crash_altstack`).
        crate::sandbox::install_thread_crash_altstack();
        EngineLoop::new(mode, inbox_tx, event_tx).run(inbox_rx)
    });
    (handle, event_rx)
}

/// Everything that can wake the event loop, from any source.
enum LoopMsg {
    /// A command from an [`EngineHandle`].
    Command(EngineCommand),
    /// A renderer sent a message (forwarded by its reader thread). `epoch`
    /// identifies the renderer *generation* so a message the pre-swap renderer
    /// queued is not processed against the post-swap tab (which reuses the
    /// `tab_id`); `gate` is the exact gate the reader took a permit on, so the
    /// loop returns it to that gate rather than to whatever tab currently holds
    /// the id.
    FromTab { tab_id: TabId, epoch: u64, gate: Arc<Gate>, msg: FromRenderer },
    /// A renderer delivered a tile via shared memory; its reader thread
    /// already received the fd, validated it (seals + real size) and mapped
    /// it, so what reaches the loop is a ready, immutable tile.
    #[cfg(all(feature = "multi-process", target_os = "linux"))]
    ShmTile { tab_id: TabId, epoch: u64, gate: Arc<Gate>, tile: Tile },
    /// A renderer's link died without a shutdown — crash, most likely. `epoch`
    /// pins it to the renderer generation that died, so a stale death from a
    /// swapped-out renderer cannot tear down the tab's new renderer.
    TabGone { tab_id: TabId, epoch: u64 },
    /// The net component answered a fetch.
    NetReply(NetResponse),
    /// The net component answered a fetch with a *streamed* body: the header
    /// to route, plus the ring fd (already received by the net reader thread)
    /// to forward to the requesting renderer. The engine never maps the ring.
    #[cfg(all(feature = "multi-process", target_os = "linux"))]
    NetStream { resp: NetResponse, fd: std::os::fd::OwnedFd },
    /// An ephemeral decoder answered (or died). Forwarded by its one-shot
    /// reader thread, which synthesizes a failure if the decoder died before
    /// answering — so a decoder crash reaches the loop as a `Failed`, never as
    /// a lost message.
    DecodeReply { request_id: u64, outcome: DecodeOutcome },
    /// The storage service answered a `Get`/`Set`.
    StorageReply { request_id: u64, value: Option<Vec<u8>> },
    /// The font service answered a metrics request.
    FontReply { request_id: u64, metrics: Option<crate::ipc::FontMetrics> },
    /// A brokered filesystem service (storage/font) died without a shutdown. The
    /// loop fails its in-flight requests and respawns it, bounded by
    /// [`MAX_SERVICE_RESTARTS`]. Sent by the service reader thread on EOF when its
    /// gate is still open (an intentional shutdown closes the gate first).
    ServiceGone { service: ServiceKind },
}

/// A running child component, however it is hosted.
enum ChildHandle {
    Thread(std::thread::JoinHandle<()>),
    #[cfg(feature = "multi-process")]
    Process(crate::spawn::Child),
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

/// Per-tab cap on outstanding decodes. Each decode forks a process, so without
/// this a renderer spamming `NeedDecode` is a fork bomb against the host. The
/// bound turns that into a flat refusal once the tab has too many in flight.
const MAX_INFLIGHT_DECODES: usize = 8;

/// How long the engine waits for a decoder's single reply before abandoning it.
/// A decode is trivial work (the parser is bounded and total), so a decoder that
/// has not answered within this window is wedged — most likely a decoder
/// compromised through the image it parsed. Without a bound its one-shot reader
/// thread blocks forever, the tab's decode slot never frees, and the process is
/// never reaped. Generous relative to real decode time; mirrors the ring's
/// [`crate::ring`] stall timeout in spirit.
const DECODE_TIMEOUT: Duration = Duration::from_secs(5);

/// Respawn bound for the brokered filesystem services (see [`ServiceRestartTracker`]).
/// A service that dies more than this many times within the window is not brought
/// back — its requests then fail fast instead of the engine spin-respawning it.
const MAX_SERVICE_RESTARTS: usize = 5;
const SERVICE_RESTART_WINDOW: Duration = Duration::from_secs(60);

/// How long the engine will block handing a reply to a renderer before giving up
/// on it. A well-behaved renderer always drains its replies promptly (it asked
/// for the data), so this only trips on one that floods requests and refuses to
/// read — which, on the single-threaded loop with blocking writes, would
/// otherwise wedge the *entire* browser (every tab, the services, and shutdown)
/// permanently. On timeout the renderer is dropped like a protocol violation. The
/// residual per-drop stall is removed only by the async broker rewrite.
const REPLY_WRITE_TIMEOUT: Duration = Duration::from_secs(5);

/// Per-source cap on messages queued-but-unprocessed in the shared inbox. All
/// sources funnel into one inbox, so without this a single renderer flooding
/// *any* message type would grow it without bound. See [`Gate`].
const MAX_QUEUED_PER_SOURCE: usize = 64;

/// Global ceiling on live renderer processes. The per-tab fetch/decode caps
/// bound what *one* renderer consumes, but nothing bounds how many renderers
/// exist — a hostile page spamming `window.open` (or a buggy embedder) would
/// otherwise spawn them until the host runs out of PIDs or memory. Opening past
/// this fails the `OpenTab` (a bounded refusal) instead of spawning. Chromium
/// has the same ceiling (its process limit); the number here is arbitrary but
/// finite, which is the point.
const MAX_RENDERERS: usize = 128;

/// Crash-loop guard. If a renderer for one `(zone, origin)` dies this many times
/// within [`CRASH_LOOP_WINDOW`], the engine stops bringing it back — further
/// opens and cross-origin navigations to that origin are refused (a bounded
/// failure) instead of spawning a process that will just crash again. A page that
/// reliably kills its renderer (a decompression bomb, a targeted exploit-probe, a
/// miscompiled asset) therefore cannot burn the host respawning forever. This is
/// Chromium's "sad tab" crash backoff in miniature.
const CRASH_LOOP_THRESHOLD: usize = 3;
const CRASH_LOOP_WINDOW: Duration = Duration::from_secs(30);

/// Per-`(zone, origin)` renderer-crash history behind the crash-loop guard.
/// Extracted from the engine loop so the policy is unit-testable without spawning
/// processes; `now` is passed in for the same reason. Stale entries are pruned on
/// every touch, so the map never grows without bound for a flaky-then-fine origin.
#[derive(Default)]
struct CrashTracker {
    history: HashMap<(ZoneId, String), Vec<Instant>>,
}

impl CrashTracker {
    /// Record a crash for `(zone, origin)` at `now`.
    ///
    /// This is the only method that *inserts* keys, so it is also where the map is
    /// kept bounded: before inserting, drop every key whose crashes have all aged
    /// out of the window. Without that sweep, a workload touching many distinct
    /// origins that each crash once would leave a key per origin forever (each
    /// method only pruned the *one* key it looked at). Crashes are rare, so the
    /// full sweep here is cheap.
    fn record(&mut self, zone: ZoneId, origin: &str, now: Instant) {
        self.history.retain(|_, hist| {
            hist.retain(|t| now.duration_since(*t) < CRASH_LOOP_WINDOW);
            !hist.is_empty()
        });
        self.history.entry((zone, origin.to_string())).or_default().push(now);
    }

    /// Whether `(zone, origin)` has crashed [`CRASH_LOOP_THRESHOLD`]+ times within
    /// the window ending at `now`.
    fn is_looping(&mut self, zone: ZoneId, origin: &str, now: Instant) -> bool {
        match self.history.get_mut(&(zone, origin.to_string())) {
            Some(hist) => {
                hist.retain(|t| now.duration_since(*t) < CRASH_LOOP_WINDOW);
                let looping = hist.len() >= CRASH_LOOP_THRESHOLD;
                if hist.is_empty() {
                    self.history.remove(&(zone, origin.to_string()));
                }
                looping
            }
            None => false,
        }
    }
}

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

    /// Whether this gate has been closed — i.e. its tab was torn down on
    /// purpose (close, shutdown, or a cross-origin swap). The reader thread
    /// checks this on EOF to tell an intentional teardown from a real crash: a
    /// closed gate means "do not raise `TabGone`", which is what stops a swap
    /// (reusing the tab id) from looking like the old renderer crashing.
    fn is_closed(&self) -> bool {
        self.state.lock().unwrap().closed
    }
}

struct Tab {
    /// The `(zone, origin)` this tab's renderer was created for. This pair is
    /// the *authoritative* identity — policy decisions use it, never claims
    /// made over IPC. The zone selects the cookie/storage partition; the
    /// origin selects same-origin access within it.
    zone: ZoneId,
    origin: String,
    /// The renderer *generation* behind this tab. A cross-origin swap replaces
    /// the process but keeps the `tab_id`, bumping this so late messages from the
    /// old renderer (tagged with the old epoch) are recognised as stale and
    /// dropped instead of being attributed to the new origin.
    epoch: u64,
    tx: EndpointTx,
    handle: ChildHandle,
    /// Number of this tab's fetches awaiting a reply from the net component.
    inflight_fetches: usize,
    /// Number of this tab's decodes awaiting an ephemeral decoder. Bounds how
    /// many decoder processes one renderer can have alive at once.
    inflight_decodes: usize,
    /// Bounds this renderer's queued-but-unprocessed messages in the inbox.
    gate: Arc<Gate>,
}

enum Role<'a> {
    Net,
    Renderer(&'a str),
    /// A throwaway image decoder — spawned per decode, decodes one image, dies.
    Decoder,
    /// A long-lived, engine-spawned service that needs a privilege the zygote
    /// gave up (filesystem or device). The token is both the argv role name and
    /// the serve-loop selector; the child self-confines with the right filter.
    Service(&'static str),
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
    /// In-flight subresource loads: request id -> the tab awaiting the reply.
    /// Kept separate from `pending_fetches` so a net reply is routed back as the
    /// right renderer message (a `FetchResult` vs a `SubresourceResult`); both
    /// ride the one net link and share the per-tab in-flight bound.
    pending_subresources: HashMap<u64, TabId>,
    /// In-flight decodes: request id -> the tab awaiting the decoded image.
    pending_decodes: HashMap<u64, TabId>,
    /// The filesystem-capable services: long-lived, engine-spawned, brokered
    /// like the net component. Keyed request/response, so many tabs multiplex
    /// over one link.
    storage: ServiceLink,
    storage_gate: Arc<Gate>,
    pending_storage: HashMap<u64, TabId>,
    font: ServiceLink,
    font_gate: Arc<Gate>,
    pending_font: HashMap<u64, TabId>,
    /// The device-backed stubs: spawned and confined, never messaged, ended at
    /// shutdown. Kept only so their links can be dropped and their processes
    /// reaped.
    devices: Vec<ServiceLink>,
    /// Renderer-crash history for the crash-loop guard (see [`CrashTracker`]).
    crashes: CrashTracker,
    /// Per-service respawn history for the respawn bound (see [`respawn_service`]).
    ///
    /// [`respawn_service`]: EngineLoop::respawn_service
    service_restarts: ServiceRestartTracker,
    next_tab_id: u64,
    next_request_id: u64,
    /// Monotonic renderer-generation counter. Every renderer (an `open_tab` or a
    /// `swap_renderer`) gets a fresh value, so no two renderer generations — even
    /// on the same reused `tab_id` — ever share an epoch.
    next_epoch: u64,
}

/// A long-lived engine-spawned service: the write half plus the handle to reap
/// it. (Its read half lives in a reader thread, and its inbox gate — for the
/// brokered ones — is created next to it.)
struct ServiceLink {
    tx: EndpointTx,
    handle: ChildHandle,
}

/// Which brokered filesystem service a [`LoopMsg::ServiceGone`] / respawn refers
/// to. Only these two are respawnable: each has its own reader thread and pending
/// map, so its death is observable and its in-flight work can be failed cleanly.
/// The device stubs are never messaged (nothing to respawn *for*), and the net
/// component and fork server are deliberately excluded — respawning them is more
/// invasive (net owns two pending maps + streaming and every tab depends on it;
/// the fork server owns the warm zygote and the shared PID namespace) and is left
/// as follow-up work.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
enum ServiceKind {
    Storage,
    Font,
}

impl ServiceKind {
    fn role_name(self) -> &'static str {
        match self {
            ServiceKind::Storage => "storage",
            ServiceKind::Font => "font",
        }
    }
}

/// The respawn bound: a service that keeps dying (a poisoned input, or a
/// deliberate kill loop) must not make the engine spin-respawn forever. The
/// service analogue of the renderer [`CrashTracker`] — stale entries pruned on
/// each touch, so it stays bounded.
#[derive(Default)]
struct ServiceRestartTracker {
    history: HashMap<ServiceKind, Vec<Instant>>,
}

impl ServiceRestartTracker {
    /// Record a restart attempt for `service` at `now`; returns `false` once it
    /// has restarted `MAX_SERVICE_RESTARTS` times within `SERVICE_RESTART_WINDOW`
    /// (the bound is reached — stop respawning).
    fn allow(&mut self, service: ServiceKind, now: Instant) -> bool {
        let hist = self.history.entry(service).or_default();
        hist.retain(|t| now.duration_since(*t) < SERVICE_RESTART_WINDOW);
        if hist.len() >= MAX_SERVICE_RESTARTS {
            return false;
        }
        hist.push(now);
        true
    }
}

impl EngineLoop {
    fn new(mode: Mode, inbox: Sender<LoopMsg>, events: Sender<EngineEvent>) -> EngineLoop {
        let mut spawner = Spawner::new(mode);

        // Bring up the net component and a reader thread that forwards its
        // replies into the inbox, bounded by the net component's gate.
        let (net_handle, ep) = spawner.spawn(Role::Net).expect("spawn net component at startup");
        let (net_tx, mut net_rx) = ep.split();
        let net_gate = Gate::new(MAX_QUEUED_PER_SOURCE);
        {
            let inbox = inbox.clone();
            let net_gate = Arc::clone(&net_gate);
            std::thread::spawn(move || {
                crate::sandbox::install_thread_crash_altstack();
                while let Ok(resp) = net_rx.recv::<NetResponse>() {
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
            });
        }

        // Prepare the on-disk state the filesystem services expect *before*
        // spawning them: the engine is unconfined and can create directories,
        // while the services' filters have `openat` but not `mkdirat`.
        crate::storage::ensure_dir();
        crate::font::ensure_font_file();

        // The brokered filesystem services: each gets a reader thread that
        // forwards its responses into the inbox (gated like the net component)
        // and, on an *unexpected* death, asks the loop to respawn it. Extracted
        // to helpers so the respawn path wires an identical reader (see
        // `respawn_service`).
        let (storage_handle, ep) =
            spawner.spawn(Role::Service("storage")).expect("spawn storage service at startup");
        let (storage_tx, storage_rx) = ep.split();
        let storage_gate = Gate::new(MAX_QUEUED_PER_SOURCE);
        Self::spawn_storage_reader(inbox.clone(), storage_rx, Arc::clone(&storage_gate));

        let (font_handle, ep) =
            spawner.spawn(Role::Service("font")).expect("spawn font service at startup");
        let (font_tx, font_rx) = ep.split();
        let font_gate = Gate::new(MAX_QUEUED_PER_SOURCE);
        Self::spawn_font_reader(inbox.clone(), font_rx, Arc::clone(&font_gate));

        // The device stubs: spawned and confined, then left idle. No reader
        // thread — they are never messaged; the engine only holds their links
        // so it can end them cleanly at shutdown.
        let devices = ["audio", "gpu"]
            .into_iter()
            .map(|name| {
                let (handle, ep) =
                    spawner.spawn(Role::Service(name)).expect("spawn device service at startup");
                let (tx, _rx) = ep.split();
                ServiceLink { tx, handle }
            })
            .collect();

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
            pending_subresources: HashMap::new(),
            pending_decodes: HashMap::new(),
            storage: ServiceLink { tx: storage_tx, handle: storage_handle },
            storage_gate,
            pending_storage: HashMap::new(),
            font: ServiceLink { tx: font_tx, handle: font_handle },
            font_gate,
            pending_font: HashMap::new(),
            devices,
            crashes: CrashTracker::default(),
            service_restarts: ServiceRestartTracker::default(),
            next_tab_id: 0,
            next_request_id: 0,
            next_epoch: 0,
        }
    }

    fn emit(&self, event: EngineEvent) {
        let _ = self.events.send(event);
    }

    /// Send a reply to a renderer, tearing the tab down on any send failure
    /// (a write timeout from a renderer that floods and never reads, or a broken
    /// pipe). Returns whether the send succeeded. This is the failure-aware path
    /// every renderer-facing reply on the loop thread must use, so one wedged
    /// renderer cannot block the single-threaded loop forever.
    fn send_to_tab(&mut self, tab_id: TabId, msg: &ToRenderer) -> bool {
        let ok = match self.tabs.get_mut(&tab_id) {
            Some(tab) => tab.tx.send(msg).is_ok(),
            None => return false,
        };
        if !ok {
            self.drop_tab_crashed(tab_id);
        }
        ok
    }

    /// Tear a tab down as a crash: close its gate, kill and reap its renderer,
    /// drop its in-flight broker state, record it against the crash-loop guard,
    /// and tell the embedder. This is the shared teardown behind both a genuine
    /// `TabGone` and a reply-write failure to a wedged renderer.
    fn drop_tab_crashed(&mut self, tab_id: TabId) {
        if let Some(mut tab) = self.tabs.remove(&tab_id) {
            tab.gate.close();
            kill_child(&mut tab.handle); // kill-before-join: a renderer we drop *because* it wedged must not hang the join
            join(tab.handle);
            self.pending_fetches.retain(|_, t| *t != tab_id);
            self.pending_subresources.retain(|_, t| *t != tab_id);
            self.pending_decodes.retain(|_, t| *t != tab_id);
            self.pending_storage.retain(|_, t| *t != tab_id);
            self.pending_font.retain(|_, t| *t != tab_id);
            self.crashes.record(tab.zone, &tab.origin, Instant::now());
            self.emit(EngineEvent::TabCrashed { tab_id });
        }
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
                LoopMsg::FromTab { tab_id, epoch, gate, msg } => {
                    // Process only if this message belongs to the tab's *current*
                    // renderer generation. A message the pre-swap renderer queued
                    // carries the old epoch; handling it would stamp it with the
                    // new origin's identity (a cross-origin storage write), so it
                    // is dropped. The permit is always returned — to the gate the
                    // reader actually took it on, never to whatever tab now holds
                    // the reused id.
                    if self.tabs.get(&tab_id).is_some_and(|t| t.epoch == epoch) {
                        self.tab_request(tab_id, msg);
                    }
                    gate.release();
                }
                #[cfg(all(feature = "multi-process", target_os = "linux"))]
                LoopMsg::ShmTile { tab_id, epoch, gate, tile } => {
                    if self.tabs.get(&tab_id).is_some_and(|t| t.epoch == epoch) {
                        // Zero-copy hand-off: the event carries the mapping
                        // itself, and the mapping (+ pages) is freed when the
                        // consumer drops the Tile.
                        self.emit(EngineEvent::FrameReady { tab_id, tile });
                    }
                    gate.release();
                }
                LoopMsg::TabGone { tab_id, epoch } => {
                    // Only a crash if we didn't remove the tab ourselves
                    // (close/shutdown also end the link, after removal) *and* the
                    // death is the tab's current generation — a stale death from a
                    // swapped-out renderer must not tear down its replacement.
                    if self.tabs.get(&tab_id).is_none_or(|t| t.epoch != epoch) {
                        continue;
                    }
                    // Teardown (close gate, reap, drop in-flight state, record
                    // against the crash-loop guard, emit TabCrashed) is shared
                    // with the reply-write-failure path.
                    self.drop_tab_crashed(tab_id);
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
                LoopMsg::DecodeReply { request_id, outcome } => {
                    self.decode_reply(request_id, outcome);
                }
                LoopMsg::StorageReply { request_id, value } => {
                    self.storage_reply(request_id, value);
                    self.storage_gate.release();
                }
                LoopMsg::FontReply { request_id, metrics } => {
                    self.font_reply(request_id, metrics);
                    self.font_gate.release();
                }
                LoopMsg::ServiceGone { service } => {
                    self.respawn_service(service);
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

        // Global process cap: refuse rather than spawn an unbounded number of
        // renderers. Checked here, before any process is created.
        if self.tabs.len() >= MAX_RENDERERS {
            self.emit(EngineEvent::OpenTabFailed {
                url: url.to_string(),
                reason: format!("renderer limit reached ({MAX_RENDERERS} live)"),
            });
            return;
        }

        // Crash-loop guard: an origin that has repeatedly crashed its renderer is
        // refused a fresh one rather than respawned into a loop.
        if self.crashes.is_looping(zone, &origin, Instant::now()) {
            self.emit(EngineEvent::OpenTabFailed {
                url: url.to_string(),
                reason: format!(
                    "crash loop: {origin} crashed its renderer {CRASH_LOOP_THRESHOLD}+ times in {}s",
                    CRASH_LOOP_WINDOW.as_secs()
                ),
            });
            return;
        }

        let tab_id = TabId(self.next_tab_id);
        self.next_tab_id += 1;

        // The renderer process is bound to this (zone, origin): a separate
        // process from the same origin in another zone, so it can never touch
        // that zone's partition. A spawn failure here means the fork server is
        // gone — refuse the tab rather than panic the engine.
        let Some((handle, ep)) = self.spawner.spawn(Role::Renderer(&origin)) else {
            self.emit(EngineEvent::OpenTabFailed {
                url: url.to_string(),
                reason: "fork server unavailable".into(),
            });
            return;
        };
        let (mut tx, rx) = ep.split();
        // Bound how long a reply to this renderer may block the loop: a renderer
        // that floods requests and never reads must not wedge the single-threaded
        // loop forever (see REPLY_WRITE_TIMEOUT).
        let _ = tx.set_write_timeout(Some(REPLY_WRITE_TIMEOUT));
        let gate = Gate::new(MAX_QUEUED_PER_SOURCE);
        let epoch = self.next_epoch;
        self.next_epoch += 1;
        self.spawn_tab_reader(tab_id, epoch, rx, Arc::clone(&gate));

        self.tabs.insert(
            tab_id,
            Tab {
                zone,
                origin: origin.clone(),
                epoch,
                tx,
                handle,
                inflight_fetches: 0,
                inflight_decodes: 0,
                gate,
            },
        );
        self.emit(EngineEvent::TabOpened { tab_id, zone, origin });
    }

    /// Spawn the reader thread that forwards one renderer's messages into the
    /// engine inbox, tagged with its tab. A gate permit is taken before each
    /// forward, bounding how many of this renderer's messages sit unprocessed
    /// (and backpressuring its socket when it floods).
    ///
    /// On EOF (or a rejected shm tile) the renderer is gone. Whether that is a
    /// *crash* depends on the gate: an intentional teardown — close, shutdown,
    /// or a cross-origin renderer swap — closes the gate first, so `is_closed()`
    /// suppresses the `TabGone`. Without that, a swap (which reuses the tab id)
    /// would race a spurious `TabCrashed` from the old renderer's reader against
    /// the freshly installed one. A real crash leaves the gate open → `TabGone`.
    fn spawn_tab_reader(
        &self,
        tab_id: TabId,
        epoch: u64,
        mut rx: crate::ipc::EndpointRx,
        gate: Arc<Gate>,
    ) {
        let inbox = self.inbox.clone();
        std::thread::spawn(move || {
            crate::sandbox::install_thread_crash_altstack();
            // Loop ends when `recv` errors (renderer gone) or a shm tile fails
            // validation.
            while let Ok(msg) = rx.recv::<FromRenderer>() {
                match msg {
                    // A shared-memory tile: the fd follows the message on the
                    // same socket, so this thread — the socket's only reader —
                    // receives and validates it here. The message dimensions are
                    // a claim; map_sealed_tile refuses an fd that isn't sealed or
                    // can't actually hold them. A tile that fails validation is a
                    // protocol violation: drop the link and report the tab gone.
                    #[cfg(all(feature = "multi-process", target_os = "linux"))]
                    FromRenderer::TileShm { width, height } => {
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
                                let m = LoopMsg::ShmTile {
                                    tab_id,
                                    epoch,
                                    gate: Arc::clone(&gate),
                                    tile,
                                };
                                if inbox.send(m).is_err() {
                                    return;
                                }
                            }
                            Err(e) => {
                                eprintln!("[engine] {tab_id}: rejected shm tile: {e}");
                                break;
                            }
                        }
                    }
                    msg => {
                        if !gate.acquire() {
                            return;
                        }
                        let m = LoopMsg::FromTab { tab_id, epoch, gate: Arc::clone(&gate), msg };
                        if inbox.send(m).is_err() {
                            return;
                        }
                    }
                }
            }
            // Intentional teardown closes the gate first; only an *unexpected*
            // death (gate still open) is a crash worth reporting.
            if !gate.is_closed() {
                let _ = inbox.send(LoopMsg::TabGone { tab_id, epoch });
            }
        });
    }

    fn tab_command(&mut self, tab_id: TabId, cmd: TabCommand) {
        if !self.tabs.contains_key(&tab_id) {
            return; // tab already gone; the Crashed/Closed event said so
        }
        match cmd {
            TabCommand::Navigate { url } => {
                let Some(new_origin) = origin_of(&url) else {
                    self.emit(EngineEvent::NavigationFailed {
                        tab_id,
                        reason: format!("unparseable URL {url}"),
                    });
                    return;
                };
                if new_origin == self.tabs[&tab_id].origin {
                    // Same origin: the existing renderer handles it.
                    let tab = self.tabs.get_mut(&tab_id).unwrap();
                    // On failure the renderer is gone; its reader thread will
                    // report TabGone.
                    let _ = tab.tx.send(&ToRenderer::RenderPage { url });
                } else {
                    // Cross-origin: site isolation forbids one renderer serving
                    // two origins, so swap in a fresh renderer for the new one.
                    self.swap_renderer(tab_id, new_origin, url);
                }
            }
            TabCommand::Close => {
                let mut tab = self.tabs.remove(&tab_id).unwrap();
                tab.gate.close(); // unblock the reader thread if it's flooding
                let _ = tab.tx.send(&ToRenderer::Shutdown);
                // Kill-before-join: a renderer that ignores Shutdown must not hang
                // the loop on the join (a no-op for a fork-served child, which the
                // fork server reaps; matters for the directly-parented Process
                // renderers on non-Linux).
                kill_child(&mut tab.handle);
                join(tab.handle);
                self.pending_fetches.retain(|_, t| *t != tab_id);
                self.pending_subresources.retain(|_, t| *t != tab_id);
                self.pending_decodes.retain(|_, t| *t != tab_id);
                self.pending_storage.retain(|_, t| *t != tab_id);
                self.pending_font.retain(|_, t| *t != tab_id);
                self.emit(EngineEvent::TabClosed { tab_id });
            }
        }
    }

    /// Swap a tab's renderer for a fresh one bound to `new_origin`, then render
    /// `url` — the site-isolation mechanism a real browser uses for cross-origin
    /// navigation (Chromium's renderer swap / RenderFrameHost change), in place
    /// of the PoC's former outright refusal. The new origin gets its *own*
    /// process, so two origins never share an address space; the same code runs
    /// in single-process mode with the "renderer" as a thread.
    ///
    /// The old renderer is torn down exactly like `Close`, with one difference
    /// that matters: its gate is closed *first*, so its reader thread exits
    /// quietly (see [`spawn_tab_reader`]) instead of racing a `TabCrashed` for
    /// the tab id this swap immediately reuses. In-flight broker state for the
    /// tab is dropped — a late reply to the *old* renderer finds no pending
    /// entry and is discarded, and the new renderer starts with zero in-flight.
    ///
    /// [`spawn_tab_reader`]: Self::spawn_tab_reader
    fn swap_renderer(&mut self, tab_id: TabId, new_origin: String, url: String) {
        // Crash-loop guard first, *before* tearing anything down: if the new
        // origin keeps crashing, refuse the navigation and keep the current
        // renderer rather than swapping into one that will just crash again.
        let Some(zone) = self.tabs.get(&tab_id).map(|t| t.zone) else {
            return;
        };
        if self.crashes.is_looping(zone, &new_origin, Instant::now()) {
            self.emit(EngineEvent::NavigationFailed {
                tab_id,
                reason: format!("crash loop: {new_origin} keeps crashing its renderer"),
            });
            return;
        }

        let Some(mut old) = self.tabs.remove(&tab_id) else {
            return;
        };

        // Tear down the old renderer. Closing the gate before ending the link is
        // what makes this a *swap* and not a *crash*: the reader sees the gate
        // closed on EOF and does not raise TabGone for `tab_id`. Kill-before-join
        // so an old renderer that ignores Shutdown can't hang the swap (no-op for
        // a fork-served child; matters for Process renderers on non-Linux).
        old.gate.close();
        let _ = old.tx.send(&ToRenderer::Shutdown);
        kill_child(&mut old.handle);
        join(old.handle);
        self.pending_fetches.retain(|_, t| *t != tab_id);
        self.pending_subresources.retain(|_, t| *t != tab_id);
        self.pending_decodes.retain(|_, t| *t != tab_id);
        self.pending_storage.retain(|_, t| *t != tab_id);
        self.pending_font.retain(|_, t| *t != tab_id);

        // Bring up the new renderer bound to (zone, new_origin), wired exactly
        // as `open_tab` does. If the fork server is gone the old renderer is
        // already torn down, so report the navigation as failed rather than
        // panicking; the tab ends up closed.
        let Some((handle, ep)) = self.spawner.spawn(Role::Renderer(&new_origin)) else {
            self.emit(EngineEvent::NavigationFailed {
                tab_id,
                reason: "fork server unavailable".into(),
            });
            return;
        };
        let (mut tx, rx) = ep.split();
        // Same reply-write bound as open_tab: a flooding renderer must not wedge
        // the loop (see REPLY_WRITE_TIMEOUT).
        let _ = tx.set_write_timeout(Some(REPLY_WRITE_TIMEOUT));
        let gate = Gate::new(MAX_QUEUED_PER_SOURCE);
        // A fresh epoch for the new generation: any message still in flight from
        // the old renderer carries the old epoch and is dropped by the loop
        // rather than being attributed to `new_origin`.
        let epoch = self.next_epoch;
        self.next_epoch += 1;
        self.spawn_tab_reader(tab_id, epoch, rx, Arc::clone(&gate));
        self.tabs.insert(
            tab_id,
            Tab {
                zone,
                origin: new_origin.clone(),
                epoch,
                tx,
                handle,
                inflight_fetches: 0,
                inflight_decodes: 0,
                gate,
            },
        );

        // Tell the embedder the tab committed a new origin, then render it.
        self.emit(EngineEvent::TabNavigated { tab_id, origin: new_origin });
        let tab = self.tabs.get_mut(&tab_id).unwrap();
        let _ = tab.tx.send(&ToRenderer::RenderPage { url });
    }

    /// A renderer asked for something privileged. This dispatch *is* the
    /// security boundary — and it is the same code in both modes.
    fn tab_request(&mut self, tab_id: TabId, msg: FromRenderer) {
        // A renderer-facing send that fails (a write timeout on a renderer that
        // floods and never reads, or a broken pipe) sets this; the tab is then
        // torn down *after* the `tab` borrow ends — `drop_tab_crashed` needs
        // `&mut self`, which the borrow would conflict with mid-body.
        let mut send_failed = false;
        'req: {
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
                        let reason =
                            format!("{url} is outside this renderer's origin {}", tab.origin);
                        if tab.tx.send(&ToRenderer::FetchDenied { reason }).is_err() {
                            send_failed = true;
                        }
                        break 'req;
                    }
                    // Backpressure: refuse a renderer that floods fetches without
                    // consuming replies, so it can't grow the engine unbounded.
                    if tab.inflight_fetches >= MAX_INFLIGHT_FETCHES {
                        if tab
                            .tx
                            .send(&ToRenderer::FetchDenied {
                                reason: "too many in-flight fetches".into(),
                            })
                            .is_err()
                        {
                            send_failed = true;
                        }
                        break 'req;
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
                    observe_cookies("fetch", tab.zone, &tab.origin, &cookies);
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
                        if tab
                            .tx
                            .send(&ToRenderer::FetchDenied {
                                reason: "net component unavailable".into(),
                            })
                            .is_err()
                        {
                            send_failed = true;
                        }
                    }
                }
                FromRenderer::NeedCookies { origin: requested } => {
                    // Same-origin check against the tab's authoritative identity,
                    // not the message contents. The renderer receives only the
                    // *non-HttpOnly* cookies — the `document.cookie` view — so an
                    // exploited renderer never sees its origin's session token.
                    let reply = if requested == tab.origin {
                        let visible = visible_cookies(&self.cookies, tab.zone, &requested);
                        observe_cookies("document.cookie", tab.zone, &requested, &visible);
                        ToRenderer::Cookies(Some(visible))
                    } else {
                        ToRenderer::Cookies(None)
                    };
                    if tab.tx.send(&reply).is_err() {
                        send_failed = true;
                    }
                }
                FromRenderer::Tile { width, height, pixels } => {
                    self.emit(EngineEvent::FrameReady {
                        tab_id,
                        tile: Tile { width, height, pixels: TilePixels::Inline(pixels) },
                    });
                }
                FromRenderer::NeedDecode { image } => {
                    self.broker_decode(tab_id, image);
                }
                FromRenderer::NeedStorage { op } => {
                    // Identity stamped from engine bookkeeping, never the message —
                    // the same rule as fetches. The storage service partitions by
                    // this pair, so a renderer cannot reach another origin's data.
                    let request_id = self.next_request_id;
                    self.next_request_id += 1;
                    self.pending_storage.insert(request_id, tab_id);
                    let req = StorageRequest::Op {
                        request_id,
                        zone: tab.zone.0,
                        origin: tab.origin.clone(),
                        op,
                    };
                    if self.storage.tx.send(&req).is_err() {
                        self.pending_storage.remove(&request_id);
                        if tab.tx.send(&ToRenderer::StorageResult(None)).is_err() {
                            send_failed = true;
                        }
                    }
                }
                FromRenderer::NeedFont { family } => {
                    let request_id = self.next_request_id;
                    self.next_request_id += 1;
                    self.pending_font.insert(request_id, tab_id);
                    let req = FontRequest::Metrics { request_id, family };
                    if self.font.tx.send(&req).is_err() {
                        self.pending_font.remove(&request_id);
                        if tab.tx.send(&ToRenderer::FontResult(None)).is_err() {
                            send_failed = true;
                        }
                    }
                }
                FromRenderer::NeedSubresource { url, mode } => {
                    // Unlike NeedFetch (own-origin only), a subresource may be
                    // cross-origin. The engine resolves the *destination* origin and
                    // attaches *its* cookies — never this renderer's — so an
                    // exploited renderer cannot redirect its own (HttpOnly) cookies
                    // to another host. What may then be *read back* is decided by
                    // Opaque Response Blocking in the net component; the renderer's
                    // claimed identity is never trusted.
                    let Some(dest_origin) = origin_of(&url) else {
                        if tab
                            .tx
                            .send(&ToRenderer::SubresourceResult(SubresourceOutcome::Denied {
                                reason: format!("unparseable subresource URL: {url}"),
                            }))
                            .is_err()
                        {
                            send_failed = true;
                        }
                        break 'req;
                    };
                    // Shares the per-tab in-flight bound with fetches (one net link).
                    if tab.inflight_fetches >= MAX_INFLIGHT_FETCHES {
                        if tab
                            .tx
                            .send(&ToRenderer::SubresourceResult(SubresourceOutcome::Denied {
                                reason: "too many in-flight requests".into(),
                            }))
                            .is_err()
                        {
                            send_failed = true;
                        }
                        break 'req;
                    }
                    let same_origin = dest_origin == tab.origin;
                    // Destination-origin cookies in this tab's zone (HttpOnly
                    // included — they reach the net component, never the renderer;
                    // the response is ORB-filtered regardless).
                    let cookies = attachable_cookies(&self.cookies, tab.zone, &dest_origin);
                    let request_id = self.next_request_id;
                    self.next_request_id += 1;
                    self.pending_subresources.insert(request_id, tab_id);
                    tab.inflight_fetches += 1;
                    let req =
                        NetRequest::Subresource { request_id, url, mode, same_origin, cookies };
                    if self.net_tx.send(&req).is_err() {
                        self.pending_subresources.remove(&request_id);
                        tab.inflight_fetches -= 1;
                        if tab
                            .tx
                            .send(&ToRenderer::SubresourceResult(SubresourceOutcome::Denied {
                                reason: "net component unavailable".into(),
                            }))
                            .is_err()
                        {
                            send_failed = true;
                        }
                    }
                }
                // Consumed (fd received, validated, mapped) by the reader thread;
                // never reaches the loop as a FromTab message.
                #[cfg(all(feature = "multi-process", target_os = "linux"))]
                FromRenderer::TileShm { .. } => {}
            }
        }
        if send_failed {
            self.drop_tab_crashed(tab_id);
        }
    }

    /// Relay a storage service reply to the tab that requested it.
    fn storage_reply(&mut self, request_id: u64, value: Option<Vec<u8>>) {
        let Some(tab_id) = self.pending_storage.remove(&request_id) else {
            return;
        };
        self.send_to_tab(tab_id, &ToRenderer::StorageResult(value));
    }

    /// Relay a font service reply to the tab that requested it.
    fn font_reply(&mut self, request_id: u64, metrics: Option<crate::ipc::FontMetrics>) {
        let Some(tab_id) = self.pending_font.remove(&request_id) else {
            return;
        };
        self.send_to_tab(tab_id, &ToRenderer::FontResult(metrics));
    }

    /// Reader thread for the storage service: forward each response into the
    /// inbox (taking a gate permit first, for backpressure), and on an
    /// *unexpected* death — recv EOF with the gate still open — ask the loop to
    /// respawn it. An intentional teardown closes the gate first (as at
    /// shutdown), so `is_closed()` suppresses the respawn request, exactly like
    /// the tab reader distinguishes a swap from a crash.
    fn spawn_storage_reader(inbox: Sender<LoopMsg>, mut rx: crate::ipc::EndpointRx, gate: Arc<Gate>) {
        std::thread::spawn(move || {
            crate::sandbox::install_thread_crash_altstack();
            while let Ok(resp) = rx.recv::<StorageResponse>() {
                if !gate.acquire() {
                    break;
                }
                let msg = LoopMsg::StorageReply { request_id: resp.request_id, value: resp.value };
                if inbox.send(msg).is_err() {
                    break;
                }
            }
            if !gate.is_closed() {
                let _ = inbox.send(LoopMsg::ServiceGone { service: ServiceKind::Storage });
            }
        });
    }

    /// Reader thread for the font service — same shape as [`spawn_storage_reader`].
    fn spawn_font_reader(inbox: Sender<LoopMsg>, mut rx: crate::ipc::EndpointRx, gate: Arc<Gate>) {
        std::thread::spawn(move || {
            crate::sandbox::install_thread_crash_altstack();
            while let Ok(resp) = rx.recv::<FontResponse>() {
                if !gate.acquire() {
                    break;
                }
                let msg = LoopMsg::FontReply { request_id: resp.request_id, metrics: resp.metrics };
                if inbox.send(msg).is_err() {
                    break;
                }
            }
            if !gate.is_closed() {
                let _ = inbox.send(LoopMsg::ServiceGone { service: ServiceKind::Font });
            }
        });
    }

    /// A brokered service died without a shutdown: fail everything that was
    /// in flight to it (those replies will never come, so the waiting renderers
    /// must hear a failure rather than hang), then respawn it — bounded, so a
    /// service that keeps dying is eventually left down and its requests fail fast
    /// rather than the engine spin-respawning forever.
    ///
    /// A respawned service self-confines with the same filter + Landlock as at
    /// startup, so there is no privilege regression. New requests that arrive
    /// while it is down (or given-up) fail fast at the send site in `tab_request`
    /// (a failed `tx.send` already replies `None`), so no request is left hanging.
    fn respawn_service(&mut self, service: ServiceKind) {
        // Fail the requests lost with the dead process first.
        self.fail_pending_for(service);

        if !self.service_restarts.allow(service, Instant::now()) {
            eprintln!(
                "[engine] {} service died {MAX_SERVICE_RESTARTS}+ times in {}s — not respawning; its requests will fail",
                service.role_name(),
                SERVICE_RESTART_WINDOW.as_secs()
            );
            return;
        }

        let Some((handle, ep)) = self.spawner.spawn(Role::Service(service.role_name())) else {
            eprintln!("[engine] could not respawn {} service", service.role_name());
            return;
        };
        let (tx, rx) = ep.split();
        let gate = Gate::new(MAX_QUEUED_PER_SOURCE);
        let old = match service {
            ServiceKind::Storage => {
                Self::spawn_storage_reader(self.inbox.clone(), rx, Arc::clone(&gate));
                self.storage_gate = gate;
                std::mem::replace(&mut self.storage, ServiceLink { tx, handle })
            }
            ServiceKind::Font => {
                Self::spawn_font_reader(self.inbox.clone(), rx, Arc::clone(&gate));
                self.font_gate = gate;
                std::mem::replace(&mut self.font, ServiceLink { tx, handle })
            }
        };
        // Reap the dead process (kill-before-join so a not-yet-fully-exited one
        // can't hang the loop).
        let mut old_handle = old.handle;
        kill_child(&mut old_handle);
        join(old_handle);
        eprintln!("[engine] respawned {} service after it died", service.role_name());
    }

    /// Fail every request in flight to `service`, replying `None` to each waiting
    /// tab (via [`send_to_tab`], which drops a tab whose own send then fails).
    ///
    /// [`send_to_tab`]: EngineLoop::send_to_tab
    fn fail_pending_for(&mut self, service: ServiceKind) {
        match service {
            ServiceKind::Storage => {
                for (_id, tab_id) in std::mem::take(&mut self.pending_storage) {
                    self.send_to_tab(tab_id, &ToRenderer::StorageResult(None));
                }
            }
            ServiceKind::Font => {
                for (_id, tab_id) in std::mem::take(&mut self.pending_font) {
                    self.send_to_tab(tab_id, &ToRenderer::FontResult(None));
                }
            }
        }
    }

    /// Fork a throwaway decoder for one image, hand it the bytes, and arrange
    /// for its reply to come back tagged with the tab that asked.
    ///
    /// The decoder is spawned per request and never reused — that is the
    /// ephemerality property, and it is why this bounds `inflight_decodes`: a
    /// renderer that spammed `NeedDecode` would otherwise fork processes without
    /// limit. The bytes come *from* the renderer, so no origin check is needed
    /// (a renderer decoding its own image reveals nothing it did not already
    /// have); the isolation is about containing the *parser*, not the data.
    fn broker_decode(&mut self, tab_id: TabId, image: Vec<u8>) {
        // Like tab_request: a failed renderer-facing send tears the tab down once
        // the `tab` borrow has ended (drop_tab_crashed needs `&mut self`).
        let mut send_failed = false;
        'dec: {
            let Some(tab) = self.tabs.get_mut(&tab_id) else {
                return;
            };
            if tab.inflight_decodes >= MAX_INFLIGHT_DECODES {
                if tab
                    .tx
                    .send(&ToRenderer::DecodeResult(DecodeOutcome::Failed {
                        reason: "too many in-flight decodes".into(),
                    }))
                    .is_err()
                {
                    send_failed = true;
                }
                break 'dec;
            }

            let request_id = self.next_request_id;
            self.next_request_id += 1;

            // Spawn the decoder and hand it the image. If either step fails, the
            // renderer gets a `Failed` rather than a silent hang. A None here is
            // the fork server being gone — same graceful failure.
            let Some((handle, ep)) = self.spawner.spawn(Role::Decoder) else {
                if tab
                    .tx
                    .send(&ToRenderer::DecodeResult(DecodeOutcome::Failed {
                        reason: "decoder unavailable (fork server down)".into(),
                    }))
                    .is_err()
                {
                    send_failed = true;
                }
                break 'dec;
            };
            let (mut dec_tx, dec_rx) = ep.split();
            if dec_tx.send(&ToDecoder::Decode { image }).is_err() {
                join(handle);
                if tab
                    .tx
                    .send(&ToRenderer::DecodeResult(DecodeOutcome::Failed {
                        reason: "decoder unavailable".into(),
                    }))
                    .is_err()
                {
                    send_failed = true;
                }
                break 'dec;
            }

            tab.inflight_decodes += 1;
            self.pending_decodes.insert(request_id, tab_id);

            // One-shot reader thread: wait for the single reply, forward it, then
            // reap the decoder. If the link closes *before* a reply, the decoder
            // died mid-decode — synthesize a `Failed` so the renderer always hears
            // an outcome. This is the fault-isolation guarantee: a decoder crash is
            // a decode failure, never a lost request or a broken engine.
            //
            // The wait is *bounded* (`DECODE_TIMEOUT`): a wedged decoder that neither
            // answers nor exits must not pin this thread and the tab's decode slot
            // forever. On timeout we synthesize a failure (so the slot frees and the
            // renderer hears an outcome), drop our socket end so a merely-slow decoder
            // sees EOF, and kill the child where we parent it (the non-fork-served
            // path) so the join below cannot block.
            let inbox = self.inbox.clone();
            std::thread::spawn(move || {
                crate::sandbox::install_thread_crash_altstack();
                let mut handle = handle;
                let mut dec_rx = dec_rx;
                let _ = dec_rx.set_read_timeout(Some(DECODE_TIMEOUT));
                let mut timed_out = false;
                let outcome = match dec_rx.recv::<FromDecoder>() {
                    Ok(FromDecoder::Decoded { width, height, pixels }) => {
                        DecodeOutcome::Ok { width, height, pixels }
                    }
                    Ok(FromDecoder::Failed { reason }) => DecodeOutcome::Failed { reason },
                    Err(e)
                        if matches!(
                            e.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                        ) =>
                    {
                        timed_out = true;
                        DecodeOutcome::Failed { reason: "decoder timed out".into() }
                    }
                    Err(_) => {
                        DecodeOutcome::Failed { reason: "decoder died before answering".into() }
                    }
                };
                let _ = inbox.send(LoopMsg::DecodeReply { request_id, outcome });
                // Drop our socket end first: a cooperative decoder still finishing up
                // sees EOF and exits, then is reaped (by the fork server on Linux).
                drop(dec_rx);
                // A wedged decoder never exits, so kill it before joining or the join
                // blocks forever — a no-op for a fork-served child (killed with its
                // PID namespace at shutdown) or a thread.
                if timed_out {
                    kill_child(&mut handle);
                }
                join(handle);
            });
        }
        if send_failed {
            self.drop_tab_crashed(tab_id);
        }
    }

    /// Relay an ephemeral decoder's result back to the tab that requested it.
    fn decode_reply(&mut self, request_id: u64, outcome: DecodeOutcome) {
        let Some(tab_id) = self.pending_decodes.remove(&request_id) else {
            return; // requester gone while the decode was in flight
        };
        // Free the decode slot first (short borrow), then deliver through the
        // failure-aware path so a wedged renderer is dropped rather than blocking.
        match self.tabs.get_mut(&tab_id) {
            Some(tab) => tab.inflight_decodes = tab.inflight_decodes.saturating_sub(1),
            None => return,
        }
        self.send_to_tab(tab_id, &ToRenderer::DecodeResult(outcome));
    }

    fn net_reply(&mut self, resp: NetResponse) {
        // A reply is for either a document fetch or a subresource load; its
        // request id is in exactly one of the two pending maps, which is how the
        // engine knows whether to answer with a `FetchResult` or a
        // `SubresourceResult`.
        if let Some(tab_id) = self.pending_fetches.remove(&resp.request_id) {
            // Free the in-flight slot (short borrow), then deliver through the
            // failure-aware path once the borrow has ended.
            match self.tabs.get_mut(&tab_id) {
                Some(tab) => tab.inflight_fetches = tab.inflight_fetches.saturating_sub(1),
                None => return,
            }
            let reply = match resp.outcome {
                FetchOutcome::Ok { status, body } => ToRenderer::FetchResult { status, body },
                FetchOutcome::Denied { reason } => ToRenderer::FetchDenied { reason },
                // ORB outcomes are only produced for subresource requests.
                FetchOutcome::Opaque { .. } | FetchOutcome::Blocked { .. } => {
                    ToRenderer::FetchDenied {
                        reason: "unexpected subresource outcome for a fetch".into(),
                    }
                }
                // Streamed outcomes arrive as LoopMsg::NetStream, never here.
                #[cfg(all(feature = "multi-process", target_os = "linux"))]
                FetchOutcome::OkStreaming { .. } => return,
            };
            self.send_to_tab(tab_id, &reply);
        } else if let Some(tab_id) = self.pending_subresources.remove(&resp.request_id) {
            match self.tabs.get_mut(&tab_id) {
                Some(tab) => tab.inflight_fetches = tab.inflight_fetches.saturating_sub(1),
                None => return,
            }
            let outcome = match resp.outcome {
                FetchOutcome::Ok { status, body } => {
                    SubresourceOutcome::Delivered { status, opaque: false, body }
                }
                FetchOutcome::Opaque { status, body } => {
                    SubresourceOutcome::Delivered { status, opaque: true, body }
                }
                FetchOutcome::Blocked { reason } => SubresourceOutcome::Blocked { reason },
                FetchOutcome::Denied { reason } => SubresourceOutcome::Denied { reason },
                // Subresources never take the streaming path.
                #[cfg(all(feature = "multi-process", target_os = "linux"))]
                FetchOutcome::OkStreaming { .. } => return,
            };
            self.send_to_tab(tab_id, &ToRenderer::SubresourceResult(outcome));
        }
        // else: requester disappeared while the request was in flight.
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
            // A streamed reply is only valid for a *document* fetch. If the id is
            // instead a subresource (which must never take the streaming path),
            // don't silently leak its in-flight slot: clean it up, tell the
            // renderer, and let `fd` drop. Defends the "subresources never stream"
            // invariant rather than relying on it.
            if let Some(tab_id) = self.pending_subresources.remove(&resp.request_id) {
                if let Some(tab) = self.tabs.get_mut(&tab_id) {
                    tab.inflight_fetches = tab.inflight_fetches.saturating_sub(1);
                    let _ = tab.tx.send(&ToRenderer::SubresourceResult(
                        SubresourceOutcome::Blocked {
                            reason: "subresource may not use the streaming path".into(),
                        },
                    ));
                }
            }
            return; // requester disappeared, or the subresource case handled above
        };
        // Free the in-flight slot (short borrow), then deliver.
        match self.tabs.get_mut(&tab_id) {
            Some(tab) => tab.inflight_fetches = tab.inflight_fetches.saturating_sub(1),
            None => return,
        }
        let FetchOutcome::OkStreaming { status, body_len } = resp.outcome else {
            return;
        };
        // Header first, fd right behind it — the renderer consumes them as
        // one exchange (the tile path's discipline, direction reversed). On any
        // send failure the renderer is wedged (or gone): drop it rather than let
        // it block the single-threaded loop.
        let mut failed = false;
        if let Some(tab) = self.tabs.get_mut(&tab_id) {
            if tab.tx.send(&ToRenderer::FetchBodyStream { status, body_len }).is_ok() {
                if tab.tx.send_fd(fd.as_raw_fd()).is_err() {
                    failed = true;
                }
            } else {
                failed = true;
            }
        }
        if failed {
            self.drop_tab_crashed(tab_id);
        }
    }

    fn shutdown(&mut self) {
        // Kill-before-join throughout: each child gets its Shutdown message (so a
        // cooperative one exits cleanly), then is killed before the join so a
        // wedged or compromised child — a service that ignores Shutdown, a
        // non-Linux Process renderer — cannot hang the engine's own exit. `kill`
        // is a harmless no-op on an already-exiting child, a fork-served child
        // (reaped by the fork server), or an in-process thread.
        for (_, mut tab) in self.tabs.drain() {
            tab.gate.close();
            let _ = tab.tx.send(&ToRenderer::Shutdown);
            kill_child(&mut tab.handle);
            join(tab.handle);
        }
        self.net_gate.close();
        let _ = self.net_tx.send(&NetRequest::Shutdown);
        let mut net_handle = std::mem::replace(&mut self.net_handle, ChildHandle::Thread(dummy_thread()));
        kill_child(&mut net_handle);
        join(net_handle);

        // End the services. Each gets its shutdown message, then is killed and
        // reaped; the device stubs only need their links dropped (they exit on
        // EOF), but a Shutdown makes the intent explicit.
        self.storage_gate.close();
        let _ = self.storage.tx.send(&StorageRequest::Shutdown);
        let mut storage_handle =
            std::mem::replace(&mut self.storage.handle, ChildHandle::Thread(dummy_thread()));
        kill_child(&mut storage_handle);
        join(storage_handle);
        self.font_gate.close();
        let _ = self.font.tx.send(&FontRequest::Shutdown);
        let mut font_handle =
            std::mem::replace(&mut self.font.handle, ChildHandle::Thread(dummy_thread()));
        kill_child(&mut font_handle);
        join(font_handle);
        for mut dev in self.devices.drain(..) {
            let _ = dev.tx.send(&ServiceControl::Shutdown);
            kill_child(&mut dev.handle);
            join(dev.handle);
        }

        self.spawner.shutdown_forkserver();

        // Every child is now reaped, so the per-child cgroups are empty: tear the
        // broker's cgroup subtree down (best-effort) rather than orphaning it
        // under /sys/fs/cgroup. A no-op in single-process mode and where no
        // subtree was set up.
        #[cfg(feature = "multi-process")]
        crate::sandbox::cleanup_spawned_cgroups();

        self.emit(EngineEvent::EngineShutdown);
    }
}

/// Placeholder so `shutdown` can move the real net handle out of the loop
/// struct without wrapping the field in an `Option`.
fn dummy_thread() -> std::thread::JoinHandle<()> {
    std::thread::spawn(|| {})
}

/// Single-process dispatch: run a service's serve loop as a thread, selected by
/// the same token that names its role in multi-process mode.
fn service_serve(name: &str, ep: Endpoint) {
    match name {
        "storage" => crate::storage::serve(ep),
        "font" => crate::font::serve(ep),
        "audio" | "gpu" => crate::device_service::serve(ep),
        other => panic!("unknown service {other}"),
    }
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

/// Best-effort kill of a child we still parent, so a later [`join`] does not
/// block on one that has wedged. Only the directly-spawned `Process` variant is
/// killable: a fork-served child is parented by the fork server (the engine has
/// no pid for it — it dies with the fork server / its PID namespace at
/// shutdown), and a thread cannot be killed. A no-op for those.
fn kill_child(handle: &mut ChildHandle) {
    #[cfg(feature = "multi-process")]
    if let ChildHandle::Process(child) = handle {
        let _ = child.kill();
    }
    let _ = handle;
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

    let (host, port, is_ipv6) = if let Some(bracketed) = authority.strip_prefix('[') {
        // [IPv6] or [IPv6]:port
        let (host, after) = bracketed.split_once(']')?;
        (host, after.strip_prefix(':'), true)
    } else if let Some((host, port)) = authority.rsplit_once(':') {
        (host, Some(port), false)
    } else {
        (authority, None, false)
    };
    if host.is_empty() {
        return None;
    }

    let scheme = scheme.to_ascii_lowercase();
    // Re-bracket an IPv6 literal in the canonical origin, or `[::1]:8080` and
    // `[::1:8080]` would both collapse to `::1:8080` — two distinct origins
    // sharing one cookie/storage partition and passing each other's same-origin
    // checks. The brackets are load-bearing identity here, not cosmetics.
    let host = if is_ipv6 {
        format!("[{}]", host.to_ascii_lowercase())
    } else {
        host.to_ascii_lowercase()
    };
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
/// Test/debug observability of the cookie flow, gated by `GOSUB_OBSERVE_COOKIES`
/// so it is silent in normal operation. Prints to the broker's **stdout** — a
/// single process, distinct from the child processes' *shared* stderr — so an
/// integration test can assert the HttpOnly property deterministically, without
/// the mid-line interleaving that makes combined child stderr unreliable. `kind`
/// is `"document.cookie"` (the visible set sent to a renderer) or `"fetch"` (the
/// full set attached to an outbound request).
fn observe_cookies(kind: &str, zone: ZoneId, origin: &str, cookies: &[(String, String)]) {
    if std::env::var_os("GOSUB_OBSERVE_COOKIES").is_some() {
        let names = cookies.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>().join(",");
        println!("[observe] zone {} {kind} {origin} = [{names}]", zone.0);
    }
}

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
        fork_child: crate::spawn::Child,
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

    fn spawn(&mut self, role: Role) -> Option<(ChildHandle, Endpoint)> {
        Some(match self {
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
                    Role::Decoder => {
                        std::thread::spawn(move || crate::decoder::serve_one(theirs))
                    }
                    Role::Service(name) => std::thread::spawn(move || service_serve(name, theirs)),
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
                // Services need a privilege the zygote gave up, so they cannot
                // be fork-served — they are spawned fork+exec straight from the
                // engine (like the net component) and self-confine with their
                // own filter. None needs the network, so each gets an empty
                // netns.
                Role::Service(name) => {
                    let (parent_end, child_end) =
                        crate::channel::Channel::pair().expect("channel pair");
                    let child = spawn_inherited(exe, &[name], child_end, true);
                    let ep = Endpoint::from_channel(parent_end).expect("wrap parent end");
                    (ChildHandle::Process(child), ep)
                }
                // Both renderers and decoders are fork-served: the engine
                // creates the socketpair, keeps one end, and hands the other to
                // the fork server via SCM_RIGHTS — so the child talks straight
                // to the engine even though the fork server is its OS parent.
                // Only the ForkRequest differs.
                Role::Renderer(_) | Role::Decoder => {
                    use std::os::fd::AsRawFd;
                    let req = match role {
                        Role::Renderer(origin) => ipc::ForkRequest::Renderer { origin: origin.to_string() },
                        Role::Decoder => ipc::ForkRequest::Decoder,
                        Role::Net | Role::Service(_) => unreachable!(),
                    };
                    let (parent_end, child_end) =
                        std::os::unix::net::UnixStream::pair().expect("socketpair");
                    // If the fork server has died (crash / OOM-kill), these fail
                    // at steady state. Degrade to a spawn failure the caller can
                    // report (OpenTabFailed / NavigationFailed / decode Failed)
                    // rather than panicking the whole engine loop. A fork
                    // *failure inside a live* fork server is handled elsewhere
                    // (the child's end is dropped → engine reader sees EOF →
                    // TabCrashed); only fork-server *death* reaches here.
                    if ipc::send_msg(fork_control, &req).is_err() {
                        eprintln!("[engine] fork server unavailable; cannot spawn content process");
                        return None;
                    }
                    // SCM_RIGHTS duplicates the fd into the fork server; the
                    // engine then drops its copy of the child's end so it sees
                    // EOF when the child dies (a decoder always, a renderer on
                    // crash).
                    if unsafe { ipc::send_fd(fork_control.as_raw_fd(), child_end.as_raw_fd()) }
                        .is_err()
                    {
                        eprintln!("[engine] fork server unavailable; cannot pass content-process fd");
                        return None;
                    }
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
                    Role::Decoder => vec!["decoder"],
                    Role::Service(name) => vec![name],
                };
                let (parent_end, child_end) =
                    crate::channel::Channel::pair().expect("channel pair");
                // No-op off Linux (no namespaces), but kept truthful per role:
                // only the net component needs the network.
                let isolate_network = !matches!(role, Role::Net);
                let child = spawn_inherited(exe, &role_args, child_end, isolate_network);
                let ep = Endpoint::from_channel(parent_end).expect("wrap parent end");
                (ChildHandle::Process(child), ep)
            }
        })
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
) -> crate::spawn::Child {
    let child = crate::spawn::spawn(exe, args, child_end, isolate_network)
        .expect("spawn child process");
    // Parent-side confinement, for the mechanisms a child cannot apply to
    // itself. A no-op outside Windows, where everything is self-applied.
    if let Err(e) = crate::sandbox::confine_spawned_child(&child) {
        // Fail closed, matching the lockdown precedent: a child that was meant
        // to be capped and silently is not is worse than an honest refusal.
        panic!("could not confine spawned child: {e}");
    }
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

    #[test]
    fn crash_loop_guard_trips_at_threshold_then_recovers() {
        let mut t = CrashTracker::default();
        let z = ZoneId(0);
        let t0 = Instant::now();

        // Below the threshold, an origin is not looping.
        assert!(!t.is_looping(z, "https://x", t0), "no crashes yet");
        t.record(z, "https://x", t0);
        t.record(z, "https://x", t0);
        assert!(!t.is_looping(z, "https://x", t0), "{CRASH_LOOP_THRESHOLD}> 2 crashes is not a loop");

        // The threshold-th crash within the window trips it.
        t.record(z, "https://x", t0);
        assert!(t.is_looping(z, "https://x", t0), "threshold crashes in the window is a loop");

        // The guard is scoped to `(zone, origin)`: a different origin, and the
        // same origin in another zone, are unaffected.
        assert!(!t.is_looping(z, "https://y", t0), "a different origin is independent");
        assert!(!t.is_looping(ZoneId(1), "https://x", t0), "the same origin in another zone is independent");

        // Once the crashes age past the window, the origin recovers — the guard
        // is a *recent*-crash backoff, not a permanent ban.
        let later = t0 + CRASH_LOOP_WINDOW + Duration::from_secs(1);
        assert!(!t.is_looping(z, "https://x", later), "stale crashes prune away");
    }

    #[test]
    fn service_respawn_bound_trips_then_recovers() {
        let mut t = ServiceRestartTracker::default();
        let t0 = Instant::now();

        // Up to the limit, respawns are allowed.
        for i in 0..MAX_SERVICE_RESTARTS {
            let at = t0 + Duration::from_secs(i as u64);
            assert!(t.allow(ServiceKind::Font, at), "restart {i} should be allowed");
        }
        // The next restart within the window is refused — stop respawning.
        let at = t0 + Duration::from_secs(MAX_SERVICE_RESTARTS as u64);
        assert!(!t.allow(ServiceKind::Font, at), "past the limit, no more respawns");

        // The bound is per service: storage is unaffected by font's deaths.
        assert!(t.allow(ServiceKind::Storage, t0), "a different service is independent");

        // Once the deaths age out of the window, the service may respawn again —
        // a recent-death backoff, not a permanent ban.
        let later = t0 + SERVICE_RESTART_WINDOW + Duration::from_secs(5);
        assert!(t.allow(ServiceKind::Font, later), "stale deaths prune away");
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
        // Case-insensitive scheme/host, IPv6 hosts keep their brackets.
        assert_eq!(origin_of("HTTPS://Example.COM/x").as_deref(), Some("https://example.com"));
        assert_eq!(origin_of("http://[::1]:8080/x").as_deref(), Some("http://[::1]:8080"));
        assert_eq!(origin_of("http://[::1]/").as_deref(), Some("http://[::1]"));
        // The brackets are load-bearing: an addr-with-port and a same-text host
        // must stay distinct origins, not collapse to one partition.
        assert_ne!(origin_of("http://[::1]:8080/"), origin_of("http://[::1:8080]/"));
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
    fn cross_origin_navigation_swaps_renderer() {
        // A cross-origin navigation is no longer refused: the tab keeps its id
        // but its renderer is swapped for one bound to the new origin, which
        // then renders. (The broker/swap code is identical in both modes; the
        // single-process engine exercises it deterministically.)
        let (engine, events) = start(Mode::Single);
        // A distinct zone from the other rendering unit test, so their
        // (zone, origin)-keyed storage files never collide in the shared default
        // storage dir when the two tests run in parallel.
        engine.open_tab(ZoneId(9), "https://example.com").unwrap();

        let (mut swapped, mut framed_after_swap) = (false, false);
        for ev in events {
            match ev {
                EngineEvent::TabOpened { tab_id, origin, .. } => {
                    assert_eq!(origin, "https://example.com");
                    engine.navigate(tab_id, "https://evil.com/").unwrap();
                }
                EngineEvent::TabNavigated { tab_id, origin } => {
                    assert_eq!(origin, "https://evil.com", "tab should commit the new origin");
                    swapped = true;
                    let _ = tab_id;
                }
                EngineEvent::FrameReady { tab_id, .. } => {
                    // The frame must arrive *after* the swap, from the new
                    // renderer — never a cross-origin render by the old one.
                    assert!(swapped, "rendered before the renderer was swapped");
                    framed_after_swap = true;
                    engine.close_tab(tab_id).unwrap();
                }
                EngineEvent::TabClosed { .. } => engine.shutdown().unwrap(),
                EngineEvent::NavigationFailed { reason, .. } => panic!("nav should swap, not fail: {reason}"),
                EngineEvent::TabCrashed { .. } => panic!("swap must not surface as a crash"),
                EngineEvent::EngineShutdown => break,
                _ => {}
            }
        }
        assert!(swapped && framed_after_swap);
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
