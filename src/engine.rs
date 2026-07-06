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

use crate::events::{EngineCommand, EngineEvent, TabCommand, TabId, Tile};
use crate::ipc::{
    self, Endpoint, EndpointTx, FetchOutcome, FromRenderer, NetRequest, NetResponse, ToRenderer,
};
use crate::{net_daemon, renderer};
use std::collections::HashMap;
use std::io;
use std::sync::mpsc::{self, Receiver, Sender};

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

    pub fn open_tab(&self, url: impl Into<String>) -> io::Result<()> {
        self.send(EngineCommand::OpenTab { url: url.into() })
    }

    pub fn navigate(&self, tab_id: TabId, url: impl Into<String>) -> io::Result<()> {
        self.send(EngineCommand::Tab { tab_id, cmd: TabCommand::Navigate { url: url.into() } })
    }

    pub fn close_tab(&self, tab_id: TabId) -> io::Result<()> {
        self.send(EngineCommand::Tab { tab_id, cmd: TabCommand::Close })
    }

    pub fn set_cookie(
        &self,
        origin: impl Into<String>,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> io::Result<()> {
        self.send(EngineCommand::SetCookie {
            origin: origin.into(),
            name: name.into(),
            value: value.into(),
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
    /// A renderer's link died without a shutdown — crash, most likely.
    TabGone { tab_id: TabId },
    /// The net component answered a fetch.
    NetReply(NetResponse),
}

/// A running child component, however it is hosted.
enum ChildHandle {
    Thread(std::thread::JoinHandle<()>),
    #[cfg(feature = "multi-process")]
    Process(std::process::Child),
}

/// Per-tab cap on outstanding brokered fetches. Bounds the engine memory a
/// single (possibly compromised) renderer can pin by spamming `NeedFetch`
/// without waiting for replies. The 16 MiB frame cap only bounds one message;
/// this bounds how many can be in flight at once.
const MAX_INFLIGHT_FETCHES: usize = 32;

struct Tab {
    /// The origin this tab's renderer was created for. This is the
    /// *authoritative* identity — policy decisions use this, never claims
    /// made over IPC.
    origin: String,
    tx: EndpointTx,
    handle: ChildHandle,
    /// Number of this tab's fetches awaiting a reply from the net component.
    inflight_fetches: usize,
}

enum Role<'a> {
    Net,
    Renderer(&'a str),
}

struct EngineLoop {
    spawner: Spawner,
    /// Cloned into every reader thread so all sources feed one inbox.
    inbox: Sender<LoopMsg>,
    events: Sender<EngineEvent>,
    net_tx: EndpointTx,
    net_handle: ChildHandle,
    tabs: HashMap<TabId, Tab>,
    /// The engine's private state. Renderers can only get at this through
    /// the broker protocol — in multi-process mode it never even lives in
    /// their address space.
    cookies: HashMap<String, Vec<(String, String)>>,
    /// In-flight fetches: request id -> the tab awaiting the reply.
    pending_fetches: HashMap<u64, TabId>,
    next_tab_id: u64,
    next_request_id: u64,
}

impl EngineLoop {
    fn new(mode: Mode, inbox: Sender<LoopMsg>, events: Sender<EngineEvent>) -> EngineLoop {
        let spawner = Spawner::new(mode);

        // Bring up the net component and a reader thread that forwards its
        // replies into the inbox.
        let (net_handle, ep) = spawner.spawn(Role::Net);
        let (net_tx, mut net_rx) = ep.split();
        {
            let inbox = inbox.clone();
            std::thread::spawn(move || loop {
                match net_rx.recv::<NetResponse>() {
                    Ok(resp) => {
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
                LoopMsg::Command(EngineCommand::OpenTab { url }) => self.open_tab(&url),
                LoopMsg::Command(EngineCommand::Tab { tab_id, cmd }) => {
                    self.tab_command(tab_id, cmd)
                }
                LoopMsg::Command(EngineCommand::SetCookie { origin, name, value }) => {
                    self.cookies.entry(origin).or_default().push((name, value));
                }
                LoopMsg::Command(EngineCommand::Shutdown) => {
                    self.shutdown();
                    return;
                }
                LoopMsg::FromTab { tab_id, msg } => self.tab_request(tab_id, msg),
                LoopMsg::TabGone { tab_id } => {
                    // Only a crash if we didn't remove the tab ourselves
                    // (close/shutdown also end the link, after removal).
                    if let Some(tab) = self.tabs.remove(&tab_id) {
                        join(tab.handle);
                        self.pending_fetches.retain(|_, t| *t != tab_id);
                        self.emit(EngineEvent::TabCrashed { tab_id });
                    }
                }
                LoopMsg::NetReply(resp) => self.net_reply(resp),
            }
        }
    }

    fn open_tab(&mut self, url: &str) {
        let Some(origin) = origin_of(url) else {
            self.emit(EngineEvent::OpenTabFailed {
                url: url.to_string(),
                reason: "unparseable URL".into(),
            });
            return;
        };

        let tab_id = TabId(self.next_tab_id);
        self.next_tab_id += 1;

        let (handle, ep) = self.spawner.spawn(Role::Renderer(&origin));
        let (tx, mut rx) = ep.split();

        // Reader thread: forward everything this renderer says into the
        // inbox, tagged with the tab it belongs to; report EOF as TabGone.
        {
            let inbox = self.inbox.clone();
            std::thread::spawn(move || {
                loop {
                    match rx.recv::<FromRenderer>() {
                        Ok(msg) => {
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

        self.tabs.insert(tab_id, Tab { origin: origin.clone(), tx, handle, inflight_fetches: 0 });
        self.emit(EngineEvent::TabOpened { tab_id, origin });
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
                self.pending_fetches.insert(request_id, tab_id);
                tab.inflight_fetches += 1;
                let req =
                    NetRequest::Fetch { request_id, for_origin: tab.origin.clone(), url };
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
                // not the message contents.
                let reply = if requested == tab.origin {
                    ToRenderer::Cookies(self.cookies.get(&requested).cloned())
                } else {
                    ToRenderer::Cookies(None)
                };
                let _ = tab.tx.send(&reply);
            }
            FromRenderer::Tile { width, height, pixels } => {
                self.emit(EngineEvent::FrameReady {
                    tab_id,
                    tile: Tile { width, height, pixels },
                });
            }
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
        };
        let _ = tab.tx.send(&reply);
    }

    fn shutdown(&mut self) {
        for (_, mut tab) in self.tabs.drain() {
            let _ = tab.tx.send(&ToRenderer::Shutdown);
            join(tab.handle);
        }
        let _ = self.net_tx.send(&NetRequest::Shutdown);
        join(std::mem::replace(&mut self.net_handle, ChildHandle::Thread(dummy_thread())));
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
    }
}

/// `scheme://host` -> `host`. Good enough for the PoC; a real engine uses a
/// proper URL parser and the full origin tuple (scheme, host, port).
fn origin_of(url: &str) -> Option<String> {
    let rest = url.split("://").nth(1)?;
    let host = rest.split('/').next()?;
    if host.is_empty() {
        return None;
    }
    Some(host.to_string())
}

/// Knows how to bring up a child component in the selected mode. The mode
/// decision lives entirely here; everything above deals in `Endpoint`s and
/// `ChildHandle`s.
enum Spawner {
    Single,
    #[cfg(feature = "multi-process")]
    Multi { exe: std::path::PathBuf },
}

impl Spawner {
    fn new(mode: Mode) -> Spawner {
        match mode {
            Mode::Single => Spawner::Single,
            #[cfg(feature = "multi-process")]
            Mode::Multi => Spawner::Multi { exe: std::env::current_exe().unwrap() },
        }
    }

    fn spawn(&self, role: Role) -> (ChildHandle, Endpoint) {
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
            // Multi-process: re-exec ourselves in the child role, handing it
            // one end of a `socketpair(2)` as an *inherited file descriptor*.
            //
            // This is the whole authentication story: an inherited fd is
            // unforgeable, so there is no rendezvous path on disk, no auth
            // token on argv (which any local user could read via
            // /proc/<pid>/cmdline), and no accept() race for a local attacker
            // to win. Only the fd *number* travels on argv, and that is not a
            // secret.
            #[cfg(feature = "multi-process")]
            Spawner::Multi { exe } => {
                use std::os::fd::IntoRawFd;
                use std::os::unix::process::CommandExt;

                let role_args: Vec<&str> = match role {
                    Role::Net => vec!["net-daemon"],
                    Role::Renderer(origin) => vec!["renderer", origin],
                };

                let (parent_end, child_end) =
                    std::os::unix::net::UnixStream::pair().expect("socketpair");
                let child_fd = child_end.into_raw_fd();

                let mut cmd = std::process::Command::new(exe);
                cmd.args(&role_args).arg(child_fd.to_string());
                // Clear FD_CLOEXEC on the child's end (post-fork, pre-exec) so
                // it survives the exec. Every other fd the engine holds keeps
                // CLOEXEC and is therefore NOT leaked into the child — so one
                // renderer never inherits another's channel.
                unsafe {
                    cmd.pre_exec(move || {
                        // Impose resource ceilings before the child runs a line
                        // of its own code (inherited across exec).
                        crate::sandbox::apply_child_rlimits()?;
                        let flags = libc::fcntl(child_fd, libc::F_GETFD);
                        if flags < 0 {
                            return Err(std::io::Error::last_os_error());
                        }
                        if libc::fcntl(child_fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                            return Err(std::io::Error::last_os_error());
                        }
                        Ok(())
                    });
                }
                let child = cmd.spawn().expect("spawn child process");
                // The engine keeps only its own end; drop its copy of the
                // child's end so the socket reports EOF (→ TabCrashed) once the
                // child dies.
                unsafe { libc::close(child_fd) };

                let ep = Endpoint::from_stream(parent_end).expect("wrap parent end");
                (ChildHandle::Process(child), ep)
            }
        }
    }

}
