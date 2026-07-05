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

struct Tab {
    /// The origin this tab's renderer was created for. This is the
    /// *authoritative* identity — policy decisions use this, never claims
    /// made over IPC.
    origin: String,
    tx: EndpointTx,
    handle: ChildHandle,
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

        self.tabs.insert(tab_id, Tab { origin: origin.clone(), tx, handle });
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
                // Forward to the net component, stamped with the identity
                // the engine knows for this tab — the renderer cannot spoof
                // it. The reply is matched back via the request id.
                let request_id = self.next_request_id;
                self.next_request_id += 1;
                self.pending_fetches.insert(request_id, tab_id);
                let req =
                    NetRequest::Fetch { request_id, for_origin: tab.origin.clone(), url };
                if self.net_tx.send(&req).is_err() {
                    self.pending_fetches.remove(&request_id);
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
        self.spawner.cleanup();
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
    Multi {
        exe: std::path::PathBuf,
        listener: std::os::unix::net::UnixListener,
        sock_path: String,
        sock_dir: std::path::PathBuf,
    },
}

impl Spawner {
    fn new(mode: Mode) -> Spawner {
        match mode {
            Mode::Single => Spawner::Single,
            #[cfg(feature = "multi-process")]
            Mode::Multi => {
                let sock_dir =
                    std::env::temp_dir().join(format!("gosub-poc-{}", std::process::id()));
                std::fs::create_dir_all(&sock_dir).unwrap();
                let sock_path = sock_dir.join("broker.sock");
                let listener = std::os::unix::net::UnixListener::bind(&sock_path).unwrap();
                Spawner::Multi {
                    exe: std::env::current_exe().unwrap(),
                    listener,
                    sock_path: sock_path.to_str().unwrap().to_string(),
                    sock_dir,
                }
            }
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
            // Multi-process: re-exec ourselves in the child role; the child
            // connects back and authenticates with a one-time token.
            //
            // Production note: the real implementation should pass one end of
            // a `socketpair(2)` as an inherited fd instead of a filesystem
            // rendezvous path plus token — unforgeable, nothing on disk.
            #[cfg(feature = "multi-process")]
            Spawner::Multi { exe, listener, sock_path, .. } => {
                use std::time::{SystemTime, UNIX_EPOCH};
                let (role_args, label): (Vec<&str>, &str) = match role {
                    Role::Net => (vec!["net-daemon"], "net"),
                    Role::Renderer(origin) => (vec!["renderer", origin], origin),
                };
                let nonce =
                    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().subsec_nanos();
                let token = format!("tok-{label}-{}-{nonce}", std::process::id());

                let child = std::process::Command::new(exe)
                    .args(&role_args)
                    .arg(sock_path)
                    .arg(&token)
                    .spawn()
                    .expect("spawn child process");

                let (mut stream, _) = listener.accept().expect("accept child connection");
                let hello: ipc::Hello = ipc::recv_msg(&mut stream).expect("child hello");
                assert_eq!(hello.token, token, "child failed authentication");
                let ep = Endpoint::from_stream(stream).expect("split child stream");
                (ChildHandle::Process(child), ep)
            }
        }
    }

    fn cleanup(&self) {
        #[cfg(feature = "multi-process")]
        if let Spawner::Multi { sock_dir, .. } = self {
            let _ = std::fs::remove_dir_all(sock_dir);
        }
    }
}
