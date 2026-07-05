//! The parent engine: spawns the net component and per-origin renderers,
//! owns the cookie jar, and brokers every privileged operation. This is the
//! `GosubEngine (parent)` box from issue #1080's diagram.
//!
//! It runs in one of two modes:
//! - `Mode::Multi`  — children are separate sandboxable processes (issue #1080)
//! - `Mode::Single` — children are threads in this process (classic engine)
//!
//! The broker protocol and all policy checks are identical in both modes;
//! only the transport and the spawning differ. What single-process mode
//! *cannot* offer is the hard boundary: the demos call that out where it
//! matters.

use crate::ipc::{self, Endpoint, FromRenderer, NetRequest, NetResponse, ToRenderer};
use crate::{net_daemon, renderer};
use std::collections::HashMap;
use std::time::Instant;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Single,
    #[cfg(feature = "multi-process")]
    Multi,
}

impl Mode {
    fn label(self) -> &'static str {
        match self {
            Mode::Single => "single-process (components are threads)",
            #[cfg(feature = "multi-process")]
            Mode::Multi => "multi-process (components are isolated processes)",
        }
    }
}

fn log(msg: &str) {
    eprintln!("\x1b[1;36m[engine  ]\x1b[0m {msg}");
}

fn banner(msg: &str) {
    eprintln!("\n\x1b[1m━━━ {msg} ━━━\x1b[0m");
}

/// A running child component, however it is hosted.
enum ChildHandle {
    Thread(std::thread::JoinHandle<()>),
    #[cfg(feature = "multi-process")]
    Process(std::process::Child),
}

struct RendererHandle {
    handle: ChildHandle,
    ep: Endpoint,
    /// The origin this component was created for. This is the *authoritative*
    /// identity — policy decisions use this, never claims made over IPC.
    origin: String,
}

type CookieJar = HashMap<String, Vec<(String, String)>>;

enum Role<'a> {
    Net,
    Renderer(&'a str),
}

/// Knows how to bring up a child component in the selected mode.
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
                (ChildHandle::Process(child), Endpoint::Socket(stream))
            }
        }
    }

    fn cleanup(self) {
        #[cfg(feature = "multi-process")]
        if let Spawner::Multi { sock_dir, .. } = self {
            let _ = std::fs::remove_dir_all(sock_dir);
        }
    }
}

pub fn run(mode: Mode) {
    eprintln!("\x1b[1mgosub issue #1080 PoC — multi-process architecture\x1b[0m");
    log(&format!("engine up (pid {}), mode: {}", std::process::id(), mode.label()));

    let spawner = Spawner::new(mode);

    // The engine's private state. Renderers can only get at this through the
    // broker protocol below — in multi-process mode it never even lives in
    // their address space.
    let mut jar: CookieJar = HashMap::new();
    jar.insert("example.com".into(), vec![("session".into(), "top-secret-session-token".into())]);
    jar.insert("attacker.com".into(), vec![("tracking".into(), "evil-id-42".into())]);

    banner("Phase 1: bring up the network component");
    let (net_handle, mut net) = spawner.spawn(Role::Net);
    log("network capability delegated; engine and renderers do no socket I/O themselves");

    banner("Phase 2: bring up one renderer per origin");
    let mut renderer_a = spawn_renderer(&spawner, "example.com");
    let mut renderer_b = spawn_renderer(&spawner, "attacker.com");

    banner("Demo 1: normal page render (example.com)");
    drive_render(&mut renderer_a, &mut net, &jar, false);

    banner("Demo 2: compromised renderer (attacker.com) probes the boundary");
    drive_render(&mut renderer_b, &mut net, &jar, false);
    if mode == Mode::Single {
        log("\x1b[1;33mnote:\x1b[0m policy held at the IPC layer, but in single-process mode the \
             renderer shares this address space — a real exploit reads the cookie jar from \
             memory directly, no IPC needed. The boundary only becomes real in multi-process mode.");
    }

    banner("Demo 3: IPC latency per frame (acceptance criterion: <10 ms)");
    const FRAMES: u32 = 100;
    let start = Instant::now();
    let mut worst = std::time::Duration::ZERO;
    for _ in 0..FRAMES {
        let t = Instant::now();
        drive_render(&mut renderer_a, &mut net, &jar, true);
        worst = worst.max(t.elapsed());
    }
    let avg = start.elapsed() / FRAMES;
    log(&format!(
        "{FRAMES} frames: each = 1 brokered fetch + 1 cookie lookup + 1 MiB tile transfer"
    ));
    log(&format!(
        "avg {:.3} ms, worst {:.3} ms per frame → criterion {}",
        avg.as_secs_f64() * 1e3,
        worst.as_secs_f64() * 1e3,
        if worst.as_millis() < 10 { "\x1b[1;32mMET\x1b[0m" } else { "\x1b[1;31mMISSED\x1b[0m" }
    ));

    banner("Demo 4: crash containment — exploit kills only its own process");
    match &mut renderer_b.handle {
        #[cfg(feature = "multi-process")]
        ChildHandle::Process(child) => {
            use std::os::unix::process::ExitStatusExt;
            renderer_b.ep.send(&ToRenderer::SimulateCompromise).unwrap();
            let status = child.wait().unwrap();
            log(&format!(
                "attacker.com renderer died with signal {:?} — engine, net component and other tabs unaffected",
                status.signal()
            ));
            log("re-rendering example.com to prove the rest of the browser still works:");
            drive_render(&mut renderer_a, &mut net, &jar, false);
        }
        ChildHandle::Thread(_) => {
            log("\x1b[1;33mskipped in single-process mode:\x1b[0m the simulated exploit calls \
                 abort() — here that would kill the ENTIRE browser (every tab, the cookie jar, \
                 the net stack). This is exactly the failure mode issue #1080 eliminates; \
                 run without --single-process to see it contained.");
            let _ = renderer_b.ep.send(&ToRenderer::Shutdown);
        }
    }
    join(renderer_b.handle);

    banner("Shutdown");
    let _ = renderer_a.ep.send(&ToRenderer::Shutdown);
    let _ = net.send(&NetRequest::Shutdown);
    join(renderer_a.handle);
    join(net_handle);
    spawner.cleanup();
    log("all child components reaped, clean exit");
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

fn spawn_renderer(spawner: &Spawner, origin: &str) -> RendererHandle {
    let (handle, ep) = spawner.spawn(Role::Renderer(origin));
    match &handle {
        ChildHandle::Thread(_) => log(&format!("renderer for {origin} running as thread")),
        #[cfg(feature = "multi-process")]
        ChildHandle::Process(child) => {
            log(&format!("renderer for {origin} spawned as process (pid {})", child.id()))
        }
    }
    RendererHandle { handle, ep, origin: origin.to_string() }
}

/// Ask a renderer to produce one frame, brokering every privileged request it
/// makes along the way. This loop *is* the security boundary — and it is the
/// same code in both modes.
fn drive_render(r: &mut RendererHandle, net: &mut Endpoint, jar: &CookieJar, quiet: bool) {
    let url = format!("https://{}", r.origin);
    r.ep.send(&ToRenderer::RenderPage { url, quiet }).unwrap();

    loop {
        let msg: FromRenderer = r.ep.recv().unwrap();
        match msg {
            FromRenderer::NeedFetch { url } => {
                // Forward to the net component, stamped with the identity the
                // engine knows for this endpoint — the renderer can't spoof it.
                net.send(&NetRequest::Fetch { for_origin: r.origin.clone(), url, quiet })
                    .unwrap();
                let reply = match net.recv::<NetResponse>().unwrap() {
                    NetResponse::Ok { status, body } => ToRenderer::FetchResult { status, body },
                    NetResponse::Denied { reason } => ToRenderer::FetchDenied { reason },
                };
                r.ep.send(&reply).unwrap();
            }
            FromRenderer::NeedCookies { origin } => {
                // Same-origin check against the endpoint's authoritative
                // identity, not the message contents.
                let reply = if origin == r.origin {
                    ToRenderer::Cookies(jar.get(&origin).cloned())
                } else {
                    log(&format!(
                        "\x1b[1;31mPOLICY VIOLATION\x1b[0m renderer for {} requested cookies of {origin} — denied",
                        r.origin
                    ));
                    ToRenderer::Cookies(None)
                };
                r.ep.send(&reply).unwrap();
            }
            FromRenderer::Tile { width, height, pixels } => {
                if !quiet {
                    log(&format!(
                        "compositing {width}x{height} tile ({} KiB) from {}",
                        pixels.len() / 1024,
                        r.origin
                    ));
                }
                break;
            }
        }
    }
}
