//! Phase 2: a per-origin renderer component.
//!
//! It holds no cookies, no DOM of other origins, and no network capability.
//! Everything it needs it must request from the parent engine over its IPC
//! endpoint, and the parent decides. The renderer for `attacker.com` acts
//! compromised on purpose to show that the broker, not the renderer, is the
//! security boundary.
//!
//! The `serve` loop is transport-agnostic: in multi-process mode it runs in
//! its own child process, in single-process mode as a thread of the engine.
//! Only the process boundary changes — the protocol and policy do not.

use crate::ipc::{Endpoint, FromRenderer, ToRenderer};

const TILE_W: u32 = 512;
const TILE_H: u32 = 512;

fn log(origin: &str, msg: &str) {
    let color = if origin.starts_with("attacker") { "1;31" } else { "1;32" };
    eprintln!("\x1b[{color}m[{origin:<12}]\x1b[0m {msg}");
}

/// Multi-process entry point: connect back to the engine, authenticate, serve.
#[cfg(feature = "multi-process")]
pub fn run(socket_path: &str, origin: &str, token: &str) {
    use crate::ipc::{self, Hello};
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(socket_path).expect("renderer: connect to engine");
    ipc::send_msg(&mut stream, &Hello { token: token.to_string() }).unwrap();
    serve(Endpoint::Socket(stream), origin);
}

/// The actual renderer loop — identical in both modes.
pub fn serve(mut ep: Endpoint, origin: &str) {
    log(origin, &format!("up (pid {}) — no cookie jar, no sockets, just pixels", std::process::id()));

    loop {
        let cmd: ToRenderer = match ep.recv() {
            Ok(cmd) => cmd,
            Err(_) => break,
        };
        match cmd {
            ToRenderer::RenderPage { url, quiet } => render_page(&mut ep, origin, &url, quiet),
            ToRenderer::SimulateCompromise => {
                log(origin, "malicious payload hit the rasterizer — memory corrupted, aborting");
                // Stand-in for the issue's buffer-overflow scenario: the
                // process dies violently (SIGABRT). In multi-process mode it
                // takes only itself down; in single-process mode this would
                // kill the entire browser, which is why the parent never
                // sends this command to a thread-backed renderer.
                std::process::abort();
            }
            ToRenderer::Shutdown => break,
            other => log(origin, &format!("unexpected command: {other:?}")),
        }
    }
}

fn render_page(ep: &mut Endpoint, origin: &str, url: &str, quiet: bool) {
    // 1. Subresource fetch — must go through the broker (Phase 1).
    if !quiet {
        log(origin, &format!("render {url}: requesting subresource via broker"));
    }
    ep.send(&FromRenderer::NeedFetch { url: format!("{url}/app.js") }).unwrap();
    match ep.recv::<ToRenderer>().unwrap() {
        ToRenderer::FetchResult { status, body } if !quiet => {
            log(origin, &format!("got subresource: HTTP {status}, {} bytes", body.len()))
        }
        ToRenderer::FetchDenied { reason } => log(origin, &format!("fetch denied: {reason}")),
        _ => {}
    }

    // 2. Own cookies — allowed, but only via the broker (Phase 2).
    ep.send(&FromRenderer::NeedCookies { origin: origin.to_string() }).unwrap();
    match ep.recv::<ToRenderer>().unwrap() {
        ToRenderer::Cookies(Some(cookies)) if !quiet => {
            log(origin, &format!("own cookies granted: {cookies:?}"))
        }
        ToRenderer::Cookies(None) => log(origin, "own cookies DENIED (unexpected)"),
        _ => {}
    }

    // 3. The attacker.com renderer behaves as if exploited: it tries to reach
    //    across the origin boundary. Pre-#1080 (single process) both of these
    //    would trivially succeed — the data lives in the same address space.
    if origin == "attacker.com" {
        log(origin, "😈 compromised! trying to steal example.com session cookies...");
        ep.send(&FromRenderer::NeedCookies { origin: "example.com".into() }).unwrap();
        match ep.recv::<ToRenderer>().unwrap() {
            ToRenderer::Cookies(None) => {
                log(origin, "😤 broker refused — cross-origin cookies unreachable")
            }
            ToRenderer::Cookies(Some(c)) => log(origin, &format!("💰 GOT THEM: {c:?} (BUG!)")),
            _ => {}
        }

        log(origin, "😈 trying SSRF against the cloud metadata service...");
        ep.send(&FromRenderer::NeedFetch {
            url: "http://169.254.169.254/latest/meta-data/iam/credentials".into(),
        })
        .unwrap();
        match ep.recv::<ToRenderer>().unwrap() {
            ToRenderer::FetchDenied { reason } => log(origin, &format!("😤 blocked: {reason}")),
            ToRenderer::FetchResult { .. } => log(origin, "💰 metadata service reached (BUG!)"),
            _ => {}
        }
    }

    // 4. Rasterize and ship the tile back — the ~1 MB texture transfer the
    //    issue budgets for each frame.
    let pixels = vec![0xAB; (TILE_W * TILE_H * 4) as usize];
    ep.send(&FromRenderer::Tile { width: TILE_W, height: TILE_H, pixels }).unwrap();
}
