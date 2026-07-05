//! Phase 1: the network component (`gosub-net-daemon` in the issue).
//!
//! In multi-process mode this runs as a separate child process — the only
//! process in the architecture allowed to open outbound connections (a
//! production build would enforce that with seccomp/landlock). In
//! single-process mode the very same `serve` loop runs as a thread: the
//! policy checks still apply, but there is no hard boundary behind them.

use crate::ipc::{Endpoint, NetRequest, NetResponse};

fn log(msg: &str) {
    eprintln!("\x1b[1;33m[net    ]\x1b[0m {msg}");
}

/// Multi-process entry point: connect back to the engine, authenticate, serve.
#[cfg(feature = "multi-process")]
pub fn run(socket_path: &str, token: &str) {
    use crate::ipc::{self, Hello};
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(socket_path).expect("net-daemon: connect to engine");
    ipc::send_msg(&mut stream, &Hello { token: token.to_string() }).unwrap();
    serve(Endpoint::Socket(stream));
}

/// The actual daemon loop — transport-agnostic, identical in both modes.
pub fn serve(mut ep: Endpoint) {
    log(&format!(
        "up (pid {}) — sole owner of network capability",
        std::process::id()
    ));

    loop {
        let req: NetRequest = match ep.recv() {
            Ok(req) => req,
            Err(_) => break, // engine went away
        };
        match req {
            NetRequest::Shutdown => break,
            NetRequest::Fetch { for_origin, url, quiet } => {
                let resp = handle_fetch(&for_origin, &url, quiet);
                ep.send(&resp).unwrap();
            }
        }
    }
}

fn handle_fetch(for_origin: &str, url: &str, quiet: bool) -> NetResponse {
    if let Some(reason) = ssrf_block_reason(url) {
        log(&format!(
            "\x1b[1;31mDENIED\x1b[0m fetch of {url} (for {for_origin}): {reason}"
        ));
        return NetResponse::Denied { reason };
    }
    if !quiet {
        log(&format!("fetching {url} on behalf of {for_origin}"));
    }
    // A real daemon performs the HTTP request here; the PoC synthesizes the
    // response so it runs offline and deterministically.
    let body = format!("<html><!-- 200 OK, served for {url} --></html>").into_bytes();
    NetResponse::Ok { status: 200, body }
}

/// The centralized SSRF policy the issue calls for: requests to loopback,
/// link-local (cloud metadata!) and private ranges are rejected for all
/// renderers, no matter what a compromised renderer asks for.
fn ssrf_block_reason(url: &str) -> Option<String> {
    let host = match url.split("://").nth(1).and_then(|rest| rest.split('/').next()) {
        Some(host) => host.split(':').next().unwrap_or(host),
        None => return Some("unparseable URL".into()),
    };
    const BLOCKED_PREFIXES: &[&str] = &["127.", "10.", "192.168.", "169.254.", "0."];
    if host == "localhost" || BLOCKED_PREFIXES.iter().any(|p| host.starts_with(p)) {
        return Some(format!("host {host} is loopback/link-local/private (SSRF policy)"));
    }
    None
}
