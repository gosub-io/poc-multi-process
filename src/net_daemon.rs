//! Phase 1: the network component (`gosub-net-daemon` in the issue).
//!
//! In multi-process mode this runs as a separate child process — the only
//! process in the architecture allowed to open outbound connections (a
//! production build would enforce that with seccomp/landlock). In
//! single-process mode the very same `serve` loop runs as a thread: the
//! policy checks still apply, but there is no hard boundary behind them.

use crate::ipc::{Endpoint, FetchOutcome, NetRequest, NetResponse};

/// Multi-process entry point: connect back to the engine, authenticate, serve.
#[cfg(feature = "multi-process")]
pub fn run(socket_path: &str, token: &str) {
    use crate::ipc::{self, Hello};
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(socket_path).expect("net: connect to engine");
    ipc::send_msg(&mut stream, &Hello { token: token.to_string() }).unwrap();
    // The net component keeps network access (it is the one process that has
    // it) but still drops exec/ptrace.
    crate::sandbox::lock_down_net();
    // Optional live demonstration: same probe as the renderer, but here
    // network is expected to be ALLOWED and only exec DENIED.
    if std::env::var_os("GOSUB_POC_PROBE").is_some() {
        crate::sandbox::probe_io("net");
    }
    serve(Endpoint::from_stream(stream).expect("net: split stream"));
}

/// The component loop — transport-agnostic, identical in both modes.
pub fn serve(mut ep: Endpoint) {
    loop {
        let req: NetRequest = match ep.recv() {
            Ok(req) => req,
            Err(_) => break, // engine went away
        };
        match req {
            NetRequest::Shutdown => break,
            NetRequest::Fetch { request_id, for_origin, url } => {
                // The request id travels with the reply so the engine can
                // route it back to the tab that asked, even with many
                // fetches in flight.
                let resp = NetResponse { request_id, outcome: handle_fetch(&for_origin, &url) };
                if ep.send(&resp).is_err() {
                    break;
                }
            }
        }
    }
}

/// `for_origin` is the requesting renderer's identity as recorded by the
/// engine; a real implementation uses it for per-origin network policy
/// (CORS, cookie attachment, request headers).
fn handle_fetch(_for_origin: &str, url: &str) -> FetchOutcome {
    if let Some(reason) = ssrf_block_reason(url) {
        return FetchOutcome::Denied { reason };
    }
    // A real implementation performs the HTTP request here; the PoC
    // synthesizes the response so it runs offline and deterministically.
    let body = format!("<html><!-- 200 OK, served for {url} --></html>").into_bytes();
    FetchOutcome::Ok { status: 200, body }
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
