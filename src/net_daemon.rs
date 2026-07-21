//! Phase 1: the network component (`gosub-net-daemon` in the issue).
//!
//! In multi-process mode this runs as a separate child process — the only
//! process in the architecture allowed to open outbound connections (a
//! production build would enforce that with seccomp/landlock). In
//! single-process mode the very same `serve` loop runs as a thread: the
//! policy checks still apply, but there is no hard boundary behind them.

use crate::ip_utils::{resolve_and_pin, Resolver};
use crate::ipc::{Endpoint, FetchOutcome, NetRequest, NetResponse};

/// Multi-process entry point: adopt the inherited IPC link, sandbox, serve.
/// `link` is the transport's argv token for the channel end the engine handed
/// us — possessing it is our authentication (see [`crate::renderer::run`]).
#[cfg(feature = "multi-process")]
pub fn run(link: &str) {
    // SAFETY: the engine passed us sole ownership of this inherited channel.
    let ch = unsafe { crate::channel::Channel::from_argv(link) }.expect("net: bad link arg");
    // Split before sandboxing (on Unix the split's dup is not on the allowlist).
    let ep = Endpoint::from_channel(ch).expect("net: wrap link");
    // The net component keeps network access (it is the one process that has
    // it) but still drops exec/io_uring/openat/etc.
    crate::sandbox::lock_down_net();
    serve(ep);
}

/// The component loop — transport-agnostic, identical in both modes.
/// The resolver this PoC runs against.
///
/// The net component synthesizes its responses offline and deterministically,
/// so it must not perform real DNS — a test host with no network would other-
/// wise fail every fetch. This stands in for a resolver without weakening the
/// policy it feeds: loopback names still answer loopback, so they are still
/// refused, and they are refused by the *same* resolution path a real deploy-
/// ment uses rather than by a special-case string match.
///
/// A real net component swaps in `ip_utils::SystemResolver` and connects to
/// the returned `Pinned::addr` — connecting to the *name* instead would
/// re-resolve and undo the pin.
struct SyntheticResolver;

impl Resolver for SyntheticResolver {
    fn resolve(&self, host: &str) -> std::io::Result<Vec<std::net::IpAddr>> {
        let lower = host.to_ascii_lowercase();
        if lower == "localhost" || lower.ends_with(".localhost") {
            return Ok(vec![std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)]);
        }
        // Any other name answers one fixed public address.
        Ok(vec![std::net::IpAddr::V4(std::net::Ipv4Addr::new(93, 184, 216, 34))])
    }
}

pub fn serve(mut ep: Endpoint) {
    loop {
        let req: NetRequest = match ep.recv() {
            Ok(req) => req,
            Err(_) => break, // engine went away
        };
        match req {
            NetRequest::Shutdown => break,
            NetRequest::Fetch { request_id, for_zone, for_origin, url, cookies } => {
                // Large bodies stream through a shared-memory ring when the
                // transport can carry the fd (SSRF policy still applies
                // first). `GOSUB_BODY_TRANSPORT=socket` forces the in-band
                // copy so the bench can compare the two.
                #[cfg(all(feature = "multi-process", target_os = "linux"))]
                if resolve_and_pin(&url, &SyntheticResolver).is_ok()
                    && ep.tx.supports_fd_passing()
                    && !std::env::var_os("GOSUB_BODY_TRANSPORT").is_some_and(|v| v == "socket")
                {
                    if let Some(body_len) = blob_len(&url) {
                        if stream_blob(&mut ep, request_id, body_len).is_err() {
                            break; // engine went away mid-stream setup
                        }
                        continue;
                    }
                }

                // The request id travels with the reply so the engine can
                // route it back to the tab that asked, even with many
                // fetches in flight.
                let requester = format!("zone-{for_zone}/{for_origin}");
                let outcome = handle_fetch(&requester, &url, &cookies);
                let resp = NetResponse { request_id, outcome };
                if ep.send(&resp).is_err() {
                    break;
                }
            }
        }
    }
}

/// The deterministic byte at position `i` of every synthesized large body.
/// Public so the consumer side can byte-compare a delivered body against what
/// this component must have produced — the ring's round-trip check.
pub fn body_pattern(i: usize) -> u8 {
    (i.wrapping_mul(131) ^ (i >> 7)) as u8
}

/// `https://host/blob/<n>` synthesizes an `n`-MiB body — the PoC's stand-in
/// for a large download (an image, a video segment). 1–256 MiB.
fn blob_len(url: &str) -> Option<u64> {
    let path = url.split("://").nth(1)?.split_once('/')?.1;
    let mib: u64 = path.strip_prefix("blob/")?.parse().ok()?;
    (1..=256).contains(&mib).then(|| mib * 1024 * 1024)
}

/// Ring window for streamed bodies. Small on purpose: a 64 MiB body wraps
/// through it hundreds of times, and neither producer nor consumer ever
/// holds more than this (plus one chunk) for the transport.
#[cfg(all(feature = "multi-process", target_os = "linux"))]
const RING_CAPACITY: u32 = 256 * 1024;

/// Stream a synthesized `body_len`-byte body through a shared-memory ring:
/// header in-band first (so the consumer knows to start draining), ring fd
/// right behind it via `SCM_RIGHTS`, then produce chunk by chunk — the whole
/// body never exists in this process. `Err` means the engine link is gone; a
/// dead *consumer* only costs this stream (bounded by the ring's stall
/// timeout), not the component.
#[cfg(all(feature = "multi-process", target_os = "linux"))]
fn stream_blob(ep: &mut Endpoint, request_id: u64, body_len: u64) -> std::io::Result<()> {
    use crate::ipc::FetchOutcome;
    use std::os::fd::AsRawFd;

    let (mut producer, fd) = match crate::ring::RingProducer::create(RING_CAPACITY) {
        Ok(pair) => pair,
        Err(e) => {
            eprintln!("[net] ring setup failed ({e}); denying stream");
            let outcome = FetchOutcome::Denied { reason: "body stream setup failed".into() };
            return ep.send(&NetResponse { request_id, outcome });
        }
    };
    let outcome = FetchOutcome::OkStreaming { status: 200, body_len };
    ep.send(&NetResponse { request_id, outcome })?;
    ep.tx.send_fd(fd.as_raw_fd())?;
    drop(fd); // the consumer got its duplicate; our mapping needs no fd

    let mut chunk = vec![0u8; 64 * 1024];
    let mut sent = 0u64;
    while sent < body_len {
        let n = chunk.len().min((body_len - sent) as usize);
        for (i, b) in chunk[..n].iter_mut().enumerate() {
            *b = body_pattern(sent as usize + i);
        }
        if let Err(e) = producer.write_all(&chunk[..n]) {
            // Consumer gone, stalled, or corrupt: abandon this stream (the
            // producer's Drop marks the ring aborted). The engine link is
            // fine, so keep serving other fetches.
            eprintln!("[net] body stream abandoned after {sent} bytes: {e}");
            return Ok(());
        }
        sent += n as u64;
    }
    producer.finish();
    Ok(())
}

/// `requester` is the `zone-N/origin` identity as recorded by the engine; a
/// real implementation uses it for per-partition network policy. `cookies` are
/// that partition's cookies (including HttpOnly) the engine wants attached to
/// this request — the net component is the only process outside the engine
/// that sees their values.
fn handle_fetch(_requester: &str, url: &str, cookies: &[(String, String)]) -> FetchOutcome {
    // Policy and destination in one step: what comes back is the address a
    // real component would connect to, not a verdict it would then re-resolve.
    let _pinned = match resolve_and_pin(url, &SyntheticResolver) {
        Ok(pinned) => pinned,
        Err(reason) => return FetchOutcome::Denied { reason },
    };
    // A large body on a transport without fd passing (single-process mode,
    // or the bench's forced-socket comparison) is copied in-band — if it
    // fits. The 16 MiB frame cap is DoS protection and stays authoritative:
    // beyond it the honest answer is a refusal, not a raised limit.
    if let Some(body_len) = blob_len(url) {
        const MAX_INLINE_BLOB: u64 = 12 * 1024 * 1024; // frame cap minus headroom
        if body_len > MAX_INLINE_BLOB {
            return FetchOutcome::Denied {
                reason: "body too large for in-band transport (needs the shm ring)".into(),
            };
        }
        let mut body = vec![0u8; body_len as usize];
        for (i, b) in body.iter_mut().enumerate() {
            *b = body_pattern(i);
        }
        return FetchOutcome::Ok { status: 200, body };
    }
    // A real implementation would set `Cookie: name=value; ...` on the
    // outbound request from `cookies` and perform the HTTP fetch here; the PoC
    // synthesizes the response so it runs offline and deterministically.
    let body = format!(
        "<html><!-- 200 OK for {url}; {} cookie(s) attached --></html>",
        cookies.len()
    )
    .into_bytes();
    FetchOutcome::Ok { status: 200, body }
}
