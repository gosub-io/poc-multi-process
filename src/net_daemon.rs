//! Phase 1: the network component (`gosub-net-daemon` in the issue).
//!
//! In multi-process mode this runs as a separate child process — the only
//! process in the architecture allowed to open outbound connections (a
//! production build would enforce that with seccomp/landlock). In
//! single-process mode the very same `serve` loop runs as a thread: the
//! policy checks still apply, but there is no hard boundary behind them.
//!
//! Fetching follows redirects, and the SSRF classifier runs on **every hop**,
//! not just the entry URL — an open redirect to an internal address is the
//! classic way past an entry-only check. Each hop is re-resolved and re-pinned
//! through the [`Resolver`] seam, the chain is bounded, and a redirect that
//! crosses an origin drops the request's cookies rather than leaking them
//! onward. See [`handle_fetch`].

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
    // Loop ends when `recv` errors (engine went away) or on `Shutdown`.
    while let Ok(req) = ep.recv::<NetRequest>() {
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
                let outcome = handle_fetch(&requester, &url, &cookies, &SyntheticResolver);
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

/// Redirect chain bound. Large enough for real navigation, small enough that a
/// redirect *loop* terminates as a refusal rather than spinning forever. Every
/// mainstream browser caps this around 20; 10 is plenty for the PoC.
const MAX_REDIRECTS: u32 = 10;

/// What the (synthetic) origin server returns for one request: a body, or a
/// redirect the client must follow. Real HTTP lives here in a production
/// component; the PoC models just enough to exercise the redirect-following
/// policy — which is the security-relevant part.
enum ServerReply {
    Body { status: u16, body: Vec<u8> },
    Redirect { location: String },
}

/// The (synthetic) origin server. Recognised paths:
/// - `/redirect-loop…` redirects to itself (exercises the hop cap).
/// - `/relative-redirect` returns `Location: /landing` (root-relative, same origin).
/// - `/redirect/<rest>` returns `Location: <rest>` when `<rest>` carries a
///   scheme, else `http://<rest>/` — a targeted, usually cross-origin redirect,
///   the open-redirect an SSRF abuses.
/// - anything else is a 200 body naming how many cookies were attached.
fn synthetic_server(url: &str, cookies: &[(String, String)]) -> ServerReply {
    let path = path_of(url);
    if path.starts_with("/redirect-loop") {
        return ServerReply::Redirect { location: url.to_string() };
    }
    if path.starts_with("/relative-redirect") {
        return ServerReply::Redirect { location: "/landing".into() };
    }
    if let Some(rest) = path.strip_prefix("/redirect/") {
        let location =
            if rest.contains("://") { rest.to_string() } else { format!("http://{rest}/") };
        return ServerReply::Redirect { location };
    }
    // A real implementation would set `Cookie: name=value; ...` on the outbound
    // request from `cookies` and perform the HTTP fetch here; the PoC
    // synthesizes the response so it runs offline and deterministically.
    let body =
        format!("<html><!-- 200 OK for {url}; {} cookie(s) attached --></html>", cookies.len())
            .into_bytes();
    ServerReply::Body { status: 200, body }
}

/// The path (with any query/fragment) of a URL, or `/` if it has none.
fn path_of(url: &str) -> &str {
    match url.split_once("://") {
        Some((_, rest)) => match rest.find('/') {
            Some(i) => &rest[i..],
            None => "/",
        },
        None => "/",
    }
}

/// `scheme://authority` of a URL, for resolving root-relative redirects and
/// comparing origins. Deliberately coarse (keeps userinfo/port verbatim): a
/// mismatch only makes a cookie decision err on the *drop* side.
fn origin_prefix(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    let authority = rest.split(['/', '?', '#']).next()?;
    (!authority.is_empty()).then(|| format!("{scheme}://{authority}"))
}

/// Whether two URLs share a `scheme://authority`. Used to decide if cookies may
/// follow a redirect.
fn same_authority(a: &str, b: &str) -> bool {
    match (origin_prefix(a), origin_prefix(b)) {
        (Some(x), Some(y)) => x.eq_ignore_ascii_case(&y),
        _ => false,
    }
}

/// Resolve a `Location` against the URL it was returned from: an absolute URL
/// (has a scheme) is used as-is; a root-relative path is joined onto the current
/// origin. Anything else (a bare relative path) is not modeled → `None`.
fn resolve_redirect_target(current: &str, location: &str) -> Option<String> {
    if location.contains("://") {
        Some(location.to_string())
    } else if let Some(path) = location.strip_prefix('/') {
        Some(format!("{}/{}", origin_prefix(current)?, path))
    } else {
        None
    }
}

/// Perform a fetch, following the server's redirects.
///
/// `requester` is the `zone-N/origin` identity the engine recorded; a real
/// component uses it for per-partition network policy. `cookies` are that
/// partition's cookies (including HttpOnly) the engine wants attached — the net
/// component is the only process outside the engine that sees their values.
///
/// The security-critical property is that [`resolve_and_pin`] runs on **every**
/// hop, the entry URL and each `Location` alike. An entry-only check is a
/// classic SSRF hole: the entry is public, the server 302s to
/// `http://169.254.169.254/`, and a naive client follows it. Here each hop is
/// re-resolved and re-pinned, so a redirect into blocked space is refused even
/// when the entry was allowed, and the chain is bounded by [`MAX_REDIRECTS`] so
/// a loop terminates.
///
/// Cookies do not cross an origin boundary. The engine handed us *this* origin's
/// cookies, so a redirect to a different origin drops them rather than leaking
/// them onward — a redirect-following fetcher that kept them would send one
/// origin's session token to another host. A real component would instead ask
/// the engine for the new origin's cookies; dropping is the safe subset.
fn handle_fetch(
    _requester: &str,
    start_url: &str,
    cookies: &[(String, String)],
    resolver: &impl Resolver,
) -> FetchOutcome {
    let mut url = start_url.to_string();
    let mut carry_cookies = true;
    let mut hops = 0u32;

    loop {
        // Policy + destination for THIS hop — re-resolved and re-pinned every
        // iteration. `_pinned.addr` is the address a real component would
        // connect to (connecting to the *name* would re-resolve and undo it).
        if let Err(reason) = resolve_and_pin(&url, resolver) {
            return FetchOutcome::Denied { reason };
        }

        // A large body is terminal and copied in-band here (the streaming path
        // in `serve` handles it when fd-passing is available). The 16 MiB frame
        // cap stays authoritative: beyond it the honest answer is a refusal.
        if let Some(body_len) = blob_len(&url) {
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

        let effective: &[(String, String)] = if carry_cookies { cookies } else { &[] };
        match synthetic_server(&url, effective) {
            ServerReply::Body { status, body } => return FetchOutcome::Ok { status, body },
            ServerReply::Redirect { location } => {
                hops += 1;
                if hops > MAX_REDIRECTS {
                    return FetchOutcome::Denied {
                        reason: format!("too many redirects (> {MAX_REDIRECTS})"),
                    };
                }
                let Some(next) = resolve_redirect_target(&url, &location) else {
                    return FetchOutcome::Denied {
                        reason: format!("unfollowable redirect Location: {location}"),
                    };
                };
                // Once a hop leaves the original origin, this origin's cookies
                // stop travelling — and do not come back on a redirect home.
                if carry_cookies && !same_authority(&url, &next) {
                    carry_cookies = false;
                }
                url = next;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ip_utils::Resolver;
    use std::net::IpAddr;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// A resolver where one name points into private space and everything else
    /// is public — so a hop to `internal.example` proves the per-hop check
    /// re-*resolves* (not merely re-classifies an IP literal).
    struct RedirectResolver;
    impl Resolver for RedirectResolver {
        fn resolve(&self, host: &str) -> std::io::Result<Vec<IpAddr>> {
            Ok(match host.to_ascii_lowercase().as_str() {
                "internal.example" => vec![ip("10.0.0.5")],
                _ => vec![ip("93.184.216.34")],
            })
        }
    }

    fn body_text(o: &FetchOutcome) -> String {
        match o {
            FetchOutcome::Ok { body, .. } => String::from_utf8_lossy(body).into_owned(),
            other => panic!("expected an Ok body, got {other:?}"),
        }
    }

    #[test]
    fn follows_a_redirect_to_a_public_body() {
        let out =
            handle_fetch("r", "https://example.com/redirect/example.com", &[], &RedirectResolver);
        assert!(matches!(out, FetchOutcome::Ok { status: 200, .. }));
    }

    /// The property #4 exists for: entry public, `Location` link-local (cloud
    /// metadata). An entry-only check would have followed it.
    #[test]
    fn a_redirect_to_an_internal_literal_is_refused_at_the_hop() {
        let out = handle_fetch(
            "r",
            "https://example.com/redirect/169.254.169.254",
            &[],
            &RedirectResolver,
        );
        match out {
            FetchOutcome::Denied { reason } => {
                assert!(reason.contains("169.254"), "reason should name the address: {reason}");
                assert!(reason.contains("SSRF"), "reason should cite the policy: {reason}");
            }
            other => panic!("expected Denied, got {other:?}"),
        }
    }

    /// Proves the hop is re-*resolved*: the `Location` is a bare name only the
    /// resolver knows maps to 10.0.0.5.
    #[test]
    fn a_redirect_to_a_name_resolving_internal_is_refused() {
        let out = handle_fetch(
            "r",
            "https://example.com/redirect/internal.example",
            &[],
            &RedirectResolver,
        );
        match out {
            FetchOutcome::Denied { reason } => {
                assert!(reason.contains("10.0.0.5"), "reason should name the address: {reason}")
            }
            other => panic!("expected Denied, got {other:?}"),
        }
    }

    #[test]
    fn a_redirect_loop_terminates_as_too_many_redirects() {
        let out = handle_fetch("r", "https://example.com/redirect-loop", &[], &RedirectResolver);
        match out {
            FetchOutcome::Denied { reason } => {
                assert!(reason.contains("too many redirects"), "{reason}")
            }
            other => panic!("expected Denied, got {other:?}"),
        }
    }

    #[test]
    fn an_internal_entry_url_is_still_refused() {
        let out = handle_fetch("r", "http://127.0.0.1/", &[], &RedirectResolver);
        assert!(matches!(out, FetchOutcome::Denied { .. }));
    }

    /// A redirect that changes origin must not carry this origin's cookies; a
    /// same-origin (root-relative) redirect keeps them.
    #[test]
    fn cookies_do_not_cross_an_origin_boundary_on_redirect() {
        let cookies = vec![("sid".to_string(), "secret".to_string())];

        let out = handle_fetch(
            "r",
            "https://example.com/redirect/other.example",
            &cookies,
            &RedirectResolver,
        );
        assert!(
            body_text(&out).contains("0 cookie"),
            "cookies must not follow a cross-origin redirect: {}",
            body_text(&out)
        );

        let out =
            handle_fetch("r", "https://example.com/relative-redirect", &cookies, &RedirectResolver);
        assert!(
            body_text(&out).contains("1 cookie"),
            "a same-origin redirect keeps cookies: {}",
            body_text(&out)
        );
    }
}
