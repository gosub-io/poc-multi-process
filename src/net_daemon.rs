//! Phase 1: the network component (`gosub-net-daemon` in the issue).
//!
//! In multi-process mode this runs as a separate child process — the only
//! process in the architecture allowed to open outbound connections (a
//! production build would enforce that with seccomp/landlock). In
//! single-process mode the very same `serve` loop runs as a thread: the
//! policy checks still apply, but there is no hard boundary behind them.

use crate::ipc::{Endpoint, FetchOutcome, NetRequest, NetResponse};
use std::net::{IpAddr, Ipv4Addr};

/// Multi-process entry point: adopt the inherited IPC fd, sandbox, serve.
/// `fd` is the `socketpair(2)` end the engine handed us — possessing it is our
/// authentication (see [`crate::renderer::run`]).
#[cfg(feature = "multi-process")]
pub fn run(fd: &str) {
    use std::os::fd::FromRawFd;
    use std::os::unix::net::UnixStream;

    let fd: std::os::fd::RawFd = fd.parse().expect("net: bad fd arg");
    // SAFETY: the engine passed us sole ownership of this inherited fd.
    let stream = unsafe { UnixStream::from_raw_fd(fd) };
    // Split before sandboxing (try_clone's dup is not on the allowlist).
    let ep = Endpoint::from_stream(stream).expect("net: wrap fd");
    // The net component keeps network access (it is the one process that has
    // it) but still drops exec/io_uring/openat/etc.
    crate::sandbox::lock_down_net();
    serve(ep);
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
            NetRequest::Fetch { request_id, for_zone, for_origin, url, cookies } => {
                // Large bodies stream through a shared-memory ring when the
                // transport can carry the fd (SSRF policy still applies
                // first). `GOSUB_BODY_TRANSPORT=socket` forces the in-band
                // copy so the bench can compare the two.
                #[cfg(all(feature = "multi-process", target_os = "linux"))]
                if ssrf_block_reason(&url).is_none()
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
    if let Some(reason) = ssrf_block_reason(url) {
        return FetchOutcome::Denied { reason };
    }
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

/// The centralized SSRF policy the issue calls for: requests to loopback,
/// link-local (cloud metadata!), private and other internal ranges are
/// rejected for all renderers, no matter what a compromised renderer asks for.
///
/// The classification works on the *numeric* address, not a string prefix, so
/// it can't be slipped past with alternate encodings (`http://2130706433/`,
/// `0x7f.1`, `[::ffff:169.254.169.254]`), userinfo confusion
/// (`http://real.com@127.0.0.1/`), or a trailing dot. What it can't do here is
/// resolve a *hostname*: a real net component would resolve DNS and re-check
/// the resolved IPs, and pin that IP for the connection to defeat DNS
/// rebinding. The PoC synthesizes responses offline, so a non-literal host is
/// allowed with that caveat noted.
fn ssrf_block_reason(url: &str) -> Option<String> {
    // Scheme allowlist: the net component speaks HTTP(S) only. Anything else
    // (`file:`, `gopher:`, `ftp:`, …) is refused outright rather than reasoned
    // about — a renderer confined to its own *host* origin can still name a
    // non-HTTP scheme, since origin identity here is scheme-blind.
    match scheme_of(url) {
        Some(s) if s == "http" || s == "https" => {}
        Some(s) => return Some(format!("scheme {s}:// is not allowed (SSRF policy)")),
        None => return Some("unparseable URL".into()),
    }

    let Some(host) = host_of(url) else {
        return Some("unparseable URL".into());
    };

    // Names that resolve to loopback without touching a resolver.
    let lower = host.to_ascii_lowercase();
    if lower == "localhost" || lower.ends_with(".localhost") {
        return Some(format!("host {host} resolves to loopback (SSRF policy)"));
    }

    // If the host is an IP literal (in any accepted encoding), classify it.
    if let Some(ip) = parse_ip_literal(&host) {
        if let Some(category) = blocked_ip_reason(ip) {
            return Some(format!("host {host} is {category} (SSRF policy)"));
        }
    }
    None
}

/// The lowercased URL scheme (the part before `://`), or `None` if the URL has
/// no `scheme://` form at all.
fn scheme_of(url: &str) -> Option<String> {
    let (scheme, _) = url.split_once("://")?;
    (!scheme.is_empty()).then(|| scheme.to_ascii_lowercase())
}

/// Extract the host from a URL: drops the scheme, path/query/fragment, any
/// `user:pass@` userinfo, and the `:port`, and unwraps `[..]` around an IPv6
/// literal. Deliberately lenient — its job is to see the *same* host the OS
/// eventually connects to, including the tricks an attacker would use.
fn host_of(url: &str) -> Option<String> {
    let after_scheme = url.split("://").nth(1)?;
    let authority = after_scheme.split(['/', '?', '#']).next()?;
    // Userinfo confusion: real.com@127.0.0.1 connects to 127.0.0.1.
    let hostport = authority.rsplit_once('@').map_or(authority, |(_, hp)| hp);

    let host = if let Some(rest) = hostport.strip_prefix('[') {
        rest.split(']').next()? // [IPv6] or [IPv6]:port
    } else if hostport.matches(':').count() >= 2 {
        hostport // bare IPv6 literal (no port possible)
    } else {
        hostport.split(':').next()? // host or host:port
    };

    let host = host.trim_end_matches('.'); // FQDN trailing dot
    (!host.is_empty()).then(|| host.to_string())
}

/// Parse a host as an IP literal, accepting the alternate IPv4 encodings that
/// `inet_aton(3)`/browsers accept (a single decimal/octal/hex number, or fewer
/// than four dotted parts) — the encodings SSRF filters classically miss.
fn parse_ip_literal(host: &str) -> Option<IpAddr> {
    // Strip an IPv6 zone id (`fe80::1%eth0`, or percent-encoded `fe80::1%25eth0`)
    // before parsing, so a scoped link-local literal is still classified
    // numerically instead of slipping through as an "unresolvable hostname".
    let host = host.split('%').next().unwrap_or(host);
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Some(ip); // standard dotted-quad IPv4 or IPv6
    }
    parse_ipv4_inet_aton(host).map(IpAddr::V4)
}

fn parse_ipv4_inet_aton(host: &str) -> Option<Ipv4Addr> {
    let parts: Vec<u32> = host.split('.').map(parse_c_integer).collect::<Option<_>>()?;
    // 1–4 parts; the final part fills all remaining low-order bytes.
    let value: u32 = match parts.as_slice() {
        [a] => *a,
        [a, b] if *a <= 0xff && *b <= 0x00ff_ffff => (a << 24) | b,
        [a, b, c] if *a <= 0xff && *b <= 0xff && *c <= 0xffff => (a << 24) | (b << 16) | c,
        [a, b, c, d] if [a, b, c, d].iter().all(|&&x| x <= 0xff) => {
            (a << 24) | (b << 16) | (c << 8) | d
        }
        _ => return None,
    };
    Some(Ipv4Addr::from(value))
}

/// A C-style integer: `0x`/`0X` hex, a leading `0` octal, otherwise decimal.
fn parse_c_integer(s: &str) -> Option<u32> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).ok()
    } else if s.len() > 1 && s.starts_with('0') {
        u32::from_str_radix(&s[1..], 8).ok()
    } else {
        s.parse::<u32>().ok()
    }
}

/// Classify an IP against the ranges that must never be reachable from a
/// renderer. Returns the category name, or `None` if the address is public.
fn blocked_ip_reason(ip: IpAddr) -> Option<&'static str> {
    match ip {
        IpAddr::V4(v4) => blocked_v4(v4),
        IpAddr::V6(v6) => {
            // An IPv4-mapped address (::ffff:a.b.c.d) reaches an IPv4 host.
            if let Some(v4) = v6.to_ipv4_mapped() {
                return blocked_v4(v4);
            }
            let seg = v6.segments();
            if v6.is_loopback() {
                Some("IPv6 loopback (::1)")
            } else if v6.is_unspecified() {
                Some("IPv6 unspecified (::)")
            } else if seg[0] & 0xfe00 == 0xfc00 {
                Some("IPv6 unique-local (fc00::/7)")
            } else if seg[0] & 0xffc0 == 0xfe80 {
                Some("IPv6 link-local (fe80::/10)")
            } else if v6.is_multicast() {
                Some("IPv6 multicast")
            } else {
                None
            }
        }
    }
}

fn blocked_v4(v4: Ipv4Addr) -> Option<&'static str> {
    let o = v4.octets();
    if v4.is_loopback() {
        Some("loopback (127.0.0.0/8)")
    } else if v4.is_private() {
        Some("private (10/8, 172.16/12, 192.168/16)")
    } else if v4.is_link_local() {
        Some("link-local 169.254.0.0/16 (cloud metadata)")
    } else if v4.is_unspecified() || o[0] == 0 {
        Some("\"this host\" (0.0.0.0/8)")
    } else if v4.is_broadcast() {
        Some("broadcast (255.255.255.255)")
    } else if o[0] == 100 && o[1] & 0xc0 == 64 {
        Some("shared/CGNAT (100.64.0.0/10)")
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_internal_ranges_and_encoding_bypasses() {
        for u in [
            // Standard internal ranges (incl. the previously-missed 172.16/12).
            "http://127.0.0.1/", "http://10.0.0.5/", "http://172.16.0.1/",
            "http://172.31.255.9/", "http://192.168.1.1/", "http://169.254.169.254/",
            "http://0.0.0.0/", "http://100.64.0.1/", "http://255.255.255.255/",
            // Names that resolve to loopback.
            "http://localhost/", "http://api.localhost/",
            // Alternate IPv4 encodings for 127.0.0.1.
            "http://2130706433/", "http://0x7f000001/", "http://017700000001/", "http://127.1/",
            // IPv6 internal + IPv4-mapped + scoped (zone id, raw and %25-encoded).
            "http://[::1]/", "http://[::ffff:169.254.169.254]/", "http://[fc00::1]/", "http://[fe80::1]/",
            "http://[fe80::1%eth0]/", "http://[fe80::1%25eth0]/",
            // Parser-confusion: userinfo and trailing dot.
            "http://real.com@127.0.0.1/", "http://127.0.0.1.:80/",
            // Non-HTTP schemes are refused outright, whatever the host.
            "file://example.com/etc/passwd", "gopher://example.com/", "ftp://127.0.0.1/",
        ] {
            assert!(ssrf_block_reason(u).is_some(), "should block {u}: {:?}", ssrf_block_reason(u));
        }
    }

    #[test]
    fn allows_only_http_schemes() {
        assert!(scheme_of("https://example.com/").as_deref() == Some("https"));
        assert!(scheme_of("HTTP://example.com/").as_deref() == Some("http")); // case-folded
        assert!(scheme_of("not-a-url").is_none());
        // A public host over http/https is fine; the same host over file:// is not.
        assert!(ssrf_block_reason("https://example.com/").is_none());
        assert!(ssrf_block_reason("file://example.com/").is_some());
    }

    #[test]
    fn allows_public_addresses() {
        for u in [
            "http://93.184.216.34/", "http://example.com/", "http://8.8.8.8/",
            "http://172.32.0.1/",   // just outside 172.16/12
            "http://100.128.0.1/",  // just outside 100.64/10
            "http://[2606:2800:220:1::1]/",
        ] {
            assert!(ssrf_block_reason(u).is_none(), "should allow {u}: {:?}", ssrf_block_reason(u));
        }
    }

    #[test]
    fn host_extraction_sees_the_real_host() {
        assert_eq!(host_of("http://real.com@127.0.0.1/x").as_deref(), Some("127.0.0.1"));
        assert_eq!(host_of("http://[::1]:8080/").as_deref(), Some("::1"));
        assert_eq!(host_of("http://example.com:443/a?b#c").as_deref(), Some("example.com"));
        assert_eq!(host_of("http://127.0.0.1.:80/").as_deref(), Some("127.0.0.1"));
    }

    #[test]
    fn alternate_ipv4_encodings_parse_to_loopback() {
        let loopback: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        for h in ["2130706433", "0x7f000001", "017700000001", "127.1"] {
            assert_eq!(parse_ip_literal(h), Some(loopback), "{h}");
        }
    }
}
