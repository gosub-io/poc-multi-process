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

/// `requester` is the `zone-N/origin` identity as recorded by the engine; a
/// real implementation uses it for per-partition network policy. `cookies` are
/// that partition's cookies (including HttpOnly) the engine wants attached to
/// this request — the net component is the only process outside the engine
/// that sees their values.
fn handle_fetch(_requester: &str, url: &str, cookies: &[(String, String)]) -> FetchOutcome {
    if let Some(reason) = ssrf_block_reason(url) {
        return FetchOutcome::Denied { reason };
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
