//! URL host extraction and IP classification for the SSRF policy — the pure
//! "is this destination allowed?" logic, factored out of the net component so
//! it can be read (and audited) without the transport around it. No I/O, no
//! resolver: everything here works on the URL string and numeric addresses.

use std::net::{IpAddr, Ipv4Addr};

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
pub fn ssrf_block_reason(url: &str) -> Option<String> {
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
            } else if seg[0] == 0x64 && seg[1] == 0xff9b && seg[2..6] == [0, 0, 0, 0] {
                // NAT64 (64:ff9b::/96): what gets reached is the *embedded
                // IPv4*, so classify that — a public embed stays allowed.
                blocked_v4(embedded_v4(seg))
            } else if seg[..6] == [0, 0, 0, 0, 0, 0] {
                // Deprecated IPv4-compatible (::a.b.c.d): same reach as the
                // embedded IPv4 on stacks that still honor it. (::1 and ::
                // were already handled above.)
                blocked_v4(embedded_v4(seg))
            } else {
                None
            }
        }
    }
}

/// The IPv4 address in the low 32 bits of an IPv6 address (NAT64 and
/// IPv4-compatible embeddings).
fn embedded_v4(seg: [u16; 8]) -> Ipv4Addr {
    Ipv4Addr::new((seg[6] >> 8) as u8, seg[6] as u8, (seg[7] >> 8) as u8, seg[7] as u8)
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
    } else if v4.is_multicast() {
        Some("IPv4 multicast (224.0.0.0/4)")
    } else if o[0] >= 240 {
        Some("reserved class E (240.0.0.0/4)")
    } else if o[0] == 192 && o[1] == 0 && o[2] == 0 {
        Some("IETF protocol assignments (192.0.0.0/24)")
    } else if o[0] == 192 && o[1] == 88 && o[2] == 99 {
        Some("6to4 relay anycast (192.88.99.0/24)")
    } else if o[0] == 198 && o[1] & 0xfe == 18 {
        Some("benchmarking (198.18.0.0/15)")
    } else if (o[0] == 192 && o[1] == 0 && o[2] == 2)
        || (o[0] == 198 && o[1] == 51 && o[2] == 100)
        || (o[0] == 203 && o[1] == 0 && o[2] == 113)
    {
        Some("documentation TEST-NET (192.0.2/24, 198.51.100/24, 203.0.113/24)")
    } else {
        None
    }
    // Deliberately NOT blocked: subnet-directed broadcast (x.y.z.255) — which
    // addresses are broadcasts depends on the local netmask, and refusing
    // every .255 would break legitimate public hosts.
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
            // Multicast, class E, and the special-purpose IPv4 registry blocks.
            "http://224.0.0.1/", "http://239.255.255.250/", "http://240.0.0.1/",
            "http://192.0.0.5/", "http://192.88.99.1/", "http://198.18.0.1/",
            "http://198.19.255.1/", "http://192.0.2.1/", "http://198.51.100.7/",
            "http://203.0.113.9/",
            // IPv6 embeddings that reach internal IPv4: NAT64 + deprecated
            // IPv4-compatible.
            "http://[64:ff9b::7f00:1]/", "http://[64:ff9b::a00:1]/", "http://[::127.0.0.1]/",
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
            "http://223.255.255.1/", // just below multicast
            "http://198.20.0.1/",    // just outside benchmarking 198.18/15
            "http://[2606:2800:220:1::1]/",
            "http://[64:ff9b::808:808]/", // NAT64 embedding a *public* v4 (8.8.8.8)
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
