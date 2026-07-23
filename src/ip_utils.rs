//! URL host extraction and IP classification for the SSRF policy — the
//! "is this destination allowed?" logic, factored out of the net component so
//! it can be read (and audited) without the transport around it.
//!
//! ## Deciding and connecting must be one step
//!
//! The obvious API — "is this URL allowed?", answered yes or no — cannot be
//! made safe for hostnames, however good the classification behind it is. The
//! caller still has to connect, connecting re-resolves the name, and the
//! attacker controls what the *second* lookup returns. That is DNS rebinding,
//! and no amount of checking inside a boolean-returning function closes it.
//!
//! So [`resolve_and_pin`] returns the **address the caller must connect to**,
//! not a verdict. One resolution happens, every answer is classified, and the
//! survivor is handed back for the connection to use directly. A caller that
//! takes the returned [`Pinned`] and connects to it cannot be rebound, because
//! there is no second lookup to poison.
//!
//! Resolution goes through the [`Resolver`] seam so the policy is testable
//! without a network: the tests inject hostile answer sets (a fixed resolver)
//! that a real DNS server would have to be compromised to produce.

use std::net::{IpAddr, Ipv4Addr};

/// How a hostname becomes addresses. A seam, so the SSRF policy can be tested
/// against hostile answer sets offline — the interesting cases (a name
/// answering `127.0.0.1`, or mixing a public address with a private one) need
/// a cooperating DNS server to reproduce for real.
pub trait Resolver {
    /// Every address `host` resolves to, in the order the resolver returned
    /// them. An empty result is a resolution failure.
    fn resolve(&self, host: &str) -> std::io::Result<Vec<IpAddr>>;
}

/// The real resolver: whatever the OS says.
///
/// Unused in this PoC — the net component synthesizes responses offline and
/// resolves through its own stand-in, so wiring this in would make every fetch
/// depend on a working network. It is the implementation a real deployment
/// selects, kept here so the production path is one line rather than a design
/// exercise.
#[allow(dead_code)]
pub struct SystemResolver;

impl Resolver for SystemResolver {
    fn resolve(&self, host: &str) -> std::io::Result<Vec<IpAddr>> {
        use std::net::ToSocketAddrs;
        // Port is irrelevant to the lookup; `to_socket_addrs` just needs one.
        Ok((host, 0u16).to_socket_addrs()?.map(|sa| sa.ip()).collect())
    }
}

/// A resolver with a canned answer, for tests.
#[cfg(test)]
pub struct FixedResolver(pub Vec<IpAddr>);

#[cfg(test)]
impl Resolver for FixedResolver {
    fn resolve(&self, _host: &str) -> std::io::Result<Vec<IpAddr>> {
        Ok(self.0.clone())
    }
}

/// A destination that passed policy: the exact address to connect to.
///
/// The point of returning this rather than `bool` is that it removes the second
/// DNS lookup. Connect to `addr` and rebinding is structurally impossible;
/// re-resolve `host` and every guarantee here is void.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pinned {
    pub host: String,
    pub addr: IpAddr,
}

/// Resolve `url`'s host and decide the destination, returning the address to
/// pin the connection to or the reason it is refused.
///
/// IP literals skip resolution — there is nothing to look up and nothing to
/// rebind. Names are resolved once, and **every** returned address must pass:
/// if any answer is internal the whole name is refused, rather than connecting
/// to whichever answers survive. That is deliberate. Which address the OS hands
/// out of a multi-answer set is not the caller's choice, so a name answering
/// `[1.2.3.4, 127.0.0.1]` is one round-robin away from being loopback. Treating
/// the good answer as usable would be trusting an attacker-supplied answer set
/// to be partly honest. The cost is that a host with one stray private address
/// becomes unreachable, which is the right side to err on for a fetch a
/// renderer asked for.
pub fn resolve_and_pin(url: &str, resolver: &impl Resolver) -> Result<Pinned, String> {
    match scheme_of(url) {
        Some(s) if s == "http" || s == "https" => {}
        Some(s) => return Err(format!("scheme {s}:// is not allowed (SSRF policy)")),
        None => return Err("unparseable URL".into()),
    }

    let Some(host) = host_of(url) else {
        return Err("unparseable URL".into());
    };

    // A literal is already an address: classify it and pin it as-is. No
    // resolution means no rebinding window, so this needs no special handling
    // beyond the classification that was always here.
    if let Some(ip) = parse_ip_literal(&host) {
        return match blocked_ip_reason(ip) {
            Some(category) => Err(format!("host {host} is {category} (SSRF policy)")),
            None => Ok(Pinned { host, addr: ip }),
        };
    }

    let addrs = resolver
        .resolve(&host)
        .map_err(|e| format!("host {host} did not resolve: {e} (SSRF policy)"))?;
    if addrs.is_empty() {
        return Err(format!("host {host} did not resolve (SSRF policy)"));
    }

    // Fail closed on *any* blocked answer — see the doc comment above.
    for ip in &addrs {
        if let Some(category) = blocked_ip_reason(*ip) {
            return Err(format!(
                "host {host} resolves to {ip}, which is {category} (SSRF policy)"
            ));
        }
    }

    Ok(Pinned { host, addr: addrs[0] })
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
            } else if seg[0] == 0x2002 {
                // 6to4 (2002::/16): the IPv4 is embedded in the *next* 32 bits
                // (2002:AABB:CCDD::), not the low ones — on a host with a 6to4
                // pseudo-interface/relay that IPv4 is what gets reached, so
                // classify it like NAT64. A public embed stays allowed.
                let v4 =
                    Ipv4Addr::new((seg[1] >> 8) as u8, seg[1] as u8, (seg[2] >> 8) as u8, seg[2] as u8);
                blocked_v4(v4)
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

    /// A resolver standing in for a realistic world: loopback names answer
    /// loopback, one name is deliberately internal, everything else is public.
    /// Literal hosts never reach it — they are classified directly.
    struct TestResolver;

    impl Resolver for TestResolver {
        fn resolve(&self, host: &str) -> std::io::Result<Vec<IpAddr>> {
            let lower = host.to_ascii_lowercase();
            Ok(match lower.as_str() {
                "localhost" => vec![ip("127.0.0.1")],
                h if h.ends_with(".localhost") => vec![ip("127.0.0.1")],
                "internal.example" => vec![ip("10.0.0.5")],
                "nx.example" => vec![],
                _ => vec![ip("93.184.216.34")],
            })
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// Convenience: run the policy against the realistic resolver.
    fn check(url: &str) -> Result<Pinned, String> {
        resolve_and_pin(url, &TestResolver)
    }

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
            // IPv4-compatible + 6to4 (2002:AABB:CCDD::).
            "http://[64:ff9b::7f00:1]/", "http://[64:ff9b::a00:1]/", "http://[::127.0.0.1]/",
            "http://[2002:c0a8:0101::]/", // 6to4 wrapping 192.168.1.1
            "http://[2002:7f00:0001::]/", // 6to4 wrapping 127.0.0.1
            // Parser-confusion: userinfo and trailing dot.
            "http://real.com@127.0.0.1/", "http://127.0.0.1.:80/",
            // Non-HTTP schemes are refused outright, whatever the host.
            "file://example.com/etc/passwd", "gopher://example.com/", "ftp://127.0.0.1/",
        ] {
            assert!(check(u).is_err(), "should block {u}: {:?}", check(u));
        }
    }

    #[test]
    fn allows_only_http_schemes() {
        assert!(scheme_of("https://example.com/").as_deref() == Some("https"));
        assert!(scheme_of("HTTP://example.com/").as_deref() == Some("http")); // case-folded
        assert!(scheme_of("not-a-url").is_none());
        // A public host over http/https is fine; the same host over file:// is not.
        assert!(check("https://example.com/").is_ok());
        assert!(check("file://example.com/").is_err());
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
            "http://[2002:5db8:d822::1]/", // 6to4 embedding a *public* v4 (93.184.216.34)
        ] {
            assert!(check(u).is_ok(), "should allow {u}: {:?}", check(u));
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

    /// The gap the old `ssrf_block_reason(url) -> Option<String>` could not
    /// close: a name is not an address, and this one answers loopback.
    #[test]
    fn hostname_resolving_to_loopback_is_blocked() {
        let err = check("http://localhost/").unwrap_err();
        assert!(err.contains("127.0.0.1"), "reason should name the address: {err}");
    }

    /// A perfectly ordinary-looking name pointing at internal space. Nothing
    /// about the *string* is suspicious — only the resolved address is.
    #[test]
    fn innocuous_name_resolving_to_private_space_is_blocked() {
        let err = check("https://internal.example/admin").unwrap_err();
        assert!(err.contains("10.0.0.5"), "reason should name the address: {err}");
    }

    /// Fail closed on a mixed answer set. Which address the OS hands out is the
    /// attacker's choice, not ours, so one internal answer poisons the name.
    #[test]
    fn any_internal_answer_refuses_the_whole_name() {
        let hostile = FixedResolver(vec![ip("93.184.216.34"), ip("127.0.0.1")]);
        let err = resolve_and_pin("http://rebind.example/", &hostile).unwrap_err();
        assert!(err.contains("127.0.0.1"), "should refuse on the internal answer: {err}");

        // Order must not matter — the internal answer first is the same verdict.
        let hostile = FixedResolver(vec![ip("169.254.169.254"), ip("93.184.216.34")]);
        assert!(resolve_and_pin("http://rebind.example/", &hostile).is_err());
    }

    /// The anti-rebinding property itself: what comes back is an address, so
    /// the caller never has to resolve again. A second lookup is the only way
    /// a rebind can land, and the API removes the reason to perform one.
    #[test]
    fn allowed_destination_is_pinned_to_an_address() {
        let pinned = check("https://example.com/page").unwrap();
        assert_eq!(pinned.host, "example.com");
        assert_eq!(pinned.addr, ip("93.184.216.34"));

        // An IP literal pins to itself, with no resolution involved at all.
        let pinned = resolve_and_pin("http://93.184.216.34/", &FixedResolver(vec![])).unwrap();
        assert_eq!(pinned.addr, ip("93.184.216.34"));
    }

    /// A name that does not resolve is refused, not treated as allowed.
    #[test]
    fn unresolvable_name_is_refused() {
        assert!(check("http://nx.example/").is_err());
    }

    /// Deterministic stand-in for `cargo fuzz run ssrf_url`: throw pseudo-random
    /// URL-ish strings (from an alphabet that stresses the scheme/host/IP-literal
    /// parsers — `inet_aton` digits, brackets, `@`, `%`, `:`) at the classifier.
    /// It must classify or reject any string without panicking; a parser panic in
    /// the one process allowed to open sockets is itself a bug. The `fuzz/` target
    /// explores far more; this is the CI floor.
    #[test]
    fn resolve_and_pin_never_panics_on_arbitrary_urls() {
        let alpha = b"htps:/.[]@%:0123456789abcdefABCDEFxX-";
        let mut s = 0xdead_beef_cafe_babeu64;
        for _ in 0..50_000 {
            let len = (xorshift(&mut s) % 40) as usize;
            let url: String = (0..len)
                .map(|_| alpha[(xorshift(&mut s) as usize) % alpha.len()] as char)
                .collect();
            let _ = resolve_and_pin(&url, &TestResolver); // must return, not panic
        }
    }

    /// Tiny deterministic xorshift PRNG — reproducible, no `rand`, no clock seed.
    fn xorshift(s: &mut u64) -> u64 {
        let mut x = *s;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *s = x;
        x
    }
}
