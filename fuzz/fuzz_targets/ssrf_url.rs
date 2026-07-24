#![no_main]
//! Fuzz the SSRF URL/host/IP-literal parsing that gates every outbound fetch.
//! `resolve_and_pin` must classify or reject any string without panicking — a
//! parser panic in the one process allowed to open sockets is a real bug, and a
//! *mis*-parse there is an SSRF. The `inet_aton` encodings (`0x7f.1`, octal,
//! single-integer) and the IPv6/userinfo/trailing-dot handling are the parts
//! worth hammering.
//!
//! The resolver answers one fixed public address, so hostnames exercise the
//! resolve → classify path while IP literals exercise the classifier directly.
//!
//! Run: `cargo +nightly fuzz run ssrf_url`

use gosub_proc_iso_poc::ip_utils::{resolve_and_pin, Resolver};
use libfuzzer_sys::fuzz_target;
use std::net::{IpAddr, Ipv4Addr};

struct FuzzResolver;
impl Resolver for FuzzResolver {
    fn resolve(&self, _host: &str) -> std::io::Result<Vec<IpAddr>> {
        Ok(vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))])
    }
}

fuzz_target!(|data: &[u8]| {
    let url = String::from_utf8_lossy(data);
    let _ = resolve_and_pin(&url, &FuzzResolver);
});
