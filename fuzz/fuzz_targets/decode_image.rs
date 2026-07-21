#![no_main]
//! Fuzz the ephemeral image decoder's parser — the highest-value memory-safety
//! surface a browser has (the libwebp CVE-2023-4863 lineage: a header that lies
//! about its dimensions). The contract is total: any byte string returns `Ok`
//! or `Err`, never panics and never reads past the buffer. A crash here is a
//! real finding.
//!
//! Run: `cargo +nightly fuzz run decode_image`

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = gosub_proc_iso_poc::decoder::decode(data);
});
