//! An **ephemeral image decoder** — the process that parses the single most
//! dangerous input a browser handles.
//!
//! Image decoding is where the memory-corruption RCEs actually live (libwebp
//! CVE-2023-4863 was a zero-click RCE in every major browser). So the decoder
//! gets three properties the renderer alone cannot give it:
//!
//! 1. **Isolation** — it runs in its own process with the renderer's
//!    content-process confinement (no network, no files, no exec). A parser
//!    bug is contained; a crash becomes a `DecodeFailed` the engine relays,
//!    not a failure that touches anything else.
//! 2. **Ephemerality** — one process decodes exactly *one* image and exits.
//!    It holds no state, so unlike a long-lived shared decoder it can never see
//!    a second origin's data. This is the property that makes a *shared*
//!    decoder wrong: it would quietly reintroduce the cross-origin channel the
//!    per-`(zone, origin)` renderer split exists to close.
//! 3. **Cheapness** — forked from the warm zygote, so spawning one per image is
//!    affordable. This is the feature the fork server was built to enable.
//!
//! The "format" here is a deliberately tiny stand-in (`GIMG`), enough to
//! exercise the thing that matters: a header that *claims* dimensions, and a
//! decoder that must validate that claim against the actual byte length before
//! trusting it. The classic decoder bug is believing the header — a dimension
//! that overflows an allocation, or pixel data that does not match the size the
//! header promised. Everything malformed is rejected, not trusted.

use crate::ipc::{Endpoint, FromDecoder, ToDecoder};

/// Magic bytes: a real format has a signature; validating it first rejects the
/// bulk of "this isn't even an image" input cheaply.
pub const MAGIC: &[u8; 4] = b"GIMG";

/// The header is magic + width + height, all before any pixel data.
pub const HEADER_LEN: usize = 4 + 4 + 4;

/// A hostile header can claim any dimensions; this bounds what we will act on
/// *before* the multiply that turns them into an allocation size. The classic
/// decoder overflow is `width * height * bytes_per_pixel` wrapping — the check
/// below is `checked_mul`, but capping the inputs first keeps even the
/// intermediate honest.
pub const MAX_DECODE_DIM: u32 = 4096;

/// Decode a `GIMG` image into `(width, height, RGBA pixels)`, or a reason it
/// was rejected.
///
/// Every field the header claims is checked against reality: the magic, the
/// dimension bounds, and — the one that matters — that the pixel bytes are
/// *exactly* `width * height * 4`. A header promising a 4096×4096 image with
/// twelve bytes of data is refused here rather than read past the end of the
/// buffer.
pub fn decode(bytes: &[u8]) -> Result<(u32, u32, Vec<u8>), String> {
    if bytes.len() < HEADER_LEN {
        return Err(format!("truncated: {} bytes, need at least {HEADER_LEN}", bytes.len()));
    }
    if &bytes[0..4] != MAGIC {
        return Err("bad magic (not a GIMG image)".into());
    }
    // `try_into` cannot fail — the slices are exactly 4 bytes given the length
    // check above.
    let width = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
    let height = u32::from_le_bytes(bytes[8..12].try_into().unwrap());

    if width == 0 || height == 0 || width > MAX_DECODE_DIM || height > MAX_DECODE_DIM {
        return Err(format!("dimensions out of range: {width}x{height}"));
    }

    // Checked all the way: `width*height*4` must not overflow, and must match
    // the pixel bytes present. This is the check a naive decoder skips.
    let expected = (width as usize)
        .checked_mul(height as usize)
        .and_then(|n| n.checked_mul(4))
        .ok_or("pixel count overflows usize")?;
    let actual = bytes.len() - HEADER_LEN;
    if actual != expected {
        return Err(format!("pixel data is {actual} bytes, header implies {expected}"));
    }

    Ok((width, height, bytes[HEADER_LEN..].to_vec()))
}

/// Encode `(width, height, pixels)` into the `GIMG` wire form. Used by the demo
/// and tests to produce well-formed input to decode back.
pub fn encode(width: u32, height: u32, pixels: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + pixels.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&width.to_le_bytes());
    out.extend_from_slice(&height.to_le_bytes());
    out.extend_from_slice(pixels);
    out
}

/// The deterministic byte at position `i` of a sample image, so a consumer can
/// byte-compare a decoded image against what must have gone in — the round-trip
/// acceptance check, mirroring `renderer::tile_pattern`.
pub fn sample_pixel(i: usize) -> u8 {
    (i.wrapping_mul(37) ^ (i >> 5)) as u8
}

/// The whole life of an ephemeral decoder: receive one image, answer, return.
///
/// It handles a *single* `Decode` and stops — in a child process the caller
/// then exits, so the process cannot be reused for a second image. That is the
/// ephemerality property, enforced by structure rather than policy.
pub fn serve_one(mut ep: Endpoint) {
    let reply = match ep.recv::<ToDecoder>() {
        Ok(ToDecoder::Decode { image }) => match decode(&image) {
            Ok((width, height, pixels)) => FromDecoder::Decoded { width, height, pixels },
            Err(reason) => FromDecoder::Failed { reason },
        },
        // The engine closed the link without asking for a decode: nothing to do.
        Err(_) => return,
    };
    let _ = ep.send(&reply);
}

/// Multi-process entry point: adopt the inherited IPC link, confine, decode one
/// image, exit.
///
/// The decoder is a *content process* exactly like the renderer — no network,
/// no files, no new programs — so it reuses the renderer's lockdown rather than
/// inventing a second identical one. It arguably needs even less (it never
/// creates shared-memory tiles), but a tighter-than-necessary confinement is a
/// refinement, not a correctness issue, and the renderer baseline is a safe
/// superset.
#[cfg(feature = "multi-process")]
pub fn run(link: &str) {
    // SAFETY: the engine passed us sole ownership of this inherited channel.
    let ch = unsafe { crate::channel::Channel::from_argv(link) }.expect("decoder: bad link arg");
    let ep = Endpoint::from_channel(ch).expect("decoder: wrap link");
    crate::sandbox::lock_down_renderer();
    serve_one(ep);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(width: u32, height: u32) -> Vec<u8> {
        (0..(width * height * 4) as usize).map(sample_pixel).collect()
    }

    #[test]
    fn round_trips_a_well_formed_image() {
        let pixels = sample(8, 8);
        let (w, h, out) = decode(&encode(8, 8, &pixels)).expect("should decode");
        assert_eq!((w, h), (8, 8));
        assert_eq!(out, pixels);
    }

    #[test]
    fn rejects_bad_magic() {
        let mut img = encode(2, 2, &sample(2, 2));
        img[0] = b'X';
        assert!(decode(&img).is_err());
    }

    #[test]
    fn rejects_truncated_header() {
        assert!(decode(b"GIM").is_err());
        assert!(decode(MAGIC).is_err());
    }

    #[test]
    fn rejects_dimension_pixel_mismatch() {
        // Header claims 4x4 (256 bytes) but carries only 4 — the lie a naive
        // decoder would act on by reading past the buffer.
        let mut img = encode(4, 4, &sample(4, 4));
        img.truncate(HEADER_LEN + 4);
        assert!(decode(&img).is_err());
    }

    #[test]
    fn rejects_oversized_dimensions() {
        // Only a header — no gigabytes of pixels needed to test the bound. The
        // dimension cap rejects it before any allocation is sized from it.
        let huge = encode(MAX_DECODE_DIM + 1, MAX_DECODE_DIM + 1, &[]);
        assert!(decode(&huge).is_err());
    }

    #[test]
    fn rejects_zero_dimensions() {
        assert!(decode(&encode(0, 4, &[])).is_err());
        assert!(decode(&encode(4, 0, &[])).is_err());
    }

    /// Deterministic stand-in for `cargo fuzz run decode_image`, so the "any
    /// byte string returns Ok/Err, never panics or reads OOB" contract is
    /// checked in the ordinary test suite too (no nightly required). The real
    /// fuzzer in `fuzz/` explores far more; this pins a regression floor.
    #[test]
    fn decode_never_panics_on_arbitrary_bytes() {
        let mut s = 0x9e37_79b9_7f4a_7c15u64;
        for _ in 0..50_000 {
            let len = (xorshift(&mut s) % 64) as usize;
            let mut buf: Vec<u8> = (0..len).map(|_| xorshift(&mut s) as u8).collect();
            // Half the time, lead with the real magic so the deeper
            // dimension/length paths are reached, not just the magic rejection.
            if len >= HEADER_LEN && xorshift(&mut s) & 1 == 0 {
                buf[..4].copy_from_slice(MAGIC);
            }
            let _ = decode(&buf); // the assertion is that this returns at all
        }
    }

    /// Tiny deterministic xorshift PRNG — no `rand` dependency, no wall-clock
    /// seed, so the "fuzz" is reproducible in CI.
    fn xorshift(s: &mut u64) -> u64 {
        let mut x = *s;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *s = x;
        x
    }
}
