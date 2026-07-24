//! Phase 2: a per-origin renderer component.
//!
//! It holds no cookies, no DOM of other origins, and no network capability.
//! Everything it needs it must request from the engine over its IPC endpoint,
//! and the engine decides.
//!
//! The `serve` loop is transport-agnostic: in multi-process mode it runs in
//! its own child process, in single-process mode as a thread of the engine.
//! Only the process boundary changes — the protocol and policy do not.

use crate::ipc::{Endpoint, FromRenderer, ToRenderer};
use std::io;

const TILE_W: u32 = 512;
const TILE_H: u32 = 512;

/// The deterministic placeholder "rasterization": byte `i` of a tile always
/// has this value. Public so the consumer side (demo, bench, tests) can
/// byte-compare a received tile against what the renderer must have written —
/// the round-trip acceptance check for the shared-memory channel.
pub fn tile_pattern(i: usize) -> u8 {
    (i.wrapping_mul(31) ^ (i >> 8)) as u8
}

/// For `/blob/` bodies (the large-download stand-in), byte-compare against
/// the net component's deterministic pattern and report the transport used —
/// the round-trip acceptance check for the fetch-body channel, mirrored on
/// stderr for the integration tests.
fn report_blob(url: &str, transport: &str, body: &[u8]) {
    if !url.contains("/blob/") {
        return;
    }
    let ok = body.iter().enumerate().all(|(i, &b)| b == crate::net_daemon::body_pattern(i));
    eprintln!(
        "[renderer] {} KiB body via {transport} (pattern {})",
        body.len() / 1024,
        if ok { "ok" } else { "MISMATCH" },
    );
}

fn fill_tile(buf: &mut [u8]) {
    for (i, b) in buf.iter_mut().enumerate() {
        *b = tile_pattern(i);
    }
}

/// Multi-process entry point: adopt the inherited IPC link, sandbox, serve.
///
/// `link` is the transport's argv token for the channel end the engine handed
/// us at spawn (a descriptor number on Unix, a handle pair on Windows —
/// opaque here, see [`crate::channel`]). Possessing it *is* our
/// authentication: an inherited kernel object cannot be forged, so there is no
/// connect step and no token to check.
#[cfg(feature = "multi-process")]
pub fn run(origin: &str, link: &str) {
    // SAFETY: the engine passed us sole ownership of this inherited channel.
    let ch = unsafe { crate::channel::Channel::from_argv(link) }.expect("renderer: bad link arg");
    // Split the endpoint *before* sandboxing: on Unix the split does a dup,
    // which the allowlist deliberately does not permit at run time.
    let ep = Endpoint::from_channel(ch).expect("renderer: wrap link");
    // Drop privileges now that the IPC link is established: from here on the
    // renderer can only push pixels, not open sockets, files, or programs.
    crate::sandbox::lock_down_renderer();
    serve(ep, origin);
}

/// The component loop — identical in both modes.
pub fn serve(mut ep: Endpoint, origin: &str) {
    // Loop ends when `recv` errors (engine went away) or on `Shutdown`.
    while let Ok(cmd) = ep.recv::<ToRenderer>() {
        match cmd {
            ToRenderer::RenderPage { url } => {
                if render_page(&mut ep, origin, &url).is_err() {
                    break;
                }
            }
            ToRenderer::Shutdown => break,
            // Replies outside an active render exchange are ignored.
            _ => {}
        }
    }
}

fn render_page(ep: &mut Endpoint, origin: &str, url: &str) -> io::Result<()> {
    // Fetch the document — must go through the broker (Phase 1).
    ep.send(&FromRenderer::NeedFetch { url: url.to_string() })?;
    let _document = match ep.recv::<ToRenderer>()? {
        ToRenderer::FetchResult { body, .. } => {
            report_blob(url, "message copy", &body);
            Some(body)
        }
        // A large body streams through a shared-memory ring: the fd follows
        // the header on the same socket. `ring::consume` validates the fd
        // (size seals, real size, bounded claim) and drains the producer.
        #[cfg(all(feature = "multi-process", target_os = "linux"))]
        ToRenderer::FetchBodyStream { body_len, .. } => {
            let fd = ep.rx.recv_fd()?;
            match crate::ring::consume(fd, body_len) {
                Ok(body) => {
                    report_blob(url, "ring", &body);
                    Some(body)
                }
                Err(e) => {
                    // A broken stream fails this fetch, not the renderer —
                    // same shape as FetchDenied.
                    eprintln!("[renderer] body stream failed: {e}");
                    None
                }
            }
        }
        _ => None,
    };

    // Cookies for our own origin — held out of this process, requested via the
    // broker (Phase 2). The reply is the `document.cookie` view: non-HttpOnly
    // cookies only, so a session token never enters a renderer's address space.
    ep.send(&FromRenderer::NeedCookies { origin: origin.to_string() })?;
    let cookies = match ep.recv::<ToRenderer>()? {
        ToRenderer::Cookies(cookies) => cookies,
        _ => None,
    };
    // Report what document.cookie exposed, so the end-to-end HttpOnly property
    // is observable (and asserted by the integration suite): the visible names
    // must include non-HttpOnly cookies and never an HttpOnly one.
    let names = cookies
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .map(|(n, _)| n.as_str())
        .collect::<Vec<_>>()
        .join(",");
    eprintln!("[renderer] document.cookie exposes: [{names}]");

    // The page has an image. A renderer never parses image bytes itself — that
    // is the most dangerous input a browser handles — so it brokers the decode
    // to a throwaway process (Phase: decoder isolation). In a real browser the
    // bytes come from the network; here the renderer synthesizes a small one so
    // the round trip is self-checking.
    decode_image(ep)?;

    // The page uses storage and a web font. Renderers have no filesystem, so
    // both are brokered to services that do — storage keyed by this renderer's
    // (zone, origin), the font returning only metrics, never the file.
    use_storage(ep)?;
    use_font(ep)?;

    // The page pulls in cross-origin subresources. What the renderer may see is
    // decided by Opaque Response Blocking in the broker/net, not here.
    load_subresources(ep)?;

    // A real renderer parses, styles, lays out and rasterizes here; the PoC
    // ships a placeholder tile of the size the issue budgets per frame.
    send_tile(ep)
}

/// Ask the broker to decode an image in an isolated, ephemeral process, then
/// verify the pixels came back byte-for-byte — the round-trip acceptance check
/// for the decoder channel, reported on stderr like the tile and blob checks.
fn decode_image(ep: &mut Endpoint) -> io::Result<()> {
    use crate::decoder;
    const W: u32 = 16;
    const H: u32 = 16;
    let pixels: Vec<u8> = (0..(W * H * 4) as usize).map(decoder::sample_pixel).collect();

    // `GOSUB_DECODE_BADIMAGE` sends a header that *lies* about its size — a
    // 4096×4096 image carrying no pixels. It exercises the fault-isolation path
    // end to end: the decoder must reject it, the engine relay a failure, and
    // everything keep running. A real hostile image is this, with a parser bug
    // behind it; here the parser has no bug, so rejection is the whole story.
    let image = if std::env::var_os("GOSUB_DECODE_BADIMAGE").is_some() {
        decoder::encode(decoder::MAX_DECODE_DIM, decoder::MAX_DECODE_DIM, &[])
    } else {
        decoder::encode(W, H, &pixels)
    };

    ep.send(&FromRenderer::NeedDecode { image })?;
    match ep.recv::<ToRenderer>()? {
        ToRenderer::DecodeResult(crate::ipc::DecodeOutcome::Ok { width, height, pixels: got }) => {
            let ok = width == W && height == H && got == pixels;
            eprintln!("[renderer] image decoded {width}x{height} (pattern {})", if ok { "ok" } else { "MISMATCH" });
        }
        ToRenderer::DecodeResult(crate::ipc::DecodeOutcome::Failed { reason }) => {
            eprintln!("[renderer] image decode failed: {reason}");
        }
        _ => {}
    }
    Ok(())
}

/// Round-trip a value through the storage service: set it, read it back, and
/// confirm the bytes match — the acceptance check for the storage channel, and
/// a demonstration that a renderer with no filesystem still persists per-origin
/// data through the broker.
fn use_storage(ep: &mut Endpoint) -> io::Result<()> {
    use crate::ipc::StorageOp;
    let value = b"remembered".to_vec();
    ep.send(&FromRenderer::NeedStorage { op: StorageOp::Set { key: "greeting".into(), value: value.clone() } })?;
    let _ = ep.recv::<ToRenderer>()?; // Set result (always None)

    ep.send(&FromRenderer::NeedStorage { op: StorageOp::Get { key: "greeting".into() } })?;
    match ep.recv::<ToRenderer>()? {
        ToRenderer::StorageResult(got) => {
            let ok = got.as_deref() == Some(value.as_slice());
            eprintln!("[renderer] storage round-trip ({})", if ok { "ok" } else { "MISMATCH" });
        }
        _ => {}
    }
    Ok(())
}

/// Ask the font service for a font's metrics — a renderer cannot open the font
/// file itself, so this shows the derived data coming back from a service that
/// can, without the file ever entering the renderer.
fn use_font(ep: &mut Endpoint) -> io::Result<()> {
    ep.send(&FromRenderer::NeedFont { family: "sans".into() })?;
    match ep.recv::<ToRenderer>()? {
        ToRenderer::FontResult(Some(m)) => {
            eprintln!("[renderer] font '{}' metrics: {} glyphs, {} bytes read", m.family, m.glyphs, m.file_len);
        }
        ToRenderer::FontResult(None) => eprintln!("[renderer] font unavailable"),
        _ => {}
    }
    Ok(())
}

/// Pull in cross-origin subresources and report what Opaque Response Blocking
/// let through — the demonstration that a renderer can *request* cross-origin
/// resources but only ever *reads* what the trusted broker permits. An
/// embeddable image comes back opaque (usable, not readable), a cross-origin
/// JSON data resource is withheld entirely, and a CORS-approved fetch is
/// readable. The decision is the engine/net's; the renderer only observes it.
fn load_subresources(ep: &mut Endpoint) -> io::Result<()> {
    use crate::ipc::{FetchMode, SubresourceOutcome};
    let requests = [
        ("https://cdn.example.org/logo.png", FetchMode::NoCors, "cross-origin image (no-cors)"),
        ("https://api.other.test/secret.json", FetchMode::NoCors, "cross-origin JSON (no-cors)"),
        ("https://api.other.test/cors/data.json", FetchMode::Cors, "cross-origin JSON (cors)"),
    ];
    for (url, mode, label) in requests {
        ep.send(&FromRenderer::NeedSubresource { url: url.to_string(), mode })?;
        if let ToRenderer::SubresourceResult(outcome) = ep.recv::<ToRenderer>()? {
            let desc = match outcome {
                SubresourceOutcome::Delivered { opaque: true, body, .. } => {
                    format!("delivered opaque ({} bytes, not readable as data)", body.len())
                }
                SubresourceOutcome::Delivered { opaque: false, body, .. } => {
                    format!("delivered readable ({} bytes)", body.len())
                }
                SubresourceOutcome::Blocked { reason } => format!("BLOCKED by ORB — {reason}"),
                SubresourceOutcome::Denied { reason } => format!("denied — {reason}"),
            };
            eprintln!("[renderer] subresource {label}: {desc}");
        }
    }
    Ok(())
}

/// Deliver the rendered tile, preferring shared memory: rasterize into a
/// memfd, seal it immutable, send only the dimensions in-band and the fd via
/// `SCM_RIGHTS`. Falls back to copying the pixels through the socket if the
/// transport can't carry fds (single-process mode) or the memfd path fails —
/// the fallback is about availability, not security: the *consumer* validates
/// whatever arrives. `GOSUB_TILE_TRANSPORT=socket` forces the copy path so the
/// bench can compare the two.
fn send_tile(ep: &mut Endpoint) -> io::Result<()> {
    #[cfg(all(feature = "multi-process", target_os = "linux"))]
    if ep.tx.supports_fd_passing()
        && !std::env::var_os("GOSUB_TILE_TRANSPORT").is_some_and(|v| v == "socket")
    {
        use std::os::fd::AsRawFd;
        match crate::shm::create_sealed_tile(TILE_W, TILE_H, fill_tile) {
            Ok(fd) => {
                // Dimensions in-band first, then the fd right behind them —
                // the engine's reader consumes them as one exchange.
                ep.send(&FromRenderer::TileShm { width: TILE_W, height: TILE_H })?;
                ep.tx.send_fd(fd.as_raw_fd())?;
                // Our copy of the fd closes here (drop); the engine received
                // its own duplicate. Nothing stays mapped on this side either
                // (create_sealed_tile unmapped before sealing).
                return Ok(());
            }
            Err(e) => {
                eprintln!("[renderer] shm tile failed ({e}); falling back to socket copy")
            }
        }
    }

    let mut pixels = vec![0u8; TILE_W as usize * TILE_H as usize * 4];
    fill_tile(&mut pixels);
    ep.send(&FromRenderer::Tile { width: TILE_W, height: TILE_H, pixels })
}
