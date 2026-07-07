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

fn fill_tile(buf: &mut [u8]) {
    for (i, b) in buf.iter_mut().enumerate() {
        *b = tile_pattern(i);
    }
}

/// Multi-process entry point: adopt the inherited IPC fd, sandbox, serve.
///
/// `fd` is the number of the `socketpair(2)` end the engine handed us at
/// spawn. Possessing it *is* our authentication — an inherited fd cannot be
/// forged — so there is no connect step and no token to check.
#[cfg(feature = "multi-process")]
pub fn run(origin: &str, fd: &str) {
    use std::os::fd::FromRawFd;
    use std::os::unix::net::UnixStream;

    let fd: std::os::fd::RawFd = fd.parse().expect("renderer: bad fd arg");
    // SAFETY: the engine passed us sole ownership of this inherited fd.
    let stream = unsafe { UnixStream::from_raw_fd(fd) };
    // Split the endpoint *before* sandboxing: try_clone() does a dup, which
    // the allowlist deliberately does not permit at run time.
    let ep = Endpoint::from_stream(stream).expect("renderer: wrap fd");
    // Drop privileges now that the IPC link is established: from here on the
    // renderer can only push pixels, not open sockets, files, or programs.
    crate::sandbox::lock_down_renderer();
    serve(ep, origin);
}

/// The component loop — identical in both modes.
pub fn serve(mut ep: Endpoint, origin: &str) {
    loop {
        let cmd: ToRenderer = match ep.recv() {
            Ok(cmd) => cmd,
            Err(_) => break, // engine went away
        };
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
        ToRenderer::FetchResult { body, .. } => Some(body),
        _ => None,
    };

    // Cookies for our own origin — held by the engine, requested via the
    // broker (Phase 2).
    ep.send(&FromRenderer::NeedCookies { origin: origin.to_string() })?;
    let _cookies = match ep.recv::<ToRenderer>()? {
        ToRenderer::Cookies(cookies) => cookies,
        _ => None,
    };

    // A real renderer parses, styles, lays out and rasterizes here; the PoC
    // ships a placeholder tile of the size the issue budgets per frame.
    send_tile(ep)
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
