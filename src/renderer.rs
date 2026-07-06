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

/// Multi-process entry point: connect back to the engine, authenticate, serve.
#[cfg(feature = "multi-process")]
pub fn run(socket_path: &str, origin: &str, token: &str) {
    use crate::ipc::{self, Hello};
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(socket_path).expect("renderer: connect to engine");
    ipc::send_msg(&mut stream, &Hello { token: token.to_string() }).unwrap();
    // Split the endpoint *before* sandboxing: try_clone() does a dup, which
    // the allowlist deliberately does not permit at run time.
    let ep = Endpoint::from_stream(stream).expect("renderer: split stream");
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
    let pixels = vec![0xAB; (TILE_W * TILE_H * 4) as usize];
    ep.send(&FromRenderer::Tile { width: TILE_W, height: TILE_H, pixels })
}
