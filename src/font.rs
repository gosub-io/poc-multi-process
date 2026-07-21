//! Font service — the second reason a renderer's `openat` denial is only
//! sustainable while nothing renders real text.
//!
//! Real text needs font files and shaping tables read from disk; renderers deny
//! `openat` outright, so those reads happen in a service that can. Like the
//! storage service it is engine-spawned (outside the zygote) with a filesystem
//! filter, and returns only *derived* data — metrics — never the font bytes
//! themselves, so a renderer never handles the file.
//!
//! The "font file" here is a small deterministic stand-in the engine writes at
//! startup; the point being demonstrated is the isolation and the `openat`
//! capability, not a real font parser (that would be another decoder-shaped
//! hostile-input process in its own right).

use crate::ipc::{Endpoint, FontMetrics, FontRequest, FontResponse};
use std::path::PathBuf;

/// The stand-in font file the service reads. One flat file (not a directory),
/// so the service needs only `openat`, not `mkdirat`.
pub fn font_file() -> PathBuf {
    std::env::temp_dir().join("gosub-font.dat")
}

/// Deterministic stand-in contents, written by the engine at startup.
const FONT_BYTES: &[u8] = &[0xF0; 1024];

/// Write the stand-in font file. Called by the engine before the service is
/// spawned (the engine is unconfined; the service's filter has no file
/// *creation* beyond `openat`, and none is needed once the file exists).
pub fn ensure_font_file() {
    let _ = std::fs::write(font_file(), FONT_BYTES);
}

/// Read the font file and derive metrics. The renderer receives these, never
/// the bytes — the file stays inside the service.
fn metrics_for(family: &str) -> Option<FontMetrics> {
    let bytes = std::fs::read(font_file()).ok()?;
    Some(FontMetrics {
        family: family.to_string(),
        // A stand-in for "glyphs parsed out of the file": derived from the real
        // file length so it actually depends on the `openat` having worked.
        glyphs: (bytes.len() as u32) / 4 + family.len() as u32,
        file_len: bytes.len() as u64,
    })
}

/// The service loop — transport-agnostic, identical in both modes.
pub fn serve(mut ep: Endpoint) {
    // Loop ends when `recv` errors (engine went away) or on `Shutdown`.
    while let Ok(FontRequest::Metrics { request_id, family }) = ep.recv::<FontRequest>() {
        let metrics = metrics_for(&family);
        if ep.send(&FontResponse { request_id, metrics }).is_err() {
            break;
        }
    }
}

/// Multi-process entry point: adopt the inherited link, confine with a
/// filesystem filter, serve.
#[cfg(feature = "multi-process")]
pub fn run(link: &str) {
    // SAFETY: the engine passed us sole ownership of this inherited channel.
    let ch = unsafe { crate::channel::Channel::from_argv(link) }.expect("font: bad link arg");
    let ep = Endpoint::from_channel(ch).expect("font: wrap link");
    // Landlock scopes the service to just its one (read-only) font file.
    let file = font_file();
    crate::sandbox::lock_down_service(
        "font",
        crate::sandbox::ServiceCaps { filesystem: true, device: false },
        &[(file.as_path(), false)],
    );
    serve(ep);
}
