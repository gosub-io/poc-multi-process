//! Fallback backend for platforms with no confinement mechanism wired up
//! (everything that is neither Linux nor macOS). The parent module only
//! compiles this file when neither `target_os = "linux"` nor
//! `target_os = "macos"` matches.
//!
//! What that means depends on the platform, and the difference matters:
//!
//! * **Other Unixes** (the BSDs, illumos, …): multi-process mode builds and
//!   runs here over Unix-domain sockets — socketpairs, inherited-fd auth and
//!   `SCM_RIGHTS` all carry over — but the privilege drops are honest no-ops.
//!   Components run unconfined and say so. The architecture is exercised; the
//!   confinement is not. Wiring up `pledge`/`unveil` or Capsicum would be a
//!   backend-shaped piece of work, like the macOS one.
//!
//! Windows is **not** one of these cases any more: it has its own transport
//! (`channel/windows.rs`) and its own backend (`sandbox/windows.rs`), so it
//! never reaches this file.

/// No sandbox mechanism here — run unconfined and be honest about it.
#[cfg(feature = "multi-process")]
pub fn lock_down_renderer() {
    eprintln!("[renderer] no sandbox on this platform — running unconfined");
}

#[cfg(feature = "multi-process")]
pub fn lock_down_net() {}

/// No confinement here either; the service runs unconfined like everything else
/// on this platform.
#[cfg(feature = "multi-process")]
pub fn lock_down_service(name: &str, _filesystem: bool, _device: bool) {
    eprintln!("[{name}] no sandbox on this platform — running unconfined");
}

/// rlimits are POSIX, but this fallback keeps the whole backend as no-ops so a
/// port is an all-or-nothing, clearly-visible piece of work rather than a
/// partial illusion of confinement.
#[cfg(feature = "multi-process")]
pub fn apply_child_rlimits() -> std::io::Result<()> {
    Ok(())
}

/// No network namespaces; nothing to do (see the Linux/macOS backends).
#[cfg(feature = "multi-process")]
pub fn isolate_network(_enable: bool) -> std::io::Result<()> {
    Ok(())
}

/// No anti-debugging primitive wired up here.
pub fn deny_debugger_attach() {}
