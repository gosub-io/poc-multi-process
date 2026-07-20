//! Fallback backend for platforms with no confinement mechanism wired up
//! (everything that is neither Linux nor macOS). Multi-process mode still
//! builds and runs here over Unix-domain sockets, but the privilege drops are
//! honest no-ops: a component runs unconfined and says so. The parent module
//! only compiles this file when neither `target_os = "linux"` nor
//! `target_os = "macos"` matches.

/// No sandbox mechanism here — run unconfined and be honest about it.
#[cfg(feature = "multi-process")]
pub fn lock_down_renderer() {
    eprintln!("[renderer] no sandbox on this platform — running unconfined");
}

#[cfg(feature = "multi-process")]
pub fn lock_down_net() {}

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
