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
//! * **Windows**: multi-process mode does not compile at all, so this backend
//!   is never reached with the feature on. The transport layer is POSIX to the
//!   core — `std::os::unix`, `std::os::fd`, `socketpair`, `SCM_RIGHTS`,
//!   `fork()` for the zygote — and `libc` itself is a `cfg(unix)` dependency.
//!   Only `--no-default-features` (single-process) builds there, where the one
//!   operation that still applies is `deny_debugger_attach`, a no-op below.
//!   A port needs a new transport and spawn model *and* a parent-side sandbox
//!   hook the current contract has no place for — see the seam notes in
//!   `mod.rs`. Do not read "unsupported" as "runs unconfined" on Windows; it
//!   does not run multi-process at all.

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
