//! OS-level privilege capping for the engine and its child components.
//!
//! Process isolation is only worth as much as the privileges dropped inside
//! each process. This module is the single, platform-neutral surface the rest
//! of the engine calls; the actual mechanisms live in per-OS backends and are
//! selected once, here, so no caller — and no other module — carries a
//! `#[cfg(target_os = ...)]` for sandboxing:
//!
//! * [`linux`] — a default-deny **seccomp-BPF** syscall allowlist, an empty
//!   **network namespace** for renderers, `prctl(PR_SET_DUMPABLE)`, and
//!   rlimits. The reference implementation of the model.
//! * [`macos`] — a **Seatbelt** (`sandbox_init`) SBPL profile, `PT_DENY_ATTACH`,
//!   and rlimits. Same guarantees, different primitives (see that module for
//!   where the seams don't line up 1:1 — network isolation folds into the
//!   profile, and there is no W^X argument filtering).
//! * [`unsupported`] — honest no-ops elsewhere: multi-process still runs over
//!   Unix sockets, but components run unconfined and say so.
//!
//! The privilege model itself (why a default-deny allowlist, why fail-closed,
//! why the placement of each call matters) is documented on the Linux backend,
//! which realizes it most fully.
//!
//! ## The seam
//!
//! Five operations make up the contract every backend implements. Their timing
//! relative to `fork`/`exec` is load-bearing and identical across platforms:
//!
//! | Operation | When | Applies to |
//! |-----------|------|------------|
//! | [`deny_debugger_attach`] | after exec (survives fork, not exec) | engine + every child |
//! | [`apply_child_rlimits`]  | `pre_exec` (async-signal-safe) | children |
//! | [`isolate_network`]      | `pre_exec` (async-signal-safe) | children (renderers isolate) |
//! | [`lock_down_renderer`]   | after the IPC link is connected | renderer |
//! | [`lock_down_net`]        | after the IPC link is connected | net component |
//!
//! `deny_debugger_attach` is compiled in every build — the single-process
//! engine has no children to confine but still holds the cookie jar in its own
//! address space. The other four exist only under the `multi-process` feature,
//! where there are separate processes to cap.

// --- platform seam: the only place a sandbox `target_os` cfg lives ---
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
use linux as imp;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
use macos as imp;

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod unsupported;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
use unsupported as imp;

// --- public API: thin, cfg-free wrappers over the selected backend ---

/// Mark the calling process non-dumpable, closing the *inbound* debugging
/// surface so another same-user process cannot attach a debugger and read our
/// address space (for the engine: the cookie jar in cleartext). Best-effort
/// hardening — warns rather than aborts on failure. Must be called *after*
/// `exec` (the flag does not survive it) but is inherited across `fork`.
pub fn deny_debugger_attach() {
    imp::deny_debugger_attach();
}

/// Impose resource ceilings (address space, fd count, no core dumps, lowered
/// scheduling priority) on a child. Called from `pre_exec`, so it must stay
/// async-signal-safe. rlimits only ever lower, so a child cannot undo them.
#[cfg(feature = "multi-process")]
pub fn apply_child_rlimits() -> std::io::Result<()> {
    imp::apply_child_rlimits()
}

/// Isolate a child from the network when `enable` is set (renderers), leaving
/// it in place otherwise (the net component). Called from `pre_exec`, so it
/// must stay async-signal-safe. On platforms without network namespaces this
/// is deferred into the lockdown profile — see the backend docs.
#[cfg(feature = "multi-process")]
pub fn isolate_network(enable: bool) -> std::io::Result<()> {
    imp::isolate_network(enable)
}

/// Confine a renderer to pixels only: no network, no files, no new programs.
/// Called once the IPC link is connected. Fail-closed — the backend aborts the
/// process rather than let a renderer meant to be confined run unconfined.
#[cfg(feature = "multi-process")]
pub fn lock_down_renderer() {
    imp::lock_down_renderer();
}

/// Confine the net component: the renderer's restrictions minus the network,
/// which is the one privilege this role keeps. Called once the IPC link is
/// connected. Fail-closed.
#[cfg(feature = "multi-process")]
pub fn lock_down_net() {
    imp::lock_down_net();
}
