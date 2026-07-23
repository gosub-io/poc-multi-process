//! OS-level privilege capping for the engine and its child components.
//!
//! Process isolation is only worth as much as the privileges dropped inside
//! each process. This module is the single, platform-neutral surface the rest
//! of the engine calls; the actual mechanisms live in per-OS backends and are
//! selected once, here, so no caller — and no other module — carries a
//! `#[cfg(target_os = ...)]` for sandboxing:
//!
//! (Plain paths rather than intra-doc links below: only one backend is
//! compiled per target, so a link to the other two would dangle — on whichever
//! platform the docs happen to be built.)
//!
//! * `linux.rs` — a default-deny **seccomp-BPF** syscall allowlist, an empty
//!   **network namespace** for renderers, `prctl(PR_SET_DUMPABLE)`, and
//!   rlimits. The reference implementation of the model.
//! * `macos.rs` — a **Seatbelt** (`sandbox_init`) SBPL profile,
//!   `PT_DENY_ATTACH`, and rlimits. Same guarantees, different primitives (see
//!   that module for where the seams don't line up 1:1 — network isolation
//!   folds into the profile, and there is no W^X argument filtering).
//! * `windows.rs` — **process mitigation policies** (no dynamic code, no child
//!   processes, no injection extension points). Self-applied, so it fits this
//!   contract unchanged — but it is only half a sandbox: the access-confining
//!   half (restricted token, integrity level, AppContainer, job object) is
//!   parent-side and not implemented, so a Windows renderer can still reach
//!   files and the network. See that module.
//! * `unsupported.rs` — honest no-ops on the other Unixes: multi-process still
//!   runs over Unix sockets with components unconfined and saying so.
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
//! | [`confine_spawned_child`] | immediately after spawn, **by the parent** | children (Windows job object; Linux cgroup memory bound) |
//!
//! Linux additionally has [`lock_down_fork_server`], which is not part of the
//! cross-platform contract: no other backend has a zygote to confine.
//!
//! `deny_debugger_attach` is compiled in every build — the single-process
//! engine has no children to confine but still holds the cookie jar in its own
//! address space. The other four exist only under the `multi-process` feature,
//! where there are separate processes to cap.
//!
//! ### The contract assumes self-application
//!
//! Every operation above is invoked *by the process being confined*, on itself,
//! after `fork`/`exec`. That is a POSIX assumption, and both current backends
//! satisfy it: seccomp, `unshare`, `prctl`, `sandbox_init` and `PT_DENY_ATTACH`
//! are all self-applied, and a process may always restrict itself further
//! without privilege. The additions each backend still wants (Landlock on
//! Linux, a tighter profile on macOS) are self-applied too, so they fit the
//! contract as it stands.
//!
//! Windows does not work this way, so the table above is not portable as
//! written. Its primary mechanisms — a restricted token, a job object, an
//! AppContainer, and the process mitigation policies (`ProhibitDynamicCode`,
//! `NoChildProcessCreation`) — are attached by the *parent* at
//! `CreateProcess` time, before the child executes an instruction. They cannot
//! be expressed as a `lock_down_*` call from inside the child.
//!
//! That is what [`confine_spawned_child`] is: the sixth operation, applied by the
//! parent rather than the process itself. It turned out to be less invasive
//! than expected, because the mechanisms split three ways rather than two:
//!
//! * Self-applied after exec — the mitigation policies, and (because a token
//!   may always lower its own integrity) the low-integrity drop. These fit the
//!   original contract untouched.
//! * Parent-side but *post*-spawn — a job object, which can be attached to a
//!   process that already exists. This is the one new hook.
//! * Parent-side and *pre*-create — supplied to `CreateProcess` itself, which
//!   [`crate::spawn`] now owns. A **restricted token** (privileges stripped,
//!   groups deny-only) is applied this way. Its stronger *restricting-SID*
//!   form, and an AppContainer, are not: the first cannot start a process
//!   unless the executable is ACLed for the `RESTRICTED` SID (verified by
//!   experiment, not assumed — see `windows.rs`), and both are larger pieces
//!   of work. Notably, Chromium's two-phase drop does **not** rescue the
//!   restricting-SID token here: image loading is checked against the primary
//!   token throughout, which thread impersonation does not cover, so the child
//!   dies in the loader regardless.

// --- platform seam: the only place a sandbox `target_os` cfg lives ---
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
use linux as imp;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
use macos as imp;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
use windows as imp;

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
mod unsupported;
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
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

/// Impose resource ceilings (committed heap plus an address-space ceiling, fd
/// count, no core dumps, lowered scheduling priority) on a child. Called from
/// `pre_exec`, so it must stay async-signal-safe. rlimits only ever lower, so a
/// child cannot undo them.
#[cfg(feature = "multi-process")]
pub fn apply_child_rlimits() -> std::io::Result<()> {
    imp::apply_child_rlimits()
}

/// Isolate a child's namespaces when `enable` is set (content processes and
/// services), leaving them in place otherwise (the net component). On Linux this
/// unshares the network namespace (the load-bearing one) plus IPC and UTS as
/// defense in depth; the mount and PID namespaces are deliberately left out for
/// concrete reasons (see the backend docs). Called from `pre_exec`, so it must
/// stay async-signal-safe. On platforms without namespaces this is deferred into
/// the lockdown profile — see the backend docs.
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

/// What extra capability an engine-spawned service needs beyond the content
/// baseline. Unlike a renderer or the decoder, these roles need a privilege the
/// zygote gave up (filesystem or device access), which is why each is spawned
/// from the engine with its own filter rather than forked from the fork server.
#[derive(Clone, Copy)]
pub struct ServiceCaps {
    /// Needs to open files (font, storage). Adds `openat` on Linux.
    pub filesystem: bool,
    /// Needs a device node + `ioctl` (audio, GPU). Adds `openat` + `ioctl`.
    pub device: bool,
}

/// Confine an engine-spawned service to the content baseline plus exactly the
/// capability `caps` selects. `name` is the label in its lockdown banner.
///
/// `fs_allow` names the directories/files a filesystem service may touch, each
/// with a `writable` flag. On Linux these become a Landlock ruleset that
/// confines the service's `openat` to exactly those paths — the path-level
/// guard seccomp cannot provide. Ignored on platforms whose confinement gates
/// files another way (macOS) or not at all (Windows). Empty for device
/// services and where no path scoping applies.
///
/// Fail-closed on the seccomp/profile install like the other lockdowns; the
/// Landlock portion is best-effort (see the Linux backend).
#[cfg(feature = "multi-process")]
pub fn lock_down_service(name: &str, caps: ServiceCaps, fs_allow: &[(&std::path::Path, bool)]) {
    imp::lock_down_service(name, caps.filesystem, caps.device, fs_allow);
}

/// Apply parent-side confinement to a child that has just been spawned.
///
/// **The sixth operation**, and the first that is not self-applied: the parent
/// does this *to* the child. Windows needs it because its access controls
/// (here a job object; later a restricted token and an AppContainer) can only
/// be attached from outside — see the note below on why the contract assumed
/// otherwise. **Linux** uses it too, for the one bound a process cannot set on
/// itself usefully: a cgroup v2 `memory.max` places the child in its own
/// memory-limited cgroup (the RSS analogue of the Windows job-object memory cap),
/// best-effort. macOS confinement is entirely self-applied, so this stays a no-op
/// there and the platforms keep a symmetric call site.
///
/// Called immediately after spawn, before the child has done any work. The
/// Windows path is fail-closed; the Linux cgroup bound is best-effort (never
/// fatal — a child that can't be cgroup-limited still runs, rlimit-bounded).
#[cfg(feature = "multi-process")]
pub fn confine_spawned_child(child: &crate::spawn::Child) -> std::io::Result<()> {
    #[cfg(target_os = "windows")]
    {
        return imp::confine_spawned_child(child.raw_handle());
    }
    #[cfg(target_os = "linux")]
    {
        // Best-effort cgroup memory bound (never fatal); see the backend.
        return imp::confine_spawned_child(child.id());
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        let _ = child;
        Ok(())
    }
}

/// Test hook for the `cgroup-memory-limit` probe: bound this process's memory via
/// cgroup v2 `memory.max` and read the ceiling back, or `None` where cgroup v2
/// memory delegation is unavailable (the probe then skips). Linux only.
#[cfg(all(feature = "multi-process", target_os = "linux"))]
pub fn cgroup_confine_self(limit: u64) -> Option<std::io::Result<u64>> {
    imp::cgroup_confine_self(limit)
}

/// Build a restricted primary token for a Windows child, or `None` if the host
/// refuses (the spawner then falls back to the inherited token). Windows only.
#[cfg(all(feature = "multi-process", target_os = "windows"))]
pub fn restricted_token() -> Option<::windows_sys::Win32::Foundation::HANDLE> {
    imp::restricted_token()
}

/// The AppContainer (lowbox) identity for a Windows child — the capability
/// sandbox that gives content roles no network and the net component
/// `internetClient`. Windows only. See the backend for the image-loading caveat.
#[cfg(all(feature = "multi-process", target_os = "windows"))]
pub use imp::AppContainerIdentity;

/// Build the AppContainer identity for a child (`internet` grants the
/// `internetClient` capability), or `None` if the SIDs cannot be built (the
/// spawner then falls back to the restricted-token path). Windows only.
#[cfg(all(feature = "multi-process", target_os = "windows"))]
pub fn app_container_identity(name: &str, internet: bool) -> Option<AppContainerIdentity> {
    imp::app_container_identity(name, internet)
}

/// Grant ALL APPLICATION PACKAGES read+execute on `path` so an AppContainer
/// child can load the image (the install-time ACL, done at spawn). Windows only.
#[cfg(all(feature = "multi-process", target_os = "windows"))]
pub fn grant_app_package_execute(path: &std::path::Path) -> std::io::Result<()> {
    imp::grant_app_package_execute(path)
}

/// Give a service's own AppContainer access to its file/directory (`writable`
/// also relabels it Low integrity) — the Windows analogue of the Linux services'
/// `openat` + Landlock to their own path. Windows only.
#[cfg(all(feature = "multi-process", target_os = "windows"))]
pub fn grant_container_path_access(
    path: &std::path::Path,
    container_sid: *mut std::ffi::c_void,
    writable: bool,
) -> std::io::Result<()> {
    imp::grant_container_path_access(path, container_sid, writable)
}

/// Apply a job-object memory cap to a process. Exposed for the probe suite,
/// which assigns the caps to itself to verify they bind. Windows only.
#[cfg(all(feature = "multi-process", target_os = "windows"))]
pub fn apply_job_limits(
    process: ::windows_sys::Win32::Foundation::HANDLE,
    memory_limit: usize,
) -> std::io::Result<()> {
    imp::apply_job_limits(process, memory_limit)
}

/// Read back a Windows process mitigation policy's flag word, so a probe can
/// confirm the kernel recorded what the backend asked for. Windows only.
#[cfg(all(feature = "multi-process", target_os = "windows"))]
pub fn get_mitigation_policy(
    policy: ::windows_sys::Win32::System::Threading::PROCESS_MITIGATION_POLICY,
) -> std::io::Result<u32> {
    imp::get_policy(policy)
}

/// Whether Landlock (path-level filesystem confinement) is usable on this
/// kernel. Linux only; used by the probe to skip cleanly where it is absent.
#[cfg(all(feature = "multi-process", target_os = "linux"))]
pub fn landlock_available() -> bool {
    imp::landlock_available()
}

/// Confine the **broker** (engine) process: a *loose* sandbox — like a browser's
/// main process — for the one process that holds every secret and deserializes
/// untrusted frames. It cannot be tightened to a renderer's degree (it must spawn
/// children, exec their libraries, thread, and open files and sockets), but two
/// blast radii can be reduced: a **Landlock** ruleset limits *writes* to the temp
/// dir (read/exec stay open), and a **deny-list seccomp filter** removes the
/// escalation syscalls it never uses (`ptrace`, kernel-module/`kexec`/`bpf`, the
/// keyring, `mount`/`setns`, …) while allowing everything else. Called by the
/// binary on its main thread before the engine starts, so every engine thread and
/// child inherits both. Linux only; a no-op elsewhere (a macOS Seatbelt broker
/// profile would be the equivalent, and is not built yet). Best-effort: a kernel
/// missing either mechanism leaves that layer off rather than aborting.
#[cfg(all(feature = "multi-process", target_os = "linux"))]
pub fn lock_down_broker() {
    imp::lock_down_broker();
}

#[cfg(all(feature = "multi-process", not(target_os = "linux")))]
pub fn lock_down_broker() {}

/// Cap the fork server (Linux only — it is the one platform with a zygote).
///
/// Sits outside the five-operation table above because it is not a per-platform
/// contract: no other backend has a fork server to confine. Note its filter is
/// inherited by every renderer it forks, so it must stay a superset of the
/// renderer baseline — see the backend for what that forces in.
#[cfg(all(feature = "multi-process", target_os = "linux"))]
pub fn lock_down_fork_server() {
    imp::lock_down_fork_server();
}

/// Verify at startup that the fork-server filter permits what a forked
/// renderer needs on *this* host's C library, aborting if it does not. Called
/// straight after [`lock_down_fork_server`]. The allowlist is libc-sensitive in
/// ways a compile-time check cannot see, so this verifies rather than predicts
/// — see the backend for what varies and why.
#[cfg(all(feature = "multi-process", target_os = "linux"))]
pub fn verify_fork_server_filter() {
    imp::verify_fork_server_filter();
}

/// Test hook: run the canary against a filter with one syscall deliberately
/// removed, so the integration suite can prove the canary *detects* rather than
/// merely passes. Aborts the process, as a real canary failure would. Spawned
/// only by the `selftest` role.
#[cfg(all(feature = "multi-process", target_os = "linux"))]
pub fn canary_must_detect_a_missing_syscall() -> ! {
    imp::canary_must_detect_a_missing_syscall()
}
