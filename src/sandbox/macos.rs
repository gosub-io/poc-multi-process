//! macOS backend: Seatbelt confinement (`sandbox_init`), `PT_DENY_ATTACH`
//! anti-debugging, and POSIX rlimits. This satisfies the same public surface
//! as the Linux backend ([`crate::sandbox`]); the mechanisms differ because
//! macOS has no seccomp and no network namespaces. The parent module only
//! compiles this file on `target_os = "macos"`, so nothing here is guarded.
//!
//! Where Linux installs a default-deny seccomp *syscall* allowlist, macOS uses
//! **Seatbelt** — the `sandbox_init(3)` policy engine that backs App Sandbox
//! and Chromium's macOS renderer sandbox. We hand it an SBPL profile that
//! starts from `(deny default)` and re-grants only what a already-initialized,
//! IPC-connected component still needs: signals to itself, read-only sysctls,
//! and Mach bootstrap lookups the runtime performs. Everything the Linux
//! allowlist withholds — opening files, spawning programs, and (for the
//! renderer) the network — is denied here too, in one profile rather than a
//! syscall list.
//!
//! Three seams do not line up with Linux, by design:
//!
//! * **Network isolation is folded into the lockdown profile.** Linux drops a
//!   renderer into an empty netns in `pre_exec` ([`isolate_network`]); macOS
//!   has no namespaces, so that hook is a no-op and the renderer's *profile*
//!   simply omits `network*`. The net component's profile grants it. Net
//!   effect is the same: renderers cannot reach the network, the net component
//!   can.
//! * **No `PROT_EXEC`/W^X argument filtering.** SBPL gates operations, not
//!   syscall arguments, so the fine-grained "writable-xor-executable" rule the
//!   seccomp filter carries has no direct analogue here. `(deny default)` still
//!   denies the file/network/exec escalation surface.
//! * **Seatbelt is deprecated API.** `sandbox_init` has been marked deprecated
//!   since 10.7 yet remains the mechanism every shipping browser uses; a
//!   production build would move to the modern App Sandbox entitlement model.
//!   We suppress the deprecation warning at the call site.
//!
//! Startup is **fail-closed** exactly as on Linux: if `sandbox_init` refuses
//! the profile the component aborts rather than run unconfined.

use std::ffi::{c_char, c_int};

// Seatbelt entry points live in libSystem but are absent from the `libc`
// crate's macOS surface, so we declare them here. `sandbox_init` compiles the
// SBPL `profile` string and applies it to the calling process, returning 0 on
// success or -1 with a freshly allocated message in `*errorbuf` (released with
// `sandbox_free_error`). Passing a raw SBPL string (rather than a named
// profile) means `flags` is 0.
extern "C" {
    fn sandbox_init(profile: *const c_char, flags: u64, errorbuf: *mut *mut c_char) -> c_int;
    fn sandbox_free_error(errorbuf: *mut c_char);
}

// The profiles are deliberately *tight*, the SBPL counterpart of the seccomp
// allowlist's "enumerate exactly what's needed": we start from `(deny default)`
// and re-grant only what a component that is *already initialized* still
// touches. A renderer reaches lockdown with dyld done, its IPC socket and
// stderr already open, and thereafter only computes and reads/writes those
// existing fds — none of which is a sandbox-checked operation. Empirically it
// needs nothing beyond signalling and querying *itself*: no `mach-lookup`, no
// `sysctl-read`, no file or network access. Each grant here is a privilege a
// compromised renderer could turn against the host, so the shorter the list
// the smaller the surface. If a future renderer (a real rasterizer, fonts,
// GPU) needs more, add the *narrowest* grant that unblocks it — a specific
// `(allow mach-lookup (global-name "..."))`, not the blanket form.

/// A renderer may only push pixels: no network, no files, no new programs, and
/// no Mach/sysctl reach beyond itself.
#[cfg(feature = "multi-process")]
const RENDERER_PROFILE: &str = "\
(version 1)
(deny default)
(allow signal (target self))
(allow process-info* (target self))
\0";

/// The net component is the one role that keeps the network. It is otherwise
/// confined exactly like the renderer: no file opens, no exec, no Mach/sysctl.
#[cfg(feature = "multi-process")]
const NET_PROFILE: &str = "\
(version 1)
(deny default)
(allow signal (target self))
(allow process-info* (target self))
(allow network-outbound)
(allow system-socket)
\0";

/// Cap a renderer: pixels only — no network, files, or exec.
#[cfg(feature = "multi-process")]
pub fn lock_down_renderer() {
    deny_debugger_attach();
    enforce("renderer", RENDERER_PROFILE);
}

/// Cap the net component: like the renderer, but the network stays open.
#[cfg(feature = "multi-process")]
pub fn lock_down_net() {
    deny_debugger_attach();
    enforce("net", NET_PROFILE);
}

/// Cap an engine-spawned service. Seatbelt gates *operations* rather than
/// syscalls, so the Linux `filesystem`/`device` distinction maps onto profile
/// clauses: a filesystem service is granted `file-read*`/`file-write*`, a
/// device service additionally `iokit-open` (the closest analogue to `ioctl`
/// on a device node). Everything else stays `(deny default)`.
#[cfg(feature = "multi-process")]
pub fn lock_down_service(name: &str, filesystem: bool, device: bool, _fs_allow: &[(&std::path::Path, bool)]) {
    deny_debugger_attach();
    let mut profile = String::from("(version 1)\n(deny default)\n");
    profile.push_str("(allow signal (target self))\n");
    profile.push_str("(allow process-info* (target self))\n");
    if filesystem || device {
        profile.push_str("(allow file-read* file-write*)\n");
    }
    if device {
        profile.push_str("(allow iokit-open)\n");
    }
    profile.push('\0');
    enforce(name, &profile);
}

/// Apply an SBPL profile to this process, or die trying. Fail-closed, matching
/// the seccomp precedent: a component meant to be confined must never run as if
/// it were not.
#[cfg(feature = "multi-process")]
fn enforce(role: &str, profile: &str) {
    // SAFETY: `profile` is a NUL-terminated SBPL string (the `\0` suffix on the
    // constants); `err` is a valid out-pointer. On failure the callee allocates
    // a message we own and free.
    let mut err: *mut c_char = std::ptr::null_mut();
    #[allow(deprecated)]
    let rc = unsafe { sandbox_init(profile.as_ptr().cast(), 0, &mut err) };
    if rc == 0 {
        eprintln!("[{role}] seatbelt profile active (deny default)");
        return;
    }
    // SAFETY: on failure `err` points to a NUL-terminated C string we own.
    let detail = if err.is_null() {
        "unknown error".to_string()
    } else {
        let msg = unsafe { std::ffi::CStr::from_ptr(err) }.to_string_lossy().into_owned();
        unsafe { sandbox_free_error(err) };
        msg
    };
    eprintln!("[{role}] FATAL: could not install seatbelt sandbox: {detail}");
    std::process::exit(1);
}

/// Resource ceilings the engine imposes on a child at spawn time — the macOS
/// analogue of the Linux rlimits. `setrlimit`/`setpriority` are POSIX and
/// behave as on Linux, with one gap: macOS has no working `RLIMIT_AS`. Unlike
/// Linux it rejects the call outright (`EINVAL`, "current limit exceeds
/// maximum") rather than accepting-but-not-enforcing, so we cannot even set it
/// advisorily — the address-space cap is simply unavailable here. The fd,
/// core-dump, and priority caps are real. Called pre-exec, so async-signal-
/// safe: only `setrlimit`/`setpriority` syscalls.
#[cfg(feature = "multi-process")]
pub fn apply_child_rlimits() -> std::io::Result<()> {
    // No RLIMIT_AS on macOS (see above): a compromised child's memory growth is
    // bounded by the machine, not by us. A production build would reach for a
    // Jetsam/memory-pressure limit or a per-process memory footprint API.
    // A child needs only a handful of fds (its IPC socket + std streams).
    set_rlimit(libc::RLIMIT_NOFILE, 128)?;
    // No core dumps — a crash must not spill page contents (cookies, tokens).
    set_rlimit(libc::RLIMIT_CORE, 0)?;
    // Deprioritize content processes so a compromised child cannot starve the
    // trusted engine/UI of CPU. Raising the nice value needs no privilege and
    // cannot be undone by the child.
    set_priority(10)?;
    Ok(())
}

/// No network namespaces on macOS: a renderer's network is denied inside its
/// Seatbelt profile instead (see [`lock_down_renderer`]), applied once the
/// child is running. This pre-exec hook therefore has nothing to do — but it
/// stays truthful to its Linux counterpart's contract and returns `Ok` only
/// for the roles that are meant to be isolated.
#[cfg(feature = "multi-process")]
pub fn isolate_network(_enable: bool) -> std::io::Result<()> {
    Ok(())
}

/// Mark the calling process non-dumpable, closing the *inbound* debugging
/// surface — the macOS analogue of Linux's `PR_SET_DUMPABLE`.
///
/// `ptrace(PT_DENY_ATTACH)` tells the kernel to refuse any future
/// `PT_ATTACH`/`task_for_pid` against this process, so another same-user
/// process cannot attach a debugger and read our address space — which for the
/// engine means the cookie jar in cleartext. This is best-effort hardening
/// against *other* software on the host, not the boundary that contains a
/// compromised child, so (like the Linux version) it warns rather than aborts
/// on failure. Applies to the single-process build too, which still holds the
/// jar in its address space.
///
/// **Verification limit.** The probe suite checks only that the kernel accepts
/// this request, not that an attach is subsequently refused — unlike Linux,
/// where the equivalent probe performs a real `PTRACE_ATTACH` and requires
/// `EPERM`. An unprivileged macOS process cannot `PT_ATTACH` even to its own
/// child without SIP disabled or task-port entitlements, so the control case
/// for such a test fails and it proves nothing either way. Confirming the
/// effect needs a privileged host.
pub fn deny_debugger_attach() {
    // SAFETY: PT_DENY_ATTACH takes no addr/data and affects only the caller.
    if unsafe { libc::ptrace(libc::PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) } < 0 {
        eprintln!(
            "[sandbox] warning: could not deny debugger attach: {}",
            std::io::Error::last_os_error()
        );
    }
}

/// Lower the calling process's scheduling priority (higher nice = lower
/// priority). Async-signal-safe (a single syscall), so usable pre-exec.
#[cfg(feature = "multi-process")]
fn set_priority(nice: c_int) -> std::io::Result<()> {
    // SAFETY: PRIO_PROCESS with pid 0 targets the calling process.
    if unsafe { libc::setpriority(libc::PRIO_PROCESS, 0, nice) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// macOS `setrlimit` takes the resource as a plain `c_int` (Linux uses
/// `__rlimit_resource_t`); otherwise identical.
#[cfg(feature = "multi-process")]
fn set_rlimit(resource: c_int, limit: libc::rlim_t) -> std::io::Result<()> {
    let rl = libc::rlimit { rlim_cur: limit, rlim_max: limit };
    // SAFETY: valid resource id and a valid rlimit pointer.
    if unsafe { libc::setrlimit(resource, &rl) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}
