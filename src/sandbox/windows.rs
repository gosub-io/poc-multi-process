//! Windows backend: process mitigation policies.
//!
//! Satisfies the same public surface as the other backends
//! ([`crate::sandbox`]); the mechanisms differ because Windows has neither
//! seccomp nor Seatbelt. The parent module only compiles this file on
//! `target_os = "windows"`, so nothing here is guarded.
//!
//! ## What this is, and what it is not
//!
//! Windows confinement comes in two halves, and only one of them can be
//! applied by the process to itself:
//!
//! * **Process mitigation policies** — `SetProcessMitigationPolicy`, called by
//!   a process *on itself*, irreversibly. These remove classes of capability:
//!   allocating executable memory, creating child processes, accepting
//!   injected DLLs. That is what this file implements.
//! * **Access confinement** — a restricted token, a low/untrusted integrity
//!   level, an AppContainer, a job object. These decide what *objects* the
//!   process may touch: files, registry keys, the network, other processes.
//!   Every one of them is attached by the **parent** at `CreateProcess` time
//!   and cannot be self-applied. That is not implemented yet.
//!
//! The split matters for reading the guarantees honestly. What follows removes
//! the ability to *run new code* and to *spawn programs* — the tail end of most
//! exploit chains. It does **not** stop a compromised renderer from reading
//! your files or opening a socket, because on Windows those are token
//! decisions. Linux gets both halves (seccomp for syscalls, netns for reach)
//! and macOS gets both (SBPL covers operations and objects in one profile);
//! Windows here gets the first half only.
//!
//! Concretely, the per-role distinction the other backends enforce — renderers
//! have no network, the net component does — is **not enforced here**, because
//! the mechanism that would express it (AppContainer capabilities) is
//! parent-side. Both roles currently receive the same policy set.
//!
//! ## Adding the second half
//!
//! It needs the sixth, parent-side operation described in `mod.rs`: the
//! spawner attaches a restricted token and AppContainer at `CreateProcess`,
//! and `lock_down_*` becomes the second stage of a two-phase drop (Chromium's
//! model — create suspended and already-confined, warm up, then `LowerToken`).
//! That is a change to the shared contract, which is why it is not bundled
//! here: this half needed no contract change at all.
//!
//! Startup is **fail-closed** as on the other platforms: if a policy this file
//! considers essential cannot be installed, the component aborts rather than
//! run believing itself confined.

use std::ffi::c_void;

use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetProcessMitigationPolicy, SetProcessMitigationPolicy,
    ProcessChildProcessPolicy, ProcessDynamicCodePolicy, ProcessExtensionPointDisablePolicy,
    ProcessSystemCallDisablePolicy, PROCESS_MITIGATION_POLICY,
};

// The `PROCESS_MITIGATION_*_POLICY` structs are each a single `DWORD` of
// bitfields. windows-sys does not expose the struct types, and there is nothing
// to gain from them here: passing the flag word directly is exactly what the
// API reads. Bit positions are from the Win32 headers.

/// `PROCESS_MITIGATION_DYNAMIC_CODE_POLICY::ProhibitDynamicCode` — no new
/// executable memory, and no making existing memory executable.
const PROHIBIT_DYNAMIC_CODE: u32 = 1 << 0;

/// `PROCESS_MITIGATION_CHILD_PROCESS_POLICY::NoChildProcessCreation`.
const NO_CHILD_PROCESS_CREATION: u32 = 1 << 0;

/// `PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY::DisableExtensionPoints`
/// — refuses the legacy injection vectors (AppInit_DLLs, global window hooks,
/// IME plugins) that would otherwise load third-party code into this process.
const DISABLE_EXTENSION_POINTS: u32 = 1 << 0;

/// `PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY::DisallowWin32kSystemCalls`.
const DISALLOW_WIN32K_SYSCALLS: u32 = 1 << 0;

/// The policies every confined component installs, and which must succeed.
///
/// * **Dynamic code** is the W^X analogue of the seccomp `PROT_EXEC` argument
///   filter: it blocks the step most memory-corruption chains need in order to
///   run injected code. A real JS JIT would have to opt out of this one for a
///   dedicated region, exactly as the Linux filter would need relaxing.
/// * **Child process** is the analogue of `execve`/`clone` being absent from
///   the allowlist.
/// * **Extension points** has no Unix counterpart — it is a Windows-specific
///   injection surface that simply does not exist elsewhere.
#[cfg(feature = "multi-process")]
const ESSENTIAL: &[(PROCESS_MITIGATION_POLICY, u32, &str)] = &[
    (ProcessDynamicCodePolicy, PROHIBIT_DYNAMIC_CODE, "dynamic-code"),
    (ProcessChildProcessPolicy, NO_CHILD_PROCESS_CREATION, "child-process"),
    (ProcessExtensionPointDisablePolicy, DISABLE_EXTENSION_POINTS, "extension-points"),
];

/// Set one mitigation policy on the calling process.
#[cfg(feature = "multi-process")]
fn set_policy(policy: PROCESS_MITIGATION_POLICY, flags: u32) -> std::io::Result<()> {
    // SAFETY: `flags` is a 4-byte policy word matching the DWORD bitfield the
    // API expects for each of the policies used here, and its length is passed
    // explicitly.
    let ok = unsafe {
        SetProcessMitigationPolicy(
            policy,
            std::ptr::addr_of!(flags).cast::<c_void>(),
            std::mem::size_of::<u32>(),
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Read back a mitigation policy's flag word for the current process.
#[cfg(feature = "multi-process")]
pub fn get_policy(policy: PROCESS_MITIGATION_POLICY) -> std::io::Result<u32> {
    let mut flags: u32 = 0;
    // SAFETY: pseudo-handle for self; a 4-byte out-buffer with its length.
    let ok = unsafe {
        GetProcessMitigationPolicy(
            GetCurrentProcess(),
            policy,
            std::ptr::addr_of_mut!(flags).cast::<c_void>(),
            std::mem::size_of::<u32>(),
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(flags)
}

/// Install the policy set shared by every confined role.
///
/// Win32k lockdown is applied **best-effort**, unlike the essential three.
/// `DisallowWin32kSystemCalls` removes the win32k.sys syscall table — a large
/// kernel attack surface and, in Chromium's renderer, one of the most valuable
/// mitigations there is. But whether it can be enabled depends on what the
/// process has already loaded: a process that has initialized the GUI subsystem
/// cannot take it. Making it fatal would mean a component refusing to start on
/// hosts where the others apply perfectly well, so a failure here degrades
/// hardening and says so, in the same spirit as `deny_debugger_attach`
/// elsewhere. The `win32k` probe reports whether it actually took.
#[cfg(feature = "multi-process")]
fn lock_down(role: &str) {
    for (policy, flags, name) in ESSENTIAL {
        if let Err(e) = set_policy(*policy, *flags) {
            // Fail closed: never run a component that was meant to be confined
            // as though it were not.
            eprintln!("[{role}] FATAL: could not set {name} mitigation policy: {e}");
            std::process::exit(1);
        }
    }

    let win32k = match set_policy(ProcessSystemCallDisablePolicy, DISALLOW_WIN32K_SYSCALLS) {
        Ok(()) => "win32k-blocked",
        Err(e) => {
            eprintln!("[{role}] warning: win32k lockdown unavailable: {e}");
            "win32k-available"
        }
    };

    eprintln!("[{role}] mitigation policies active (no dynamic code, no child processes, {win32k})");
}

/// Cap a renderer.
///
/// Note this is *not* the full renderer confinement the Linux and macOS
/// backends provide: it removes code execution and process creation, but the
/// renderer can still reach files and the network, because those need the
/// parent-side half described in the module docs.
#[cfg(feature = "multi-process")]
pub fn lock_down_renderer() {
    deny_debugger_attach();
    lock_down("renderer");
}

/// Cap the net component.
///
/// Identical to the renderer's policy set today. The other backends give the
/// net component *more* than a renderer (it keeps the network); here neither
/// role is network-confined in the first place, so there is nothing to
/// differentiate. That is a gap, not a design choice — see the module docs.
#[cfg(feature = "multi-process")]
pub fn lock_down_net() {
    deny_debugger_attach();
    lock_down("net");
}

/// Resource ceilings. Not implemented on Windows.
///
/// The natural mechanism is a **job object** (`JOB_OBJECT_LIMIT_PROCESS_MEMORY`
/// for the `RLIMIT_AS` analogue, plus an active-process cap), which a process
/// can create and assign itself to. It is not wired up yet, and this hook is
/// additionally never reached: it is called from `pre_exec`, which is a Unix
/// concept the Windows spawn path has no equivalent of.
#[cfg(feature = "multi-process")]
pub fn apply_child_rlimits() -> std::io::Result<()> {
    Ok(())
}

/// No network isolation. On Linux this is an empty netns; on macOS the
/// Seatbelt profile omits `network-outbound`. The Windows equivalent is an
/// AppContainer without the `internetClient` capability — genuinely
/// capability-based, and the closest analogue of the three — but it is attached
/// by the parent at `CreateProcess`, so it cannot be expressed here. Until then
/// a Windows renderer *can* reach the network.
#[cfg(feature = "multi-process")]
pub fn isolate_network(_enable: bool) -> std::io::Result<()> {
    Ok(())
}

/// No equivalent on Windows, deliberately left as a no-op.
///
/// Same-user debugging is permitted by design: a process cannot refuse it the
/// way `PR_SET_DUMPABLE` or `PT_DENY_ATTACH` can. Stripping `PROCESS_VM_READ`
/// and `PROCESS_VM_WRITE` from the process object's DACL raises the bar, but
/// anyone holding `SeDebugPrivilege` — any administrator — bypasses it. The
/// real mechanism is Protected Process Light, which requires an anti-malware or
/// Windows-signed certificate a normal application will not have. So the honest
/// answer for this row is "weaker than both other platforms", not a workaround.
pub fn deny_debugger_attach() {}
