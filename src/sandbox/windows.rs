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
//! ## What is applied, and what is left
//!
//! Applied: the mitigation policies (self-applied), low integrity (a token can
//! always lower its own), a job object with a memory cap, and a **restricted
//! primary token** — privileges stripped, groups deny-only — handed to the
//! child at `CreateProcessAsUserW` (see [`crate::spawn`]).
//!
//! Left: the *restricting-SID* form of the token, which would confine file
//! access much further but cannot start a process without the executable being
//! ACLed for the `RESTRICTED` SID (established empirically — see
//! [`restricted_token`]); and an AppContainer, which is what would give the
//! renderer/net network split. Both are parent-side and neither is here.
//!
//! Startup is **fail-closed** as on the other platforms: if a policy this file
//! considers essential cannot be installed, the component aborts rather than
//! run believing itself confined.

use std::ffi::c_void;

/// Address-space ceiling for a confined child — the `RLIMIT_AS` analogue,
/// matching the Linux backend's 512 MiB.
#[cfg(feature = "multi-process")]
const CHILD_MEMORY_LIMIT: usize = 512 * 1024 * 1024;

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

    // Lower integrity *after* the mitigation policies: those are pure
    // capability removals, whereas this changes what objects we may touch, and
    // doing it last keeps the window in which we are both privileged and
    // partially confined as small as possible.
    let integrity = match set_low_integrity() {
        Ok(()) => "low-integrity",
        Err(e) => {
            // Best-effort, like win32k below: a host or token configuration
            // that refuses this should degrade hardening, not refuse to run.
            eprintln!("[{role}] warning: could not drop to low integrity: {e}");
            "integrity-unchanged"
        }
    };

    let win32k = match set_policy(ProcessSystemCallDisablePolicy, DISALLOW_WIN32K_SYSCALLS) {
        Ok(()) => "win32k-blocked",
        Err(e) => {
            eprintln!("[{role}] warning: win32k lockdown unavailable: {e}");
            "win32k-available"
        }
    };

    eprintln!(
        "[{role}] mitigation policies active (no dynamic code, no child processes, \
         {win32k}, {integrity})"
    );
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
/// Cap an engine-spawned service.
///
/// The `filesystem`/`device` caps are ignored here: the Windows mitigation
/// policies remove code execution and process creation but do not gate file or
/// device access (that would need the restricted-token/AppContainer half the
/// module docs describe as unbuilt). So every service gets the same policy set
/// as a renderer, and the per-service distinction the Linux backend draws does
/// not exist on Windows yet.
#[cfg(feature = "multi-process")]
pub fn lock_down_service(name: &str, _filesystem: bool, _device: bool) {
    deny_debugger_attach();
    lock_down(name);
}

#[cfg(feature = "multi-process")]
pub fn lock_down_net() {
    deny_debugger_attach();
    lock_down("net");
}

/// Resource ceilings are imposed by [`confine_spawned_child`] instead.
///
/// This hook is a Unix `pre_exec` concept and is never reached on Windows —
/// there is no post-fork/pre-exec moment to run code in. The equivalent caps
/// live in a job object, which the *parent* attaches after `CreateProcess`
/// returns.
#[cfg(feature = "multi-process")]
pub fn apply_child_rlimits() -> std::io::Result<()> {
    Ok(())
}

/// Put a freshly spawned child into a job object carrying its resource caps.
///
/// This is the parent-side half of Windows confinement — the half that cannot
/// be self-applied — and it is deliberately the *simplest* member of that
/// family, because a job can be attached to a process that already exists.
/// Its siblings (a restricted token, an AppContainer) must be supplied at
/// `CreateProcess` time and so need a spawn path that `std::process::Command`
/// cannot provide. See the module docs.
///
/// The limits:
/// * **`PROCESS_MEMORY`** — the `RLIMIT_AS` analogue Windows otherwise lacks.
///   An over-allocating child fails its allocation and dies alone rather than
///   taking the machine with it.
/// * **`ACTIVE_PROCESS` = 1** — belt and braces with the child-process
///   mitigation policy: even if that policy could be evaded, the job refuses to
///   hold a second process.
/// * **`KILL_ON_JOB_CLOSE`** — when the last handle to the job closes, every
///   process in it dies. Since the engine holds that handle for its own
///   lifetime, an engine that crashes takes its renderers with it instead of
///   orphaning them.
///
/// **The job handle is deliberately never closed.** `KILL_ON_JOB_CLOSE` is
/// armed by exactly that: were it closed here, the child would be killed
/// immediately. Leaking it ties the job's lifetime to the engine process,
/// which is the property we want. The cost is one handle per child spawned,
/// which for this PoC is negligible; a long-running browser would store the
/// handle alongside the child and drop it when the child is reaped.
#[cfg(feature = "multi-process")]
pub fn confine_spawned_child(child: windows_sys::Win32::Foundation::HANDLE) -> std::io::Result<()> {
    apply_job_limits(child, CHILD_MEMORY_LIMIT)
}

/// Create a job with `memory_limit`, apply it to `process`, and leak the job
/// handle (see [`confine_spawned_child`] for why).
#[cfg(feature = "multi-process")]
pub fn apply_job_limits(
    process: windows_sys::Win32::Foundation::HANDLE,
    memory_limit: usize,
) -> std::io::Result<()> {
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, SetInformationJobObject,
        JobObjectExtendedLimitInformation, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JOB_OBJECT_LIMIT_ACTIVE_PROCESS, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        JOB_OBJECT_LIMIT_PROCESS_MEMORY,
    };

    // SAFETY: an unnamed job with default security.
    let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
    if job.is_null() {
        return Err(std::io::Error::last_os_error());
    }

    // SAFETY: the struct is plain data with no pointers; zeroing is its
    // documented "no limits" state, and we then set only the fields we want.
    let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_PROCESS_MEMORY
        | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    info.BasicLimitInformation.ActiveProcessLimit = 1;
    info.ProcessMemoryLimit = memory_limit;

    // SAFETY: the info class matches the struct passed, with its true size.
    let ok = unsafe {
        SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            std::ptr::addr_of!(info).cast::<c_void>(),
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }

    // SAFETY: both handles are valid and owned by this process.
    if unsafe { AssignProcessToJobObject(job, process) } == 0 {
        return Err(std::io::Error::last_os_error());
    }

    // Intentionally not closed — see the doc comment.
    Ok(())
}

/// Drop this process to **low integrity**, self-applied and irreversible.
///
/// Windows integrity levels are mandatory access control: a low-integrity
/// process cannot write to any securable object labelled medium or above,
/// which is essentially all of the user's profile and registry. A token may
/// always lower its own level — raising it is what requires privilege — so
/// this fits the self-applied contract even though it is an access control,
/// unlike its siblings.
///
/// This is the largest single reduction in blast radius available here, and it
/// partially covers the gap left by the missing restricted token: the renderer
/// can still *read* broadly, but it can no longer write to the user's files.
fn set_low_integrity() -> std::io::Result<()> {
    use windows_sys::Win32::Foundation::{CloseHandle, LocalFree};
    use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;
    use windows_sys::Win32::Security::{
        SetTokenInformation, TokenIntegrityLevel, SID_AND_ATTRIBUTES, TOKEN_ADJUST_DEFAULT,
        TOKEN_MANDATORY_LABEL,
    };
    // windows-sys files this constant under SystemServices rather than
    // Security, though it is a token group attribute.
    use windows_sys::Win32::System::SystemServices::SE_GROUP_INTEGRITY;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    // S-1-16-4096 = SECURITY_MANDATORY_LOW_RID.
    let sid_text: Vec<u16> = "S-1-16-4096\0".encode_utf16().collect();
    let mut sid = std::ptr::null_mut();
    // SAFETY: NUL-terminated wide string in, owned SID out (freed below).
    if unsafe { ConvertStringSidToSidW(sid_text.as_ptr(), &mut sid) } == 0 {
        return Err(std::io::Error::last_os_error());
    }

    let mut token = std::ptr::null_mut();
    // SAFETY: pseudo-handle for self; token handle out.
    let opened =
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_DEFAULT, &mut token) };
    if opened == 0 {
        let e = std::io::Error::last_os_error();
        unsafe { LocalFree(sid) };
        return Err(e);
    }

    let label = TOKEN_MANDATORY_LABEL {
        Label: SID_AND_ATTRIBUTES { Sid: sid, Attributes: SE_GROUP_INTEGRITY as u32 },
    };
    // SAFETY: the info class matches the struct; the SID is valid until freed.
    let set = unsafe {
        SetTokenInformation(
            token,
            TokenIntegrityLevel,
            std::ptr::addr_of!(label).cast::<c_void>(),
            std::mem::size_of::<TOKEN_MANDATORY_LABEL>() as u32,
        )
    };
    let result = if set == 0 { Err(std::io::Error::last_os_error()) } else { Ok(()) };

    // SAFETY: both were allocated by the calls above and are no longer used.
    unsafe {
        CloseHandle(token);
        LocalFree(sid);
    }
    result
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

/// Build a restricted primary token for a child, or `None` if the host
/// refuses (the spawner then falls back to the inherited token).
///
/// The token has:
///
/// * **Every privilege stripped** but `SeChangeNotifyPrivilege`
///   (`DISABLE_MAX_PRIVILEGE`). Privileges are the ambient "may override an
///   ACL" rights — debug other processes, load drivers, take ownership. A
///   renderer needs none.
/// * **Administrators marked deny-only.** A deny-only SID matches a DENY ace
///   but never an ALLOW one, so access held by virtue of being an admin — often
///   most of the interesting access on a developer's own box — stops applying.
///
/// ## The ceiling this deliberately stops short of
///
/// The strong form adds the `RESTRICTED` SID as a *restricting* SID, so access
/// requires the object's ACL to satisfy a second check that almost nothing
/// grants. That is close to "no file access at all" — and it does not work
/// here, which was established empirically rather than assumed:
///
/// A child created under such a token dies in the loader, before its `main`
/// runs, because **image and DLL loading are access-checked against the
/// primary token**, and nothing on disk grants `RESTRICTED` read on the
/// executable or the system DLLs. Chromium's two-phase drop (create suspended
/// under the lockdown token, impersonate a permissive token on the first
/// thread, warm up, then `RevertToSelf`) does *not* rescue this: thread
/// impersonation covers file opens the thread performs, not the loader's image
/// section mapping, which uses the primary token throughout. A direct A/B test
/// confirmed it — with the restricting SID the renderer never reached `main`;
/// without it the same two-phase machinery started and rendered cleanly.
///
/// Making the restricting SID usable needs the executable and every DLL it
/// loads to carry an ACE granting `RESTRICTED` read+execute. Chromium does
/// exactly this against its install directory at install time. That is an
/// installer concern, not something a program should do to its own build
/// output at spawn, so it is left as the documented next step rather than
/// implemented. Everything up to it — privileges, groups, low integrity, the
/// mitigation policies, the job object — is real and applied.
#[cfg(feature = "multi-process")]
pub fn restricted_token() -> Option<windows_sys::Win32::Foundation::HANDLE> {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{
        CreateRestrictedToken, CreateWellKnownSid, SID_AND_ATTRIBUTES, DISABLE_MAX_PRIVILEGE,
        TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_QUERY, WinBuiltinAdministratorsSid,
    };
    // Filed under SystemServices in windows-sys, like SE_GROUP_INTEGRITY.
    use windows_sys::Win32::System::SystemServices::SE_GROUP_USE_FOR_DENY_ONLY;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    // A SID must be DWORD-aligned: its sub-authority array is `DWORD`s starting
    // at offset 8, and the kernel reads them as such. A bare `[u8; 68]` has
    // 1-byte alignment, so on an unlucky stack address `CreateRestrictedToken`
    // faults with ERROR_NOACCESS (998) — intermittently, since stack alignment
    // varies per call and per process. That flakiness is what made a broken
    // token *sometimes* build and mimicked a working sandbox. The alignment
    // here is the fix; `align(8)` covers the DWORDs with margin.
    #[repr(align(8))]
    struct Sid([u8; 68]);

    /// A well-known SID fits comfortably in SECURITY_MAX_SID_SIZE (68 bytes).
    fn well_known(kind: i32) -> Option<Sid> {
        let mut sid = Sid([0u8; 68]);
        let mut len = sid.0.len() as u32;
        // SAFETY: a correctly sized, aligned buffer with its length by pointer.
        let ok = unsafe {
            CreateWellKnownSid(kind, std::ptr::null_mut(), sid.0.as_mut_ptr().cast(), &mut len)
        };
        (ok != 0).then_some(sid)
    }

    let mut admins = match well_known(WinBuiltinAdministratorsSid) {
        Some(s) => s,
        None => {
            eprintln!("[sandbox] could not build Administrators SID — using inherited token");
            return None;
        }
    };

    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: pseudo-handle for self; token handle out.
    let opened = unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY,
            &mut token,
        )
    };
    if opened == 0 {
        eprintln!(
            "[sandbox] OpenProcessToken failed ({}) — using inherited token",
            std::io::Error::last_os_error()
        );
        return None;
    }

    let deny = [SID_AND_ATTRIBUTES {
        Sid: admins.0.as_mut_ptr().cast(),
        Attributes: SE_GROUP_USE_FOR_DENY_ONLY as u32,
    }];

    let mut out: HANDLE = std::ptr::null_mut();
    // SAFETY: `token` is valid; the deny array lives across the call. No
    // restricting SIDs — see the doc comment for why the strong form is out.
    let ok = unsafe {
        CreateRestrictedToken(
            token,
            DISABLE_MAX_PRIVILEGE,
            deny.len() as u32,
            deny.as_ptr(),
            0,
            std::ptr::null(),
            0,
            std::ptr::null(),
            &mut out,
        )
    };
    let err = std::io::Error::last_os_error();
    // SAFETY: opened above and no longer needed.
    unsafe { CloseHandle(token) };

    if ok == 0 {
        eprintln!("[sandbox] CreateRestrictedToken failed ({err}) — using inherited token");
        return None;
    }
    Some(out)
}
