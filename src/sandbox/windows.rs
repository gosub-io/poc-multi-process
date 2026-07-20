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
    // Phase two of the two-phase drop, and it must come first: the child has
    // been running under a permissive impersonation token so that startup could
    // complete. Dropping it here — at the moment the component is warm and
    // about to touch untrusted input — leaves only the heavily restricted
    // primary token it was created with. A no-op when the spawner fell back to
    // a single token.
    // Read the primary token's restricting-SID set *before* anything else, so
    // the banner reports what the parent actually gave us rather than what it
    // intended to.
    let restricting = restricted_sid_count().unwrap_or(0);

    lower_token();

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

    // `restricting-sids=N` is the one field here that reports the *parent's*
    // work rather than our own: non-zero means we were spawned two-phase under
    // the lockdown token, zero means the spawner fell back.
    eprintln!(
        "[{role}] mitigation policies active (no dynamic code, no child processes, \
         {win32k}, {integrity}, token-lowered, restricting-sids={restricting})"
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
    let sid_text: Vec<u16> = "S-1-16-4096 ".encode_utf16().collect();
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

/// The two tokens a two-phase drop needs.
///
/// ## Why two
///
/// A maximally restricted token cannot complete process startup. Loading the
/// CRT and the system DLLs needs read access that a token with restricting
/// SIDs no longer has, so a child created with only the lockdown token dies
/// during initialization — before any of our code runs, which makes it
/// undebuggable from the inside.
///
/// Chromium's answer, and the one used here: give the child the **lockdown**
/// token as its permanent identity, and additionally impersonate a more
/// permissive **initial** token on its first thread. Windows uses the
/// impersonation token for access checks while it is present, so startup
/// succeeds. Once warm, the child calls `RevertToSelf` (see [`lower_token`])
/// and from that moment only the lockdown token applies.
///
/// This is what makes a strong token usable at all — without it the only
/// alternative is weakening the *executable's* ACL to compensate for the token,
/// which is a worse trade: it makes the file permanently more accessible to
/// everything, rather than sequencing one process's drop correctly.
#[cfg(feature = "multi-process")]
pub struct TokenPair {
    /// The child's permanent, heavily restricted primary token.
    pub lockdown: windows_sys::Win32::Foundation::HANDLE,
    /// A more permissive impersonation token, dropped once the child is warm.
    pub initial: windows_sys::Win32::Foundation::HANDLE,
}

/// Build one restricted token from this process's own.
///
/// `restricting` adds the RESTRICTED SID as a *restricting* SID, which is the
/// strong form: access then requires the object's ACL to satisfy **both** the
/// normal check and a second check against the restricted set. Almost nothing
/// on the system grants RESTRICTED, so this is close to "no file access at
/// all" — correct for a warmed-up renderer, fatal during startup.
///
/// Without `restricting` the token still has every privilege stripped
/// (`DISABLE_MAX_PRIVILEGE`) and Administrators marked deny-only, so
/// group-granted access no longer applies. That is the permissive half of the
/// pair: confined, but still able to start a process.
#[cfg(feature = "multi-process")]
fn build_token(restricting: bool) -> std::io::Result<windows_sys::Win32::Foundation::HANDLE> {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{
        CreateRestrictedToken, CreateWellKnownSid, SID_AND_ATTRIBUTES, DISABLE_MAX_PRIVILEGE,
        TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_QUERY, WinBuiltinAdministratorsSid,
        WinRestrictedCodeSid,
    };
    // Filed under SystemServices in windows-sys, like SE_GROUP_INTEGRITY.
    use windows_sys::Win32::System::SystemServices::SE_GROUP_USE_FOR_DENY_ONLY;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    /// A well-known SID fits comfortably in SECURITY_MAX_SID_SIZE (68 bytes).
    fn well_known(kind: i32) -> std::io::Result<[u8; 68]> {
        let mut sid = [0u8; 68];
        let mut len = sid.len() as u32;
        // SAFETY: a correctly sized buffer with its length passed by pointer.
        let ok = unsafe {
            CreateWellKnownSid(kind, std::ptr::null_mut(), sid.as_mut_ptr().cast(), &mut len)
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(sid)
    }

    let mut admins = well_known(WinBuiltinAdministratorsSid)?;
    let mut restricted_sid = well_known(WinRestrictedCodeSid)?;

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
        return Err(std::io::Error::last_os_error());
    }

    let deny = [SID_AND_ATTRIBUTES {
        Sid: admins.as_mut_ptr().cast(),
        Attributes: SE_GROUP_USE_FOR_DENY_ONLY as u32,
    }];
    let restrict = [SID_AND_ATTRIBUTES {
        Sid: restricted_sid.as_mut_ptr().cast(),
        Attributes: 0,
    }];

    let mut out: HANDLE = std::ptr::null_mut();
    // SAFETY: `token` is valid; both SID arrays live across the call.
    let ok = unsafe {
        CreateRestrictedToken(
            token,
            DISABLE_MAX_PRIVILEGE,
            deny.len() as u32,
            deny.as_ptr(),
            0,
            std::ptr::null(),
            if restricting { restrict.len() as u32 } else { 0 },
            if restricting { restrict.as_ptr() } else { std::ptr::null() },
            &mut out,
        )
    };
    let err = std::io::Error::last_os_error();
    // SAFETY: opened above and no longer needed.
    unsafe { CloseHandle(token) };

    if ok == 0 {
        return Err(err);
    }
    Ok(out)
}

/// Build both tokens, or `None` if either cannot be made.
///
/// All-or-nothing on purpose. A half-built pair would mean creating the child
/// with the lockdown token and no way to let it start — a browser that refuses
/// to run. Returning `None` instead lets the spawner fall back to the
/// single-token path, which is less confined but works.
#[cfg(feature = "multi-process")]
pub fn token_pair() -> Option<TokenPair> {
    use windows_sys::Win32::Foundation::CloseHandle;
    let lockdown = match build_token(true) {
        Ok(t) => t,
        Err(e) => {
            // Say why, and say it loudly: a silent fallback here means every
            // Windows child runs less confined than intended, and nothing else
            // in the output would reveal it.
            eprintln!("[sandbox] lockdown token unavailable ({e}) — falling back");
            return None;
        }
    };
    match build_token(false) {
        Ok(initial) => Some(TokenPair { lockdown, initial }),
        Err(e) => {
            eprintln!("[sandbox] initial token unavailable ({e}) — falling back");
            // SAFETY: built just above and otherwise leaked.
            unsafe { CloseHandle(lockdown) };
            None
        }
    }
}

/// Build a single restricted token, the fallback when the pair cannot be made.
#[cfg(feature = "multi-process")]
pub fn restricted_token() -> Option<windows_sys::Win32::Foundation::HANDLE> {
    match build_token(false) {
        Ok(t) => Some(t),
        Err(e) => {
            eprintln!("[sandbox] restricted token unavailable ({e}) — using inherited token");
            None
        }
    }
}

/// How many *restricting* SIDs this process's token carries.
///
/// This is the observable that distinguishes a two-phase spawn from its
/// fallbacks, and it exists because nothing else did. `lower_token` runs on
/// every path and `RevertToSelf` succeeds trivially when there is no
/// impersonation to drop, so the lockdown banner alone cannot tell whether the
/// strong token was ever applied — a silent fallback would look exactly like
/// success. Only the primary token's restricted-SID set differs, and only the
/// child can see it.
///
/// Non-zero means the child is running under the lockdown token: access
/// requires both the normal ACL check and a second check against this set.
#[cfg(feature = "multi-process")]
fn restricted_sid_count() -> Option<u32> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::Security::{GetTokenInformation, TokenRestrictedSids, TOKEN_QUERY};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token = std::ptr::null_mut();
    // SAFETY: pseudo-handle for self; token handle out.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return None;
    }
    // The first DWORD of TOKEN_GROUPS is the count; a modest buffer reads it
    // even when the full list would not fit.
    let mut buf = [0u8; 4096];
    let mut needed = 0u32;
    // SAFETY: correctly sized buffer with its length and an out-param.
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenRestrictedSids,
            buf.as_mut_ptr().cast(),
            buf.len() as u32,
            &mut needed,
        )
    };
    // SAFETY: opened above.
    unsafe { CloseHandle(token) };
    (ok != 0).then(|| u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]))
}

/// Drop the permissive impersonation token, leaving only the lockdown token.
///
/// This is phase two, and the reason it lives here rather than in the spawner
/// is that only the child knows when it is warm. Called at the top of the
/// lockdown, which is precisely the point the component has finished
/// initializing and is about to start handling untrusted input.
///
/// Harmless when the child was spawned by the single-token fallback: there is
/// no impersonation token to drop and `RevertToSelf` succeeds trivially.
#[cfg(feature = "multi-process")]
fn lower_token() {
    use windows_sys::Win32::Security::RevertToSelf;
    // SAFETY: affects only the calling thread's impersonation state.
    if unsafe { RevertToSelf() } == 0 {
        eprintln!(
            "[sandbox] warning: could not lower token: {}",
            std::io::Error::last_os_error()
        );
    }
}
