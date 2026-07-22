//! Windows backend: process mitigation policies.
//!
//! Satisfies the same public surface as the other backends
//! ([`crate::sandbox`]); the mechanisms differ because Windows has neither
//! seccomp nor Seatbelt. The parent module only compiles this file on
//! `target_os = "windows"`, so nothing here is guarded.
//!
//! ## What this is, and what it is not
//!
//! Windows confinement comes in two halves:
//!
//! * **Process mitigation policies** — `SetProcessMitigationPolicy`, called by
//!   a process *on itself*, irreversibly. These remove classes of capability:
//!   allocating executable memory, creating child processes, accepting
//!   injected DLLs. That is the self-applied half.
//! * **Access confinement** — a restricted token, a low/untrusted integrity
//!   level, an **AppContainer**, a job object. These decide what *objects* the
//!   process may touch: files, registry keys, the network, other processes.
//!   Every one is attached by the **parent** at `CreateProcess` time (that is
//!   what [`crate::spawn`] owning the spawn call buys).
//!
//! Both halves are now here. What the mitigation policies remove is the ability
//! to *run new code* and to *spawn programs* — the tail end of most exploit
//! chains. What the AppContainer adds is the *object* confinement Linux gets
//! from seccomp+netns and macOS from SBPL: a renderer with **no network and no
//! broad file access**, the net component with **`internetClient`**, and each
//! filesystem service reaching **only its own path** — the per-role split the
//! other backends enforce, which Windows can only express through an
//! AppContainer (a "lowbox" token, what UWP apps and Chromium's renderer run
//! under). See [`app_container_identity`] and [`crate::spawn`].
//!
//! ## What is applied, and how the AppContainer is gated
//!
//! Always applied: the mitigation policies (self-applied), low integrity (a
//! token can always lower its own), a job object with a memory cap, and a
//! **restricted primary token** — privileges stripped, groups deny-only.
//!
//! The **AppContainer** is applied when `GOSUB_WIN_APPCONTAINER` is set, and it
//! then replaces the restricted token (the lowbox *is* the confinement). It is
//! env-gated, not default-on, for one honest reason: a lowbox process can only
//! load images (its own executable, DLLs) that the filesystem grants an
//! app-package SID, so the binary must live at an **app-package-accessible
//! location** — `C:\ProgramData` or `C:\Program Files`, where installers put
//! programs (Chromium ACLs its own install dir for exactly this). Run from an
//! ordinary build/`target` directory it cannot load, so leaving it default-on
//! would break a from-`target` run (and CI). The `grant_app_package_execute`
//! and per-service `grant_container_path_access` calls at spawn are what make it
//! work once the binary is at such a location; validated end to end on Windows 11.
//!
//! The *restricting-SID* form of the token remains out for the same
//! image-loading reason it always was (see [`restricted_token`]); the
//! AppContainer above is the mechanism that actually clears that wall.
//!
//! Startup is **fail-closed** as on the other platforms: if a mitigation policy
//! this file considers essential cannot be installed, the component aborts
//! rather than run believing itself confined.

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
pub fn lock_down_service(name: &str, _filesystem: bool, _device: bool, _fs_allow: &[(&std::path::Path, bool)]) {
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

/// An AppContainer identity for a spawned child: the container SID plus any
/// capability SIDs, kept alive so a `SECURITY_CAPABILITIES` can point into it
/// across `CreateProcess`. Frees the SIDs on drop.
///
/// AppContainer is the Windows capability sandbox — the "lowbox" token that UWP
/// apps and Chromium's renderer run under. A lowbox process can reach a securable
/// object only if the object's ACL grants an app-package or *capability* SID, on
/// top of the ordinary user check. A **content** role (renderer, decoder,
/// services) gets an AppContainer with **no** capabilities — no network, no
/// broad file access; the **net** component gets the **`internetClient`**
/// capability. That is the renderer/net split the Unix and macOS backends enforce
/// and the Windows backend otherwise could not.
///
/// One caveat, shared with the restricting-SID token (see [`restricted_token`]):
/// a lowbox process can only load images the filesystem grants an app-package SID
/// — system DLLs already do, but the PoC's own executable in `target\…` does not,
/// so without an install-time (or spawn-time) ACL granting `ALL_APPLICATION_PACKAGES`
/// the child dies in the loader. That is what [`grant_app_package_execute`]
/// exists to work around.
#[cfg(feature = "multi-process")]
pub struct AppContainerIdentity {
    container_sid: *mut c_void,
    capability_sids: Vec<*mut c_void>,
}

// SAFETY: the contained SIDs are heap allocations owned solely by this struct;
// they are not tied to the creating thread and are only read (by CreateProcess)
// or freed (on drop).
#[cfg(feature = "multi-process")]
unsafe impl Send for AppContainerIdentity {}

#[cfg(feature = "multi-process")]
impl AppContainerIdentity {
    /// The AppContainer (lowbox) SID, for `SECURITY_CAPABILITIES::AppContainerSid`.
    pub fn container_sid(&self) -> *mut c_void {
        self.container_sid
    }

    /// The capability SIDs, for the `SECURITY_CAPABILITIES::Capabilities` array.
    pub fn capability_sids(&self) -> &[*mut c_void] {
        &self.capability_sids
    }
}

#[cfg(feature = "multi-process")]
impl Drop for AppContainerIdentity {
    fn drop(&mut self) {
        use windows_sys::Win32::Foundation::LocalFree;
        use windows_sys::Win32::Security::FreeSid;
        // SAFETY: `container_sid` came from DeriveAppContainerSidFromAppContainerName
        // (released with FreeSid); each capability SID from ConvertStringSidToSidW
        // (released with LocalFree). Null guards cover a partially-built identity.
        unsafe {
            for &cap in &self.capability_sids {
                if !cap.is_null() {
                    LocalFree(cap);
                }
            }
            if !self.container_sid.is_null() {
                FreeSid(self.container_sid);
            }
        }
    }
}

/// Build the AppContainer identity for a child. `name` is the container name (its
/// SID is *derived* from it — no registered profile is needed for the process's
/// lifetime); `internet` adds the `internetClient` capability (the net
/// component's one privilege). Returns `None` if the SIDs cannot be built, so the
/// spawner can fall back to the restricted-token path.
#[cfg(feature = "multi-process")]
pub fn app_container_identity(name: &str, internet: bool) -> Option<AppContainerIdentity> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;
    use windows_sys::Win32::Security::Isolation::{
        CreateAppContainerProfile, DeriveAppContainerSidFromAppContainerName,
    };
    use windows_sys::Win32::Security::SID_AND_ATTRIBUTES;
    use windows_sys::Win32::System::SystemServices::SE_GROUP_ENABLED;

    // HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS) — the profile is already registered.
    const ALREADY_EXISTS: i32 = 0x8007_00B7u32 as i32;

    let w = |s: &str| -> Vec<u16> { s.encode_utf16().chain(std::iter::once(0)).collect() };

    // Build the capability SIDs first — they are needed both to register the
    // profile and for the launch-time SECURITY_CAPABILITIES.
    let mut capability_sids: Vec<*mut c_void> = Vec::new();
    if internet {
        // The `internetClient` capability's well-known SID (outbound network).
        let mut cap: *mut c_void = std::ptr::null_mut();
        // SAFETY: NUL-terminated SID string in; an owned PSID out on success.
        if unsafe { ConvertStringSidToSidW(w("S-1-15-3-1").as_ptr(), &mut cap) } == 0 || cap.is_null()
        {
            eprintln!("[sandbox] could not build internetClient capability SID");
            return None;
        }
        capability_sids.push(cap);
    }
    let mut cap_attrs: Vec<SID_AND_ATTRIBUTES> = capability_sids
        .iter()
        .map(|&c| SID_AND_ATTRIBUTES { Sid: c, Attributes: SE_GROUP_ENABLED as u32 })
        .collect();
    let (caps_ptr, caps_len) = if cap_attrs.is_empty() {
        (std::ptr::null_mut(), 0u32)
    } else {
        (cap_attrs.as_mut_ptr(), cap_attrs.len() as u32)
    };

    // Register the AppContainer profile. This is what creates the container's
    // on-disk profile (its LocalState folders) that a launched process needs —
    // deriving the SID alone does not, and `CreateProcess` into an unregistered
    // container fails with ERROR_FILE_NOT_FOUND. Idempotent: a container that is
    // already registered is fetched with `DeriveAppContainerSidFromAppContainerName`.
    let name_w = w(name);
    let mut container_sid: *mut c_void = std::ptr::null_mut();
    // SAFETY: NUL-terminated strings; the capability array with its length; an
    // owned PSID out.
    let hr = unsafe {
        CreateAppContainerProfile(
            name_w.as_ptr(),
            w("gosub PoC").as_ptr(),
            w("gosub process-isolation PoC sandbox").as_ptr(),
            caps_ptr,
            caps_len,
            &mut container_sid,
        )
    };
    let ok = if hr == ALREADY_EXISTS {
        // SAFETY: NUL-terminated name; an owned PSID out.
        let d = unsafe {
            DeriveAppContainerSidFromAppContainerName(name_w.as_ptr(), &mut container_sid)
        };
        d >= 0 && !container_sid.is_null()
    } else {
        hr >= 0 && !container_sid.is_null()
    };
    if !ok {
        eprintln!("[sandbox] could not set up AppContainer profile {name} (hr={hr:#010x})");
        // SAFETY: free the capability SIDs we built (nothing else was allocated).
        for &c in &capability_sids {
            unsafe { LocalFree(c) };
        }
        return None;
    }

    Some(AppContainerIdentity { container_sid, capability_sids })
}

// File-generic rights.
#[cfg(feature = "multi-process")]
const GENERIC_READ: u32 = 0x8000_0000;
#[cfg(feature = "multi-process")]
const GENERIC_WRITE: u32 = 0x4000_0000;
#[cfg(feature = "multi-process")]
const GENERIC_EXECUTE: u32 = 0x2000_0000;
// ACE inheritance flags: propagate to child objects (files) and containers
// (subdirectories) so a granted directory covers what is created under it.
#[cfg(feature = "multi-process")]
const OBJECT_INHERIT_ACE: u32 = 0x1;
#[cfg(feature = "multi-process")]
const CONTAINER_INHERIT_ACE: u32 = 0x2;

/// Merge one ALLOW ACE — `sid`, `rights`, `inheritance` — into `path`'s existing
/// DACL. The building block for the app-package and per-container grants below.
/// Idempotent: `SetEntriesInAclW` with `GRANT_ACCESS` folds into any existing ACE
/// for the same trustee rather than stacking duplicates.
#[cfg(feature = "multi-process")]
fn add_allow_ace(
    path: &std::path::Path,
    sid: *mut c_void,
    rights: u32,
    inheritance: u32,
) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{LocalFree, ERROR_SUCCESS};
    use windows_sys::Win32::Security::Authorization::{
        GetNamedSecurityInfoW, SetEntriesInAclW, SetNamedSecurityInfoW, EXPLICIT_ACCESS_W,
        GRANT_ACCESS, SE_FILE_OBJECT, TRUSTEE_IS_SID, TRUSTEE_IS_UNKNOWN,
    };
    use windows_sys::Win32::Security::{ACL, DACL_SECURITY_INFORMATION};

    let mut path_w: Vec<u16> = path.as_os_str().encode_wide().chain(std::iter::once(0)).collect();

    // Read the current DACL so the new grant merges rather than replaces it.
    let mut old_dacl: *mut ACL = std::ptr::null_mut();
    let mut sd: *mut c_void = std::ptr::null_mut();
    // SAFETY: valid path; out-params for the DACL and its owning descriptor.
    let rc = unsafe {
        GetNamedSecurityInfoW(
            path_w.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut old_dacl,
            std::ptr::null_mut(),
            &mut sd,
        )
    };
    if rc != ERROR_SUCCESS {
        return Err(std::io::Error::from_raw_os_error(rc as i32));
    }

    // SAFETY: a zeroed EXPLICIT_ACCESS_W is valid; we set the fields we need.
    let mut ea: EXPLICIT_ACCESS_W = unsafe { std::mem::zeroed() };
    ea.grfAccessPermissions = rights;
    ea.grfAccessMode = GRANT_ACCESS;
    ea.grfInheritance = inheritance;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType = TRUSTEE_IS_UNKNOWN;
    ea.Trustee.ptstrName = sid.cast();

    let mut new_dacl: *mut ACL = std::ptr::null_mut();
    // SAFETY: one entry, merged onto `old_dacl`; `new_dacl` owned (LocalFree).
    let rc = unsafe { SetEntriesInAclW(1, &ea, old_dacl, &mut new_dacl) };
    if rc != ERROR_SUCCESS {
        // SAFETY: allocated above.
        unsafe { LocalFree(sd) };
        return Err(std::io::Error::from_raw_os_error(rc as i32));
    }

    // SAFETY: valid path; applies the merged DACL.
    let rc = unsafe {
        SetNamedSecurityInfoW(
            path_w.as_mut_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            new_dacl,
            std::ptr::null_mut(),
        )
    };
    // SAFETY: all owned by us and no longer needed.
    unsafe {
        LocalFree(new_dacl.cast());
        LocalFree(sd);
    }
    if rc != ERROR_SUCCESS {
        return Err(std::io::Error::from_raw_os_error(rc as i32));
    }
    Ok(())
}

/// Build a SID from its string form (`ConvertStringSidToSidW`), or `None`.
/// Owned; free with `LocalFree`.
#[cfg(feature = "multi-process")]
fn sid_from_string(sddl: &str) -> Option<*mut c_void> {
    use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;
    let s: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
    let mut sid: *mut c_void = std::ptr::null_mut();
    // SAFETY: NUL-terminated SID string in; an owned PSID out on success.
    if unsafe { ConvertStringSidToSidW(s.as_ptr(), &mut sid) } == 0 || sid.is_null() {
        return None;
    }
    Some(sid)
}

/// Grant **ALL APPLICATION PACKAGES** read+execute on `path` so an AppContainer
/// (lowbox) child can load this image.
///
/// This is the install-time step Chromium performs on its own directory, done
/// here at spawn instead. Without it a lowbox child cannot read the PoC's
/// executable — under the user profile it grants no app-package access — and
/// `CreateProcess` fails with `ERROR_FILE_NOT_FOUND`. System DLLs already carry
/// this ACE (that is how UWP apps load them). Note the *directory* path to the
/// image must also be app-package-traversable, which is why the binary is run
/// from an app-package-accessible location (e.g. `C:\ProgramData`).
#[cfg(feature = "multi-process")]
pub fn grant_app_package_execute(path: &std::path::Path) -> std::io::Result<()> {
    // ALL APPLICATION PACKAGES.
    let sid = sid_from_string("S-1-15-2-1")
        .ok_or_else(|| std::io::Error::other("could not build ALL APPLICATION PACKAGES SID"))?;
    let r = add_allow_ace(path, sid, GENERIC_READ | GENERIC_EXECUTE, 0);
    // SAFETY: built above and no longer needed.
    unsafe { windows_sys::Win32::Foundation::LocalFree(sid) };
    r
}

/// Give one service's AppContainer access to *its* file/directory, the way the
/// Linux services get `openat` + Landlock to their own path — so a lowbox
/// storage or font service can still reach its data even though it has no broad
/// file access. `container_sid` is the service's own container (each service has
/// its own, so this never widens another role's reach). `writable` adds write
/// and, because the lowbox runs at Low integrity while the engine-created path is
/// Medium, relabels the path to Low integrity so the write is actually permitted.
#[cfg(all(feature = "multi-process", target_os = "windows"))]
pub fn grant_container_path_access(
    path: &std::path::Path,
    container_sid: *mut c_void,
    writable: bool,
) -> std::io::Result<()> {
    let mut rights = GENERIC_READ | GENERIC_EXECUTE;
    if writable {
        rights |= GENERIC_WRITE;
    }
    // A directory grant must propagate to the files created under it.
    let inheritance = if path.is_dir() { CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE } else { 0 };
    add_allow_ace(path, container_sid, rights, inheritance)?;
    if writable {
        set_low_integrity_label(path)?;
    }
    Ok(())
}

/// Relabel `path` to **Low** integrity (inherited, no-write-up), so a
/// Low-integrity lowbox process may write to it — the engine creates the path at
/// its own Medium integrity, which a Low process otherwise cannot write.
#[cfg(all(feature = "multi-process", target_os = "windows"))]
fn set_low_integrity_label(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{LocalFree, ERROR_SUCCESS};
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SetNamedSecurityInfoW, SE_FILE_OBJECT,
        SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{
        GetSecurityDescriptorSacl, ACL, LABEL_SECURITY_INFORMATION,
    };

    // SACL with one mandatory-label ACE: object+container inherit, no-write-up,
    // Low integrity level.
    let sddl: Vec<u16> = "S:(ML;OICI;NW;;;LW)\0".encode_utf16().collect();
    let mut psd: *mut c_void = std::ptr::null_mut();
    // SAFETY: NUL-terminated SDDL in; an owned security descriptor out (LocalFree).
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1 as u32,
            &mut psd,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error());
    }

    let mut present: i32 = 0;
    let mut sacl: *mut ACL = std::ptr::null_mut();
    let mut defaulted: i32 = 0;
    // SAFETY: valid descriptor; out-params for the SACL.
    if unsafe { GetSecurityDescriptorSacl(psd, &mut present, &mut sacl, &mut defaulted) } == 0 {
        // SAFETY: allocated above.
        unsafe { LocalFree(psd) };
        return Err(std::io::Error::last_os_error());
    }

    let mut path_w: Vec<u16> = path.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
    // SAFETY: valid path; the label goes in the SACL slot.
    let rc = unsafe {
        SetNamedSecurityInfoW(
            path_w.as_mut_ptr(),
            SE_FILE_OBJECT,
            LABEL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            sacl,
        )
    };
    // SAFETY: owns the descriptor (which owns the SACL); no longer needed.
    unsafe { LocalFree(psd) };
    if rc != ERROR_SUCCESS {
        return Err(std::io::Error::from_raw_os_error(rc as i32));
    }
    Ok(())
}
