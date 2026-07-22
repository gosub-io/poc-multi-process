//! Linux backend: seccomp-BPF confinement, network namespaces, rlimits, and
//! `prctl(PR_SET_DUMPABLE)`. This is the reference implementation of the
//! privilege model; the public surface it satisfies lives in
//! [`crate::sandbox`]. Every item here is unconditionally Linux — the parent
//! module only compiles this file on `target_os = "linux"`, so nothing inside
//! carries a `target_os` guard.
//!
//! Process isolation is only worth as much as the privileges you drop inside
//! each process. After a child has connected its IPC link we install a
//! seccomp-BPF filter — the same mechanism Chromium uses to sandbox its
//! renderers.
//!
//! The filter is a default-deny **allowlist**: we enumerate the syscalls a
//! component legitimately needs and everything else is a fatal `SIGSYS`. This
//! is fail-closed — a syscall we never considered (a new one, or an obscure
//! bypass such as io_uring-based networking) is denied for free — and killing
//! on violation, rather than returning `EPERM`, denies an exploit the chance to
//! probe the sandbox and adapt.
//!
//! The default action is `SECCOMP_RET_TRAP`, not `KillProcess`, so a small
//! handler (`sigsys_handler`) can name the blocked syscall on stderr before
//! re-raising SIGSYS — the process still dies with the same signal, we just
//! learn *which* call it was. The only cost is `tgkill`, argument-filtered to
//! SIGSYS-to-self so it cannot be used for anything else.
//!
//! A handful of allowed syscalls are additionally **argument-filtered**:
//! `mmap`/`mprotect` are permitted only when `PROT_EXEC` is clear, so a
//! renderer can never turn writable memory executable (the W^X property that
//! blocks the final step of most memory-corruption exploit chains), and
//! `fcntl` is permitted only for the memfd seal commands the shared-memory
//! tile path needs (`F_ADD_SEALS`/`F_GET_SEALS`). An empty rule for a syscall
//! matches any arguments; these carry real conditions.
//!
//! Installing it is safe here because the child has already connected and
//! split its endpoint (the `socket`/`connect`/`dup` for that happened *before*
//! the filter); during `serve()` it only reads/writes existing fds and works
//! in memory. seccomp filters only ever remove privileges, and a process may
//! always restrict itself — no root needed.
//!
//! Startup is **fail-closed**: if the filter cannot be installed the component
//! aborts rather than run unconfined (a sandbox that silently fails to apply is
//! worse than an honest none). So multi-process mode requires seccomp support;
//! environments without it use `--single-process` / `--no-default-features`.
//!
//! This applies only in multi-process mode: in single-process mode the
//! components are threads inside the engine, which needs network and exec, so
//! there is nothing to drop.
//!
//! Production would go further still: a per-arch baseline tested across
//! libc/kernel versions, filesystem restriction (Landlock), and namespaces.
//! A real JS JIT needs executable memory, so it would relax the `PROT_EXEC`
//! rule for a dedicated JIT region (or use a dual-mapping/`memfd` scheme)
//! rather than the blanket denial that suits this JIT-less renderer.

/// Syscalls any confined child needs after startup: I/O on already-open fds
/// (its IPC socket + stderr), memory management, synchronization, signals,
/// time, teardown. Deliberately ABSENT: `socket`/`connect` (no new network),
/// `openat` (no file opens), `execve`/`clone` (no new programs/processes),
/// `io_uring_*` (no async-submission network bypass), `ptrace`.
#[cfg(feature = "multi-process")]
const BASELINE: &[libc::c_long] = &[
    // I/O on existing fds only — a new socket/file fd cannot be obtained
    // because socket()/openat() are not on this list.
    libc::SYS_read,
    libc::SYS_write,
    libc::SYS_readv,
    libc::SYS_writev,
    libc::SYS_recvfrom,
    libc::SYS_sendto,
    libc::SYS_recvmsg,
    libc::SYS_sendmsg,
    libc::SYS_close,
    // Both spellings of fstat: which one `fstat()` becomes is a glibc
    // decision, not ours. Debian bookworm's 2.36 issues `newfstatat` with
    // AT_EMPTY_PATH; Ubuntu 24.04's 2.39 issues `fstat`. Allowing only the
    // one the build host happens to use kills the ring and tile consumers on
    // the other — found by running these probes under a different libc, not
    // by reading the code.
    libc::SYS_fstat,
    libc::SYS_newfstatat,
    libc::SYS_statx,
    libc::SYS_lseek,
    // memory — mmap/mprotect are argument-filtered in `install` to forbid
    // PROT_EXEC (mremap preserves an existing mapping's protection, so it can't
    // introduce exec).
    libc::SYS_mmap,
    libc::SYS_munmap,
    libc::SYS_mremap,
    libc::SYS_mprotect,
    libc::SYS_madvise,
    libc::SYS_brk,
    // shared-memory tile transport: create an anonymous sealable buffer, size
    // it, seal it. fcntl is argument-filtered in `install` to the two seal
    // commands only — its other commands (F_DUPFD, F_SETFD/F_SETFL, locks)
    // stay fatal. memfd_create yields a plain memory fd: it opens no path on
    // the filesystem, so this adds no reach `openat`'s absence was denying.
    libc::SYS_memfd_create,
    libc::SYS_ftruncate,
    libc::SYS_fcntl,
    // runtime / synchronization
    libc::SYS_futex,
    libc::SYS_getrandom,
    libc::SYS_sched_yield,
    libc::SYS_sched_getaffinity,
    libc::SYS_membarrier,
    // signals (Rust installs runtime handlers)
    libc::SYS_rt_sigreturn,
    libc::SYS_rt_sigprocmask,
    libc::SYS_rt_sigaction,
    libc::SYS_sigaltstack,
    // time
    libc::SYS_clock_gettime,
    libc::SYS_clock_nanosleep,
    libc::SYS_nanosleep,
    libc::SYS_gettimeofday,
    // identity (cheap, non-escalating)
    libc::SYS_getpid,
    libc::SYS_gettid,
    // teardown
    libc::SYS_exit,
    libc::SYS_exit_group,
];

/// The network syscalls the net component additionally needs. A real net
/// daemon would also need `openat` (resolv.conf/hosts) and DNS plumbing; the
/// PoC synthesizes responses so the socket family alone models the intent.
///
/// Deliberately **outbound only**: `bind`/`listen`/`accept`/`accept4` are NOT
/// granted, so a compromised net component cannot open a listening socket and
/// become a local backdoor/C2 — it can only originate connections, which is
/// all a fetcher does. (Egress destinations still can't be constrained by
/// seccomp — `connect` takes a pointer argument seccomp can't dereference — so
/// a real deployment additionally confines egress with a network namespace +
/// firewall rules rather than trusting the in-process SSRF check alone.)
#[cfg(feature = "multi-process")]
const NET_EXTRA: &[libc::c_long] = &[
    libc::SYS_socket,
    libc::SYS_socketpair,
    libc::SYS_connect,
    libc::SYS_getsockopt,
    libc::SYS_setsockopt,
    libc::SYS_getsockname,
    libc::SYS_getpeername,
];

/// Extra syscalls the fork server needs on top of the baseline: making
/// renderers, and reaping them.
///
/// `clone3` matters as much as `clone` — glibc's `fork()` issues `clone3` on
/// current versions, so an allowlist carrying only `clone` kills the zygote at
/// its first fork. It cannot be argument-filtered directly: `clone3` passes its
/// flags in a struct in memory rather than in registers, and seccomp can only
/// see registers. So we use the production trick ([`install_clone3_enosys`]):
/// return `ENOSYS` for `clone3`, which makes glibc's `fork()` fall back to the
/// register-based `clone` — and *that* we argument-filter (see the `clone` rule
/// in [`install_with`]) to a plain fork, forbidding the namespace-creation and
/// thread/VM-sharing flags. `clone3` stays on this list as *allowed* on purpose:
/// the `ENOSYS` is delivered by a stacked pre-filter whose `Errno` outranks this
/// `Allow`, so removing it here would instead make `clone3` a fatal `SIGSYS` and
/// defeat the fallback. musl (`SYS_fork` on x86, `clone` on aarch64) and pre-2.34
/// glibc never issue `clone3`, so for them the pre-filter is simply inert.
///
/// `prctl`/`seccomp` are here for the *children*, not for the fork server
/// itself. A forked renderer's first act is to install its own filter, which
/// means `prctl(PR_SET_NO_NEW_PRIVS)` followed by `seccomp(SECCOMP_SET_MODE_FILTER)`
/// — under the filter it inherited from this process. Omit them and every
/// renderer dies on `SIGSYS` at the moment it tries to sandbox itself, which
/// surfaces as `TabCrashed` and looks nothing like a sandbox problem.
///
/// Granting them costs nothing: both syscalls only ever *remove* privilege.
/// There is no version of `seccomp(2)` that widens an existing filter, and the
/// `prctl` commands involved are one-way switches.
#[cfg(feature = "multi-process")]
const FORK_SERVER_EXTRA: &[libc::c_long] = &[
    // All three spellings of "make a process", because which one `fork()`
    // becomes is the C library's choice: glibc issues `clone3` (new) or
    // `clone` (older), musl issues the legacy `SYS_fork`. Allowing only the
    // pair glibc uses kills the fork server outright on musl — at its own
    // canary, which is the one failure the canary cannot report politely.
    //
    // `SYS_fork` is x86-only: aarch64 has no fork syscall at all, and naming
    // it there does not compile.
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    libc::SYS_fork,
    libc::SYS_clone,
    libc::SYS_clone3,
    libc::SYS_wait4,
    libc::SYS_prctl,
    libc::SYS_seccomp,
    // The C library's own post-fork housekeeping in the child, before a single
    // line of our code runs — and each libc does it differently: glibc resets
    // the robust-futex list, musl registers a TID address. Invisible in the
    // source, fatal without them. Both merely register a pointer for the
    // kernel to clear on exit; neither can escalate.
    libc::SYS_set_robust_list,
    libc::SYS_set_tid_address,
];

/// Prove, on *this* machine, that the fork-server filter actually permits what
/// a forked renderer needs — before any renderer depends on it.
///
/// The allowlist is sensitive to the C library, not just the architecture, and
/// the sensitivity is invisible in our source. `fork()` reaches the kernel as
/// `clone3` on current glibc but `clone` on older ones and on musl; the child
/// calls `set_robust_list` before a line of our code runs; the endpoint split
/// is an `fcntl(F_DUPFD_CLOEXEC)` rather than a `dup`. Every one of those is a
/// property of the libc *loaded at run time*, so a compile-time check cannot
/// see it: glibc is dynamically linked, and the version on the build host is
/// not the version on the deployment host.
///
/// So this verifies instead of predicting. It forks one child that performs
/// exactly what a renderer does between `fork` and its own lockdown — clone
/// the descriptor, then install a filter (`prctl` + `seccomp`) — and exits.
/// If that child dies on `SIGSYS`, the filter is wrong for this libc and we
/// abort here, at startup, naming the cause.
///
/// Without it the same breakage appears as every renderer dying moments after
/// spawn, surfacing to the engine as `TabCrashed` — a symptom that points at
/// the transport, not the sandbox. That is precisely how this filter's three
/// missing syscalls presented while it was being written.
///
/// One case it cannot catch politely: if `fork` itself is denied, `KillProcess`
/// kills *us* at the call below rather than the child. That still fails at
/// startup rather than mid-session, which is the point, but it arrives as a
/// bare `SIGSYS` on the fork server instead of the message here.
#[cfg(feature = "multi-process")]
pub fn verify_fork_server_filter() {
    // SAFETY: the fork server is single-threaded, so the child may run normal
    // code (the async-signal-safe-only rule applies to multithreaded fork).
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        fail_canary(&format!("could not fork: {}", std::io::Error::last_os_error()));
    }

    if pid == 0 {
        // The child: do what a renderer does before it is confined.
        // SAFETY: fd 2 is open; F_DUPFD_CLOEXEC returns a new descriptor.
        let duped = unsafe { libc::fcntl(2, libc::F_DUPFD_CLOEXEC, 0) };
        if duped < 0 {
            unsafe { libc::_exit(EXIT_CANARY_DUP) };
        }
        unsafe { libc::close(duped) };
        // Installing a filter is `prctl` + `seccomp`, both issued *under* the
        // filter we inherited. Silent: `enforce` would print a second lockdown
        // banner and this is a probe, not a component starting up.
        if install(BASELINE.to_vec()).is_err() {
            unsafe { libc::_exit(EXIT_CANARY_SECCOMP) };
        }
        unsafe { libc::_exit(0) };
    }

    let mut status: libc::c_int = 0;
    // SAFETY: `status` is a valid out-param for our own child.
    if unsafe { libc::waitpid(pid, &mut status, 0) } != pid {
        fail_canary("could not reap the canary child (is wait4 allowed?)");
    }

    if libc::WIFSIGNALED(status) {
        let sig = libc::WTERMSIG(status);
        fail_canary(&format!(
            "canary child killed by signal {sig}{} — the allowlist is missing a \
             syscall this C library needs (glibc issues clone3 on newer versions, \
             clone on older; musl differs again)",
            if sig == libc::SIGSYS { " (SIGSYS)" } else { "" }
        ));
    }
    match libc::WEXITSTATUS(status) {
        0 => {}
        EXIT_CANARY_DUP => fail_canary("fcntl(F_DUPFD_CLOEXEC) refused — a forked \
             renderer could not split its endpoint"),
        EXIT_CANARY_SECCOMP => fail_canary("the child could not install its own \
             seccomp filter — are prctl and seccomp on the allowlist?"),
        other => fail_canary(&format!("canary child exited {other}")),
    }
}

/// Install a deliberately incomplete fork-server filter and run the canary
/// against it, so the *detection* is tested and not merely the happy path.
///
/// Spawned only by the integration suite (`selftest forkserver-canary-gap`).
/// The canary must catch the gap and exit non-zero; a canary that only ever
/// passes is indistinguishable from no canary at all.
#[cfg(feature = "multi-process")]
pub fn canary_must_detect_a_missing_syscall() -> ! {
    // The gap is the missing `F_DUPFD_CLOEXEC` permission, deliberately, and
    // not a missing syscall from the list: the syscall a forked child needs is
    // itself libc-dependent, so removing any *one* of them tests nothing on the
    // libc that does not use it. An earlier version dropped `set_robust_list`,
    // which glibc issues and musl does not — so on musl the crippled filter was
    // not crippled, the canary correctly reported no problem, and this test
    // failed for being wrong rather than the code being wrong. Every libc needs
    // to clone a descriptor here, so denying that is a gap everywhere.
    let full: Vec<libc::c_long> = BASELINE.iter().chain(FORK_SERVER_EXTRA).copied().collect();
    // `fork_server: false` here: the gap under test is the missing
    // `F_DUPFD_CLOEXEC`, and the `clone` argument-filter is orthogonal to it.
    if install_with(full, false, false).is_err() {
        eprintln!("could not install the crippled filter");
        std::process::exit(2);
    }
    // Must not return: the canary is expected to abort the process.
    verify_fork_server_filter();
    eprintln!("canary did NOT detect the missing syscall");
    std::process::exit(3);
}

/// Distinct child exit codes, so a canary failure names the operation rather
/// than just reporting "the child died".
#[cfg(feature = "multi-process")]
const EXIT_CANARY_DUP: libc::c_int = 91;
#[cfg(feature = "multi-process")]
const EXIT_CANARY_SECCOMP: libc::c_int = 92;

/// Fail closed, matching the rest of this module: a sandbox that cannot be
/// shown to work is treated exactly like one that failed to install.
#[cfg(feature = "multi-process")]
fn fail_canary(detail: &str) -> ! {
    eprintln!("[fork-server] FATAL: sandbox self-check failed: {detail}");
    eprintln!("[fork-server] renderers would crash on spawn; refusing to continue. \
               Use --single-process on this host.");
    std::process::exit(1);
}

/// Cap the fork server: the baseline, plus forking, reaping, and the one
/// `fcntl` command a freshly-forked renderer needs before its own lockdown.
///
/// **This filter also constrains every renderer**, because seccomp filters are
/// inherited across `fork` — so it must be a *superset* of the renderer
/// baseline or renderers break in ways that look like transport bugs. It is
/// the reason `F_DUPFD_CLOEXEC` is permitted here: the forked child splits its
/// endpoint (`Endpoint::from_channel` → `try_clone`) *before* calling
/// `lock_down_renderer`, and on Linux that split is an `fcntl(F_DUPFD_CLOEXEC)`
/// — there is no `dup` call involved. Filters stack most-restrictive-wins, so
/// the renderer's own filter still denies it a moment later; the
/// `fcntl-dupfd` probe pins exactly that.
#[cfg(feature = "multi-process")]
pub fn lock_down_fork_server() {
    deny_debugger_attach();
    // Stack the `clone3` → `ENOSYS` pre-filter *first*, so glibc's `fork()` uses
    // the register-based `clone` the main filter can constrain. Best-effort: if
    // it cannot install, `clone3` stays allowed (coarse but safe, the prior
    // behaviour) rather than the fork server refusing to start. If it installs
    // but a libc does not honour the fallback, `verify_fork_server_filter`
    // catches it at startup.
    if let Err(e) = install_clone3_enosys() {
        eprintln!("[fork-server] warning: could not install clone3->ENOSYS filter ({e}); clone3 stays coarse");
    }
    let allowed: Vec<libc::c_long> =
        BASELINE.iter().chain(FORK_SERVER_EXTRA).copied().collect();
    enforce("fork-server", install_fork_server(allowed));
}

/// Cap a renderer: pixels only — the baseline, no network, files, or exec.
#[cfg(feature = "multi-process")]
pub fn lock_down_renderer() {
    deny_debugger_attach();
    enforce("renderer", install(BASELINE.to_vec()));
}

/// Cap the net component: the baseline plus the socket family.
#[cfg(feature = "multi-process")]
pub fn lock_down_net() {
    deny_debugger_attach();
    let allowed: Vec<libc::c_long> = BASELINE.iter().chain(NET_EXTRA).copied().collect();
    enforce("net", install(allowed));
}

/// The syscalls a filesystem-capable service needs beyond the baseline to open
/// a file. Renderers deny these outright (their filesystem is capped without
/// Landlock); a font or storage service is *defined* by needing them, which is
/// exactly why it is a separate process rather than something a renderer does.
///
/// **`openat` is not enough on its own — which libc you run against decides the
/// syscall.** Rust's `std::fs` open reaches the kernel as `openat` under glibc
/// (which routes `open()` through `openat` internally) but as the legacy
/// `SYS_open` under musl on x86. Granting only `openat` therefore kills every
/// file open in a service under musl with `SIGSYS` on syscall #2, and the
/// failure surfaces as an unrelated hang: the service dies, the renderer's
/// storage/font request is never answered, and its tab never completes. Found
/// by the musl CI row, invisible on a glibc dev box — the same class of bug as
/// the fork server's `clone3`-vs-`clone`. `SYS_open` is x86-only: aarch64 has no
/// such syscall (it only ever had `openat`), so naming it there does not compile.
///
/// Seccomp permits these on *any* path — the argument is a pointer the filter
/// cannot dereference — so *which* files a service may touch is confined by
/// Landlock instead ([`landlock`]), not by this list.
#[cfg(feature = "multi-process")]
const FS_EXTRA: &[libc::c_long] = &[
    libc::SYS_openat,
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    libc::SYS_open,
];

/// Landlock: filesystem access control by *path*, the thing seccomp cannot do.
///
/// A filesystem service gets `openat` in its seccomp filter — but seccomp sees
/// only the syscall number and registers, never the path string a pointer
/// points at, so it cannot say "under `/tmp/gosub-storage` but not
/// `/etc/shadow`". Landlock can: you declare a ruleset of `(directory, rights)`
/// and the kernel enforces it on every path resolution. Here it turns the
/// storage service's key-hashing from the *only* guard against path traversal
/// into defense in depth behind a kernel boundary.
///
/// It is applied *before* seccomp: its own syscalls and the `open(O_PATH)` used
/// to anchor a rule then run unfiltered, and once installed only path access is
/// restricted, not the syscall set. It is **best-effort** — Landlock needs a
/// kernel built with it and listed in `lsm=`, which not every host has — so an
/// absence degrades to seccomp + application-level scoping rather than refusing
/// to start. `libc` exposes the three syscall numbers but not the ABI structs
/// or rights bits, so those are declared here; the ABI version is queried and
/// rights beyond it are masked off (a newer right on an older kernel makes
/// `create_ruleset` reject the whole thing).
#[cfg(feature = "multi-process")]
mod landlock {
    use std::os::fd::RawFd;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    // Access-right bits (ABI v1 unless noted). From the Landlock uapi.
    const EXECUTE: u64 = 1 << 0;
    const WRITE_FILE: u64 = 1 << 1;
    const READ_FILE: u64 = 1 << 2;
    const READ_DIR: u64 = 1 << 3;
    const REMOVE_DIR: u64 = 1 << 4;
    const REMOVE_FILE: u64 = 1 << 5;
    const MAKE_CHAR: u64 = 1 << 6;
    const MAKE_DIR: u64 = 1 << 7;
    const MAKE_REG: u64 = 1 << 8;
    const MAKE_SOCK: u64 = 1 << 9;
    const MAKE_FIFO: u64 = 1 << 10;
    const MAKE_BLOCK: u64 = 1 << 11;
    const MAKE_SYM: u64 = 1 << 12;
    const REFER: u64 = 1 << 13; // ABI v2
    const TRUNCATE: u64 = 1 << 14; // ABI v3

    const CREATE_RULESET_VERSION: u32 = 1 << 0;
    const RULE_PATH_BENEATH: libc::c_int = 1;

    #[repr(C)]
    struct RulesetAttr {
        handled_access_fs: u64,
    }

    #[repr(C)]
    struct PathBeneathAttr {
        allowed_access: u64,
        parent_fd: RawFd,
    }

    /// The supported ABI version, or `-1`/`0` when Landlock is unavailable.
    fn abi() -> i32 {
        // SAFETY: create_ruleset(NULL, 0, VERSION) is the documented probe; it
        // returns the ABI version and creates nothing.
        unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                std::ptr::null::<RulesetAttr>(),
                0usize,
                CREATE_RULESET_VERSION,
            ) as i32
        }
    }

    /// Whether Landlock is usable on this kernel.
    pub fn available() -> bool {
        abi() >= 1
    }

    /// Every fs right this ABI knows — the set the ruleset *handles* (anything
    /// handled but not granted by a rule is denied). Masked to the ABI so an
    /// unsupported bit does not make `create_ruleset` fail.
    fn handled(abi: i32) -> u64 {
        let mut h = EXECUTE
            | WRITE_FILE
            | READ_FILE
            | READ_DIR
            | REMOVE_DIR
            | REMOVE_FILE
            | MAKE_CHAR
            | MAKE_DIR
            | MAKE_REG
            | MAKE_SOCK
            | MAKE_FIFO
            | MAKE_BLOCK
            | MAKE_SYM;
        if abi >= 2 {
            h |= REFER;
        }
        if abi >= 3 {
            h |= TRUNCATE;
        }
        h
    }

    /// Rights to grant one *service* path. Directory-only rights (`READ_DIR`,
    /// `MAKE_REG`, `REMOVE_FILE`) must not be set on a *file* path or `add_rule`
    /// rejects the ruleset with `EINVAL` — so the grant depends on `is_dir`.
    /// `TRUNCATE` (ABI v3) is included unconditionally; [`apply`] masks it off on
    /// older kernels.
    fn grant(is_dir: bool, writable: bool) -> u64 {
        let mut a = READ_FILE;
        if is_dir {
            a |= READ_DIR;
        }
        if writable {
            a |= WRITE_FILE | TRUNCATE;
            if is_dir {
                // Create and remove entries under the directory.
                a |= MAKE_REG | REMOVE_FILE;
            }
        }
        a
    }

    /// Directory-only rights — invalid on a *file* path, so [`apply`] strips them
    /// there rather than let one file rule `EINVAL` the whole ruleset.
    const DIR_ONLY: u64 = READ_DIR
        | MAKE_REG
        | MAKE_DIR
        | REMOVE_FILE
        | REMOVE_DIR
        | MAKE_CHAR
        | MAKE_SOCK
        | MAKE_FIFO
        | MAKE_BLOCK
        | MAKE_SYM;

    /// Create a ruleset handling all fs access, add each `(path, rights)` rule
    /// (rights masked to this ABI, and to what the path — file vs directory —
    /// can carry), then enforce it on the calling thread and everything it later
    /// spawns. `Ok(true)` = applied, `Ok(false)` = Landlock unavailable (caller
    /// degrades), `Err` = a real failure.
    fn apply(rules: &[(&Path, u64)]) -> std::io::Result<bool> {
        let abi = abi();
        if abi < 1 {
            return Ok(false);
        }
        let attr = RulesetAttr { handled_access_fs: handled(abi) };
        // SAFETY: valid attr pointer with its size; flags 0.
        let rs = unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                &attr as *const RulesetAttr,
                std::mem::size_of::<RulesetAttr>(),
                0u32,
            )
        };
        if rs < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let rs = rs as RawFd;

        for (path, rights) in rules {
            let cpath = std::ffi::CString::new(path.as_os_str().as_bytes())
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL in path"))?;
            // SAFETY: NUL-terminated path; O_PATH just anchors the rule.
            let pfd = unsafe { libc::open(cpath.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
            if pfd < 0 {
                let e = std::io::Error::last_os_error();
                unsafe { libc::close(rs) };
                return Err(e);
            }
            let mut allowed = *rights & handled(abi);
            if !path.is_dir() {
                allowed &= !DIR_ONLY;
            }
            let rule = PathBeneathAttr { allowed_access: allowed, parent_fd: pfd };
            // SAFETY: valid ruleset fd, rule pointer, and rule type.
            let rc = unsafe {
                libc::syscall(
                    libc::SYS_landlock_add_rule,
                    rs,
                    RULE_PATH_BENEATH,
                    &rule as *const PathBeneathAttr,
                    0u32,
                )
            };
            unsafe { libc::close(pfd) };
            if rc < 0 {
                let e = std::io::Error::last_os_error();
                unsafe { libc::close(rs) };
                return Err(e);
            }
        }

        // restrict_self requires NO_NEW_PRIVS (the seccomp install would set it
        // too, but that runs later — and the broker never installs seccomp).
        // SAFETY: a one-way prctl switch.
        if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } < 0 {
            let e = std::io::Error::last_os_error();
            unsafe { libc::close(rs) };
            return Err(e);
        }
        // SAFETY: valid ruleset fd; flags 0.
        let rc = unsafe { libc::syscall(libc::SYS_landlock_restrict_self, rs, 0u32) };
        let e = std::io::Error::last_os_error();
        unsafe { libc::close(rs) };
        if rc < 0 {
            return Err(e);
        }
        Ok(true)
    }

    /// Restrict this thread's filesystem access to exactly `rules`
    /// `(path, writable)` — the *service* confinement (read, plus write on a
    /// `writable` path).
    pub fn restrict(rules: &[(&Path, bool)]) -> std::io::Result<bool> {
        let mapped: Vec<(&Path, u64)> =
            rules.iter().map(|(p, w)| (*p, grant(p.is_dir(), *w))).collect();
        apply(&mapped)
    }

    /// The *broker* confinement — a loose sandbox for the engine process.
    ///
    /// It may **read and execute anywhere**: it forks+execs its children, whose
    /// shared libraries can live in distro-specific places all over the host, so
    /// an allowlist of library directories would be fragile (this is the same
    /// reason a browser's main process is only loosely sandboxed). But it may
    /// only **write beneath `temp`**, where the storage dir and font file live.
    /// So a broker subverted through its one untrusted surface — the frames it
    /// `bincode::deserialize`s — cannot plant persistence, overwrite its own
    /// binary, or corrupt the user's files and configs. The ruleset is inherited
    /// by every engine thread and every fork+exec'd child, so nothing in the
    /// process tree can write outside `temp` either; each child then further
    /// restricts itself.
    pub fn restrict_broker(temp: &Path) -> std::io::Result<bool> {
        // Read + traverse + execute everything, so the loader can `execve` the
        // child binary and mmap its shared libraries PROT_EXEC wherever they are.
        let root = READ_FILE | READ_DIR | EXECUTE;
        // Full write beneath the temp dir: create/remove the storage dir and the
        // font file, and write/truncate them.
        let temp_rw = READ_FILE
            | READ_DIR
            | WRITE_FILE
            | TRUNCATE
            | MAKE_REG
            | MAKE_DIR
            | REMOVE_FILE
            | REMOVE_DIR;
        apply(&[(Path::new("/"), root), (temp, temp_rw)])
    }
}

/// Whether Landlock is usable on this host (for probes and diagnostics).
#[cfg(feature = "multi-process")]
pub fn landlock_available() -> bool {
    landlock::available()
}

/// The dangerous syscalls the broker (engine) is denied, even though it keeps
/// the broad set it legitimately needs. Unlike a renderer — capped to an
/// allowlist — the broker execs helpers, spawns threads, and opens files and
/// sockets, so a tight allowlist does not fit (Chromium's *browser* process is
/// likewise not seccomp-allowlisted). What it never needs are the
/// post-compromise **escalation primitives**: attaching to or reading another
/// process's memory (`ptrace`, `process_vm_*`), loading kernel code
/// (`init_module`/`finit_module`, `kexec_*`, `bpf`), the classic local-privilege
/// escalation surfaces (`perf_event_open`, `userfaultfd`, the kernel keyring,
/// `kcmp`), and namespace/mount escapes (`setns`, `mount`, `umount2`,
/// `pivot_root`, `swapon`/`swapoff`, `reboot`). Denying exactly those turns the
/// trusted process from seccomp-unconfined into "can still do its job, cannot
/// reach for a kernel exploit" — a deny-list, the inverse of the allowlist the
/// children carry.
///
/// **Every entry must be a syscall no child needs either.** This filter is
/// inherited by the fork server and by every renderer (before each installs its
/// own, stricter allowlist), and when filters stack a `Trap` outranks a child's
/// `Allow` — so a syscall denied here is denied for the children too. `unshare`
/// (the renderer's network isolation), `clone`/`execve` (spawning), and
/// `seccomp`/`prctl` (a child sandboxing itself) are therefore deliberately
/// absent: denying any of them would kill the children this process exists to
/// launch.
#[cfg(feature = "multi-process")]
const BROKER_DENY: &[libc::c_long] = &[
    // Attach to / read / write another process — injection and secret theft.
    libc::SYS_ptrace,
    libc::SYS_process_vm_readv,
    libc::SYS_process_vm_writev,
    // Load kernel code — the shortest path from a broker compromise to ring 0.
    libc::SYS_kexec_load,
    libc::SYS_kexec_file_load,
    libc::SYS_init_module,
    libc::SYS_finit_module,
    libc::SYS_delete_module,
    libc::SYS_bpf,
    // Classic LPE / exploit-primitive surfaces.
    libc::SYS_perf_event_open,
    libc::SYS_userfaultfd,
    libc::SYS_add_key,
    libc::SYS_request_key,
    libc::SYS_keyctl,
    libc::SYS_kcmp,
    // Namespace / mount escapes (the broker uses `unshare`, never these).
    libc::SYS_setns,
    libc::SYS_mount,
    libc::SYS_umount2,
    libc::SYS_pivot_root,
    libc::SYS_swapon,
    libc::SYS_swapoff,
    libc::SYS_reboot,
];

/// Confine the **broker** (engine) process. Two best-effort layers, applied on
/// the process's main thread before it spawns anything, so every engine thread
/// and every fork+exec'd child inherits both:
///
/// 1. **Landlock** on the filesystem — read and execute anywhere, but write only
///    beneath the temp dir (see [`landlock::restrict_broker`]).
/// 2. A **deny-list seccomp filter** — allow by default (the broker's job needs a
///    broad surface), `Trap` the [`BROKER_DENY`] escalation syscalls it never uses.
///
/// Best-effort, deliberately unlike the child lockdowns: the broker is not the
/// boundary that *contains* a compromised renderer — it is defense in depth on
/// the one process that holds every secret and parses untrusted frames. A kernel
/// missing either mechanism leaves that layer off rather than refusing to start;
/// the children's fail-closed allowlists are what actually contain a compromise.
#[cfg(feature = "multi-process")]
pub fn lock_down_broker() {
    let temp = std::env::temp_dir();
    match landlock::restrict_broker(&temp) {
        Ok(true) => {
            eprintln!("[broker] landlock active (writes confined to {})", temp.display())
        }
        Ok(false) => {
            eprintln!("[broker] landlock unavailable on this kernel; broker filesystem unconfined")
        }
        Err(e) => {
            eprintln!("[broker] landlock could not be applied ({e}); broker filesystem unconfined")
        }
    }

    // Seccomp after Landlock: the deny-list is default-allow, so it never blocks
    // Landlock's own setup syscalls, and keeping the same order as the services
    // (Landlock first, then seccomp) is one less thing to reason about.
    match install_broker_seccomp() {
        Ok(()) => eprintln!(
            "[broker] seccomp deny-list active (escalation syscalls denied, SIGSYS + report)"
        ),
        Err(e) => eprintln!(
            "[broker] seccomp deny-list could not be applied ({e}); broker syscall surface unconfined"
        ),
    }
}

/// Install the broker's deny-list seccomp filter: allow by default, `Trap`
/// (→ SIGSYS, named by [`install_sigsys_reporter`], then re-raised) on any
/// [`BROKER_DENY`] syscall. The inverse polarity of [`install_with`]'s
/// allowlist — default action `Allow`, matched action `Trap` — so listing a
/// syscall *denies* it and everything unlisted passes.
#[cfg(feature = "multi-process")]
fn install_broker_seccomp() -> Result<(), Box<dyn std::error::Error>> {
    use seccompiler::{apply_filter, BpfProgram, SeccompAction, SeccompFilter, SeccompRule};
    use std::collections::BTreeMap;

    #[cfg(target_arch = "x86_64")]
    let arch = seccompiler::TargetArch::x86_64;
    #[cfg(target_arch = "aarch64")]
    let arch = seccompiler::TargetArch::aarch64;

    // Each denied syscall matches unconditionally (an empty rule vec); every
    // other syscall falls through to the default `Allow`.
    let rules: BTreeMap<i64, Vec<SeccompRule>> =
        BROKER_DENY.iter().map(|&nr| (nr as i64, Vec::new())).collect();

    // Name a denied syscall on stderr before it kills us, exactly as the
    // allowlist path does — "broker tried ptrace (#101), killed" rather than a
    // bare SIGSYS. Its own syscalls are all on the default-allow side here.
    install_sigsys_reporter();

    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow, // default & argument-mismatch: allow (the broker needs breadth)
        SeccompAction::Trap,  // matched (a BROKER_DENY syscall): SIGSYS → report → re-raise
        arch,
    )?;
    let program: BpfProgram = filter.try_into()?;
    apply_filter(&program)?;
    Ok(())
}

/// What a *device*-backed service (audio, GPU) needs: open a device node and
/// talk to it via `ioctl`. `ioctl` is a large, driver-defined surface that
/// seccomp constrains poorly (its request codes and pointer arguments are
/// opaque to the filter), which is precisely why these processes are isolated —
/// the confinement they get is the process boundary and everything *else* in
/// the baseline, not a tight filter on the device path itself.
///
/// `SYS_open` alongside `openat` for the same libc reason as [`FS_EXTRA`]: musl
/// opens a device node via the legacy `open` on x86, glibc via `openat`.
#[cfg(feature = "multi-process")]
const DEVICE_EXTRA: &[libc::c_long] = &[
    libc::SYS_openat,
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    libc::SYS_open,
    libc::SYS_ioctl,
];

/// Cap an engine-spawned service — a role that needs a privilege renderers do
/// not, so it lives outside the zygote and carries its own, wider filter. The
/// caps select the superset: `filesystem` adds `openat`, `device` adds
/// `openat` + `ioctl`. Everything else is the same default-deny baseline, so a
/// storage service still cannot open a socket and an audio service still cannot
/// spawn a program.
#[cfg(feature = "multi-process")]
pub fn lock_down_service(name: &str, filesystem: bool, device: bool, fs_allow: &[(&std::path::Path, bool)]) {
    deny_debugger_attach();

    // Landlock first (see the module doc): it runs before the seccomp filter so
    // its own syscalls and the O_PATH opens are unfiltered, and it confines
    // *which* paths the coming `openat` may reach. Best-effort — a kernel
    // without Landlock leaves seccomp + application-level path scoping as the
    // guard rather than refusing to start.
    if !fs_allow.is_empty() {
        match landlock::restrict(fs_allow) {
            Ok(true) => eprintln!("[{name}] landlock active (filesystem scoped to its own paths)"),
            Ok(false) => {
                eprintln!("[{name}] landlock unavailable on this kernel; seccomp + path scoping only")
            }
            Err(e) => eprintln!("[{name}] landlock could not be applied ({e}); seccomp + path scoping only"),
        }
    }

    let mut allowed = BASELINE.to_vec();
    if filesystem {
        allowed.extend_from_slice(FS_EXTRA);
    }
    if device {
        allowed.extend_from_slice(DEVICE_EXTRA);
    }
    enforce(name, install(allowed));
}

#[cfg(feature = "multi-process")]
fn enforce(role: &str, result: Result<(), Box<dyn std::error::Error>>) {
    match result {
        Ok(()) => eprintln!("[{role}] seccomp allowlist active (default-deny, SIGSYS + report)"),
        Err(e) => {
            // Fail closed: never run a component that was meant to be confined
            // as if it were unconfined.
            eprintln!("[{role}] FATAL: could not install seccomp sandbox: {e}");
            std::process::exit(1);
        }
    }
}

/// Build and apply a default-deny allowlist: syscalls in `allowed` pass (subject
/// to any argument filter), every other syscall — and any allowed syscall whose
/// arguments fail its filter — is a fatal `SIGSYS`.
#[cfg(feature = "multi-process")]
fn install(allowed: Vec<libc::c_long>) -> Result<(), Box<dyn std::error::Error>> {
    install_with(allowed, false, false)
}

/// The fork server's main filter: as [`install`], but `F_DUPFD_CLOEXEC` is
/// permitted (its forked children clone a descriptor before their own lockdown)
/// and `clone` is argument-filtered to a plain fork (see [`install_with`]).
/// Pair with [`install_clone3_enosys`], installed first.
#[cfg(feature = "multi-process")]
fn install_fork_server(allowed: Vec<libc::c_long>) -> Result<(), Box<dyn std::error::Error>> {
    install_with(allowed, true, true)
}

/// As [`install`], but `allow_dup_fd` additionally permits
/// `fcntl(F_DUPFD_CLOEXEC)` and `fork_server` argument-filters `clone` — both
/// needed only by the fork server.
#[cfg(feature = "multi-process")]
fn install_with(
    allowed: Vec<libc::c_long>,
    allow_dup_fd: bool,
    fork_server: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use seccompiler::{
        apply_filter, BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition,
        SeccompFilter, SeccompRule,
    };
    use std::collections::BTreeMap;

    #[cfg(target_arch = "x86_64")]
    let arch = seccompiler::TargetArch::x86_64;
    #[cfg(target_arch = "aarch64")]
    let arch = seccompiler::TargetArch::aarch64;

    // Most syscalls match unconditionally: an empty rule vec = any arguments.
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> =
        allowed.iter().map(|&nr| (nr as i64, Vec::new())).collect();

    // …except mmap/mprotect, which are allowed only when PROT_EXEC is clear.
    // `prot` is argument index 2 of both. `MaskedEq(PROT_EXEC)` against value 0
    // means "(prot & PROT_EXEC) == 0" — so a mapping can be made writable or
    // readable, but never executable (W^X). A request that sets PROT_EXEC
    // matches no rule and hits the KillProcess default.
    for nr in [libc::SYS_mmap, libc::SYS_mprotect] {
        let no_exec = SeccompCondition::new(
            2,
            SeccompCmpArgLen::Qword,
            SeccompCmpOp::MaskedEq(libc::PROT_EXEC as u64),
            0,
        )?;
        rules.insert(nr as i64, vec![SeccompRule::new(vec![no_exec])?]);
    }

    // …and fcntl, allowed only for memfd sealing plus the read-only F_GETFD
    // (`cmd` is argument index 1; multiple rules OR together). A renderer must
    // be able to seal its tile buffers, and Rust's std *debug* builds probe
    // fds with fcntl(F_GETFD) when an OwnedFd drops (debug_assert_fd_is_open)
    // — a pure query with nothing to escalate. Every *mutating* fcntl command
    // — F_DUPFD (fd fabrication), F_SETFL, locks — hits KillProcess. F_SETFD
    // is a special case handled below: permitted only to *set* close-on-exec,
    // never to clear it.
    let mut fcntl_allowed = Vec::new();
    let mut cmds = vec![libc::F_ADD_SEALS, libc::F_GET_SEALS, libc::F_GETFD];
    if allow_dup_fd {
        cmds.push(libc::F_DUPFD_CLOEXEC);
    }
    for cmd in cmds {
        let is_cmd =
            SeccompCondition::new(1, SeccompCmpArgLen::Qword, SeccompCmpOp::Eq, cmd as u64)?;
        fcntl_allowed.push(SeccompRule::new(vec![is_cmd])?);
    }
    // `fcntl(F_SETFD, FD_CLOEXEC)` — permitted for *every* filter, not just the
    // fork server. musl issues it after *any* file open (its `std::fs` opens
    // with `O_CLOEXEC` and then redundantly re-sets `FD_CLOEXEC` via `fcntl`),
    // as well as after `F_DUPFD_CLOEXEC`; glibc does neither. Gating it behind
    // the fork server's `allow_dup_fd` therefore killed every file open in a
    // filesystem/device service under musl with `SIGSYS` on syscall #72 — the
    // failure surfacing as a service dying and the renderer's storage/font
    // request never being answered. Found on the musl CI row, the same libc
    // class of bug as `open`-vs-`openat` above.
    //
    // Both conditions AND together, so this permits *setting* close-on-exec and
    // nothing else: `F_SETFD` with any other flag word — crucially 0, which
    // would CLEAR close-on-exec and leak a descriptor across an exec — still
    // hits the default action. Setting the flag only ever narrows a descriptor,
    // so it grants no reach (and a confined child cannot `exec` anyway).
    let is_setfd =
        SeccompCondition::new(1, SeccompCmpArgLen::Qword, SeccompCmpOp::Eq, libc::F_SETFD as u64)?;
    let sets_cloexec =
        SeccompCondition::new(2, SeccompCmpArgLen::Qword, SeccompCmpOp::Eq, libc::FD_CLOEXEC as u64)?;
    fcntl_allowed.push(SeccompRule::new(vec![is_setfd, sets_cloexec])?);

    rules.insert(libc::SYS_fcntl as i64, fcntl_allowed);

    // tgkill is permitted ONLY to deliver SIGSYS to a thread of this process —
    // the one thing `sigsys_handler` does to re-raise after logging. `sig` is
    // argument index 2; every other tgkill (any other signal, or poking another
    // process) fails the condition and hits the Trap default. This is the whole
    // cost of the diagnostic: one syscall, argument-pinned to the exact use.
    let sig_is_sigsys =
        SeccompCondition::new(2, SeccompCmpArgLen::Qword, SeccompCmpOp::Eq, libc::SIGSYS as u64)?;
    rules.insert(libc::SYS_tgkill as i64, vec![SeccompRule::new(vec![sig_is_sigsys])?]);

    // …and, for the fork server only, `clone` — argument-filtered to a plain
    // fork. Once `clone3` is `ENOSYS`'d ([`install_clone3_enosys`]), glibc's
    // `fork()` reaches the kernel as `clone` with `flags` in a *register* we can
    // finally inspect (`flags` is argument index 0). `MaskedEq(DANGEROUS, 0)`
    // means "(flags & DANGEROUS) == 0": a plain `fork()` — glibc or musl — sets
    // only `SIGCHLD | CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID`, none of them in
    // the mask, so it passes on every libc; a `clone` that tries to unshare a
    // namespace (`CLONE_NEW*`) or spawn a thread / share the address space
    // (`CLONE_THREAD` / `CLONE_VM`) hits the default action. So even a fork
    // server subverted through its one input (the engine's `ForkRequest`) cannot
    // escalate via `clone` flags. The empty `clone` allow that `allowed` would
    // otherwise produce is replaced here.
    if fork_server {
        // Kernel CLONE_* bits (stable UAPI). Declared locally rather than via
        // `libc` so the mask does not depend on which constants a given `libc`
        // version happens to export.
        const CLONE_VM: u64 = 0x0000_0100;
        const CLONE_THREAD: u64 = 0x0001_0000;
        const CLONE_NEWTIME: u64 = 0x0000_0080;
        const CLONE_NEWNS: u64 = 0x0002_0000;
        const CLONE_NEWCGROUP: u64 = 0x0200_0000;
        const CLONE_NEWUTS: u64 = 0x0400_0000;
        const CLONE_NEWIPC: u64 = 0x0800_0000;
        const CLONE_NEWUSER: u64 = 0x1000_0000;
        const CLONE_NEWPID: u64 = 0x2000_0000;
        const CLONE_NEWNET: u64 = 0x4000_0000;
        const DANGEROUS: u64 = CLONE_VM
            | CLONE_THREAD
            | CLONE_NEWTIME
            | CLONE_NEWNS
            | CLONE_NEWCGROUP
            | CLONE_NEWUTS
            | CLONE_NEWIPC
            | CLONE_NEWUSER
            | CLONE_NEWPID
            | CLONE_NEWNET;
        let plain_fork =
            SeccompCondition::new(0, SeccompCmpArgLen::Qword, SeccompCmpOp::MaskedEq(DANGEROUS), 0)?;
        rules.insert(libc::SYS_clone as i64, vec![SeccompRule::new(vec![plain_fork])?]);
    }

    // A blocked syscall used to be an immediate `KillProcess` — correct, but it
    // told you nothing about *which* syscall. Switch the default to `Trap`
    // (SECCOMP_RET_TRAP → SIGSYS) and install a handler that names the offending
    // syscall on stderr, then re-raises SIGSYS so the process still terminates
    // with the same signal it always did (the selftest probes assert exactly
    // that). The handler is installed *before* the filter applies, so its own
    // `sigaction`/`getpid`/`gettid`/`tgkill`/`write` are unfiltered here and are
    // on the allowlist for when it actually runs. Matters most once V8 lands and
    // the renderer starts issuing syscalls we did not anticipate: "renderer
    // died" becomes "renderer tried openat (#257), killed".
    install_sigsys_reporter();

    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Trap,  // default & argument-mismatch: SIGSYS → sigsys_handler → re-raised
        SeccompAction::Allow, // matched: allow
        arch,
    )?;
    let program: BpfProgram = filter.try_into()?;
    apply_filter(&program)?;
    Ok(())
}

/// Install a stacked pre-filter that turns `clone3` into `ENOSYS`, so glibc's
/// `fork()` retries with the register-based `clone` the main fork-server filter
/// argument-filters. `clone3` cannot be argument-filtered directly — it passes
/// its flags in a memory struct seccomp cannot dereference — so `ENOSYS`-ing it
/// is the only way to route fork onto a constrainable path. This is the standard
/// technique (Chromium, systemd) and relies on a fallback glibc has carried
/// since it started issuing `clone3`.
///
/// **Why a separate filter.** seccomp applies one action per filter, so a single
/// filter cannot both `Allow` most syscalls and `Errno` one. Stacking solves it:
/// the kernel runs every installed filter and takes the highest-precedence
/// return, ordered `KILL > TRAP > ERRNO > ALLOW`. This pre-filter returns
/// `ERRNO(ENOSYS)` for `clone3` and `Allow` for everything else; the main filter
/// (installed *after*, so both are active) `Allow`s `clone3`. For `clone3`,
/// `ERRNO` outranks the main filter's `Allow` → `ENOSYS` is returned. For a
/// genuinely-blocked syscall the main filter returns `TRAP`, which outranks this
/// filter's `Allow` → still killed. So the pre-filter can only ever turn
/// `clone3` into `ENOSYS`; it cannot weaken anything else.
///
/// Inert where `clone3` is never issued: musl (`SYS_fork`/`clone`) and pre-2.34
/// glibc simply never trip the rule.
#[cfg(feature = "multi-process")]
fn install_clone3_enosys() -> Result<(), Box<dyn std::error::Error>> {
    use seccompiler::{apply_filter, BpfProgram, SeccompAction, SeccompFilter, SeccompRule};
    use std::collections::BTreeMap;

    #[cfg(target_arch = "x86_64")]
    let arch = seccompiler::TargetArch::x86_64;
    #[cfg(target_arch = "aarch64")]
    let arch = seccompiler::TargetArch::aarch64;

    // One rule, any arguments: clone3 → the match action below.
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    rules.insert(libc::SYS_clone3 as i64, Vec::new());

    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,                       // mismatch: defer to the main filter
        SeccompAction::Errno(libc::ENOSYS as u32),  // match (clone3): ENOSYS, triggering fork's fallback
        arch,
    )?;
    let program: BpfProgram = filter.try_into()?;
    apply_filter(&program)?;
    Ok(())
}

/// Install the SIGSYS reporter (SA_SIGINFO so the handler sees which syscall
/// trapped; SA_NODEFER so the re-raised SIGSYS is delivered synchronously
/// against the restored default disposition). Best-effort: if it cannot be
/// installed the `Trap` default still terminates the process on a violation —
/// it just does so without the diagnostic line.
#[cfg(feature = "multi-process")]
fn install_sigsys_reporter() {
    // SAFETY: zeroed sigaction is a valid empty handler; we then set the two
    // fields we need and register it for SIGSYS only.
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = sigsys_handler as *const () as usize;
        sa.sa_flags = libc::SA_SIGINFO | libc::SA_NODEFER;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGSYS, &sa, std::ptr::null_mut());
    }
}

/// SIGSYS handler for `SECCOMP_RET_TRAP`: name the blocked syscall, then
/// terminate with SIGSYS exactly as `KillProcess` would have.
///
/// Runs in signal context, so it touches only async-signal-safe operations: a
/// fixed stack buffer, a hand-rolled integer formatter, one `write(2)`, then
/// `sigaction`/`tgkill` (both on the allowlist). No allocation, no formatting
/// machinery, no locks.
#[cfg(feature = "multi-process")]
extern "C" fn sigsys_handler(
    _sig: libc::c_int,
    info: *mut libc::siginfo_t,
    _ctx: *mut libc::c_void,
) {
    // `si_syscall` sits at byte offset 24 of `siginfo_t` on LP64 Linux — after
    // {si_signo, si_errno, si_code, pad} (16 bytes) and the `_call_addr`
    // pointer (8). Same layout on x86_64 and aarch64, the two arches this
    // crate builds seccomp for. A wrong read only mislabels the log line; it
    // cannot affect the termination below.
    let nr: i32 = if info.is_null() {
        -1
    } else {
        // SAFETY: `info` points at a kernel-filled siginfo_t at least 32 bytes
        // long; the read is unaligned-safe and within that.
        unsafe { std::ptr::read_unaligned((info as *const u8).add(24).cast::<i32>()) }
    };

    let mut buf = [0u8; 80];
    let mut len = 0usize;
    for &b in b"[sandbox] SIGSYS: blocked syscall #" {
        buf[len] = b;
        len += 1;
    }
    len += write_i32(&mut buf[len..], nr);
    for &b in b" \xe2\x80\x94 terminating\n" {
        buf[len] = b;
        len += 1;
    }
    // SAFETY: fd 2 (stderr) is open; buf/len describe a valid initialized slice.
    unsafe {
        libc::write(2, buf.as_ptr().cast(), len);

        // Restore the default action and re-raise, so the process dies with
        // SIGSYS (the signal, and the exit semantics the probes check) rather
        // than returning from the trap and resuming the blocked call.
        let mut dfl: libc::sigaction = std::mem::zeroed();
        dfl.sa_sigaction = libc::SIG_DFL;
        libc::sigaction(libc::SIGSYS, &dfl, std::ptr::null_mut());
        let pid = libc::getpid();
        let tid = libc::syscall(libc::SYS_gettid) as libc::pid_t;
        libc::syscall(libc::SYS_tgkill, pid, tid, libc::SIGSYS);
        // Unreachable with SA_NODEFER (SIGSYS delivered synchronously above);
        // a belt-and-braces exit in case a future change masks it.
        libc::_exit(159);
    }
}

/// Async-signal-safe decimal formatter for the SIGSYS reporter: writes `v`
/// (handling a negative) into `out` and returns the byte count. No allocation.
#[cfg(feature = "multi-process")]
fn write_i32(out: &mut [u8], v: i32) -> usize {
    let mut n = v as i64;
    let neg = n < 0;
    if neg {
        n = -n;
    }
    let mut digits = [0u8; 10];
    let mut d = 0usize;
    if n == 0 {
        digits[d] = b'0';
        d += 1;
    }
    while n > 0 {
        digits[d] = b'0' + (n % 10) as u8;
        n /= 10;
        d += 1;
    }
    let mut len = 0usize;
    if neg {
        out[len] = b'-';
        len += 1;
    }
    while d > 0 {
        d -= 1;
        out[len] = digits[d];
        len += 1;
    }
    len
}

/// Resource ceilings the engine imposes on a child at spawn time. seccomp caps
/// *what* syscalls a child may run; this caps *how much* it may consume, so a
/// compromised child cannot exhaust host memory or fd tables. rlimits can only
/// ever be lowered, never raised, so the child cannot undo them.
///
/// Called from the post-fork/pre-exec context, so it must stay
/// async-signal-safe: nothing but `setrlimit` syscalls here.
#[cfg(feature = "multi-process")]
pub fn apply_child_rlimits() -> std::io::Result<()> {
    // Memory: bound the *heap*, not the address space. `RLIMIT_DATA` caps
    // committed writable anonymous memory (brk + writable `mmap`), and since
    // Linux 4.7 it deliberately does *not* count `PROT_NONE` reservations — so a
    // real JIT's multi-GiB virtual cage (V8 reserves ~4 GiB up front) still fits,
    // while a renderer trying to allocate the host to death hits a failed
    // `mmap`/`brk` → Rust's alloc-error path aborts *that process*, not the
    // machine. `RLIMIT_AS` — the *virtual* cap this used to be — is the wrong
    // axis: it would kill V8 at init for reserving address space it never
    // commits. (A production browser bounds true RSS with a cgroup `memory.max`,
    // whose OOM kill is scoped to the offending renderer; this self-applied
    // rlimit is the cheap approximation of that — see the architecture doc.)
    set_rlimit(libc::RLIMIT_DATA, 512 * 1024 * 1024)?;
    // A generous *virtual* ceiling on top: high enough to clear a JIT's cage, low
    // enough to catch a runaway that reserves absurd address space. Belt to the
    // `RLIMIT_DATA` braces — a JIT-less renderer never approaches it.
    set_rlimit(libc::RLIMIT_AS, 16 * 1024 * 1024 * 1024)?;
    // A child needs only a handful of fds (its IPC socket + std streams).
    set_rlimit(libc::RLIMIT_NOFILE, 128)?;
    // No core dumps — a crash must not spill page contents (cookies, tokens).
    set_rlimit(libc::RLIMIT_CORE, 0)?;
    // Deprioritize: content processes should yield to the trusted engine/UI, so
    // a compromised child spinning in a busy loop can't starve them of CPU. A
    // hard RLIMIT_CPU is unusable here — it counts *cumulative* CPU time and
    // would eventually kill a legitimately long-lived renderer — so we lower
    // scheduling priority instead. Raising the nice value is always permitted
    // and needs no privilege, so a child can't undo it either.
    set_priority(10)?;
    Ok(())
}

/// Move the calling process into fresh, empty namespaces when `enable` is set
/// (content processes and the engine-spawned services); a no-op otherwise (the
/// net component, the one role that must keep the host network).
///
/// The load-bearing one is the **network** namespace — defense in depth for the
/// same property the seccomp allowlist already gives: a renderer must never
/// reach the network, and the two fail independently (a missing socket syscall
/// in the filter is survivable when the namespace has no interface to connect
/// through). Alongside it, as cheaper defense in depth for properties seccomp
/// also already covers, are the **IPC** namespace (no shared System V IPC or
/// POSIX message queues with the host — `shmget`/`msgget`/`semget` are off the
/// allowlist too) and the **UTS** namespace (its own hostname/domainname —
/// `sethostname` is off the allowlist too).
///
/// Two namespaces are deliberately *not* here, each for a concrete reason worth
/// recording rather than a shortcut:
///
/// - **Mount** (an empty root, the filesystem analogue of the empty netns).
///   Emptying the root needs `pivot_root`, which needs `CAP_SYS_ADMIN` over the
///   mount that `/` lives on. A renderer's user namespace has **no `uid_map`**
///   (deliberate — see below — so it runs as the unmapped overflow uid), and an
///   unmapped userns confers no usable mount capability over the parent-owned
///   `/` (verified: the mount `EPERM`s even in an `apparmor=unconfined`
///   container). The fix — write a `uid_map` mapping to root-in-ns — is blocked
///   *twice*: by AppArmor on modern hosts (`apparmor_restrict_unprivileged_userns`
///   refuses the `uid_map` write) and, everywhere, by the **broker Landlock**,
///   which confines writes to the temp dir and `/proc/self/uid_map` is not there.
///   So it is genuinely blocked by two other (deliberate) hardening choices, not
///   merely unimplemented. Seccomp's `openat`/`open` denial is the actual no-fs
///   guarantee regardless.
/// - **PID**. Isolating the fork server's renderers cleanly needs the fork server
///   to be its ns's PID 1 (init/reaper), which needs the *engine* to
///   `clone(CLONE_NEWPID)` when spawning it — and `std::process::Command` cannot
///   pass clone flags. Giving each renderer its *own* PID namespace instead needs
///   the fork server to `clone(CLONE_NEWPID)` per renderer — which its own
///   hardening now forbids (clone3 → `ENOSYS` plus the `CLONE_NEW*` mask). And a
///   plain `unshare(CLONE_NEWPID)` in the fork server would make the *first*
///   renderer PID 1, whose death `SIGKILL`s every other renderer, breaking the
///   fault isolation a single crashed tab must not violate. It waits on a
///   spawn-path rework; seccomp denies `kill`/`ptrace` in the meantime.
///
/// `CLONE_NEWNET`/`NEWIPC`/`NEWUTS` on their own require `CAP_SYS_ADMIN`. Pairing
/// them with `CLONE_NEWUSER` in the *same* `unshare` gets it unprivileged: the
/// new user namespace grants a full capability set within itself, enough to
/// create the rest in that one call.
///
/// We deliberately do **not** write `/proc/self/uid_map`. Leaving it unmapped
/// means the process runs as the overflow uid (`nobody`) inside the namespace,
/// which is strictly better than an identity map — and on distributions that
/// restrict unprivileged user namespaces via AppArmor (Ubuntu 24.04+,
/// `kernel.apparmor_restrict_unprivileged_userns=1`) the map write is refused
/// with `EPERM` even though the `unshare` itself succeeds. The one consequence
/// is that the exec'd binary must be world-executable, since the file's owner
/// no longer maps to this process's credentials.
///
/// Called from the post-fork/pre-exec context, so it must stay
/// async-signal-safe: a single `unshare` syscall, nothing else.
#[cfg(feature = "multi-process")]
pub fn isolate_network(enable: bool) -> std::io::Result<()> {
    if !enable {
        return Ok(());
    }
    let flags =
        libc::CLONE_NEWUSER | libc::CLONE_NEWNET | libc::CLONE_NEWIPC | libc::CLONE_NEWUTS;
    // SAFETY: unshare with valid flags; affects only the calling process.
    if unsafe { libc::unshare(flags) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Mark the calling process non-dumpable, closing the *inbound* debugging
/// surface.
///
/// Everything else here confines what a compromised child can do. This defends
/// the opposite direction: what another process on the host may do *to* us.
/// A same-uid process can normally `ptrace`-attach to any of ours and read
/// `/proc/<pid>/mem` — which for the engine means the cookie jar in cleartext.
/// `RLIMIT_CORE = 0` already stops a crash from spilling those pages to disk;
/// this stops a live process from reading them.
///
/// The observable effect is that `PTRACE_ATTACH` (and so `/proc/<pid>/mem`)
/// is refused with `EPERM`. Note it does *not* reliably reassign the existing
/// `/proc/<pid>` directory to root — that ownership is decided when the inode
/// is created, so a directory already materialized under the invoking user
/// stays that way. Do not use `/proc` ownership as evidence this took effect;
/// `PR_GET_DUMPABLE`, or an actual attach attempt, is the honest check.
///
/// Note the children cannot do this to *each other* anyway — `ptrace` is not on
/// the allowlist — so the threat model here is other software running as the
/// same user, which seccomp has no say over.
///
/// **Placement matters**: the dumpable flag is reset to 1 by `execve` (for a
/// normal, non-setuid binary), but is inherited across `fork`. So this must be
/// called by each role *after* it has exec'd — calling it in `pre_exec`
/// alongside the rlimits would be silently undone by the exec that follows.
/// The fork server calls it once and every renderer it forks inherits it.
/// Applies in single-process mode too: that build has no children to confine,
/// but it still holds the cookie jar in its address space.
pub fn deny_debugger_attach() {
    // SAFETY: PR_SET_DUMPABLE takes one value argument and affects only the
    // calling process.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) } < 0 {
        // Not fatal, unlike seccomp: this is a hardening measure against other
        // software on the host, not the boundary that contains a compromised
        // renderer. Losing it degrades defense in depth rather than opening the
        // sandbox, so we report it and continue.
        eprintln!(
            "[sandbox] warning: could not clear dumpable flag: {}",
            std::io::Error::last_os_error()
        );
    }
}

/// Lower the calling process's scheduling priority (higher nice = lower
/// priority). Async-signal-safe (a single syscall), so usable pre-exec.
#[cfg(feature = "multi-process")]
fn set_priority(nice: libc::c_int) -> std::io::Result<()> {
    // SAFETY: PRIO_PROCESS with pid 0 targets the calling process.
    if unsafe { libc::setpriority(libc::PRIO_PROCESS, 0, nice) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// The first argument of `setrlimit(2)`, whose Rust type is libc-dependent:
/// glibc exposes a dedicated `__rlimit_resource_t` enum, musl uses a plain
/// `c_int`. Naming either one directly makes the crate uncompilable on the
/// other — a portability break the type checker only reports when something
/// actually builds against that libc.
#[cfg(target_env = "gnu")]
type RlimitResource = libc::__rlimit_resource_t;
#[cfg(not(target_env = "gnu"))]
type RlimitResource = libc::c_int;

#[cfg(feature = "multi-process")]
fn set_rlimit(resource: RlimitResource, limit: libc::rlim_t) -> std::io::Result<()> {
    let rl = libc::rlimit { rlim_cur: limit, rlim_max: limit };
    // SAFETY: valid resource id and a valid rlimit pointer.
    if unsafe { libc::setrlimit(resource, &rl) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}
