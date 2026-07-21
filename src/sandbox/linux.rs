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
//! component legitimately needs and everything else is a fatal `SIGSYS`
//! (`KillProcess`). This is fail-closed — a syscall we never considered (a new
//! one, or an obscure bypass such as io_uring-based networking) is denied for
//! free — and killing on violation, rather than returning `EPERM`, denies an
//! exploit the chance to probe the sandbox and adapt.
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
/// its first fork. It cannot be argument-filtered either: `clone3` passes its
/// flags in a struct in memory rather than in registers, and seccomp can only
/// see registers. (The trick production sandboxes use is to return `ENOSYS`
/// for `clone3` so glibc falls back to the filterable `clone`; not done here.)
/// Coarse is acceptable in this one process because it is minimal, trusted and
/// secret-free — and because a renderer cannot inherit the privilege: its own
/// filter, installed straight after the fork, denies both.
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
    if install_with(full, false).is_err() {
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
    let allowed: Vec<libc::c_long> =
        BASELINE.iter().chain(FORK_SERVER_EXTRA).copied().collect();
    enforce("fork-server", install_with(allowed, true));
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

#[cfg(feature = "multi-process")]
fn enforce(role: &str, result: Result<(), Box<dyn std::error::Error>>) {
    match result {
        Ok(()) => eprintln!("[{role}] seccomp allowlist active (default-deny, KillProcess)"),
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
    install_with(allowed, false)
}

/// As [`install`], but `allow_dup_fd` additionally permits
/// `fcntl(F_DUPFD_CLOEXEC)` — needed only by the fork server, whose forked
/// children must clone a descriptor before installing their own filter.
#[cfg(feature = "multi-process")]
fn install_with(
    allowed: Vec<libc::c_long>,
    allow_dup_fd: bool,
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
    if allow_dup_fd {
        // musl follows its `F_DUPFD_CLOEXEC` with an explicit
        // `fcntl(F_SETFD, FD_CLOEXEC)`; glibc does not. Both conditions are
        // required together (they AND), so this permits *setting* close-on-exec
        // and nothing else: `F_SETFD` with any other flag word — crucially 0,
        // which would CLEAR close-on-exec and leak the descriptor across an
        // exec — still hits KillProcess. Setting the flag only ever narrows
        // what a descriptor can do, so this grants no reach.
        let is_setfd =
            SeccompCondition::new(1, SeccompCmpArgLen::Qword, SeccompCmpOp::Eq, libc::F_SETFD as u64)?;
        let sets_cloexec = SeccompCondition::new(
            2,
            SeccompCmpArgLen::Qword,
            SeccompCmpOp::Eq,
            libc::FD_CLOEXEC as u64,
        )?;
        fcntl_allowed.push(SeccompRule::new(vec![is_setfd, sets_cloexec])?);
    }
    rules.insert(libc::SYS_fcntl as i64, fcntl_allowed);

    let filter = SeccompFilter::new(
        rules,
        SeccompAction::KillProcess, // default & argument-mismatch: fatal SIGSYS
        SeccompAction::Allow,       // matched: allow
        arch,
    )?;
    let program: BpfProgram = filter.try_into()?;
    apply_filter(&program)?;
    Ok(())
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
    // Address space: enough for legitimate rendering, but a renderer that
    // tries to allocate the host to death instead hits a failed mmap → Rust's
    // alloc-error path aborts *that process*, not the machine.
    set_rlimit(libc::RLIMIT_AS, 512 * 1024 * 1024)?;
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

/// Move the calling process into a fresh, empty network namespace when
/// `enable` is set (renderers); a no-op otherwise (the net component, which is
/// the one role that must keep the network).
///
/// This is defense in depth for the *same* property the seccomp allowlist
/// already provides: a renderer must never reach the network. The two fail
/// independently. seccomp's guarantee is "we enumerated the syscalls correctly"
/// — one missing entry on a new architecture, one novel socket-obtaining path,
/// and it is gone. An empty netns has no interfaces at all, so there is nothing
/// to connect *to* even if a syscall slips through the filter.
///
/// `CLONE_NEWNET` on its own requires `CAP_SYS_ADMIN`. Pairing it with
/// `CLONE_NEWUSER` gets it unprivileged: the new user namespace grants a full
/// capability set *within itself*, which is enough to create the netns.
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
    // SAFETY: unshare with valid flags; affects only the calling process.
    if unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET) } < 0 {
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
