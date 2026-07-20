//! OS-level privilege capping for child components (Linux, multi-process only).
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
#[cfg(all(feature = "multi-process", target_os = "linux"))]
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
    libc::SYS_fstat,
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
#[cfg(all(feature = "multi-process", target_os = "linux"))]
const NET_EXTRA: &[libc::c_long] = &[
    libc::SYS_socket,
    libc::SYS_socketpair,
    libc::SYS_connect,
    libc::SYS_getsockopt,
    libc::SYS_setsockopt,
    libc::SYS_getsockname,
    libc::SYS_getpeername,
];

/// Cap a renderer: pixels only — the baseline, no network, files, or exec.
#[cfg(all(feature = "multi-process", target_os = "linux"))]
pub fn lock_down_renderer() {
    deny_debugger_attach();
    enforce("renderer", install(BASELINE.to_vec()));
}

/// Cap the net component: the baseline plus the socket family.
#[cfg(all(feature = "multi-process", target_os = "linux"))]
pub fn lock_down_net() {
    deny_debugger_attach();
    let allowed: Vec<libc::c_long> = BASELINE.iter().chain(NET_EXTRA).copied().collect();
    enforce("net", install(allowed));
}

#[cfg(all(feature = "multi-process", target_os = "linux"))]
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
#[cfg(all(feature = "multi-process", target_os = "linux"))]
fn install(allowed: Vec<libc::c_long>) -> Result<(), Box<dyn std::error::Error>> {
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
    // — F_DUPFD (fd fabrication), F_SETFD (clearing CLOEXEC), F_SETFL, locks —
    // hits KillProcess.
    let mut fcntl_allowed = Vec::new();
    for cmd in [libc::F_ADD_SEALS, libc::F_GET_SEALS, libc::F_GETFD] {
        let is_cmd =
            SeccompCondition::new(1, SeccompCmpArgLen::Qword, SeccompCmpOp::Eq, cmd as u64)?;
        fcntl_allowed.push(SeccompRule::new(vec![is_cmd])?);
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
#[cfg(all(feature = "multi-process", target_os = "linux"))]
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

/// Move the calling process into a fresh, empty network namespace.
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
#[cfg(all(feature = "multi-process", target_os = "linux"))]
pub fn unshare_network() -> std::io::Result<()> {
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
#[cfg(target_os = "linux")]
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
#[cfg(all(feature = "multi-process", target_os = "linux"))]
fn set_priority(nice: libc::c_int) -> std::io::Result<()> {
    // SAFETY: PRIO_PROCESS with pid 0 targets the calling process.
    if unsafe { libc::setpriority(libc::PRIO_PROCESS, 0, nice) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(all(feature = "multi-process", target_os = "linux"))]
fn set_rlimit(resource: libc::__rlimit_resource_t, limit: libc::rlim_t) -> std::io::Result<()> {
    let rl = libc::rlimit { rlim_cur: limit, rlim_max: limit };
    // SAFETY: valid resource id and a valid rlimit pointer.
    if unsafe { libc::setrlimit(resource, &rl) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// No-op off Linux. macOS has `PT_DENY_ATTACH` and Windows has process
/// mitigation policies; both would go here.
#[cfg(not(target_os = "linux"))]
pub fn deny_debugger_attach() {}

// On non-Linux (multi-process still builds over Unix sockets on e.g. macOS)
// there is no seccomp; the caps are no-ops with a note.
#[cfg(all(feature = "multi-process", not(target_os = "linux")))]
pub fn lock_down_renderer() {
    eprintln!("[renderer] no seccomp on this platform — running unconfined");
}

#[cfg(all(feature = "multi-process", not(target_os = "linux")))]
pub fn lock_down_net() {}

#[cfg(all(feature = "multi-process", not(target_os = "linux")))]
pub fn apply_child_rlimits() -> std::io::Result<()> {
    Ok(())
}
