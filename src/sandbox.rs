//! OS-level privilege capping for child components (Linux, multi-process only).
//!
//! Process isolation is only worth as much as the privileges you drop inside
//! each process. After a child has connected its IPC link we install a
//! seccomp-BPF filter — the same mechanism Chromium uses to sandbox its
//! renderers.
//!
//! The filter is a default-deny **allowlist**: we enumerate the syscalls a
//! component legitimately needs and reject everything else with `EPERM`. This
//! is fail-closed — a syscall we never considered (a new one, or an obscure
//! bypass such as io_uring-based networking) is denied for free.
//!
//! Installing it is safe here because the child has already connected and
//! split its endpoint (the `socket`/`connect`/`dup` for that happened *before*
//! the filter); during `serve()` it only reads/writes existing fds and works
//! in memory. seccomp filters only ever remove privileges, and a process may
//! always restrict itself — no root needed.
//!
//! This applies only in multi-process mode: in single-process mode the
//! components are threads inside the engine, which needs network and exec, so
//! there is nothing to drop.
//!
//! Production would go further: `KillProcess` instead of `EPERM` (a denied
//! syscall should be fatal, not merely fail), a per-arch baseline tested across
//! libc/kernel versions, filesystem restriction (Landlock), namespaces, and
//! fail-closed startup (refuse to run if the filter cannot be installed). Here
//! we warn and continue so the PoC still runs in restricted containers/CI.

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
    // memory
    libc::SYS_mmap,
    libc::SYS_munmap,
    libc::SYS_mremap,
    libc::SYS_mprotect,
    libc::SYS_madvise,
    libc::SYS_brk,
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
#[cfg(all(feature = "multi-process", target_os = "linux"))]
const NET_EXTRA: &[libc::c_long] = &[
    libc::SYS_socket,
    libc::SYS_socketpair,
    libc::SYS_connect,
    libc::SYS_bind,
    libc::SYS_listen,
    libc::SYS_accept,
    libc::SYS_accept4,
    libc::SYS_getsockopt,
    libc::SYS_setsockopt,
    libc::SYS_getsockname,
    libc::SYS_getpeername,
];

/// Cap a renderer: pixels only — the baseline, no network, files, or exec.
#[cfg(all(feature = "multi-process", target_os = "linux"))]
pub fn lock_down_renderer() {
    announce("renderer", install(BASELINE.to_vec()));
}

/// Cap the net component: the baseline plus the socket family.
#[cfg(all(feature = "multi-process", target_os = "linux"))]
pub fn lock_down_net() {
    let allowed: Vec<libc::c_long> = BASELINE.iter().chain(NET_EXTRA).copied().collect();
    announce("net", install(allowed));
}

#[cfg(all(feature = "multi-process", target_os = "linux"))]
fn announce(role: &str, result: Result<(), Box<dyn std::error::Error>>) {
    match result {
        Ok(()) => eprintln!("[{role}] seccomp allowlist active (default-deny)"),
        Err(e) => {
            eprintln!("[{role}] WARNING: could not install seccomp sandbox ({e}); running unconfined")
        }
    }
}

/// Build and apply a default-deny allowlist: syscalls in `allowed` pass, every
/// other syscall returns `EPERM`.
#[cfg(all(feature = "multi-process", target_os = "linux"))]
fn install(allowed: Vec<libc::c_long>) -> Result<(), Box<dyn std::error::Error>> {
    use seccompiler::{apply_filter, BpfProgram, SeccompAction, SeccompFilter};
    use std::collections::BTreeMap;

    #[cfg(target_arch = "x86_64")]
    let arch = seccompiler::TargetArch::x86_64;
    #[cfg(target_arch = "aarch64")]
    let arch = seccompiler::TargetArch::aarch64;

    // Empty rule vec = match the syscall unconditionally (any args).
    let rules: BTreeMap<i64, Vec<seccompiler::SeccompRule>> =
        allowed.iter().map(|&nr| (nr as i64, Vec::new())).collect();

    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Errno(libc::EPERM as u32), // default: deny
        SeccompAction::Allow,                     // listed: allow
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
