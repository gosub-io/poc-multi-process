//! OS-level privilege capping for child components (Linux, multi-process only).
//!
//! Process isolation is only worth as much as the privileges you *drop* inside
//! each process. A renderer's whole job is to turn bytes into pixels; it never
//! needs to open a network socket, exec another program, or trace anyone. So
//! after it has connected its IPC link, we install a **seccomp-BPF** filter
//! that makes those syscalls fail at the kernel level — the same mechanism
//! Chromium uses to sandbox its renderers.
//!
//! Two things make this safe to do here:
//! - The renderer already connected to the engine over its Unix socket during
//!   startup (that used `socket()`/`connect()` *before* the filter). During
//!   `serve()` it only does `read`/`write` on that fd plus memory work, so
//!   denying socket creation costs it nothing.
//! - seccomp filters are inherited and can only ever *remove* privileges, and
//!   a process is always allowed to restrict itself — no root needed.
//!
//! This only applies in multi-process mode: in single-process mode the
//! "renderer" is a thread inside the engine, which legitimately needs the
//! network (for the net component thread), so there is nothing to drop. That
//! is, once more, why the boundary is only real with separate processes.
//!
//! A production sandbox would go further — an allowlist rather than this
//! focused denylist, plus filesystem restriction (Landlock), a pid/net
//! namespace, and `chroot`/`pivot_root` — and would *fail closed* (refuse to
//! run unconfined). For the PoC we deny the sharpest syscalls and, if the
//! filter cannot be installed, warn loudly and continue so the demo still
//! runs in restricted containers/CI.

/// Cap a renderer process: no network, no exec, no ptrace.
#[cfg(all(feature = "multi-process", target_os = "linux"))]
pub fn lock_down_renderer() {
    // Denying `socket`/`socketpair` alone already makes network I/O
    // impossible (you can't `connect` without first creating a socket), but
    // we list the whole family to make the intent obvious and defense layered.
    let denied = &[
        libc::SYS_socket,
        libc::SYS_socketpair,
        libc::SYS_connect,
        libc::SYS_bind,
        libc::SYS_listen,
        libc::SYS_accept,
        libc::SYS_accept4,
        libc::SYS_execve,
        libc::SYS_execveat,
        libc::SYS_ptrace,
    ];

    match install_denylist(denied) {
        Ok(()) => {
            // Prove the cap is real rather than merely claimed: creating a
            // socket must now fail with EPERM.
            let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
            if fd >= 0 {
                unsafe { libc::close(fd) };
                eprintln!("[renderer] WARNING: sandbox not effective — socket() succeeded");
            } else {
                eprintln!(
                    "[renderer] seccomp sandbox active — network/exec denied, socket() blocked"
                );
            }
        }
        Err(e) => eprintln!(
            "[renderer] WARNING: could not install seccomp sandbox ({e}); running unconfined"
        ),
    }
}

/// Attempt network + exec I/O and report what the kernel does to each. Runs
/// inside a child process *after* its filter is installed, when
/// `GOSUB_POC_PROBE` is set — a live demonstration of each role's caps.
///
/// The expected outcome differs by role, which is the point:
/// - renderer: network DENIED, exec DENIED (it only pushes pixels)
/// - net:      network ALLOWED, exec DENIED (it owns network, nothing else)
#[cfg(all(feature = "multi-process", target_os = "linux"))]
pub fn probe_io(role: &str) {
    use std::io::Write;
    eprintln!("[{role}] ---- sandbox probe (attempting network + exec I/O) ----");

    // 1. The raw syscall: create a network socket.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        report::<()>(role, "socket(AF_INET, SOCK_STREAM)", Err(std::io::Error::last_os_error()));
    } else {
        unsafe { libc::close(fd) };
        report::<()>(role, "socket(AF_INET, SOCK_STREAM)", Ok(()));
    }

    // 2. A real outbound TCP connection (numeric IP, so no DNS in the way —
    //    when denied, this fails at socket creation, before a byte leaves).
    report(role, "TcpStream::connect 1.1.1.1:80", std::net::TcpStream::connect("1.1.1.1:80"));

    // 3. Spawn a subprocess: exec is denied for *both* roles.
    report(role, "exec /bin/sh -c ...", std::process::Command::new("/bin/sh").arg("-c").arg("true").status());

    // 4. Contrast: reading a file is on neither denylist, so it still works.
    //    seccomp can't do path-based filtering (it can't inspect the string
    //    argument to openat), so a compromised renderer can still read any
    //    file the user can — /etc/passwd, ~/.ssh/*, the cookies DB, ... This
    //    is the next hole to close, with Landlock (a filesystem LSM), not
    //    seccomp. The read below proves the gap is real.
    match std::fs::read_to_string("/etc/passwd") {
        Ok(contents) => {
            let first = contents.lines().next().unwrap_or("");
            eprintln!("[{role}] read /etc/passwd            : ALLOWED — first line: {first:?}");
        }
        Err(e) => eprintln!("[{role}] read /etc/passwd            : DENIED ({e})"),
    }

    eprintln!("[{role}] ---- end probe ----");
    let _ = std::io::stderr().flush();
}

/// Print a probe result neutrally — whether ALLOWED is right or wrong depends
/// on the role (see [`probe_io`]).
#[cfg(all(feature = "multi-process", target_os = "linux"))]
fn report<T>(role: &str, what: &str, result: std::io::Result<T>) {
    match result {
        Err(e) => eprintln!("[{role}] {what:<30}: DENIED ({e})"),
        Ok(_) => eprintln!("[{role}] {what:<30}: ALLOWED"),
    }
}

/// Cap the net component: it *is* allowed sockets (it owns network access),
/// but it still never needs to exec another program or trace processes.
#[cfg(all(feature = "multi-process", target_os = "linux"))]
pub fn lock_down_net() {
    let denied = &[libc::SYS_execve, libc::SYS_execveat, libc::SYS_ptrace];
    match install_denylist(denied) {
        Ok(()) => eprintln!("[net] seccomp sandbox active — exec/ptrace denied (network allowed)"),
        Err(e) => {
            eprintln!("[net] WARNING: could not install seccomp sandbox ({e}); running unconfined")
        }
    }
}

/// Build and apply a filter that returns `EPERM` for `denied` and allows
/// everything else.
#[cfg(all(feature = "multi-process", target_os = "linux"))]
fn install_denylist(denied: &[libc::c_long]) -> Result<(), Box<dyn std::error::Error>> {
    use seccompiler::{apply_filter, BpfProgram, SeccompAction, SeccompFilter};
    use std::collections::BTreeMap;

    #[cfg(target_arch = "x86_64")]
    let arch = seccompiler::TargetArch::x86_64;
    #[cfg(target_arch = "aarch64")]
    let arch = seccompiler::TargetArch::aarch64;

    // Empty rule vec = match the syscall unconditionally (regardless of args).
    let rules: BTreeMap<i64, Vec<seccompiler::SeccompRule>> =
        denied.iter().map(|&nr| (nr as i64, Vec::new())).collect();

    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,                     // syscalls not listed: allow
        SeccompAction::Errno(libc::EPERM as u32), // listed syscalls: fail with EPERM
        arch,
    )?;
    let program: BpfProgram = filter.try_into()?;
    apply_filter(&program)?;
    Ok(())
}

// On non-Linux (e.g. macOS, where multi-process still builds over Unix
// sockets) there is no seccomp; the caps are no-ops with a note.
#[cfg(all(feature = "multi-process", not(target_os = "linux")))]
pub fn lock_down_renderer() {
    eprintln!("[renderer] no seccomp on this platform — running unconfined");
}

#[cfg(all(feature = "multi-process", not(target_os = "linux")))]
pub fn lock_down_net() {}

#[cfg(all(feature = "multi-process", not(target_os = "linux")))]
pub fn probe_io(role: &str) {
    eprintln!("[{role}] sandbox probe unavailable on this platform");
}
