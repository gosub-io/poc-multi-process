//! Sandbox self-tests, spawned by the integration suite (never by the demo).
//!
//! Each probe applies the renderer lockdown and then attempts one operation,
//! letting the test harness observe the outcome from the *outside*: a forbidden
//! syscall is a fatal `SIGSYS` (seccomp `KillProcess`), while an allowed program
//! exits cleanly. We can't assert this from inside a `#[cfg(test)]` unit test
//! because the filter is irreversible and would kill the test runner itself —
//! so enforcement is checked here, in a throwaway child process.

/// Fork a child that optionally marks itself non-dumpable, then try to
/// `PTRACE_ATTACH` to it from here (its parent, so Yama permits the attempt).
///
/// Returns `None` if the attach succeeded, or `Some(errno)` if it was refused.
/// The child is killed either way.
#[cfg(all(feature = "multi-process", target_os = "linux"))]
fn attach_refused(protect: bool) -> Option<i32> {
    let mut ready = [0 as libc::c_int; 2];
    assert_eq!(unsafe { libc::pipe(ready.as_mut_ptr()) }, 0, "pipe");
    let (rd, wr) = (ready[0], ready[1]);

    // SAFETY: single-threaded at this point, so the child may run normal code.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork");
    if pid == 0 {
        unsafe { libc::close(rd) };
        if protect {
            crate::sandbox::deny_debugger_attach();
        }
        // Signal that the flag is set *before* parking, so the parent never
        // races ahead and attaches to a child that hasn't protected itself yet.
        unsafe {
            libc::write(wr, [1u8].as_ptr().cast(), 1);
            loop {
                libc::pause();
            }
        }
    }

    unsafe { libc::close(wr) };
    let mut byte = [0u8; 1];
    assert_eq!(unsafe { libc::read(rd, byte.as_mut_ptr().cast(), 1) }, 1, "child never signalled");
    unsafe { libc::close(rd) };

    // SAFETY: PTRACE_ATTACH takes the target pid; the addr/data args are unused.
    let rc = unsafe {
        libc::ptrace(libc::PTRACE_ATTACH, pid, std::ptr::null_mut::<libc::c_void>(), std::ptr::null_mut::<libc::c_void>())
    };
    let outcome = if rc == -1 {
        Some(std::io::Error::last_os_error().raw_os_error().unwrap_or(0))
    } else {
        // A successful attach stops the tracee; reap that stop before killing.
        unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) };
        None
    };

    unsafe {
        libc::kill(pid, libc::SIGKILL);
        libc::waitpid(pid, std::ptr::null_mut(), 0);
    }
    outcome
}

/// Every probe compiled into *this* binary, for this platform.
///
/// The integration suite asserts this list against a per-platform expectation,
/// so a probe that silently disappears behind a `cfg` fails the build instead
/// of vanishing from a green test run. That is not hypothetical: the Windows
/// port compiled out 13 of 16 integration tests, and the suite still reported
/// success. An empty list for a platform is therefore a *finding* — it means
/// whatever that platform's sandbox backend does is currently unverified.
pub const PROBES: &[&str] = &[
    #[cfg(target_os = "linux")]
    "baseline",
    #[cfg(target_os = "linux")]
    "mprotect-exec",
    #[cfg(target_os = "linux")]
    "socket",
    #[cfg(target_os = "linux")]
    "memfd-seal",
    #[cfg(target_os = "linux")]
    "fcntl-dupfd",
    #[cfg(target_os = "linux")]
    "ring",
    #[cfg(target_os = "linux")]
    "netns",
    #[cfg(target_os = "linux")]
    "no-ptrace",
    #[cfg(target_os = "linux")]
    "forkserver-can-fork",
    #[cfg(target_os = "linux")]
    "forkserver-canary-gap",
    #[cfg(target_os = "linux")]
    "forkserver-no-exec",
    #[cfg(target_os = "linux")]
    "forkserver-no-socket",
    #[cfg(target_os = "macos")]
    "seatbelt-file",
    #[cfg(target_os = "macos")]
    "seatbelt-network",
    #[cfg(target_os = "macos")]
    "seatbelt-exec",
    #[cfg(target_os = "macos")]
    "seatbelt-net-role-keeps-network",
    #[cfg(target_os = "macos")]
    "seatbelt-baseline",
    #[cfg(target_os = "macos")]
    "seatbelt-file-write",
    #[cfg(target_os = "macos")]
    "seatbelt-fork",
    #[cfg(target_os = "macos")]
    "seatbelt-signal-other",
    #[cfg(target_os = "macos")]
    "seatbelt-sysctl",
    #[cfg(target_os = "macos")]
    "rlimits",
    #[cfg(target_os = "macos")]
    "ptrace-deny-accepted",
];

/// Entry point for the `selftest <probe>` role.
///
/// `list` prints the compiled-in probe names, one per line — the inventory the
/// harness checks. Everything else is a platform probe.
pub fn run(probe: &str) {
    if probe == "list" {
        for name in PROBES {
            println!("{name}");
        }
        std::process::exit(0);
    }
    #[cfg(target_os = "linux")]
    run_platform_probe(probe);
    #[cfg(target_os = "macos")]
    run_macos_probe(probe);
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        eprintln!("no sandbox probes are compiled in for this platform: {probe}");
        std::process::exit(2);
    }
}

/// Outcome codes shared by the macOS probes. They exist because a Seatbelt
/// denial is *not* fatal: unlike seccomp's `KillProcess`, the call simply
/// returns `EPERM` and the process runs on. So the harness cannot read a signal
/// from outside — the probe has to report what it observed, and distinguishing
/// "correctly denied" from "the operation never worked anyway" is the whole
/// point.
#[cfg(target_os = "macos")]
mod code {
    /// The operation failed *before* lockdown, so the probe proves nothing:
    /// a denial afterwards would have happened regardless of the profile.
    pub const CONTROL_FAILED: i32 = 90;
    /// The operation still succeeded after lockdown — the profile is not
    /// enforcing what it claims to.
    pub const NOT_DENIED: i32 = 91;
    /// Denied, but not by the sandbox (some other errno) — reported separately
    /// so a misleading pass cannot come from an unrelated failure.
    pub const WRONG_ERROR: i32 = 92;
    /// A cap was applied but did not take the value it claims to.
    pub const WRONG_VALUE: i32 = 93;
}

/// Read back one rlimit's soft value.
#[cfg(target_os = "macos")]
fn rlimit_soft(resource: libc::c_int) -> libc::rlim_t {
    let mut rl = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: valid resource id and a valid out-pointer.
    if unsafe { libc::getrlimit(resource, &mut rl) } < 0 {
        return libc::rlim_t::MAX;
    }
    rl.rlim_cur
}

/// Can this process signal another one? Uses the target's own parent and
/// signal 0 (an existence check that still counts as a `signal` operation to
/// Seatbelt), so nothing is actually delivered.
#[cfg(target_os = "macos")]
fn try_signal_parent() -> i32 {
    // SAFETY: getppid is infallible; kill with signal 0 sends nothing.
    unsafe {
        let ppid = libc::getppid();
        if libc::kill(ppid, 0) == 0 {
            0
        } else {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
        }
    }
}

/// Can this process read a sysctl? `hw.memsize` is a plain read-only value.
#[cfg(target_os = "macos")]
fn try_sysctl() -> i32 {
    let name = c"hw.memsize";
    let mut out: u64 = 0;
    let mut len = std::mem::size_of::<u64>();
    // SAFETY: NUL-terminated name, correctly sized out-buffer and length.
    unsafe {
        if libc::sysctlbyname(
            name.as_ptr(),
            std::ptr::addr_of_mut!(out).cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        ) == 0
        {
            0
        } else {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
        }
    }
}

/// Fork a child that immediately exits. Returns `Ok` if the fork was permitted.
#[cfg(target_os = "macos")]
fn try_fork() -> Result<(), i32> {
    // SAFETY: the child does nothing but _exit, which is async-signal-safe.
    unsafe {
        match libc::fork() {
            -1 => Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)),
            0 => libc::_exit(0),
            pid => {
                libc::waitpid(pid, std::ptr::null_mut(), 0);
                Ok(())
            }
        }
    }
}

/// Can this process open a well-known readable file? `Ok` = yes.
#[cfg(target_os = "macos")]
fn try_open_file() -> std::io::Result<()> {
    std::fs::File::open("/etc/hosts").map(|_| ())
}

/// Attempt an outbound TCP connect, returning the raw errno (0 = connected).
///
/// The target is a closed port on loopback, so *unconfined* this fails fast
/// with `ECONNREFUSED` — a definite "the network stack let me try". Confined,
/// the socket or connect is refused with `EPERM` before any packet moves. The
/// two errnos are what separates "the sandbox blocked it" from "there was
/// nothing to connect to", which a bare success/failure check cannot do.
#[cfg(target_os = "macos")]
fn try_connect() -> i32 {
    // SAFETY: a plain AF_INET socket and a fully initialized sockaddr_in.
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        if fd < 0 {
            return std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
        }
        let addr = libc::sockaddr_in {
            sin_len: std::mem::size_of::<libc::sockaddr_in>() as u8,
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: 9u16.to_be(), // discard, expected closed
            sin_addr: libc::in_addr { s_addr: u32::from_ne_bytes([127, 0, 0, 1]) },
            sin_zero: [0; 8],
        };
        let rc = libc::connect(
            fd,
            std::ptr::addr_of!(addr).cast(),
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        );
        let errno =
            if rc == 0 { 0 } else { std::io::Error::last_os_error().raw_os_error().unwrap_or(-1) };
        libc::close(fd);
        errno
    }
}

/// The macOS probe set: Seatbelt profile enforcement.
///
/// Every probe runs its operation **twice** — once before `sandbox_init` and
/// once after — and requires success then denial. The pairing is not ceremony.
/// A Seatbelt denial surfaces as an ordinary error, so a one-sided check is
/// satisfied by an operation that was broken to begin with (no network in the
/// CI sandbox, a missing file, a busy port). Only the transition from working
/// to refused shows the *profile* is what changed.
///
/// Note the probes avoid `assert!` after lockdown and exit with codes instead:
/// panicking would run formatting and backtrace machinery inside a process that
/// has just had its file access removed, which is a poor place to discover a
/// second failure.
#[cfg(target_os = "macos")]
fn run_macos_probe(probe: &str) {
    match probe {
        // A renderer has no filesystem: `(deny default)` withholds `file-read*`,
        // the SBPL counterpart of `openat` being absent from the seccomp list.
        "seatbelt-file" => {
            if try_open_file().is_err() {
                std::process::exit(code::CONTROL_FAILED);
            }
            crate::sandbox::lock_down_renderer();
            match try_open_file() {
                Ok(()) => std::process::exit(code::NOT_DENIED),
                Err(e) if e.raw_os_error() == Some(libc::EPERM) => std::process::exit(0),
                Err(_) => std::process::exit(code::WRONG_ERROR),
            }
        }

        // A renderer has no network. On Linux this is the empty netns plus the
        // missing socket syscalls; here it is the profile omitting
        // `network-outbound`, which is why it is worth testing separately.
        "seatbelt-network" => {
            if try_connect() != libc::ECONNREFUSED {
                std::process::exit(code::CONTROL_FAILED);
            }
            crate::sandbox::lock_down_renderer();
            match try_connect() {
                0 => std::process::exit(code::NOT_DENIED),
                e if e == libc::EPERM => std::process::exit(0),
                _ => std::process::exit(code::WRONG_ERROR),
            }
        }

        // No new programs: the analogue of `execve`/`clone` being off the
        // seccomp list. `(deny default)` covers process-fork and process-exec,
        // so spawning must fail rather than replace this process.
        "seatbelt-exec" => {
            if std::process::Command::new("/usr/bin/true").status().is_err() {
                std::process::exit(code::CONTROL_FAILED);
            }
            crate::sandbox::lock_down_renderer();
            match std::process::Command::new("/usr/bin/true").status() {
                Ok(_) => std::process::exit(code::NOT_DENIED),
                Err(_) => std::process::exit(0),
            }
        }

        // The positive half, and the one that keeps the others honest: the net
        // component's profile *does* grant `network-outbound`. Without this, a
        // green "renderer cannot reach the network" would be equally consistent
        // with the host having no network at all.
        "seatbelt-net-role-keeps-network" => {
            crate::sandbox::lock_down_net();
            match try_connect() {
                e if e == libc::ECONNREFUSED => std::process::exit(0),
                e if e == libc::EPERM => std::process::exit(code::NOT_DENIED),
                _ => std::process::exit(code::WRONG_ERROR),
            }
        }

        // The control for every "denied" probe above: normal work must still
        // run under the profile. Without this, all the denials are equally
        // consistent with a profile so tight the component cannot function —
        // which would pass every negative test and ship a broken renderer.
        "seatbelt-baseline" => {
            crate::sandbox::lock_down_renderer();
            // Allocate, compute, and write to an already-open fd: exactly what
            // a rasterizing renderer does between messages.
            let buf: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
            let sum: u64 = buf.iter().map(|b| *b as u64).sum();
            eprintln!("[selftest] baseline computed {sum} under the profile");
            std::process::exit(0);
        }

        // `file-read*` and `file-write*` are separate SBPL operations, so a
        // read-only denial does not imply a write denial. A renderer that could
        // create files could stage a payload even without being able to read.
        "seatbelt-file-write" => {
            let path = std::env::temp_dir().join("gosub-seatbelt-probe");
            if std::fs::write(&path, b"control").is_err() {
                std::process::exit(code::CONTROL_FAILED);
            }
            let _ = std::fs::remove_file(&path);
            crate::sandbox::lock_down_renderer();
            match std::fs::write(&path, b"after") {
                Ok(()) => {
                    let _ = std::fs::remove_file(&path);
                    std::process::exit(code::NOT_DENIED)
                }
                Err(e) if e.raw_os_error() == Some(libc::EPERM) => std::process::exit(0),
                Err(_) => std::process::exit(code::WRONG_ERROR),
            }
        }

        // `process-fork` is distinct from `process-exec`: a renderer that can
        // fork can multiply itself even with exec denied.
        "seatbelt-fork" => {
            if try_fork().is_err() {
                std::process::exit(code::CONTROL_FAILED);
            }
            crate::sandbox::lock_down_renderer();
            match try_fork() {
                Ok(()) => std::process::exit(code::NOT_DENIED),
                Err(_) => std::process::exit(0),
            }
        }

        // Tests the *precision* of the profile, not just its existence. The
        // grant is `(allow signal (target self))` — scoped deliberately — so
        // signalling any other process must still be refused. If `(target
        // self)` were dropped or widened, every other probe here would still
        // pass and only this one would notice.
        "seatbelt-signal-other" => {
            if try_signal_parent() != 0 {
                std::process::exit(code::CONTROL_FAILED);
            }
            crate::sandbox::lock_down_renderer();
            match try_signal_parent() {
                0 => std::process::exit(code::NOT_DENIED),
                e if e == libc::EPERM => std::process::exit(0),
                _ => std::process::exit(code::WRONG_ERROR),
            }
        }

        // The module docs claim the profile grants no `sysctl-read`. Nothing
        // verified that claim; sysctls leak host details (memory size, CPU
        // count, boot time) useful for fingerprinting and exploit tuning.
        "seatbelt-sysctl" => {
            if try_sysctl() != 0 {
                std::process::exit(code::CONTROL_FAILED);
            }
            crate::sandbox::lock_down_renderer();
            match try_sysctl() {
                0 => std::process::exit(code::NOT_DENIED),
                e if e == libc::EPERM => std::process::exit(0),
                _ => std::process::exit(code::WRONG_ERROR),
            }
        }

        // The rlimits are a mechanism entirely separate from Seatbelt and were
        // wholly unverified on macOS. Checks the two caps that actually change
        // a value here — note `RLIMIT_CORE` is deliberately not asserted,
        // because macOS already defaults it to 0 and proving a no-op proves
        // nothing. `RLIMIT_AS` is absent by design (see the backend docs).
        "rlimits" => {
            let nofile_before = rlimit_soft(libc::RLIMIT_NOFILE);
            // SAFETY: PRIO_PROCESS with pid 0 targets this process.
            let prio_before = unsafe { libc::getpriority(libc::PRIO_PROCESS, 0) };
            if nofile_before == 128 || prio_before == 10 {
                // Already at the target value: the check below would pass
                // without the call having done anything.
                std::process::exit(code::CONTROL_FAILED);
            }
            if crate::sandbox::apply_child_rlimits().is_err() {
                std::process::exit(code::WRONG_ERROR);
            }
            let prio_after = unsafe { libc::getpriority(libc::PRIO_PROCESS, 0) };
            if rlimit_soft(libc::RLIMIT_NOFILE) != 128 || prio_after != 10 {
                std::process::exit(code::WRONG_VALUE);
            }
            std::process::exit(0);
        }

        // The inbound direction, and the one mechanism here that is not
        // Seatbelt. This verifies only that the kernel *accepts*
        // `PT_DENY_ATTACH` — deliberately a weaker claim than the Linux
        // `no-ptrace` probe makes, and named so it cannot be misread as more.
        //
        // The stronger test (attach to a protected child and be refused) is not
        // available to us: on macOS an unprivileged process cannot `PT_ATTACH`
        // even to its own child without SIP disabled or task-port entitlements,
        // so the *control* fails and the probe proves nothing either way. An
        // earlier version tried exactly that and reported CONTROL_FAILED on CI,
        // which is the honest outcome but not a usable test.
        //
        // What this still catches: the request being rejected outright — a
        // wrong constant, or a future macOS dropping support. That matters
        // because `deny_debugger_attach` only *warns* on failure, so a silent
        // regression would otherwise go unnoticed.
        "ptrace-deny-accepted" => {
            // SAFETY: PT_DENY_ATTACH takes no addr/data and affects only us.
            let rc = unsafe { libc::ptrace(libc::PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) };
            if rc < 0 {
                std::process::exit(code::NOT_DENIED);
            }
            std::process::exit(0);
        }

        other => {
            eprintln!("unknown macOS probe: {other}");
            std::process::exit(2);
        }
    }
}

/// The Linux probe set. Each either exits 0 (property holds) or dies on
/// `SIGSYS` (the sandbox killed a forbidden operation), which the harness
/// observes from outside.
///
/// ## Shape note for other platforms
///
/// This works because seccomp is *self-applied* and violations are fatal: a
/// probe can confine itself and then attempt one operation. Windows cannot use
/// this shape — a job object, restricted token and AppContainer are attached
/// by the parent at `CreateProcess` time, and a denial surfaces as
/// `ACCESS_DENIED` from the call rather than as a killed process. A Windows
/// probe is therefore just the *attempt*, run twice: once in an unconfined
/// child (must succeed) and once in a confined one (must be denied). Only the
/// pair proves anything — "the call failed" alone is satisfied by a call that
/// would have failed anyway, which is exactly how the first `netns` probe here
/// passed vacuously against `/sys/class/net`.
#[cfg(target_os = "linux")]
fn run_platform_probe(probe: &str) {
    // The netns probe must run *before* the seccomp lockdown: verifying the
    // namespace is empty means enumerating interfaces, and a locked-down
    // renderer has no `openat`/`socket` with which to look. It asserts the
    // layer underneath the filter, so it is checked underneath it too.
    if probe == "netns" {
        // Read the interface list from procfs, NOT `/sys/class/net`: sysfs
        // reports the namespace it was *mounted* in, so it keeps showing the
        // host's interfaces after an unshare and would make this probe pass
        // vacuously. `/proc/self/net` follows the calling task's netns.
        let interfaces = || -> Vec<String> {
            let dev = std::fs::read_to_string("/proc/self/net/dev").expect("read /proc/self/net/dev");
            let mut names: Vec<String> = dev
                .lines()
                .skip(2) // two header lines
                .filter_map(|l| l.split(':').next())
                .map(|n| n.trim().to_string())
                .collect();
            names.sort();
            names
        };

        let before = std::fs::read_link("/proc/self/ns/net").expect("read netns link");
        assert!(interfaces().len() > 1, "host netns looks empty already — probe proves nothing");

        crate::sandbox::isolate_network(true).expect("unshare netns");

        // The namespace must actually have changed, and the new one must hold
        // nothing but loopback: no route off this machine exists at all.
        let after = std::fs::read_link("/proc/self/ns/net").expect("read netns link");
        assert_ne!(before, after, "still in the host network namespace");
        assert_eq!(interfaces(), vec!["lo".to_string()], "netns is not empty");
        std::process::exit(0);
    }

    // Also pre-lockdown, for the same reason: `prctl` is not on the allowlist,
    // so `PR_GET_DUMPABLE` after lockdown would itself be a fatal SIGSYS.
    if probe == "no-ptrace" {
        // Prove the property itself — that a `PTRACE_ATTACH` is refused —
        // rather than just reading back the flag we set. The attach has to run
        // parent→child: Yama's default `ptrace_scope=1` permits tracing only
        // descendants, so a child attaching to its parent would fail for
        // reasons that have nothing to do with the dumpable flag and the test
        // would pass vacuously.
        //
        // The control case matters for the same reason: if an *unprotected*
        // child can't be attached to either, this probe proves nothing about
        // what `deny_debugger_attach` bought us.
        assert!(attach_refused(false).is_none(), "control: an unprotected child should be traceable");
        let errno = attach_refused(true).expect("a non-dumpable child must refuse PTRACE_ATTACH");
        assert_eq!(errno, libc::EPERM, "expected EPERM, got errno {errno}");
        std::process::exit(0);
    }

    // Fork-server probes: this role's filter is not the renderer's, and it is
    // inherited by every renderer forked under it — so it gets its own
    // lockdown here rather than falling through to `lock_down_renderer`.
    if let Some(op) = probe.strip_prefix("forkserver-") {
        crate::sandbox::lock_down_fork_server();
        match op {
            // The positive case, and the one that actually bites: this filter
            // is inherited across `fork`, so anything it forgets kills the
            // renderer instead of the fork server. Forking, reaping, and the
            // `F_DUPFD_CLOEXEC` a child needs to split its endpoint before its
            // own lockdown must all still work. Clean exit = pass.
            "can-fork" => unsafe {
                let pid = libc::fork();
                assert!(pid >= 0, "fork refused under the fork-server filter");
                if pid == 0 {
                    libc::_exit(0);
                }
                let mut status = 0;
                assert_eq!(libc::waitpid(pid, &mut status, 0), pid, "cannot reap");
                // What `Endpoint::from_channel` does in a freshly forked child.
                let dup = libc::fcntl(2, libc::F_DUPFD_CLOEXEC, 0);
                assert!(dup >= 0, "endpoint split would fail in a forked child");
                std::process::exit(0);
            },

            // The canary must *detect*, not merely pass. Runs it against a
            // filter with one syscall deliberately removed; the canary is
            // expected to abort the process, so a clean exit here is a failure.
            "canary-gap" => crate::sandbox::canary_must_detect_a_missing_syscall(),

            // The fork server forks; it never execs. Reached only if the
            // allowlist let `execve` through.
            "no-exec" => unsafe {
                let path = b"/bin/true\0";
                let argv = [path.as_ptr().cast::<libc::c_char>(), std::ptr::null()];
                let _ = libc::execve(
                    path.as_ptr().cast::<libc::c_char>(),
                    argv.as_ptr(),
                    [std::ptr::null()].as_ptr(),
                );
                std::process::exit(0);
            },

            // It talks only on the control fd it was handed. A new socket must
            // be fatal, exactly as for a renderer.
            "no-socket" => unsafe {
                let _ = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
                std::process::exit(0);
            },

            other => {
                eprintln!("unknown fork-server probe: {other}");
                std::process::exit(2);
            }
        }
    }

    // Drop to the renderer's privileges, exactly as a real renderer does.
    crate::sandbox::lock_down_renderer();

    match probe {
        // The sandbox must NOT kill an allowed program: only reads/writes on
        // existing fds, memory, and exit. Clean exit = pass.
        "baseline" => std::process::exit(0),

        // W^X: turning writable memory executable must be fatal. We reach the
        // exit only if the argument filter FAILED to trap the PROT_EXEC.
        "mprotect-exec" => unsafe {
            let p = libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            );
            let _ = libc::mprotect(p, 4096, libc::PROT_READ | libc::PROT_EXEC);
            std::process::exit(0);
        },

        // Network: a renderer has no socket family, so obtaining a socket must
        // be fatal. Reached only if the allowlist let it through.
        "socket" => unsafe {
            let _ = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
            std::process::exit(0);
        },

        // The full shared-memory tile producer dance (memfd_create, ftruncate,
        // mmap write, munmap, fcntl F_ADD_SEALS) must survive the sandbox —
        // it's how a confined renderer ships every frame. Clean exit = pass.
        "memfd-seal" => {
            crate::shm::create_sealed_tile(64, 64, |buf| buf.fill(0xCD))
                .expect("sealed tile under sandbox");
            std::process::exit(0);
        }

        // fcntl is allowed *only* for the seal commands; any other command —
        // here F_DUPFD, an fd-fabrication primitive — must be fatal. Reached
        // only if the argument filter failed.
        "fcntl-dupfd" => unsafe {
            let _ = libc::fcntl(2, libc::F_DUPFD, 0);
            std::process::exit(0);
        },

        // The full ring-buffer dance (memfd + size seals, RW mapping, cursor
        // atomics, drain) must survive the sandbox — it's how a confined
        // renderer receives every large fetch body. Single-threaded (the
        // sandbox has no clone), so the body must fit the window: write it
        // all, finish, then consume. Clean exit = pass.
        "ring" => {
            let (mut producer, fd) =
                crate::ring::RingProducer::create(64 * 1024).expect("ring create under sandbox");
            let body: Vec<u8> = (0..16 * 1024).map(|i| (i % 251) as u8).collect();
            producer.write_all(&body).expect("ring write under sandbox");
            producer.finish();
            let got = crate::ring::consume(fd, body.len() as u64).expect("ring consume under sandbox");
            assert_eq!(got, body, "ring bytes corrupted under sandbox");
            std::process::exit(0);
        }

        other => {
            eprintln!("unknown selftest probe: {other}");
            std::process::exit(2);
        }
    }
}
