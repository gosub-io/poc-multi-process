//! Integration tests: run the *actual built binary* end to end, so they
//! exercise the real process spawning, IPC, sandbox and shutdown — the parts a
//! single-process unit test can't reach. Pure logic (SSRF, cookie policy, IPC
//! framing, the backpressure gate, origin parsing) is unit-tested in `src/`.

use std::process::{Command, Output};

/// Path to the compiled PoC binary, provided by Cargo to integration tests.
fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_gosub-proc-iso-poc")
}

/// How long the binary may run before the harness gives up on it. Everything
/// here finishes in seconds; this is a backstop, not a budget.
const RUN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Run the binary to completion, killing it if it exceeds [`RUN_TIMEOUT`].
///
/// The timeout is the point. `Command::output()` waits forever, so anything
/// that wedges the engine — a renderer dying on a syscall the sandbox forgot,
/// on a libc nobody tested — stops being a test failure and becomes a hung
/// job. That is exactly what happened on the first CI run: the musl leg sat
/// for hours on a demo that had already lost both its renderers, reporting
/// nothing. A hang must present as a fast, loud failure.
fn run(args: &[&str]) -> Output {
    use std::process::Stdio;

    let mut child = Command::new(bin())
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn poc binary");

    let deadline = std::time::Instant::now() + RUN_TIMEOUT;
    loop {
        match child.try_wait().expect("poll child") {
            Some(_) => break,
            None if std::time::Instant::now() >= deadline => {
                let _ = child.kill();
                let out = child.wait_with_output().expect("reap timed-out child");
                panic!(
                    "`{}` did not finish within {RUN_TIMEOUT:?} — killed.\n\
                     A hang here usually means a renderer died and the engine is \
                     still waiting on it.\nstdout:\n{}\nstderr:\n{}",
                    args.join(" "),
                    String::from_utf8_lossy(&out.stdout),
                    String::from_utf8_lossy(&out.stderr),
                );
            }
            None => std::thread::sleep(std::time::Duration::from_millis(20)),
        }
    }
    child.wait_with_output().expect("collect child output")
}

/// The default run (multi-process where the feature is on) must open two tabs,
/// render a frame for each, and shut down cleanly with no crash.
#[test]
fn default_run_renders_and_shuts_down() {
    let out = run(&[]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "exit {:?}\nstdout: {stdout}", out.status);
    assert!(stdout.contains("frame ready"), "no frame rendered:\n{stdout}");
    assert!(stdout.contains("engine shut down"), "no clean shutdown:\n{stdout}");
    assert!(!stdout.contains("crashed"), "unexpected crash:\n{stdout}");
}

/// The same lifecycle must work with components as threads. No fd-passing on
/// in-process channels, so tiles arrive as message copies — still verified.
#[test]
fn single_process_run_renders_and_shuts_down() {
    let out = run(&["--single-process"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "exit {:?}\nstdout: {stdout}", out.status);
    assert!(stdout.contains("frame ready") && stdout.contains("engine shut down"), "{stdout}");
    assert!(stdout.contains("via message copy"), "expected copied tiles:\n{stdout}");
    assert!(stdout.contains("pattern ok"), "tile pattern not verified:\n{stdout}");
}

/// In multi-process mode tiles must travel as sealed shared memory — only the
/// dimensions and an fd cross the socket — and the received pixels must be
/// byte-identical to the pattern the renderer wrote (the round-trip check for
/// the memfd + SCM_RIGHTS channel).
#[cfg(all(feature = "multi-process", target_os = "linux"))]
#[test]
fn multi_process_tiles_travel_via_shared_memory() {
    let out = run(&[]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "exit {:?}\nstdout: {stdout}", out.status);
    assert!(stdout.contains("via shared memory"), "expected shm tiles:\n{stdout}");
    assert!(stdout.contains("pattern ok"), "tile pattern not verified:\n{stdout}");
    assert!(!stdout.contains("MISMATCH"), "tile bytes corrupted in transit:\n{stdout}");
}

/// The demo's large (4 MiB) fetch body must stream net → renderer through the
/// shared-memory ring — 16× its 256 KiB window, so it demonstrably wraps —
/// and byte-match the producer's pattern (the ring's round-trip check). The
/// renderer reports both on stderr. In single-process mode the same body
/// falls back to the in-band copy, still verified.
#[cfg(all(feature = "multi-process", target_os = "linux"))]
#[test]
fn large_fetch_body_streams_through_the_ring() {
    let out = run(&[]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "exit {:?}\nstderr: {stderr}", out.status);
    assert!(stderr.contains("4096 KiB body via ring"), "expected ring body:\n{stderr}");
    assert!(stderr.contains("(pattern ok)"), "body pattern not verified:\n{stderr}");
    assert!(!stderr.contains("MISMATCH"), "body bytes corrupted in transit:\n{stderr}");

    let out = run(&["--single-process"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "exit {:?}\nstderr: {stderr}", out.status);
    assert!(
        stderr.contains("4096 KiB body via message copy") && stderr.contains("(pattern ok)"),
        "expected verified in-band fallback:\n{stderr}"
    );
}

/// The tile bench must complete on both transports (the numbers themselves
/// are for humans; asserting on timing would be flaky).
#[cfg(all(feature = "multi-process", target_os = "linux"))]
#[test]
fn bench_tiles_runs_on_both_transports() {
    for transport in ["shm", "socket"] {
        let out = run(&["--bench-tiles", "5", transport]);
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(out.status.success(), "bench {transport}: exit {:?}\n{stdout}", out.status);
        assert!(stdout.contains("ms/frame"), "bench {transport} incomplete:\n{stdout}");
        let expected =
            if transport == "shm" { "via shared memory" } else { "via message copy" };
        assert!(stdout.contains(expected), "bench {transport} wrong path:\n{stdout}");
    }
}

/// The body-stream bench must complete on both transports, with the renderer
/// verifying the pattern either way.
#[cfg(all(feature = "multi-process", target_os = "linux"))]
#[test]
fn bench_stream_runs_on_both_transports() {
    for transport in ["ring", "socket"] {
        let out = run(&["--bench-stream", "4", transport]);
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "bench {transport}: exit {:?}\n{stdout}{stderr}", out.status);
        assert!(stdout.contains("MiB/s"), "bench {transport} incomplete:\n{stdout}");
        let expected = if transport == "ring" { "via ring" } else { "via message copy" };
        assert!(
            stderr.contains(expected) && stderr.contains("(pattern ok)"),
            "bench {transport} wrong/unverified path:\n{stderr}"
        );
    }
}

#[test]
fn unknown_argument_is_rejected() {
    let out = run(&["--nonsense"]);
    assert!(!out.status.success(), "unknown arg should be an error");
}

/// What each platform's lockdown prints when a *child process* starts up.
/// Only a real child emits this — in single-process mode the components are
/// threads and no lockdown runs at all — which is what makes it a usable
/// signal that multi-process mode really spawned processes.
#[cfg(target_os = "linux")]
const LOCKDOWN_BANNER: &str = "seccomp allowlist active";
#[cfg(target_os = "macos")]
const LOCKDOWN_BANNER: &str = "seatbelt profile active";
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
const LOCKDOWN_BANNER: &str = "no sandbox on this platform";

/// Multi-process mode must actually spawn *processes* — and this is the only
/// test that checks it.
///
/// It used to be Linux-only, asserting the seccomp banner. That left a hole
/// everywhere else: on a platform with no shared memory, multi-process and
/// single-process runs produce byte-identical output ("via message copy"), so
/// a silent degradation to threads would pass every other test in this file.
/// Windows exposed that — all four of its tests passed without anything
/// confirming a child had been spawned.
///
/// The negative half matters as much as the positive one: asserting the banner
/// is *absent* from a single-process run is what proves the banner distinguishes
/// the two modes, rather than being something the engine prints regardless.
#[cfg(feature = "multi-process")]
#[test]
fn multi_process_spawns_real_children() {
    let out = run(&[]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains(LOCKDOWN_BANNER),
        "no child announced its lockdown ({LOCKDOWN_BANNER:?}) — did multi-process \
         mode silently run its components as threads?\n{stderr}"
    );

    let out = run(&["--single-process"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains(LOCKDOWN_BANNER),
        "single-process mode announced a lockdown ({LOCKDOWN_BANNER:?}), so this \
         banner does not distinguish the two modes and the check above proves \
         nothing:\n{stderr}"
    );
}

/// Seatbelt must *enforce*, not just install.
///
/// Unlike seccomp, a Seatbelt denial is not fatal — the call returns `EPERM`
/// and the process continues — so these probes cannot be judged from a signal.
/// Each performs its operation before and after `sandbox_init` and reports the
/// transition through an exit code; the codes below are what those mean.
#[cfg(all(feature = "multi-process", target_os = "macos"))]
mod seatbelt_enforcement {
    use super::bin;
    use std::process::Command;

    /// Mirrors `selftest::code`.
    const CONTROL_FAILED: i32 = 90;
    const NOT_DENIED: i32 = 91;
    const WRONG_ERROR: i32 = 92;
    const WRONG_VALUE: i32 = 93;

    fn probe(name: &str) -> i32 {
        let st = Command::new(bin()).args(["selftest", name]).status().expect("spawn selftest");
        st.code().unwrap_or_else(|| panic!("{name}: killed by a signal, expected an exit code"))
    }

    /// Turn a probe's exit code into a message that says which half failed —
    /// "the sandbox let it through" and "it never worked anyway" are very
    /// different bugs and a bare assertion cannot tell them apart.
    fn check(name: &str) {
        match probe(name) {
            0 => {}
            CONTROL_FAILED => panic!(
                "{name}: the operation already failed BEFORE lockdown, so this proves \
                 nothing about the profile — the control is broken, not the sandbox"
            ),
            NOT_DENIED => panic!("{name}: the operation SUCCEEDED under the profile — not enforcing"),
            WRONG_ERROR => panic!("{name}: denied, but not with EPERM — something else refused it"),
            WRONG_VALUE => panic!("{name}: the cap was applied but did not take the expected value"),
            other => panic!("{name}: unexpected exit {other}"),
        }
    }

    /// A renderer has no filesystem — `(deny default)` withholding `file-read*`
    /// is the SBPL counterpart of `openat` being off the seccomp list.
    #[test]
    fn renderer_cannot_open_files() {
        check("seatbelt-file");
    }

    /// A renderer has no network. On Linux that is an empty netns plus missing
    /// socket syscalls; here it is the profile omitting `network-outbound`, so
    /// it needs its own test rather than inheriting the Linux one's assurance.
    #[test]
    fn renderer_cannot_reach_the_network() {
        check("seatbelt-network");
    }

    /// No new programs, the analogue of `execve`/`clone` being off the list.
    #[test]
    fn renderer_cannot_spawn_programs() {
        check("seatbelt-exec");
    }

    /// The control for the test above it: the net component's profile *does*
    /// grant outbound access. Without this, "the renderer cannot reach the
    /// network" would be equally satisfied by a machine with no network.
    #[test]
    fn net_component_keeps_its_network() {
        check("seatbelt-net-role-keeps-network");
    }

    /// The control for every denial in this module: ordinary work must still
    /// run under the profile. A profile so tight the renderer cannot function
    /// would satisfy every negative test above and ship a broken component.
    #[test]
    fn ordinary_work_survives_the_profile() {
        check("seatbelt-baseline");
    }

    /// `file-read*` and `file-write*` are separate SBPL operations — denying
    /// reads does not imply denying writes.
    #[test]
    fn renderer_cannot_write_files() {
        check("seatbelt-file-write");
    }

    /// `process-fork` is distinct from `process-exec`: forking without exec is
    /// still process creation.
    #[test]
    fn renderer_cannot_fork() {
        check("seatbelt-fork");
    }

    /// Tests the profile's *precision*, not merely that one exists. The grant
    /// is `(allow signal (target self))`; if that scope were widened or lost,
    /// every other test here would still pass and only this one would notice.
    #[test]
    fn renderer_cannot_signal_other_processes() {
        check("seatbelt-signal-other");
    }

    /// The backend docs claim the profile grants no `sysctl-read`. Nothing
    /// checked that until now; sysctls leak host details useful for
    /// fingerprinting and exploit tuning.
    #[test]
    fn renderer_cannot_read_sysctls() {
        check("seatbelt-sysctl");
    }

    /// The rlimits are a mechanism wholly separate from Seatbelt, and were
    /// entirely unverified on macOS.
    #[test]
    fn child_rlimits_are_applied() {
        check("rlimits");
    }

    /// Verifies the kernel *accepts* `PT_DENY_ATTACH` — deliberately weaker
    /// than the Linux `children_refuse_debugger_attach`, which proves an attach
    /// is actually refused.
    ///
    /// That stronger test is unavailable here: an unprivileged macOS process
    /// cannot `PT_ATTACH` even to its own child without SIP disabled or
    /// task-port entitlements, so the control fails and the probe proves
    /// nothing. The first version did exactly that and CI reported
    /// CONTROL_FAILED — the right answer, but not a usable test. What remains
    /// still catches the call being rejected outright, which matters because
    /// `deny_debugger_attach` only warns on failure.
    #[test]
    fn ptrace_deny_attach_is_accepted() {
        check("ptrace-deny-accepted");
    }
}

/// Guards the enforcement suite against silently shrinking.
///
/// Every test below this point is `cfg`'d to Linux, so on another platform
/// they do not fail — they cease to exist, and the run still reports success.
/// That is not a hypothetical: the Windows port compiled out 13 of these 16
/// tests and `cargo test` was green. A green suite that tests nothing is worse
/// than a red one.
///
/// So the binary reports which probes it actually has, and this asserts that
/// inventory against a per-platform expectation. Adding a probe fails here
/// until the list is updated (which is the prompt to also add a test for it);
/// losing one to a `cfg` fails here too. A platform whose expected set is
/// empty is making an explicit, reviewable claim: *nothing about this
/// platform's sandbox is verified.*
#[cfg(feature = "multi-process")]
mod probe_inventory {
    use super::bin;
    use std::process::Command;

    /// What this platform is expected to verify. Keep in sync with
    /// `selftest::PROBES` — that is the point of the test.
    #[cfg(target_os = "linux")]
    const EXPECTED: &[&str] = &[
        "baseline",
        "mprotect-exec",
        "socket",
        "memfd-seal",
        "fcntl-dupfd",
        "ring",
        "netns",
        "no-ptrace",
        "forkserver-can-fork",
        "forkserver-canary-gap",
        "forkserver-no-exec",
        "forkserver-no-socket",
    ];

    /// The Seatbelt profile's enforcement. `PT_DENY_ATTACH` and the rlimits
    /// are still unprobed — the list says so rather than implying coverage.
    #[cfg(target_os = "macos")]
    const EXPECTED: &[&str] = &[
        "seatbelt-file",
        "seatbelt-network",
        "seatbelt-exec",
        "seatbelt-net-role-keeps-network",
        "seatbelt-baseline",
        "seatbelt-file-write",
        "seatbelt-fork",
        "seatbelt-signal-other",
        "seatbelt-sysctl",
        "rlimits",
        "ptrace-deny-accepted",
    ];

    /// Windows has no sandbox backend at all yet: children run unconfined
    /// under `sandbox::unsupported`. Nothing to probe until a measure lands —
    /// and when one does, this list is what forces a probe to land with it.
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    const EXPECTED: &[&str] = &[];

    #[test]
    fn compiled_probes_match_this_platform() {
        let out = Command::new(bin()).args(["selftest", "list"]).output().expect("spawn selftest");
        assert!(out.status.success(), "selftest list failed: {out:?}");
        let got: Vec<String> =
            String::from_utf8_lossy(&out.stdout).lines().map(|l| l.trim().to_string()).collect();
        assert_eq!(
            got,
            EXPECTED,
            "sandbox probe inventory changed.\n\
             If you added a measure, add a probe AND a test for it, then update EXPECTED.\n\
             If a probe vanished, a `cfg` is hiding it — that is the bug this test exists to catch."
        );
    }
}

/// The sandbox must *enforce*, not just announce. These run the `selftest`
/// probes in a child that applies the renderer lockdown and then attempts one
/// operation; a forbidden op is killed by `SIGSYS`, an allowed one exits clean.
#[cfg(all(feature = "multi-process", target_os = "linux"))]
mod sandbox_enforcement {
    use super::bin;
    use std::os::unix::process::ExitStatusExt;
    use std::process::Command;

    /// `SIGSYS` — the signal seccomp `KillProcess` terminates with.
    const SIGSYS: i32 = 31;

    fn probe(name: &str) -> std::process::ExitStatus {
        Command::new(bin()).args(["selftest", name]).status().expect("spawn selftest")
    }

    #[test]
    fn baseline_program_survives_the_sandbox() {
        // Sanity: normal work isn't killed, so a kill below means the op, not
        // the lockdown itself, was the cause.
        let st = probe("baseline");
        assert!(st.success(), "baseline should exit cleanly, got {st:?}");
    }

    #[test]
    fn making_memory_executable_is_killed() {
        let st = probe("mprotect-exec");
        assert_eq!(st.signal(), Some(SIGSYS), "expected SIGSYS (W^X), got {st:?}");
        assert!(st.code().is_none(), "should be killed, not exit");
    }

    #[test]
    fn opening_a_socket_is_killed() {
        let st = probe("socket");
        assert_eq!(st.signal(), Some(SIGSYS), "expected SIGSYS (no network), got {st:?}");
    }

    /// The inbound direction: other software running as the same user must not
    /// be able to `ptrace`-attach or read `/proc/<pid>/mem`. Guards the
    /// placement as much as the call — the dumpable flag does not survive
    /// `execve`, so setting it pre-exec would leave this silently at 1.
    #[test]
    fn children_refuse_debugger_attach() {
        let st = probe("no-ptrace");
        assert!(st.success(), "expected a non-dumpable process, got {st:?}");
    }

    /// Defense in depth beneath the allowlist: even if `socket()` were somehow
    /// reachable, the renderer's network namespace has nothing in it. This
    /// probe unshares and then enumerates interfaces, so it fails loudly if the
    /// namespace was never actually created.
    #[test]
    fn renderer_network_namespace_is_empty() {
        let st = probe("netns");
        assert!(st.success(), "expected an empty netns, got {st:?}");
    }

    /// The fork server's filter is inherited by every renderer it forks, so a
    /// gap in it kills *renderers*, not the fork server — and surfaces as
    /// `TabCrashed`, looking nothing like a sandbox problem. This is the
    /// positive case guarding that: forking, reaping, and the
    /// `fcntl(F_DUPFD_CLOEXEC)` a forked child needs to split its endpoint
    /// before its own lockdown must all survive.
    #[test]
    fn fork_server_can_still_fork_and_reap() {
        let st = probe("forkserver-can-fork");
        assert!(st.success(), "the zygote cannot do its job under its filter: {st:?}");
    }

    /// The canary has to *detect*, not just pass. This runs it against a filter
    /// missing `set_robust_list` — one of the three syscalls that really were
    /// absent when this filter was written — and requires it to abort. A canary
    /// that only ever succeeds is indistinguishable from no canary.
    #[test]
    fn startup_canary_detects_a_missing_syscall() {
        let st = probe("forkserver-canary-gap");
        assert_eq!(st.code(), Some(1), "canary should abort with exit 1, got {st:?}");
    }

    #[test]
    fn fork_server_cannot_exec() {
        let st = probe("forkserver-no-exec");
        assert_eq!(st.signal(), Some(SIGSYS), "expected SIGSYS (no exec), got {st:?}");
    }

    #[test]
    fn fork_server_cannot_open_a_socket() {
        let st = probe("forkserver-no-socket");
        assert_eq!(st.signal(), Some(SIGSYS), "expected SIGSYS (no network), got {st:?}");
    }

    #[test]
    fn sealed_memfd_tile_survives_the_sandbox() {
        // The shared-memory tile producer path (memfd_create → ftruncate →
        // mmap → seal) is exactly what a confined renderer does per frame.
        let st = probe("memfd-seal");
        assert!(st.success(), "sealed-tile creation should survive the sandbox, got {st:?}");
    }

    #[test]
    fn fcntl_outside_the_seal_commands_is_killed() {
        // fcntl is argument-filtered to F_ADD_SEALS/F_GET_SEALS; anything
        // else (here F_DUPFD) must be fatal.
        let st = probe("fcntl-dupfd");
        assert_eq!(st.signal(), Some(SIGSYS), "expected SIGSYS (fcntl filter), got {st:?}");
    }

    #[test]
    fn ring_buffer_survives_the_sandbox() {
        // The ring produce+consume dance (memfd + size seals, RW mapping,
        // cursor atomics) is how a confined renderer receives large bodies.
        let st = probe("ring");
        assert!(st.success(), "ring transport should survive the sandbox, got {st:?}");
    }
}
