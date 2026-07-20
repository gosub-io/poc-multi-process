//! Integration tests: run the *actual built binary* end to end, so they
//! exercise the real process spawning, IPC, sandbox and shutdown — the parts a
//! single-process unit test can't reach. Pure logic (SSRF, cookie policy, IPC
//! framing, the backpressure gate, origin parsing) is unit-tested in `src/`.

use std::process::{Command, Output};

/// Path to the compiled PoC binary, provided by Cargo to integration tests.
fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_gosub-proc-iso-poc")
}

fn run(args: &[&str]) -> Output {
    Command::new(bin()).args(args).output().expect("spawn poc binary")
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

/// In multi-process mode on Linux the children announce their seccomp sandbox.
#[cfg(all(feature = "multi-process", target_os = "linux"))]
#[test]
fn multi_process_children_are_sandboxed() {
    let out = run(&[]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("seccomp allowlist active"), "children not sandboxed:\n{stderr}");
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
