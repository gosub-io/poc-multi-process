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

/// The same lifecycle must work with components as threads.
#[test]
fn single_process_run_renders_and_shuts_down() {
    let out = run(&["--single-process"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "exit {:?}\nstdout: {stdout}", out.status);
    assert!(stdout.contains("frame ready") && stdout.contains("engine shut down"), "{stdout}");
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
}
