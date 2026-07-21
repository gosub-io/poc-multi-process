//! Unix spawn backend: `fork` + `exec` via `std::process::Command`.
//!
//! Everything privilege-related happens in `pre_exec`, i.e. in the forked child
//! before it becomes the new program: resource ceilings, the network namespace,
//! and clearing `FD_CLOEXEC` on exactly the one descriptor the child should
//! inherit. Doing the last of those in the child rather than the parent is what
//! keeps the descriptor out of every *other* concurrent spawn.

use std::io;

/// A spawned child process.
pub struct Child(std::process::Child);

impl Child {
    /// Wait for the child to exit, discarding its status.
    pub fn wait(&mut self) -> io::Result<()> {
        self.0.wait().map(|_| ())
    }
}

/// Spawn `exe` with `args`, handing `child_end` over as an inherited channel.
///
/// `isolate_network` additionally drops the child into an empty network
/// namespace where the platform supports one.
pub fn spawn(
    exe: &std::path::Path,
    args: &[&str],
    child_end: crate::channel::Channel,
    isolate_network: bool,
) -> io::Result<Child> {
    use std::os::unix::process::CommandExt;

    let mut cmd = std::process::Command::new(exe);
    cmd.args(args).arg(child_end.to_argv());

    // Strip the dynamic-loader injection vectors from the child's environment
    // before it execs: DYLD_INSERT_LIBRARIES (macOS) and LD_PRELOAD/LD_* (glibc)
    // are the runtime linker's "load this code into every new process" knobs. A
    // child inheriting one would run attacker-supplied library code *before* it
    // reaches its own lockdown, sidestepping the sandbox entirely.
    for (key, _) in std::env::vars_os() {
        if key.to_str().is_some_and(|k| k.starts_with("DYLD_") || k.starts_with("LD_")) {
            cmd.env_remove(&key);
        }
    }

    let raw = child_end.raw();
    // SAFETY: the closure runs post-fork/pre-exec and calls only
    // async-signal-safe operations (setrlimit, setpriority, unshare, fcntl).
    unsafe {
        cmd.pre_exec(move || {
            crate::sandbox::apply_child_rlimits()?;
            // Fail-closed, matching the seccomp precedent: a child that was
            // meant to be network-isolated and silently isn't is worse than an
            // honest refusal to start.
            crate::sandbox::isolate_network(isolate_network)?;
            crate::channel::Channel::make_inheritable(raw)?;
            Ok(())
        });
    }

    let child = cmd.spawn()?;
    // The child holds its own copy now; drop ours so a dead child is seen as
    // EOF rather than a link the engine is itself holding open.
    drop(child_end);
    Ok(Child(child))
}
