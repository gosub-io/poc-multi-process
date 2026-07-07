//! Sandbox self-tests, spawned by the integration suite (never by the demo).
//!
//! Each probe applies the renderer lockdown and then attempts one operation,
//! letting the test harness observe the outcome from the *outside*: a forbidden
//! syscall is a fatal `SIGSYS` (seccomp `KillProcess`), while an allowed program
//! exits cleanly. We can't assert this from inside a `#[cfg(test)]` unit test
//! because the filter is irreversible and would kill the test runner itself —
//! so enforcement is checked here, in a throwaway child process.

/// Entry point for the `selftest <probe>` role.
pub fn run(probe: &str) {
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

        other => {
            eprintln!("unknown selftest probe: {other}");
            std::process::exit(2);
        }
    }
}
