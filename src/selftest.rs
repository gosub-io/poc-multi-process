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

        crate::sandbox::unshare_network().expect("unshare netns");

        // The namespace must actually have changed, and the new one must hold
        // nothing but loopback: no route off this machine exists at all.
        let after = std::fs::read_link("/proc/self/ns/net").expect("read netns link");
        assert_ne!(before, after, "still in the host network namespace");
        assert_eq!(interfaces(), vec!["lo".to_string()], "netns is not empty");
        std::process::exit(0);
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
