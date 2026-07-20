//! The fork server (Firefox's name; Chromium/Android call it the *zygote*).
//! A minimal process that renderers are `fork()`ed from **without exec**, so a
//! new renderer inherits an already-initialized runtime copy-on-write instead
//! of paying full process startup each time.
//!
//! Why a separate process rather than forking renderers from the engine:
//! - The engine is **multithreaded** (event loop + one reader thread per
//!   child). `fork()` in a multithreaded process only carries the calling
//!   thread; a lock another thread held stays locked forever in the child →
//!   deadlock. The fork server is deliberately **single-threaded**.
//! - The engine holds **secrets** (the cookie jar). A child forked from it
//!   would inherit them. The fork server holds none.
//!
//! So this is the reconciliation: keep one pristine, single-threaded,
//! secret-free process around specifically to fork from.
//!
//! Flow: the engine creates the renderer's `socketpair`, keeps one end, and
//! sends the other to the fork server over the control channel via
//! `SCM_RIGHTS` fd-passing. The fork server `fork()`s; the child adopts that
//! fd, drops privileges (seccomp + inherited rlimits), and serves.
//!
//! Simplifications vs. a real fork server: it is `exec`'d fresh here (one
//! exec at startup) rather than forked from the engine early to inherit the
//! *engine's* warm libraries — but the load-bearing behavior, renderers
//! fork-without-exec from a warm process, is modeled. It is left unsandboxed
//! (minimal and trusted, holds no secrets); each forked child sandboxes
//! itself. Linux only — `fork()`-without-exec plus the Rust runtime is only
//! sound with `fork()` semantics, and it pairs with the Linux seccomp story.

use crate::ipc::{self, Endpoint, ForkRequest};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;

/// Entry point for the `fork-server` role. `control_fd` is the inherited end
/// of the engine↔fork-server socketpair.
pub fn run(control_fd: &str) {
    let control_fd: RawFd = control_fd.parse().expect("fork-server: bad control fd");
    // SAFETY: the engine passed us sole ownership of this inherited fd.
    let mut control = unsafe { UnixStream::from_raw_fd(control_fd) };

    // Confine ourselves before touching the control channel — from here the
    // fork server can fork, reap, and move bytes on fds it already holds, and
    // nothing else: no sockets, no file opens, no exec. It was previously left
    // unconfined on the grounds of being minimal and secret-free, but "minimal"
    // is not "harmless": this process holds `fork()` and the fd-passing path,
    // which is a useful primitive to land on.
    //
    // Also clears the dumpable flag (it does not survive `execve`, so it could
    // not have been set pre-exec) — and *that* is inherited by every renderer
    // forked below, covering the window before each reaches its own lockdown.
    crate::sandbox::lock_down_fork_server();

    loop {
        let req: ForkRequest = match ipc::recv_msg(&mut control) {
            Ok(req) => req,
            Err(_) => break, // engine went away
        };
        match req {
            ForkRequest::Shutdown => break,
            ForkRequest::Renderer { origin } => {
                // The renderer's IPC fd arrives right after the request.
                // SAFETY: the control stream is a valid open descriptor.
                let comp_fd = match unsafe { ipc::recv_fd(control.as_raw_fd()) } {
                    Ok(fd) => fd,
                    Err(_) => break,
                };
                fork_renderer(control.as_raw_fd(), comp_fd, origin);
            }
        }
    }

    // Reap every renderer we forked before exiting, so none is left orphaned.
    while unsafe { libc::waitpid(-1, std::ptr::null_mut(), 0) } > 0 {}
}

fn fork_renderer(control_fd: RawFd, comp_fd: OwnedFd, origin: String) {
    // SAFETY: we are single-threaded, so the child may run normal code (the
    // async-signal-safe-only rule applies to *multithreaded* fork).
    match unsafe { libc::fork() } {
        -1 => {
            eprintln!("[fork-server] fork failed: {}", std::io::Error::last_os_error());
            // comp_fd drops (closes) here.
        }
        0 => {
            // Child — this IS the renderer now. It inherited the fork server's
            // warm runtime via copy-on-write; no exec, no re-init.
            unsafe { libc::close(control_fd) }; // never touch the engine's control channel
            let ch = crate::channel::Channel::from_stream(UnixStream::from(comp_fd));
            let ep = Endpoint::from_channel(ch).expect("fork-server child: wrap fd");
            // Drop privileges, then serve. rlimits were inherited from the
            // fork server; seccomp is per-process, applied here.
            crate::sandbox::lock_down_renderer();
            crate::renderer::serve(ep, &origin);
            std::process::exit(0); // must not fall back into the fork-server loop
        }
        _pid => {
            // Parent (fork server): drop our copy of the renderer's end so the
            // engine sees EOF (→ TabCrashed) when the renderer dies.
            drop(comp_fd);
        }
    }
}
