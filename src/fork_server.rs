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

    // Pin PID 1 of the renderers' shared PID namespace *before* forking anything
    // else, so a renderer's death never tears the namespace down (see
    // `fork_pinned_init`). Must come first: the first child forked into a fresh
    // PID namespace becomes PID 1, and we want that to be the placeholder, not the
    // verification canary below (which exits) or a renderer.
    fork_pinned_init();

    // Then prove the filter is right for *this* host's C library before any
    // renderer stakes its life on it. The allowlist depends on how libc issues
    // fork and how it splits descriptors, which varies by glibc version and
    // differs again on musl — none of it visible at compile time, since the
    // libc we build against is not the one we run against. Failing here costs
    // one fork; failing later looks like every tab crashing on open.
    crate::sandbox::verify_fork_server_filter();

    // Loop ends when `recv_msg` errors (engine went away) or on `Shutdown`.
    while let Ok(req) = ipc::recv_msg::<ForkRequest>(&mut control) {
        match req {
            ForkRequest::Shutdown => break,
            ForkRequest::Renderer { origin } => {
                // The renderer's IPC fd arrives right after the request.
                // SAFETY: the control stream is a valid open descriptor.
                let comp_fd = match unsafe { ipc::recv_fd(control.as_raw_fd()) } {
                    Ok(fd) => fd,
                    Err(_) => break,
                };
                fork_child(control.as_raw_fd(), comp_fd, Child::Renderer(origin));
            }
            ForkRequest::Decoder => {
                // SAFETY: the control stream is a valid open descriptor.
                let comp_fd = match unsafe { ipc::recv_fd(control.as_raw_fd()) } {
                    Ok(fd) => fd,
                    Err(_) => break,
                };
                fork_child(control.as_raw_fd(), comp_fd, Child::Decoder);
            }
        }
    }

    // Reap any content processes that have already exited, without blocking:
    // the pinned init (PID 1 of the renderers' namespace, where one exists) does
    // not exit on its own — it dies with us via `PR_SET_PDEATHSIG`, and *that*
    // tears the namespace down and `SIGKILL`s any renderer still in it, which the
    // subreaper then collects. A blocking `waitpid(-1)` here would instead hang
    // forever waiting on that pinned init.
    while unsafe { libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG) } > 0 {}
}

/// Fork the pinned "init" for the renderers' shared PID namespace.
///
/// When [`crate::sandbox::isolate_network`] created a PID namespace for the fork
/// server, every child it forks lands in that namespace and the *first* becomes
/// PID 1 — and a PID namespace is destroyed, `SIGKILL`ing all its members, the
/// moment its PID 1 exits. If a renderer were PID 1, closing its tab would kill
/// every other renderer. So we fork one placeholder first, as PID 1, that does
/// nothing but stay alive; real renderers are then PID 2+, and any of them
/// exiting leaves the namespace (and its siblings) intact. The placeholder dies
/// with the fork server via `PR_SET_PDEATHSIG`, which tears the namespace down and
/// takes any survivors with it.
///
/// A no-op where no PID namespace was created (best-effort `unshare` fell back, or
/// the build lacks it): the placeholder sees a normal pid rather than 1 and exits
/// immediately, so nothing is pinned and nothing leaks.
fn fork_pinned_init() {
    // SAFETY: the fork server is single-threaded, so the child may run normal
    // code; it touches only allowlisted syscalls (getpid, prctl, nanosleep).
    match unsafe { libc::fork() } {
        -1 => eprintln!(
            "[fork-server] could not fork the pid-ns init ({}); renderers share the namespace unpinned",
            std::io::Error::last_os_error()
        ),
        0 => {
            // Child. Ask the kernel via the raw syscall (not glibc's possibly
            // cached `getpid`) whether we are PID 1 of a fresh namespace.
            let pid = unsafe { libc::syscall(libc::SYS_getpid) };
            if pid != 1 {
                // No PID namespace here — nothing to pin.
                unsafe { libc::_exit(0) };
            }
            // Die when the fork server dies (graceful exit or crash); that death
            // is what tears the namespace down and reaps the renderers.
            unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) };
            // Stay alive as PID 1, doing nothing. Long sleeps in a loop; every
            // wake (a stray signal, or the timer) just sleeps again.
            loop {
                let req = libc::timespec { tv_sec: 1 << 20, tv_nsec: 0 };
                unsafe { libc::nanosleep(&req, std::ptr::null_mut()) };
            }
        }
        _ => { /* fork server continues; the init is collected at teardown */ }
    }
}

/// What a forked child becomes. Both are content processes forked the same
/// way and confined the same way; only the serve loop differs — a renderer is
/// long-lived and per-origin, a decoder handles one image and exits.
enum Child {
    Renderer(String),
    Decoder,
}

fn fork_child(control_fd: RawFd, comp_fd: OwnedFd, kind: Child) {
    // SAFETY: we are single-threaded, so the child may run normal code (the
    // async-signal-safe-only rule applies to *multithreaded* fork).
    match unsafe { libc::fork() } {
        -1 => {
            eprintln!("[fork-server] fork failed: {}", std::io::Error::last_os_error());
            // comp_fd drops (closes) here.
        }
        0 => {
            // Child — this IS the content process now. It inherited the fork
            // server's warm runtime via copy-on-write; no exec, no re-init.
            if std::env::var_os("GOSUB_DEBUG_PIDNS").is_some() {
                // Raw getpid: a small pid (2+, since the pinned init is 1) means
                // we are in the renderers' PID namespace; a large host pid means
                // none was created (best-effort fell back).
                let pid = unsafe { libc::syscall(libc::SYS_getpid) };
                eprintln!("[fork-server child] ns-local pid = {pid}");
            }
            unsafe { libc::close(control_fd) }; // never touch the engine's control channel
            let ch = crate::channel::Channel::from_stream(UnixStream::from(comp_fd));
            let ep = Endpoint::from_channel(ch).expect("fork-server child: wrap fd");
            // Drop privileges, then serve. rlimits were inherited from the fork
            // server; seccomp is per-process, applied here. A decoder is a
            // content process just like a renderer, so it shares the lockdown.
            crate::sandbox::lock_down_renderer();
            match kind {
                Child::Renderer(origin) => crate::renderer::serve(ep, &origin),
                Child::Decoder => crate::decoder::serve_one(ep),
            }
            std::process::exit(0); // must not fall back into the fork-server loop
        }
        _pid => {
            // Parent (fork server): drop our copy of the child's end so the
            // engine sees EOF when the child dies (a decoder always exits after
            // one image; a renderer only on crash).
            drop(comp_fd);
        }
    }
}
