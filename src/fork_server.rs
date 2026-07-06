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
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::UnixStream;

/// Entry point for the `fork-server` role. `control_fd` is the inherited end
/// of the engine↔fork-server socketpair.
pub fn run(control_fd: &str) {
    let control_fd: RawFd = control_fd.parse().expect("fork-server: bad control fd");
    // SAFETY: the engine passed us sole ownership of this inherited fd.
    let mut control = unsafe { UnixStream::from_raw_fd(control_fd) };

    loop {
        let req: ForkRequest = match ipc::recv_msg(&mut control) {
            Ok(req) => req,
            Err(_) => break, // engine went away
        };
        match req {
            ForkRequest::Shutdown => break,
            ForkRequest::Renderer { origin } => {
                // The renderer's IPC fd arrives right after the request.
                let comp_fd = match unsafe { recv_fd(control.as_raw_fd()) } {
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

fn fork_renderer(control_fd: RawFd, comp_fd: RawFd, origin: String) {
    // SAFETY: we are single-threaded, so the child may run normal code (the
    // async-signal-safe-only rule applies to *multithreaded* fork).
    match unsafe { libc::fork() } {
        -1 => {
            eprintln!("[fork-server] fork failed: {}", std::io::Error::last_os_error());
            unsafe { libc::close(comp_fd) };
        }
        0 => {
            // Child — this IS the renderer now. It inherited the fork server's
            // warm runtime via copy-on-write; no exec, no re-init.
            unsafe { libc::close(control_fd) }; // never touch the engine's control channel
            let stream = unsafe { UnixStream::from_raw_fd(comp_fd) };
            let ep = Endpoint::from_stream(stream).expect("fork-server child: wrap fd");
            // Drop privileges, then serve. rlimits were inherited from the
            // fork server; seccomp is per-process, applied here.
            crate::sandbox::lock_down_renderer();
            crate::renderer::serve(ep, &origin);
            std::process::exit(0); // must not fall back into the fork-server loop
        }
        _pid => {
            // Parent (fork server): drop our copy of the renderer's end so the
            // engine sees EOF (→ TabCrashed) when the renderer dies.
            unsafe { libc::close(comp_fd) };
        }
    }
}

/// Send one file descriptor over a Unix socket via `SCM_RIGHTS`, with a 1-byte
/// dummy payload (fd-passing must carry at least one data byte).
///
/// SAFETY: `sock_fd` and `fd` must be valid open descriptors.
pub unsafe fn send_fd(sock_fd: RawFd, fd: RawFd) -> std::io::Result<()> {
    let mut byte = [0u8; 1];
    let mut iov = libc::iovec { iov_base: byte.as_mut_ptr().cast(), iov_len: 1 };
    let mut cmsg = [0u8; 32]; // > CMSG_SPACE(size_of::<RawFd>())

    let mut msg: libc::msghdr = std::mem::zeroed();
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg.as_mut_ptr().cast();
    msg.msg_controllen = libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) as _;

    let cmsgp = libc::CMSG_FIRSTHDR(&msg);
    (*cmsgp).cmsg_level = libc::SOL_SOCKET;
    (*cmsgp).cmsg_type = libc::SCM_RIGHTS;
    (*cmsgp).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as _;
    std::ptr::copy_nonoverlapping(&fd, libc::CMSG_DATA(cmsgp).cast::<RawFd>(), 1);

    if libc::sendmsg(sock_fd, &msg, 0) < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Receive one file descriptor sent via [`send_fd`].
///
/// SAFETY: `sock_fd` must be a valid open descriptor.
unsafe fn recv_fd(sock_fd: RawFd) -> std::io::Result<RawFd> {
    let mut byte = [0u8; 1];
    let mut iov = libc::iovec { iov_base: byte.as_mut_ptr().cast(), iov_len: 1 };
    let mut cmsg = [0u8; 32];

    let mut msg: libc::msghdr = std::mem::zeroed();
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg.as_mut_ptr().cast();
    msg.msg_controllen = cmsg.len() as _;

    let n = libc::recvmsg(sock_fd, &mut msg, 0);
    if n <= 0 {
        return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "no fd received"));
    }
    let cmsgp = libc::CMSG_FIRSTHDR(&msg);
    if cmsgp.is_null()
        || (*cmsgp).cmsg_type != libc::SCM_RIGHTS
        || (*cmsgp).cmsg_level != libc::SOL_SOCKET
    {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "no SCM_RIGHTS cmsg"));
    }
    let mut fd: RawFd = -1;
    std::ptr::copy_nonoverlapping(libc::CMSG_DATA(cmsgp).cast::<RawFd>(), &mut fd, 1);
    Ok(fd)
}
