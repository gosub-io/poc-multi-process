//! Length-framed bincode messaging, per gosub-engine issue #1080: every frame
//! is a little-endian u32 payload length followed by the bincode-encoded
//! message.
//!
//! The [`Endpoint`] abstraction carries the same frames over two transports:
//! Unix domain sockets (multi-process mode) or in-process channels
//! (single-process mode), so components are written once against `Endpoint`
//! and run unchanged in either mode. An `Endpoint` can be [`split`] into its
//! send/receive halves so the engine's event loop can hand the receive half
//! to a reader thread while keeping the send half for replies.
//!
//! [`split`]: Endpoint::split

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::io;
#[cfg(feature = "multi-process")]
use std::io::{Read, Write};
// fd passing is `SCM_RIGHTS`-specific and only the Linux shared-memory paths
// (sealed tiles, the body ring, the fork server) use it — macOS and Windows
// multi-process never send a descriptor, so this stays Linux-gated.
#[cfg(all(feature = "multi-process", target_os = "linux"))]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
#[cfg(feature = "multi-process")]
use crate::channel;
use std::sync::mpsc::{self, Receiver, Sender};

/// A corrupted (or malicious) length prefix must not make the peer allocate
/// unbounded memory.
pub const MAX_FRAME_LEN: u32 = 16 * 1024 * 1024;

/// Engine -> fork server (Linux). The engine asks the fork server to `fork()`
/// a renderer for `origin`; the renderer's IPC fd is passed alongside this
/// message via `SCM_RIGHTS` (see `fork_server`).
#[cfg(all(feature = "multi-process", target_os = "linux"))]
#[derive(Serialize, Deserialize, Debug)]
pub enum ForkRequest {
    Renderer { origin: String },
    /// Fork a throwaway decoder. Its IPC fd follows via `SCM_RIGHTS`, exactly
    /// like a renderer's; the difference is entirely in what the child does —
    /// decode one image and exit.
    Decoder,
    Shutdown,
}

/// Renderer -> engine.
#[derive(Serialize, Deserialize, Debug)]
pub enum FromRenderer {
    /// Renderers have no network access; they must ask the engine, which
    /// brokers the request to the net component (Phase 1).
    NeedFetch { url: String },
    /// Renderers hold no cookie jar (Phase 2). The engine enforces
    /// same-origin using the *endpoint identity*, never this field.
    NeedCookies { origin: String },
    /// The final product of a `RenderPage` command: a rasterized tile,
    /// copied in-band through the message itself.
    Tile { width: u32, height: u32, pixels: Vec<u8> },
    /// The same product via shared memory (Linux): only the dimensions travel
    /// in-band; the sealed memfd holding the pixels follows immediately as an
    /// `SCM_RIGHTS` fd (see `shm`). The dimensions are a *claim* — the engine
    /// validates the received fd's seals and real size against them.
    #[cfg(all(feature = "multi-process", target_os = "linux"))]
    TileShm { width: u32, height: u32 },
    /// Renderers do not parse images themselves — that is the most dangerous
    /// input a browser handles, so it is brokered to a throwaway decoder
    /// process (see `decoder`). The bytes are the encoded image; the reply is a
    /// [`ToRenderer::DecodeResult`].
    NeedDecode { image: Vec<u8> },
}

/// Engine -> renderer.
#[derive(Serialize, Deserialize, Debug)]
pub enum ToRenderer {
    RenderPage { url: String },
    FetchResult { status: u16, body: Vec<u8> },
    /// The outcome of a [`FromRenderer::NeedDecode`]: the decoded pixels, or the
    /// reason the (ephemeral) decoder refused or died. A decoder crash is
    /// reported as a failure here, never as a failure of the renderer.
    DecodeResult(DecodeOutcome),
    /// A fetch whose body streams through a shared-memory ring (Linux): the
    /// ring fd follows immediately via `SCM_RIGHTS`. `body_len` is a *claim*
    /// the renderer bounds before allocating; the ring fd itself is validated
    /// by `ring::consume` (size seals, real size).
    #[cfg(all(feature = "multi-process", target_os = "linux"))]
    FetchBodyStream { status: u16, body_len: u64 },
    FetchDenied { reason: String },
    /// `None` means the broker refused to hand the cookies over.
    Cookies(Option<Vec<(String, String)>>),
    Shutdown,
}

/// Engine -> net component. `request_id` lets the engine multiplex fetches
/// for many tabs over one link and route each reply back to its requester.
#[derive(Serialize, Deserialize, Debug)]
pub enum NetRequest {
    Fetch {
        request_id: u64,
        /// The `(zone, origin)` identity, stamped by the *engine* from its own
        /// bookkeeping — a compromised renderer cannot spoof either half.
        for_zone: u64,
        for_origin: String,
        url: String,
        /// The origin's cookies (name, value) for the net component to attach
        /// to the request — *including* HttpOnly ones. These reach the
        /// network process but never the renderer.
        cookies: Vec<(String, String)>,
    },
    Shutdown,
}

/// Net component -> engine.
#[derive(Serialize, Deserialize, Debug)]
pub struct NetResponse {
    pub request_id: u64,
    pub outcome: FetchOutcome,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum FetchOutcome {
    Ok { status: u16, body: Vec<u8> },
    /// The body streams through a shared-memory ring: the ring fd follows
    /// this message via `SCM_RIGHTS`. The engine routes header + fd to the
    /// requesting renderer without ever mapping the ring itself.
    #[cfg(all(feature = "multi-process", target_os = "linux"))]
    OkStreaming { status: u16, body_len: u64 },
    Denied { reason: String },
}

/// Engine -> decoder. A decoder handles exactly one of these and exits.
#[derive(Serialize, Deserialize, Debug)]
pub enum ToDecoder {
    Decode { image: Vec<u8> },
}

/// Decoder -> engine: the result of decoding one image.
#[derive(Serialize, Deserialize, Debug)]
pub enum FromDecoder {
    Decoded { width: u32, height: u32, pixels: Vec<u8> },
    Failed { reason: String },
}

/// The decode outcome as it reaches the renderer — the decoder's own result,
/// plus a synthesized failure for the case where the decoder died before
/// answering (which the engine turns into a `Failed`, so a decoder crash is
/// indistinguishable from a rejection to the renderer).
#[derive(Serialize, Deserialize, Debug)]
pub enum DecodeOutcome {
    Ok { width: u32, height: u32, pixels: Vec<u8> },
    Failed { reason: String },
}

/// Send half of an IPC link.
pub enum EndpointTx {
    #[cfg(feature = "multi-process")]
    Socket(channel::Tx),
    Local(Sender<Vec<u8>>),
}

/// Receive half of an IPC link.
pub enum EndpointRx {
    #[cfg(feature = "multi-process")]
    Socket(channel::Rx),
    Local(Receiver<Vec<u8>>),
}

impl EndpointTx {
    /// Whether this endpoint can carry file descriptors (`SCM_RIGHTS`) — true
    /// for the socket transport, false for in-process channels, where shared
    /// memory would be pointless anyway (same address space). Only the
    /// shared-memory tile path asks (hence the cfg).
    #[cfg(all(feature = "multi-process", target_os = "linux"))]
    pub fn supports_fd_passing(&self) -> bool {
        matches!(self, EndpointTx::Socket(_))
    }

    /// Pass a duplicate of `fd` to the peer. The caller keeps (and should
    /// promptly close) its own copy.
    #[cfg(all(feature = "multi-process", target_os = "linux"))]
    pub fn send_fd(&mut self, fd: RawFd) -> io::Result<()> {
        match self {
            // SAFETY: both descriptors are valid — the stream is live and the
            // caller owns `fd`.
            EndpointTx::Socket(stream) => unsafe { send_fd(stream.as_raw_fd(), fd) },
            EndpointTx::Local(_) => {
                Err(io::Error::new(io::ErrorKind::Unsupported, "no fd passing on local channels"))
            }
        }
    }

    pub fn send<T: Serialize>(&mut self, msg: &T) -> io::Result<()> {
        match self {
            #[cfg(feature = "multi-process")]
            EndpointTx::Socket(stream) => send_msg(stream, msg),
            EndpointTx::Local(tx) => {
                let payload = bincode::serialize(msg)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                if payload.len() > MAX_FRAME_LEN as usize {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "frame too large"));
                }
                tx.send(payload)
                    .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "peer gone"))
            }
        }
    }
}

impl EndpointRx {
    /// Receive a file descriptor the peer announced (e.g. right after a
    /// `TileShm` message). Fails on local channels, which never carry fds.
    #[cfg(all(feature = "multi-process", target_os = "linux"))]
    pub fn recv_fd(&mut self) -> io::Result<OwnedFd> {
        match self {
            // SAFETY: the stream is a valid open descriptor.
            EndpointRx::Socket(stream) => unsafe { recv_fd(stream.as_raw_fd()) },
            EndpointRx::Local(_) => {
                Err(io::Error::new(io::ErrorKind::Unsupported, "no fd passing on local channels"))
            }
        }
    }

    pub fn recv<T: DeserializeOwned>(&mut self) -> io::Result<T> {
        match self {
            #[cfg(feature = "multi-process")]
            EndpointRx::Socket(stream) => recv_msg(stream),
            EndpointRx::Local(rx) => {
                let payload = rx
                    .recv()
                    .map_err(|_| io::Error::new(io::ErrorKind::UnexpectedEof, "peer gone"))?;
                bincode::deserialize(&payload)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
            }
        }
    }
}

/// One end of a duplex IPC link. Components are written against this type
/// only, so the exact same renderer/net code runs either as a child *process*
/// (Socket) or as an in-process *thread* (Local). Both variants carry
/// identical bincode frames, so the protocol — and every policy check built
/// on it — behaves the same in both modes.
pub struct Endpoint {
    pub tx: EndpointTx,
    pub rx: EndpointRx,
}

impl Endpoint {
    /// Wrap a connected transport channel, splitting it into halves that can
    /// be used independently (a reader thread plus the event loop's writer).
    #[cfg(feature = "multi-process")]
    pub fn from_channel(ch: channel::Channel) -> io::Result<Endpoint> {
        let (tx, rx) = ch.split()?;
        Ok(Endpoint { tx: EndpointTx::Socket(tx), rx: EndpointRx::Socket(rx) })
    }

    pub fn send<T: Serialize>(&mut self, msg: &T) -> io::Result<()> {
        self.tx.send(msg)
    }

    pub fn recv<T: DeserializeOwned>(&mut self) -> io::Result<T> {
        self.rx.recv()
    }

    /// Split into independent send/receive halves (e.g. reader thread +
    /// event-loop writer).
    pub fn split(self) -> (EndpointTx, EndpointRx) {
        (self.tx, self.rx)
    }
}

/// A connected pair of in-process endpoints (single-process mode's stand-in
/// for `socketpair(2)`).
pub fn local_pair() -> (Endpoint, Endpoint) {
    let (tx_a, rx_b) = mpsc::channel();
    let (tx_b, rx_a) = mpsc::channel();
    (
        Endpoint { tx: EndpointTx::Local(tx_a), rx: EndpointRx::Local(rx_a) },
        Endpoint { tx: EndpointTx::Local(tx_b), rx: EndpointRx::Local(rx_b) },
    )
}

#[cfg(feature = "multi-process")]
pub fn send_msg<T: Serialize>(w: &mut impl Write, msg: &T) -> io::Result<()> {
    let payload = bincode::serialize(msg)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let len = u32::try_from(payload.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "frame too large"))?;
    if len > MAX_FRAME_LEN {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "frame too large"));
    }
    w.write_all(&len.to_le_bytes())?;
    w.write_all(&payload)?;
    w.flush()
}

#[cfg(feature = "multi-process")]
pub fn recv_msg<T: DeserializeOwned>(r: &mut impl Read) -> io::Result<T> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)?;
    let len = u32::from_le_bytes(len_buf);
    if len > MAX_FRAME_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("refusing {len}-byte frame (corrupt or malicious length prefix)"),
        ));
    }
    let mut payload = vec![0u8; len as usize];
    r.read_exact(&mut payload)?;
    bincode::deserialize(&payload).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Send one file descriptor over a Unix socket via `SCM_RIGHTS`, with a 1-byte
/// dummy payload (fd-passing must carry at least one data byte). The kernel
/// duplicates the fd into the receiver; the sender keeps its own copy.
///
/// SAFETY: `sock_fd` and `fd` must be valid open descriptors.
#[cfg(all(feature = "multi-process", target_os = "linux"))]
pub unsafe fn send_fd(sock_fd: RawFd, fd: RawFd) -> io::Result<()> {
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
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Receive one file descriptor sent via [`send_fd`]. The new fd is created
/// `CLOEXEC` (`MSG_CMSG_CLOEXEC`) and returned owned, so an early return in
/// the caller can never leak it.
///
/// The kernel installs **every** fd the peer attached into this process's fd
/// table before we ever look at the message, so this walks all control
/// messages and wraps every received fd in an `OwnedFd` *first*, then
/// enforces the protocol: exactly one fd. A peer stuffing extra fds into the
/// hand-off (or overflowing the control buffer, `MSG_CTRUNC`) gets a refusal
/// and every received fd closed — without this, each malicious message would
/// leak descriptors into the engine until its fd table is exhausted.
///
/// SAFETY: `sock_fd` must be a valid open descriptor.
#[cfg(all(feature = "multi-process", target_os = "linux"))]
pub unsafe fn recv_fd(sock_fd: RawFd) -> io::Result<OwnedFd> {
    let mut byte = [0u8; 1];
    let mut iov = libc::iovec { iov_base: byte.as_mut_ptr().cast(), iov_len: 1 };
    // Room for several fds on purpose: a smuggling attempt should be *seen*
    // (received, counted, closed) rather than silently truncated.
    let mut cmsg = [0u8; 64];

    let mut msg: libc::msghdr = std::mem::zeroed();
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg.as_mut_ptr().cast();
    msg.msg_controllen = cmsg.len() as _;

    #[cfg(target_os = "linux")]
    let flags = libc::MSG_CMSG_CLOEXEC;
    #[cfg(not(target_os = "linux"))]
    let flags = 0;
    let n = libc::recvmsg(sock_fd, &mut msg, flags);
    if n <= 0 {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "no fd received"));
    }

    // Adopt every fd across every SCM_RIGHTS cmsg (each may carry several)
    // before any verdict, so whatever is rejected below is closed, not leaked.
    let mut fds: Vec<OwnedFd> = Vec::new();
    let mut cmsgp = libc::CMSG_FIRSTHDR(&msg);
    while !cmsgp.is_null() {
        if (*cmsgp).cmsg_level == libc::SOL_SOCKET && (*cmsgp).cmsg_type == libc::SCM_RIGHTS {
            let payload = (*cmsgp).cmsg_len as usize - libc::CMSG_LEN(0) as usize;
            let data = libc::CMSG_DATA(cmsgp).cast::<RawFd>();
            for i in 0..payload / std::mem::size_of::<RawFd>() {
                let mut fd: RawFd = -1;
                std::ptr::copy_nonoverlapping(data.add(i), &mut fd, 1);
                if fd >= 0 {
                    fds.push(OwnedFd::from_raw_fd(fd));
                }
            }
        }
        cmsgp = libc::CMSG_NXTHDR(&msg, cmsgp);
    }

    // Truncated control data = the peer attached more than even the roomy
    // buffer holds; the kernel closed the overflow, we close the rest here.
    if msg.msg_flags & libc::MSG_CTRUNC != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "control data truncated (peer attached too many fds)",
        ));
    }
    if fds.len() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("expected exactly 1 fd in the hand-off, got {}", fds.len()),
        ));
    }
    Ok(fds.pop().expect("checked len"))
}

#[cfg(test)]
mod tests {
    use super::*;
    // The `SCM_RIGHTS` tests below drive a socketpair directly rather than
    // through `channel`, since what they pin down is fd-passing behaviour —
    // Linux-only, like the paths that use it.
    #[cfg(all(feature = "multi-process", target_os = "linux"))]
    use std::os::unix::net::UnixStream;

    #[test]
    fn local_pair_roundtrip() {
        let (mut a, mut b) = local_pair();
        a.send(&NetRequest::Shutdown).unwrap();
        assert!(matches!(b.recv::<NetRequest>().unwrap(), NetRequest::Shutdown));
    }

    #[cfg(feature = "multi-process")]
    #[test]
    fn frame_roundtrip() {
        let msg = NetResponse {
            request_id: 42,
            outcome: FetchOutcome::Ok { status: 200, body: vec![9, 9, 9] },
        };
        let mut buf: Vec<u8> = Vec::new();
        send_msg(&mut buf, &msg).unwrap();
        let mut cur = std::io::Cursor::new(buf);
        let back: NetResponse = recv_msg(&mut cur).unwrap();
        assert_eq!(back.request_id, 42);
        assert!(matches!(back.outcome, FetchOutcome::Ok { status: 200, .. }));
    }

    /// Hand-rolled sendmsg attaching `fds` to ONE SCM_RIGHTS cmsg — what a
    /// compromised peer (sendmsg is on its allowlist) can do to smuggle
    /// descriptors into the fd hand-off.
    #[cfg(all(feature = "multi-process", target_os = "linux"))]
    unsafe fn send_fds_one_cmsg(sock_fd: std::os::fd::RawFd, fds: &[std::os::fd::RawFd]) {
        let mut byte = [0u8; 1];
        let mut iov = libc::iovec { iov_base: byte.as_mut_ptr().cast(), iov_len: 1 };
        let payload = std::mem::size_of_val(fds) as u32;
        let mut buf = vec![0u8; libc::CMSG_SPACE(payload) as usize];

        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = buf.as_mut_ptr().cast();
        msg.msg_controllen = buf.len() as _;

        let cmsgp = libc::CMSG_FIRSTHDR(&msg);
        (*cmsgp).cmsg_level = libc::SOL_SOCKET;
        (*cmsgp).cmsg_type = libc::SCM_RIGHTS;
        (*cmsgp).cmsg_len = libc::CMSG_LEN(payload) as _;
        std::ptr::copy_nonoverlapping(
            fds.as_ptr(),
            libc::CMSG_DATA(cmsgp).cast::<std::os::fd::RawFd>(),
            fds.len(),
        );
        assert!(libc::sendmsg(sock_fd, &msg, 0) >= 0, "{}", io::Error::last_os_error());
    }

    #[cfg(all(feature = "multi-process", target_os = "linux"))]
    #[test]
    fn recv_fd_roundtrips_exactly_one() {
        let (a, b) = UnixStream::pair().unwrap();
        unsafe { send_fd(a.as_raw_fd(), 2).unwrap() }; // stderr as a stand-in
        let fd = unsafe { recv_fd(b.as_raw_fd()) }.unwrap();
        assert!(fd.as_raw_fd() >= 0);
    }

    #[cfg(all(feature = "multi-process", target_os = "linux"))]
    #[test]
    fn recv_fd_rejects_smuggled_extra_fds() {
        // Several fds stuffed into the one-fd hand-off must be refused — and
        // the extras closed, not leaked into the receiver's fd table (the
        // OwnedFd-before-verdict adoption in recv_fd is what guarantees the
        // close; this pins the refusal).
        let (a, b) = UnixStream::pair().unwrap();
        unsafe { send_fds_one_cmsg(a.as_raw_fd(), &[2, 2, 2]) };
        assert!(unsafe { recv_fd(b.as_raw_fd()) }.is_err());
    }

    #[cfg(all(feature = "multi-process", target_os = "linux"))]
    #[test]
    fn recv_fd_rejects_data_without_fd() {
        use std::io::Write;
        let (mut a, b) = UnixStream::pair().unwrap();
        a.write_all(&[0u8]).unwrap(); // plain byte, no SCM_RIGHTS attached
        assert!(unsafe { recv_fd(b.as_raw_fd()) }.is_err());
    }

    #[cfg(feature = "multi-process")]
    #[test]
    fn oversized_length_prefix_rejected() {
        // A corrupt/malicious length prefix must not force an allocation.
        let mut buf: Vec<u8> = (MAX_FRAME_LEN + 1).to_le_bytes().to_vec();
        buf.extend_from_slice(&[0u8; 8]);
        let mut cur = std::io::Cursor::new(buf);
        let r: io::Result<NetResponse> = recv_msg(&mut cur);
        assert!(r.is_err(), "should reject an oversized frame");
    }
}
