//! Length-framed bincode messaging over Unix domain sockets, as proposed in
//! gosub-engine issue #1080: every frame is a little-endian u32 payload length
//! followed by the bincode-encoded message.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::io;
#[cfg(feature = "multi-process")]
use std::io::{Read, Write};
#[cfg(feature = "multi-process")]
use std::os::unix::net::UnixStream;
use std::sync::mpsc::{self, Receiver, Sender};

/// A corrupted (or malicious) length prefix must not make the peer allocate
/// unbounded memory — one of the issue's acceptance criteria is graceful
/// handling of IPC message corruption.
pub const MAX_FRAME_LEN: u32 = 16 * 1024 * 1024;

/// First message on any connection: the child proves it is the process the
/// parent just spawned by echoing the one-time token it received on argv.
///
/// A production implementation would instead inherit one end of a
/// `socketpair(2)` so no rendezvous path or token exists at all; the
/// path+token dance keeps this PoC dependency-free.
#[cfg(feature = "multi-process")]
#[derive(Serialize, Deserialize, Debug)]
pub struct Hello {
    pub token: String,
}

/// Renderer -> parent engine.
#[derive(Serialize, Deserialize, Debug)]
pub enum FromRenderer {
    /// Renderers have no network access at all (Phase 1). They must ask the
    /// parent, which brokers the request to the net daemon.
    NeedFetch { url: String },
    /// Renderers hold no cookie jar (Phase 2). The parent enforces
    /// same-origin using the *socket identity*, never this field.
    NeedCookies { origin: String },
    /// The final product of a `RenderPage` command: a rasterized tile.
    Tile { width: u32, height: u32, pixels: Vec<u8> },
}

/// Parent engine -> renderer.
#[derive(Serialize, Deserialize, Debug)]
pub enum ToRenderer {
    /// `quiet` suppresses log chatter during the latency benchmark.
    RenderPage { url: String, quiet: bool },
    FetchResult { status: u16, body: Vec<u8> },
    FetchDenied { reason: String },
    /// `None` means the broker refused to hand the cookies over.
    Cookies(Option<Vec<(String, String)>>),
    /// Pretend a malicious payload achieved code execution and corrupted
    /// memory in this renderer (the issue's rasterizer-exploit scenario).
    SimulateCompromise,
    Shutdown,
}

/// Parent engine -> net daemon.
#[derive(Serialize, Deserialize, Debug)]
pub enum NetRequest {
    Fetch {
        /// Stamped by the *parent* from its own bookkeeping, so a compromised
        /// renderer cannot spoof another origin's identity.
        for_origin: String,
        url: String,
        quiet: bool,
    },
    Shutdown,
}

/// Net daemon -> parent engine.
#[derive(Serialize, Deserialize, Debug)]
pub enum NetResponse {
    Ok { status: u16, body: Vec<u8> },
    Denied { reason: String },
}

/// One end of a duplex IPC link. Components are written against this type
/// only, so the exact same renderer/net-daemon code runs either as a child
/// *process* (Socket) or as an in-process *thread* (Local). Both variants
/// carry identical bincode frames, so the protocol — and every policy check
/// built on it — behaves the same in both modes.
pub enum Endpoint {
    /// Multi-process mode: length-framed bincode over a Unix domain socket.
    #[cfg(feature = "multi-process")]
    Socket(UnixStream),
    /// Single-process mode: the same bincode frames over in-process channels.
    Local { tx: Sender<Vec<u8>>, rx: Receiver<Vec<u8>> },
}

impl Endpoint {
    pub fn send<T: Serialize>(&mut self, msg: &T) -> io::Result<()> {
        match self {
            #[cfg(feature = "multi-process")]
            Endpoint::Socket(stream) => send_msg(stream, msg),
            Endpoint::Local { tx, .. } => {
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

    pub fn recv<T: DeserializeOwned>(&mut self) -> io::Result<T> {
        match self {
            #[cfg(feature = "multi-process")]
            Endpoint::Socket(stream) => recv_msg(stream),
            Endpoint::Local { rx, .. } => {
                let payload = rx
                    .recv()
                    .map_err(|_| io::Error::new(io::ErrorKind::UnexpectedEof, "peer gone"))?;
                bincode::deserialize(&payload)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
            }
        }
    }
}

/// A connected pair of in-process endpoints (single-process mode's stand-in
/// for `socketpair(2)`).
pub fn local_pair() -> (Endpoint, Endpoint) {
    let (tx_a, rx_b) = mpsc::channel();
    let (tx_b, rx_a) = mpsc::channel();
    (Endpoint::Local { tx: tx_a, rx: rx_a }, Endpoint::Local { tx: tx_b, rx: rx_b })
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
