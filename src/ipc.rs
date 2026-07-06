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
#[cfg(feature = "multi-process")]
use std::os::unix::net::UnixStream;
use std::sync::mpsc::{self, Receiver, Sender};

/// A corrupted (or malicious) length prefix must not make the peer allocate
/// unbounded memory.
pub const MAX_FRAME_LEN: u32 = 16 * 1024 * 1024;

/// Renderer -> engine.
#[derive(Serialize, Deserialize, Debug)]
pub enum FromRenderer {
    /// Renderers have no network access; they must ask the engine, which
    /// brokers the request to the net component (Phase 1).
    NeedFetch { url: String },
    /// Renderers hold no cookie jar (Phase 2). The engine enforces
    /// same-origin using the *endpoint identity*, never this field.
    NeedCookies { origin: String },
    /// The final product of a `RenderPage` command: a rasterized tile.
    Tile { width: u32, height: u32, pixels: Vec<u8> },
}

/// Engine -> renderer.
#[derive(Serialize, Deserialize, Debug)]
pub enum ToRenderer {
    RenderPage { url: String },
    FetchResult { status: u16, body: Vec<u8> },
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
    Denied { reason: String },
}

/// Send half of an IPC link.
pub enum EndpointTx {
    #[cfg(feature = "multi-process")]
    Socket(UnixStream),
    Local(Sender<Vec<u8>>),
}

/// Receive half of an IPC link.
pub enum EndpointRx {
    #[cfg(feature = "multi-process")]
    Socket(UnixStream),
    Local(Receiver<Vec<u8>>),
}

impl EndpointTx {
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
    /// Wrap a connected Unix stream (the stream is cloned so the two halves
    /// can be used independently).
    #[cfg(feature = "multi-process")]
    pub fn from_stream(stream: UnixStream) -> io::Result<Endpoint> {
        let write_half = stream.try_clone()?;
        Ok(Endpoint { tx: EndpointTx::Socket(write_half), rx: EndpointRx::Socket(stream) })
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
