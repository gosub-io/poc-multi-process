#![no_main]
//! Fuzz the broker's IPC deserialization surface — the sharpest edge in the
//! whole model. A *compromised* child sends these frames to the engine, which
//! parses them **unconfined and with full ambient authority** (see the README's
//! sandbox section). `recv_msg` reads the length prefix and bincode-decodes the
//! payload; neither step may panic or over-allocate on hostile bytes.
//!
//! The types below are exactly the untrusted → broker direction: what a
//! renderer, the net component, a decoder, and the storage/font services send
//! *in*. Each is decoded from the same fuzz bytes via a fresh cursor.
//!
//! Run: `cargo +nightly fuzz run ipc_frame`

use gosub_proc_iso_poc::ipc::{
    self, FontResponse, FromDecoder, FromRenderer, NetResponse, StorageResponse,
};
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    let _ = ipc::recv_msg::<FromRenderer>(&mut Cursor::new(data));
    let _ = ipc::recv_msg::<NetResponse>(&mut Cursor::new(data));
    let _ = ipc::recv_msg::<FromDecoder>(&mut Cursor::new(data));
    let _ = ipc::recv_msg::<StorageResponse>(&mut Cursor::new(data));
    let _ = ipc::recv_msg::<FontResponse>(&mut Cursor::new(data));
});
