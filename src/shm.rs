//! Shared-memory tile transport (Linux): the renderer rasterizes into a
//! `memfd`, seals it, and passes the *fd* to the engine over the existing
//! `SCM_RIGHTS` channel — the engine then maps the same physical pages
//! instead of copying ~1 MiB of pixels through the socket. Only a ~10-byte
//! header travels in-band. This is the channel OOPIFs and a future decode
//! process will reuse.
//!
//! Ownership and lifecycle (producer = renderer, consumer = engine):
//! 1. The producer creates the memfd (`MFD_CLOEXEC | MFD_ALLOW_SEALING`),
//!    sizes it, writes the tile, and **unmaps before sealing** — the kernel
//!    refuses `F_SEAL_WRITE` while any writable mapping exists, which is
//!    exactly what makes the seal meaningful.
//! 2. It seals `SHRINK | GROW | WRITE | SEAL` and only then sends the fd. From
//!    that point the contents are immutable *to everyone*, permanently: there
//!    is no window where both processes can write the same pages, and the
//!    seals themselves can never be removed.
//! 3. The producer drops its fd right after sending (`SCM_RIGHTS` duplicated
//!    it into the consumer). One fd per side, nothing leaks.
//! 4. The consumer trusts nothing in the message: it bounds the claimed
//!    dimensions, requires the seals to actually be present (`F_GET_SEALS`),
//!    and checks the fd's *real* size (`fstat`) against what those dimensions
//!    need. `F_SEAL_SHRINK` makes the size check TOCTOU-free — the file
//!    cannot be shrunk after validation, so a later read through the mapping
//!    can never `SIGBUS`.
//! 5. The consumer maps read-only and closes the fd immediately (the mapping
//!    pins the pages); [`TileMapping`] unmaps on drop, so a dropped or
//!    rejected tile releases everything on the spot.
//!
//! Buffer reuse: this creates one sealed memfd per tile. Sealing is one-shot
//! (`F_SEAL_WRITE` can never be lifted), so the reusable buffer *pool* a real
//! compositor uses at 60 fps to avoid fd churn must give up write-sealing and
//! synchronize with fences/ownership-handoff instead. Per-tile sealing is the
//! right trade here: strictly stronger guarantees, and the PoC renders one
//! tile per navigation.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

/// RGBA8.
pub const BYTES_PER_PIXEL: usize = 4;

/// Upper bound on either tile dimension the consumer will accept (8192² × 4 =
/// 256 MiB) — far above the PoC's 512², but a ceiling on how much memory a
/// malicious renderer's "tile" can make the engine map.
pub const MAX_TILE_DIM: u32 = 8192;

/// The seals a consumer must see before touching the pages: size fixed in
/// both directions, contents immutable.
const REQUIRED_SEALS: libc::c_int =
    libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;

/// Byte length of a `width`×`height` RGBA tile, refusing out-of-range
/// dimensions. Both sides use this: the producer to size the memfd, the
/// consumer to derive what the fd must hold *from the dimensions* — never
/// from a length claimed in a message.
fn tile_len(width: u32, height: u32) -> io::Result<usize> {
    if width == 0 || height == 0 || width > MAX_TILE_DIM || height > MAX_TILE_DIM {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("tile dimensions {width}x{height} out of range"),
        ));
    }
    Ok(width as usize * height as usize * BYTES_PER_PIXEL)
}

/// Producer side: create a sealed, immutable memfd holding one rendered tile,
/// ready to pass to the consumer. `fill` receives the zeroed pixel buffer.
pub fn create_sealed_tile(
    width: u32,
    height: u32,
    fill: impl FnOnce(&mut [u8]),
) -> io::Result<OwnedFd> {
    let len = tile_len(width, height)?;

    // SAFETY: plain libc calls on values we own; the raw fd is wrapped in an
    // OwnedFd immediately, so every early return below closes it.
    let raw = unsafe {
        libc::memfd_create(c"gosub-tile".as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING)
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };

    if unsafe { libc::ftruncate(fd.as_raw_fd(), len as libc::off_t) } < 0 {
        return Err(io::Error::last_os_error());
    }

    // Write the pixels through a temporary mapping, then unmap: F_SEAL_WRITE
    // below is refused while any writable mapping exists.
    unsafe {
        let ptr = libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd.as_raw_fd(),
            0,
        );
        if ptr == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        fill(std::slice::from_raw_parts_mut(ptr.cast::<u8>(), len));
        libc::munmap(ptr, len);
    }

    // Freeze size and contents, and seal the seals themselves. After this no
    // process — including this one — can modify the tile, so it is safe to
    // hand out.
    let all = REQUIRED_SEALS | libc::F_SEAL_SEAL;
    if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_ADD_SEALS, all) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}

/// A consumer-side read-only view of a sealed tile. The backing fd is closed
/// as soon as the mapping exists (the mapping pins the pages); dropping the
/// mapping unmaps them.
pub struct TileMapping {
    ptr: std::ptr::NonNull<u8>,
    len: usize,
}

// SAFETY: the mapping is PROT_READ over a memfd sealed with F_SEAL_WRITE (no
// writer can exist in any process) and F_SEAL_SHRINK (the range stays valid),
// so reading it from any thread is sound.
unsafe impl Send for TileMapping {}
unsafe impl Sync for TileMapping {}

impl TileMapping {
    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: ptr/len describe a live PROT_READ mapping we own.
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }
}

impl Drop for TileMapping {
    fn drop(&mut self) {
        // SAFETY: exactly the range mmap returned; mapped once, unmapped once.
        unsafe { libc::munmap(self.ptr.as_ptr().cast(), self.len) };
    }
}

/// Consumer side: validate a received tile fd and map it read-only.
///
/// `width`/`height` come from the accompanying IPC message and are treated as
/// a *claim*: this bounds them, requires the immutability seals to actually
/// be present, and checks the fd's real size with `fstat` — a tile whose fd
/// cannot hold its claimed dimensions is refused before anything is mapped.
/// The fd is consumed and closed either way.
pub fn map_sealed_tile(fd: OwnedFd, width: u32, height: u32) -> io::Result<TileMapping> {
    let len = tile_len(width, height)?;

    // SAFETY: fcntl/fstat/mmap on an fd we own.
    let seals = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GET_SEALS) };
    if seals < 0 {
        return Err(io::Error::last_os_error()); // not a sealable memfd at all
    }
    if seals & REQUIRED_SEALS != REQUIRED_SEALS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "tile fd is not sealed (sender could still write or shrink it)",
        ));
    }

    // The real size, not the claimed one. F_SEAL_SHRINK (verified above) makes
    // this check stable: the file cannot shrink afterwards, so no read through
    // the mapping can SIGBUS.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } < 0 {
        return Err(io::Error::last_os_error());
    }
    if (st.st_size as u128) < len as u128 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("tile fd holds {} bytes, {width}x{height} needs {len}", st.st_size),
        ));
    }

    let ptr = unsafe {
        libc::mmap(std::ptr::null_mut(), len, libc::PROT_READ, libc::MAP_SHARED, fd.as_raw_fd(), 0)
    };
    if ptr == libc::MAP_FAILED {
        return Err(io::Error::last_os_error());
    }
    Ok(TileMapping { ptr: std::ptr::NonNull::new(ptr.cast()).expect("mmap returned null"), len })
    // `fd` drops (closes) here; the mapping keeps the pages alive.
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sealed_tile_roundtrip() {
        let fd = create_sealed_tile(8, 4, |buf| {
            for (i, b) in buf.iter_mut().enumerate() {
                *b = (i * 7) as u8;
            }
        })
        .unwrap();
        let map = map_sealed_tile(fd, 8, 4).unwrap();
        assert_eq!(map.as_slice().len(), 8 * 4 * BYTES_PER_PIXEL);
        assert!(map.as_slice().iter().enumerate().all(|(i, &b)| b == (i * 7) as u8));
    }

    #[test]
    fn unsealed_fd_refused() {
        // Same memfd, correct size — but never sealed. A consumer must refuse
        // it: the sender could still write to or shrink it after validation.
        let len = tile_len(8, 4).unwrap();
        let raw = unsafe {
            libc::memfd_create(c"unsealed".as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING)
        };
        assert!(raw >= 0);
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        assert_eq!(unsafe { libc::ftruncate(fd.as_raw_fd(), len as libc::off_t) }, 0);
        assert!(map_sealed_tile(fd, 8, 4).is_err());
    }

    #[test]
    fn undersized_fd_refused() {
        // Sealed as 8x4 but claimed as 512x512: the fstat check must catch
        // that the fd cannot hold the claimed tile.
        let fd = create_sealed_tile(8, 4, |_| {}).unwrap();
        assert!(map_sealed_tile(fd, 512, 512).is_err());
    }

    #[test]
    fn absurd_dimensions_refused() {
        assert!(tile_len(0, 4).is_err());
        assert!(tile_len(MAX_TILE_DIM + 1, 1).is_err());
        assert!(create_sealed_tile(0, 0, |_| {}).is_err());
    }
}
