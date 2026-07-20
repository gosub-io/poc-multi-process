//! Windows transport backend: a pair of anonymous pipes.
//!
//! `CreatePipe` gives a *half-duplex* pipe, so a duplex link needs two of them
//! — one per direction. That is the whole reason [`Channel`] carries two
//! handles here where the Unix backend carries one descriptor, and why
//! [`Channel::to_argv`] emits two comma-separated values.
//!
//! Anonymous, deliberately. A *named* pipe would be duplex in a single object
//! and would collapse this file to something close to the Unix backend, but it
//! places the endpoint in the object namespace where another local process can
//! reach it, reintroducing exactly the rendezvous and `accept()`-race the
//! inherited-handle model exists to avoid. Chromium accepts that trade and
//! defends it with random names plus a restrictive DACL; this PoC would rather
//! keep the stronger property and pay two handles for it.
//!
//! Handles are wrapped in `File`, which gives `Read`/`Write` via
//! `ReadFile`/`WriteFile` — precisely what a pipe handle wants — and closes on
//! drop. No hand-rolled I/O.
//!
//! ## Validation
//!
//! Written on Linux and verified on real Windows through CI: the transport
//! carries the demo end to end. Confinement is a separate concern handled by
//! `sandbox/windows.rs`, which installs process mitigation policies — see
//! there for which half of a Windows sandbox that is, and which half is still
//! missing.

use std::fs::File;
use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, RawHandle};

use windows_sys::Win32::Foundation::{SetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT};
use windows_sys::Win32::System::Pipes::CreatePipe;

/// One end of a duplex link: the read end of one pipe, the write end of the
/// other.
pub struct Channel {
    rx: File,
    tx: File,
}

/// Send half.
pub type Tx = File;
/// Receive half.
pub type Rx = File;

/// Create one anonymous pipe, returning `(read, write)`.
///
/// Both handles are non-inheritable (null security attributes); inheritance is
/// granted selectively later, to the child's two ends only.
fn pipe() -> io::Result<(File, File)> {
    let mut read: HANDLE = std::ptr::null_mut();
    let mut write: HANDLE = std::ptr::null_mut();
    // SAFETY: both out-params are valid; null attributes = default security,
    // non-inheritable; 0 = default buffer size.
    let ok = unsafe { CreatePipe(&mut read, &mut write, std::ptr::null(), 0) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: CreatePipe succeeded, so both handles are valid and owned by us.
    unsafe {
        Ok((
            File::from_raw_handle(read as RawHandle),
            File::from_raw_handle(write as RawHandle),
        ))
    }
}

impl Channel {
    /// A connected pair: one end for the engine, one to hand to the child.
    pub fn pair() -> io::Result<(Channel, Channel)> {
        // Pipe A carries child → engine, pipe B carries engine → child.
        let (a_read, a_write) = pipe()?;
        let (b_read, b_write) = pipe()?;
        Ok((
            Channel { rx: a_read, tx: b_write },
            Channel { rx: b_read, tx: a_write },
        ))
    }

    /// Split into independent halves — already separate objects here, so
    /// unlike the Unix backend this cannot fail for want of a `dup`.
    pub fn split(self) -> io::Result<(Tx, Rx)> {
        Ok((self.tx, self.rx))
    }

    /// The child's end as an argv token: `read,write`. Handle *values* are not
    /// secrets, and an inherited handle keeps the same numeric value in the
    /// child, so the child can adopt them directly.
    pub fn to_argv(&self) -> String {
        format!("{},{}", self.rx.as_raw_handle() as isize, self.tx.as_raw_handle() as isize)
    }

    /// Adopt a channel this process inherited from its parent.
    ///
    /// # Safety
    /// `spec` must be a token produced by [`Channel::to_argv`] in the parent,
    /// naming handles this process inherited and does not otherwise own.
    pub unsafe fn from_argv(spec: &str) -> io::Result<Channel> {
        let bad = || io::Error::new(io::ErrorKind::InvalidInput, "bad link handles");
        let (rx, tx) = spec.split_once(',').ok_or_else(bad)?;
        let rx: isize = rx.parse().map_err(|_| bad())?;
        let tx: isize = tx.parse().map_err(|_| bad())?;
        Ok(Channel {
            rx: File::from_raw_handle(rx as RawHandle),
            tx: File::from_raw_handle(tx as RawHandle),
        })
    }

    /// Let this end survive into the child, by setting `HANDLE_FLAG_INHERIT`.
    ///
    /// Unlike the Unix backend this must run in the *parent* before
    /// `CreateProcess`, because Windows has no `pre_exec` equivalent. See the
    /// module docs on `channel/mod.rs` for why that is safe with a
    /// single-threaded spawner and what a threaded one would need instead.
    pub fn make_inheritable(handles: (RawHandle, RawHandle)) -> io::Result<()> {
        for h in [handles.0, handles.1] {
            // SAFETY: a handle the caller owns; the flag mask and value match.
            let ok = unsafe {
                SetHandleInformation(h as HANDLE, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT)
            };
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }

    /// The raw handles `make_inheritable` applies to, captured so the spawner
    /// can grant inheritance while the `Channel` still owns them.
    pub fn raw(&self) -> (RawHandle, RawHandle) {
        (self.rx.as_raw_handle(), self.tx.as_raw_handle())
    }

}
