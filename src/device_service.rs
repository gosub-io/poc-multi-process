//! Audio and GPU services — **honest stubs**.
//!
//! Both are real *processes* with a real, correct confinement shape: spawned
//! from the engine (they need a privilege the zygote gave up), and confined
//! with a `device` filter — the content baseline plus `openat` and `ioctl`,
//! which is what opening a device node (`/dev/snd/*`, a DRM render node) and
//! driving it actually requires.
//!
//! What they do **not** do is any real work. A PoC has no audio hardware and no
//! GPU driver to talk to, and pretending otherwise would be theater. So each is
//! spawned, prints its lockdown banner (proving the process exists and is
//! confined with the device filter), and idles until the engine drops its link
//! at shutdown. They are here to make the *shape* real — a device-class process
//! outside the zygote with an `ioctl`-permitting filter — and to mark exactly
//! where a real audio mixer or GPU compositor would slot in.
//!
//! The GPU process is additionally a cross-origin chokepoint by construction
//! (one process composites every tab's output), and `ioctl` is a large,
//! driver-defined surface seccomp constrains poorly — both noted so the stub
//! does not read as "GPU isolation solved".

use crate::ipc::{Endpoint, ServiceControl};

/// Idle until the engine closes the link. A real device service would loop
/// here receiving work requests and driving its device via `ioctl`; the stub
/// only waits for the single `Shutdown` (or the link's EOF), then returns.
pub fn serve(mut ep: Endpoint) {
    let _ = ep.recv::<ServiceControl>();
}

/// Multi-process entry point for a device-backed service (`audio` or `gpu`).
/// Confines with the device filter, then idles.
#[cfg(feature = "multi-process")]
pub fn run(name: &'static str, link: &str) {
    // SAFETY: the engine passed us sole ownership of this inherited channel.
    let ch = unsafe { crate::channel::Channel::from_argv(link) }.expect("device: bad link arg");
    let ep = Endpoint::from_channel(ch).expect("device: wrap link");
    crate::sandbox::lock_down_service(
        name,
        crate::sandbox::ServiceCaps { filesystem: false, device: true },
    );
    serve(ep);
}
