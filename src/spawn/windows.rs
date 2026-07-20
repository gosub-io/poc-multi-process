//! Windows spawn backend: `CreateProcessW` with an extended startup info.
//!
//! Replaces `std::process::Command` so the spawn call is ours, which is the
//! precondition for every parent-side access control Windows has. Today it
//! uses that ownership for one thing — an explicit inherited-handle list — and
//! is structured so a restricted token (`CreateProcessAsUserW`) and an
//! AppContainer (`PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES`) slot into the
//! same call.
//!
//! ## The handle list
//!
//! Windows handle inheritance is process-wide: `SetHandleInformation(...,
//! HANDLE_FLAG_INHERIT)` makes a handle visible to *every* child created while
//! the flag is set, not just the one it was meant for. The previous approach
//! relied on the engine being single-threaded so no other `CreateProcess`
//! could be in flight — true, but an accident of structure rather than a
//! guarantee.
//!
//! `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` replaces that with an allowlist: this
//! child inherits exactly the handles named here and nothing else, whatever
//! else happens to be marked inheritable. That restores the property the Unix
//! side gets by clearing `FD_CLOEXEC` inside the forked child.

use std::ffi::c_void;
use std::io;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0};
use windows_sys::Win32::System::Threading::{
    CreateProcessAsUserW, CreateProcessW, DeleteProcThreadAttributeList,
    InitializeProcThreadAttributeList, UpdateProcThreadAttribute, WaitForSingleObject,
    EXTENDED_STARTUPINFO_PRESENT, INFINITE, PROCESS_INFORMATION,
    PROC_THREAD_ATTRIBUTE_HANDLE_LIST, STARTUPINFOEXW,
};

/// A spawned child process. Owns the process handle and closes it on drop.
pub struct Child {
    process: HANDLE,
    thread: HANDLE,
}

// SAFETY: a process handle is just a kernel object reference; it is not tied to
// the creating thread and may be waited on or closed from any thread.
unsafe impl Send for Child {}
unsafe impl Sync for Child {}

impl Child {
    /// Wait for the child to exit.
    pub fn wait(&mut self) -> io::Result<()> {
        // SAFETY: `process` is a valid handle owned by this struct.
        let rc = unsafe { WaitForSingleObject(self.process, INFINITE) };
        if rc != WAIT_OBJECT_0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// The raw process handle, for the parent-side confinement hook.
    pub fn raw_handle(&self) -> HANDLE {
        self.process
    }
}

impl Drop for Child {
    fn drop(&mut self) {
        // SAFETY: both handles are valid and owned here; the child keeps
        // running if it has not exited — closing a handle does not kill it.
        unsafe {
            CloseHandle(self.thread);
            CloseHandle(self.process);
        }
    }
}

/// Quote one argument for the Windows command line.
///
/// Windows passes a single string and lets each program parse it, so the
/// parent must produce something the CRT's parser turns back into the argument
/// we meant. The backslash rules are the fiddly part: a run of backslashes is
/// literal, *unless* it precedes a quote, in which case each one must be
/// doubled. Getting this wrong is how a path with a trailing separator turns
/// into a broken argument or, worse, an injected one.
fn quote(arg: &str) -> String {
    if !arg.is_empty() && !arg.contains([' ', '\t', '"']) {
        return arg.to_string();
    }
    let mut out = String::with_capacity(arg.len() + 2);
    out.push('"');
    let mut backslashes = 0usize;
    for c in arg.chars() {
        match c {
            '\\' => {
                backslashes += 1;
                out.push(c);
            }
            '"' => {
                // Double the run, then escape the quote itself.
                out.extend(std::iter::repeat_n('\\', backslashes + 1));
                out.push('"');
                backslashes = 0;
            }
            _ => {
                backslashes = 0;
                out.push(c);
            }
        }
    }
    // A trailing run precedes the closing quote, so it must be doubled too.
    out.extend(std::iter::repeat_n('\\', backslashes));
    out.push('"');
    out
}

/// A NUL-terminated UTF-16 buffer, as every `*W` API wants.
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Spawn `exe` with `args`, handing `child_end` over as an inherited channel.
///
/// `isolate_network` is accepted for signature parity with the Unix backend and
/// is unused: network isolation on Windows needs an AppContainer, which is not
/// implemented (see `sandbox/windows.rs`).
pub fn spawn(
    exe: &std::path::Path,
    args: &[&str],
    child_end: crate::channel::Channel,
    isolate_network: bool,
) -> io::Result<Child> {
    let _ = isolate_network;

    // argv[0] is the program itself, by convention.
    let mut line = quote(&exe.to_string_lossy());
    for a in args {
        line.push(' ');
        line.push_str(&quote(a));
    }
    line.push(' ');
    line.push_str(&quote(&child_end.to_argv()));

    let mut exe_w = wide(&exe.to_string_lossy());
    let mut line_w = wide(&line);

    // The child's two pipe ends must be inheritable *and* on the list below.
    // The flag alone is process-wide; the list is what makes it per-child.
    let (rx, tx) = child_end.raw();
    crate::channel::Channel::make_inheritable((rx, tx))?;
    let mut handles: [HANDLE; 2] = [rx as HANDLE, tx as HANDLE];

    // Attribute lists are sized by the API: ask with a null buffer, allocate,
    // then initialize for real.
    let mut size: usize = 0;
    // SAFETY: the documented two-call sizing protocol; failure here is
    // expected and reports the required size through `size`.
    unsafe { InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &mut size) };
    if size == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut attr_buf = vec![0u8; size];
    let attr_list = attr_buf.as_mut_ptr().cast();

    // SAFETY: `attr_list` points at `size` bytes, matching what the sizing call
    // asked for; one attribute is declared.
    if unsafe { InitializeProcThreadAttributeList(attr_list, 1, 0, &mut size) } == 0 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: the handle array outlives the CreateProcessW call below, which is
    // what the attribute list requires.
    let updated = unsafe {
        UpdateProcThreadAttribute(
            attr_list,
            0,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
            handles.as_mut_ptr().cast::<c_void>(),
            std::mem::size_of_val(&handles),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if updated == 0 {
        let e = io::Error::last_os_error();
        // SAFETY: initialized above.
        unsafe { DeleteProcThreadAttributeList(attr_list) };
        return Err(e);
    }

    // SAFETY: zeroed is the documented "no overrides" state for STARTUPINFO.
    let mut si: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
    si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
    si.lpAttributeList = attr_list;

    // SAFETY: zeroed out-param, filled by CreateProcessW on success.
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    // Spawn under a restricted token when one can be built: privileges
    // stripped, group-granted access denied. Falling back to the inherited
    // token if not is deliberate — a host or policy that refuses token
    // creation should get a less-confined child rather than no browser, the
    // same call made for low integrity and win32k lockdown. The child's own
    // lockdown still applies either way.
    let token = crate::sandbox::restricted_token();

    // SAFETY: `exe_w` and `line_w` are NUL-terminated and live across the call;
    // `bInheritHandles = TRUE` is required for the handle list to apply.
    let ok = unsafe {
        match token {
            Some(t) => CreateProcessAsUserW(
                t,
                exe_w.as_mut_ptr(),
                line_w.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                1, // inherit handles — scoped by the list above
                EXTENDED_STARTUPINFO_PRESENT,
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::addr_of!(si).cast(),
                &mut pi,
            ),
            None => CreateProcessW(
                exe_w.as_mut_ptr(),
                line_w.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                1,
                EXTENDED_STARTUPINFO_PRESENT,
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::addr_of!(si).cast(),
                &mut pi,
            ),
        }
    };
    let err = io::Error::last_os_error();

    if let Some(t) = token {
        // SAFETY: created by `restricted_token`; the process holds its own
        // reference now.
        unsafe { CloseHandle(t) };
    }

    // SAFETY: initialized above and no longer needed either way.
    unsafe { DeleteProcThreadAttributeList(attr_list) };

    if ok == 0 {
        return Err(err);
    }

    // The child holds its own copies now; drop ours so a dead child is seen as
    // EOF rather than a link the engine is itself holding open.
    drop(child_end);

    Ok(Child { process: pi.hProcess, thread: pi.hThread })
}
