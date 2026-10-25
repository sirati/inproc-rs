//! DLL entry point support for [`entry!`](crate::entry).

use std::ffi::c_void;
use std::sync::OnceLock;

use windows_sys::Win32::System::LibraryLoader::DisableThreadLibraryCalls;
use windows_sys::Win32::System::SystemServices::{DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH};

static MODULE: OnceLock<usize> = OnceLock::new();

/// Handle of the DLL this code was loaded as.
pub fn module_handle() -> Option<usize> {
    MODULE.get().copied()
}

/// One more reference to this DLL (`LoadLibraryW` on its own file), for
/// a module that will `FreeLibrary` a handle of it it was given; the
/// handle (0 if it could not be had).
pub fn add_reference() -> u32 {
    use windows_sys::Win32::System::LibraryLoader::{GetModuleFileNameW, LoadLibraryW};
    let Some(module) = module_handle() else { return 0 };
    let mut path = [0u16; 1024];
    // SAFETY: our own module's handle and a buffer of ours.
    let n = unsafe { GetModuleFileNameW(module as _, path.as_mut_ptr(), path.len() as u32) } as usize;
    if n == 0 || n >= path.len() {
        return 0;
    }
    path[n] = 0;
    // SAFETY: a NUL-terminated path of ours: our own DLL, already loaded.
    unsafe { LoadLibraryW(path.as_ptr()) as usize as u32 }
}

/// No early initialisation, nothing at the process's end (see
/// [`entry!`](crate::entry)).
pub fn nothing() {}

pub fn dll_main(module: *mut c_void, reason: u32, reserved: *mut c_void, init: fn(), early: fn(), ending: fn()) -> i32 {
    // (A non-null `reserved`: the process ends, rather than a FreeLibrary.)
    if reason == DLL_PROCESS_DETACH && !reserved.is_null() {
        let _ = std::panic::catch_unwind(ending);
        return 1;
    }
    if reason == DLL_PROCESS_ATTACH {
        let _ = MODULE.set(module as usize);
        // SAFETY: `module` is the handle the loader passed to DllMain.
        unsafe { DisableThreadLibraryCalls(module as _) };
        if std::panic::catch_unwind(early).is_err() {
            log::error!("early DLL initialisation panicked");
        }
        // The loader lock is held here: anything substantial (loading other
        // DLLs, waiting on threads) must happen elsewhere. A new thread only
        // starts running once DllMain has returned.
        let spawned = std::thread::Builder::new().name("inproc-init".into()).spawn(move || {
            if std::panic::catch_unwind(init).is_err() {
                log::error!("DLL initialisation panicked");
            }
        });
        if spawned.is_err() {
            return 0;
        }
    }
    1
}
