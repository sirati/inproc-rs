//! DLL entry point support for [`entry!`](crate::entry).

use std::ffi::c_void;
use std::sync::OnceLock;

use windows_sys::Win32::System::LibraryLoader::DisableThreadLibraryCalls;
use windows_sys::Win32::System::SystemServices::DLL_PROCESS_ATTACH;

static MODULE: OnceLock<usize> = OnceLock::new();

/// Handle of the DLL this code was loaded as.
pub fn module_handle() -> Option<usize> {
    MODULE.get().copied()
}

/// No early initialisation (see [`entry!`](crate::entry)).
pub fn nothing() {}

pub fn dll_main(module: *mut c_void, reason: u32, _reserved: *mut c_void, init: fn(), early: fn()) -> i32 {
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
