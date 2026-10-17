//! Learning of the libraries a module of the foreign program loads, as it
//! loads them: for redirecting a library's imports before its own code
//! first runs them (a library loaded later than our DLL, whose window or
//! screen size would otherwise be set up before a hook could be placed).
//!
//! [`hook_load_library`] redirects a module's import of `LoadLibraryA`.

use crate::hook::HookError;
use crate::mem::Ptr32;

crate::stdcall_hook! {
    /// `HMODULE LoadLibraryA(LPCSTR)`.
    mod load_library_a(name) -> u32;
}

/// The redirected import; restored when dropped.
pub struct Hook(#[allow(dead_code)] load_library_a::Installed);

impl std::fmt::Debug for Hook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Hook(LoadLibraryA)")
    }
}

/// The NUL-terminated string at `at` (up to `MAX_PATH` bytes), lossily.
fn c_string(at: u32) -> Option<String> {
    let mut bytes = Vec::new();
    for i in 0..260 {
        match Ptr32::<u8>::new(at.checked_add(i)?).read().ok()? {
            0 => break,
            b => bytes.push(b),
        }
    }
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

/// Redirects `module`'s `LoadLibraryA` import: after each library it loads,
/// `loaded` gets the library's file name in lower case (without its folder,
/// e.g. `jgl.dll`) and its base address, on the loading thread, before the
/// call returns to the module. `None` if the module does not import it.
/// Once per process; safe to call from `DllMain` (no library is loaded).
#[cfg(windows)]
pub fn hook_load_library(module: u32, loaded: impl Fn(&str, u32) + Send + Sync + 'static) -> Result<Option<Hook>, HookError> {
    let Some(slot) = crate::pe::import_slot(module, "KERNEL32.dll", "LoadLibraryA")? else { return Ok(None) };
    let installed = load_library_a::install_slot(slot, move |call| {
        load_then_notify(|| call.original(), || c_string(call.name), |name, base| loaded(name, base))
    })?;
    Ok(Some(Hook(installed)))
}

/// Complete import redirection on the caller's loading thread, after the
/// module is mapped but before control returns to its first caller.
fn load_then_notify(load: impl FnOnce() -> u32, path: impl FnOnce() -> Option<String>, loaded: impl FnOnce(&str, u32)) -> u32 {
    let base = load();
    if base != 0 {
        if let Some(path) = path() {
            let name = path.rsplit(['\\', '/']).next().unwrap_or(&path).to_ascii_lowercase();
            // A name without an extension is a DLL's.
            let name = if name.contains('.') { name } else { format!("{name}.dll") };
            loaded(&name, base);
        }
    }
    base
}

#[cfg(test)]
mod tests {
    use super::load_then_notify;
    use std::cell::{Cell, RefCell};

    #[test]
    fn import_hook_is_ready_for_the_first_call_after_load_library_returns() {
        let patched = Cell::new(false);
        let events = RefCell::new(Vec::new());
        let base = load_then_notify(|| {
            events.borrow_mut().push("library mapped");
            0x1000
        }, || Some("C:\\Game\\JGL.DLL".into()), |name, base| {
            assert_eq!(name, "jgl.dll");
            assert_eq!(base, 0x1000);
            patched.set(true);
            events.borrow_mut().push("text import patched");
        });
        // The game calls the newly loaded library immediately, without a
        // yield, sleep, repaint, or background worker getting a turn.
        assert_eq!(base, 0x1000);
        assert!(patched.get(), "the first text output must already be intercepted");
        events.borrow_mut().push("first text output");
        assert_eq!(*events.borrow(), ["library mapped", "text import patched", "first text output"]);
    }

    #[test]
    fn load_notifications_normalize_supported_library_paths() {
        for path in ["jgl", "JGL.DLL", "C:/Game/JGL.dll", "C:\\Game\\jgl"] {
            assert_eq!(load_then_notify(|| 0x2000, || Some(path.into()), |name, _| assert_eq!(name, "jgl.dll")), 0x2000);
        }
    }

    #[test]
    fn failed_load_never_redirects_an_unmapped_module() {
        assert_eq!(load_then_notify(|| 0, || panic!("failed load must not inspect its module"), |_, _| panic!("failed load must not install hooks")), 0);
        assert_eq!(load_then_notify(|| 0x3000, || None, |_, _| panic!("unknown module must not install hooks")), 0x3000);
    }
}
