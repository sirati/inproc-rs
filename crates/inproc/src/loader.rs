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
pub fn hook_load_library(module: u32, loaded: impl Fn(&str, u32) + Send + Sync + 'static) -> Result<Option<Hook>, HookError> {
    let Some(slot) = crate::pe::import_slot(module, "KERNEL32.dll", "LoadLibraryA")? else { return Ok(None) };
    let installed = load_library_a::install_slot(slot, move |call| {
        let base = call.original();
        if base != 0 {
            if let Some(path) = c_string(call.name) {
                let name = path.rsplit(['\\', '/']).next().unwrap_or(&path).to_ascii_lowercase();
                // (A name without extension is a DLL's.)
                let name = if name.contains('.') { name } else { format!("{name}.dll") };
                loaded(&name, base);
            }
        }
        base
    })?;
    Ok(Some(Hook(installed)))
}
