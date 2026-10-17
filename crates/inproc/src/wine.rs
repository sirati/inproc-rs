//! Running under Wine: whether we do, and the Unix file system as Windows
//! paths (for files shared with the Linux side, e.g. a native renderer's).

use std::path::{Path, PathBuf};

use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows_sys::Win32::System::Memory::{GetProcessHeap, HeapFree};

/// `WCHAR * CDECL wine_get_dos_file_name(const char *unix_name)` (kernel32
/// under Wine; the result is freed with `HeapFree` on the process heap).
type DosFileName = unsafe extern "C" fn(*const u8) -> *mut u16;

fn dos_file_name() -> Option<DosFileName> {
    // SAFETY: both names are NUL-terminated; kernel32 is always loaded.
    let f = unsafe { GetProcAddress(GetModuleHandleA(c"kernel32.dll".as_ptr() as *const u8), c"wine_get_dos_file_name".as_ptr() as *const u8) }?;
    // SAFETY: Wine's kernel32 exports it with this signature (cdecl).
    Some(unsafe { std::mem::transmute::<unsafe extern "system" fn() -> isize, DosFileName>(f) })
}

/// Whether this process runs under Wine.
pub fn is_wine() -> bool {
    dos_file_name().is_some()
}

/// Unix path `unix` (absolute, e.g. `/home/me/.config/x`) as a Windows path
/// of this Wine prefix (e.g. `Z:\home\me\.config\x`); `None` outside Wine
/// or if it has no such path.
pub fn dos_path(unix: &Path) -> Option<PathBuf> {
    let f = dos_file_name()?;
    let unix = std::ffi::CString::new(unix.to_str()?).ok()?;
    // SAFETY: a NUL-terminated string in; a heap string out, or NULL.
    let wide = unsafe { f(unix.as_ptr() as *const u8) };
    if wide.is_null() {
        return None;
    }
    // SAFETY: Wine returns a NUL-terminated wide string; it is read up to
    // its terminator, then freed as its documentation says.
    let path = unsafe {
        let len = (0..).take_while(|&i| *wide.add(i) != 0).count();
        let s = String::from_utf16_lossy(std::slice::from_raw_parts(wide, len));
        HeapFree(GetProcessHeap(), 0, wide as *const _);
        s
    };
    Some(PathBuf::from(path))
}
