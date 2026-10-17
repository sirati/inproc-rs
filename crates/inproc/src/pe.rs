//! Reading loaded modules' PE headers (through guarded reads).

use windows_sys::Win32::System::LibraryLoader::GetModuleHandleA;

use crate::mem::{MemError, Ptr32};

/// Base address of a loaded module, by file name ("jgl.dll").
pub fn module_base(name: &str) -> Option<u32> {
    let c = std::ffi::CString::new(name).ok()?;
    // SAFETY: NUL-terminated name; returns NULL if not loaded.
    let h = unsafe { GetModuleHandleA(c.as_ptr() as *const u8) };
    (!h.is_null()).then_some(h as usize as u32)
}

/// Base address of the process's executable.
pub fn main_module() -> u32 {
    // SAFETY: NULL asks for the executable's handle, which always exists.
    unsafe { GetModuleHandleA(std::ptr::null()) as usize as u32 }
}

/// The NUL-terminated name at `at` (at most 256 bytes), read a byte at a
/// time: a name may end right at the end of its module's mapped memory.
fn c_string(at: Ptr32<u8>) -> Result<String, MemError> {
    let mut bytes = Vec::new();
    for i in 0..256 {
        match at.offset::<u8>(i)?.read()? {
            0 => break,
            b => bytes.push(b),
        }
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// The import address table slot through which `module` calls
/// `dll!function` (by name; case-insensitive DLL name).
pub fn import_slot(module: u32, dll: &str, function: &str) -> Result<Option<Ptr32<u32>>, MemError> {
    let base = Ptr32::<u8>::new(module);
    let pe: u32 = base.offset::<u32>(0x3C)?.read()?;
    // Optional header data directory 1 (imports): PE + 0x80 for PE32.
    let imports: u32 = base.offset::<u32>(pe + 0x80)?.read()?;
    if imports == 0 {
        return Ok(None);
    }
    for i in 0.. {
        let desc = base.offset::<u32>(imports + 20 * i)?;
        let [lookup, _, _, name, iat]: [u32; 5] = desc.read_array(5)?.try_into().unwrap();
        if name == 0 {
            break;
        }
        if !c_string(base.offset(name)?)?.eq_ignore_ascii_case(dll) {
            continue;
        }
        let names = if lookup != 0 { lookup } else { iat };
        for j in 0.. {
            let entry: u32 = base.offset::<u32>(names + 4 * j)?.read()?;
            if entry == 0 {
                break;
            }
            // Not by ordinal: RVA of (hint, name).
            if entry & 0x8000_0000 == 0 && c_string(base.offset(entry + 2)?)? == function {
                return Ok(Some(base.offset::<u32>(iat + 4 * j)?));
            }
        }
    }
    Ok(None)
}
