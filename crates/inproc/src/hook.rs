//! Replacing pointer-sized slots (vtable entries, function pointers) in
//! foreign memory, and the `__fastcall` trampolines to put in them.

use crate::mem::{MemError, Ptr32};

#[derive(Debug, thiserror::Error)]
pub enum HookError {
    #[error(transparent)]
    Mem(#[from] MemError),
    #[error("cannot change protection of {0:#x}")]
    Protect(u32),
    #[error("hooks need a 32-bit x86 process")]
    Unsupported,
}

/// A slot whose content was replaced; the original is put back on drop.
#[derive(Debug)]
pub struct SlotPatch {
    slot: Ptr32<u32>,
    original: u32,
}

impl SlotPatch {
    /// The slot's previous content (the function that was there).
    pub fn original(&self) -> u32 {
        self.original
    }

    /// Writes `value` into `slot` (temporarily making the page writable).
    ///
    /// This only swaps a pointer: it is the *meaning* of the new value that
    /// matters to the foreign program, which is why the public way in is
    /// [`fastcall_hook!`](crate::fastcall_hook), whose trampolines have the
    /// signature the slot's callers expect.
    #[doc(hidden)]
    pub fn replace(slot: Ptr32<u32>, value: u32) -> Result<SlotPatch, HookError> {
        let original = slot.read()?;
        imp::write_u32(slot.raw(), value)?;
        Ok(SlotPatch { slot, original })
    }
}

impl Drop for SlotPatch {
    fn drop(&mut self) {
        if let Err(e) = imp::write_u32(self.slot.raw(), self.original) {
            log::error!("restoring hooked slot {:?}: {e}", self.slot);
        }
    }
}

#[cfg(all(windows, target_arch = "x86"))]
mod imp {
    use super::HookError;
    use windows_sys::Win32::System::Diagnostics::Debug::{FlushInstructionCache, WriteProcessMemory};
    use windows_sys::Win32::System::Memory::{PAGE_EXECUTE_READWRITE, VirtualProtect};
    use windows_sys::Win32::System::Threading::GetCurrentProcess;

    pub fn write_u32(addr: u32, value: u32) -> Result<(), HookError> {
        let ptr = addr as usize as *mut core::ffi::c_void;
        let mut old = 0u32;
        // SAFETY: VirtualProtect/WriteProcessMemory validate the address and
        // fail on unmapped memory; we never dereference it ourselves. The
        // write is a single aligned dword, which other threads observe
        // atomically on x86.
        unsafe {
            if VirtualProtect(ptr, 4, PAGE_EXECUTE_READWRITE, &mut old) == 0 {
                return Err(HookError::Protect(addr));
            }
            let mut done = 0usize;
            let ok = WriteProcessMemory(GetCurrentProcess(), ptr, (&value as *const u32).cast(), 4, &mut done);
            let mut ignored = 0u32;
            VirtualProtect(ptr, 4, old, &mut ignored);
            FlushInstructionCache(GetCurrentProcess(), ptr, 4);
            if ok == 0 || done != 4 {
                return Err(HookError::Mem(crate::MemError::Unreadable { addr: addr as u64, len: 4 }));
            }
        }
        Ok(())
    }
}

#[cfg(not(all(windows, target_arch = "x86")))]
mod imp {
    use super::HookError;
    pub fn write_u32(_addr: u32, _value: u32) -> Result<(), HookError> {
        Err(HookError::Unsupported)
    }
}

/// Defines a hook for a `__fastcall` (or `__thiscall`-compatible) function
/// slot of a 32-bit x86 program: a module with `install(slot, handler)`.
///
/// ```ignore
/// inproc::fastcall_hook! {
///     /// Map_Renderer::Draw_Tiles(this, edx, a, b, c)
///     pub mod draw_tiles(this, edx; a, b, c) -> ();
/// }
/// let hook = draw_tiles::install(slot, |call| {
///     before();
///     call.original();          // run the game's function
///     after();
/// })?;
/// ```
///
/// The handler receives a `Call` with the register arguments (`this` = ecx,
/// `edx`) and the stack arguments, all as `u32` (wrap them in `Ptr32` to
/// read through them), and must call `call.original()` (or not) itself.
///
/// The declaration is the one assumption that cannot be checked: the slot
/// must hold a `__fastcall` function taking exactly the listed stack
/// arguments (the callee pops them, so a wrong count corrupts the stack).
/// Only one installation per hook module may be active at a time.
#[macro_export]
macro_rules! fastcall_hook {
    ($(#[$m:meta])* $vis:vis mod $name:ident($this:ident, $edx:ident; $($arg:ident),*) -> $ret:ty;) => {
        $(#[$m])*
        $vis mod $name {
            #![allow(unsafe_code, dead_code, unused_imports)]
            use super::*;

            /// One invocation of the hooked function.
            pub struct Call {
                pub $this: u32,
                pub $edx: u32,
                $(pub $arg: u32,)*
                original: u32,
            }

            impl Call {
                /// Runs the game's original function with the same arguments.
                pub fn original(&self) -> $ret {
                    self.original_with(self.$this, $(self.$arg),*)
                }

                /// Runs the game's original function with other arguments.
                pub fn original_with(&self, $this: u32, $($arg: u32),*) -> $ret {
                    #[cfg(target_arch = "x86")]
                    {
                        type Raw = extern "fastcall" fn(u32, u32 $(, $crate::__ident_u32!($arg))*) -> $ret;
                        // SAFETY: `original` was read from the hooked slot,
                        // whose callers use this exact signature (the macro
                        // invocation's documented contract).
                        let f: Raw = unsafe { ::core::mem::transmute::<usize, Raw>(self.original as usize) };
                        f($this, self.$edx $(, $arg)*)
                    }
                    #[cfg(not(target_arch = "x86"))]
                    { let _ = ($this, $($arg),*); unreachable!("hooks only run in 32-bit x86 processes") }
                }
            }

            type Handler = ::std::boxed::Box<dyn Fn(&Call) -> $ret + Send + Sync>;
            static HANDLER: ::std::sync::RwLock<Option<(Handler, u32)>> = ::std::sync::RwLock::new(None);

            #[cfg(target_arch = "x86")]
            extern "fastcall" fn trampoline($this: u32, $edx: u32 $(, $arg: u32)*) -> $ret {
                let guard = HANDLER.read().unwrap_or_else(|e| e.into_inner());
                let (handler, original) = guard.as_ref().expect("hook trampoline without handler");
                let call = Call { $this, $edx, $($arg,)* original: *original };
                match ::std::panic::catch_unwind(::std::panic::AssertUnwindSafe(|| handler(&call))) {
                    Ok(r) => r,
                    Err(_) => {
                        // Never unwind into the foreign program; fall back
                        // to the game's own behaviour.
                        ::log::error!(concat!("hook ", stringify!($name), " panicked; calling original"));
                        call.original()
                    }
                }
            }

            /// Active installation; uninstalls (restores the slot) on drop.
            pub struct Installed($crate::hook::SlotPatch);

            /// Points `slot` at this hook's trampoline, which calls `handler`.
            pub fn install(
                slot: $crate::mem::Ptr32<u32>,
                handler: impl Fn(&Call) -> $ret + Send + Sync + 'static,
            ) -> Result<Installed, $crate::hook::HookError> {
                #[cfg(target_arch = "x86")]
                {
                    let original = slot.read()?;
                    *HANDLER.write().unwrap_or_else(|e| e.into_inner()) = Some((Box::new(handler), original));
                    let patch = $crate::hook::SlotPatch::replace(slot, trampoline as usize as u32)?;
                    Ok(Installed(patch))
                }
                #[cfg(not(target_arch = "x86"))]
                { let _ = (slot, handler); Err($crate::hook::HookError::Unsupported) }
            }
        }
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __ident_u32 {
    ($i:ident) => {
        u32
    };
}
