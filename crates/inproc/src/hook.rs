//! Redirecting a foreign program's functions to Rust handlers.
//!
//! Two ways in, both reversible:
//!
//! * **Slot hooks** replace a function pointer the program calls through
//!   (a vtable entry). The cleanest option when it exists.
//! * **Inline hooks** overwrite the first instructions of a function with a
//!   jump; the overwritten instructions are moved into a *trampoline* that
//!   then continues into the rest of the function, so the original stays
//!   callable. The caller states the exact bytes it expects there: the patch
//!   is refused unless they match, which protects against the wrong build,
//!   another mod's patch, and prologues with position-dependent instructions
//!   (only declare bytes that can run unchanged from elsewhere).
//!
//! The public way in is [`fastcall_hook!`](crate::fastcall_hook), which
//! generates a trampoline with the hooked function's signature.

use crate::mem::{MemError, Ptr32};

#[derive(Debug, thiserror::Error)]
pub enum HookError {
    #[error(transparent)]
    Mem(#[from] MemError),
    #[error("cannot change protection of {0:#x}")]
    Protect(u32),
    #[error("cannot allocate executable memory")]
    Alloc,
    #[error("code at {addr:#x} is {found:02x?}, expected {expected:02x?}")]
    UnexpectedCode { addr: u32, found: Vec<u8>, expected: Vec<u8> },
    #[error("an inline hook needs at least 5 bytes of prologue")]
    PrologueTooShort,
    #[error("this hook is already installed")]
    AlreadyInstalled,
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

    #[doc(hidden)]
    pub fn replace(slot: Ptr32<u32>, value: u32) -> Result<SlotPatch, HookError> {
        let original = slot.read()?;
        imp::write(slot.raw(), &value.to_le_bytes())?;
        Ok(SlotPatch { slot, original })
    }
}

impl Drop for SlotPatch {
    fn drop(&mut self) {
        if let Err(e) = imp::write(self.slot.raw(), &self.original.to_le_bytes()) {
            log::error!("restoring hooked slot {:?}: {e}", self.slot);
        }
    }
}

/// A function whose prologue was replaced by a jump; restored on drop.
#[derive(Debug)]
pub struct InlinePatch {
    target: u32,
    original: Vec<u8>,
    trampoline: u32,
}

impl InlinePatch {
    /// Address that behaves like the original, unpatched function.
    pub fn trampoline(&self) -> u32 {
        self.trampoline
    }

    /// Verifies that `target` starts with exactly `expected`.
    #[doc(hidden)]
    pub fn check(target: u32, expected: &[u8]) -> Result<(), HookError> {
        if expected.len() < 5 {
            return Err(HookError::PrologueTooShort);
        }
        let found = Ptr32::<u8>::new(target).read_array(expected.len())?;
        if found != expected {
            return Err(HookError::UnexpectedCode { addr: target, found, expected: expected.to_vec() });
        }
        Ok(())
    }

    /// Builds the trampoline, reports it to `on_trampoline` (before the
    /// jump to `detour` is written), then patches `target`.
    #[doc(hidden)]
    pub fn install(
        target: u32,
        expected: &[u8],
        detour: u32,
        on_trampoline: impl FnOnce(u32),
    ) -> Result<InlinePatch, HookError> {
        Self::check(target, expected)?;
        // Trampoline: the stolen instructions, then jump back behind them.
        let trampoline = imp::alloc_exec(expected.len() + 5)?;
        let mut code = expected.to_vec();
        code.extend(jmp(trampoline + expected.len() as u32, target + expected.len() as u32));
        imp::write(trampoline, &code)?;
        on_trampoline(trampoline);
        // Target: jump to the detour, NOP-padded over the stolen bytes.
        let mut patch = jmp(target, detour).to_vec();
        patch.resize(expected.len(), 0x90);
        imp::write(target, &patch)?;
        Ok(InlinePatch { target, original: expected.to_vec(), trampoline })
    }
}

impl InlinePatch {
    /// Takes over a function that already starts with a `jmp rel32`
    /// (another mod's hook): the jump is pointed at `detour`; the old
    /// destination, reported to `on_original` first, still behaves like the
    /// function. No instructions are moved, so nothing position-dependent
    /// can break.
    #[doc(hidden)]
    pub fn install_over_jmp(target: u32, detour: u32, on_original: impl FnOnce(u32)) -> Result<InlinePatch, HookError> {
        let bytes = Ptr32::<u8>::new(target).read_array(5)?;
        if bytes[0] != 0xE9 {
            return Err(HookError::UnexpectedCode { addr: target, found: bytes, expected: vec![0xE9] });
        }
        let rel = i32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
        let destination = target.wrapping_add(5).wrapping_add(rel as u32);
        on_original(destination);
        imp::write(target, &jmp(target, detour))?;
        Ok(InlinePatch { target, original: bytes, trampoline: destination })
    }
}

impl Drop for InlinePatch {
    fn drop(&mut self) {
        // The trampoline is leaked on purpose: a thread may still be in it.
        if let Err(e) = imp::write(self.target, &self.original) {
            log::error!("restoring inline-hooked function {:#x}: {e}", self.target);
        }
    }
}

/// `jmp rel32` located at `at`, jumping to `to`.
fn jmp(at: u32, to: u32) -> [u8; 5] {
    let rel = to.wrapping_sub(at.wrapping_add(5)).to_le_bytes();
    [0xE9, rel[0], rel[1], rel[2], rel[3]]
}

#[cfg(all(windows, target_arch = "x86"))]
mod imp {
    use super::HookError;
    use windows_sys::Win32::System::Diagnostics::Debug::{FlushInstructionCache, WriteProcessMemory};
    use windows_sys::Win32::System::Memory::{
        MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAlloc, VirtualProtect,
    };
    use windows_sys::Win32::System::Threading::GetCurrentProcess;

    /// Writes `bytes` at `addr`, making the pages writable meanwhile.
    pub fn write(addr: u32, bytes: &[u8]) -> Result<(), HookError> {
        let ptr = addr as usize as *mut core::ffi::c_void;
        let mut old = 0u32;
        // SAFETY: VirtualProtect/WriteProcessMemory validate the address and
        // fail on unmapped memory; we never dereference it ourselves. Writes
        // of up to 8 aligned bytes are observed atomically by other threads;
        // longer patches are only applied to code the caller has vetted.
        unsafe {
            if VirtualProtect(ptr, bytes.len(), PAGE_EXECUTE_READWRITE, &mut old) == 0 {
                return Err(HookError::Protect(addr));
            }
            let mut done = 0usize;
            let ok = WriteProcessMemory(GetCurrentProcess(), ptr, bytes.as_ptr().cast(), bytes.len(), &mut done);
            let mut ignored = 0u32;
            VirtualProtect(ptr, bytes.len(), old, &mut ignored);
            FlushInstructionCache(GetCurrentProcess(), ptr, bytes.len());
            if ok == 0 || done != bytes.len() {
                return Err(HookError::Mem(crate::MemError::Unreadable { addr: addr as u64, len: bytes.len() }));
            }
        }
        Ok(())
    }

    pub fn alloc_exec(len: usize) -> Result<u32, HookError> {
        // SAFETY: plain allocation; the pointer is only used as an address.
        let p = unsafe { VirtualAlloc(core::ptr::null(), len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE) };
        if p.is_null() { Err(HookError::Alloc) } else { Ok(p as usize as u32) }
    }
}

#[cfg(not(all(windows, target_arch = "x86")))]
mod imp {
    use super::HookError;
    pub fn write(_addr: u32, _bytes: &[u8]) -> Result<(), HookError> {
        Err(HookError::Unsupported)
    }
    pub fn alloc_exec(_len: usize) -> Result<u32, HookError> {
        Err(HookError::Unsupported)
    }
}

/// Defines a hook for a `__fastcall` (or `__thiscall`-compatible) function
/// of a 32-bit x86 program: a module with `install_slot(slot, handler)` and
/// `install_inline(function, prologue, handler)`.
///
/// ```ignore
/// inproc::fastcall_hook! {
///     /// Map_Renderer::Draw_Tiles(this, edx, a, b, c)
///     pub mod draw_tiles(this, edx; a, b, c) -> ();
/// }
/// let hook = draw_tiles::install_slot(slot, |call| {
///     before();
///     call.original();          // run the game's function
///     after();
/// })?;
/// ```
///
/// The handler receives a `Call` with the register arguments (`this` = ecx,
/// `edx`) and the stack arguments, all as `u32` (wrap them in `Ptr32` to
/// read through them), and decides itself whether to call
/// `call.original()`.
///
/// The declaration is the one assumption that cannot be checked: the
/// function must be `__fastcall` with exactly the listed stack arguments
/// (the callee pops them, so a wrong count corrupts the stack). A hook
/// module can be installed once at a time (`AlreadyInstalled` otherwise).
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
                        // SAFETY: `original` is the hooked function (or its
                        // trampoline), whose signature is this macro
                        // invocation's documented contract.
                        let f: Raw = unsafe { ::core::mem::transmute::<usize, Raw>(self.original as usize) };
                        f($this, self.$edx $(, $arg)*)
                    }
                    #[cfg(not(target_arch = "x86"))]
                    { let _ = ($this, $($arg),*); unreachable!("hooks only run in 32-bit x86 processes") }
                }
            }

            #[cfg(target_arch = "x86")]
            extern "fastcall" fn trampoline($this: u32, $edx: u32 $(, $arg: u32)*) -> $ret {
                let call = Call { $this, $edx, $($arg,)* original: ORIGINAL.load(SeqCst) };
                let guard = HANDLER.read().unwrap_or_else(|e| e.into_inner());
                let Some(handler) = guard.as_ref() else { return call.original() };
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

            $crate::__hook_common!($name, $ret);
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

#[cfg(test)]
mod tests {
    #[test]
    fn jmp_encodes_relative_targets() {
        assert_eq!(super::jmp(0x1000, 0x1005), [0xE9, 0, 0, 0, 0]);
        assert_eq!(super::jmp(0x1000, 0x0FFB), [0xE9, 0xF6, 0xFF, 0xFF, 0xFF]);
    }
}

/// The parts of a hook module shared by all calling conventions: the
/// handler and original-function slots, `Installed`, `install_slot` and
/// `install_inline`. Expects `Call` and `trampoline` in the module.
#[doc(hidden)]
#[macro_export]
macro_rules! __hook_common {
    ($name:ident, $ret:ty) => {
            type Handler = ::std::boxed::Box<dyn Fn(&Call) -> $ret + Send + Sync>;
        static HANDLER: ::std::sync::RwLock<Option<Handler>> = ::std::sync::RwLock::new(None);
        /// The function to call as "original"; stays valid after
        /// uninstalling (slot: the old pointer; inline: the leaked
        /// trampoline), so a call racing an uninstall still works.
        static ORIGINAL: ::std::sync::atomic::AtomicU32 = ::std::sync::atomic::AtomicU32::new(0);
        static ACTIVE: ::std::sync::atomic::AtomicBool = ::std::sync::atomic::AtomicBool::new(false);
        use ::std::sync::atomic::Ordering::SeqCst;

            enum Patch {
            Slot($crate::hook::SlotPatch),
            Inline($crate::hook::InlinePatch),
        }

        /// An active hook; uninstalls when dropped.
        pub struct Installed(Option<Patch>);

        impl Drop for Installed {
            fn drop(&mut self) {
                // Restore the code first, then retire the handler (this
                // waits for calls still inside it).
                drop(self.0.take());
                *HANDLER.write().unwrap_or_else(|e| e.into_inner()) = None;
                ACTIVE.store(false, SeqCst);
            }
        }

        fn claim() -> Result<(), $crate::hook::HookError> {
            if ACTIVE.swap(true, SeqCst) { Err($crate::hook::HookError::AlreadyInstalled) } else { Ok(()) }
        }

        /// Points the function-pointer `slot` at this hook.
        pub fn install_slot(
            slot: $crate::mem::Ptr32<u32>,
            handler: impl Fn(&Call) -> $ret + Send + Sync + 'static,
        ) -> Result<Installed, $crate::hook::HookError> {
            #[cfg(target_arch = "x86")]
            {
                claim()?;
                let result = (|| {
                    ORIGINAL.store(slot.read()?, SeqCst);
                    *HANDLER.write().unwrap_or_else(|e| e.into_inner()) = Some(Box::new(handler));
                    $crate::hook::SlotPatch::replace(slot, trampoline as usize as u32)
                })();
                result.map(|p| Installed(Some(Patch::Slot(p)))).inspect_err(|_| ACTIVE.store(false, SeqCst))
            }
            #[cfg(not(target_arch = "x86"))]
            { let _ = (slot, handler); Err($crate::hook::HookError::Unsupported) }
        }

        /// Patches the start of `function`, whose first bytes must be
        /// exactly `prologue` (>= 5 bytes of self-contained instructions).
        pub fn install_inline(
            function: u32,
            prologue: &[u8],
            handler: impl Fn(&Call) -> $ret + Send + Sync + 'static,
        ) -> Result<Installed, $crate::hook::HookError> {
            #[cfg(target_arch = "x86")]
            {
                claim()?;
                let result = (|| {
                    $crate::hook::InlinePatch::check(function, prologue)?;
                    // Handler first: the jump may be taken the moment it
                    // is written. Until ORIGINAL is set, the trampoline
                    // cannot be reached (the jump is not written yet).
                    *HANDLER.write().unwrap_or_else(|e| e.into_inner()) = Some(Box::new(handler));
                    $crate::hook::InlinePatch::install(function, prologue, trampoline as usize as u32, |t| {
                        ORIGINAL.store(t, SeqCst)
                    })
                })();
                result.map(|p| Installed(Some(Patch::Inline(p)))).inspect_err(|_| {
                    *HANDLER.write().unwrap_or_else(|e| e.into_inner()) = None;
                    ACTIVE.store(false, SeqCst);
                })
            }
            #[cfg(not(target_arch = "x86"))]
            { let _ = (function, prologue, handler); Err($crate::hook::HookError::Unsupported) }
        }

        /// Patches the start of `function`: like `install_inline` if it
        /// begins with `prologue`, like `install_over_jmp` if another mod
        /// (e.g. a newer release of it) redirects it with a `jmp rel32`.
        pub fn install_at_start(
            function: u32,
            prologue: &[u8],
            handler: impl Fn(&Call) -> $ret + Send + Sync + 'static,
        ) -> Result<Installed, $crate::hook::HookError> {
            let first = $crate::mem::Ptr32::<u8>::new(function).read()?;
            if first == 0xE9 && prologue.first() != Some(&0xE9) {
                install_over_jmp(function, handler)
            } else {
                install_inline(function, prologue, handler)
            }
        }

        /// Hooks a function another mod already redirects with a `jmp rel32`
        /// at its start (see `InlinePatch::install_over_jmp`).
        pub fn install_over_jmp(
            function: u32,
            handler: impl Fn(&Call) -> $ret + Send + Sync + 'static,
        ) -> Result<Installed, $crate::hook::HookError> {
            #[cfg(target_arch = "x86")]
            {
                claim()?;
                *HANDLER.write().unwrap_or_else(|e| e.into_inner()) = Some(Box::new(handler));
                let result = $crate::hook::InlinePatch::install_over_jmp(function, trampoline as usize as u32, |t| {
                    ORIGINAL.store(t, SeqCst)
                });
                result.map(|p| Installed(Some(Patch::Inline(p)))).inspect_err(|_| {
                    *HANDLER.write().unwrap_or_else(|e| e.into_inner()) = None;
                    ACTIVE.store(false, SeqCst);
                })
            }
            #[cfg(not(target_arch = "x86"))]
            { let _ = (function, handler); Err($crate::hook::HookError::Unsupported) }
        }
    };
}

/// Like [`fastcall_hook!`] for `__stdcall` functions (Win32 APIs, callee
/// pops the stack arguments):
///
/// ```ignore
/// inproc::stdcall_hook! {
///     pub mod text_out(hdc, x, y, text, len) -> i32;
/// }
/// ```
#[macro_export]
macro_rules! stdcall_hook {
    ($(#[$m:meta])* $vis:vis mod $name:ident($($arg:ident),*) -> $ret:ty;) => {
        $(#[$m])*
        $vis mod $name {
            #![allow(unsafe_code, dead_code, unused_imports)]
            use super::*;

            /// One invocation of the hooked function.
            pub struct Call {
                $(pub $arg: u32,)*
                original: u32,
            }

            impl Call {
                /// Runs the original function with the same arguments.
                pub fn original(&self) -> $ret {
                    self.original_with($(self.$arg),*)
                }

                /// Runs the original function with other arguments.
                pub fn original_with(&self, $($arg: u32),*) -> $ret {
                    #[cfg(target_arch = "x86")]
                    {
                        type Raw = extern "stdcall" fn($($crate::__ident_u32!($arg)),*) -> $ret;
                        // SAFETY: `original` is the hooked function, whose
                        // signature is this macro invocation's contract.
                        let f: Raw = unsafe { ::core::mem::transmute::<usize, Raw>(self.original as usize) };
                        f($($arg),*)
                    }
                    #[cfg(not(target_arch = "x86"))]
                    { let _ = ($($arg),*); unreachable!("hooks only run in 32-bit x86 processes") }
                }
            }

            #[cfg(target_arch = "x86")]
            extern "stdcall" fn trampoline($($arg: u32),*) -> $ret {
                let call = Call { $($arg,)* original: ORIGINAL.load(SeqCst) };
                let guard = HANDLER.read().unwrap_or_else(|e| e.into_inner());
                let Some(handler) = guard.as_ref() else { return call.original() };
                match ::std::panic::catch_unwind(::std::panic::AssertUnwindSafe(|| handler(&call))) {
                    Ok(r) => r,
                    Err(_) => {
                        ::log::error!(concat!("hook ", stringify!($name), " panicked; calling original"));
                        call.original()
                    }
                }
            }

            $crate::__hook_common!($name, $ret);
        }
    };
}
