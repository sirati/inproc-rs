//! Safe building blocks for code that lives inside someone else's process.
//!
//! A DLL injected into a game must read memory it does not own, whose layout
//! it only knows from reverse engineering, while the game's own threads keep
//! writing it. Dereferencing such pointers directly is unsound in Rust (they
//! may be dangling, misaligned, or concurrently written). This crate keeps
//! all of that behind three safe interfaces:
//!
//! * [`mem`]: copy plain-old-data out of foreign memory. Copies go through
//!   the kernel (`ReadProcessMemory` on our own process), so an invalid
//!   address is an `Err`, never a crash, and a concurrent write can at worst
//!   produce a stale or mixed value, never undefined behaviour.
//! * [`hook`]: replace a function pointer in a vtable (or any pointer-sized
//!   slot) and restore it when the guard is dropped.
//! * [`entry!`]: the DLL entry point, which runs the client's initialisation
//!   on a fresh thread, outside the loader lock, with panics caught.
//!
//! Everything `unsafe` in the project's Windows interop lives in this crate.
#![cfg_attr(not(windows), allow(dead_code, unused))]

pub mod hook;
pub mod logging;
pub mod mem;
#[cfg(windows)]
#[doc(hidden)]
pub mod dll;

pub use logging::log_to_file;
pub use mem::{MemError, Ptr32};

/// Defines the DLL's entry point. `init` runs once, on its own thread, after
/// the DLL is loaded; panics in it are caught and logged.
///
/// ```ignore
/// inproc::entry!(my_init);
/// fn my_init() { /* ... */ }
/// ```
#[macro_export]
macro_rules! entry {
    ($init:path) => {
        #[cfg(windows)]
        #[doc(hidden)]
        #[allow(unsafe_code)]
        #[unsafe(no_mangle)]
        pub extern "system" fn DllMain(
            module: *mut ::core::ffi::c_void,
            reason: u32,
            reserved: *mut ::core::ffi::c_void,
        ) -> i32 {
            $crate::dll::dll_main(module, reason, reserved, $init)
        }
    };
}
