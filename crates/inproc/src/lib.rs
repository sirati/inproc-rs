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
//! * `window`: find the process's main window and post input messages to it.
//! * `pointer`: what a module of the program learns of the pointer and the
//!   keyboard focus (`GetCursorPos`, `GetFocus`), overridable.
//! * `screen`: what it learns of the screen's size (`GetSystemMetrics`),
//!   overridable.
//! * `paint`: its hidden windows painted as if shown.
//! * `hidden`: its top-level windows kept hidden from the start.
//! * `loader`: the libraries it loads, as it loads them.
//! * `wine`: whether it runs under Wine, Unix paths as its Windows ones.
//! * `dpi`: our own thread's DPI awareness, not the program's.
//! * [`entry!`]: the DLL entry point, which runs the client's initialisation
//!   on a fresh thread, outside the loader lock, with panics caught.
//!
//! Everything `unsafe` in the project's Windows interop lives in this crate.
#![cfg_attr(not(windows), allow(dead_code, unused))]

pub mod hook;
pub mod logging;
#[cfg(windows)]
pub mod message;
pub mod mem;
#[cfg(windows)]
pub mod dpi;
#[cfg(windows)]
pub mod gdi;
#[cfg(windows)]
pub mod hidden;
#[cfg(any(windows, test))]
pub mod loader;
#[cfg(windows)]
pub mod paint;
#[cfg(windows)]
pub mod pe;
#[cfg(windows)]
pub mod pointer;
#[cfg(windows)]
pub mod process;
#[cfg(windows)]
pub mod screen;
#[cfg(windows)]
pub mod window;
#[cfg(windows)]
pub mod wine;
#[cfg(windows)]
#[doc(hidden)]
pub mod dll;

pub use logging::log_to_file;
pub use mem::{MemError, Ptr32};

/// Defines the DLL's entry point. `init` runs once, on its own thread, after
/// the DLL is loaded; panics in it are caught and logged. `early`, if given,
/// runs before, in `DllMain` itself (under the loader lock: before the
/// program's own code runs on, for redirecting what it asks the system
/// first; it must not load libraries or wait for threads).
///
/// ```ignore
/// inproc::entry!(my_init);
/// fn my_init() { /* ... */ }
/// ```
#[macro_export]
macro_rules! entry {
    ($init:path) => {
        $crate::entry!($init, early = $crate::dll::nothing);
    };
    ($init:path, early = $early:path) => {
        #[cfg(windows)]
        #[doc(hidden)]
        #[allow(unsafe_code)]
        #[unsafe(no_mangle)]
        pub extern "system" fn DllMain(
            module: *mut ::core::ffi::c_void,
            reason: u32,
            reserved: *mut ::core::ffi::c_void,
        ) -> i32 {
            $crate::dll::dll_main(module, reason, reserved, $init, $early)
        }
    };
}
