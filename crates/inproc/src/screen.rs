//! What a module of the foreign program learns of the screen's size from
//! the system (`GetSystemMetrics` with `SM_CXSCREEN` / `SM_CYSCREEN`),
//! overridable: for running a program that sizes itself to the desktop at a
//! fraction of it (a desktop scaled 2×: the program at its logical size,
//! shown 2× elsewhere).
//!
//! [`hook_scaled`] redirects a module's import of `GetSystemMetrics`.

use std::sync::OnceLock;

use crate::hook::HookError;

crate::stdcall_hook! {
    /// `int GetSystemMetrics(int)` of a first module.
    mod get_system_metrics(index) -> i32;
}

crate::stdcall_hook! {
    /// The same of a second module.
    mod get_system_metrics_2(index) -> i32;
}

const SM_CXSCREEN: u32 = 0;
const SM_CYSCREEN: u32 = 1;

/// A redirected import; restored when dropped.
pub struct Hook(#[allow(dead_code)] Installed);

enum Installed {
    First(#[allow(dead_code)] get_system_metrics::Installed),
    Second(#[allow(dead_code)] get_system_metrics_2::Installed),
}

impl std::fmt::Debug for Hook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Hook(GetSystemMetrics)")
    }
}

/// The screen's size as reported, once asked for (shared by every module
/// redirected: they all learn the same size).
static SIZE: OnceLock<(i32, i32)> = OnceLock::new();

/// The primary display's mode in its own pixels (`EnumDisplaySettingsW`'s
/// current settings: whatever the caller's DPI awareness, unlike
/// `GetSystemMetrics`, which a DPI-unaware thread gets in logical pixels).
fn display_mode() -> Option<(i32, i32)> {
    use windows_sys::Win32::Graphics::Gdi::{DEVMODEW, ENUM_CURRENT_SETTINGS, EnumDisplaySettingsW};
    // SAFETY: DEVMODEW is plain data; zeroed with its size set is how the
    // call wants it.
    let mut mode: DEVMODEW = unsafe { std::mem::zeroed() };
    mode.dmSize = std::mem::size_of::<DEVMODEW>() as u16;
    // SAFETY: NULL names the primary display; `mode` is written in place.
    let ok = unsafe { EnumDisplaySettingsW(std::ptr::null(), ENUM_CURRENT_SETTINGS, &mut mode) } != 0;
    (ok && mode.dmPelsWidth > 0 && mode.dmPelsHeight > 0).then_some((mode.dmPelsWidth as i32, mode.dmPelsHeight as i32))
}

/// The primary display's mode now (its own pixels), if the system tells.
pub fn current_mode() -> Option<(u32, u32)> {
    display_mode().map(|(w, h)| (w as u32, h as u32))
}

/// The sizes the primary display offers (its modes: those a program may
/// switch it to, Wine's emulated ones included), each once.
pub fn display_modes() -> Vec<(u32, u32)> {
    use windows_sys::Win32::Graphics::Gdi::{DEVMODEW, EnumDisplaySettingsW};
    let mut out: Vec<(u32, u32)> = Vec::new();
    for i in 0..4096 {
        // SAFETY: as in `display_mode`; mode `i` of the primary display.
        let mut mode: DEVMODEW = unsafe { std::mem::zeroed() };
        mode.dmSize = std::mem::size_of::<DEVMODEW>() as u16;
        if unsafe { EnumDisplaySettingsW(std::ptr::null(), i, &mut mode) } == 0 {
            break;
        }
        let size = (mode.dmPelsWidth, mode.dmPelsHeight);
        if size.0 > 0 && size.1 > 0 && !out.contains(&size) {
            out.push(size);
        }
    }
    out
}

/// What a redirected module learns of the screen: `size` of the display's
/// mode (its own pixels).
pub type ScreenSize = std::sync::Arc<dyn Fn((i32, i32)) -> (i32, i32) + Send + Sync>;

/// Redirects `module`'s `GetSystemMetrics` import so that it reports the
/// primary screen as `size` makes it of the display's mode when first
/// asked (in its own pixels, the program's DPI awareness aside; else as the
/// system says it), from then on: once the program switched the display to
/// that size (Wine emulates such modes) it must not be made smaller again.
/// Other metrics pass through. `None` if the module does not import it.
/// For up to two modules of a process (e.g. a program and the library that
/// makes its window), all learning the same size; safe to call from
/// `DllMain` (no library is loaded).
pub fn hook_scaled(module: u32, size: ScreenSize) -> Result<Option<Hook>, HookError> {
    use windows_sys::Win32::UI::WindowsAndMessaging::GetSystemMetrics;
    let Some(slot) = crate::pe::import_slot(module, "USER32.dll", "GetSystemMetrics")? else { return Ok(None) };
    let scaled = move |index: u32, original: &dyn Fn() -> i32| {
        let axis = match index {
            SM_CXSCREEN => 0,
            SM_CYSCREEN => 1,
            _ => return original(),
        };
        let (w, h) = match SIZE.get() {
            Some(&known) => known,
            None => {
                // SAFETY: plain queries of the screen's size.
                let full = display_mode().unwrap_or_else(|| unsafe { (GetSystemMetrics(SM_CXSCREEN as i32), GetSystemMetrics(SM_CYSCREEN as i32)) });
                let (w, h) = size(full);
                // (A thread racing this one computed the same; the first stays.)
                let _ = SIZE.set((w.max(1), h.max(1)));
                *SIZE.get().unwrap_or(&(w.max(1), h.max(1)))
            }
        };
        if axis == 0 { w } else { h }
    };
    // Each of the two hook modules claims itself once; the first free one
    // takes this module.
    let first = scaled.clone();
    let installed = match get_system_metrics::install_slot(slot, move |call| first(call.index, &|| call.original())) {
        Err(HookError::AlreadyInstalled) => Installed::Second(get_system_metrics_2::install_slot(slot, move |call| scaled(call.index, &|| call.original()))?),
        first => Installed::First(first?),
    };
    Ok(Some(Hook(installed)))
}
