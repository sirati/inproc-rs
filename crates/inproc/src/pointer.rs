//! What a module of the foreign program learns of the pointer and of the
//! keyboard focus from the system (`GetCursorPos`, `GetFocus`), overridable:
//! for driving a program whose real pointer is elsewhere (e.g. over another
//! window showing the program's picture) where it polls these rather than
//! reading the mouse messages it is posted — a game scrolling its map while
//! its pointer rests at its screen's edge.
//!
//! [`hook_cursor_pos`] and [`hook_focus`] redirect a module's imports of the
//! two functions; while an [`Override`] is [`set`], they answer with it, else
//! the system's answer passes through unchanged.
//!
//! [`hook_set_cursor`] watches which pointer a module shows (`SetCursor`):
//! [`last_set_cursor`] tells, [`standard_cursor`] names it if it is one of
//! the system's own.

use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};

use crate::hook::HookError;
use crate::mem::Ptr32;
use crate::window::Window;

crate::stdcall_hook! {
    /// `BOOL GetCursorPos(LPPOINT)`.
    mod get_cursor_pos(point) -> i32;
}

crate::stdcall_hook! {
    /// `HWND GetFocus(void)`.
    mod get_focus() -> u32;
}

crate::stdcall_hook! {
    /// `HCURSOR SetCursor(HCURSOR)`.
    mod set_cursor(cursor) -> u32;
}

/// The pointer at client position (`x`, `y`) of `window`, which has the
/// keyboard focus.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Override {
    pub window: Window,
    pub x: i32,
    pub y: i32,
}

static OVERRIDE: Mutex<Option<Override>> = Mutex::new(None);

/// Sets (or with `None` ends) the override the hooked imports answer with.
pub fn set(o: Option<Override>) {
    *OVERRIDE.lock().unwrap_or_else(|e| e.into_inner()) = o;
}

fn current() -> Option<Override> {
    *OVERRIDE.lock().unwrap_or_else(|e| e.into_inner())
}

/// A redirected import; restored when dropped.
pub struct Hook(Hooked);

enum Hooked {
    CursorPos(#[allow(dead_code)] get_cursor_pos::Installed),
    Focus(#[allow(dead_code)] get_focus::Installed),
    SetCursor(#[allow(dead_code)] set_cursor::Installed),
}

impl std::fmt::Debug for Hook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self.0 {
            Hooked::CursorPos(_) => "Hook(GetCursorPos)",
            Hooked::Focus(_) => "Hook(GetFocus)",
            Hooked::SetCursor(_) => "Hook(SetCursor)",
        })
    }
}

/// The import slot of `user32!function` in `module` (base address).
fn slot(module: u32, function: &str) -> Result<Option<Ptr32<u32>>, HookError> {
    Ok(crate::pe::import_slot(module, "USER32.dll", function)?)
}

/// Redirects `module`'s `GetCursorPos` import: under an override it reports
/// the override's point (in screen coordinates, as the system does).
/// `None` if the module does not import it. Once per process.
pub fn hook_cursor_pos(module: u32) -> Result<Option<Hook>, HookError> {
    let Some(slot) = slot(module, "GetCursorPos")? else { return Ok(None) };
    let installed = get_cursor_pos::install_slot(slot, |call| {
        let Some(o) = current() else { return call.original() };
        let Some(screen) = o.window.client_to_screen(o.x, o.y) else { return call.original() };
        // A bad buffer fails as the system's own call would.
        match Ptr32::<[i32; 2]>::new(call.point).write(&[screen.0, screen.1]) {
            Ok(()) => 1,
            Err(_) => 0,
        }
    })?;
    Ok(Some(Hook(Hooked::CursorPos(installed))))
}

/// Redirects `module`'s `GetFocus` import: under an override it reports the
/// override's window. `None` if the module does not import it. Once per
/// process.
pub fn hook_focus(module: u32) -> Result<Option<Hook>, HookError> {
    let Some(slot) = slot(module, "GetFocus")? else { return Ok(None) };
    let installed = get_focus::install_slot(slot, |call| match current() {
        Some(o) => o.window.handle(),
        None => call.original(),
    })?;
    Ok(Some(Hook(Hooked::Focus(installed))))
}

/// The cursor handle last set through a hooked `SetCursor` (0: none yet,
/// or the pointer hidden).
static LAST_SET: AtomicU32 = AtomicU32::new(0);

/// Watches `module`'s `SetCursor` import: the handle it sets is kept for
/// [`last_set_cursor`] (the call goes on unchanged). `None` if the module
/// does not import it. Once per process.
pub fn hook_set_cursor(module: u32) -> Result<Option<Hook>, HookError> {
    let Some(slot) = slot(module, "SetCursor")? else { return Ok(None) };
    let installed = set_cursor::install_slot(slot, |call| {
        LAST_SET.store(call.cursor, Ordering::Relaxed);
        call.original()
    })?;
    Ok(Some(Hook(Hooked::SetCursor(installed))))
}

/// The cursor handle the watched module set last ([`hook_set_cursor`]),
/// if any.
pub fn last_set_cursor() -> Option<u32> {
    Some(LAST_SET.load(Ordering::Relaxed)).filter(|&h| h != 0)
}

/// The system's standard pointers, by resource id (`IDC_*`).
pub const IDC_ARROW: u16 = 32512;
pub const IDC_IBEAM: u16 = 32513;
pub const IDC_WAIT: u16 = 32514;
pub const IDC_CROSS: u16 = 32515;
pub const IDC_SIZENWSE: u16 = 32642;
pub const IDC_SIZENESW: u16 = 32643;
pub const IDC_SIZEWE: u16 = 32644;
pub const IDC_SIZENS: u16 = 32645;
pub const IDC_SIZEALL: u16 = 32646;
pub const IDC_NO: u16 = 32648;
pub const IDC_HAND: u16 = 32649;
pub const IDC_APPSTARTING: u16 = 32650;

/// Which of the system's standard pointers (`IDC_*` above) cursor
/// `handle` is, if it is one (shared handles: what `LoadCursor(NULL, id)`
/// gives every caller).
pub fn standard_cursor(handle: u32) -> Option<u16> {
    use windows_sys::Win32::UI::WindowsAndMessaging::LoadCursorW;
    const IDS: [u16; 12] =
        [IDC_ARROW, IDC_IBEAM, IDC_WAIT, IDC_CROSS, IDC_SIZENWSE, IDC_SIZENESW, IDC_SIZEWE, IDC_SIZENS, IDC_SIZEALL, IDC_NO, IDC_HAND, IDC_APPSTARTING];
    IDS.into_iter().find(|&id| {
        // SAFETY: a system cursor by resource id (`MAKEINTRESOURCE`), no
        // module: reads nothing of ours; a null result is no match.
        let h = unsafe { LoadCursorW(std::ptr::null_mut(), id as usize as *const u16) };
        !h.is_null() && h as usize as u32 == handle
    })
}
