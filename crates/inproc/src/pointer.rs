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

use std::sync::Mutex;

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
}

impl std::fmt::Debug for Hook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self.0 {
            Hooked::CursorPos(_) => "Hook(GetCursorPos)",
            Hooked::Focus(_) => "Hook(GetFocus)",
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
