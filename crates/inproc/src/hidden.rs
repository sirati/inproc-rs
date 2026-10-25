//! Keeping a module's top-level windows hidden from the start: real windows
//! (they take posted input, have a client area, paint into their DC), but
//! never shown, so a windowing system shows nothing of them (no task bar
//! or switcher entry, nothing on screen), and never made fullscreen by it.
//!
//! [`hook_hidden_windows`] redirects a module's imports of `CreateWindowExA`
//! (made without `WS_VISIBLE`), `ShowWindow` (hides instead) and
//! `SetWindowPos` (without `SWP_SHOWWINDOW`), for top-level windows, while
//! hiding is on ([`set_hiding`], on at first).

use std::sync::atomic::{AtomicBool, Ordering};

use crate::hook::HookError;
use crate::window::Window;

crate::stdcall_hook! {
    /// `HWND CreateWindowExA(DWORD, LPCSTR, LPCSTR, DWORD, int, int, int,
    /// int, HWND, HMENU, HINSTANCE, LPVOID)`.
    mod create_window_ex_a(ex_style, class, title, style, x, y, w, h, parent, menu, instance, param) -> u32;
}

crate::stdcall_hook! {
    /// The same of a second module.
    mod create_window_ex_a_2(ex_style, class, title, style, x, y, w, h, parent, menu, instance, param) -> u32;
}

crate::stdcall_hook! {
    /// `BOOL ShowWindow(HWND, int)`.
    mod show_window(hwnd, show) -> i32;
}

crate::stdcall_hook! {
    /// `BOOL SetWindowPos(HWND, HWND, int, int, int, int, UINT)`.
    mod set_window_pos(hwnd, after, x, y, w, h, flags) -> i32;
}

const WS_CHILD: u32 = 0x4000_0000;
const WS_VISIBLE: u32 = 0x1000_0000;
const SW_HIDE: u32 = 0;
const SWP_SHOWWINDOW: u32 = 0x40;

static HIDING: AtomicBool = AtomicBool::new(true);

/// Turns hiding on or off (e.g. off when what was to show the program
/// instead failed). Windows hidden so far stay hidden.
pub fn set_hiding(on: bool) {
    HIDING.store(on, Ordering::SeqCst);
}

/// Whether windows are kept hidden.
pub fn hiding() -> bool {
    HIDING.load(Ordering::SeqCst)
}

/// The `ShowWindow` command a window gets for `show`: `SW_HIDE` for a
/// top-level window while hiding.
pub fn show_command(hwnd: u32, show: u32) -> u32 {
    let hide = hiding() && show != SW_HIDE && Window::from_handle(hwnd).is_top_level();
    if hide { SW_HIDE } else { show }
}

/// The redirected imports; restored when dropped.
pub struct Hooks(Vec<Installed>);

#[allow(dead_code)]
enum Installed {
    Create(create_window_ex_a::Installed),
    Create2(create_window_ex_a_2::Installed),
    Show(show_window::Installed),
    Pos(set_window_pos::Installed),
}

impl std::fmt::Debug for Hooks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Hooks({} of CreateWindowExA, ShowWindow, SetWindowPos)", self.0.len())
    }
}

/// The style a top-level window is made with: without `WS_VISIBLE` while
/// hiding.
fn hidden_style(style: u32, parent: u32) -> u32 {
    let top_level = parent == 0 || style & WS_CHILD == 0;
    if hiding() && top_level { style & !WS_VISIBLE } else { style }
}

/// Redirects `module`'s imports of `CreateWindowExA`, `ShowWindow` and
/// `SetWindowPos` (those it has) so that its top-level windows stay hidden
/// (see the module docs). `None` if it imports none of them. For up to two
/// modules' `CreateWindowExA`, one module's others (an import redirected
/// already fails with `HookError::AlreadyInstalled`).
pub fn hook_hidden_windows(module: u32) -> Result<Option<Hooks>, HookError> {
    let slot = |f| crate::pe::import_slot(module, "USER32.dll", f);
    let mut hooks = Vec::new();
    if let Some(s) = slot("CreateWindowExA")? {
        let first = create_window_ex_a::install_slot(s, |c| {
            let style = hidden_style(c.style, c.parent);
            c.original_with(c.ex_style, c.class, c.title, style, c.x, c.y, c.w, c.h, c.parent, c.menu, c.instance, c.param)
        });
        hooks.push(match first {
            Ok(installed) => Installed::Create(installed),
            Err(HookError::AlreadyInstalled) => Installed::Create2(create_window_ex_a_2::install_slot(s, |c| {
                let style = hidden_style(c.style, c.parent);
                c.original_with(c.ex_style, c.class, c.title, style, c.x, c.y, c.w, c.h, c.parent, c.menu, c.instance, c.param)
            })?),
            Err(e) => return Err(e),
        });
    }
    if let Some(s) = slot("ShowWindow")? {
        hooks.push(Installed::Show(show_window::install_slot(s, |c| {
            c.original_with(c.hwnd, show_command(c.hwnd, c.show))
        })?));
    }
    if let Some(s) = slot("SetWindowPos")? {
        hooks.push(Installed::Pos(set_window_pos::install_slot(s, |c| {
            let flags = if hiding() && Window::from_handle(c.hwnd).is_top_level() { c.flags & !SWP_SHOWWINDOW } else { c.flags };
            c.original_with(c.hwnd, c.after, c.x, c.y, c.w, c.h, flags)
        })?));
    }
    Ok((!hooks.is_empty()).then_some(Hooks(hooks)))
}
