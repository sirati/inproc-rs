//! Painting a window that is hidden: a program that draws its screen when
//! told to paint (`WM_PAINT`, `BeginPaint`) goes on drawing it while its
//! window is hidden (its picture is wanted elsewhere, e.g. by hooks on its
//! drawing), though the system sends hidden windows no paint messages.
//!
//! [`hook_hidden_painting`] redirects a module's imports of
//! `InvalidateRect` and `BeginPaint`: what it invalidates of a hidden
//! window is kept, a `WM_PAINT` posted for it, and the `BeginPaint` of that
//! paint reports the kept area as the one to paint (the system's would be
//! empty). Visible windows are painted by the system as always.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::hook::HookError;
use crate::mem::Ptr32;
use crate::window::Window;

crate::stdcall_hook! {
    /// `BOOL InvalidateRect(HWND, const RECT *, BOOL)`.
    mod invalidate_rect(hwnd, rect, erase) -> i32;
}

crate::stdcall_hook! {
    /// `HDC BeginPaint(HWND, PAINTSTRUCT *)`.
    mod begin_paint(hwnd, paint) -> u32;
}

/// Per hidden window (its handle): the area to paint (left, top, right,
/// bottom), with a `WM_PAINT` posted for it.
static PENDING: Mutex<Option<HashMap<u32, [i32; 4]>>> = Mutex::new(None);

/// Adds `rect` to what `window` has to paint; posts a paint message unless
/// one is waiting already.
fn invalidate(window: Window, rect: [i32; 4]) {
    if rect[2] <= rect[0] || rect[3] <= rect[1] {
        return;
    }
    let mut pending = PENDING.lock().unwrap_or_else(|e| e.into_inner());
    let pending = pending.get_or_insert_with(HashMap::new);
    match pending.get_mut(&window.handle()) {
        Some(r) => *r = [r[0].min(rect[0]), r[1].min(rect[1]), r[2].max(rect[2]), r[3].max(rect[3])],
        None => {
            pending.insert(window.handle(), rect);
            window.post_paint();
        }
    }
}

/// The whole client area of `window`.
fn client(window: Window) -> Option<[i32; 4]> {
    window.client_size().map(|(w, h)| [0, 0, w as i32, h as i32])
}

/// Has hidden `window` paint all of itself (e.g. just after hiding it).
pub fn repaint(window: Window) {
    if let Some(r) = client(window) {
        invalidate(window, r);
    }
}

/// The redirected imports; restored when dropped.
pub struct Hooks(#[allow(dead_code)] invalidate_rect::Installed, #[allow(dead_code)] begin_paint::Installed);

impl std::fmt::Debug for Hooks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Hooks(InvalidateRect, BeginPaint)")
    }
}

/// Redirects `module`'s `InvalidateRect` and `BeginPaint` imports so that
/// its hidden windows are painted as if shown (see the module docs).
/// `None` if it does not import both. Once per process.
pub fn hook_hidden_painting(module: u32) -> Result<Option<Hooks>, HookError> {
    let slot = |f| crate::pe::import_slot(module, "USER32.dll", f);
    let (Some(invalidate_slot), Some(begin_slot)) = (slot("InvalidateRect")?, slot("BeginPaint")?) else { return Ok(None) };
    let invalidated = invalidate_rect::install_slot(invalidate_slot, |call| {
        let r = call.original();
        let window = Window::from_handle(call.hwnd);
        if call.hwnd != 0 && !window.is_visible() {
            let rect = match call.rect {
                0 => client(window),
                at => Ptr32::<[i32; 4]>::new(at).read().ok(),
            };
            if let Some(rect) = rect {
                invalidate(window, rect);
            }
        }
        r
    })?;
    let begun = begin_paint::install_slot(begin_slot, |call| {
        let dc = call.original();
        let pending = PENDING.lock().unwrap_or_else(|e| e.into_inner()).as_mut().and_then(|p| p.remove(&call.hwnd));
        if let (Some(rect), false) = (pending, Window::from_handle(call.hwnd).is_visible()) {
            // PAINTSTRUCT: hdc, fErase, then rcPaint.
            let _ = Ptr32::<[i32; 4]>::new(call.paint).offset::<[i32; 4]>(8).and_then(|p| p.write(&rect));
        }
        dc
    })?;
    Ok(Some(Hooks(invalidated, begun)))
}
