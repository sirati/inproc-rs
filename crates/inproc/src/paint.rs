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

use std::sync::LazyLock;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

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

/// A hidden window's area to paint, handed from whichever thread
/// invalidates it to the window's thread painting it, without a lock.
struct Hidden {
    /// The window's handle, 0 while the entry is free.
    window: AtomicU32,
    /// A `WM_PAINT` was posted and its `BeginPaint` has not run yet.
    waiting: AtomicBool,
    /// Rectangles (left, top, right, bottom) invalidated since.
    rects: handoff::Mailbox<[i32; 4]>,
}

/// More hidden windows than a program paints.
static HIDDEN: LazyLock<[Hidden; 8]> = LazyLock::new(|| {
    std::array::from_fn(|_| Hidden { window: AtomicU32::new(0), waiting: AtomicBool::new(false), rects: handoff::Mailbox::new() })
});

fn hidden(window: u32, claim: bool) -> Option<&'static Hidden> {
    let table = &*HIDDEN;
    table.iter().find(|h| h.window.load(Ordering::Acquire) == window).or_else(|| {
        claim.then(|| table.iter().find(|h| h.window.compare_exchange(0, window, Ordering::AcqRel, Ordering::Acquire).is_ok() || h.window.load(Ordering::Acquire) == window)).flatten()
    })
}

/// Adds `rect` to what `window` has to paint; posts a paint message unless
/// one is waiting already.
fn invalidate(window: Window, rect: [i32; 4]) {
    if rect[2] <= rect[0] || rect[3] <= rect[1] {
        return;
    }
    let Some(entry) = hidden(window.handle(), true) else {
        window.post_paint();
        return;
    };
    entry.rects.send(rect);
    // Sent before the flag: a paint that cleared it drains this rect or a
    // new message is posted for it.
    if !entry.waiting.swap(true, Ordering::AcqRel) {
        window.post_paint();
    }
}

/// On the window's thread, inside `BeginPaint`: everything invalidated.
fn take_pending(window: u32) -> Option<[i32; 4]> {
    let entry = hidden(window, false)?;
    // Acquires the invalidations that set the flag before draining them.
    entry.waiting.swap(false, Ordering::AcqRel);
    entry.rects.drain().reduce(|r, n| [r[0].min(n[0]), r[1].min(n[1]), r[2].max(n[2]), r[3].max(n[3])])
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

/// After `InvalidateRect(hwnd, rect, ..)` (`rect` a `RECT*`, 0 for all
/// of the window): for a hidden window, keeps the area and posts a paint.
/// For a program that calls Windows itself, as the hooks below do it.
pub fn invalidated(hwnd: u32, rect: u32) {
    let window = Window::from_handle(hwnd);
    if hwnd != 0 && !window.is_visible() {
        let rect = match rect {
            0 => client(window),
            at => Ptr32::<[i32; 4]>::new(at).read().ok(),
        };
        if let Some(rect) = rect {
            invalidate(window, rect);
        }
    }
}

/// After `BeginPaint(hwnd, paint)` (`paint` a `PAINTSTRUCT*`): for a
/// hidden window, the area kept since becomes the paint's `rcPaint`.
pub fn begun(hwnd: u32, paint: u32) {
    let pending = take_pending(hwnd);
    if let (Some(rect), false) = (pending, Window::from_handle(hwnd).is_visible()) {
        // PAINTSTRUCT: hdc, fErase, then rcPaint.
        let _ = Ptr32::<[i32; 4]>::new(paint).offset::<[i32; 4]>(8).and_then(|p| p.write(&rect));
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
        invalidated(call.hwnd, call.rect);
        r
    })?;
    let begun = begin_paint::install_slot(begin_slot, |call| {
        let dc = call.original();
        begun(call.hwnd, call.paint);
        dc
    })?;
    Ok(Some(Hooks(invalidated, begun)))
}
