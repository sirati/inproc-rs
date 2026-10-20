//! What a module of the foreign program learns of the pointer and of the
//! keyboard focus from the system (`GetCursorPos`, `GetFocus`), overridable:
//! for driving a program whose real pointer is elsewhere (e.g. over another
//! window showing the program's picture) where it polls these rather than
//! reading the mouse messages it is posted — a game scrolling its map while
//! its pointer rests at its screen's edge.
//!
//! [`hook_cursor_pos`] and [`hook_focus`] redirect a module's imports of the
//! two functions; while an [`Override`] is [`set`], they answer with it, else
//! the system's answer passes through unchanged, but for the focus of a
//! window kept hidden ([`keep_focus`]).
//!
//! [`hook_set_cursor`] watches which pointer a module shows (`SetCursor`):
//! [`last_set_cursor`] tells, [`standard_cursor`] names it if it is one of
//! the system's own. While the module's windows are kept hidden
//! (`crate::hidden`) it never hides the system pointer (`SetCursor(NULL)`,
//! [`hook_show_cursor`]): another window shows the program, and the pointer
//! there is that window's (Wine's macOS driver hides the pointer for the
//! whole application, a viewer in the same process included).
//!
//! For our own windows: [`Confinement`] clips the system pointer to a
//! rectangle; [`cursor_base_size`] and [`cursor_metric_size`] tell the
//! user's pointer size.

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

crate::stdcall_hook! {
    /// `int ShowCursor(BOOL)`.
    mod show_cursor(show) -> i32;
}

/// The pointer at client position (`x`, `y`) of `window`, which has the
/// keyboard focus.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Override {
    pub window: Window,
    pub x: i32,
    pub y: i32,
}

/// Read by the hooked imports on the game's thread without waiting.
static OVERRIDE: civ3r_sync::Latest<Override> = civ3r_sync::Latest::new();

/// Sets (or with `None` ends) the override the hooked imports answer with.
pub fn set(o: Option<Override>) {
    match o {
        Some(o) => OVERRIDE.publish(o),
        None => OVERRIDE.clear(),
    }
}

fn current() -> Option<Override> {
    OVERRIDE.get()
}

/// The kept window's handle, 0 for none.
static KEPT_FOCUS: AtomicU32 = AtomicU32::new(0);

/// Has `GetFocus` report `window` (`None`: no longer) while the system says
/// no window has the focus: for a window kept hidden that still takes the
/// keyboard (posted to it), a hidden window never having the focus.
pub fn keep_focus(window: Option<Window>) {
    KEPT_FOCUS.store(window.map_or(0, |w| w.handle()), Ordering::Release);
}

/// A redirected import; restored when dropped.
pub struct Hook(Hooked);

enum Hooked {
    CursorPos(#[allow(dead_code)] get_cursor_pos::Installed),
    Focus(#[allow(dead_code)] get_focus::Installed),
    SetCursor(#[allow(dead_code)] set_cursor::Installed),
    ShowCursor(#[allow(dead_code)] show_cursor::Installed),
}

impl std::fmt::Debug for Hook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self.0 {
            Hooked::CursorPos(_) => "Hook(GetCursorPos)",
            Hooked::Focus(_) => "Hook(GetFocus)",
            Hooked::SetCursor(_) => "Hook(SetCursor)",
            Hooked::ShowCursor(_) => "Hook(ShowCursor)",
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
/// override's window; with no window focused, the one [`keep_focus`] keeps.
/// `None` if the module does not import it. Once per process.
pub fn hook_focus(module: u32) -> Result<Option<Hook>, HookError> {
    let Some(slot) = slot(module, "GetFocus")? else { return Ok(None) };
    let installed = get_focus::install_slot(slot, |call| match current() {
        Some(o) => o.window.handle(),
        None => match call.original() {
            0 => KEPT_FOCUS.load(Ordering::Acquire),
            focused => focused,
        },
    })?;
    Ok(Some(Hook(Hooked::Focus(installed))))
}

/// The cursor handle last set through a hooked `SetCursor` (0: none yet,
/// or the pointer hidden).
static LAST_SET: AtomicU32 = AtomicU32::new(0);

/// Watches `module`'s `SetCursor` import: the handle it sets is kept for
/// [`last_set_cursor`]; the call goes on, but for hiding the pointer while
/// the module's windows are kept hidden ([`keeps_pointer_shown`]: then it
/// only answers with the handle set before). `None` if the module does not
/// import it. Once per process.
pub fn hook_set_cursor(module: u32) -> Result<Option<Hook>, HookError> {
    let Some(slot) = slot(module, "SetCursor")? else { return Ok(None) };
    let installed = set_cursor::install_slot(slot, |call| {
        let before = LAST_SET.swap(call.cursor, Ordering::Relaxed);
        if call.cursor == 0 && keeps_pointer_shown() {
            return before;
        }
        call.original()
    })?;
    Ok(Some(Hook(Hooked::SetCursor(installed))))
}

/// The display count `ShowCursor` answers with while its calls are kept
/// from the system (0: shown, as the system starts with a mouse).
static SHOW_COUNT: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);

/// Redirects `module`'s `ShowCursor` import: while the module's windows are
/// kept hidden ([`keeps_pointer_shown`]) the system pointer stays as it is,
/// the display count the module sees kept here. `None` if the module does
/// not import it. Once per process.
pub fn hook_show_cursor(module: u32) -> Result<Option<Hook>, HookError> {
    let Some(slot) = slot(module, "ShowCursor")? else { return Ok(None) };
    let installed = show_cursor::install_slot(slot, |call| {
        if !keeps_pointer_shown() {
            return call.original();
        }
        let by = if call.show != 0 { 1 } else { -1 };
        SHOW_COUNT.fetch_add(by, Ordering::Relaxed) + by
    })?;
    Ok(Some(Hook(Hooked::ShowCursor(installed))))
}

/// Whether the module's hiding of the system pointer is kept from the
/// system: while its windows are kept hidden, where the pointer the user
/// sees is never over them.
pub fn keeps_pointer_shown() -> bool {
    crate::hidden::hiding()
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


/// A rectangular system-pointer confinement in screen coordinates,
/// `[left, top, right, bottom]`. Releasing or dropping it only removes the
/// rectangle this instance installed, so a later clip from another window
/// is left alone. The caller releases before losing focus or handing the
/// pointer to another capture mechanism.
#[derive(Default)]
pub struct Confinement {
    screen: Option<[i32; 4]>,
}

impl Confinement {
    /// Installs a nonempty rectangle, or releases with `None`. Returns
    /// whether a requested rectangle was installed successfully.
    pub fn set(&mut self, screen: Option<[i32; 4]>) -> bool {
        use windows_sys::Win32::Foundation::RECT;
        use windows_sys::Win32::UI::WindowsAndMessaging::ClipCursor;
        let Some(screen) = screen.filter(|r| r[2] > r[0] && r[3] > r[1]) else { self.release(); return false };
        if self.screen == Some(screen) { return true; }
        let rect = RECT { left: screen[0], top: screen[1], right: screen[2], bottom: screen[3] };
        // SAFETY: ClipCursor reads a valid RECT for the duration of this call.
        if unsafe { ClipCursor(&rect) } != 0 {
            self.screen = Some(screen);
            return true;
        }
        false
    }

    /// Releases this instance's rectangle, unless another window has
    /// already replaced the global clip with its own rectangle.
    pub fn release(&mut self) {
        use windows_sys::Win32::Foundation::RECT;
        use windows_sys::Win32::UI::WindowsAndMessaging::{ClipCursor, GetClipCursor};
        let Some(screen) = self.screen.take() else { return };
        let mut current = RECT::default();
        // SAFETY: GetClipCursor writes one valid RECT; null releases the clip.
        unsafe {
            if GetClipCursor(&mut current) != 0 && [current.left, current.top, current.right, current.bottom] == screen {
                ClipCursor(std::ptr::null());
            }
        }
    }
}

impl Drop for Confinement {
    fn drop(&mut self) { self.release(); }
}

/// The user's pointer size at 96 DPI, in pixels: the accessibility
/// setting `HKCU\Control Panel\Cursors\CursorBaseSize` (a DWORD; Windows
/// writes it once the size is changed, 32 being the default). `None` when
/// it is absent or not a positive DWORD.
pub fn cursor_base_size() -> Option<u32> {
    use windows_sys::Win32::System::Registry::{HKEY_CURRENT_USER, RRF_RT_REG_DWORD, RegGetValueW};
    let key: Vec<u16> = "Control Panel\\Cursors\0".encode_utf16().collect();
    let value: Vec<u16> = "CursorBaseSize\0".encode_utf16().collect();
    let mut data = 0u32;
    let mut size = std::mem::size_of::<u32>() as u32;
    // SAFETY: both names are NUL-terminated UTF-16 that outlive the call;
    // RRF_RT_REG_DWORD restricts the value to 4 bytes, the size of `data`
    // as told in `size`; a null type pointer is permitted.
    let status = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            key.as_ptr(),
            value.as_ptr(),
            RRF_RT_REG_DWORD,
            std::ptr::null_mut(),
            (&mut data as *mut u32).cast(),
            &mut size,
        )
    };
    (status == 0 && data > 0).then_some(data)
}

/// The system's cursor width metric (`SM_CXCURSOR`) at 96 DPI, in pixels.
pub fn cursor_metric_size() -> Option<u32> {
    use windows_sys::Win32::UI::HiDpi::GetSystemMetricsForDpi;
    use windows_sys::Win32::UI::WindowsAndMessaging::SM_CXCURSOR;
    // SAFETY: a value query without pointers; 0 means failure.
    let size = unsafe { GetSystemMetricsForDpi(SM_CXCURSOR, 96) };
    u32::try_from(size).ok().filter(|&s| s > 0)
}
