//! The process's own windows: finding the main window, its client size, and
//! posting input messages to it as if the user had typed or clicked there.

use windows_sys::Win32::Foundation::{HWND, LPARAM, POINT, RECT, WPARAM};
use windows_sys::Win32::Graphics::Gdi::ClientToScreen;
use windows_sys::Win32::System::SystemServices::{MK_LBUTTON, MK_MBUTTON, MK_RBUTTON};
use windows_sys::Win32::System::Threading::GetCurrentProcessId;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{MAPVK_VK_TO_VSC, MapVirtualKeyW};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    EnumWindows, GetClientRect, GetWindowTextW, GetWindowThreadProcessId, IsWindowVisible,
    PostMessageW, WM_CHAR, WM_KEYDOWN, WM_KEYUP, WM_LBUTTONDOWN, WM_LBUTTONUP, WM_MBUTTONDOWN, WM_MBUTTONUP,
    WM_MOUSEMOVE, WM_MOUSEWHEEL, WM_RBUTTONDOWN, WM_RBUTTONUP,
};

/// A mouse button.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MouseButton {
    Left,
    Right,
    Middle,
}

/// Which buttons are held, for mouse messages' `wParam`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Buttons {
    pub left: bool,
    pub right: bool,
    pub middle: bool,
}

impl Buttons {
    fn flags(self) -> usize {
        (if self.left { MK_LBUTTON } else { 0 } | if self.right { MK_RBUTTON } else { 0 } | if self.middle { MK_MBUTTON } else { 0 })
            as usize
    }
}

/// A top-level window of this process. Holding one is harmless: messages to
/// a window that no longer exists are dropped by the system.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Window(isize);

fn lparam_xy(x: i32, y: i32) -> LPARAM {
    ((y as u16 as u32) << 16 | x as u16 as u32) as i32 as LPARAM
}

impl Window {
    fn hwnd(self) -> HWND {
        self.0 as HWND
    }

    /// The visible top-level windows of this process.
    pub fn of_this_process() -> Vec<Window> {
        struct Search {
            pid: u32,
            found: Vec<Window>,
        }
        unsafe extern "system" fn visit(hwnd: HWND, data: LPARAM) -> i32 {
            // SAFETY: `data` is the `&mut Search` passed to `EnumWindows`
            // below, which outlives the enumeration.
            let search = unsafe { &mut *(data as *mut Search) };
            let mut pid = 0;
            // SAFETY: plain Win32 queries on a handle the system gave us.
            unsafe { GetWindowThreadProcessId(hwnd, &mut pid) };
            if pid == search.pid && unsafe { IsWindowVisible(hwnd) } != 0 {
                search.found.push(Window(hwnd as isize));
            }
            1
        }
        // SAFETY: trivial query.
        let pid = unsafe { GetCurrentProcessId() };
        let mut search = Search { pid, found: Vec::new() };
        // SAFETY: the callback only uses `search` during this call.
        unsafe { EnumWindows(Some(visit), &mut search as *mut Search as LPARAM) };
        search.found
    }

    /// The window's title.
    pub fn title(self) -> String {
        let mut buf = [0u16; 256];
        // SAFETY: writes at most `buf.len()` units into `buf`.
        let n = unsafe { GetWindowTextW(self.hwnd(), buf.as_mut_ptr(), buf.len() as i32) };
        String::from_utf16_lossy(&buf[..n.clamp(0, buf.len() as i32) as usize])
    }

    /// Size of the client area.
    pub fn client_size(self) -> Option<(u32, u32)> {
        let mut r = RECT { left: 0, top: 0, right: 0, bottom: 0 };
        // SAFETY: writes only `r`; fails cleanly for a stale handle.
        (unsafe { GetClientRect(self.hwnd(), &mut r) } != 0)
            .then(|| ((r.right - r.left).max(0) as u32, (r.bottom - r.top).max(0) as u32))
    }

    fn post(self, message: u32, wparam: WPARAM, lparam: LPARAM) {
        // SAFETY: posting copies plain values into the target's queue.
        unsafe { PostMessageW(self.hwnd(), message, wparam, lparam) };
    }

    /// The pointer moved to client position (x, y).
    pub fn mouse_move(self, x: i32, y: i32, held: Buttons) {
        self.post(WM_MOUSEMOVE, held.flags(), lparam_xy(x, y));
    }

    /// A button went down or up at client position (x, y); `held` is the
    /// state after the change.
    pub fn mouse_button(self, button: MouseButton, down: bool, x: i32, y: i32, held: Buttons) {
        let message = match (button, down) {
            (MouseButton::Left, true) => WM_LBUTTONDOWN,
            (MouseButton::Left, false) => WM_LBUTTONUP,
            (MouseButton::Right, true) => WM_RBUTTONDOWN,
            (MouseButton::Right, false) => WM_RBUTTONUP,
            (MouseButton::Middle, true) => WM_MBUTTONDOWN,
            (MouseButton::Middle, false) => WM_MBUTTONUP,
        };
        self.post(message, held.flags(), lparam_xy(x, y));
    }

    /// The wheel turned by `delta` (120 per notch) at client position (x, y).
    pub fn wheel(self, delta: i32, x: i32, y: i32, held: Buttons) {
        // WM_MOUSEWHEEL carries screen coordinates.
        let mut p = POINT { x, y };
        // SAFETY: writes only `p`.
        unsafe { ClientToScreen(self.hwnd(), &mut p) };
        self.post(WM_MOUSEWHEEL, ((delta as i16 as u16 as usize) << 16) | held.flags(), lparam_xy(p.x, p.y));
    }

    /// A key (Windows virtual-key code) went down or up.
    pub fn key(self, vk: u32, down: bool) {
        // SAFETY: pure lookup.
        let scan = unsafe { MapVirtualKeyW(vk, MAPVK_VK_TO_VSC) };
        let mut lparam = 1 | (scan as isize & 0xFF) << 16;
        if !down {
            lparam |= 0xC000_0000u32 as i32 as isize;
        }
        self.post(if down { WM_KEYDOWN } else { WM_KEYUP }, vk as WPARAM, lparam);
    }

    /// A typed character.
    pub fn char(self, c: char) {
        let mut units = [0u16; 2];
        for &u in c.encode_utf16(&mut units).iter() {
            self.post(WM_CHAR, u as WPARAM, 1);
        }
    }
}
