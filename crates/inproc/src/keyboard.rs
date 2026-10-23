//! Keyboard modifiers forwarded to an intercepted window. State changes
//! run on its own UI thread, so `GetKeyState` agrees with the key messages
//! without sending global input or changing another thread's keyboard.

use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::OnceLock;

use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{GetKeyboardState, SetKeyboardState};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    DispatchMessageW, MSG, PM_REMOVE, PeekMessageW, PostMessageW, TranslateMessage, WM_CHAR,
    WM_DEADCHAR, WM_KEYDOWN, WM_KEYUP, WM_KILLFOCUS, WM_NCDESTROY, WM_SYSCHAR, WM_SYSDEADCHAR,
    WM_SYSKEYDOWN, WM_SYSKEYUP,
};

use crate::message::Message;
use crate::window::Window;

const SIDES: [usize; 6] = [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5];
const AGGREGATES: [usize; 3] = [0x10, 0x11, 0x12];

thread_local! {
    // Only this UI thread's intercepted windows contribute held modifiers.
    static HELD: RefCell<HashMap<u32, u8>> = RefCell::new(HashMap::new());
}

fn release_message() -> u32 {
    static ID: OnceLock<u32> = OnceLock::new();
    *ID.get_or_init(|| crate::message::register("civ3-renderer/release-forwarded-modifiers/v1"))
}

/// Queues release of this window's held modifiers on its owning UI thread.
/// Use when the separate viewer loses focus; the hidden game's window may
/// receive no native focus-loss message. Queue order preserves prior input.
/// An unintercepted window is rejected without changing keyboard state.
pub fn release(window: Window) -> bool {
    crate::message::is_intercepted(window)
        && release_message() != 0
        && window.post_message(release_message(), 0)
}

const KEY_DOWN: usize = 1 << 16;
const CHARACTER: usize = 1 << 17;

fn forwarded_message() -> u32 {
    static ID: OnceLock<u32> = OnceLock::new();
    *ID.get_or_init(|| crate::message::register("civ3-renderer/ordered-forwarded-key/v1"))
}

fn post(window: Window, wparam: usize, lparam: isize) -> bool {
    let id = forwarded_message();
    if id == 0 || !crate::message::is_intercepted(window) {
        return false;
    }
    // SAFETY: plain key values, copied into this process-owned window's
    // queue. No user input is injected into the desktop or another process.
    unsafe { PostMessageW(window.handle() as usize as HWND, id, wparam, lparam) != 0 }
}

pub(crate) fn post_key(window: Window, vk: u32, down: bool, lparam: isize) -> bool {
    vk <= 0xff
        && post(
            window,
            vk as usize | if down { KEY_DOWN } else { 0 },
            lparam,
        )
}

pub(crate) fn post_char(window: Window, unit: u16) -> bool {
    post(window, unit as usize | CHARACTER, 1)
}

/// Forwarded keys use an ordinary posted envelope so the game's outer
/// message loop cannot translate them ahead of the modifier state. Each
/// key and its translated characters finish before later queued keyups.
/// Typed text uses the same envelope to retain its place among keys.
pub(crate) fn dispatch_forwarded(message: Message) -> bool {
    let id = forwarded_message();
    if id == 0 || message.id != id {
        return false;
    }
    let character = message.wparam & CHARACTER != 0;
    let down = message.wparam & KEY_DOWN != 0;
    let id = if character {
        WM_CHAR
    } else if down {
        WM_KEYDOWN
    } else {
        WM_KEYUP
    };
    let key = Message {
        id,
        wparam: message.wparam & 0xffff,
        ..message
    };
    let mut native = MSG {
        hwnd: message.window.handle() as usize as HWND,
        message: key.id,
        wParam: key.wparam,
        lParam: key.lparam,
        ..Default::default()
    };
    if !character {
        // In particular, Shift/Ctrl/Alt is already correct when the system
        // translates this key. Dispatch below also retains native key
        // observation and the usual interceptor/original procedure chain.
        observe(key);
        unsafe {
            TranslateMessage(&native);
        }
    }
    unsafe {
        DispatchMessageW(&native);
    }
    if !character && down {
        // These two ranges deliberately skip WM_SYSKEYDOWN/WM_SYSKEYUP,
        // which lie between WM_DEADCHAR and WM_SYSCHAR numerically. Limit
        // draining to this owned window, leaving other windows' input alone.
        for (first, last) in [(WM_CHAR, WM_DEADCHAR), (WM_SYSCHAR, WM_SYSDEADCHAR)] {
            unsafe {
                while PeekMessageW(
                    &mut native,
                    message.window.handle() as usize as HWND,
                    first,
                    last,
                    PM_REMOVE,
                ) != 0
                {
                    DispatchMessageW(&native);
                }
            }
        }
    }
    true
}

fn side(vk: usize, lparam: isize) -> Option<usize> {
    match vk {
        0x10 => Some(if (lparam >> 16) & 0xff == 0x36 { 1 } else { 0 }),
        0x11 => Some(if lparam & (1 << 24) != 0 { 3 } else { 2 }),
        0x12 => Some(if lparam & (1 << 24) != 0 { 5 } else { 4 }),
        0xA0..=0xA5 => Some(vk - 0xA0),
        _ => None,
    }
}

fn set_down(state: &mut [u8; 256], vk: usize, down: bool) {
    state[vk] = state[vk] & 0x7f | if down { 0x80 } else { 0 };
}

/// Called only by the registered interceptor, before its handler and the
/// original WNDPROC. The OS calls both on the window's owning UI thread.
pub(crate) fn observe(message: Message) -> bool {
    let key = match message.id {
        WM_KEYDOWN | WM_SYSKEYDOWN => Some(true),
        WM_KEYUP | WM_SYSKEYUP => Some(false),
        _ => None,
    };
    let private = release_message();
    let explicit_release = private != 0 && message.id == private;
    let releasing = matches!(message.id, WM_KILLFOCUS | WM_NCDESTROY) || explicit_release;
    if key.is_none() && !releasing {
        return false;
    }
    let mut state = [0; 256];
    // SAFETY: these read and write this calling UI thread's 256-byte key
    // state only. No global/physical input or other thread is modified.
    if unsafe { GetKeyboardState(state.as_mut_ptr()) } == 0 {
        return explicit_release;
    }
    HELD.with(|held| {
        let mut held = held.borrow_mut();
        let window = message.window.handle();
        let mut changed = if releasing {
            held.remove(&window).unwrap_or(0)
        } else {
            0
        };
        if let Some(down) = key {
            if let Some(side) = side(message.wparam, message.lparam) {
                let mask = 1 << side;
                let owned = held.entry(window).or_default();
                if down {
                    *owned |= mask;
                } else {
                    *owned &= !mask;
                }
                changed |= mask;
                if *owned == 0 {
                    held.remove(&window);
                }
            }
        }
        let active = held.values().fold(0, |all, &mask| all | mask);
        for (i, &vk) in SIDES.iter().enumerate() {
            if (active | changed) & (1 << i) != 0 {
                set_down(&mut state, vk, active & (1 << i) != 0);
            }
        }
        for (i, &vk) in AGGREGATES.iter().enumerate() {
            if (active | changed) & (3 << (2 * i)) != 0 {
                let down = (state[SIDES[2 * i]] | state[SIDES[2 * i + 1]]) & 0x80 != 0;
                set_down(&mut state, vk, down);
            }
        }
        if active | changed != 0 && unsafe { SetKeyboardState(state.as_ptr()) } == 0 {
            log::warn!("could not synchronize forwarded keyboard modifiers");
        }
    });
    explicit_release
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use windows_sys::Win32::Foundation::{HINSTANCE, HWND, LPARAM, LRESULT, WPARAM};
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::GetKeyState;
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, HWND_MESSAGE, MSG,
        PM_REMOVE, PeekMessageW, RegisterClassW, SendMessageW, TranslateMessage, UnregisterClassW,
        WM_CHAR, WNDCLASSW,
    };

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct Seen {
        id: u32,
        vk: usize,
        held: u8,
    }

    thread_local! { static SEEN: RefCell<Vec<Seen>> = const { RefCell::new(Vec::new()) }; }
    static SERIAL: AtomicU32 = AtomicU32::new(0);

    fn modifiers() -> u8 {
        let mut held = 0;
        for (i, vk) in [0x10, 0x11, 0x12, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4]
            .into_iter()
            .enumerate()
        {
            if unsafe { GetKeyState(vk) } < 0 {
                held |= 1 << i;
            }
        }
        held
    }

    unsafe extern "system" fn original(
        window: HWND,
        id: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        if matches!(
            id,
            WM_KEYDOWN | WM_KEYUP | WM_SYSKEYDOWN | WM_SYSKEYUP | WM_CHAR | WM_KILLFOCUS
        ) {
            SEEN.with(|seen| {
                seen.borrow_mut().push(Seen {
                    id,
                    vk: wparam,
                    held: modifiers(),
                })
            });
            return 0;
        }
        unsafe { DefWindowProcW(window, id, wparam, lparam) }
    }

    struct TestWindow {
        handle: HWND,
        instance: HINSTANCE,
        class: Vec<u16>,
        hook: Option<crate::message::Interceptor>,
        initial: [u8; 256],
    }

    impl TestWindow {
        fn new() -> Self {
            SEEN.with(|seen| seen.borrow_mut().clear());
            let mut initial = [0; 256];
            let clear = [0u8; 256];
            unsafe {
                assert_ne!(GetKeyboardState(initial.as_mut_ptr()), 0);
                assert_ne!(SetKeyboardState(clear.as_ptr()), 0);
            }
            let class: Vec<u16> = format!(
                "Civ3RendererKeyboardTest{}\0",
                SERIAL.fetch_add(1, Ordering::Relaxed)
            )
            .encode_utf16()
            .collect();
            let (instance, handle) = unsafe {
                let instance = GetModuleHandleW(std::ptr::null());
                let descriptor = WNDCLASSW {
                    lpfnWndProc: Some(original),
                    hInstance: instance,
                    lpszClassName: class.as_ptr(),
                    ..Default::default()
                };
                assert_ne!(RegisterClassW(&descriptor), 0);
                let handle = CreateWindowExW(
                    0,
                    class.as_ptr(),
                    class.as_ptr(),
                    0,
                    0,
                    0,
                    0,
                    0,
                    HWND_MESSAGE,
                    std::ptr::null_mut(),
                    instance,
                    std::ptr::null(),
                );
                assert!(!handle.is_null());
                (instance, handle)
            };
            let hook =
                crate::message::intercept(Window::from_handle(handle as usize as u32), |_| None)
                    .unwrap();
            Self {
                handle,
                instance,
                class,
                hook: Some(hook),
                initial,
            }
        }

        fn window(&self) -> Window {
            Window::from_handle(self.handle as usize as u32)
        }

        fn send(&self, id: u32, vk: usize, lparam: isize) {
            unsafe {
                SendMessageW(self.handle, id, vk, lparam);
            }
        }
    }

    impl Drop for TestWindow {
        fn drop(&mut self) {
            self.send(WM_KILLFOCUS, 0, 0);
            self.hook.take();
            unsafe {
                DestroyWindow(self.handle);
                UnregisterClassW(self.class.as_ptr(), self.instance);
                SetKeyboardState(self.initial.as_ptr());
            }
        }
    }

    fn pump() {
        let mut message = MSG::default();
        unsafe {
            while PeekMessageW(&mut message, std::ptr::null_mut(), 0, 0, PM_REMOVE) != 0 {
                TranslateMessage(&message);
                DispatchMessageW(&message);
            }
        }
    }

    fn seen() -> Vec<Seen> {
        SEEN.with(|seen| seen.borrow().clone())
    }

    #[test]
    fn immediate_keys_finish_before_return_and_reject_other_threads() {
        let test = TestWindow::new();
        let window = test.window();
        assert!(window.key_now(0x1B, true));
        assert!(window.key_now(0x1B, false));
        // (With its character: Civ3's context menu and tile box close on
        // the Escape character, never on the key alone.)
        assert_eq!(seen().iter().map(|s| (s.id, s.vk)).collect::<Vec<_>>(),
            vec![(WM_KEYDOWN, 0x1B), (WM_CHAR, 0x1B), (WM_KEYUP, 0x1B)],
            "Escape must reach the native handler before another dismissal is processed");
        let rejected = std::thread::spawn(move || !window.key_now(0x1B, true)).join().unwrap();
        assert!(rejected, "a foreign thread must not block sending a synchronous key");
        pump();
        assert_eq!(seen().len(), 3, "neither immediate delivery nor rejected delivery queues another Escape");
    }

    #[test]
    fn posted_chords_are_visible_to_get_key_state_and_character_translation() {
        let test = TestWindow::new();
        for (vk, down) in [
            (0x10, true),
            (0x0D, true),
            (0x0D, false),
            (0x41, true),
            (0x41, false),
            (0x10, false),
            (0x11, true),
            (0x41, true),
            (0x41, false),
            (0x11, false),
        ] {
            test.window().key(vk, down);
        }
        pump();
        let seen = seen();
        let keys: Vec<_> = seen
            .iter()
            .filter(|e| e.id == WM_KEYDOWN || e.id == WM_KEYUP)
            .copied()
            .collect();
        assert_eq!(keys[0].held & 1, 1, "Shift keydown state");
        assert_eq!(keys[1].vk, 0x0D);
        assert_eq!(keys[1].held & 1, 1, "Shift+Enter callback must see Shift");
        assert_eq!(keys[5].held & 1, 0, "Shift keyup state");
        assert_eq!(keys[7].held & 2, 2, "Ctrl+A callback must see Control");
        assert_eq!(keys[9].held & 3, 0, "all modifiers released");
        let chars: Vec<_> = seen
            .iter()
            .filter(|e| e.id == WM_CHAR)
            .map(|e| e.vk)
            .collect();
        assert!(
            chars.contains(&(b'A' as usize)),
            "Shift+A translation: {chars:?}"
        );
        assert!(chars.contains(&1), "Ctrl+A translation: {chars:?}");
        assert_eq!(modifiers() & 3, 0);
    }

    #[test]
    fn rapid_chord_characters_run_before_their_modifiers_are_released() {
        let test = TestWindow::new();
        for (modifier, vk) in [(0x10, 0x0d), (0x11, 0x41), (0x12, 0x41)] {
            for (key, down) in [(modifier, true), (vk, true), (vk, false), (modifier, false)] {
                test.window().key(key, down);
            }
        }
        test.window().key(0x41, true);
        test.window().key(0x41, false);
        pump();
        let characters: Vec<_> = seen().into_iter().filter(|e| e.id == WM_CHAR).collect();
        assert_eq!(characters.len(), 4, "each press translates exactly once");
        assert_eq!(characters[0].vk, 0x0d);
        assert_eq!(
            characters[0].held & 7,
            1,
            "Shift+Enter WM_CHAR must see Shift"
        );
        assert_eq!(characters[1].vk, 1);
        assert_eq!(characters[1].held & 7, 2, "Ctrl+A WM_CHAR must see Control");
        assert_eq!(characters[2].vk, b'a' as usize);
        assert_eq!(characters[2].held & 7, 4, "Alt+A WM_CHAR must see Alt");
        assert_eq!(characters[3].vk, b'a' as usize);
        assert_eq!(
            characters[3].held & 7,
            0,
            "later ordinary typing has no modifiers"
        );
        assert_eq!(modifiers(), 0, "every keyup has released its modifiers");
    }

    #[test]
    fn character_dispatch_keeps_later_text_and_another_windows_input_in_order() {
        let test = TestWindow::new();
        let other = TestWindow::new();
        for (vk, down) in [(0x10, true), (0x41, true), (0x41, false), (0x10, false)] {
            test.window().key(vk, down);
        }
        test.window().char('!');
        // Deliberately raw input to another window must not be stolen by
        // the first window's translated-character drain.
        unsafe {
            assert_ne!(PostMessageW(other.handle, WM_CHAR, b'?' as usize, 1), 0);
        }
        pump();
        let characters: Vec<_> = seen().into_iter().filter(|e| e.id == WM_CHAR).collect();
        assert_eq!(
            characters.iter().map(|e| e.vk).collect::<Vec<_>>(),
            [b'A' as usize, b'!' as usize, b'?' as usize]
        );
        assert_eq!(
            characters.iter().map(|e| e.held & 7).collect::<Vec<_>>(),
            [1, 0, 0]
        );
    }

    #[test]
    fn translated_character_drain_does_not_dispatch_later_native_system_keyups() {
        let test = TestWindow::new();
        test.send(WM_SYSKEYDOWN, 0x12, 0);
        test.window().key(0x0d, true);
        unsafe {
            assert_ne!(PostMessageW(test.handle, WM_SYSKEYUP, 0x12, 0), 0);
        }
        test.window().key(0x0d, false);
        let mut message = MSG::default();
        unsafe {
            assert_ne!(
                PeekMessageW(
                    &mut message,
                    test.handle,
                    forwarded_message(),
                    forwarded_message(),
                    PM_REMOVE
                ),
                0
            );
            DispatchMessageW(&message);
        }
        assert_eq!(modifiers() & 7, 4, "system keyup remains queued");
        assert!(!seen().iter().any(|e| e.id == WM_SYSKEYUP));
        let enter = seen()
            .into_iter()
            .find(|e| e.id == WM_CHAR && e.vk == 0x0d)
            .unwrap();
        assert_eq!(enter.held & 7, 4);
        pump();
        assert_eq!(modifiers() & 7, 0);
        assert!(seen().iter().any(|e| e.id == WM_SYSKEYUP));
    }

    #[test]
    fn side_specific_native_messages_keep_aggregate_until_both_sides_release() {
        let test = TestWindow::new();
        for (vk, scan) in [
            (0x10, 0x36 << 16),
            (0x10, 0x2a << 16),
            (0x11, 1 << 24),
            (0x11, 0),
            (0x12, 1 << 24),
            (0x12, 0),
        ] {
            test.send(WM_KEYDOWN, vk, scan);
        }
        assert_eq!(modifiers() & 0x7f, 0x7f);
        for vk in [0xA0, 0xA2, 0xA4] {
            test.send(WM_KEYUP, vk, 0);
        }
        assert_eq!(modifiers() & 7, 7, "right sides still hold aggregates");
        for vk in [0xA1, 0xA3, 0xA5] {
            test.send(WM_KEYUP, vk, 0);
        }
        assert_eq!(modifiers(), 0);
    }

    #[test]
    fn releasing_on_focus_loss_precedes_the_original_callback_and_retains_other_keys() {
        let test = TestWindow::new();
        let mut state = [0u8; 256];
        state[0x14] = 1; // Caps Lock toggle.
        state[0x90] = 0x81; // Num Lock toggle and unrelated held key.
        state[0x42] = 0x80;
        unsafe {
            assert_ne!(SetKeyboardState(state.as_ptr()), 0);
        }
        // Native Windows may reject manually seeding an ordinary held key
        // such as B. Preserve the state the API accepted, including toggles
        // and the unrelated Num Lock key, rather than the requested bytes.
        let mut accepted = [0; 256];
        unsafe {
            assert_ne!(GetKeyboardState(accepted.as_mut_ptr()), 0);
        }
        assert_eq!(accepted[0x14], 1);
        assert_eq!(accepted[0x90], 0x81);
        test.send(WM_KEYDOWN, 0x10, 0x2a << 16);
        test.send(WM_KEYDOWN, 0x11, 0);
        test.send(WM_SYSKEYDOWN, 0x12, 0);
        assert_eq!(modifiers() & 7, 7);
        test.send(WM_KILLFOCUS, 0, 0);
        assert_eq!(seen().last().unwrap().held, 0);
        let mut after = [0; 256];
        unsafe {
            assert_ne!(GetKeyboardState(after.as_mut_ptr()), 0);
        }
        for vk in 0..256 {
            if ![0x10, 0x11, 0x12, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5].contains(&vk) {
                assert_eq!(after[vk], accepted[vk], "unrelated key {vk:#x} changed");
            }
        }
    }

    #[test]
    fn explicit_viewer_focus_release_preserves_queue_order() {
        let test = TestWindow::new();
        test.window().key(0x10, true);
        test.window().key(0x0D, true);
        assert!(release(test.window()));
        test.window().key(0x0D, true);
        pump();
        let enters: Vec<_> = seen()
            .into_iter()
            .filter(|e| e.id == WM_KEYDOWN && e.vk == 0x0D)
            .collect();
        assert_eq!(enters.len(), 2);
        assert_eq!(enters[0].held & 1, 1);
        assert_eq!(enters[1].held & 1, 0);
        SEEN.with(|seen| seen.borrow_mut().clear());
        test.window().key(0x41, true);
        test.window().key(0x41, false);
        pump();
        assert!(
            seen()
                .iter()
                .any(|e| e.id == WM_CHAR && e.vk == b'a' as usize)
        );
    }

    #[test]
    fn destroying_the_intercepted_window_releases_held_modifiers() {
        let test = TestWindow::new();
        test.send(WM_KEYDOWN, 0x10, 0x2a << 16);
        test.send(WM_KEYDOWN, 0x11, 0);
        assert_eq!(modifiers() & 3, 3);
        unsafe {
            assert_ne!(DestroyWindow(test.handle), 0);
        }
        assert_eq!(modifiers() & 3, 0);
        assert!(!crate::message::is_intercepted(test.window()));
        assert!(!release(test.window()));
    }

    #[test]
    fn synchronization_does_not_change_another_threads_keyboard() {
        let _test = TestWindow::new();
        let before = modifiers();
        std::thread::spawn(|| {
            let other = TestWindow::new();
            other.send(WM_KEYDOWN, 0x10, 0x2a << 16);
            other.send(WM_KEYDOWN, 0x11, 0);
            assert_eq!(modifiers() & 3, 3);
        })
        .join()
        .unwrap();
        assert_eq!(modifiers(), before);
    }
}
