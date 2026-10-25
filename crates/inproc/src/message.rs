//! Intercepting messages to a window of this process. Private posted
//! messages run on the window's thread, in the same queue as keyboard and
//! pointer input. Other messages continue through its existing procedure.

use std::sync::atomic::{AtomicIsize, Ordering::SeqCst};

use windows_sys::Win32::Foundation::{GetLastError, HWND, LPARAM, LRESULT, SetLastError, WPARAM};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CallWindowProcW, GWLP_WNDPROC, GetWindowLongPtrW, RegisterWindowMessageW, SetWindowLongPtrW,
    WM_NCDESTROY,
};

use crate::window::Window;

/// One message delivered on the window's own thread.
#[derive(Clone, Copy, Debug)]
pub struct Message {
    pub window: Window,
    pub id: u32,
    pub wparam: usize,
    pub lparam: isize,
}

type Handler = Box<dyn Fn(Message) -> Option<isize> + Send + Sync>;

/// One intercepted window. The window procedure (on the game's thread, for
/// every message) finds its entry by scanning these atomics: nothing it
/// reads can make it wait for the thread installing or removing an entry.
struct Entry {
    /// The window's handle; [`FREE`] or [`BUSY`] (being filled or emptied).
    window: AtomicIsize,
    previous: AtomicIsize,
    handler: crate::hook::HandlerSlot<Handler>,
}

const FREE: isize = 0;
const BUSY: isize = -1;
/// More windows than a process intercepts at once.
const ENTRIES: usize = 32;
static TABLE: [Entry; ENTRIES] = [const {
    Entry { window: AtomicIsize::new(FREE), previous: AtomicIsize::new(0), handler: crate::hook::HandlerSlot::new() }
}; ENTRIES];

fn find(window: isize) -> Option<&'static Entry> {
    TABLE.iter().find(|e| e.window.load(SeqCst) == window)
}

/// The entry's procedure and handler, if it still belongs to `window`
/// after reading them (an entry is reused only after its window is gone).
fn lookup(window: isize) -> Option<(isize, &'static Handler)> {
    let entry = find(window)?;
    let found = (entry.previous.load(SeqCst), entry.handler.get()?);
    (entry.window.load(SeqCst) == window).then_some(found)
}

fn release(window: isize) {
    if let Some(entry) = find(window) {
        let _ = entry.window.compare_exchange(window, FREE, SeqCst, SeqCst);
    }
}

/// Whether this process still has an active interceptor for the window.
/// Destroying a window removes its entry before a stale cached handle can
/// advertise a private-message endpoint to another thread.
pub fn is_intercepted(window: Window) -> bool {
    find(window.handle() as isize).is_some()
}

/// A process-wide message ID, shared by senders and receivers using the
/// same name. Zero means registration failed.
pub fn register(name: &str) -> u32 {
    let name: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
    // SAFETY: a NUL-terminated UTF-16 string for the duration of the call.
    unsafe { RegisterWindowMessageW(name.as_ptr()) }
}

/// How many milliseconds ago the posted message now being handled on this
/// thread entered its queue (`GetMessageTime` against `GetTickCount`).
/// Only meaningful for posted messages, while they are dispatched.
pub fn queued_age_ms() -> u32 {
    // SAFETY: both only read tick counts (the thread's last message time).
    unsafe {
        windows_sys::Win32::System::SystemInformation::GetTickCount()
            .wrapping_sub(windows_sys::Win32::UI::WindowsAndMessaging::GetMessageTime() as u32)
    }
}

unsafe extern "system" fn procedure(
    window: HWND,
    id: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    let Some((previous, handler)) = lookup(window as isize) else { return 0 };
    let message = Message {
        window: Window::from_handle(window as usize as u32),
        id,
        wparam,
        lparam,
    };
    if crate::keyboard::dispatch_forwarded(message) || crate::keyboard::observe(message) {
        return 0;
    }
    // A game can open another modal dialog and dispatch messages recursively
    // from inside the handler; nothing here is held across it.
    let handled =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handler(message)))
            .unwrap_or_else(|_| {
                log::error!("window message handler panicked");
                None
            });
    if id == WM_NCDESTROY {
        release(window as isize);
    }
    let result = match handled {
        Some(result) => result,
        None => {
            // SAFETY: previous is the actual WNDPROC returned by Windows
            // when this live same-process window was subclassed.
            let previous = unsafe { std::mem::transmute(previous) };
            unsafe { CallWindowProcW(previous, window, id, wparam, lparam) }
        }
    };
    if id == WM_NCDESTROY {
        crate::paint::destroyed(window as usize as u32);
    }
    result
}

/// Restores the original procedure on drop, provided no later subclass
/// has replaced ours. Keep this for as long as private messages are sent.
pub struct Interceptor {
    window: Window,
}

impl Drop for Interceptor {
    fn drop(&mut self) {
        let window = self.window.handle() as usize as HWND;
        let Some(entry) = find(window as isize) else {
            return;
        };
        // SAFETY: querying and restoring this process's window procedure.
        // If another subclass is above us, its chain still needs our entry.
        unsafe {
            if GetWindowLongPtrW(window, GWLP_WNDPROC) as isize == procedure as *const () as isize {
                SetWindowLongPtrW(window, GWLP_WNDPROC, entry.previous.load(SeqCst) as _);
                release(window as isize);
            }
        }
    }
}

/// Intercepts messages to a window owned by this process. The handler
/// returns a result to consume a message, or None to call the previous
/// procedure. Installation may happen from another thread of the process.
pub fn intercept(
    window: Window,
    handler: impl Fn(Message) -> Option<isize> + Send + Sync + 'static,
) -> std::io::Result<Interceptor> {
    let handle = window.handle() as usize as HWND;
    let already = || std::io::Error::other("window message interceptor already installed");
    if find(handle as isize).is_some() {
        return Err(already());
    }
    let Some(entry) = TABLE
        .iter()
        .find(|e| e.window.compare_exchange(FREE, BUSY, SeqCst, SeqCst).is_ok())
    else {
        return Err(std::io::Error::other("too many intercepted windows"));
    };
    // The entry is complete before our procedure can be called: the
    // previous procedure is read first and corrected after the swap.
    entry.handler.set(Some(Box::new(handler)));
    // SAFETY: querying this process's window procedure.
    entry.previous.store(unsafe { GetWindowLongPtrW(handle, GWLP_WNDPROC) } as isize, SeqCst);
    entry.window.store(handle as isize, SeqCst);
    if TABLE.iter().filter(|e| e.window.load(SeqCst) == handle as isize).count() > 1 {
        // Another thread intercepted the same window at the same time.
        entry.window.store(FREE, SeqCst);
        return Err(already());
    }
    unsafe { SetLastError(0) };
    // SAFETY: window is a same-process HWND found by Window's enumerator;
    // procedure has the documented Windows callback calling convention.
    let previous =
        unsafe { SetWindowLongPtrW(handle, GWLP_WNDPROC, procedure as *const () as isize as _) }
            as isize;
    if previous == 0 {
        let error = unsafe { GetLastError() };
        entry.window.store(FREE, SeqCst);
        return Err(std::io::Error::from_raw_os_error(error as i32));
    }
    entry.previous.store(previous, SeqCst);
    Ok(Interceptor { window })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, HWND_MESSAGE, MSG,
        PM_REMOVE, PeekMessageW, RegisterClassW, UnregisterClassW, WNDCLASSW,
    };

    static ID: AtomicU32 = AtomicU32::new(0);
    thread_local! {
        // Window procedures run on the thread pumping the test window.
        static SEEN: std::cell::RefCell<Vec<(bool, usize)>> = const { std::cell::RefCell::new(Vec::new()) };
    }

    unsafe extern "system" fn original(
        window: HWND,
        id: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        if id == ID.load(Ordering::Relaxed) {
            SEEN.with_borrow_mut(|s| s.push((false, wparam)));
            return 17;
        }
        unsafe { DefWindowProcW(window, id, wparam, lparam) }
    }

    fn pump() {
        let mut message = MSG::default();
        // SAFETY: the buffer stays valid through each Windows call and
        // every queued message belongs to this test's current thread.
        unsafe {
            while PeekMessageW(&mut message, std::ptr::null_mut(), 0, 0, PM_REMOVE) != 0 {
                DispatchMessageW(&message);
            }
        }
    }

    #[test]
    fn private_input_preserves_queue_order_and_restores_the_original_procedure() {
        let class: Vec<u16> = "Civ3RendererMessageQueueTest\0".encode_utf16().collect();
        let id = register("civ3-renderer/test-ordered-private-input/v1");
        assert_ne!(id, 0);
        ID.store(id, Ordering::Relaxed);
        SEEN.with_borrow_mut(Vec::clear);
        // SAFETY: a process-owned, invisible message-only window with a
        // procedure matching the Windows ABI. No desktop window is shown.
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
        let window = Window::from_handle(handle as usize as u32);
        let hook = intercept(window, move |message| {
            if message.id == id && message.wparam != 2 {
                SEEN.with_borrow_mut(|s| s.push((true, message.wparam)));
                Some(23)
            } else {
                None
            }
        })
        .unwrap();
        assert!(is_intercepted(window));
        for token in [1, 2, 3] {
            assert!(window.post_message(id, token));
        }
        pump();
        assert_eq!(SEEN.with_borrow(Vec::clone), [(true, 1), (false, 2), (true, 3)]);
        drop(hook);
        assert!(!is_intercepted(window));
        assert!(window.post_message(id, 4));
        pump();
        assert_eq!(
            SEEN.with_borrow(Vec::clone),
            [(true, 1), (false, 2), (true, 3), (false, 4)]
        );
        // SAFETY: these resources were created above and the interceptor
        // has already restored the original window procedure.
        unsafe {
            assert_ne!(DestroyWindow(handle), 0);
            assert_ne!(UnregisterClassW(class.as_ptr(), instance), 0);
        }
    }

    unsafe extern "system" fn plain(window: HWND, id: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
        unsafe { DefWindowProcW(window, id, wparam, lparam) }
    }

    #[test]
    fn queued_age_reports_how_long_posted_input_waited_for_a_stalled_thread() {
        thread_local! {
            static AGES: std::cell::RefCell<Vec<(usize, u32)>> = const { std::cell::RefCell::new(Vec::new()) };
        }
        let class: Vec<u16> = "Civ3RendererMessageAgeTest\0".encode_utf16().collect();
        let id = register("civ3-renderer/test-queued-input-age/v1");
        assert_ne!(id, 0);
        // SAFETY: a process-owned, invisible message-only window, as above.
        let (instance, handle) = unsafe {
            let instance = GetModuleHandleW(std::ptr::null());
            let descriptor = WNDCLASSW { lpfnWndProc: Some(plain), hInstance: instance, lpszClassName: class.as_ptr(), ..Default::default() };
            assert_ne!(RegisterClassW(&descriptor), 0);
            let handle = CreateWindowExW(0, class.as_ptr(), class.as_ptr(), 0, 0, 0, 0, 0, HWND_MESSAGE, std::ptr::null_mut(), instance, std::ptr::null());
            assert!(!handle.is_null());
            (instance, handle)
        };
        let window = Window::from_handle(handle as usize as u32);
        let hook = intercept(window, move |message| {
            (message.id == id).then(|| {
                AGES.with_borrow_mut(|a| a.push((message.wparam, queued_age_ms())));
                0
            })
        })
        .unwrap();
        // Posted, then the window's thread is busy for 1.2 s (a stall).
        assert!(window.post_message(id, 1));
        std::thread::sleep(std::time::Duration::from_millis(1200));
        pump();
        assert!(window.post_message(id, 2));
        pump();
        let ages = AGES.with_borrow(Vec::clone);
        assert_eq!(ages.len(), 2);
        assert!(ages[0].1 >= 1100, "stalled input is seen as old: {ages:?}");
        assert!(ages[1].1 < 500, "input handled at once is fresh: {ages:?}");
        drop(hook);
        // SAFETY: created above; the interceptor is gone.
        unsafe {
            assert_ne!(DestroyWindow(handle), 0);
            assert_ne!(UnregisterClassW(class.as_ptr(), instance), 0);
        }
    }
}
