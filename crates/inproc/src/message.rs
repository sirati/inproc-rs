//! Intercepting messages to a window of this process. Private posted
//! messages run on the window's thread, in the same queue as keyboard and
//! pointer input. Other messages continue through its existing procedure.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

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

type Handler = Arc<dyn Fn(Message) -> Option<isize> + Send + Sync>;
#[derive(Clone)]
struct Entry {
    previous: isize,
    handler: Handler,
}
static ENTRIES: OnceLock<Mutex<HashMap<isize, Entry>>> = OnceLock::new();

fn entries() -> &'static Mutex<HashMap<isize, Entry>> {
    ENTRIES.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Whether this process still has an active interceptor for the window.
/// Destroying a window removes its entry before a stale cached handle can
/// advertise a private-message endpoint to another thread.
pub fn is_intercepted(window: Window) -> bool {
    entries()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .contains_key(&(window.handle() as isize))
}

/// A process-wide message ID, shared by senders and receivers using the
/// same name. Zero means registration failed.
pub fn register(name: &str) -> u32 {
    let name: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
    // SAFETY: a NUL-terminated UTF-16 string for the duration of the call.
    unsafe { RegisterWindowMessageW(name.as_ptr()) }
}

unsafe extern "system" fn procedure(
    window: HWND,
    id: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    let entry = entries()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&(window as isize))
        .cloned();
    let Some(entry) = entry else { return 0 };
    let message = Message {
        window: Window::from_handle(window as usize as u32),
        id,
        wparam,
        lparam,
    };
    // Do not hold the registry lock while the handler or the original runs.
    // A game can open another modal dialog and dispatch messages recursively.
    let handled =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| (entry.handler)(message)))
            .unwrap_or_else(|_| {
                log::error!("window message handler panicked");
                None
            });
    if id == WM_NCDESTROY {
        entries()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&(window as isize));
    }
    match handled {
        Some(result) => result,
        None => {
            // SAFETY: previous is the actual WNDPROC returned by Windows
            // when this live same-process window was subclassed.
            let previous = unsafe { std::mem::transmute(entry.previous) };
            unsafe { CallWindowProcW(previous, window, id, wparam, lparam) }
        }
    }
}

/// Restores the original procedure on drop, provided no later subclass
/// has replaced ours. Keep this for as long as private messages are sent.
pub struct Interceptor {
    window: Window,
}

impl Drop for Interceptor {
    fn drop(&mut self) {
        let window = self.window.handle() as usize as HWND;
        let mut entries = entries().lock().unwrap_or_else(|e| e.into_inner());
        let Some(entry) = entries.get(&(window as isize)) else {
            return;
        };
        // SAFETY: querying and restoring this process's window procedure.
        // If another subclass is above us, its chain still needs our entry.
        unsafe {
            if GetWindowLongPtrW(window, GWLP_WNDPROC) as isize == procedure as *const () as isize {
                SetWindowLongPtrW(window, GWLP_WNDPROC, entry.previous as _);
                entries.remove(&(window as isize));
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
    let mut entries = entries().lock().unwrap_or_else(|e| e.into_inner());
    if entries.contains_key(&(handle as isize)) {
        return Err(std::io::Error::other(
            "window message interceptor already installed",
        ));
    }
    // The registry remains locked until the previous procedure is stored,
    // so a message delivered concurrently waits for a complete entry.
    unsafe { SetLastError(0) };
    // SAFETY: window is a same-process HWND found by Window's enumerator;
    // procedure has the documented Windows callback calling convention.
    let previous =
        unsafe { SetWindowLongPtrW(handle, GWLP_WNDPROC, procedure as *const () as isize as _) }
            as isize;
    if previous == 0 {
        let error = unsafe { GetLastError() };
        return Err(std::io::Error::from_raw_os_error(error as i32));
    }
    entries.insert(
        handle as isize,
        Entry {
            previous,
            handler: Arc::new(handler),
        },
    );
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
    static SEEN: Mutex<Vec<(bool, usize)>> = Mutex::new(Vec::new());

    unsafe extern "system" fn original(
        window: HWND,
        id: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        if id == ID.load(Ordering::Relaxed) {
            SEEN.lock().unwrap().push((false, wparam));
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
        SEEN.lock().unwrap().clear();
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
                SEEN.lock().unwrap().push((true, message.wparam));
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
        assert_eq!(*SEEN.lock().unwrap(), [(true, 1), (false, 2), (true, 3)]);
        drop(hook);
        assert!(!is_intercepted(window));
        assert!(window.post_message(id, 4));
        pump();
        assert_eq!(
            *SEEN.lock().unwrap(),
            [(true, 1), (false, 2), (true, 3), (false, 4)]
        );
        // SAFETY: these resources were created above and the interceptor
        // has already restored the original window procedure.
        unsafe {
            assert_ne!(DestroyWindow(handle), 0);
            assert_ne!(UnregisterClassW(class.as_ptr(), instance), 0);
        }
    }
}
