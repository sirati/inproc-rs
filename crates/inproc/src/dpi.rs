//! DPI awareness of this thread alone: a window of ours in someone else's
//! process (e.g. a viewer in a game's) gets the screen's own pixels without
//! making the whole process DPI aware, which would change what the
//! program's own windows report (their client size in the screen's pixels,
//! its mouse coordinates scaled by it).

use windows_sys::Win32::UI::HiDpi::{DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2, SetThreadDpiAwarenessContext};

/// Makes the calling thread per-monitor DPI aware (its windows made from
/// now on have the screen's own pixels); whether that worked.
pub fn thread_per_monitor_aware() -> bool {
    // SAFETY: changes only the calling thread's awareness; returns the
    // previous context, or NULL if refused.
    !unsafe { SetThreadDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2) }.is_null()
}
