//! This process's own numbers.

use windows_sys::Win32::System::ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

/// Memory of this process, in bytes.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Memory {
    pub working_set: usize,
    pub peak_working_set: usize,
    /// Committed private memory (`PagefileUsage`).
    pub commit: usize,
    pub peak_commit: usize,
}

pub fn memory() -> Option<Memory> {
    // SAFETY: a plain C struct, all zeroes is valid.
    let mut c: PROCESS_MEMORY_COUNTERS = unsafe { std::mem::zeroed() };
    c.cb = size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
    // SAFETY: writes at most `cb` bytes into `c`; the pseudo handle needs no
    // closing.
    let ok = unsafe { GetProcessMemoryInfo(GetCurrentProcess(), &mut c, c.cb) } != 0;
    ok.then_some(Memory {
        working_set: c.WorkingSetSize,
        peak_working_set: c.PeakWorkingSetSize,
        commit: c.PagefileUsage,
        peak_commit: c.PeakPagefileUsage,
    })
}
