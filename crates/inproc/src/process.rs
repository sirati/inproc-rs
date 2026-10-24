//! This process's own numbers.

use windows_sys::Win32::System::ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
use windows_sys::Win32::System::Threading::{ExitProcess, GetCurrentProcess, TerminateProcess};

/// Ends this process at once, from any thread, without running DLL detach
/// or the DLLs' `atexit` handlers.
///
/// `ExitProcess` (and so `std::process::exit`) first kills every other
/// thread and then calls each DLL's detach. A DLL whose detach waits for
/// one of its own threads waits forever, because that thread is already
/// dead. Civ III's `sound.dll` does this: its `atexit` handler posts to its
/// sound thread and retries every 100 ms until the post succeeds. While the
/// game runs, use this function, not `std::process::exit`.
pub fn terminate(code: u32) -> ! {
    // SAFETY: the pseudo handle names this process; terminating it does
    // not return.
    unsafe { TerminateProcess(GetCurrentProcess(), code) };
    // (Not reached: the call ends this process, this thread included.)
    // SAFETY: as above, a last resort.
    unsafe { ExitProcess(code) }
}

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

/// CPU time the calling thread has used so far (user and kernel, ns;
/// 100 ns resolution), or `None`. Against wall time, it tells a thread that
/// works from one that waits.
pub fn thread_cpu_ns() -> Option<u64> {
    use windows_sys::Win32::Foundation::FILETIME;
    use windows_sys::Win32::System::Threading::{GetCurrentThread, GetThreadTimes};
    let zero = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
    let (mut created, mut exited, mut kernel, mut user) = (zero, zero, zero, zero);
    // SAFETY: the pseudo handle names this thread; the call writes the four
    // local structs only.
    let ok = unsafe { GetThreadTimes(GetCurrentThread(), &mut created, &mut exited, &mut kernel, &mut user) } != 0;
    let ns = |t: FILETIME| ((u64::from(t.dwHighDateTime) << 32) | u64::from(t.dwLowDateTime)) * 100;
    ok.then(|| ns(kernel) + ns(user))
}

#[cfg(test)]
mod tests {
    /// The child runs this test again with the variable set: a second thread
    /// ends the process while the main thread is still busy.
    const CHILD: &str = "INPROC_TERMINATE_CHILD";

    #[test]
    fn terminate_ends_the_whole_process_from_another_thread_with_its_code() {
        if std::env::var_os(CHILD).is_some() {
            std::thread::spawn(|| super::terminate(7));
            loop {
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        }
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "process::tests::terminate_ends_the_whole_process_from_another_thread_with_its_code", "--nocapture"])
            .env(CHILD, "1")
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if std::time::Instant::now() > deadline {
                let _ = child.kill();
                panic!("the child did not end");
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        };
        assert_eq!(status.code(), Some(7));
    }
}

/// The calling thread's id (`GetCurrentThreadId`).
pub fn thread_id() -> u32 {
    // SAFETY: no arguments, no failure.
    unsafe { windows_sys::Win32::System::Threading::GetCurrentThreadId() }
}
