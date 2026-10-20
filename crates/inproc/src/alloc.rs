//! A global allocator that keeps injected code off the host program's
//! process heap.
//!
//! Rust's default Windows allocator uses `HeapAlloc(GetProcessHeap())`, the
//! heap the game itself allocates from. Our publisher, art and font threads
//! allocate megabytes per second, so they hold the process heap's critical
//! section often, and the game's thread has to wait for it. Under ARM64
//! Wine/FEX on macOS such a contended wait was seen to lose its wake-up: the
//! game thread and ours both slept five seconds on the free heap section
//! ("main process heap section wait timed out ... blocked by 0000").
//!
//! [`PrivateHeap`] uses a heap of its own, created without serialization,
//! behind a guard that only spins and yields. A contended allocation never
//! sleeps in a futex wait, so it cannot lose a wake-up, and the game's own
//! heap never sees our allocation traffic.

use std::alloc::{GlobalAlloc, Layout};
use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicU64, Ordering};

use windows_sys::Win32::System::Memory::{
    HEAP_NO_SERIALIZE, HEAP_ZERO_MEMORY, HeapAlloc, HeapCreate, HeapDestroy, HeapFree,
    HeapReAlloc,
};
use windows_sys::Win32::System::SystemInformation::GetTickCount64;
use windows_sys::Win32::System::Threading::GetCurrentThreadId;

/// Who holds a [`PrivateHeap`]'s guard and since when (`GetTickCount64`
/// ms), for [`watchdog`]: 0 when free. (Neither call allocates or waits.)
static HOLDER: AtomicU32 = AtomicU32::new(0);
static HELD_SINCE: AtomicU64 = AtomicU64::new(0);
use windows_sys::Win32::System::Threading::{Sleep, SwitchToThread};

/// What `HeapAlloc` guarantees (`MEMORY_ALLOCATION_ALIGNMENT`).
#[cfg(target_pointer_width = "32")]
const HEAP_ALIGN: usize = 8;
#[cfg(target_pointer_width = "64")]
const HEAP_ALIGN: usize = 16;

/// A heap of our own for `#[global_allocator]`; see the module docs.
pub struct PrivateHeap {
    heap: AtomicPtr<c_void>,
    /// Set by the allocation, reallocation or free that uses the heap now.
    busy: AtomicBool,
}

impl Default for PrivateHeap {
    fn default() -> Self {
        Self::new()
    }
}

impl PrivateHeap {
    pub const fn new() -> Self {
        PrivateHeap { heap: AtomicPtr::new(std::ptr::null_mut()), busy: AtomicBool::new(false) }
    }

    /// The heap, created on first use. If another thread creates one at the
    /// same time, the loser destroys its own before anything uses it.
    fn heap(&self) -> *mut c_void {
        self.heap_or_create(|| {
            // SAFETY: a growable private heap, serialized only by our guard.
            unsafe { HeapCreate(HEAP_NO_SERIALIZE, 0, 0) }
        })
    }

    fn heap_or_create(&self, create: impl FnOnce() -> *mut c_void) -> *mut c_void {
        let heap = self.heap.load(Ordering::Acquire);
        if !heap.is_null() {
            return heap;
        }
        let created = create();
        if created.is_null() {
            // Our guard cannot serialize the game's process-heap callers.
            // Never use that heap with HEAP_NO_SERIALIZE. A racing creator
            // may already have published a private heap; otherwise allocation
            // fails normally, without passing a null handle to HeapAlloc.
            return self.heap.load(Ordering::Acquire);
        }
        match self.heap.compare_exchange(std::ptr::null_mut(), created, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => created,
            Err(winner) => {
                // SAFETY: `created` is ours and nothing has allocated from it.
                unsafe { HeapDestroy(created) };
                winner
            }
        }
    }

    fn lock(&self) -> Guard<'_> {
        let mut tries = 0u32;
        loop {
            if !self.busy.swap(true, Ordering::Acquire) {
                // SAFETY: plain reads of this thread's id and the tick count.
                unsafe {
                    HELD_SINCE.store(GetTickCount64(), Ordering::Relaxed);
                    HOLDER.store(GetCurrentThreadId(), Ordering::Relaxed);
                }
                return Guard(&self.busy);
            }
            while self.busy.load(Ordering::Relaxed) {
                tries = tries.saturating_add(1);
                if tries < 64 {
                    std::hint::spin_loop();
                } else if tries < 4096 {
                    // SAFETY: yields this thread's time slice; no state.
                    unsafe { SwitchToThread() };
                } else {
                    // A holder that is descheduled for long (e.g. suspended
                    // by the emulator): a timed sleep, never a futex wait.
                    // SAFETY: a plain timed sleep of this thread.
                    unsafe { Sleep(1) };
                }
            }
        }
    }
}

struct Guard<'a>(&'a AtomicBool);

impl Drop for Guard<'_> {
    fn drop(&mut self) {
        HOLDER.store(0, Ordering::Relaxed);
        self.0.store(false, Ordering::Release);
    }
}

/// Progress counters a [`watchdog`] watches: a name and a counter its
/// thread bumps whenever it makes progress (e.g. once per round).
pub type Watched = &'static [(&'static str, &'static AtomicU64)];

/// Starts a thread that notes in `path` (appended) when the allocator's
/// guard is held for seconds (by which thread), or a `watched` counter
/// stops moving, and when that ends. It allocates nothing once running and
/// writes straight to the file, so it reports even when every other thread
/// (the logger too) is stuck on the heap. For diagnosing hangs.
pub fn watchdog(path: &std::path::Path, watched: Watched) -> std::io::Result<()> {
    use std::io::Write;
    use std::fmt::Write as _;
    let mut file = std::fs::OpenOptions::new().create(true).append(true).open(path)?;
    std::thread::Builder::new().name("civ3r-watchdog".into()).spawn(move || {
        const STUCK_MS: u64 = 2000;
        let mut reported_hold = (0u32, 0u64);
        let mut seen = [(0u64, 0u64, false); 16];
        loop {
            std::thread::sleep(std::time::Duration::from_millis(500));
            // SAFETY: a plain read of the tick count.
            let now = unsafe { GetTickCount64() };
            let mut line = Line::default();
            let holder = HOLDER.load(Ordering::Relaxed);
            let since = HELD_SINCE.load(Ordering::Relaxed);
            if holder != 0 && now.saturating_sub(since) >= STUCK_MS && reported_hold != (holder, since) {
                reported_hold = (holder, since);
                let _ = write!(line, "tick {now}: the allocator's guard held by thread {holder:#x} for {} ms\n", now - since);
            } else if holder == 0 && reported_hold.0 != 0 {
                let _ = write!(line, "tick {now}: the allocator's guard free again (was thread {:#x})\n", reported_hold.0);
                reported_hold = (0, 0);
            }
            for (i, (name, counter)) in watched.iter().enumerate().take(seen.len()) {
                let value = counter.load(Ordering::Relaxed);
                // (Not started yet.)
                if value == 0 {
                    continue;
                }
                let (last, at, stuck) = &mut seen[i];
                if value != *last || *at == 0 {
                    if *stuck {
                        let _ = write!(line, "tick {now}: {name} moves again after {} ms\n", now - *at);
                    }
                    (*last, *at, *stuck) = (value, now, false);
                } else if !*stuck && now - *at >= STUCK_MS {
                    *stuck = true;
                    let _ = write!(line, "tick {now}: {name} has not moved for {} ms\n", now - *at);
                }
            }
            if line.len > 0 {
                let _ = file.write_all(&line.buf[..line.len]);
            }
        }
    })?;
    Ok(())
}

/// A line of text in place (no allocation), cut off when full.
struct Line {
    buf: [u8; 1024],
    len: usize,
}

impl Default for Line {
    fn default() -> Self {
        Line { buf: [0; 1024], len: 0 }
    }
}

impl std::fmt::Write for Line {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        let n = s.len().min(self.buf.len() - self.len);
        self.buf[self.len..self.len + n].copy_from_slice(&s.as_bytes()[..n]);
        self.len += n;
        Ok(())
    }
}

/// Space for the original pointer in front of an over-aligned block.
const HEADER: usize = std::mem::size_of::<usize>();

impl PrivateHeap {
    /// Allocates under the guard. Over-aligned layouts get `align` more
    /// bytes and the block's own address just below the returned pointer,
    /// as Rust's standard Windows allocator does.
    fn raw_alloc(&self, layout: Layout, flags: u32) -> *mut u8 {
        self.raw_alloc_with(layout, flags, || {
            // SAFETY: plain flags/sizes for a growable private heap.
            unsafe { HeapCreate(HEAP_NO_SERIALIZE, 0, 0) }
        })
    }

    fn raw_alloc_with(&self, layout: Layout, flags: u32, create: impl FnOnce() -> *mut c_void) -> *mut u8 {
        let heap = self.heap_or_create(create);
        if heap.is_null() { return std::ptr::null_mut(); }
        if layout.align() <= HEAP_ALIGN {
            let _guard = self.lock();
            // SAFETY: a valid heap handle, serialized by the guard.
            return unsafe { HeapAlloc(heap, HEAP_NO_SERIALIZE | flags, layout.size()) as *mut u8 };
        }
        let Some(size) = layout.size().checked_add(layout.align()) else { return std::ptr::null_mut() };
        let block = {
            let _guard = self.lock();
            // SAFETY: as above.
            unsafe { HeapAlloc(heap, HEAP_NO_SERIALIZE | flags, size) as *mut u8 }
        };
        if block.is_null() {
            return block;
        }
        // At least HEADER (<= HEAP_ALIGN < align) bytes before `aligned`
        // stay inside the block, and `aligned + size` ends inside it too.
        let offset = layout.align() - (block as usize & (layout.align() - 1));
        // SAFETY: offset is in 1..=align, within the size + align block.
        let aligned = unsafe { block.add(offset) };
        // SAFETY: aligned - HEADER >= block, and is pointer-aligned since
        // `aligned` is aligned to more than HEAP_ALIGN >= HEADER.
        unsafe { (aligned.sub(HEADER) as *mut usize).write(block as usize) };
        aligned
    }

    fn raw_free(&self, ptr: *mut u8, layout: Layout) {
        let block = if layout.align() <= HEAP_ALIGN {
            ptr
        } else {
            // SAFETY: written by raw_alloc for this over-aligned block.
            unsafe { (ptr.sub(HEADER) as *const usize).read() as *mut u8 }
        };
        // A valid allocation already published its owning private heap.
        // Deallocation must not create a replacement heap.
        let heap = self.heap.load(Ordering::Acquire);
        if heap.is_null() { return; }
        let _guard = self.lock();
        // SAFETY: `block` came from HeapAlloc on this heap.
        unsafe { HeapFree(heap, HEAP_NO_SERIALIZE, block as *const c_void) };
    }
}

// SAFETY: blocks come from one heap handle that lives for the process; all
// heap calls are serialized by `busy`. Layout requirements are met above.
unsafe impl GlobalAlloc for PrivateHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        self.raw_alloc(layout, 0)
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        self.raw_alloc(layout, HEAP_ZERO_MEMORY)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        self.raw_free(ptr, layout)
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if layout.align() <= HEAP_ALIGN {
            let heap = self.heap();
            if heap.is_null() { return std::ptr::null_mut(); }
            let _guard = self.lock();
            // SAFETY: `ptr` came from HeapAlloc on this heap.
            return unsafe { HeapReAlloc(heap, HEAP_NO_SERIALIZE, ptr as *const c_void, new_size) as *mut u8 };
        }
        // SAFETY: the caller guarantees a valid layout for new_size.
        let new_layout = unsafe { Layout::from_size_align_unchecked(new_size, layout.align()) };
        let new = self.raw_alloc(new_layout, 0);
        if !new.is_null() {
            // SAFETY: both blocks are valid for the smaller size, distinct.
            unsafe { std::ptr::copy_nonoverlapping(ptr, new, layout.size().min(new_size)) };
            self.raw_free(ptr, layout);
        }
        new
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::System::Memory::GetProcessHeap;

    static HEAP: PrivateHeap = PrivateHeap::new();

    #[test]
    fn private_heap_is_not_the_process_heap_and_honours_alignment() {
        // SAFETY: plain allocator calls with valid layouts, freed in kind.
        unsafe {
            let small = Layout::from_size_align(24, 8).unwrap();
            let p = HEAP.alloc_zeroed(small);
            assert!(!p.is_null());
            assert!(std::slice::from_raw_parts(p, 24).iter().all(|&b| b == 0));
            assert_ne!(HEAP.heap.load(Ordering::Acquire), GetProcessHeap());
            let p = HEAP.realloc(p, small, 4096);
            assert!(!p.is_null());
            HEAP.dealloc(p, Layout::from_size_align(4096, 8).unwrap());
            for align in [16, 64, 4096] {
                let layout = Layout::from_size_align(100, align).unwrap();
                let p = HEAP.alloc(layout);
                assert_eq!(p as usize % align, 0, "align {align}");
                p.write_bytes(0xA5, 100);
                let q = HEAP.realloc(p, layout, 5000);
                assert_eq!(q as usize % align, 0);
                assert!(std::slice::from_raw_parts(q, 100).iter().all(|&b| b == 0xA5));
                HEAP.dealloc(q, Layout::from_size_align(5000, align).unwrap());
            }
        }
    }

    /// A guard held for seconds and a counter that stops are both noted,
    /// and so is their end.
    #[test]
    fn the_watchdog_notes_a_held_guard_and_a_stopped_counter() {
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        static WATCHED: [(&str, &AtomicU64); 1] = [("the counter", &COUNTER)];
        let path = std::env::temp_dir().join(format!("inproc-watchdog-{}.log", std::process::id()));
        let _ = std::fs::remove_file(&path);
        watchdog(&path, &WATCHED).unwrap();
        {
            let _held = HEAP.lock();
            std::thread::sleep(std::time::Duration::from_millis(3000));
        }
        COUNTER.fetch_add(1, Ordering::Relaxed);
        std::thread::sleep(std::time::Duration::from_millis(1200));
        let text = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        // SAFETY: a plain read of this thread's id.
        let me = unsafe { GetCurrentThreadId() };
        assert!(text.contains(&format!("the allocator's guard held by thread {me:#x}")), "{text}");
        assert!(text.contains("the allocator's guard free again"), "{text}");
        assert!(text.contains("the counter has not moved"), "{text}");
        assert!(text.contains("the counter moves again"), "{text}");
    }

    #[test]
    fn concurrent_allocation_and_cross_thread_frees_stay_consistent() {
        let (tx, rx) = std::sync::mpsc::channel::<(usize, usize, usize)>();
        let workers: Vec<_> = (0..4)
            .map(|seed| {
                let tx = tx.clone();
                std::thread::spawn(move || {
                    for i in 0..20_000usize {
                        let size = 1 + (i * 7919 + seed * 104_729) % 3000;
                        let layout = Layout::from_size_align(size, if i % 5 == 0 { 32 } else { 8 }).unwrap();
                        // SAFETY: valid layout; the block is filled and either
                        // freed here or handed to the receiving thread.
                        unsafe {
                            let p = HEAP.alloc(layout);
                            assert!(!p.is_null());
                            p.write_bytes(seed as u8, size);
                            if i % 3 == 0 {
                                tx.send((p as usize, size, layout.align())).unwrap();
                            } else {
                                assert!(std::slice::from_raw_parts(p, size).iter().all(|&b| b == seed as u8));
                                HEAP.dealloc(p, layout);
                            }
                        }
                    }
                })
            })
            .collect();
        drop(tx);
        let mut freed = 0;
        while let Ok((p, size, align)) = rx.recv() {
            // SAFETY: allocated above with exactly this layout, sent once.
            unsafe { HEAP.dealloc(p as *mut u8, Layout::from_size_align(size, align).unwrap()) };
            freed += 1;
        }
        for w in workers {
            w.join().unwrap();
        }
        assert_eq!(freed, 4 * 6667);
    }

    /// Measurement, not a check (`--ignored --nocapture` under Wine): how
    /// long a "game" thread's process-heap allocations take while three
    /// "bridge" threads allocate like the publisher, from the process heap
    /// (Rust's default) or from a private one.
    #[test]
    #[ignore]
    fn measure_game_heap_latency_with_bridge_threads_on_either_heap() {
        use std::sync::atomic::AtomicBool;
        use std::time::{Duration, Instant};
        static PRIVATE: PrivateHeap = PrivateHeap::new();
        for private in [false, true] {
            let stop = std::sync::Arc::new(AtomicBool::new(false));
            let bridge: Vec<_> = (0..3)
                .map(|seed| {
                    let stop = stop.clone();
                    std::thread::spawn(move || {
                        // SAFETY: valid layouts and handles; each block freed in kind.
                        let process = unsafe { GetProcessHeap() };
                        let mut i: usize = seed;
                        while !stop.load(Ordering::Relaxed) {
                            let size = 16 + i.wrapping_mul(7919) % 70_000;
                            let layout = Layout::from_size_align(size, 8).unwrap();
                            unsafe {
                                if private {
                                    PRIVATE.dealloc(PRIVATE.alloc(layout), layout);
                                } else {
                                    HeapFree(process, 0, HeapAlloc(process, 0, size));
                                }
                            }
                            i += 1;
                        }
                    })
                })
                .collect();
            // SAFETY: as above.
            let process = unsafe { GetProcessHeap() };
            let mut took = Vec::with_capacity(200_000);
            let end = Instant::now() + Duration::from_secs(3);
            let mut i = 0usize;
            while Instant::now() < end {
                let t = Instant::now();
                unsafe { HeapFree(process, 0, HeapAlloc(process, 0, 32 + i % 2000)) };
                took.push(t.elapsed());
                i += 1;
            }
            stop.store(true, Ordering::Relaxed);
            for b in bridge {
                b.join().unwrap();
            }
            took.sort();
            let at = |q: f64| took[((took.len() - 1) as f64 * q) as usize];
            println!(
                "game-thread process-heap alloc+free with bridge threads on the {} heap: n {}, p50 {:?}, p99 {:?}, p99.9 {:?}, max {:?}",
                if private { "private" } else { "process" },
                took.len(), at(0.5), at(0.99), at(0.999), took[took.len() - 1]
            );
        }
    }
}

#[cfg(test)]
mod creation_failure_tests {
    use super::*;

    #[test]
    fn failed_private_heap_creation_returns_null_without_using_a_shared_heap() {
        let heap = PrivateHeap::new();
        for (alignment, flags) in [(HEAP_ALIGN, 0), (HEAP_ALIGN, HEAP_ZERO_MEMORY),
            (HEAP_ALIGN * 4, 0), (HEAP_ALIGN * 4, HEAP_ZERO_MEMORY)] {
            let layout = Layout::from_size_align(37, alignment).unwrap();
            assert!(heap.raw_alloc_with(layout, flags, std::ptr::null_mut).is_null());
            assert!(heap.heap.load(Ordering::Acquire).is_null());
            assert!(!heap.busy.load(Ordering::Relaxed));
        }
    }

    #[test]
    fn a_failed_creator_uses_only_a_concurrently_published_private_winner() {
        let heap = PrivateHeap::new();
        let winner = PrivateHeap::new();
        let winner_handle = winner.heap();
        assert!(!winner_handle.is_null());
        let found = heap.heap_or_create(|| {
            heap.heap.store(winner_handle, Ordering::Release);
            std::ptr::null_mut()
        });
        assert_eq!(found, winner_handle);
        // Neither PrivateHeap instance frees its process-lifetime heap.
        // SAFETY: this isolated test owns the empty heap; no later call uses
        // either PrivateHeap instance, so it can release that handle now.
        unsafe { assert_ne!(HeapDestroy(winner_handle), 0); }
    }
}
