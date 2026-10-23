//! Where one watched thread's time goes inside our hooks: for telling a
//! program that is slow by itself from one our hooks make slow.
//!
//! Every hook trampoline (`fastcall_hook!`, `stdcall_hook!`, `cdecl_hook!`,
//! `call_site_hook!`) enters [`Hook`] and every call of the program's
//! original function from a handler enters [`Original`]. Between those
//! transitions the watched thread runs our code, and that time is charged
//! to the innermost hook running: a handler's own time, without the
//! original it calls (the program's own time) and without the hooks that
//! original reaches (charged to themselves). Nothing is counted on other
//! threads, nor before [`watch_current_thread`].
//!
//! Lock-free and allocation-free on the hot path: two clock reads per
//! transition, a few relaxed atomics. Stats register themselves once, on
//! their first counted call, in a fixed table that [`snapshot`] reads.

use std::cell::Cell;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicU64, AtomicUsize, Ordering::{Acquire, Relaxed, Release}};
use std::time::Instant;

/// One hook's totals: its own time on the watched thread and how often it
/// was entered there.
pub struct Stat {
    name: &'static str,
    nanos: AtomicU64,
    calls: AtomicU64,
    registered: AtomicBool,
}

impl Stat {
    pub const fn new(name: &'static str) -> Self {
        Stat { name, nanos: AtomicU64::new(0), calls: AtomicU64::new(0), registered: AtomicBool::new(false) }
    }

    fn register(&'static self) {
        if self.registered.swap(true, Relaxed) {
            return;
        }
        let i = COUNT.fetch_add(1, Relaxed);
        if i < TABLE_LEN {
            TABLE[i].store(self as *const Stat as *mut Stat, Release);
        }
    }
}

const TABLE_LEN: usize = 256;
static TABLE: [AtomicPtr<Stat>; TABLE_LEN] = [const { AtomicPtr::new(std::ptr::null_mut()) }; TABLE_LEN];
static COUNT: AtomicUsize = AtomicUsize::new(0);

/// Totals over everything we ran on the watched thread (ns, entries).
static TOTAL_NANOS: AtomicU64 = AtomicU64::new(0);
static TOTAL_CALLS: AtomicU64 = AtomicU64::new(0);

/// The watched thread (an id of [`thread_key`]; 0: none yet).
static WATCHED: AtomicU32 = AtomicU32::new(0);
static NEXT_KEY: AtomicU32 = AtomicU32::new(1);
static ENABLED: OnceLock<bool> = OnceLock::new();

thread_local! {
    static KEY: u32 = NEXT_KEY.fetch_add(1, Relaxed);
    static STATE: Cell<State> = const { Cell::new(State { since: 0, current: std::ptr::null() }) };
}

fn thread_key() -> u32 {
    KEY.with(|k| *k)
}

fn enabled() -> bool {
    *ENABLED.get_or_init(|| std::env::var("CIV3R_HOOK_TIMING").map_or(true, |v| v != "0"))
}

/// Counts this thread's time from now on (the first caller wins; later
/// calls from any thread change nothing). Off with `CIV3R_HOOK_TIMING=0`.
pub fn watch_current_thread() {
    if WATCHED.load(Relaxed) == 0 && enabled() {
        let _ = WATCHED.compare_exchange(0, thread_key(), Relaxed, Relaxed);
    }
}

fn watched() -> bool {
    let w = WATCHED.load(Relaxed);
    w != 0 && w == thread_key()
}

fn epoch() -> Instant {
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    *EPOCH.get_or_init(Instant::now)
}

/// Nanoseconds since the epoch (never 0: 0 means "not in our code").
fn now_ns() -> u64 {
    (epoch().elapsed().as_nanos() as u64).max(1)
}

/// The watched thread's position: since when it runs our code (0: the
/// program's code), charged to which hook.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct State {
    since: u64,
    current: *const Stat,
}

/// Charges the time since `since` to the current hook, at `now`.
fn charge(state: &mut State, now: u64) {
    if state.since != 0 && !state.current.is_null() {
        let spent = now.saturating_sub(state.since);
        // SAFETY: `current` only ever holds a `&'static Stat`.
        let stat = unsafe { &*state.current };
        stat.nanos.fetch_add(spent, Relaxed);
        TOTAL_NANOS.fetch_add(spent, Relaxed);
    }
    if state.since != 0 {
        state.since = now;
    }
}

fn enter_hook(state: &mut State, stat: &'static Stat, now: u64) -> State {
    charge(state, now);
    let before = *state;
    stat.calls.fetch_add(1, Relaxed);
    if before.since == 0 {
        TOTAL_CALLS.fetch_add(1, Relaxed);
    }
    *state = State { since: now, current: stat };
    before
}

fn leave_hook(state: &mut State, before: State, now: u64) {
    charge(state, now);
    *state = State { since: if before.since != 0 { now } else { 0 }, current: before.current };
}

fn enter_original(state: &mut State, now: u64) -> State {
    charge(state, now);
    let before = *state;
    state.since = 0;
    before
}

fn leave_original(state: &mut State, before: State, now: u64) {
    *state = State { since: if before.since != 0 { now } else { 0 }, current: before.current };
}

/// Inside a hook's trampoline until dropped (see the module docs).
pub struct Hook(Option<State>);

impl Hook {
    #[inline]
    pub fn enter(stat: &'static Stat) -> Hook {
        if !watched() {
            return Hook(None);
        }
        stat.register();
        Hook(Some(STATE.with(|s| {
            let mut state = s.get();
            let before = enter_hook(&mut state, stat, now_ns());
            s.set(state);
            before
        })))
    }
}

impl Drop for Hook {
    #[inline]
    fn drop(&mut self) {
        if let Some(before) = self.0.take() {
            STATE.with(|s| {
                let mut state = s.get();
                leave_hook(&mut state, before, now_ns());
                s.set(state);
            });
        }
    }
}

/// Inside the program's original function, called from a handler, until
/// dropped.
pub struct Original(Option<State>);

impl Original {
    #[inline]
    pub fn enter() -> Original {
        if !watched() {
            return Original(None);
        }
        Original(Some(STATE.with(|s| {
            let mut state = s.get();
            let before = enter_original(&mut state, now_ns());
            s.set(state);
            before
        })))
    }
}

impl Drop for Original {
    #[inline]
    fn drop(&mut self) {
        if let Some(before) = self.0.take() {
            STATE.with(|s| {
                let mut state = s.get();
                leave_original(&mut state, before, now_ns());
                s.set(state);
            });
        }
    }
}

/// The totals now: (all of our time in ns, outermost entries) and each
/// hook's (name, ns, calls).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Snapshot {
    pub nanos: u64,
    pub calls: u64,
    pub hooks: Vec<(&'static str, u64, u64)>,
}

pub fn snapshot() -> Snapshot {
    let n = COUNT.load(Relaxed).min(TABLE_LEN);
    // By position in the table (append-only), so that `since` pairs a
    // hook with itself even where two share a name; a slot still being
    // filled reads as nothing yet.
    let hooks = TABLE[..n].iter().map(|p| {
        let p = p.load(Acquire);
        // SAFETY: the table only holds `&'static Stat`s.
        (!p.is_null()).then(|| unsafe { &*p }).map_or(("", 0, 0), |s| (s.name, s.nanos.load(Relaxed), s.calls.load(Relaxed)))
    }).collect();
    Snapshot { nanos: TOTAL_NANOS.load(Relaxed), calls: TOTAL_CALLS.load(Relaxed), hooks }
}

impl Snapshot {
    /// What happened between `earlier` and this one: our time (ms), the
    /// outermost entries, and the hooks with the most time (name, ms,
    /// calls), at most `top` of them.
    pub fn since(&self, earlier: &Snapshot, top: usize) -> (u64, u64, Vec<(&'static str, u64, u64)>) {
        let mut hooks: Vec<_> = self.hooks.iter().enumerate().map(|(i, &(name, ns, calls))| {
            let (ns0, calls0) = earlier.hooks.get(i).map_or((0, 0), |h| (h.1, h.2));
            (name, ns.saturating_sub(ns0), calls.saturating_sub(calls0))
        }).filter(|h| h.2 > 0).collect();
        hooks.sort_by_key(|h| std::cmp::Reverse(h.1));
        hooks.truncate(top);
        let ms = |ns: u64| ns / 1_000_000;
        (ms(self.nanos.saturating_sub(earlier.nanos)), self.calls.saturating_sub(earlier.calls),
            hooks.into_iter().map(|(n, ns, c)| (n, ms(ns), c)).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handlers_own_time_excludes_originals_and_nested_hooks() {
        static OUTER: Stat = Stat::new("outer");
        static INNER: Stat = Stat::new("inner");
        let base = (OUTER.nanos.load(Relaxed), INNER.nanos.load(Relaxed), TOTAL_NANOS.load(Relaxed));
        let mut s = State { since: 0, current: std::ptr::null() };
        // Game code calls the outer hook at 100; its handler runs 10 ns,
        // calls the original (game code) at 110 ...
        let outer = enter_hook(&mut s, &OUTER, 100);
        let original = enter_original(&mut s, 110);
        // ... which reaches the inner hook at 150 (5 ns of handler) ...
        let inner = enter_hook(&mut s, &INNER, 150);
        leave_hook(&mut s, inner, 155);
        // ... and returns at 200; the outer handler runs 20 ns more.
        leave_original(&mut s, original, 200);
        leave_hook(&mut s, outer, 220);
        assert_eq!(s, State { since: 0, current: std::ptr::null() });
        assert_eq!(OUTER.nanos.load(Relaxed) - base.0, 30);
        assert_eq!(INNER.nanos.load(Relaxed) - base.1, 5);
        assert_eq!(TOTAL_NANOS.load(Relaxed) - base.2, 35);
    }

    #[test]
    fn a_hook_reached_from_our_own_code_charges_itself() {
        static HANDLER: Stat = Stat::new("handler");
        static API: Stat = Stat::new("api");
        let base = (HANDLER.nanos.load(Relaxed), API.nanos.load(Relaxed));
        let mut s = State { since: 0, current: std::ptr::null() };
        let a = enter_hook(&mut s, &HANDLER, 1);
        // The handler calls a hooked API itself (no original in between).
        let b = enter_hook(&mut s, &API, 11);
        leave_hook(&mut s, b, 14);
        leave_hook(&mut s, a, 21);
        assert_eq!(HANDLER.nanos.load(Relaxed) - base.0, 17);
        assert_eq!(API.nanos.load(Relaxed) - base.1, 3);
    }

    #[test]
    fn since_lists_the_hooks_with_the_most_time() {
        let before = Snapshot { nanos: 1_000_000, calls: 3, hooks: vec![("a", 1_000_000, 3)] };
        let after = Snapshot { nanos: 9_000_000, calls: 10, hooks: vec![("a", 3_000_000, 8), ("b", 7_000_000, 2), ("c", 0, 0)] };
        assert_eq!(after.since(&before, 5), (8, 7, vec![("b", 7, 2), ("a", 2, 5)]));
        assert_eq!(after.since(&before, 1).2, vec![("b", 7, 2)]);
    }
}
