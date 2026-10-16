//! Hooks against real x86 code (32-bit Windows only; runs under Wine).
#![cfg(all(windows, target_arch = "x86"))]
#![allow(unsafe_code)]

use std::sync::atomic::{AtomicU32, Ordering};

// fastcall: ecx = this, edx = unused, one stack argument; returns this + 2·a.
// Starts with the same self-contained prologue as Civ III's
// Sprite_draw_on_map (sub esp,0Ch / push esi / push edi).
std::arch::global_asm!(
    ".globl _inproc_test_target",
    "_inproc_test_target:",
    ".byte 0x83, 0xec, 0x0c", // sub esp, 0Ch
    "push esi",
    "push edi",
    "mov eax, [esp+0x18]",
    "add eax, eax",
    "add eax, ecx",
    "pop edi",
    "pop esi",
    "add esp, 0x0c",
    "ret 4",
);

unsafe extern "fastcall" {
    fn inproc_test_target(this: u32, edx: u32, a: u32) -> u32;
}

fn call_target(this: u32, a: u32) -> u32 {
    // SAFETY: the assembly above has exactly this signature.
    unsafe { inproc_test_target(this, 0, a) }
}

// One hook module is shared by the tests, which cargo runs in parallel.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

inproc::fastcall_hook! {
    mod target_hook(this, edx; a) -> u32;
}

#[test]
fn inline_hook_intercepts_calls_original_and_restores() {
    let _serial = SERIAL.lock().unwrap();
    assert_eq!(call_target(10, 3), 16);
    let seen = std::sync::Arc::new(AtomicU32::new(0));
    let s = seen.clone();
    let addr = inproc_test_target as usize as u32;
    let hook = target_hook::install_inline(addr, &[0x83, 0xEC, 0x0C, 0x56, 0x57], move |call| {
        s.store(call.a, Ordering::SeqCst);
        // Through the trampoline, with a modified argument, plus 1000.
        call.original_with(call.this, call.a + 1) + 1000
    })
    .expect("install");
    assert_eq!(call_target(10, 3), 10 + 8 + 1000);
    assert_eq!(seen.load(Ordering::SeqCst), 3);
    drop(hook);
    assert_eq!(call_target(10, 3), 16);
}

#[test]
fn inline_hook_refuses_unexpected_code() {
    let _serial = SERIAL.lock().unwrap();
    let addr = inproc_test_target as usize as u32;
    let err = target_hook::install_inline(addr, &[0x90, 0x90, 0x90, 0x90, 0x90], |c| c.original());
    assert!(matches!(err, Err(inproc::hook::HookError::UnexpectedCode { .. })));
    assert_eq!(call_target(1, 1), 3);
}
