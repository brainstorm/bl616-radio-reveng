// SPDX-FileCopyrightText: 2026 Roman Valls Guimera <brainstorm@nopcode.org>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! `pvPortMalloc` and `vPortFree`, over Rust's global allocator.
//!
//! FreeRTOS's heap_4 is replaced by whatever allocator the firmware already
//! installs, which on this system is the SDK's TLSF heap. The size has to be
//! remembered because `vPortFree` is not told it, so each block carries a
//! header — the same trick heap_4 uses, for the same reason.

use core::alloc::Layout;
use core::ffi::c_void;

/// Kept at least 8 so every returned pointer stays 8-byte aligned.
const HEADER: usize = 8;

/// # Safety
///
/// Standard allocator contract.
pub unsafe fn alloc(size: usize) -> *mut c_void {
    let Ok(layout) = Layout::from_size_align(size + HEADER, HEADER) else {
        return core::ptr::null_mut();
    };
    let base = unsafe { alloc::alloc::alloc(layout) };
    if base.is_null() {
        return core::ptr::null_mut();
    }
    unsafe { (base as *mut usize).write(size) };
    unsafe { base.add(HEADER) as *mut c_void }
}

/// # Safety
///
/// `ptr` must have come from [`alloc`].
pub unsafe fn free(ptr: *mut c_void) {
    if ptr.is_null() {
        return;
    }
    let base = unsafe { (ptr as *mut u8).sub(HEADER) };
    let size = unsafe { (base as *mut usize).read() };
    let Ok(layout) = Layout::from_size_align(size + HEADER, HEADER) else {
        return;
    };
    unsafe { alloc::alloc::dealloc(base, layout) };
}
