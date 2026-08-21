// SPDX-FileCopyrightText: 2026 Roman Valls Guimera <brainstorm@nopcode.org>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Rust's global allocator, backed by the SDK's TLSF heap.
//!
//! The WiFi stack allocates from the same heap, so `alloc` here is not free
//! real estate: check [`crate::runtime::free_heap`] before and after
//! association if you plan to use much of it. Association is the high-water
//! mark.
//!
//! `malloc` guarantees only `max_align_t` (8 bytes here). Anything stricter is
//! served by over-allocating and stashing the original pointer just below the
//! aligned block, which is why `dealloc` has to read it back.

use core::alloc::{GlobalAlloc, Layout};
use core::ffi::c_void;

use bl616_wifi_sys as sys;

/// Alignment `malloc` is already guaranteed to satisfy.
const MALLOC_ALIGN: usize = 8;

struct SdkHeap;

unsafe impl GlobalAlloc for SdkHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if layout.align() <= MALLOC_ALIGN {
            return unsafe { sys::malloc(layout.size()) as *mut u8 };
        }

        // Room for the block, the worst-case adjustment, and the back-pointer.
        let Some(total) = layout
            .size()
            .checked_add(layout.align())
            .and_then(|n| n.checked_add(core::mem::size_of::<usize>()))
        else {
            return core::ptr::null_mut();
        };

        let raw = unsafe { sys::malloc(total) } as usize;
        if raw == 0 {
            return core::ptr::null_mut();
        }

        let aligned =
            (raw + core::mem::size_of::<usize>() + layout.align() - 1) & !(layout.align() - 1);
        unsafe { ((aligned - core::mem::size_of::<usize>()) as *mut usize).write(raw) };
        aligned as *mut u8
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ptr.is_null() {
            return;
        }
        let raw = if layout.align() <= MALLOC_ALIGN {
            ptr as *mut c_void
        } else {
            unsafe { (ptr as *mut usize).offset(-1).read() as *mut c_void }
        };
        unsafe { sys::free(raw) }
    }
}

#[global_allocator]
static ALLOCATOR: SdkHeap = SdkHeap;
