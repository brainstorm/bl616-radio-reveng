// SPDX-FileCopyrightText: 2026 Roman Valls Guimera <brainstorm@nopcode.org>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! TX buffers, in shared RAM, because the MAC DMAs straight out of them.
//!
//! `net_buf_tx_info` hands segment addresses to the MAC hardware without
//! copying, so every TX payload has to sit in the region the hardware can
//! reach. The linker script brackets that region with `_sshram`/`_eshram` and
//! fills it from `*(SHAREDRAM)` and `*(.wifi_ram*)` — so the way to get a Rust
//! static in there is to name one of those sections. Hence
//! `#[link_section = ".wifi_ram.bl616_txpool"]` below: the pool lands inside
//! `wifi_bss` and is DMA-able by construction, with no runtime check needed.
//!
//! Each buffer is laid out headroom-first:
//!
//! ```text
//!   data[0 .. HEADROOM]          reserved for the MAC's 802.11 header
//!   data[HEADROOM .. HEADROOM+n] the IEEE 802.3 frame
//! ```
//!
//! The pool is small on purpose — `ram_wifi` is 160 KiB and the blob's own
//! statics already claim ~141 KiB of it, so there is only about 22 KiB spare.

use core::ptr;
use core::sync::atomic::{AtomicU32, Ordering};

/// Headroom reserved ahead of every frame.
///
/// `NET_AL_TX_HEADROOM` is 384, but the vendor's lwIP port reserves
/// `PBUF_LINK_ENCAPSULATION_HLEN` = 388 and the blob is exercised against
/// that. Matching it costs 4 bytes a buffer and avoids finding out the hard
/// way that something rounds.
pub const HEADROOM: usize = 388;

/// Largest IEEE 802.3 frame carried, rounded up for alignment.
pub const MAX_FRAME: usize = 1536;

/// Usable bytes per buffer.
pub const BUF_LEN: usize = HEADROOM + MAX_FRAME;

/// Buffers in the pool.
///
/// Dropping lwIP freed ~60 KiB of shared RAM — `ram_wifi` went from 141 KiB
/// used to 81 KiB — so there is room for a deeper pool than the vendor's
/// arrangement allowed. Sixteen costs ~31 KiB and still leaves headroom; the
/// failure mode if this is raised too far is a `ram_wifi` overflow at link
/// time, which is loud rather than subtle.
pub const POOL_SIZE: usize = 16;

const _: () = assert!(POOL_SIZE <= 32, "the free mask is a u32");
const _: () = assert!(HEADROOM >= 384, "below NET_AL_TX_HEADROOM");

/// A TX buffer as the blob sees it: an opaque handle it never dereferences,
/// only hands back to [`super::net_buf_tx_info`] and [`super::net_buf_tx_free`].
#[repr(C, align(8))]
pub struct TxBuf {
    /// Next segment of the same frame, for `net_buf_tx_cat`. Null when last.
    pub next: *mut TxBuf,
    /// Frame length in `data[HEADROOM..]`, excluding headroom.
    pub len: u16,
    /// Index into the pool. Lets `free` be O(1) and, more usefully, lets it
    /// reject a pointer that did not come from here.
    pub slot: u16,
    /// Headroom followed by the frame.
    pub data: [u8; BUF_LEN],
}

impl TxBuf {
    /// Pointer to the frame itself, which is what the MAC is told to read.
    pub fn frame_ptr(&mut self) -> *mut u8 {
        unsafe { self.data.as_mut_ptr().add(HEADROOM) }
    }

    /// Pointer to the headroom, which the MAC fills with the 802.11 header.
    pub fn headroom_ptr(&mut self) -> *mut u8 {
        self.data.as_mut_ptr()
    }
}

// The pool lives in shared RAM. `wifi_bss` is NOLOAD in the linker script, so
// this is zero-initialised at reset like any other BSS.
#[used]
#[link_section = ".wifi_ram.bl616_txpool"]
static mut TX_POOL: [TxBuf; POOL_SIZE] = unsafe { core::mem::zeroed() };

/// One bit per free slot. Lock-free because the blob frees buffers from its
/// own tasks and, for confirmations, from interrupt context.
static FREE_MASK: AtomicU32 = AtomicU32::new(if POOL_SIZE == 32 {
    u32::MAX
} else {
    (1u32 << POOL_SIZE) - 1
});

/// High-water mark, for `bl616_wifi::net_al::stats`.
static IN_USE_PEAK: AtomicU32 = AtomicU32::new(0);
/// Allocations that found the pool empty.
static EXHAUSTED: AtomicU32 = AtomicU32::new(0);

/// Woken when a buffer returns to the pool.
///
/// embassy-net's `Driver::transmit` must arm a waker when it declines for want
/// of space, or the stack never retries. The blob frees buffers from its own
/// tasks and from interrupt context, which is exactly where this fires.
#[cfg(feature = "embassy-net")]
pub static TX_WAKER: embassy_sync::waitqueue::AtomicWaker =
    embassy_sync::waitqueue::AtomicWaker::new();

fn pool_base() -> *mut TxBuf {
    ptr::addr_of_mut!(TX_POOL) as *mut TxBuf
}

/// Claim a buffer, or `None` if the pool is empty.
///
/// Running dry is normal back-pressure, not an error: the caller drops the
/// frame and the peer retransmits.
pub fn alloc() -> Option<*mut TxBuf> {
    let mut mask = FREE_MASK.load(Ordering::Acquire);
    loop {
        if mask == 0 {
            EXHAUSTED.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        let slot = mask.trailing_zeros();
        let claimed = mask & !(1 << slot);
        match FREE_MASK.compare_exchange_weak(mask, claimed, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => {
                let in_use = POOL_SIZE as u32 - claimed.count_ones();
                IN_USE_PEAK.fetch_max(in_use, Ordering::Relaxed);

                let buf = unsafe { pool_base().add(slot as usize) };
                unsafe {
                    (*buf).next = ptr::null_mut();
                    (*buf).len = 0;
                    (*buf).slot = slot as u16;
                }
                return Some(buf);
            }
            Err(seen) => mask = seen,
        }
    }
}

/// Claim a buffer and copy `frame` into it behind the headroom.
///
/// # Safety
///
/// `frame` must point to at least `length` readable bytes.
pub unsafe fn alloc_fill(frame: *const u8, length: usize) -> Option<*mut TxBuf> {
    if length > MAX_FRAME || frame.is_null() {
        return None;
    }
    let buf = alloc()?;
    unsafe {
        ptr::copy_nonoverlapping(frame, (*buf).frame_ptr(), length);
        (*buf).len = length as u16;
    }
    Some(buf)
}

/// Return a buffer, and every segment chained after it, to the pool.
///
/// # Safety
///
/// `buf` must have come from [`alloc`] and must not be in flight. Pointers
/// that did not come from the pool are ignored rather than corrupting it —
/// the blob is not always careful, and a wild free here would be a DMA fault
/// much later and somewhere else.
pub unsafe fn free(buf: *mut TxBuf) {
    let base = pool_base();
    let mut cur = buf;

    while !cur.is_null() {
        let offset = (cur as usize).wrapping_sub(base as usize);
        let stride = core::mem::size_of::<TxBuf>();
        if offset % stride != 0 || offset / stride >= POOL_SIZE {
            return;
        }
        let slot = offset / stride;
        let next = unsafe { (*cur).next };
        unsafe {
            (*cur).next = ptr::null_mut();
            (*cur).len = 0;
        }
        FREE_MASK.fetch_or(1 << slot, Ordering::AcqRel);
        #[cfg(feature = "embassy-net")]
        TX_WAKER.wake();
        cur = next;
    }
}

/// Buffers available right now.
///
/// embassy's `transmit` must decide before building the frame, unlike
/// smoltcp's, which can allocate inside `consume`.
pub fn free_count() -> u32 {
    FREE_MASK.load(Ordering::Relaxed).count_ones()
}

/// Buffers in flight, peak in flight, and allocations that found none free.
pub fn stats() -> (u32, u32, u32) {
    let free = FREE_MASK.load(Ordering::Relaxed).count_ones();
    (
        POOL_SIZE as u32 - free,
        IN_USE_PEAK.load(Ordering::Relaxed),
        EXHAUSTED.load(Ordering::Relaxed),
    )
}
