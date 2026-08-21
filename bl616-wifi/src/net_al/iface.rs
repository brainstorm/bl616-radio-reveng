// SPDX-FileCopyrightText: 2026 Roman Valls Guimera <brainstorm@nopcode.org>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Network interfaces and the receive queue.
//!
//! The blob addresses interfaces through `net_al_if_t`, an opaque `void *` it
//! never dereferences — it only hands the value back. That means Rust is free
//! to make it a pointer to whatever it likes; here it points into a fixed
//! array of [`NetIf`], so there is no allocation on the control path and an
//! interface handle can always be validated before use.
//!
//! Two interfaces are enough: the vendor stack runs one station and one
//! soft-AP, named `wl0`/`wl1` (`NET_AL_MAX_IFNAME` is 4 bytes including NUL).

use core::ffi::c_void;
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

/// Interfaces the vendor stack can bring up: one STA, one AP.
pub const MAX_IF: usize = 2;
/// Longest interface name, including the NUL. Fixed by `NET_AL_MAX_IFNAME`.
pub const MAX_IFNAME: usize = 4;

/// Frames buffered between the blob's RX callback and the IP stack.
///
/// The callback runs in the blob's context and must not block, so it copies
/// into this ring and returns. A full ring drops the frame, which is the
/// correct behaviour — the alternative is stalling the MAC.
pub const RX_RING: usize = 12;
/// Largest frame the ring will accept.
pub const RX_FRAME_MAX: usize = 1536;

/// One network interface.
#[repr(C)]
pub struct NetIf {
    /// Whether this slot is in use.
    pub used: AtomicBool,
    /// Whether the link is up, per `net_if_up_cb` / `net_if_down_cb`.
    pub link_up: AtomicBool,
    /// MAC address, as reported to the blob by `net_if_get_mac_addr`.
    pub mac: [u8; 6],
    /// `wl0` / `wl1`, NUL-terminated.
    pub name: [u8; MAX_IFNAME],
    /// The blob's per-VIF private pointer, returned by `net_if_vif_info`.
    pub vif_priv: *mut c_void,
    /// IPv4 configuration, network byte order, 0 when unset.
    pub ipaddr: AtomicU32,
    pub netmask: AtomicU32,
    pub gw: AtomicU32,
    pub dns: AtomicU32,
    /// Ethertype registered by `net_l2_socket_create`, 0 when none. The
    /// supplicant uses this to receive EAPOL.
    pub l2_ethertype: AtomicU32,
}

impl NetIf {
    const fn new() -> Self {
        NetIf {
            used: AtomicBool::new(false),
            link_up: AtomicBool::new(false),
            mac: [0; 6],
            name: [0; MAX_IFNAME],
            vif_priv: ptr::null_mut(),
            ipaddr: AtomicU32::new(0),
            netmask: AtomicU32::new(0),
            gw: AtomicU32::new(0),
            dns: AtomicU32::new(0),
            l2_ethertype: AtomicU32::new(0),
        }
    }
}

static mut IFACES: [NetIf; MAX_IF] = [NetIf::new(), NetIf::new()];

fn iface_base() -> *mut NetIf {
    ptr::addr_of_mut!(IFACES) as *mut NetIf
}

/// Claim a free interface slot and initialise it.
pub fn add(mac: &[u8; 6], vif_priv: *mut c_void) -> Option<*mut NetIf> {
    let base = iface_base();
    for i in 0..MAX_IF {
        let p = unsafe { base.add(i) };
        let slot = unsafe { &*p };
        if slot
            .used
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            unsafe {
                (*p).mac = *mac;
                (*p).vif_priv = vif_priv;
                // "wl0", "wl1" -- three characters plus NUL fits MAX_IFNAME.
                (*p).name = [b'w', b'l', b'0' + i as u8, 0];
                (*p).link_up.store(false, Ordering::Release);
                (*p).ipaddr.store(0, Ordering::Release);
                (*p).netmask.store(0, Ordering::Release);
                (*p).gw.store(0, Ordering::Release);
                (*p).dns.store(0, Ordering::Release);
                (*p).l2_ethertype.store(0, Ordering::Release);
            }
            return Some(p);
        }
    }
    None
}

/// Check that a handle from the blob really points at one of our slots.
///
/// Cheap, and it turns a stale or bogus handle into a rejected call rather
/// than a write through a wild pointer.
pub fn validate(net_if: *mut c_void) -> Option<&'static NetIf> {
    if net_if.is_null() {
        return None;
    }
    let base = iface_base();
    let offset = (net_if as usize).wrapping_sub(base as usize);
    let stride = core::mem::size_of::<NetIf>();
    if offset % stride != 0 || offset / stride >= MAX_IF {
        return None;
    }
    let slot = unsafe { &*(net_if as *const NetIf) };
    slot.used.load(Ordering::Acquire).then_some(slot)
}

/// Find an interface by name, as `net_if_find_from_name` does.
pub fn find_by_name(name: &[u8]) -> Option<*mut NetIf> {
    let base = iface_base();
    for i in 0..MAX_IF {
        let p = unsafe { base.add(i) };
        let slot = unsafe { &*p };
        if !slot.used.load(Ordering::Acquire) {
            continue;
        }
        let n = &slot.name;
        let len = n.iter().position(|&c| c == 0).unwrap_or(n.len());
        if &n[..len] == name {
            return Some(p);
        }
    }
    None
}

/// The station interface, which is slot 0 once it exists.
pub fn primary() -> Option<*mut NetIf> {
    let p = iface_base();
    unsafe { &*p }.used.load(Ordering::Acquire).then_some(p)
}

// ------------------------------------------------------------------ RX ring

struct RxSlot {
    len: AtomicUsize,
    iface: AtomicUsize,
    data: [u8; RX_FRAME_MAX],
}

impl RxSlot {
    const fn new() -> Self {
        RxSlot {
            len: AtomicUsize::new(0),
            iface: AtomicUsize::new(0),
            data: [0; RX_FRAME_MAX],
        }
    }
}

static mut RX_SLOTS: [RxSlot; RX_RING] = [const { RxSlot::new() }; RX_RING];
static RX_HEAD: AtomicUsize = AtomicUsize::new(0);
static RX_TAIL: AtomicUsize = AtomicUsize::new(0);
static RX_DROPPED: AtomicU32 = AtomicU32::new(0);
static RX_ACCEPTED: AtomicU32 = AtomicU32::new(0);

/// Copy a received frame into the ring.
///
/// Called from the blob's RX path, so it copies and returns rather than
/// holding the blob's buffer: keeping it would stall the MAC's descriptor
/// ring behind however long the IP stack takes.
///
/// Returns false if the ring is full, in which case the frame is dropped.
///
/// # Safety
///
/// `frame` must point to at least `len` readable bytes.
pub unsafe fn rx_push(iface: *mut NetIf, frame: *const u8, len: usize) -> bool {
    if len == 0 || len > RX_FRAME_MAX || frame.is_null() {
        RX_DROPPED.fetch_add(1, Ordering::Relaxed);
        return false;
    }
    let head = RX_HEAD.load(Ordering::Relaxed);
    let tail = RX_TAIL.load(Ordering::Acquire);
    if head.wrapping_sub(tail) >= RX_RING {
        RX_DROPPED.fetch_add(1, Ordering::Relaxed);
        return false;
    }

    let slot = unsafe { &mut *(ptr::addr_of_mut!(RX_SLOTS) as *mut RxSlot).add(head % RX_RING) };
    unsafe { ptr::copy_nonoverlapping(frame, slot.data.as_mut_ptr(), len) };
    slot.iface.store(iface as usize, Ordering::Relaxed);
    slot.len.store(len, Ordering::Relaxed);

    RX_HEAD.store(head.wrapping_add(1), Ordering::Release);
    RX_ACCEPTED.fetch_add(1, Ordering::Relaxed);
    true
}

/// Take the oldest frame, copying it into `out`. Returns its length and the
/// interface it arrived on.
pub fn rx_pop(out: &mut [u8]) -> Option<(usize, *mut NetIf)> {
    let tail = RX_TAIL.load(Ordering::Relaxed);
    let head = RX_HEAD.load(Ordering::Acquire);
    if tail == head {
        return None;
    }
    let slot = unsafe { &*(ptr::addr_of!(RX_SLOTS) as *const RxSlot).add(tail % RX_RING) };
    let len = slot.len.load(Ordering::Relaxed).min(out.len());
    out[..len].copy_from_slice(&slot.data[..len]);
    let iface = slot.iface.load(Ordering::Relaxed) as *mut NetIf;

    RX_TAIL.store(tail.wrapping_add(1), Ordering::Release);
    Some((len, iface))
}

/// Frames accepted and frames dropped for want of ring space.
pub fn rx_stats() -> (u32, u32) {
    (
        RX_ACCEPTED.load(Ordering::Relaxed),
        RX_DROPPED.load(Ordering::Relaxed),
    )
}
