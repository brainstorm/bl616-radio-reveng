// SPDX-FileCopyrightText: 2026 Roman Valls Guimera <brainstorm@nopcode.org>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! The vendor stack's network adapter, in Rust.
//!
//! The blobs reach the network through ~24 `net_al_*` entry points, all of
//! which take opaque `void *` handles they never dereference -- so Rust is
//! free to represent buffers and interfaces however it likes. This replaces
//! `wifi6_lwip_adapter/net_al.c`, which is worth reading before changing
//! anything here.
//!
//! Two things are load-bearing and easy to get wrong:
//!
//! * **TX payloads must sit in shared RAM**, because `net_buf_tx_info` hands
//!   segment addresses straight to the MAC for DMA. See the `txbuf` module.
//! * **EAPOL does not travel through the IP stack.** wpa_supplicant receives
//!   it on its own event loop, keyed by interface name, so the names must be
//!   `wl1`/`wl2` exactly and `net_if_get_name` must return the length.
//!
//! Every function here is called by the blobs, so the safety contract is
//! theirs: valid handles, and lengths that match the buffers behind them.

#![allow(clippy::missing_safety_doc)]

/// Report a `net_al` call, with the `net-trace` feature.
macro_rules! trace {
    ($($arg:tt)*) => {
        #[cfg(feature = "net-trace")]
        $crate::println!($($arg)*);
    };
}

/// Report the first few calls at this site and then stay quiet.
///
/// The data path would otherwise flood the console and change the timing of
/// the thing being investigated. Each call site gets its own budget.
macro_rules! trace_n {
    ($($arg:tt)*) => {{
        #[cfg(feature = "net-trace")]
        {
            static N: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
            if N.fetch_add(1, Ordering::Relaxed) < 5 {
                $crate::println!($($arg)*);
            }
        }
    }};
}

#[cfg(feature = "embassy-net")]
pub mod embassy;
pub mod events;
pub mod iface;
pub mod txbuf;

// Two IP-stack front ends, and `net_al` is written against whichever is
// compiled in. The smoltcp one owns a poll task and sockets; the stub keeps
// only the bookkeeping, for applications that bring their own stack and must
// not be made to link a second smoltcp.
#[cfg(feature = "rust-net")]
pub mod dhcpd;
#[cfg(feature = "rust-net")]
pub mod stack;

#[cfg(not(feature = "rust-net"))]
#[path = "stack_stub.rs"]
pub mod stack;

use core::ffi::{c_char, c_int, c_void};
use core::sync::atomic::{AtomicU32, Ordering};

use iface::NetIf;
use txbuf::TxBuf;

/// Set by `net_al_set_ipv6_enable`. IPv6 is not implemented; the flag is
/// remembered so a caller asking for it gets a consistent answer.
static IPV6_ENABLED: AtomicU32 = AtomicU32::new(0);

/// `enum net_al_ext_ip_addr_mode`
const IP_ADDR_NONE: u8 = 0;
const IP_ADDR_STATIC_IPV4: u8 = 1;
const IP_ADDR_DHCP_CLIENT: u8 = 2;

/// `struct net_al_ext_ip_addr_cfg`, transcribed from `net_al_ext.h`.
///
/// The union is flattened to its widest arm: both variants are four `u32`s in
/// the `ipv4` case and two in the `dhcp` case, so a `[u32; 4]` covers both
/// with the same layout.
#[repr(C)]
pub struct IpAddrCfg {
    pub mode: u8,
    pub default_output: bool,
    pub u: [u32; 4],
}

impl IpAddrCfg {
    fn ipv4(&self) -> (u32, u32, u32, u32) {
        (self.u[0], self.u[1], self.u[2], self.u[3])
    }
    /// DHCP timeout the blob asked for. Retained for completeness: the client
    /// runs asynchronously and reports through `GOT_IP`, so nothing consumes
    /// it.
    #[allow(dead_code)]
    fn dhcp_timeout_ms(&self) -> u32 {
        self.u[0]
    }
}

// ------------------------------------------------------------ stack control

/// Initialise the network stack. Called by the blob before any interface.
#[no_mangle]
pub extern "C" fn net_init() -> c_int {
    trace!("[net_al] net_init");
    0
}

/// Checksum used by the blob for IP headers it builds itself.
///
/// The standard one's-complement sum of 16-bit words, folded.
#[no_mangle]
pub unsafe extern "C" fn net_ip_chksum(dataptr: *const c_void, len: c_int) -> u16 {
    if dataptr.is_null() || len <= 0 {
        return 0;
    }
    let bytes = unsafe { core::slice::from_raw_parts(dataptr as *const u8, len as usize) };
    let mut sum: u32 = 0;
    let mut chunks = bytes.chunks_exact(2);
    for c in &mut chunks {
        sum += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    if let [last] = chunks.remainder() {
        sum += (*last as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    (!sum as u16).to_be()
}

// --------------------------------------------------------------- interfaces

/// Register an interface. `net_if` is an out-parameter.
#[no_mangle]
pub unsafe extern "C" fn net_if_add(
    net_if: *mut *mut c_void,
    mac_addr: *const u8,
    ipaddr: *const u32,
    netmask: *const u32,
    gw: *const u32,
    vif_priv: *mut c_void,
) -> c_int {
    if net_if.is_null() || mac_addr.is_null() {
        return -1;
    }
    let mut mac = [0u8; 6];
    unsafe { core::ptr::copy_nonoverlapping(mac_addr, mac.as_mut_ptr(), 6) };

    let Some(p) = iface::add(&mac, vif_priv) else {
        return -1;
    };
    unsafe {
        if !ipaddr.is_null() {
            (*p).ipaddr.store(*ipaddr, Ordering::Release);
        }
        if !netmask.is_null() {
            (*p).netmask.store(*netmask, Ordering::Release);
        }
        if !gw.is_null() {
            (*p).gw.store(*gw, Ordering::Release);
        }
        *net_if = p as *mut c_void;
    }
    trace!(
        "[net_al] if_add slot={} mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} ip={:08x}",
        iface::index_of(p).unwrap_or(255),
        mac[0],
        mac[1],
        mac[2],
        mac[3],
        mac[4],
        mac[5],
        unsafe { (*p).ipaddr.load(Ordering::Acquire) }
    );
    // The stack needs the interface's MAC, so it cannot start any earlier.
    stack::start();
    0
}

/// The interface's MAC address. Borrowed by the blob; lives as long as the
/// interface slot, which is for the life of the program.
#[no_mangle]
pub unsafe extern "C" fn net_if_get_mac_addr(net_if: *mut c_void) -> *const u8 {
    match iface::validate(net_if) {
        Some(i) => i.mac.as_ptr(),
        None => core::ptr::null(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn net_if_find_from_name(name: *const c_char) -> *mut c_void {
    trace!("[net_al] find_from_name");
    if name.is_null() {
        return core::ptr::null_mut();
    }
    let mut len = 0usize;
    while len < iface::MAX_IFNAME && unsafe { *name.add(len) } != 0 {
        len += 1;
    }
    let bytes = unsafe { core::slice::from_raw_parts(name, len) };
    match iface::find_by_name(bytes) {
        Some(p) => p as *mut c_void,
        None => core::ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn net_if_get_name(
    net_if: *mut c_void,
    buf: *mut c_char,
    len: c_int,
) -> c_int {
    let Some(i) = iface::validate(net_if) else {
        return -1;
    };
    if buf.is_null() || len <= 0 {
        return -1;
    }
    let name_len = i.name.iter().position(|&c| c == 0).unwrap_or(0);
    if name_len + 1 > len as usize {
        return -1;
    }
    unsafe {
        core::ptr::copy_nonoverlapping(i.name.as_ptr(), buf, name_len);
        *buf.add(name_len) = 0;
    }
    // The vendor returns the character count and callers test `> 0` -- see
    // net_eth_receive, which decides the supplicant's L2 event queue from it.
    name_len as c_int
}

/// The blob's per-VIF private pointer, handed back unchanged.
#[no_mangle]
pub unsafe extern "C" fn net_if_vif_info(net_if: *mut c_void) -> *mut c_void {
    trace_n!("[net_al] vif_info");
    match iface::validate(net_if) {
        Some(i) => i.vif_priv,
        None => core::ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn net_if_up_cb(net_if: *mut c_void) {
    trace!("[net_al] if_up");
    if let Some(i) = iface::validate(net_if) {
        i.link_up.store(true, Ordering::Release);
    }
}

#[no_mangle]
pub unsafe extern "C" fn net_if_down_cb(net_if: *mut c_void) {
    trace!("[net_al] if_down");
    if let Some(i) = iface::validate(net_if) {
        i.link_up.store(false, Ordering::Release);
    }
}

/// Link state changed. The IP stack re-evaluates on the next poll, so there is
/// nothing to do here beyond acknowledging it.
#[no_mangle]
pub unsafe extern "C" fn net_al_link_set(net_if: *mut c_void) -> c_int {
    trace!("[net_al] link_set");
    if iface::validate(net_if).is_some() {
        0
    } else {
        -1
    }
}

// --------------------------------------------------------------- TX buffers

#[no_mangle]
pub extern "C" fn net_buf_tx_alloc(length: u32) -> *mut c_void {
    trace_n!("[net_al] tx_alloc len={}", length);
    match txbuf::alloc() {
        Some(b) if length as usize <= txbuf::MAX_FRAME => {
            unsafe { (*b).len = length as u16 };
            b as *mut c_void
        }
        Some(b) => {
            unsafe { txbuf::free(b) };
            core::ptr::null_mut()
        }
        None => core::ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn net_buf_tx_alloc_fill(frame: *const u8, length: u32) -> *mut c_void {
    trace_n!("[net_al] tx_alloc_fill len={}", length);
    match unsafe { txbuf::alloc_fill(frame, length as usize) } {
        Some(b) => b as *mut c_void,
        None => core::ptr::null_mut(),
    }
}

/// Allocate a descriptor whose payload is filled in later. Our buffers always
/// own their payload, so this is [`net_buf_tx_alloc`].
#[no_mangle]
pub extern "C" fn net_buf_tx_alloc_ref(length: u32) -> *mut c_void {
    net_buf_tx_alloc(length)
}

/// Describe a buffer for the MAC: total length, one entry per data segment,
/// and the headroom delta.
///
/// Despite the `net_al_tx_t *` in the header, the vendor casts the parameter
/// straight to the buffer — the value *is* the handle. Treating it as a
/// pointer-to-handle would dereference the wrong thing.
#[no_mangle]
pub unsafe extern "C" fn net_buf_tx_info(
    net_buf: *mut c_void,
    tot_len: *mut u16,
    seg_cnt: *mut c_int,
    seg_addr: *mut u32,
    seg_len: *mut u16,
    headroom_len: *mut u32,
) -> *mut c_void {
    if net_buf.is_null() || seg_cnt.is_null() {
        return core::ptr::null_mut();
    }
    let max_segs = unsafe { *seg_cnt }.max(0) as usize;
    if max_segs == 0 {
        return core::ptr::null_mut();
    }

    let mut total: u32 = 0;
    let mut idx = 0usize;
    let mut cur = net_buf as *mut TxBuf;
    let first = cur;

    while !cur.is_null() && idx < max_segs {
        let len = unsafe { (*cur).len };
        unsafe {
            *seg_addr.add(idx) = (*cur).frame_ptr() as u32;
            *seg_len.add(idx) = len;
        }
        total += len as u32;
        idx += 1;
        cur = unsafe { (*cur).next };
    }

    if !cur.is_null() {
        // More segments than the caller can take: refuse rather than send a
        // truncated frame.
        return core::ptr::null_mut();
    }

    trace_n!(
        "[net_al] tx_info segs={} tot={} frame={:08x} delta={:08x}",
        idx,
        total,
        unsafe { (*first).frame_ptr() } as u32,
        (unsafe { (*first).headroom_ptr() } as u32)
            .wrapping_sub(unsafe { (*first).frame_ptr() } as u32)
    );
    unsafe {
        *seg_cnt = idx as c_int;
        if !tot_len.is_null() {
            *tot_len = total as u16;
        }
        let headroom = (*first).headroom_ptr();
        if !headroom_len.is_null() {
            // Wrapping negative delta, matching the vendor exactly.
            *headroom_len = (headroom as u32).wrapping_sub((*first).frame_ptr() as u32);
        }
        headroom as *mut c_void
    }
}

/// Whether every segment is DMA-able. Ours always are, by construction: the
/// pool is placed in `.wifi_ram` so the linker puts it inside the shared-RAM
/// region.
#[no_mangle]
pub extern "C" fn net_buf_tx_all_shram(_net_buf: *mut c_void) -> bool {
    true
}

#[no_mangle]
pub unsafe extern "C" fn net_buf_tx_free(buf: *mut c_void) {
    trace_n!("[net_al] tx_free");
    if !buf.is_null() {
        unsafe { txbuf::free(buf as *mut TxBuf) };
    }
}

/// Chain a second buffer onto the first as an extra segment.
#[no_mangle]
pub unsafe extern "C" fn net_buf_tx_cat(first: *mut c_void, second: *mut c_void) {
    trace_n!("[net_al] tx_cat");
    if first.is_null() || second.is_null() {
        return;
    }
    let mut cur = first as *mut TxBuf;
    unsafe {
        while !(*cur).next.is_null() {
            cur = (*cur).next;
        }
        (*cur).next = second as *mut TxBuf;
    }
}

// ------------------------------------------------------------------ TX path

#[no_mangle]
pub extern "C" fn net_al_tx_init() {
    trace!("[net_al] tx_init");
}

/// Transmission confirmed. Buffers are released through the confirmation
/// callback the submitter supplied, so there is nothing to reclaim here.
#[no_mangle]
pub extern "C" fn net_al_tx_cfm() {
    trace_n!("[net_al] tx_cfm");
}

/// A station went away; release anything queued for it.
///
/// Nothing is queued per-station in this implementation — frames are handed
/// straight to `fhost_tx_start` — so there is nothing to walk.
#[no_mangle]
pub extern "C" fn net_al_tx_do_sta_del(_sta_id: u8, _release_buf: *mut c_void) {}

/// `struct net_al_tx_req`, transcribed from `net_al.h`.
#[repr(C)]
pub struct TxReq {
    pub net_buf: *mut c_void,
    pub cfm_cb: *mut c_void,
    pub cfm_cb_arg: *mut c_void,
    pub buf_rx: *mut c_void,
    pub net_if: *mut c_void,
    pub type_: c_int,
    pub no_cck: c_int,
}

/// Submit a frame the blob built itself.
///
/// Passed by value, matching `int net_al_tx_req(struct net_al_tx_req req)`.
#[no_mangle]
pub unsafe extern "C" fn net_al_tx_req(req: TxReq) -> c_int {
    trace_n!("[net_al] tx_req type={} buf={:p}", req.type_, req.net_buf);
    if req.net_buf.is_null() {
        return -1;
    }
    if iface::validate(req.net_if).is_none() {
        unsafe { txbuf::free(req.net_buf as *mut TxBuf) };
        return -1;
    }
    // `fhost_tx_req_do`, not `fhost_tx_start`. The latter is the network
    // stack's own entry point and takes four arguments; this path has to
    // carry `type`, `buf_rx` and `no_cck` through as well. Forwarding to
    // `fhost_tx_start` instead loses them and the frame is accepted but never
    // completed -- the buffer simply stays in flight forever.
    //
    // The vendor's fallback for payloads outside shared RAM does not apply:
    // ours always are, by construction, so `net_buf_tx_all_shram` is always
    // true and only this branch is ever taken.
    unsafe {
        fhost_tx_req_do(
            req.net_if,
            req.net_buf,
            req.type_,
            req.cfm_cb,
            req.cfm_cb_arg,
            req.buf_rx,
            req.no_cck,
        )
    }
}

/// IEEE 802.3 header: destination, source, ethertype.
const ETH_HDR_LEN: usize = 14;
/// Interface MTU, matching what the vendor sets on its netif.
const MTU: usize = 1500;

/// Shared fallback queue, for an interface the supplicant does not recognise.
const ELOOP_EVT_WPA_L2_DATA: c_int = 3;
/// Per-interface L2 queues, from `eloop_rtos.h`.
const ELOOP_EVT_WPA_L2_DATA_WL1: c_int = 10;
const ELOOP_EVT_WPA_L2_DATA_WL2: c_int = 11;

/// Which event queue the supplicant expects L2 frames for `name` on.
///
/// Mirrors `eloop_get_l2_event_id`, which is a `static inline` in
/// `eloop_rtos.h` and so has no symbol to link against.
fn eloop_l2_event_id(name: &[u8]) -> c_int {
    match name {
        b"wl1" => ELOOP_EVT_WPA_L2_DATA_WL1,
        b"wl2" => ELOOP_EVT_WPA_L2_DATA_WL2,
        _ => ELOOP_EVT_WPA_L2_DATA,
    }
}

extern "C" {
    /// Submit a frame with its full transmit context. Lives in the blob.
    fn fhost_tx_req_do(
        net_if: *mut c_void,
        net_buf: *mut c_void,
        type_: c_int,
        cfm_cb: *mut c_void,
        cfm_cb_arg: *mut c_void,
        buf_rx: *mut c_void,
        no_cck: c_int,
    ) -> c_int;

    /// Deliver a frame to wpa_supplicant's event loop. Lives in
    /// libwpa_supplicant.
    fn eloop_event_commit(event_type: c_int, request: *const c_char, req_len: c_int) -> c_int;

    /// Hand a buffer to the WiFi firmware for transmission. Lives in the blob.
    fn fhost_tx_start(
        net_if: *mut c_void,
        net_buf: *mut c_void,
        cfm_cb: *mut c_void,
        cfm_cb_arg: *mut c_void,
    ) -> c_int;
}

// ------------------------------------------------------------------ RX path

/// A frame arrived. Copies into the RX ring and returns; `free_fn` releases
/// the blob's buffer immediately, so the MAC's descriptor ring never waits on
/// the IP stack.
#[no_mangle]
pub unsafe extern "C" fn net_al_input(
    net_buf: *mut c_void,
    payload: *mut c_void,
    net_if: *mut c_void,
    length: u16,
    offset: u8,
    skip_after_eth_hdr: u8,
    free_fn: Option<unsafe extern "C" fn(*mut c_void)>,
) {
    trace_n!(
        "[net_al] rx len={} off={} skip={}",
        length,
        offset,
        skip_after_eth_hdr
    );

    if let Some(i) = iface::validate(net_if) {
        if !payload.is_null() && length > 0 {
            let base = payload as *mut u8;
            let skip = skip_after_eth_hdr as usize;

            // The MAC can leave material between the ethernet header and the
            // payload (LLC/SNAP, say). The vendor removes it by shifting the
            // 14-byte header *forward* over it rather than moving the body,
            // and then starts the frame past the gap.
            if skip != 0 {
                unsafe { core::ptr::copy(base, base.add(skip), ETH_HDR_LEN) };
            }

            let frame = unsafe { base.add(offset as usize + skip) };
            // Note the length is reduced by `skip`, not by `offset`: `offset`
            // shifts where the frame starts within the buffer, `length`
            // already counts from there.
            let len = (length as usize).saturating_sub(skip);

            // Drop our own frames looped back to the station. Without this a
            // broadcast we sent is received and processed as if it came from
            // the network.
            let looped = iface::index_of(net_if as *mut NetIf) == Some(0)
                && len >= ETH_HDR_LEN
                && unsafe { core::slice::from_raw_parts(frame.add(6), 6) } == i.mac;

            if !looped && len > 0 {
                // L2 first. wpa_supplicant receives EAPOL through its own
                // event loop, not through the IP stack, so a frame matching a
                // registered ethertype goes there and nowhere else. Missing
                // this is invisible until a WPA2 handshake silently never
                // completes.
                let want = i.l2_ethertype.load(Ordering::Acquire) as u16;
                let ethertype = (len >= ETH_HDR_LEN)
                    .then(|| unsafe { u16::from_be_bytes([*frame.add(12), *frame.add(13)]) });

                if want != 0 && ethertype == Some(want) {
                    let mut name = [0u8; 8];
                    let n = unsafe { net_if_get_name(net_if, name.as_mut_ptr() as *mut c_char, 8) };
                    let event = if n > 0 {
                        eloop_l2_event_id(&name[..n as usize])
                    } else {
                        ELOOP_EVT_WPA_L2_DATA
                    };
                    trace_n!("[net_al] l2 rx ethertype={:04x} -> event {}", want, event);
                    unsafe { eloop_event_commit(event, frame as *const c_char, len as c_int) };
                } else {
                    unsafe { iface::rx_push(net_if as *mut NetIf, frame, len) };
                }
            }
        }
    }
    if let Some(f) = free_fn {
        unsafe { f(net_buf) };
    }
}

/// Re-inject a frame the blob wants forwarded (AP-to-AP bridging).
///
/// Forwarding between associated stations is not implemented, so the frame is
/// dropped rather than silently looped.
#[no_mangle]
pub extern "C" fn net_al_rx_resend(
    _forward: bool,
    _buf: *mut c_void,
    _payload: *mut c_void,
    _length: c_int,
    _offset: c_int,
    _mac_hdr_len: c_int,
) {
}

// ------------------------------------------------------------- L2 (raw) I/O

/// Register interest in a raw ethertype. The supplicant uses this for EAPOL.
#[no_mangle]
pub unsafe extern "C" fn net_l2_socket_create(net_if: *mut c_void, ethertype: u16) -> c_int {
    trace!("[net_al] l2_socket_create ethertype={:04x}", ethertype);
    match iface::validate(net_if) {
        Some(i) => {
            i.l2_ethertype.store(ethertype as u32, Ordering::Release);
            0
        }
        None => -1,
    }
}

#[no_mangle]
pub unsafe extern "C" fn net_l2_socket_delete(net_if: *mut c_void) -> c_int {
    match iface::validate(net_if) {
        Some(i) => {
            i.l2_ethertype.store(0, Ordering::Release);
            0
        }
        None => -1,
    }
}

/// Retries the vendor performs before giving up on an unacknowledged frame.
const L2_SEND_SW_RETRIES: usize = 7;
/// How long to wait for a transmit confirmation before giving up on it.
///
/// Short on purpose: this sits in the middle of the WPA handshake, and the
/// supplicant's own timers are the ones that matter.
const L2_CFM_TIMEOUT_MS: u32 = 300;

/// Serialises L2 transmissions, so one sender's confirmation cannot be
/// mistaken for another's. The vendor uses a mutex plus a semaphore; this is
/// the same arrangement with atomics, since the callback may run in interrupt
/// context where a mutex would not be safe.
static L2_BUSY: AtomicU32 = AtomicU32::new(0);
static L2_DONE: AtomicU32 = AtomicU32::new(0);
static L2_ACKED: AtomicU32 = AtomicU32::new(0);

/// Transmission confirmation for [`net_l2_send`].
unsafe extern "C" fn l2_send_cfm(_frame_id: u32, acknowledged: bool, _arg: *mut c_void) {
    trace_n!("[net_al] l2_cfm acked={}", acknowledged);
    L2_ACKED.store(acknowledged as u32, Ordering::Release);
    L2_DONE.store(1, Ordering::Release);
}

/// Send one raw frame and wait for its confirmation.
///
/// Returns `Err(())` if the frame could not be submitted, else the
/// acknowledgement the MAC reported.
unsafe fn l2_send_once(
    net_if: *mut c_void,
    i: &iface::NetIf,
    data: *const u8,
    data_len: usize,
    ethertype: u16,
    dst_addr: *const u8,
) -> Result<bool, ()> {
    let with_header = !dst_addr.is_null();
    let total = data_len + if with_header { ETH_HDR_LEN } else { 0 };
    if total > txbuf::MAX_FRAME {
        return Err(());
    }

    let Some(buf) = txbuf::alloc() else {
        return Err(());
    };
    unsafe {
        let frame = (*buf).frame_ptr();
        if with_header {
            // Only when the caller names a destination: otherwise the payload
            // already carries its own header and adding one would duplicate it.
            core::ptr::copy_nonoverlapping(dst_addr, frame, 6);
            core::ptr::copy_nonoverlapping(i.mac.as_ptr(), frame.add(6), 6);
            let et = ethertype.to_be_bytes();
            *frame.add(12) = et[0];
            *frame.add(13) = et[1];
            core::ptr::copy_nonoverlapping(data, frame.add(ETH_HDR_LEN), data_len);
        } else {
            core::ptr::copy_nonoverlapping(data, frame, data_len);
        }
        (*buf).len = total as u16;
    }

    L2_DONE.store(0, Ordering::Release);
    L2_ACKED.store(0, Ordering::Release);

    let rc = unsafe {
        fhost_tx_start(
            net_if,
            buf as *mut c_void,
            l2_send_cfm as *mut c_void,
            core::ptr::null_mut(),
        )
    };
    if rc != 0 {
        unsafe { txbuf::free(buf) };
        return Err(());
    }

    // Block until the MAC confirms, as the vendor does. The bound is ours:
    // the vendor waits forever, which turns a lost confirmation into a hung
    // supplicant.
    //
    // A timeout is reported as delivered, not as unacknowledged. The two are
    // very different: a negative acknowledgement means the peer did not hear
    // us and retrying is right, whereas no confirmation at all says nothing
    // about the frame and retrying only burns the handshake's patience --
    // eight retries of a two-second wait is sixteen seconds per EAPOL frame,
    // which no supplicant will wait for.
    let mut waited = 0;
    while L2_DONE.load(Ordering::Acquire) == 0 {
        if waited >= L2_CFM_TIMEOUT_MS {
            trace_n!("[net_al] l2_cfm timeout");
            return Ok(true);
        }
        crate::runtime::delay_ms(2);
        waited += 2;
    }
    Ok(L2_ACKED.load(Ordering::Acquire) != 0)
}

/// Send a raw IEEE 802.3 frame — the supplicant's EAPOL path.
///
/// Blocks until the frame is confirmed and reports the real acknowledgement,
/// retrying like the vendor. The supplicant decides whether to retransmit
/// from `ack`, so reporting "queued" as "acknowledged" would break the WPA
/// handshake in a way that looks like packet loss.
#[no_mangle]
pub unsafe extern "C" fn net_l2_send(
    net_if: *mut c_void,
    data: *const u8,
    data_len: c_int,
    ethertype: u16,
    dst_addr: *const u8,
    ack: *mut bool,
) -> c_int {
    trace_n!(
        "[net_al] l2_send ethertype={:04x} len={}",
        ethertype,
        data_len
    );

    let Some(i) = iface::validate(net_if) else {
        return -1;
    };
    if data.is_null() || data_len <= 0 || data_len as usize >= MTU {
        return -1;
    }
    if !i.link_up.load(Ordering::Acquire) {
        return -1;
    }

    // One L2 transmission at a time: the confirmation carries no identity, so
    // overlapping sends could not tell their completions apart.
    let mut spins = 0;
    while L2_BUSY
        .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        crate::runtime::delay_ms(2);
        spins += 2;
        if spins >= 2_000 {
            return -1;
        }
    }

    let mut result = -1;
    for _ in 0..=L2_SEND_SW_RETRIES {
        match unsafe { l2_send_once(net_if, i, data, data_len as usize, ethertype, dst_addr) } {
            Err(()) => {
                result = -1;
                break;
            }
            Ok(true) => {
                if !ack.is_null() {
                    unsafe { *ack = true };
                }
                result = 0;
                break;
            }
            Ok(false) => {
                if !ack.is_null() {
                    unsafe { *ack = false };
                }
                result = 0;
            }
        }
    }

    L2_BUSY.store(0, Ordering::Release);
    result
}

// ------------------------------------------------------- IP address / DHCP

#[no_mangle]
pub unsafe extern "C" fn net_al_ext_set_vif_ip(fvif_idx: c_int, cfg: *mut IpAddrCfg) -> c_int {
    if cfg.is_null() {
        return -1;
    }
    let Some(p) = iface_for_index(fvif_idx) else {
        return -1;
    };
    let cfg = unsafe { &*cfg };
    trace!(
        "[net_al] set_vif_ip idx={} mode={} addr={:08x}",
        fvif_idx,
        cfg.mode,
        cfg.u[0]
    );
    // Bind the stack to the interface the blob is configuring. A station has
    // no address until DHCP completes, so "whichever interface has one" can
    // not identify it.
    stack::set_target(p as *mut c_void);
    match cfg.mode {
        IP_ADDR_STATIC_IPV4 => {
            let (addr, mask, gw, dns) = cfg.ipv4();
            unsafe {
                (*p).ipaddr.store(addr, Ordering::Release);
                (*p).netmask.store(mask, Ordering::Release);
                (*p).gw.store(gw, Ordering::Release);
                (*p).dns.store(dns, Ordering::Release);
            }
            // An address appearing is an address appearing, however it was
            // configured; the vendor's netif status callback does not
            // distinguish either.
            if addr != 0 {
                stack::post_got_ip();
            }
            0
        }
        IP_ADDR_DHCP_CLIENT => {
            // Asynchronous, for the same reason as net_al_ext_dhcp_connect.
            stack::start_dhcp_client_async();
            0
        }
        IP_ADDR_NONE => {
            unsafe {
                (*p).ipaddr.store(0, Ordering::Release);
                (*p).netmask.store(0, Ordering::Release);
                (*p).gw.store(0, Ordering::Release);
                (*p).dns.store(0, Ordering::Release);
            }
            0
        }
        _ => -1,
    }
}

#[no_mangle]
pub unsafe extern "C" fn net_al_ext_get_vif_ip(fvif_idx: c_int, cfg: *mut IpAddrCfg) -> c_int {
    trace_n!("[net_al] get_vif_ip idx={}", fvif_idx);
    if cfg.is_null() {
        return -1;
    }
    let Some(p) = iface_for_index(fvif_idx) else {
        return -1;
    };
    unsafe {
        let addr = (*p).ipaddr.load(Ordering::Acquire);
        (*cfg).mode = if addr == 0 {
            IP_ADDR_NONE
        } else {
            IP_ADDR_STATIC_IPV4
        };
        (*cfg).u[0] = addr;
        (*cfg).u[1] = (*p).netmask.load(Ordering::Acquire);
        (*cfg).u[2] = (*p).gw.load(Ordering::Acquire);
        (*cfg).u[3] = (*p).dns.load(Ordering::Acquire);
    }
    0
}

/// Run the DHCP client and block until it has a lease.
#[no_mangle]
pub extern "C" fn net_al_ext_dhcp_connect(is_api: c_int, to_ms: u32) -> c_int {
    trace!("[net_al] dhcp_connect is_api={} to_ms={}", is_api, to_ms);
    // The station interface is the one that runs a DHCP client.
    if let Some(p) = iface::by_index(0) {
        stack::set_target(p as *mut c_void);
    }
    // Start the client and return; do not wait for the lease.
    //
    // The vendor spawns a `wifi_dhcpc` task here and returns 0 immediately.
    // This call arrives on the blob's own WPA task, so blocking it until DHCP
    // completes stalls the task that drives the connection and delivers
    // received frames -- the station associates and then no traffic arrives
    // at all. The application learns the outcome from GOT_IP, which the
    // addressing code posts.
    let _ = (is_api, to_ms);
    stack::start_dhcp_client_async();
    0
}

#[no_mangle]
pub extern "C" fn net_al_ext_dhcp_disconnect() {
    trace!("[net_al] dhcp_disconnect");
    stack::request(stack::Command::DhcpClientStop, 2_000);
}

/// Start the soft-AP's DHCP server.
#[no_mangle]
pub extern "C" fn net_al_dhcpd_start(net_if: *mut c_void, start: c_int, limit: c_int) -> c_int {
    trace!("[net_al] dhcpd_start start={} limit={}", start, limit);
    if iface::validate(net_if).is_none() {
        trace!("[net_al] dhcpd_start: bad interface handle");
        return -1;
    }
    // Bind the stack to the interface the blob actually named.
    stack::set_target(net_if);
    stack::set_dhcpd_pool(start.max(0) as u16, limit.max(0) as u16);
    // The interface is brought up here, as the vendor does.
    if let Some(i) = iface::validate(net_if) {
        i.link_up.store(true, Ordering::Release);
    }
    stack::request(stack::Command::DhcpServerStart, 5_000);
    // Always success, matching the vendor. The blob configures the address
    // *after* this call, so reporting "no address yet" as a failure aborts
    // the very step that would have supplied one.
    trace!("[net_al] dhcpd_start -> 0");
    0
}

#[no_mangle]
pub extern "C" fn net_al_dhcpd_stop(_net_if: *mut c_void) -> c_int {
    stack::request(stack::Command::DhcpServerStop, 2_000);
    0
}

#[no_mangle]
pub extern "C" fn net_al_set_ipv6_enable(enable: c_int) -> c_int {
    trace!("[net_al] set_ipv6 {}", enable);
    IPV6_ENABLED.store(enable as u32, Ordering::Release);
    if enable != 0 {
        -1
    } else {
        0
    }
}

fn iface_for_index(idx: c_int) -> Option<*mut NetIf> {
    usize::try_from(idx).ok().and_then(iface::by_index)
}

// ------------------------------------------------------------------- shims

/// Host-to-network short. wpa_supplicant calls lwIP's.
#[no_mangle]
pub extern "C" fn lwip_htons(n: u16) -> u16 {
    n.to_be()
}

/// `inet_ntop` for AF_INET only, which is all the supplicant uses it for.
#[no_mangle]
pub unsafe extern "C" fn lwip_inet_ntop(
    af: c_int,
    src: *const c_void,
    dst: *mut c_char,
    size: c_int,
) -> *const c_char {
    const AF_INET: c_int = 2;
    if af != AF_INET || src.is_null() || dst.is_null() || size < 16 {
        return core::ptr::null();
    }
    let addr = unsafe { *(src as *const u32) };
    let o = addr.to_le_bytes();

    let mut buf = [0u8; 16];
    let mut n = 0usize;
    for (i, octet) in o.iter().enumerate() {
        if i > 0 {
            buf[n] = b'.';
            n += 1;
        }
        let mut v = *octet;
        let mut digits = [0u8; 3];
        let mut d = 0;
        loop {
            digits[d] = b'0' + v % 10;
            v /= 10;
            d += 1;
            if v == 0 {
                break;
            }
        }
        while d > 0 {
            d -= 1;
            buf[n] = digits[d];
            n += 1;
        }
    }
    unsafe {
        core::ptr::copy_nonoverlapping(buf.as_ptr(), dst, n);
        *dst.add(n) = 0;
    }
    dst
}

/// The vendor's `tcpip_init` starts lwIP's core task. Nothing to start here;
/// [`net_init`] does what little setup this stack needs.
#[no_mangle]
pub extern "C" fn tcpip_init(_initfunc: *mut c_void, _arg: *mut c_void) {}

/// TX pool and RX ring counters, for bring-up.
///
/// Returns `(tx_in_use, tx_peak, tx_exhausted, rx_accepted, rx_dropped)`.
/// Publish an address into the blob's view of an interface.
///
/// The blob and the vendor API (`wifi_sta_ip4_addr_get`, and the AP's own
/// addressing) read what `net_al_ext_get_vif_ip` reports, which is these
/// fields. When the IP stack lives in the application -- as it does under the
/// embassy front end -- nothing else writes them, so the application has to
/// hand back what its stack obtained or the two disagree about the address.
///
/// All values are in network byte order, 0 for unset.
pub fn set_vif_addr(index: usize, addr: u32, mask: u32, gw: u32, dns: u32) -> bool {
    let Some(p) = iface::by_index(index) else {
        return false;
    };
    unsafe {
        (*p).ipaddr.store(addr, core::sync::atomic::Ordering::Release);
        (*p).netmask.store(mask, core::sync::atomic::Ordering::Release);
        (*p).gw.store(gw, core::sync::atomic::Ordering::Release);
        (*p).dns.store(dns, core::sync::atomic::Ordering::Release);
    }
    if addr != 0 {
        stack::post_got_ip();
    }
    true
}

/// Pinging outward needs an ICMP socket, so it belongs to the smoltcp front
/// end. An application with its own stack pings with its own stack.
#[cfg(feature = "rust-net")]
pub use stack::{ping_start, ping_stats};

pub fn stats() -> (u32, u32, u32, u32, u32) {
    let (in_use, peak, exhausted) = txbuf::stats();
    let (accepted, dropped) = iface::rx_stats();
    (in_use, peak, exhausted, accepted, dropped)
}
