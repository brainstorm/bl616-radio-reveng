// SPDX-FileCopyrightText: 2026 Roman Valls Guimera <brainstorm@nopcode.org>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! `net_al`: the vendor WiFi stack's network interface, implemented in Rust.
//!
//! This is Stage 1 of replacing the C substrate. With `--features rust-net`,
//! `bl616-wifi-sys` holds `liblwip.a` (462 symbols, 3.6 MB) and
//! `libwifi6_lwip_adapter.a` (187 symbols, 466 KB) back from the link, and
//! what follows supplies the 24 entry points the blob actually calls, plus
//! three small shims the supplicant wants.
//!
//! # Why this is possible at all
//!
//! `net_al_if_t`, `net_al_rx_t` and `net_al_tx_t` are `void *` and the blob
//! **never dereferences them** — it only hands them back. The vendor pins them
//! to lwIP types in `net_def.h`; nothing else does. So the representation is
//! ours to choose, and this module chooses fixed arrays over allocation, which
//! also means every handle the blob returns can be validated before use.
//!
//! # What is not negotiable
//!
//! * TX payloads must live in shared RAM — see [`txbuf`].
//! * 388 bytes of headroom ahead of every frame, and the first segment must
//!   carry the whole IEEE 802.3 header.
//! * `net_buf_tx_info`'s `headroom_len` is a **wrapping negative delta**
//!   (`headroom_ptr - frame_ptr`), not a length. The vendor computes it as
//!   `end_payload - start_payload` on `uint32_t` and the blob adds it back to
//!   the frame pointer; getting the sign wrong points the MAC at the wrong
//!   memory.
//! * The RX callback runs in the blob's context and must not block.
//!
//! # Status
//!
//! The buffer, interface and RX layers are complete. The IP stack on top
//! (smoltcp) and the DHCP server that AP mode needs are the remaining work —
//! see the engineering notes.

// Every `unsafe extern "C"` below is an entry point the vendor blob calls
// under the contract in `net_al.h`, restated at the top of this module:
// pointers come from the blob and are valid for the call. Repeating that as a
// `# Safety` section on each of thirty functions would add noise, not safety.
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

pub mod dhcpd;
pub mod iface;
pub mod stack;
pub mod txbuf;

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
    unsafe { fhost_tx_start(req.net_if, req.net_buf, req.cfm_cb, req.cfm_cb_arg) }
}

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
    _skip_after_eth_hdr: u8,
    free_fn: Option<unsafe extern "C" fn(*mut c_void)>,
) {
    trace_n!("[net_al] rx len={} off={}", length, offset);
    if let Some(i) = iface::validate(net_if) {
        if !payload.is_null() && length > 0 {
            let frame = unsafe { (payload as *const u8).add(offset as usize) };
            let len = length as usize - (offset as usize).min(length as usize);

            // L2 first. wpa_supplicant receives EAPOL through its own event
            // loop, not through the IP stack, so a frame matching a
            // registered ethertype goes there and nowhere else. Missing this
            // is invisible until a WPA2 handshake silently never completes.
            let want = i.l2_ethertype.load(Ordering::Acquire) as u16;
            let ethertype = (len >= 14)
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

/// Send a raw IEEE 802.3 frame — the supplicant's EAPOL path.
///
/// Builds the 14-byte ethernet header ahead of `data` and submits it. `ack`
/// reports only that the frame was queued: the vendor's own implementation
/// does not wait for a transmit confirmation here either.
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
    if data.is_null() || data_len <= 0 {
        return -1;
    }
    let payload_len = data_len as usize;
    if payload_len + 14 > txbuf::MAX_FRAME {
        return -1;
    }

    let Some(buf) = txbuf::alloc() else {
        return -1;
    };
    unsafe {
        let frame = (*buf).frame_ptr();
        if dst_addr.is_null() {
            // Broadcast when the caller does not name a destination.
            core::ptr::write_bytes(frame, 0xff, 6);
        } else {
            core::ptr::copy_nonoverlapping(dst_addr, frame, 6);
        }
        core::ptr::copy_nonoverlapping(i.mac.as_ptr(), frame.add(6), 6);
        let et = ethertype.to_be_bytes();
        *frame.add(12) = et[0];
        *frame.add(13) = et[1];
        core::ptr::copy_nonoverlapping(data, frame.add(14), payload_len);
        (*buf).len = (payload_len + 14) as u16;
    }

    let rc = unsafe {
        fhost_tx_start(
            net_if,
            buf as *mut c_void,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        )
    };
    if rc != 0 {
        unsafe { txbuf::free(buf) };
    }
    if !ack.is_null() {
        unsafe { *ack = rc == 0 };
    }
    rc
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
    match cfg.mode {
        IP_ADDR_STATIC_IPV4 => {
            let (addr, mask, gw, dns) = cfg.ipv4();
            unsafe {
                (*p).ipaddr.store(addr, Ordering::Release);
                (*p).netmask.store(mask, Ordering::Release);
                (*p).gw.store(gw, Ordering::Release);
                (*p).dns.store(dns, Ordering::Release);
            }
            0
        }
        IP_ADDR_DHCP_CLIENT => {
            let timeout = match cfg.dhcp_timeout_ms() {
                0 => 15_000,
                t => t,
            };
            if stack::request(stack::Command::DhcpClientStart, timeout) {
                0
            } else {
                -1
            }
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
pub extern "C" fn net_al_ext_dhcp_connect(_is_api: c_int, to_ms: u32) -> c_int {
    let timeout = if to_ms == 0 { 15_000 } else { to_ms };
    if stack::request(stack::Command::DhcpClientStart, timeout) {
        0
    } else {
        -1
    }
}

#[no_mangle]
pub extern "C" fn net_al_ext_dhcp_disconnect() {
    stack::request(stack::Command::DhcpClientStop, 2_000);
}

/// Start the soft-AP's DHCP server. See [`dhcpd`].
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
    let ok = stack::request(stack::Command::DhcpServerStart, 5_000);
    trace!("[net_al] dhcpd_start -> {}", if ok { 0 } else { -1 });
    if ok {
        0
    } else {
        -1
    }
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
pub fn stats() -> (u32, u32, u32, u32, u32) {
    let (in_use, peak, exhausted) = txbuf::stats();
    let (accepted, dropped) = iface::rx_stats();
    (in_use, peak, exhausted, accepted, dropped)
}
