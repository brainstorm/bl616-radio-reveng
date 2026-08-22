// SPDX-FileCopyrightText: 2026 Roman Valls Guimera <brainstorm@nopcode.org>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! The IP stack: smoltcp over the vendor MAC.
//!
//! # Ownership, and why there are no locks
//!
//! The [`Stack`] is owned outright by one FreeRTOS task, [`poll_task`].
//! Nothing else touches it. The `net_al` entry points the blob calls run in
//! the blob's own tasks, so instead of sharing the stack behind a mutex — held
//! across a `poll()` that can run for a while — they post a request through
//! [`Command`] and wait on an atomic for the answer.
//!
//! That keeps the design consistent with the RX path, which already hands
//! frames over through a lock-free ring for the same reason: the blob's
//! callback must not block.
//!
//! # What smoltcp gives us for free
//!
//! ICMP echo is answered by `Interface::poll` without a socket, so a station
//! or soft-AP replies to ping as soon as it has an address. That is the
//! cheapest end-to-end proof the whole path works.

use core::ffi::c_int;
use core::sync::atomic::{AtomicU32, AtomicU8, AtomicUsize, Ordering};

use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{self, Checksum, DeviceCapabilities, Medium};
use smoltcp::socket::dhcpv4;
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpCidr, Ipv4Address, Ipv4Cidr};

use super::dhcpd::Dhcpd;
use super::iface::{self, NetIf, RX_FRAME_MAX};
use super::txbuf;
use crate::runtime;

/// MTU the vendor MAC presents.
const MTU: usize = 1500;

/// `CODE_WIFI_ON_*`, from `wifi_mgmr_ext.h`.
const CODE_WIFI_ON_GOT_IP: c_int = 7;
const CODE_WIFI_ON_LOST_IP: c_int = 26;
const CODE_WIFI_ON_GOT_IP_TIMEOUT: c_int = 28;

extern "C" {
    /// Post a WiFi event to the application's async bus.
    ///
    /// In the vendor this is reached from lwIP's netif status callback; with
    /// lwIP gone, the addressing code has to post it directly. Without it
    /// `Wifi::connect` waits out its timeout even after DHCP has succeeded,
    /// because `GotIp` is the event it is waiting for.
    fn platform_post_event(catalogue: c_int, code: c_int, value: c_int);
}

/// Tell the application an address appeared or went away.
fn post_ip_event(code: c_int) {
    // EV_WIFI; the vendor's implementation ignores the catalogue argument and
    // posts to EV_WIFI regardless, but pass it correctly anyway.
    unsafe { platform_post_event(2, code, 0) };
}

// ------------------------------------------------------------ command queue

/// Requests from the blob's tasks to the poll task.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Command {
    None = 0,
    DhcpClientStart = 1,
    DhcpClientStop = 2,
    DhcpServerStart = 3,
    DhcpServerStop = 4,
}

/// Outcome of the last command.
pub const RESULT_PENDING: u32 = 0;
pub const RESULT_OK: u32 = 1;
pub const RESULT_FAILED: u32 = 2;

static COMMAND: AtomicU8 = AtomicU8::new(Command::None as u8);
static RESULT: AtomicU32 = AtomicU32::new(RESULT_PENDING);
/// DHCP server pool, packed as `(start << 16) | limit`.
static DHCPD_POOL: AtomicU32 = AtomicU32::new(0);
/// Set once the poll task is running, so requests made before that fail fast
/// rather than hanging.
static RUNNING: AtomicU32 = AtomicU32::new(0);
/// Interface the blob has named, or 0 for "not yet told".
///
/// Binding to whichever interface merely exists first is wrong: the station
/// registers before the soft-AP, so an AP-mode DHCP request would be answered
/// against the station's (unset) address.
static TARGET_IF: AtomicUsize = AtomicUsize::new(0);

/// Claimed by whoever spawns the poll task.
///
/// Separate from [`RUNNING`], which the task sets only once it is scheduled:
/// the blob calls `net_if_add` twice in quick succession (station, then
/// soft-AP) and both calls would pass a `RUNNING` check and spawn a task of
/// their own. Two poll tasks then drive the same interface, allocate a
/// `Stack` each, and wedge the application behind them.
static SPAWNED: AtomicU32 = AtomicU32::new(0);

/// Post a command and block until the poll task answers or `timeout_ms`
/// elapses. Must be called from a task.
pub fn request(cmd: Command, timeout_ms: u32) -> bool {
    // The blob can ask for DHCP before the poll task has finished starting --
    // `net_if_add` spawns it and the AP bring-up follows immediately. Wait for
    // it rather than failing a request that is merely early.
    let mut waited = 0;
    while RUNNING.load(Ordering::Acquire) == 0 {
        if waited >= timeout_ms.min(2_000) {
            return false;
        }
        runtime::delay_ms(10);
        waited += 10;
    }

    RESULT.store(RESULT_PENDING, Ordering::Release);
    COMMAND.store(cmd as u8, Ordering::Release);

    while waited < timeout_ms {
        match RESULT.load(Ordering::Acquire) {
            RESULT_OK => return true,
            RESULT_FAILED => return false,
            _ => {}
        }
        runtime::delay_ms(10);
        waited += 10;
    }
    false
}

/// Name the interface the stack should serve. The blob knows which one it
/// means; we should not guess.
pub fn set_target(net_if: *mut core::ffi::c_void) {
    TARGET_IF.store(net_if as usize, Ordering::Release);
}

/// Tell the application an address is configured.
pub fn post_got_ip() {
    post_ip_event(CODE_WIFI_ON_GOT_IP);
}

/// Tell the application DHCP gave up.
pub fn post_dhcp_timeout() {
    post_ip_event(CODE_WIFI_ON_GOT_IP_TIMEOUT);
}

/// Set the soft-AP DHCP pool before requesting [`Command::DhcpServerStart`].
pub fn set_dhcpd_pool(start: u16, limit: u16) {
    DHCPD_POOL.store(((start as u32) << 16) | limit as u32, Ordering::Release);
}

// ------------------------------------------------------------------- device

/// smoltcp's view of the vendor MAC.
pub struct WifiDevice {
    net_if: *mut NetIf,
}

impl WifiDevice {
    pub fn new(net_if: *mut NetIf) -> Self {
        WifiDevice { net_if }
    }
}

pub struct WifiRxToken {
    frame: [u8; RX_FRAME_MAX],
    len: usize,
}

pub struct WifiTxToken {
    net_if: *mut NetIf,
}

impl phy::RxToken for WifiRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.frame[..self.len])
    }
}

impl phy::TxToken for WifiTxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        // Allocating here rather than in `transmit` means a frame smoltcp
        // decides not to send costs nothing, and the pool is only touched on
        // the path that really transmits.
        let Some(buf) = txbuf::alloc() else {
            // No buffer: let smoltcp build the frame into a scratch area and
            // drop it. Reporting success with nothing sent is the same
            // outcome as a collision, and the peer will retransmit.
            let mut scratch = [0u8; MTU + 14];
            let n = len.min(scratch.len());
            return f(&mut scratch[..n]);
        };

        let result = unsafe {
            let frame = (*buf).frame_ptr();
            let slice = core::slice::from_raw_parts_mut(frame, len.min(txbuf::MAX_FRAME));
            let r = f(slice);
            (*buf).len = len.min(txbuf::MAX_FRAME) as u16;
            r
        };

        let rc = unsafe {
            super::fhost_tx_start(
                self.net_if as *mut core::ffi::c_void,
                buf as *mut core::ffi::c_void,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        };
        if rc != 0 {
            // The firmware refused it; the buffer is still ours to release.
            unsafe { txbuf::free(buf) };
        }
        result
    }
}

impl phy::Device for WifiDevice {
    type RxToken<'a>
        = WifiRxToken
    where
        Self: 'a;
    type TxToken<'a>
        = WifiTxToken
    where
        Self: 'a;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let mut frame = [0u8; RX_FRAME_MAX];
        let (len, _iface) = iface::rx_pop(&mut frame)?;
        Some((
            WifiRxToken { frame, len },
            WifiTxToken {
                net_if: self.net_if,
            },
        ))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(WifiTxToken {
            net_if: self.net_if,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ethernet;
        caps.max_transmission_unit = MTU;
        // The MAC does not offload checksums, so smoltcp computes them.
        caps.checksum.ipv4 = Checksum::Both;
        caps.checksum.udp = Checksum::Both;
        caps.checksum.tcp = Checksum::Both;
        caps.checksum.icmpv4 = Checksum::Both;
        caps
    }
}

// -------------------------------------------------------------------- stack

struct Stack {
    /// Address last pushed into smoltcp, so a change made through
    /// `net_al_ext_set_vif_ip` after startup is noticed.
    applied: (u32, u32, u32),
    iface: Interface,
    device: WifiDevice,
    sockets: SocketSet<'static>,
    dhcp_client: Option<smoltcp::iface::SocketHandle>,
    dhcpd: Option<Dhcpd>,
    /// A DHCP server has been asked for but the interface had no address yet.
    dhcpd_wanted: bool,
    net_if: *mut NetIf,
}

impl Stack {
    fn new(net_if: *mut NetIf, mac: [u8; 6]) -> Self {
        let mut device = WifiDevice::new(net_if);
        let config = Config::new(HardwareAddress::Ethernet(EthernetAddress(mac)));
        let iface = Interface::new(config, &mut device, now());
        Stack {
            applied: (0, 0, 0),
            iface,
            device,
            sockets: SocketSet::new(alloc::vec::Vec::new()),
            dhcp_client: None,
            dhcpd: None,
            dhcpd_wanted: false,
            net_if,
        }
    }

    /// Apply the address the blob configured through `net_al_ext_set_vif_ip`,
    /// or that DHCP obtained.
    fn set_addr(&mut self, addr: u32, mask: u32, gw: u32) {
        let a = Ipv4Address::from(addr.to_le_bytes());
        let prefix = u32::from_be_bytes(mask.to_le_bytes()).leading_ones() as u8;
        self.iface.update_ip_addrs(|addrs| {
            addrs.clear();
            let _ = addrs.push(IpCidr::Ipv4(Ipv4Cidr::new(a, prefix)));
        });
        self.iface.routes_mut().remove_default_ipv4_route();
        if gw != 0 {
            let g = Ipv4Address::from(gw.to_le_bytes());
            let _ = self.iface.routes_mut().add_default_ipv4_route(g);
        }
        unsafe {
            (*self.net_if).ipaddr.store(addr, Ordering::Release);
            (*self.net_if).netmask.store(mask, Ordering::Release);
            (*self.net_if).gw.store(gw, Ordering::Release);
        }
    }

    fn start_dhcp_client(&mut self) {
        if self.dhcp_client.is_some() {
            return;
        }
        self.iface.update_ip_addrs(|a| a.clear());
        let socket = dhcpv4::Socket::new();
        self.dhcp_client = Some(self.sockets.add(socket));
    }

    fn stop_dhcp_client(&mut self) {
        if let Some(h) = self.dhcp_client.take() {
            self.sockets.remove(h);
        }
    }

    /// Fold a DHCP client event into the interface. Returns true once a lease
    /// is in hand.
    fn poll_dhcp_client(&mut self) -> bool {
        let Some(h) = self.dhcp_client else {
            return false;
        };
        match self.sockets.get_mut::<dhcpv4::Socket>(h).poll() {
            Some(dhcpv4::Event::Configured(cfg)) => {
                let addr = u32::from_le_bytes(cfg.address.address().octets());
                let mask = u32::from_le_bytes(
                    Ipv4Address::from_bits(!0u32 << (32 - cfg.address.prefix_len())).octets(),
                );
                let gw = cfg
                    .router
                    .map(|r| u32::from_le_bytes(r.octets()))
                    .unwrap_or(0);
                let dns = cfg
                    .dns_servers
                    .first()
                    .map(|d| u32::from_le_bytes(d.octets()))
                    .unwrap_or(0);
                self.set_addr(addr, mask, gw);
                self.applied = (addr, mask, gw);
                unsafe { (*self.net_if).dns.store(dns, Ordering::Release) };
                post_ip_event(CODE_WIFI_ON_GOT_IP);
                true
            }
            Some(dhcpv4::Event::Deconfigured) => {
                self.iface.update_ip_addrs(|a| a.clear());
                unsafe { (*self.net_if).ipaddr.store(0, Ordering::Release) };
                post_ip_event(CODE_WIFI_ON_LOST_IP);
                false
            }
            None => unsafe { (*self.net_if).ipaddr.load(Ordering::Acquire) != 0 },
        }
    }

    /// Pick up an address the blob configured while we were running.
    fn sync_addr(&mut self) {
        let want = unsafe {
            (
                (*self.net_if).ipaddr.load(Ordering::Acquire),
                (*self.net_if).netmask.load(Ordering::Acquire),
                (*self.net_if).gw.load(Ordering::Acquire),
            )
        };
        if want != self.applied && want.0 != 0 {
            self.set_addr(want.0, want.1, want.2);
            self.applied = want;
        }
    }

    /// Bring the DHCP server up once the interface has an address to serve
    /// from. Called on every poll, so it costs nothing until it can succeed.
    fn start_dhcpd_if_ready(&mut self) {
        if !self.dhcpd_wanted || self.dhcpd.is_some() {
            return;
        }
        let (addr, mask) = unsafe {
            (
                (*self.net_if).ipaddr.load(Ordering::Acquire),
                (*self.net_if).netmask.load(Ordering::Acquire),
            )
        };
        if addr == 0 {
            return;
        }
        let packed = DHCPD_POOL.load(Ordering::Acquire);
        let (start, limit) = ((packed >> 16) as u16, packed as u16);
        if let Some(d) = Dhcpd::new(&mut self.sockets, addr, mask, start, limit) {
            crate::println!(
                "[net_al] dhcpd serving {}.{}.{}.{} pool .{}..{}",
                addr as u8,
                (addr >> 8) as u8,
                (addr >> 16) as u8,
                (addr >> 24) as u8,
                start,
                start + limit - 1
            );
            self.dhcpd = Some(d);
        }
    }

    fn poll(&mut self) {
        self.sync_addr();
        self.start_dhcpd_if_ready();
        self.iface.poll(now(), &mut self.device, &mut self.sockets);
        if let Some(d) = self.dhcpd.as_mut() {
            d.poll(&mut self.iface, &mut self.sockets);
        }
    }
}

fn now() -> Instant {
    Instant::from_millis(runtime::uptime_ms() as i64)
}

// ---------------------------------------------------------------- poll task

/// Drive the IP stack. Runs until reset.
///
/// Spawned by [`start`] once the blob has registered an interface, because
/// the interface's MAC address is needed to construct the stack.
extern "C" fn poll_task(_arg: *mut core::ffi::c_void) {
    // Bind lazily. The blob registers the station interface first and the
    // soft-AP second, and only tells us which one matters when it configures
    // an address on it -- so committing to slot 0 at startup binds the stack
    // to the wrong interface in AP mode, and the DHCP server then sees
    // 0.0.0.0.
    let mut stack: Option<Stack> = None;
    RUNNING.store(1, Ordering::Release);

    loop {
        // Rebind if the blob has named an interface other than the one we are
        // serving.
        let target = TARGET_IF.load(Ordering::Acquire) as *mut NetIf;
        if !target.is_null()
            && stack.as_ref().map(|s: &Stack| s.net_if) != Some(target)
            && iface::index_of(target).is_some()
        {
            stack = None;
        }

        if stack.is_none() {
            if let Some(p) = (!target.is_null())
                .then_some(target)
                .or_else(iface::designated)
            {
                let mac = unsafe { (*p).mac };
                let mut s = Stack::new(p, mac);
                let (addr, mask, gw) = unsafe {
                    (
                        (*p).ipaddr.load(Ordering::Acquire),
                        (*p).netmask.load(Ordering::Acquire),
                        (*p).gw.load(Ordering::Acquire),
                    )
                };
                if addr != 0 {
                    s.set_addr(addr, mask, gw);
                    s.applied = (addr, mask, gw);
                }
                stack = Some(s);
            }
        }
        let Some(stack) = stack.as_mut() else {
            runtime::delay_ms(10);
            continue;
        };
        // Commands first: a caller is blocked waiting on each one.
        let cmd = COMMAND.swap(Command::None as u8, Ordering::AcqRel);
        match cmd {
            x if x == Command::DhcpClientStart as u8 => {
                stack.start_dhcp_client();
                // The lease arrives asynchronously; RESULT is set once
                // poll_dhcp_client sees it.
            }
            x if x == Command::DhcpClientStop as u8 => {
                stack.stop_dhcp_client();
                RESULT.store(RESULT_OK, Ordering::Release);
            }
            x if x == Command::DhcpServerStart as u8 => {
                // The blob starts the server before configuring the address,
                // so "no address yet" is ordering, not failure. Remember the
                // request; `start_dhcpd_if_ready` acts on it once an address
                // appears.
                stack.dhcpd_wanted = true;
                stack.start_dhcpd_if_ready();
                RESULT.store(RESULT_OK, Ordering::Release);
            }
            x if x == Command::DhcpServerStop as u8 => {
                stack.dhcpd_wanted = false;
                if let Some(d) = stack.dhcpd.take() {
                    d.close(&mut stack.sockets);
                }
                RESULT.store(RESULT_OK, Ordering::Release);
            }
            _ => {}
        }

        stack.poll();

        if stack.dhcp_client.is_some()
            && RESULT.load(Ordering::Acquire) == RESULT_PENDING
            && stack.poll_dhcp_client()
        {
            RESULT.store(RESULT_OK, Ordering::Release);
        }

        #[cfg(feature = "net-trace")]
        {
            static TICK: AtomicU32 = AtomicU32::new(0);
            if TICK.fetch_add(1, Ordering::Relaxed) % 400 == 0 {
                let (tx, peak, dry, rx, drop) = super::stats();
                crate::println!(
                    "[net_al] tx_inflight={} peak={} exhausted={} rx={} dropped={}",
                    tx,
                    peak,
                    dry,
                    rx,
                    drop
                );
            }
        }

        // 5 ms keeps ping latency respectable without spinning; smoltcp's own
        // poll_delay would be tighter but needs a timer we do not have here.
        runtime::delay_ms(5);
    }
}

/// Start the IP stack task. Called once the blob has added an interface.
///
/// Safe to call repeatedly; only the first caller wins.
pub fn start() {
    if SPAWNED
        .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return;
    }
    unsafe {
        bl616_wifi_sys::xTaskCreate(
            Some(poll_task),
            c"net".as_ptr(),
            2048,
            core::ptr::null_mut(),
            8,
            core::ptr::null_mut(),
        );
    }
}

extern crate alloc;
use bl616_wifi_sys;
