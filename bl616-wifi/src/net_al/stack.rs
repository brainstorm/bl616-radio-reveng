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

use core::sync::atomic::{AtomicU32, AtomicU8, Ordering};

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

/// Post a command and block until the poll task answers or `timeout_ms`
/// elapses. Must be called from a task.
pub fn request(cmd: Command, timeout_ms: u32) -> bool {
    if RUNNING.load(Ordering::Acquire) == 0 {
        return false;
    }
    RESULT.store(RESULT_PENDING, Ordering::Release);
    COMMAND.store(cmd as u8, Ordering::Release);

    let mut waited = 0;
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
    iface: Interface,
    device: WifiDevice,
    sockets: SocketSet<'static>,
    dhcp_client: Option<smoltcp::iface::SocketHandle>,
    dhcpd: Option<Dhcpd>,
    net_if: *mut NetIf,
}

impl Stack {
    fn new(net_if: *mut NetIf, mac: [u8; 6]) -> Self {
        let mut device = WifiDevice::new(net_if);
        let config = Config::new(HardwareAddress::Ethernet(EthernetAddress(mac)));
        let iface = Interface::new(config, &mut device, now());
        Stack {
            iface,
            device,
            sockets: SocketSet::new(alloc::vec::Vec::new()),
            dhcp_client: None,
            dhcpd: None,
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
                unsafe { (*self.net_if).dns.store(dns, Ordering::Release) };
                true
            }
            Some(dhcpv4::Event::Deconfigured) => {
                self.iface.update_ip_addrs(|a| a.clear());
                unsafe { (*self.net_if).ipaddr.store(0, Ordering::Release) };
                false
            }
            None => unsafe { (*self.net_if).ipaddr.load(Ordering::Acquire) != 0 },
        }
    }

    fn poll(&mut self) {
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
    let Some(net_if) = iface::primary() else {
        unsafe { bl616_wifi_sys::vTaskDelete(core::ptr::null_mut()) };
        unreachable!()
    };
    let mac = unsafe { (*net_if).mac };
    let mut stack = Stack::new(net_if, mac);

    // Apply whatever address the blob configured before we existed.
    let (addr, mask, gw) = unsafe {
        (
            (*net_if).ipaddr.load(Ordering::Acquire),
            (*net_if).netmask.load(Ordering::Acquire),
            (*net_if).gw.load(Ordering::Acquire),
        )
    };
    if addr != 0 {
        stack.set_addr(addr, mask, gw);
    }

    RUNNING.store(1, Ordering::Release);

    loop {
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
                let packed = DHCPD_POOL.load(Ordering::Acquire);
                let (start, limit) = ((packed >> 16) as u16, packed as u16);
                let self_addr = unsafe { (*net_if).ipaddr.load(Ordering::Acquire) };
                let mask = unsafe { (*net_if).netmask.load(Ordering::Acquire) };
                match Dhcpd::new(&mut stack.sockets, self_addr, mask, start, limit) {
                    Some(d) => {
                        stack.dhcpd = Some(d);
                        RESULT.store(RESULT_OK, Ordering::Release);
                    }
                    None => RESULT.store(RESULT_FAILED, Ordering::Release),
                }
            }
            x if x == Command::DhcpServerStop as u8 => {
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

        // 5 ms keeps ping latency respectable without spinning; smoltcp's own
        // poll_delay would be tighter but needs a timer we do not have here.
        runtime::delay_ms(5);
    }
}

/// Start the IP stack task. Called once the blob has added an interface.
pub fn start() {
    if RUNNING.load(Ordering::Acquire) != 0 {
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
