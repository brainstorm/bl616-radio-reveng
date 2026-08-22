// SPDX-FileCopyrightText: 2026 Roman Valls Guimera <brainstorm@nopcode.org>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! The IP stack: smoltcp over the vendor MAC.
//!
//! Not driven under the `embassy-net` feature: there the application brings
//! its own embassy-net stack and this module keeps only the bookkeeping the
//! blob's `net_al_ext_*` entry points need. The rest stays compiled so both
//! front ends are type-checked in every build, and `--gc-sections` drops it
//! from the image because nothing references it.
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

#![cfg_attr(feature = "embassy-net", allow(dead_code))]

use core::ffi::c_int;
use core::sync::atomic::{AtomicU32, AtomicU8, AtomicUsize, Ordering};

use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{self, Checksum, DeviceCapabilities, Medium};
use smoltcp::socket::{dhcpv4, icmp};
use smoltcp::time::Instant;
use smoltcp::wire::{
    EthernetAddress, HardwareAddress, Icmpv4Packet, Icmpv4Repr, IpCidr, Ipv4Address, Ipv4Cidr,
};

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
/// Frames handed to smoltcp, so a ring that fills without draining is
/// distinguishable from one nothing is arriving in.
pub(crate) static POPPED: AtomicU32 = AtomicU32::new(0);

/// Frames handed to `fhost_tx_start`, and those it refused.
///
/// Separate from the pool's occupancy: a buffer can be allocated and returned
/// without anything reaching the air, which is precisely the case these
/// counters exist to distinguish.
static TX_SUBMIT: AtomicU32 = AtomicU32::new(0);
static TX_FAIL: AtomicU32 = AtomicU32::new(0);
/// Inbound ARP frames, and ARP frames whose target is our own address.
static RX_ARP: AtomicU32 = AtomicU32::new(0);
static RX_ARP_FOR_US: AtomicU32 = AtomicU32::new(0);

/// Outbound echo requests sent, and replies matched.
///
/// The station lives on an access point that isolates its clients, so no other
/// host on the network can ping it -- proving the path works has to be done
/// from this end, against the gateway.
static PING_WANT: AtomicU32 = AtomicU32::new(0);
static PING_TX: AtomicU32 = AtomicU32::new(0);
static PING_RX: AtomicU32 = AtomicU32::new(0);
/// Round trip of the most recent reply, in milliseconds.
static PING_RTT_MS: AtomicU32 = AtomicU32::new(0);

/// Identifier for our echo requests; any value will do, it only has to come
/// back unchanged.
const PING_IDENT: u16 = 0x616;
/// Gap between requests.
const PING_INTERVAL_MS: u64 = 1000;

/// Start pinging the default gateway once an address is configured.
pub fn ping_start() {
    PING_WANT.store(1, Ordering::Release);
}

/// Echo requests sent, replies received, and the last round trip in ms.
pub fn ping_stats() -> (u32, u32, u32) {
    (
        PING_TX.load(Ordering::Relaxed),
        PING_RX.load(Ordering::Relaxed),
        PING_RTT_MS.load(Ordering::Relaxed),
    )
}

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
#[cfg(not(feature = "embassy-net"))]
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

/// Ask the poll task to run a DHCP client, without waiting for the lease.
///
/// The caller is usually one of the blob's own tasks, which must not be held
/// up; the outcome reaches the application as a `GOT_IP` event instead.
pub fn start_dhcp_client_async() {
    if let Some(p) = iface::by_index(0) {
        set_target(p as *mut core::ffi::c_void);
    }
    COMMAND.store(Command::DhcpClientStart as u8, Ordering::Release);
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
    /// Landing area for `rx_pop`, owned by the device so it is not a stack
    /// temporary in `receive`.
    scratch: alloc::boxed::Box<[u8; RX_FRAME_MAX]>,
}

impl WifiDevice {
    pub fn new(net_if: *mut NetIf) -> Self {
        WifiDevice {
            net_if,
            scratch: alloc::boxed::Box::new([0; RX_FRAME_MAX]),
        }
    }
}

/// A received frame on its way into smoltcp.
///
/// The payload lives on the heap rather than inline. An inline
/// `[u8; RX_FRAME_MAX]` is moved twice per receive -- once out of the local in
/// `Device::receive`, once into the token -- and smoltcp may hold more than
/// one, which is several kilobytes of a task stack that also has to fit
/// smoltcp's own frame processing. That is survivable while almost nothing is
/// arriving and is not once traffic starts.
pub struct WifiRxToken {
    frame: alloc::vec::Vec<u8>,
}

pub struct WifiTxToken {
    net_if: *mut NetIf,
}

impl phy::RxToken for WifiRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.frame)
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
        TX_SUBMIT.fetch_add(1, Ordering::Relaxed);
        if rc != 0 {
            // The firmware refused it; the buffer is still ours to release.
            TX_FAIL.fetch_add(1, Ordering::Relaxed);
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
        // Reused across calls, so the big buffer is not a stack temporary.
        let (len, _iface) = iface::rx_pop(&mut self.scratch[..])?;
        POPPED.fetch_add(1, Ordering::Relaxed);
        // Account ARP separately. "Did the request even reach smoltcp, and was
        // it asking for us?" is the question that separates a stack that never
        // generates a reply from one whose reply is not getting out.
        if len >= 42 && self.scratch[12..14] == [0x08, 0x06] {
            RX_ARP.fetch_add(1, Ordering::Relaxed);
            let mine = unsafe { (*self.net_if).ipaddr.load(Ordering::Acquire) }.to_le_bytes();
            if self.scratch[38..42] == mine {
                RX_ARP_FOR_US.fetch_add(1, Ordering::Relaxed);
            }
        }
        Some((
            WifiRxToken {
                frame: self.scratch[..len].to_vec(),
            },
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
    ping: Option<smoltcp::iface::SocketHandle>,
    ping_seq: u16,
    ping_due_ms: u64,
    ping_sent_ms: u64,
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
            ping: None,
            ping_seq: 0,
            ping_due_ms: 0,
            ping_sent_ms: 0,
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
                // smoltcp reports Deconfigured once when the client starts,
                // before it has ever held a lease. Only tell the application
                // an address was lost if it actually had one.
                let had = unsafe { (*self.net_if).ipaddr.load(Ordering::Acquire) } != 0;
                self.iface.update_ip_addrs(|a| a.clear());
                unsafe { (*self.net_if).ipaddr.store(0, Ordering::Release) };
                if had {
                    post_ip_event(CODE_WIFI_ON_LOST_IP);
                }
                false
            }
            None => unsafe { (*self.net_if).ipaddr.load(Ordering::Acquire) != 0 },
        }
    }

    /// Send an echo request to the gateway once a second and match replies.
    ///
    /// `auto-icmp-echo-reply` answers inbound pings without a socket, but
    /// originating one needs somewhere for the reply to land, so this binds an
    /// ICMP socket on our identifier.
    fn poll_ping(&mut self) {
        if PING_WANT.load(Ordering::Acquire) == 0 {
            return;
        }
        let gw = unsafe { (*self.net_if).gw.load(Ordering::Acquire) };
        let addr = unsafe { (*self.net_if).ipaddr.load(Ordering::Acquire) };
        if gw == 0 || addr == 0 {
            return;
        }

        if self.ping.is_none() {
            let rx = icmp::PacketBuffer::new(
                alloc::vec![icmp::PacketMetadata::EMPTY; 4],
                alloc::vec![0u8; 512],
            );
            let tx = icmp::PacketBuffer::new(
                alloc::vec![icmp::PacketMetadata::EMPTY; 4],
                alloc::vec![0u8; 512],
            );
            let mut sock = icmp::Socket::new(rx, tx);
            if sock.bind(icmp::Endpoint::Ident(PING_IDENT)).is_err() {
                return;
            }
            self.ping = Some(self.sockets.add(sock));
        }
        let handle = self.ping.unwrap();
        let now = runtime::uptime_ms();
        let dst = Ipv4Address::from(gw.to_le_bytes());

        let sock = self.sockets.get_mut::<icmp::Socket>(handle);
        if now >= self.ping_due_ms && sock.can_send() {
            self.ping_seq = self.ping_seq.wrapping_add(1);
            let payload = b"bl616-rust-net";
            let repr = Icmpv4Repr::EchoRequest {
                ident: PING_IDENT,
                seq_no: self.ping_seq,
                data: payload,
            };
            if let Ok(buf) = sock.send(repr.buffer_len(), dst.into()) {
                let mut packet = Icmpv4Packet::new_unchecked(buf);
                repr.emit(&mut packet, &Default::default());
                PING_TX.fetch_add(1, Ordering::Relaxed);
                self.ping_sent_ms = now;
            }
            self.ping_due_ms = now + PING_INTERVAL_MS;
        }

        while sock.can_recv() {
            let Ok((payload, _from)) = sock.recv() else {
                break;
            };
            let packet = Icmpv4Packet::new_unchecked(payload);
            if let Ok(Icmpv4Repr::EchoReply { ident, .. }) =
                Icmpv4Repr::parse(&packet, &Default::default())
            {
                if ident == PING_IDENT {
                    PING_RX.fetch_add(1, Ordering::Relaxed);
                    PING_RTT_MS.store(
                        now.saturating_sub(self.ping_sent_ms) as u32,
                        Ordering::Relaxed,
                    );
                }
            }
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
                #[cfg(feature = "net-trace")]
                crate::println!(
                    "[net_al] stack bound to slot {:?} addr={:08x}",
                    iface::index_of(p),
                    addr
                );
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

        stack.poll_ping();

        #[cfg(feature = "net-trace")]
        {
            static TICK: AtomicU32 = AtomicU32::new(0);
            if TICK.fetch_add(1, Ordering::Relaxed) % 400 == 0 {
                let (tx, peak, dry, rx, drop) = super::stats();
                crate::println!(
                    "[net_al] inflight={} peak={} dry={} rx={} drop={} pop={} txq={} txfail={} arp={}/{} ping={}/{} rtt={}ms",
                    tx,
                    peak,
                    dry,
                    rx,
                    drop,
                    POPPED.load(Ordering::Relaxed),
                    TX_SUBMIT.load(Ordering::Relaxed),
                    TX_FAIL.load(Ordering::Relaxed),
                    RX_ARP_FOR_US.load(Ordering::Relaxed),
                    RX_ARP.load(Ordering::Relaxed),
                    PING_RX.load(Ordering::Relaxed),
                    PING_TX.load(Ordering::Relaxed),
                    PING_RTT_MS.load(Ordering::Relaxed)
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
/// The RX ring has one consumer. Under the embassy front end that consumer is
/// the application's embassy-net stack, so this task must not exist -- two
/// poppers would each see half the frames.
#[cfg(feature = "embassy-net")]
pub fn start() {}

#[cfg(not(feature = "embassy-net"))]
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
            // smoltcp's frame processing is not small, and this task also
            // runs the DHCP server.
            4096,
            core::ptr::null_mut(),
            8,
            core::ptr::null_mut(),
        );
    }
}

extern crate alloc;
#[cfg(not(feature = "embassy-net"))]
use bl616_wifi_sys;
