// SPDX-FileCopyrightText: 2026 Roman Valls Guimera <brainstorm@nopcode.org>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! A minimal DHCP server, for soft-AP mode.
//!
//! smoltcp ships a DHCP *client* and no server, so this is the one piece of
//! the vendor's lwIP arrangement with no drop-in replacement — and AP mode is
//! useless without it, since a station that associates but cannot get an
//! address has not really joined anything.
//!
//! Scope is deliberately small: DISCOVER/OFFER, REQUEST/ACK, RELEASE, and a
//! fixed pool of leases indexed by MAC. No renewals bookkeeping beyond the
//! lease time, no relays, no options past the handful a client needs to
//! configure an interface. That is enough for "join the AP and get an
//! address", which is what this exists to do.
//!
//! RFC 2131 message flow, for reference:
//!
//! ```text
//!   client                         server
//!     |------- DISCOVER (bcast) ----->|   pick a free address
//!     |<------ OFFER  ----------------|
//!     |------- REQUEST --------------->|  commit the lease
//!     |<------ ACK -------------------|
//! ```

use smoltcp::iface::{Interface, SocketHandle, SocketSet};
use smoltcp::socket::udp;
use smoltcp::wire::{IpEndpoint, Ipv4Address};

/// Leases the pool can hold.
const MAX_LEASES: usize = 8;
/// Lease time handed to clients, in seconds.
const LEASE_SECS: u32 = 2 * 60 * 60;

const SERVER_PORT: u16 = 67;
const CLIENT_PORT: u16 = 68;

const OP_BOOTREQUEST: u8 = 1;
const OP_BOOTREPLY: u8 = 2;
const HTYPE_ETHERNET: u8 = 1;
const MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];

const OPT_PAD: u8 = 0;
const OPT_SUBNET_MASK: u8 = 1;
const OPT_ROUTER: u8 = 3;
const OPT_DNS: u8 = 6;
const OPT_REQUESTED_IP: u8 = 50;
const OPT_LEASE_TIME: u8 = 51;
const OPT_MSG_TYPE: u8 = 53;
const OPT_SERVER_ID: u8 = 54;
const OPT_END: u8 = 255;

const DHCP_DISCOVER: u8 = 1;
const DHCP_OFFER: u8 = 2;
const DHCP_REQUEST: u8 = 3;
const DHCP_ACK: u8 = 5;
const DHCP_NAK: u8 = 6;
const DHCP_RELEASE: u8 = 7;

/// Smallest BOOTP message we will look at: fixed header plus magic cookie.
const BOOTP_MIN: usize = 240;

#[derive(Clone, Copy, Default)]
struct Lease {
    mac: [u8; 6],
    /// Host number within the subnet, 0 when the slot is free.
    host: u8,
}

/// The server.
pub struct Dhcpd {
    socket: SocketHandle,
    /// Our own address, network byte order.
    server: u32,
    mask: u32,
    /// First and last host numbers we may hand out.
    first: u8,
    last: u8,
    leases: [Lease; MAX_LEASES],
}

impl Dhcpd {
    /// Bind port 67 and prepare the pool.
    ///
    /// `start` and `limit` come from `ApConfig` by way of
    /// `net_al_dhcpd_start`: the first host number and how many.
    pub fn new(
        sockets: &mut SocketSet<'static>,
        server: u32,
        mask: u32,
        start: u16,
        limit: u16,
    ) -> Option<Self> {
        if server == 0 || start == 0 || limit == 0 {
            return None;
        }
        // The AP is x.x.x.1 by convention and the pool follows it. Clamp so a
        // silly configuration cannot hand out the broadcast address or our
        // own.
        let first = start.min(254) as u8;
        let last = (start + limit - 1).min(254) as u8;
        if first < 2 || last < first {
            return None;
        }

        // Two 1500-byte datagrams of headroom each way is ample: DHCP traffic
        // is a handful of small packets per client.
        let rx = udp::PacketBuffer::new(
            alloc::vec![udp::PacketMetadata::EMPTY; 4],
            alloc::vec![0u8; 1500],
        );
        let tx = udp::PacketBuffer::new(
            alloc::vec![udp::PacketMetadata::EMPTY; 4],
            alloc::vec![0u8; 1500],
        );
        let mut socket = udp::Socket::new(rx, tx);
        socket.bind(SERVER_PORT).ok()?;

        Some(Dhcpd {
            socket: sockets.add(socket),
            server,
            mask,
            first,
            last,
            leases: [Lease::default(); MAX_LEASES],
        })
    }

    pub fn close(self, sockets: &mut SocketSet<'static>) {
        sockets.remove(self.socket);
    }

    /// Service any pending client messages.
    pub fn poll(&mut self, _iface: &mut Interface, sockets: &mut SocketSet<'static>) {
        loop {
            let socket = sockets.get_mut::<udp::Socket>(self.socket);
            if !socket.can_recv() {
                return;
            }
            let mut req = [0u8; 1024];
            let len = match socket.recv_slice(&mut req) {
                Ok((n, _meta)) => n,
                Err(_) => return,
            };
            if len < BOOTP_MIN {
                continue;
            }

            let mut reply = [0u8; 548];
            if let Some(reply_len) = self.handle(&req[..len], &mut reply) {
                // Always broadcast: the client has no address yet, so a
                // unicast reply would need an ARP entry it cannot answer.
                let to = IpEndpoint::new(Ipv4Address::BROADCAST.into(), CLIENT_PORT);
                let socket = sockets.get_mut::<udp::Socket>(self.socket);
                let _ = socket.send_slice(&reply[..reply_len], to);
            }
        }
    }

    /// Build a reply for one request. Returns its length, or `None` to ignore.
    fn handle(&mut self, req: &[u8], reply: &mut [u8; 548]) -> Option<usize> {
        if req[0] != OP_BOOTREQUEST || req[1] != HTYPE_ETHERNET {
            return None;
        }
        if req[236..240] != MAGIC_COOKIE {
            return None;
        }

        let mut mac = [0u8; 6];
        mac.copy_from_slice(&req[28..34]);

        let msg_type = find_option(req, OPT_MSG_TYPE)?.first().copied()?;
        let requested = find_option(req, OPT_REQUESTED_IP)
            .and_then(|o| (o.len() == 4).then(|| u32::from_le_bytes([o[0], o[1], o[2], o[3]])));

        let (reply_type, host) = match msg_type {
            // Pool exhausted: stay silent, as a real server does.
            DHCP_DISCOVER => (DHCP_OFFER, self.offer(&mac)?),
            DHCP_REQUEST => {
                let wanted = requested.map(|a| a.to_le_bytes()[3]);
                match self.commit(&mac, wanted) {
                    Some(h) => (DHCP_ACK, h),
                    None => (DHCP_NAK, 0),
                }
            }
            DHCP_RELEASE => {
                self.release(&mac);
                return None;
            }
            _ => return None,
        };

        Some(self.build_reply(req, reply, reply_type, host, &mac))
    }

    /// Address for this MAC: its existing lease, or a new one.
    fn offer(&mut self, mac: &[u8; 6]) -> Option<u8> {
        if let Some(l) = self.leases.iter().find(|l| l.host != 0 && &l.mac == mac) {
            return Some(l.host);
        }
        let taken = |h: u8, leases: &[Lease; MAX_LEASES]| leases.iter().any(|l| l.host == h);
        (self.first..=self.last).find(|&h| !taken(h, &self.leases))
    }

    /// Commit a lease, honouring the client's requested address when it is
    /// ours to give.
    fn commit(&mut self, mac: &[u8; 6], wanted: Option<u8>) -> Option<u8> {
        let host = match wanted {
            Some(h) if h >= self.first && h <= self.last => {
                let held_by_other = self
                    .leases
                    .iter()
                    .any(|l| l.host == h && &l.mac != mac && l.host != 0);
                if held_by_other {
                    return None;
                }
                h
            }
            _ => self.offer(mac)?,
        };

        if let Some(slot) = self
            .leases
            .iter_mut()
            .find(|l| l.host == host || (l.host != 0 && &l.mac == mac))
        {
            slot.mac = *mac;
            slot.host = host;
            return Some(host);
        }
        let slot = self.leases.iter_mut().find(|l| l.host == 0)?;
        slot.mac = *mac;
        slot.host = host;
        Some(host)
    }

    fn release(&mut self, mac: &[u8; 6]) {
        for l in self.leases.iter_mut() {
            if &l.mac == mac {
                *l = Lease::default();
            }
        }
    }

    fn build_reply(
        &self,
        req: &[u8],
        reply: &mut [u8; 548],
        msg_type: u8,
        host: u8,
        mac: &[u8; 6],
    ) -> usize {
        reply.fill(0);
        reply[0] = OP_BOOTREPLY;
        reply[1] = HTYPE_ETHERNET;
        reply[2] = 6; // hlen
        reply[4..8].copy_from_slice(&req[4..8]); // xid, echoed
        reply[10..12].copy_from_slice(&req[10..12]); // flags, echoed

        // yiaddr: the address being offered, in network order.
        let mut yi = self.server.to_le_bytes();
        yi[3] = host;
        if msg_type != DHCP_NAK {
            reply[16..20].copy_from_slice(&yi);
        }
        // siaddr
        reply[20..24].copy_from_slice(&self.server.to_le_bytes());
        reply[28..34].copy_from_slice(mac);
        reply[236..240].copy_from_slice(&MAGIC_COOKIE);

        let mut n = 240;
        let mut put = |code: u8, data: &[u8], n: &mut usize| {
            reply[*n] = code;
            reply[*n + 1] = data.len() as u8;
            reply[*n + 2..*n + 2 + data.len()].copy_from_slice(data);
            *n += 2 + data.len();
        };

        put(OPT_MSG_TYPE, &[msg_type], &mut n);
        put(OPT_SERVER_ID, &self.server.to_le_bytes(), &mut n);
        if msg_type != DHCP_NAK {
            put(OPT_LEASE_TIME, &LEASE_SECS.to_be_bytes(), &mut n);
            put(OPT_SUBNET_MASK, &self.mask.to_le_bytes(), &mut n);
            put(OPT_ROUTER, &self.server.to_le_bytes(), &mut n);
            // Point DNS at ourselves; there is no resolver behind it, but a
            // client that insists on a DNS option gets a well-formed one.
            put(OPT_DNS, &self.server.to_le_bytes(), &mut n);
        }
        reply[n] = OPT_END;
        n += 1;

        // BOOTP wants at least 300 bytes on the wire; pad to keep old clients
        // happy.
        while n < 300 {
            reply[n] = OPT_PAD;
            n += 1;
        }
        n
    }
}

/// Find a DHCP option's payload in a message.
fn find_option(msg: &[u8], want: u8) -> Option<&[u8]> {
    let mut i = BOOTP_MIN;
    while i < msg.len() {
        let code = msg[i];
        if code == OPT_END {
            return None;
        }
        if code == OPT_PAD {
            i += 1;
            continue;
        }
        if i + 1 >= msg.len() {
            return None;
        }
        let len = msg[i + 1] as usize;
        if i + 2 + len > msg.len() {
            return None;
        }
        if code == want {
            return Some(&msg[i + 2..i + 2 + len]);
        }
        i += 2 + len;
    }
    None
}

extern crate alloc;
