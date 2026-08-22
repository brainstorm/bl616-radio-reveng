// SPDX-FileCopyrightText: 2026 Roman Valls Guimera <brainstorm@nopcode.org>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! DHCP message handling: parsing, lease assignment and reply construction.
//!
//! Deliberately free of any dependency on smoltcp, the vendor stack or the
//! target — it is plain byte manipulation over `&[u8]`. That is what makes it
//! testable on the host, which matters because this code cannot be exercised
//! without a station associating to real hardware, and a wire-format mistake
//! here is invisible until a client silently fails to configure itself.
//!
//! `bl616-wifi`'s `net_al::dhcpd` wraps this with a UDP socket.
//!
//! It builds for the host as well as the target, so the wire format is
//! covered by unit tests in `tests/`. That matters more here than elsewhere:
//! this code cannot be exercised without a station associating to real
//! hardware, and a wire-format mistake is invisible until a client silently
//! fails to configure itself.

#![no_std]

/// Leases the pool can hold.
const MAX_LEASES: usize = 8;
/// Lease time handed to clients, in seconds.
const LEASE_SECS: u32 = 2 * 60 * 60;

/// The port a server listens on.
pub const SERVER_PORT: u16 = 67;
/// The port replies are sent to.
pub const CLIENT_PORT: u16 = 68;

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
pub struct Lease {
    pub mac: [u8; 6],
    /// Host number within the subnet, 0 when the slot is free.
    pub host: u8,
}


/// Lease table and address pool.
pub struct Leases {
    /// Our own address, network byte order (first octet in the low byte).
    pub server: u32,
    pub mask: u32,
    /// First and last host numbers we may hand out.
    pub first: u8,
    pub last: u8,
    pub leases: [Lease; MAX_LEASES],
}

impl Leases {
    /// Build a pool, or `None` if the configuration cannot produce one.
    pub fn new(server: u32, mask: u32, start: u16, limit: u16) -> Option<Self> {
        if server == 0 || start == 0 || limit == 0 {
            return None;
        }
        // Clamp so a silly configuration cannot hand out the broadcast
        // address, or our own.
        let first = start.min(254) as u8;
        let last = (start as u32 + limit as u32 - 1).min(254) as u8;
        if first < 2 || last < first {
            return None;
        }
        Some(Leases {
            server,
            mask,
            first,
            last,
            leases: [Lease::default(); MAX_LEASES],
        })
    }

    /// Build a reply for one request. Returns its length, or `None` when the
    /// message is not ours to answer.
    pub fn handle(&mut self, req: &[u8], reply: &mut [u8; 548]) -> Option<usize> {
        // Everything below indexes the fixed header, so establish it exists
        // first. Callers that read from a socket have usually checked, but a
        // public entry point cannot assume it.
        if req.len() < BOOTP_MIN {
            return None;
        }
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
    pub fn offer(&mut self, mac: &[u8; 6]) -> Option<u8> {
        if let Some(l) = self.leases.iter().find(|l| l.host != 0 && &l.mac == mac) {
            return Some(l.host);
        }
        let taken = |h: u8, leases: &[Lease; MAX_LEASES]| leases.iter().any(|l| l.host == h);
        (self.first..=self.last).find(|&h| !taken(h, &self.leases))
    }
    pub fn commit(&mut self, mac: &[u8; 6], wanted: Option<u8>) -> Option<u8> {
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
    pub fn release(&mut self, mac: &[u8; 6]) {
        for l in self.leases.iter_mut() {
            if &l.mac == mac {
                *l = Lease::default();
            }
        }
    }
    pub fn build_reply(
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

