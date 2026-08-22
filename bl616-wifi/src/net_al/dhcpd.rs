// SPDX-FileCopyrightText: 2026 Roman Valls Guimera <brainstorm@nopcode.org>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! A minimal DHCP server, for soft-AP mode.
//!
//! smoltcp ships a DHCP *client* and no server, so this is the one piece of
//! the vendor's lwIP arrangement with no drop-in replacement — and AP mode is
//! useless without it, since a station that associates but cannot get an
//! address has not really joined anything. embassy-net has no server either,
//! so this stays needed whichever stack is on top.
//!
//! Only the socket lives here. The wire format and lease assignment are in
//! [`bl616_dhcp`], which depends on nothing and is unit-tested on the host —
//! and which is what makes moving this to another stack a matter of swapping
//! the dozen lines below.

use bl616_dhcp::{Leases, CLIENT_PORT, SERVER_PORT};
use smoltcp::iface::{Interface, SocketHandle, SocketSet};
use smoltcp::socket::udp;
use smoltcp::wire::{IpEndpoint, Ipv4Address};

/// The server.
pub struct Dhcpd {
    socket: SocketHandle,
    leases: Leases,
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
        let leases = Leases::new(server, mask, start, limit)?;

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
            leases,
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

            let mut reply = [0u8; 548];
            if let Some(reply_len) = self.leases.handle(&req[..len], &mut reply) {
                // Always broadcast: the client has no address yet, so a
                // unicast reply would need an ARP entry it cannot answer.
                let to = IpEndpoint::new(Ipv4Address::BROADCAST.into(), CLIENT_PORT);
                let socket = sockets.get_mut::<udp::Socket>(self.socket);
                let _ = socket.send_slice(&reply[..reply_len], to);
            }
        }
    }
}

extern crate alloc;
