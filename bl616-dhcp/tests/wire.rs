// SPDX-FileCopyrightText: 2026 Roman Valls Guimera <brainstorm@nopcode.org>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Wire-format and lease-assignment tests.
//!
//! These exist because the only other way to exercise this code is to
//! associate a real station to real hardware and see whether it configures
//! itself — which reports "worked" or "did not", and nothing about why.

use bl616_dhcp::Leases;

const DISCOVER: u8 = 1;
const OFFER: u8 = 2;
const REQUEST: u8 = 3;
const ACK: u8 = 5;
const NAK: u8 = 6;
const RELEASE: u8 = 7;

const OPT_REQUESTED_IP: u8 = 50;
const OPT_MSG_TYPE: u8 = 53;
const MAGIC: [u8; 4] = [99, 130, 83, 99];

/// 192.168.4.1, first octet in the low byte.
fn server() -> u32 {
    u32::from_le_bytes([192, 168, 4, 1])
}
fn mask24() -> u32 {
    u32::from_le_bytes([255, 255, 255, 0])
}
fn pool() -> Leases {
    Leases::new(server(), mask24(), 2, 16).expect("pool")
}

/// A BOOTREQUEST with a message-type option, and optionally a requested
/// address.
fn request(msg_type: u8, mac: &[u8; 6], requested: Option<u8>) -> Vec<u8> {
    let mut m = vec![0u8; 240];
    m[0] = 1; // BOOTREQUEST
    m[1] = 1; // ethernet
    m[2] = 6; // hlen
    m[4..8].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]); // xid
    m[28..34].copy_from_slice(mac);
    m[236..240].copy_from_slice(&MAGIC);
    m.extend_from_slice(&[OPT_MSG_TYPE, 1, msg_type]);
    if let Some(host) = requested {
        m.extend_from_slice(&[OPT_REQUESTED_IP, 4, 192, 168, 4, host]);
    }
    m.push(255); // END
    m
}

fn option<'a>(reply: &'a [u8], want: u8) -> Option<&'a [u8]> {
    let mut i = 240;
    while i < reply.len() {
        match reply[i] {
            255 => return None,
            0 => i += 1,
            code => {
                let len = reply[i + 1] as usize;
                if code == want {
                    return Some(&reply[i + 2..i + 2 + len]);
                }
                i += 2 + len;
            }
        }
    }
    None
}

fn exchange(p: &mut Leases, msg: &[u8]) -> Option<(u8, [u8; 548], usize)> {
    let mut reply = [0u8; 548];
    let n = p.handle(msg, &mut reply)?;
    let ty = option(&reply[..n], OPT_MSG_TYPE)?[0];
    Some((ty, reply, n))
}

#[test]
fn discover_is_offered_the_first_pool_address() {
    let mut p = pool();
    let (ty, reply, n) = exchange(&mut p, &request(DISCOVER, &[2; 6], None)).unwrap();
    assert_eq!(ty, OFFER);
    assert_eq!(&reply[16..20], &[192, 168, 4, 2], "yiaddr");
    assert!(n >= 300, "BOOTP minimum, got {n}");
}

#[test]
fn reply_carries_what_a_client_needs_to_configure_itself() {
    let mut p = pool();
    let (_, reply, n) = exchange(&mut p, &request(DISCOVER, &[2; 6], None)).unwrap();
    let r = &reply[..n];
    assert_eq!(r[0], 2, "BOOTREPLY");
    assert_eq!(&r[4..8], &[0xde, 0xad, 0xbe, 0xef], "xid must be echoed");
    assert_eq!(&r[236..240], &MAGIC);
    assert_eq!(option(r, 1).unwrap(), &[255, 255, 255, 0], "subnet mask");
    assert_eq!(option(r, 3).unwrap(), &[192, 168, 4, 1], "router");
    assert_eq!(option(r, 6).unwrap(), &[192, 168, 4, 1], "dns");
    assert_eq!(option(r, 54).unwrap(), &[192, 168, 4, 1], "server id");
    // Lease time is big-endian seconds, unlike the addresses.
    assert_eq!(
        u32::from_be_bytes(option(r, 51).unwrap().try_into().unwrap()),
        2 * 60 * 60
    );
}

#[test]
fn request_commits_the_lease_and_acks() {
    let mut p = pool();
    exchange(&mut p, &request(DISCOVER, &[2; 6], None)).unwrap();
    let (ty, reply, _) = exchange(&mut p, &request(REQUEST, &[2; 6], Some(2))).unwrap();
    assert_eq!(ty, ACK);
    assert_eq!(&reply[16..20], &[192, 168, 4, 2]);
}

#[test]
fn the_same_client_keeps_its_address() {
    let mut p = pool();
    exchange(&mut p, &request(REQUEST, &[2; 6], Some(2))).unwrap();
    // A second client takes the next one, and the first is offered its own
    // back rather than a new one.
    let (_, second, _) = exchange(&mut p, &request(DISCOVER, &[3; 6], None)).unwrap();
    assert_eq!(&second[16..20], &[192, 168, 4, 3]);
    let (_, again, _) = exchange(&mut p, &request(DISCOVER, &[2; 6], None)).unwrap();
    assert_eq!(&again[16..20], &[192, 168, 4, 2]);
}

#[test]
fn an_address_held_by_someone_else_is_refused() {
    let mut p = pool();
    exchange(&mut p, &request(REQUEST, &[2; 6], Some(2))).unwrap();
    let (ty, _, _) = exchange(&mut p, &request(REQUEST, &[3; 6], Some(2))).unwrap();
    assert_eq!(ty, NAK, "a second claim on a held address must be refused");
}

#[test]
fn an_address_outside_the_pool_falls_back_rather_than_being_handed_out() {
    let mut p = pool();
    let (ty, reply, _) = exchange(&mut p, &request(REQUEST, &[2; 6], Some(200))).unwrap();
    assert_eq!(ty, ACK);
    assert_eq!(
        &reply[16..20],
        &[192, 168, 4, 2],
        "must not hand out an address outside the pool"
    );
}

#[test]
fn release_returns_the_address_to_the_pool() {
    let mut p = pool();
    exchange(&mut p, &request(REQUEST, &[2; 6], Some(2))).unwrap();
    let mut reply = [0u8; 548];
    assert!(
        p.handle(&request(RELEASE, &[2; 6], None), &mut reply).is_none(),
        "RELEASE is not answered"
    );
    // Freed, so a different client can now take it.
    let (_, r, _) = exchange(&mut p, &request(DISCOVER, &[9; 6], None)).unwrap();
    assert_eq!(&r[16..20], &[192, 168, 4, 2]);
}

#[test]
fn an_exhausted_pool_stays_silent() {
    // Eight lease slots, so a pool of eight fills exactly.
    let mut p = Leases::new(server(), mask24(), 2, 8).unwrap();
    for i in 0..8u8 {
        let (ty, _, _) = exchange(&mut p, &request(REQUEST, &[i; 6], None)).unwrap();
        assert_eq!(ty, ACK, "client {i} should get a lease");
    }
    let mut reply = [0u8; 548];
    assert!(
        p.handle(&request(DISCOVER, &[99; 6], None), &mut reply).is_none(),
        "a full pool answers nothing at all, as a real server does"
    );
}

#[test]
fn malformed_input_is_rejected_rather_than_panicking() {
    let mut p = pool();
    let mut reply = [0u8; 548];
    // Shorter than the fixed header: the case that indexes out of bounds if
    // the length guard is missing.
    for len in [0usize, 1, 34, 239] {
        assert!(p.handle(&vec![0u8; len], &mut reply).is_none(), "len {len}");
    }
    // Right length, wrong magic cookie.
    let mut bad = request(DISCOVER, &[2; 6], None);
    bad[236] = 0;
    assert!(p.handle(&bad, &mut reply).is_none(), "bad cookie");
    // An option whose length runs off the end of the message.
    let mut truncated = request(DISCOVER, &[2; 6], None);
    truncated.pop();
    truncated.extend_from_slice(&[OPT_REQUESTED_IP, 40, 1, 2]);
    let _ = p.handle(&truncated, &mut reply);
    // A BOOTREPLY, which is not ours to answer.
    let mut reply_op = request(DISCOVER, &[2; 6], None);
    reply_op[0] = 2;
    assert!(p.handle(&reply_op, &mut reply).is_none(), "BOOTREPLY");
}

#[test]
fn unusable_configurations_are_refused() {
    assert!(Leases::new(0, mask24(), 2, 16).is_none(), "no server address");
    assert!(Leases::new(server(), mask24(), 0, 16).is_none(), "zero start");
    assert!(Leases::new(server(), mask24(), 2, 0).is_none(), "empty pool");
    assert!(Leases::new(server(), mask24(), 1, 16).is_none(), "would collide with the server");
    // Clamped rather than wrapping past the broadcast address.
    let p = Leases::new(server(), mask24(), 250, 100).unwrap();
    assert_eq!(p.last, 254);
}
