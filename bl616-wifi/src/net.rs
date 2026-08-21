// SPDX-FileCopyrightText: 2026 Roman Valls Guimera <brainstorm@nopcode.org>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! IPv4 addressing.
//!
//! lwIP stores addresses in network byte order, which on this little-endian
//! core means the first octet sits in the least significant byte. [`Ipv4`]
//! wraps that representation so it can be handed to the vendor API unchanged.

use core::fmt;

use bl616_wifi_sys as sys;

/// An IPv4 address in lwIP's on-the-wire representation.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct Ipv4(u32);

impl Ipv4 {
    /// From dotted-quad octets.
    pub const fn new(a: u8, b: u8, c: u8, d: u8) -> Self {
        Ipv4(u32::from_le_bytes([a, b, c, d]))
    }

    /// From lwIP's `u32_t` (network byte order), e.g. straight out of
    /// `wifi_sta_ip4_addr_get`.
    pub const fn from_raw(raw: u32) -> Self {
        Ipv4(raw)
    }

    /// The lwIP representation, for handing back to the C API.
    pub const fn as_raw(self) -> u32 {
        self.0
    }

    /// The four octets, most significant first.
    pub const fn octets(self) -> [u8; 4] {
        self.0.to_le_bytes()
    }

    /// `true` for 0.0.0.0.
    pub const fn is_unspecified(self) -> bool {
        self.0 == 0
    }

    /// Number of leading ones, for printing a netmask as a prefix length.
    pub const fn prefix_len(self) -> u32 {
        u32::from_be_bytes(self.0.to_le_bytes()).leading_ones()
    }
}

impl fmt::Display for Ipv4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d] = self.octets();
        write!(f, "{a}.{b}.{c}.{d}")
    }
}

impl fmt::Debug for Ipv4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// A complete IPv4 configuration, as handed out by DHCP or configured on the
/// soft-AP.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct Ipv4Config {
    pub address: Ipv4,
    pub netmask: Ipv4,
    pub gateway: Ipv4,
    pub dns: Ipv4,
}

impl Ipv4Config {
    /// Read the station interface's current addressing from lwIP.
    pub fn current_sta() -> Option<Self> {
        let (mut addr, mut mask, mut gw, mut dns) = (0u32, 0u32, 0u32, 0u32);
        let rc = unsafe { sys::wifi_sta_ip4_addr_get(&mut addr, &mut mask, &mut gw, &mut dns) };
        if rc != 0 || addr == 0 {
            return None;
        }
        Some(Ipv4Config {
            address: Ipv4::from_raw(addr),
            netmask: Ipv4::from_raw(mask),
            gateway: Ipv4::from_raw(gw),
            dns: Ipv4::from_raw(dns),
        })
    }
}

impl fmt::Display for Ipv4Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}/{} via {} (dns {})",
            self.address,
            self.netmask.prefix_len(),
            self.gateway,
            self.dns
        )
    }
}

impl fmt::Debug for Ipv4Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// Format a MAC address as `aa:bb:cc:dd:ee:ff`.
pub struct MacAddr(pub [u8; 6]);

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let m = self.0;
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            m[0], m[1], m[2], m[3], m[4], m[5]
        )
    }
}

impl fmt::Debug for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
