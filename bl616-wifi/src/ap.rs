// SPDX-FileCopyrightText: 2026 Roman Valls Guimera <brainstorm@nopcode.org>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Access-point mode: hosting a network of your own.
//!
//! The vendor stack runs hostapd's authenticator and, if you let it, a DHCP
//! server, so a WPA2 soft-AP with a working address pool is one call.

use bl616_wifi_sys as sys;

use crate::cstr::{AkmStr, Passphrase, Ssid};
use crate::error::{Error, Result};
use crate::event::{self, Event};
use crate::net::{Ipv4, MacAddr};
use crate::sta::Akm;
use crate::Wifi;

/// How to run the soft-AP.
///
/// [`ApConfig::wpa2`] gives you a WPA2-PSK AP on channel 6 at 192.168.4.1
/// handing out leases from .2 upward, which is what you usually want.
#[derive(Clone, Copy, Debug)]
pub struct ApConfig<'a> {
    /// Network name, at most 32 bytes.
    pub ssid: &'a str,
    /// Passphrase, 8..=63 characters. `None` makes an open network.
    pub passphrase: Option<&'a str>,
    /// AKM to advertise. [`Akm::Auto`] means WPA2 when a passphrase is set.
    pub akm: Akm,
    /// 2.4 GHz channel, 1..=13. Zero lets the stack pick (channel 6).
    pub channel: u8,
    /// Do not put the SSID in beacons.
    pub hidden: bool,
    /// Stop associated stations from talking to each other.
    pub isolate: bool,
    /// Beacon interval in TU (1.024 ms each). Zero uses the stack default
    /// of 100 TU, i.e. about 102 ms.
    pub beacon_interval_tu: i32,
    /// Address of the AP itself. Must end in `.1` — the vendor stack derives
    /// the pool from it and complains otherwise.
    pub address: Ipv4,
    /// Subnet mask for the AP network.
    pub netmask: Ipv4,
    /// Run the built-in DHCP server.
    pub dhcp_server: bool,
    /// First host number in the DHCP pool, counted from the network address.
    pub dhcp_start: i32,
    /// How many leases the pool holds.
    pub dhcp_limit: i32,
    /// Drop a station after this many seconds of silence. Zero uses the
    /// stack default.
    pub max_inactivity_s: u32,
    /// How long to wait for the AP to come up, in milliseconds.
    pub timeout_ms: u32,
}

impl<'a> ApConfig<'a> {
    /// A WPA2-PSK access point on 192.168.4.1/24 with DHCP.
    pub const fn wpa2(ssid: &'a str, passphrase: &'a str) -> Self {
        ApConfig {
            ssid,
            passphrase: Some(passphrase),
            akm: Akm::Wpa2,
            channel: 6,
            hidden: false,
            isolate: false,
            beacon_interval_tu: 0,
            address: Ipv4::new(192, 168, 4, 1),
            netmask: Ipv4::new(255, 255, 255, 0),
            dhcp_server: true,
            dhcp_start: 2,
            dhcp_limit: 16,
            max_inactivity_s: 0,
            timeout_ms: 10_000,
        }
    }

    /// An open access point. Everything on the air is readable by anyone;
    /// only reasonable for provisioning flows.
    pub const fn open(ssid: &'a str) -> Self {
        ApConfig {
            passphrase: None,
            akm: Akm::Open,
            ..Self::wpa2(ssid, "")
        }
    }

    /// Put the AP on a specific channel.
    pub const fn on_channel(mut self, channel: u8) -> Self {
        self.channel = channel;
        self
    }

    /// Move the AP network somewhere else. `address` must end in `.1`.
    pub const fn with_network(mut self, address: Ipv4, netmask: Ipv4) -> Self {
        self.address = address;
        self.netmask = netmask;
        self
    }

    /// Do not beacon the SSID.
    pub const fn hidden(mut self) -> Self {
        self.hidden = true;
        self
    }

    /// Do not run a DHCP server; clients must configure themselves.
    pub const fn without_dhcp_server(mut self) -> Self {
        self.dhcp_server = false;
        self
    }
}

impl Wifi {
    /// Start the soft-AP and wait until it is beaconing.
    ///
    /// Blocks for up to [`ApConfig::timeout_ms`].
    pub fn start_ap(&self, config: &ApConfig<'_>) -> Result<()> {
        let ssid = Ssid::new(config.ssid).ok_or(Error::InvalidArgument)?;
        let key = Passphrase::maybe(config.passphrase)?;

        // "If NULL and key is not NULL, the default AKM is WPA2" — but being
        // explicit means an open AP cannot silently acquire a passphrase.
        let akm_str = match (config.akm, config.passphrase) {
            (Akm::Auto, Some(_)) => Some("WPA2"),
            (Akm::Auto, None) => Some("OPEN"),
            (other, _) => other.as_vendor_str(),
        };
        let akm = AkmStr::maybe(akm_str)?;

        if let Some(p) = config.passphrase {
            if !(8..=63).contains(&p.len()) {
                return Err(Error::InvalidArgument);
            }
        }

        if config.address.octets()[3] != 1 {
            // The vendor's own CLI warns about this and then misbehaves; make
            // it an error instead of a mystery.
            return Err(Error::InvalidArgument);
        }

        let mut params: sys::wifi_mgmr_ap_params_t = unsafe { core::mem::zeroed() };
        params.ssid = ssid.as_mut_ptr();
        params.key = crate::cstr::opt_ptr(&key);
        params.akm = crate::cstr::opt_ptr(&akm);
        params.channel = config.channel;
        params.type_ = 0; // 20 MHz
        params.hidden_ssid = config.hidden;
        params.isolation = config.isolate;
        params.bcn_interval = config.beacon_interval_tu;
        params.ap_max_inactivity = config.max_inactivity_s;
        params.use_ipcfg = true;
        params.ap_ipaddr = config.address.as_raw();
        params.ap_mask = config.netmask.as_raw();
        params.use_dhcpd = config.dhcp_server;
        params.start = config.dhcp_start;
        params.limit = config.dhcp_limit;

        event::clear(&[Event::ApStarted, Event::ApStopped, Event::ParamsError]);

        let rc = unsafe { sys::wifi_mgmr_ap_start(&params) };
        if rc != 0 {
            return Err(Error::Vendor(rc));
        }

        match event::wait(
            &[Event::ApStarted, Event::ApStopped, Event::ParamsError],
            config.timeout_ms,
        ) {
            Some(Event::ApStarted) => Ok(()),
            Some(Event::ParamsError) => Err(Error::InvalidArgument),
            Some(_) => Err(Error::ConnectionFailed),
            None => Err(Error::Timeout),
        }
    }

    /// Stop the soft-AP.
    pub fn stop_ap(&self) -> Result<()> {
        event::clear(&[Event::ApStopped]);
        match unsafe { sys::wifi_mgmr_ap_stop() } {
            0 => {
                event::wait(&[Event::ApStopped], 5_000);
                Ok(())
            }
            rc => Err(Error::Vendor(rc)),
        }
    }

    /// The soft-AP MAC, wrapped for printing.
    pub fn ap_mac_addr(&self) -> MacAddr {
        MacAddr(self.ap_mac())
    }
}
