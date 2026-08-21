// SPDX-FileCopyrightText: 2026 Roman Valls Guimera <brainstorm@nopcode.org>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Station mode: joining someone else's network.

use bl616_wifi_sys as sys;

use crate::cstr::{AkmStr, BssidStr, Passphrase, Ssid};
use crate::error::{Error, Result};
use crate::event::{self, Event};
use crate::net::{Ipv4Config, MacAddr};
use crate::{println, Wifi};

/// Authentication and key management to insist on.
///
/// [`Akm::Auto`] is the right answer almost always: it lets the supplicant
/// pick from what the AP advertises in its RSN element. Name one explicitly
/// only to *refuse* the alternatives — for instance to make sure a network
/// that offers both WPA2 and WPA3 is joined with WPA3.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Akm {
    /// Negotiate from the AP's advertised RSN element.
    #[default]
    Auto,
    /// No encryption.
    Open,
    /// WPA2-PSK (RSN, CCMP).
    Wpa2,
    /// WPA3-SAE.
    Wpa3,
    /// Accept either, preferring WPA3.
    Wpa2Wpa3,
}

impl Akm {
    /// The vendor's AKM string. `None` means "let the supplicant decide".
    ///
    /// `fhost_ipc_read_akm` parses a comma-separated, uppercase list.
    pub(crate) const fn as_vendor_str(self) -> Option<&'static str> {
        match self {
            Akm::Auto => None,
            Akm::Open => Some("OPEN"),
            Akm::Wpa2 => Some("WPA2"),
            Akm::Wpa3 => Some("WPA3"),
            Akm::Wpa2Wpa3 => Some("WPA2,WPA3"),
        }
    }
}

/// Protected Management Frames (802.11w).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[repr(u8)]
pub enum Pmf {
    /// Do not use PMF.
    Disabled = 0,
    /// Use it if the AP offers it. Required by WPA3.
    #[default]
    Capable = 1,
    /// Refuse to associate with an AP that will not do PMF.
    Required = 2,
}

/// How to join a network.
///
/// Build one with [`StaConfig::wpa2`] or [`StaConfig::open`] and adjust from
/// there.
#[derive(Clone, Copy, Debug)]
pub struct StaConfig<'a> {
    /// Network name, at most 32 bytes.
    pub ssid: &'a str,
    /// Passphrase, 8..=63 characters. `None` for an open network.
    pub passphrase: Option<&'a str>,
    /// Pin the association to one AP, as `"aa:bb:cc:dd:ee:ff"`. Useful in a
    /// roaming environment where you mean one specific radio.
    pub bssid: Option<&'a str>,
    /// Which AKM to accept.
    pub akm: Akm,
    /// Protected management frames.
    pub pmf: Pmf,
    /// Restrict the join scan to these two frequencies (MHz). Zero scans all
    /// channels; naming the frequency makes reconnects much faster.
    pub freq: (u16, u16),
    /// Run a DHCP client once associated. Turn it off to use
    /// [`Wifi::set_static_ip`] instead.
    pub dhcp: bool,
    /// How long to wait for association *and* addressing, in milliseconds.
    pub timeout_ms: u32,
}

impl<'a> StaConfig<'a> {
    /// A WPA2-PSK network.
    pub const fn wpa2(ssid: &'a str, passphrase: &'a str) -> Self {
        StaConfig {
            ssid,
            passphrase: Some(passphrase),
            bssid: None,
            akm: Akm::Auto,
            pmf: Pmf::Capable,
            freq: (0, 0),
            dhcp: true,
            timeout_ms: 30_000,
        }
    }

    /// An open network.
    pub const fn open(ssid: &'a str) -> Self {
        StaConfig {
            ssid,
            passphrase: None,
            bssid: None,
            akm: Akm::Open,
            pmf: Pmf::Disabled,
            freq: (0, 0),
            dhcp: true,
            timeout_ms: 30_000,
        }
    }

    /// Insist on a particular AKM.
    pub const fn with_akm(mut self, akm: Akm) -> Self {
        self.akm = akm;
        self
    }

    /// Pin to one BSSID.
    pub const fn with_bssid(mut self, bssid: &'a str) -> Self {
        self.bssid = Some(bssid);
        self
    }

    /// Restrict the join scan to one channel frequency, in MHz (2412 for
    /// channel 1, 2437 for 6, 2462 for 11).
    pub const fn on_freq(mut self, mhz: u16) -> Self {
        self.freq = (mhz, 0);
        self
    }

    /// Skip DHCP; the caller will set a static address.
    pub const fn without_dhcp(mut self) -> Self {
        self.dhcp = false;
        self
    }

    /// Change the association timeout.
    pub const fn with_timeout_ms(mut self, ms: u32) -> Self {
        self.timeout_ms = ms;
        self
    }
}

impl Wifi {
    /// Associate with an access point, and — unless [`StaConfig::dhcp`] is
    /// off — wait for a DHCP lease.
    ///
    /// Blocks for up to [`StaConfig::timeout_ms`]. On success the returned
    /// [`Ipv4Config`] is live and the stack is usable for sockets.
    ///
    /// A wrong passphrase shows up as [`Error::ConnectionFailed`]: the AP
    /// completes association and then drops us during the 4-way handshake,
    /// which the vendor stack reports as a disconnect.
    pub fn connect(&self, config: &StaConfig<'_>) -> Result<Ipv4Config> {
        let ssid = Ssid::new(config.ssid).ok_or(Error::InvalidArgument)?;
        let key = Passphrase::maybe(config.passphrase)?;
        let bssid = BssidStr::maybe(config.bssid)?;
        let akm = AkmStr::maybe(config.akm.as_vendor_str())?;

        if let Some(p) = config.passphrase {
            // The supplicant silently refuses anything outside this range;
            // catching it here makes the failure legible.
            if !(8..=63).contains(&p.len()) {
                return Err(Error::InvalidArgument);
            }
        }

        event::clear(&[
            Event::Connected,
            Event::Disconnected,
            Event::GotIp,
            Event::GotIpTimeout,
            Event::ParamsError,
        ]);

        let rc = unsafe {
            sys::wifi_sta_connect(
                ssid.as_ptr(),
                crate::cstr::opt_ptr(&key),
                crate::cstr::opt_ptr(&bssid),
                crate::cstr::opt_ptr(&akm),
                config.pmf as u8,
                config.freq.0,
                config.freq.1,
                config.dhcp as u8,
            )
        };
        if rc != 0 {
            return Err(Error::Vendor(rc));
        }

        // Association first. A `Disconnected` here is the passphrase being
        // wrong far more often than it is anything else.
        match event::wait(
            &[Event::Connected, Event::Disconnected, Event::ParamsError],
            config.timeout_ms,
        ) {
            Some(Event::Connected) => {}
            Some(Event::ParamsError) => return Err(Error::InvalidArgument),
            Some(_) => return Err(Error::ConnectionFailed),
            None => return Err(Error::Timeout),
        }

        if !config.dhcp {
            return Ok(Ipv4Config::current_sta().unwrap_or_default());
        }

        match event::wait(
            &[Event::GotIp, Event::GotIpTimeout, Event::Disconnected],
            config.timeout_ms,
        ) {
            Some(Event::GotIp) => Ipv4Config::current_sta().ok_or(Error::DhcpTimeout),
            Some(Event::GotIpTimeout) => Err(Error::DhcpTimeout),
            Some(_) => Err(Error::ConnectionFailed),
            None => Err(Error::Timeout),
        }
    }

    /// Leave the current network.
    pub fn disconnect(&self) -> Result<()> {
        event::clear(&[Event::Disconnected]);
        match unsafe { sys::wifi_sta_disconnect() } {
            0 => {
                event::wait(&[Event::Disconnected], 5_000);
                Ok(())
            }
            rc => Err(Error::Vendor(rc)),
        }
    }

    /// Configure a static address instead of using DHCP. All values are in
    /// lwIP order; build them with [`crate::net::Ipv4::new`].
    pub fn set_static_ip(&self, cfg: &Ipv4Config) -> Result<()> {
        match unsafe {
            sys::wifi_mgmr_sta_ip_set(
                cfg.address.as_raw(),
                cfg.netmask.as_raw(),
                cfg.gateway.as_raw(),
                cfg.dns.as_raw(),
            )
        } {
            0 => Ok(()),
            rc => Err(Error::Vendor(rc)),
        }
    }

    /// Keep trying to reassociate after a disconnect.
    pub fn set_autoreconnect(&self, enable: bool) -> Result<()> {
        let rc = unsafe {
            if enable {
                sys::wifi_mgmr_sta_autoconnect_enable()
            } else {
                sys::wifi_mgmr_sta_autoconnect_disable()
            }
        };
        match rc {
            0 => Ok(()),
            rc => Err(Error::Vendor(rc)),
        }
    }

    /// Scan every channel and print what is out there.
    ///
    /// A scan is the cheapest proof that the PHY is actually working, which
    /// makes it the first thing worth running on new hardware. Blocks until
    /// the results arrive or `timeout_ms` elapses.
    pub fn scan_and_print(&self, timeout_ms: u32) -> Result<u32> {
        // All-zero means "every channel, active scan, no SSID filter".
        let params: sys::wifi_mgmr_scan_params_t = unsafe { core::mem::zeroed() };

        event::clear(&[Event::ScanDone]);
        let rc = unsafe { sys::wifi_mgmr_sta_scan(&params) };
        if rc != 0 {
            return Err(Error::Vendor(rc));
        }

        if event::wait(&[Event::ScanDone], timeout_ms).is_none() {
            return Err(Error::Timeout);
        }

        let count = unsafe { sys::wifi_mgmr_sta_scanlist_nums_get() };
        println!("[wifi] {count} networks:");
        unsafe { sys::wifi_mgmr_sta_scanlist() };
        Ok(count)
    }

    /// The station MAC, wrapped for printing.
    pub fn sta_mac_addr(&self) -> MacAddr {
        MacAddr(self.sta_mac())
    }
}
