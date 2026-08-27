// SPDX-FileCopyrightText: 2026 Roman Valls Guimera <brainstorm@nopcode.org>
//
// SPDX-License-Identifier: GPL-3.0-or-later

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

//! WPA2 WiFi for the Bouffalo BL616, from Rust.
//!
//! The BL616 is a RV32IMAFCP (T-Head E907) part with an on-chip 802.11ax
//! radio. Bouffalo ships the MAC, PHY/RF and WiFi-manager layers only as
//! prebuilt archives, so this crate is a safe Rust surface over the vendor
//! stack rather than a from-scratch driver.
//!
//! # Shape of a program
//!
//! The vendor stack is FreeRTOS-shaped: `main` configures the board, the
//! radio and lwIP, then hands the CPU to the scheduler, and everything else
//! runs in tasks. [`main!`] wires that up for you and runs your entry point as
//! an ordinary task.
//!
//! ```no_run
//! # #![no_std]
//! # #![no_main]
//! use bl616_wifi::{main, println, StaConfig, Wifi};
//!
//! main!(app);
//!
//! fn app() -> ! {
//!     let wifi = Wifi::init().unwrap();
//!     let ip = wifi.connect(&StaConfig::wpa2("my-ssid", "my-passphrase")).unwrap();
//!     println!("got {ip}");
//!     loop {
//!         bl616_wifi::delay_ms(1000);
//!     }
//! }
//! ```
//!
//! # Modes
//!
//! * Station: [`Wifi::connect`] with a [`StaConfig`]. DHCP runs by default and
//!   the call returns once the lease is in, so what you get back is a usable
//!   [`Ipv4Config`].
//! * Access point: [`Wifi::start_ap`] with an [`ApConfig`]. The vendor stack
//!   carries its own DHCP server, enabled by default.
//!
//! Both are WPA2-PSK by default. WPA3-SAE and open networks are reachable
//! through [`Akm`].
//!
//! # Features
//!
//! Each replaces more of the C substrate: `rust-net` (lwIP and the vendor
//! adapter out, smoltcp in), `embassy-net` (the MAC as an
//! `embassy_net_driver::Driver`, for an application that brings its own
//! stack), `rust-crypto` (wpa_supplicant's hashes, HMAC and AES from
//! RustCrypto), `rust-rtos` (the `rtos_*` layer the blobs call), and
//! `usb-console`.
//!
//! # Threading
//!
//! Everything on `Wifi` blocks the calling task by polling an event latch;
//! none of it may be called from an interrupt or from an
//! [`event::set_handler`] callback, which runs with the scheduler suspended.
//!
//! Two consequences for an application built on [`embassy_rt`]:
//!
//! * **Do the vendor bring-up before starting the executor.** A call into the
//!   vendor stack from inside `executor.poll()` blocks with no timeout.
//! * **Size the task stack for what the application puts on it.** The default
//!   suits small locals; large socket buffers overrun it silently, and the
//!   radio fails some time later as the corruption spreads. See
//!   [`main!`] and [`runtime::start_with_stack`].

pub use bl616_wifi_sys as sys;

pub mod ap;
pub mod console;
pub mod cstr;
pub mod error;
pub mod event;
pub mod net;
pub mod flash;
pub mod rng;
pub mod runtime;
pub mod uart;
pub mod shell;
pub mod sta;

/// Rust implementation of the vendor stack's network interface, replacing
/// lwIP. See the module docs for what is done and what is not.
#[cfg(feature = "rust-net")]
// Linked for its C ABI exports alone: wpa_supplicant calls them, nothing in
// Rust does.
#[cfg(feature = "rust-crypto")]
use bl616_crypto as _;

/// The blobs' RTOS abstraction layer, replacing the vendor's rtos_al.c.
#[cfg(feature = "rust-rtos")]
pub mod rtos_al;

#[cfg(feature = "embassy-net")]
pub mod embassy_rt;
/// The vendor stack's network adapter, in Rust. Needs an IP stack behind it,
/// so it follows `rust-net-core`: the vendor adapter and lwIP have to be gone
/// before this can replace them. Which IP stack sits on top -- ours or the
/// application's -- is a separate choice.
#[cfg(feature = "rust-net-core")]
pub mod net_al;

#[cfg(feature = "alloc")]
mod heap;

#[cfg(feature = "panic-handler")]
mod panic;

pub use ap::ApConfig;
pub use error::{Error, Result};
pub use event::Event;
pub use net::Ipv4Config;
pub use runtime::delay_ms;
pub use sta::{Akm, Pmf, StaConfig};

use core::sync::atomic::{AtomicBool, Ordering};

/// Handle to the initialised WiFi subsystem.
///
/// Obtained once, from [`Wifi::init`], after the radio firmware has reported
/// itself ready. Holding it is the proof that the stack is up; every operation
/// hangs off it.
pub struct Wifi {
    _not_send: core::marker::PhantomData<*const ()>,
}

/// First boot runs RF calibration before the firmware reports in, so the
/// default deadline is deliberately loose.
pub const DEFAULT_INIT_TIMEOUT_MS: u32 = 20_000;

static INITIALISED: AtomicBool = AtomicBool::new(false);

impl Wifi {
    /// Wait for the radio firmware to finish booting and start the WiFi
    /// manager.
    ///
    /// [`runtime::start`] has already kicked off the firmware task by the time
    /// your app task runs, so this is a rendezvous rather than a launch: it
    /// blocks until the stack reports `INIT_DONE`, then until the manager
    /// reports `MGMR_DONE`.
    ///
    /// Returns [`Error::AlreadyInitialised`] once a handle exists, and
    /// [`Error::Timeout`] if the firmware never comes up — in practice that
    /// means RF calibration data is missing or the `rfparam` partition was
    /// never flashed. A timed-out call leaves nothing behind, so retrying is
    /// fine.
    pub fn init() -> Result<Self> {
        Self::init_with_timeout(DEFAULT_INIT_TIMEOUT_MS)
    }

    /// [`Wifi::init`] with a deadline of your choosing, in milliseconds.
    ///
    /// The default is generous because first boot includes RF calibration;
    /// shorten it if you would rather fail fast and retry.
    pub fn init_with_timeout(timeout_ms: u32) -> Result<Self> {
        if INITIALISED.load(Ordering::SeqCst) {
            return Err(Error::AlreadyInitialised);
        }

        // The radio task records this early on; wait for it rather than
        // racing it, but fail loudly the moment it reports a bad status
        // instead of waiting out the full timeout for a radio that was never
        // going to come up.
        let mut waited = 0;
        loop {
            match runtime::rf_status() {
                Some(0) => break,
                Some(rc) => return Err(Error::RfInit(rc)),
                None if waited >= timeout_ms => return Err(Error::Timeout),
                None => {
                    runtime::delay_ms(10);
                    waited += 10;
                }
            }
        }

        // Claim the handle only once the stack is actually up, so a timeout
        // can be retried rather than poisoning the process.
        event::wait(&[Event::InitDone], timeout_ms).ok_or(Error::Timeout)?;

        // `wifi_mgmr_task_start()` is called from the event callback itself,
        // exactly as every examples/wifi/* project does, so the manager task
        // comes up in the order the blob expects. All that is left here is to
        // wait for it to report in.
        if event::wait(&[Event::MgmrDone], timeout_ms).is_none() {
            // Not fatal on every SDK revision: some post MGMR_DONE only after
            // the first scan. The manager is running either way.
            println!("[wifi] warning: no MGMR_DONE within {timeout_ms}ms, continuing anyway");
        }

        if INITIALISED.swap(true, Ordering::SeqCst) {
            return Err(Error::AlreadyInitialised);
        }

        Ok(Wifi {
            _not_send: core::marker::PhantomData,
        })
    }

    /// Claim a handle without going through [`Wifi::init`].
    ///
    /// For code that drove the bring-up sequence itself — see
    /// `examples/bringup.rs` — and therefore cannot satisfy `init`, which
    /// waits on events the runtime normally arranges.
    ///
    /// # Safety
    ///
    /// The radio firmware must actually be up: `rfparam_init` returned 0,
    /// `wifi_task_create` and `fhost_init` have run, and the manager has
    /// reported `INIT_DONE`. Calling into a `Wifi` obtained this way before
    /// that holds hands an uninitialised blob a request, which does not fail
    /// politely.
    pub unsafe fn assume_initialised() -> Self {
        INITIALISED.store(true, Ordering::SeqCst);
        Wifi {
            _not_send: core::marker::PhantomData,
        }
    }

    /// MAC address of the station interface.
    pub fn sta_mac(&self) -> [u8; 6] {
        let mut mac = [0u8; 6];
        unsafe { sys::wifi_mgmr_sta_mac_get(mac.as_mut_ptr()) };
        mac
    }

    /// MAC address of the access-point interface.
    ///
    /// The two differ: the vendor stack derives the AP MAC from the STA one so
    /// that a device can run both at once.
    pub fn ap_mac(&self) -> [u8; 6] {
        let mut mac = [0u8; 6];
        unsafe { sys::wifi_mgmr_ap_mac_get(mac.as_mut_ptr()) };
        mac
    }

    /// Whether the station is currently associated.
    pub fn is_connected(&self) -> bool {
        unsafe { sys::wifi_mgmr_sta_state_get() == 1 }
    }

    /// Signal strength of the current association, in dBm.
    pub fn rssi(&self) -> Option<i32> {
        let mut rssi = 0;
        (unsafe { sys::wifi_mgmr_sta_rssi_get(&mut rssi) } == 0).then_some(rssi)
    }

    /// Channel the station is currently on.
    pub fn channel(&self) -> Option<u8> {
        let mut ch = 0u8;
        (unsafe { sys::wifi_mgmr_sta_channel_get(&mut ch) } == 0).then_some(ch)
    }

    /// Set the regulatory domain, e.g. `"US"`, `"EU"`, `"JP"`, `"CN"`.
    ///
    /// This decides which channels are usable and how much power may be put
    /// into them; the default is whatever the flashed RF parameters say.
    pub fn set_country(&self, code: &str) -> Result<()> {
        let code = cstr::CountryCode::new(code).ok_or(Error::InvalidArgument)?;
        match unsafe { sys::wifi_mgmr_set_country_code(code.as_mut_ptr()) } {
            0 => Ok(()),
            rc => Err(Error::Vendor(rc)),
        }
    }
}
