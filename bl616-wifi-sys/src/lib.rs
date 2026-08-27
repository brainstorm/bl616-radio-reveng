// SPDX-FileCopyrightText: 2026 Roman Valls Guimera <brainstorm@nopcode.org>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Raw, unsafe FFI to the BL616 WiFi 6 stack and the BouffaloSDK C substrate
//! it runs on.
//!
//! Nothing here is safe or ergonomic on purpose — that is [`bl616-wifi`]'s
//! job.
//!
//! The boundary is written out by hand in [`ffi`]: 57 declarations, which is
//! what the Rust side actually uses, against the 2781 lines bindgen produced
//! from the same headers. That boundary is the thing every remaining stage of
//! the pure-Rust roadmap has to reason about, so it is worth being able to
//! read and diff it — and dropping bindgen takes `libclang` off the list of
//! things a build needs.
//!
//! Hand-written FFI rots quietly, so the C compiler is kept as the oracle:
//! `build.rs` measures every size and offset `ffi` depends on directly from
//! the vendor headers, and `ffi` asserts its own layout against those numbers
//! at compile time. An SDK that moves a field fails the build and names it.
//!
//! The generated bindings are still available behind the `bindgen` feature,
//! which is how the hand-written set was cross-checked in the first place.
//!
//! # What is actually being linked
//!
//! Open source (Apache-2.0, built from `$BL_SDK_BASE`):
//! FreeRTOS, lwIP, mbedTLS, wpa_supplicant, the LHAL peripheral drivers, the
//! `macsw_os_adapter` / `wifi6_lwip_adapter` glue and `rfparam`.
//!
//! Proprietary, redistributed as prebuilt archives inside BouffaloSDK:
//! `libfhost_bl616_default.a` (WiFi manager + fully-hosted control path),
//! `libmacsw_bl616.a` (802.11 MAC), `libwl80211_bl616.a`, and
//! `libbl616_phyrf.a` (PHY/RF). See the README for the licensing consequences.
//!
//! [`bl616-wifi`]: https://docs.rs/bl616-wifi

#![no_std]
#![allow(
    non_upper_case_globals,
    non_camel_case_types,
    non_snake_case,
    clippy::missing_safety_doc,
    clippy::useless_transmute,
    rustdoc::broken_intra_doc_links
)]

#[cfg(feature = "bindgen")]
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

#[cfg(not(feature = "bindgen"))]
mod ffi;
#[cfg(not(feature = "bindgen"))]
pub use ffi::*;

/// FreeRTOS tick rate, in Hz.
///
/// `configTICK_RATE_HZ` is spelled `((TickType_t)1000)` in FreeRTOSConfig.h,
/// which bindgen will not fold into a constant, so `build.rs` parses the
/// header and passes the value through the environment.
pub const TICK_RATE_HZ: u32 = parse_u32(env!("BL616_TICK_RATE_HZ"));

const fn parse_u32(s: &str) -> u32 {
    let bytes = s.as_bytes();
    let mut value = 0u32;
    let mut i = 0;
    while i < bytes.len() {
        assert!(bytes[i].is_ascii_digit());
        value = value * 10 + (bytes[i] - b'0') as u32;
        i += 1;
    }
    value
}
