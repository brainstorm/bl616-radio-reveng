// SPDX-FileCopyrightText: 2026 Roman Valls Guimera <brainstorm@nopcode.org>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Raw, unsafe FFI to the BL616 WiFi 6 stack and the BouffaloSDK C substrate
//! it runs on.
//!
//! Nothing here is safe or ergonomic on purpose — that is [`bl616-wifi`]'s
//! job. The bindings are generated at build time by `bindgen` from the SDK's
//! own headers, using the exact preprocessor configuration CMake compiled the
//! C side with, so they track whichever SDK revision you point `BL_SDK_BASE`
//! at instead of being a hand-transcribed snapshot.
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
//! `libbl616_phyrf.a` (PHY/RF). See the engineering notes for the licensing consequences.
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

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

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
