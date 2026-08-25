// SPDX-FileCopyrightText: 2026 Roman Valls Guimera <brainstorm@nopcode.org>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Telling the application what happened to its address.
//!
//! Shared by both IP-stack front ends: whichever one is compiled in, the
//! application learns about addressing the same way the vendor's does, from
//! the async event system.

use core::ffi::c_int;

/// `CODE_WIFI_ON_GOT_IP`.
pub const CODE_WIFI_ON_GOT_IP: c_int = 7;
/// `CODE_WIFI_ON_LOST_IP`.
pub const CODE_WIFI_ON_LOST_IP: c_int = 26;
/// `CODE_WIFI_ON_GOT_IP_TIMEOUT`.
pub const CODE_WIFI_ON_GOT_IP_TIMEOUT: c_int = 28;

unsafe extern "C" {
    fn platform_post_event(catalogue: c_int, code: c_int, value: c_int) -> c_int;
}

fn post(code: c_int) {
    // EV_WIFI. The vendor's implementation ignores the catalogue argument and
    // posts to EV_WIFI regardless; pass it correctly anyway.
    unsafe { platform_post_event(2, code, 0) };
}

pub fn post_got_ip() {
    post(CODE_WIFI_ON_GOT_IP);
}

pub fn post_lost_ip() {
    post(CODE_WIFI_ON_LOST_IP);
}

pub fn post_dhcp_timeout() {
    post(CODE_WIFI_ON_GOT_IP_TIMEOUT);
}
