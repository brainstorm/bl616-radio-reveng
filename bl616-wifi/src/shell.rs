// SPDX-FileCopyrightText: 2026 Roman Valls Guimera <brainstorm@nopcode.org>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! The vendor CLI, on the console UART.
//!
//! BouffaloSDK links a shell with the whole `wifi_*` command set —
//! `wifi_scan`, `wifi_sta_connect`, `wifi_ap_start`, `wifi_sta_info`,
//! `wifi_state`. During bring-up that is worth having: it separates "the Rust
//! layer is wrong" from "the radio is wrong" in one command.
//!
//! It runs in its own task and shares the console with [`crate::println!`],
//! so output from both interleaves.

#[cfg(not(feature = "usb-console"))]
use bl616_wifi_sys as sys;

/// Start the shell task on the board console.
///
/// Returns `false` if the console device could not be found, which means
/// `board_init()` has not run yet.
///
/// With the `usb-console` feature this is a no-op that reports success:
/// `usb_console_init()` already called `shell_init_with_task(NULL)` during
/// `board_init()`, and starting a second shell would fight it for input.
pub fn start() -> bool {
    #[cfg(feature = "usb-console")]
    {
        true
    }

    #[cfg(not(feature = "usb-console"))]
    unsafe {
        let uart = sys::bflb_device_get_by_name(c"uart0".as_ptr());
        if uart.is_null() {
            return false;
        }
        sys::shell_init_with_task(uart);
        true
    }
}
