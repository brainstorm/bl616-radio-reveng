// SPDX-FileCopyrightText: 2026 Roman Valls Guimera <brainstorm@nopcode.org>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Board bring-up with the radio left alone: does this image boot at all?
//!
//! Everything the WiFi examples rely on except the radio — the linker script,
//! the C substrate, `main` coming from Rust, FreeRTOS, the console, the
//! allocator — and nothing else. If a board runs this but not `ap`/`sta`, the
//! fault is in the radio path; if it does not run this either, the fault is
//! further down, in the image or the link.
//!
//! Without a serial console there is still a signal: a BL616 that is running
//! firmware does not answer as `349b:6160 Bouffalo CDC DEMO`. If the board
//! disappears from USB and stays gone, this booted.
//!
//! ```sh
//! cargo xtask flash --example hello                     # console on UART0
//! cargo xtask flash --example hello --features usb-console
//! ```

#![no_std]
#![no_main]

use bl616_wifi::{delay_ms, println, runtime};

#[no_mangle]
pub extern "C" fn main() -> core::ffi::c_int {
    runtime::start_without_radio(app)
}

fn app() -> ! {
    bl616_wifi::shell::start();

    println!("[hello] board is up, scheduler running");
    println!("[hello] heap free {} bytes", runtime::free_heap());

    let mut tick = 0u32;
    loop {
        println!(
            "[hello] tick {tick}  uptime {}s  heap {}B",
            runtime::uptime_ms() / 1000,
            runtime::free_heap()
        );
        tick += 1;
        delay_ms(1000);
    }
}
