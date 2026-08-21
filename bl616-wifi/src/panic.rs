// SPDX-FileCopyrightText: 2026 Roman Valls Guimera <brainstorm@nopcode.org>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Panic handler: say what happened on the console, then stop.
//!
//! Halting rather than rebooting is deliberate. A BL616 that resets on panic
//! loses the message in the time it takes a terminal to reconnect, and a
//! bring-up board that sits still is much easier to reason about than one
//! stuck in a boot loop. Turn the `panic-handler` feature off and supply your
//! own if you want a watchdog reset instead.

use core::panic::PanicInfo;

#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    crate::println!();
    crate::println!("=== bl616-wifi panic ===");
    crate::println!("{info}");
    crate::println!("=== halted ===");

    loop {
        core::hint::spin_loop();
    }
}
