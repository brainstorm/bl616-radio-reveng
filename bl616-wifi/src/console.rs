// SPDX-FileCopyrightText: 2026 Roman Valls Guimera <brainstorm@nopcode.org>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Console output over the board console.
//!
//! `board_init()` has already configured the console by the time your code
//! runs — UART0 on GPIO 21/22 at 2 Mbaud, or USB-CDC with the `usb-console`
//! feature — and pointed the SDK's `printf` at it. This module just puts a
//! Rust `core::fmt` face on that.
//!
//! The SDK translates newlines to CRLF on the way out, so a dumb terminal
//! sees what it expects.
//!
//! One consequence of the USB-CDC console: writes made before the host
//! enumerates the device are dropped rather than buffered, so the boot banner
//! is usually gone by the time you attach a terminal. Everything printed
//! after that arrives normally.

use core::fmt::{self, Write};

use bl616_wifi_sys as sys;

/// Handle implementing [`core::fmt::Write`] over the SDK console.
pub struct Console;

/// Largest chunk handed to `printf` at once. Stack-allocated, so keep it
/// modest — [`Console`] splits longer writes.
const CHUNK: usize = 128;

impl Write for Console {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        // `printf("%s")` needs NUL termination and the SDK's lightweight
        // vsnprintf makes no promises about `%.*s`, so copy through a bounded
        // stack buffer. `bflb_console_write` does the CRLF translation
        // downstream; doing it here as well would only fight it.
        let mut buf = [0u8; CHUNK + 1];

        for chunk in s.as_bytes().chunks(CHUNK) {
            buf[..chunk.len()].copy_from_slice(chunk);
            buf[chunk.len()] = 0;
            unsafe { sys::printf(c"%s".as_ptr(), buf.as_ptr()) };
        }
        Ok(())
    }
}

/// Write to the console. Same shape as `core::write!`'s target.
#[doc(hidden)]
pub fn _print(args: fmt::Arguments<'_>) {
    let _ = Console.write_fmt(args);
}

/// Print to the board console.
#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => { $crate::console::_print(::core::format_args!($($arg)*)) };
}

/// Print to the board console, with a newline.
#[macro_export]
macro_rules! println {
    () => { $crate::print!("\n") };
    ($($arg:tt)*) => {{
        $crate::console::_print(::core::format_args!($($arg)*));
        $crate::print!("\n");
    }};
}
