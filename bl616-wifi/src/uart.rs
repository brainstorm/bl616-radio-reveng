// SPDX-FileCopyrightText: 2026 Roman Valls Guimera <brainstorm@nopcode.org>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! UART0, for an application that wants the serial port rather than a console
//! on it.
//!
//! # Who owns UART0
//!
//! With the `usb-console` feature the SDK's console and `printf` go to USB-CDC
//! (`CONFIG_BSP_CONSOLE_USB_CDC`), which leaves UART0 free. Without it, UART0
//! *is* the console and taking it here will interleave with every `println!`
//! in the firmware — the port still works, the output is just shared.
//!
//! [`crate::shell::start`] also claims UART0 for the vendor CLI. Calling both
//! is a mistake: the shell's task and this will each consume half the bytes.
//!
//! # No interrupts
//!
//! Reads are polled rather than interrupt-driven. The FIFO is 32 bytes, so at
//! 115200 baud a caller has about 2.7 ms to drain it — comfortable against a
//! 1 kHz tick, and it avoids installing a handler into the SDK's vector
//! table. A faster line needs the interrupt.

use crate::error::{Error, Result};
use bl616_wifi_sys as sys;

/// Parity, as the vendor spells it.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Parity {
    #[default]
    None,
    Odd,
    Even,
}

/// Stop bits.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum StopBits {
    #[default]
    One,
    Two,
}

/// How to open the port.
#[derive(Clone, Copy, Debug)]
pub struct Config {
    pub baudrate: u32,
    pub parity: Parity,
    pub stop_bits: StopBits,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            baudrate: 115_200,
            parity: Parity::None,
            stop_bits: StopBits::One,
        }
    }
}

/// An open UART.
///
/// Dropping it deinitialises the peripheral, which is what hands UART0 back
/// to whatever had it.
pub struct Uart {
    dev: *mut sys::bflb_device_s,
}

// The handle is a device pointer the SDK owns; it is not tied to a thread.
unsafe impl Send for Uart {}

impl Uart {
    /// Open UART0.
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`] if the SDK has no `uart0` device, which means
    /// `board_init()` has not run.
    pub fn open(config: &Config) -> Result<Self> {
        // SAFETY: a NUL-terminated name, and the SDK returns null when it
        // does not know it.
        let dev = unsafe { sys::bflb_device_get_by_name(c"uart0".as_ptr()) };
        if dev.is_null() {
            return Err(Error::NotFound);
        }

        let cfg = sys::bflb_uart_config_s {
            baudrate: config.baudrate,
            direction: sys::UART_DIRECTION_TXRX,
            data_bits: sys::UART_DATA_BITS_8,
            stop_bits: match config.stop_bits {
                StopBits::One => sys::UART_STOP_BITS_1,
                StopBits::Two => sys::UART_STOP_BITS_2,
            },
            parity: match config.parity {
                Parity::None => sys::UART_PARITY_NONE,
                Parity::Odd => sys::UART_PARITY_ODD,
                Parity::Even => sys::UART_PARITY_EVEN,
            },
            // LSB first, as every ordinary serial port is.
            bit_order: 0,
            flow_ctrl: sys::UART_FLOWCTRL_NONE,
            // Interrupt thresholds, unused while reads are polled, but the
            // hardware still wants them set.
            tx_fifo_threshold: 7,
            rx_fifo_threshold: 7,
        };

        // SAFETY: `dev` came from the SDK and `cfg` is a valid config whose
        // layout is asserted against the vendor header at build time.
        unsafe { sys::bflb_uart_init(dev, &cfg) };
        Ok(Uart { dev })
    }

    /// Take whatever is already in the receive FIFO, up to `buf.len()`.
    ///
    /// Returns 0 rather than blocking when nothing has arrived.
    pub fn read(&mut self, buf: &mut [u8]) -> usize {
        let mut n = 0;
        while n < buf.len() {
            // SAFETY: `dev` is live for the lifetime of `self`.
            let c = unsafe { sys::bflb_uart_getchar(self.dev) };
            if c < 0 {
                break;
            }
            buf[n] = c as u8;
            n += 1;
        }
        n
    }

    /// Whether anything is waiting.
    pub fn can_read(&self) -> bool {
        unsafe { sys::bflb_uart_rxavailable(self.dev) }
    }

    /// Write every byte, blocking until they are all in the transmit FIFO.
    ///
    /// The blocking is bounded by the line rate and the FIFO depth, not by
    /// the receiver: nothing here waits for the other end.
    pub fn write(&mut self, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        // SAFETY: the vendor signature takes a non-const pointer but does not
        // write through it.
        unsafe {
            sys::bflb_uart_put_block(self.dev, data.as_ptr() as *mut u8, data.len() as u32);
        }
    }
}

impl Drop for Uart {
    fn drop(&mut self) {
        // SAFETY: `dev` is live and was initialised by `open`.
        unsafe { sys::bflb_uart_deinit(self.dev) };
    }
}
