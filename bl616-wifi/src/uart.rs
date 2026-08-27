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
//! # Interrupt-driven
//!
//! A handler moves bytes between the FIFOs and a ring in each direction, so
//! nothing here spins on the peripheral. Receive is unmasked for the whole
//! life of the port; transmit is unmasked only while there is something left
//! to send, because the FIFO interrupts are level-triggered on the FIFO count
//! and have no acknowledge bit — a handler with an empty ring that did not
//! mask would be re-entered forever.
//!
//! Two conditions deliver received bytes. The FIFO interrupt fires once the
//! receive FIFO passes its threshold, which is what a busy line hits; the
//! receive-timeout interrupt fires when the line goes idle with fewer bytes
//! than that still waiting, which is what delivers the last few bytes of a
//! burst, and a single keystroke.
//!
//! # Which pins
//!
//! [`Config::rx_pin`] and [`Config::tx_pin`] route GPIOs to UART0 on open.
//! Leaving them `None` keeps whatever `board_init()` muxed — which, in a
//! `usb-console` build, is nothing: the SDK only muxes UART0 as part of
//! setting it up as the console, so a build with the console on USB has to
//! name its own pins or the port is wired to nowhere.

use core::cell::UnsafeCell;
use core::ffi::{c_int, c_void};
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

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

/// Data bits per frame.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum DataBits {
    Five,
    Six,
    Seven,
    #[default]
    Eight,
}

/// How to open the port.
///
/// The baud rate is a divisor of the UART peripheral clock — 40 MHz, the
/// crystal, as `board_init()` leaves it — so the expressible range is about
/// 610 baud to that clock. Nothing here clamps: a rate outside it is the
/// caller's to reject or round, and only zero is refused outright.
#[derive(Clone, Copy, Debug)]
pub struct Config {
    pub baudrate: u32,
    pub parity: Parity,
    pub stop_bits: StopBits,
    pub data_bits: DataBits,
    /// GPIO to route UART0's receive line to, or `None` to leave the pin
    /// muxing alone.
    pub rx_pin: Option<u8>,
    /// GPIO to route UART0's transmit line to, or `None` to leave the pin
    /// muxing alone.
    pub tx_pin: Option<u8>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            baudrate: 115_200,
            parity: Parity::None,
            stop_bits: StopBits::One,
            data_bits: DataBits::Eight,
            rx_pin: None,
            tx_pin: None,
        }
    }
}

/// Bytes held between the handler and the caller in each direction. Sized to
/// cover a scheduling delay rather than a session: at 115200 baud a full
/// receive ring is 44 ms of line time.
const RX_RING: usize = 512;
const TX_RING: usize = 512;

/// Receive FIFO fill that raises the FIFO interrupt. The FIFO is 32 bytes, so
/// this leaves three quarters of it as headroom for interrupt latency.
const RX_FIFO_THRESHOLD: u8 = 7;
/// Transmit FIFO fill below which the handler is asked for more.
const TX_FIFO_THRESHOLD: u8 = 7;
/// Idle line, in bit periods, that raises the receive-timeout interrupt.
/// Rather more than a character time, so it fires between bursts and not
/// inside one.
const RX_TIMEOUT_BITS: usize = 15;

/// Interrupts off for the duration.
///
/// The SDK's own primitive rather than `critical_section`, so the handler and
/// the rings work in every build of this crate and not only the ones that
/// bring an executor along.
struct IrqGuard(usize);

impl IrqGuard {
    fn new() -> Self {
        // SAFETY: saves and clears the interrupt-enable bit, nothing more.
        IrqGuard(unsafe { sys::bflb_irq_save() })
    }
}

impl Drop for IrqGuard {
    fn drop(&mut self) {
        // SAFETY: restores exactly what the matching save returned.
        unsafe { sys::bflb_irq_restore(self.0) };
    }
}

/// A byte queue with the interrupt handler at one end.
///
/// Every method takes the guard as a token: one end of each ring is an
/// interrupt handler, so no access is safe without interrupts off, and asking
/// for the proof at the call site is cheaper than an atomic protocol that
/// would still need the guard for the mask decisions.
struct Ring<const N: usize> {
    buf: UnsafeCell<[u8; N]>,
    /// Where the next byte is written.
    head: AtomicUsize,
    /// Where the next byte is read.
    tail: AtomicUsize,
    /// Bytes stored, which is what tells a full ring from an empty one.
    len: AtomicUsize,
}

impl<const N: usize> Ring<N> {
    const fn new() -> Self {
        Ring {
            buf: UnsafeCell::new([0; N]),
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
            len: AtomicUsize::new(0),
        }
    }

    fn len(&self, _irq: &IrqGuard) -> usize {
        self.len.load(Ordering::Relaxed)
    }

    fn push(&self, irq: &IrqGuard, data: &[u8]) -> usize {
        let mut n = 0;
        while n < data.len() && self.push_byte(irq, data[n]) {
            n += 1;
        }
        n
    }

    fn push_byte(&self, _irq: &IrqGuard, byte: u8) -> bool {
        let len = self.len.load(Ordering::Relaxed);
        if len == N {
            return false;
        }
        let head = self.head.load(Ordering::Relaxed);
        // SAFETY: interrupts are off, so this is the only live reference to
        // the buffer, and `head` is always in bounds.
        unsafe { (*self.buf.get())[head] = byte };
        self.head.store((head + 1) % N, Ordering::Relaxed);
        self.len.store(len + 1, Ordering::Relaxed);
        true
    }

    fn pop(&self, irq: &IrqGuard, out: &mut [u8]) -> usize {
        let mut n = 0;
        while n < out.len() {
            match self.pop_byte(irq) {
                Some(b) => {
                    out[n] = b;
                    n += 1;
                }
                None => break,
            }
        }
        n
    }

    fn pop_byte(&self, _irq: &IrqGuard) -> Option<u8> {
        let len = self.len.load(Ordering::Relaxed);
        if len == 0 {
            return None;
        }
        let tail = self.tail.load(Ordering::Relaxed);
        // SAFETY: as `push_byte`, and `tail` is in bounds while `len > 0`.
        let byte = unsafe { (*self.buf.get())[tail] };
        self.tail.store((tail + 1) % N, Ordering::Relaxed);
        self.len.store(len - 1, Ordering::Relaxed);
        Some(byte)
    }

    fn clear(&self, _irq: &IrqGuard) {
        self.head.store(0, Ordering::Relaxed);
        self.tail.store(0, Ordering::Relaxed);
        self.len.store(0, Ordering::Relaxed);
    }
}

/// What the handler and the caller share. One UART0, so one of these.
struct State {
    rx: Ring<RX_RING>,
    tx: Ring<TX_RING>,
    /// Bytes the handler took off the wire and had nowhere to put.
    overruns: AtomicUsize,
    #[cfg(feature = "embassy-net")]
    rx_waker: embassy_sync::waitqueue::AtomicWaker,
    #[cfg(feature = "embassy-net")]
    tx_waker: embassy_sync::waitqueue::AtomicWaker,
}

// SAFETY: the buffers are only ever touched with interrupts off, which on a
// single hart is what makes the handler and the caller mutually exclusive.
unsafe impl Sync for State {}

static STATE: State = State {
    rx: Ring::new(),
    tx: Ring::new(),
    overruns: AtomicUsize::new(0),
    #[cfg(feature = "embassy-net")]
    rx_waker: embassy_sync::waitqueue::AtomicWaker::new(),
    #[cfg(feature = "embassy-net")]
    tx_waker: embassy_sync::waitqueue::AtomicWaker::new(),
};

/// Whether a [`Uart`] is live, since [`STATE`] can only serve one.
static OPEN: AtomicBool = AtomicBool::new(false);

/// Move bytes between the FIFOs and the rings.
///
/// `arg` is the device handle, passed at attach time so the handler does not
/// have to look it up on every interrupt.
unsafe extern "C" fn on_interrupt(_irq: c_int, arg: *mut c_void) {
    let dev = arg.cast::<sys::bflb_device_s>();
    let irq = IrqGuard::new();
    // SAFETY: `dev` is the handle passed to `bflb_irq_attach`, which lives as
    // long as the SDK does.
    let status = unsafe { sys::bflb_uart_get_intstatus(dev) };

    if status & (sys::UART_INTSTS_RX_FIFO | sys::UART_INTSTS_RTO) != 0 {
        // Drain regardless of which of the two fired: the FIFO bit clears by
        // emptying the FIFO, so a byte left behind re-enters the handler for
        // as long as it sits there.
        loop {
            // SAFETY: as above; returns -1 once the FIFO is empty.
            let c = unsafe { sys::bflb_uart_getchar(dev) };
            let Ok(byte) = u8::try_from(c) else { break };
            if !STATE.rx.push_byte(&irq, byte) {
                STATE.overruns.fetch_add(1, Ordering::Relaxed);
            }
        }
        if status & sys::UART_INTSTS_RTO != 0 {
            // The timeout is the one receive condition with a latch to clear.
            // SAFETY: as above.
            unsafe { sys::bflb_uart_int_clear(dev, sys::UART_INTCLR_RTO) };
        }
        #[cfg(feature = "embassy-net")]
        STATE.rx_waker.wake();
    }

    if status & sys::UART_INTSTS_TX_FIFO != 0 {
        // SAFETY: as above.
        while unsafe { sys::bflb_uart_txready(dev) } {
            let Some(byte) = STATE.tx.pop_byte(&irq) else {
                // Nothing left, and no way to acknowledge a condition that is
                // just "the FIFO has room". Mask until there is more to send.
                // SAFETY: as above.
                unsafe { sys::bflb_uart_txint_mask(dev, true) };
                break;
            };
            // SAFETY: as above.
            unsafe { sys::bflb_uart_putchar(dev, c_int::from(byte)) };
        }
        #[cfg(feature = "embassy-net")]
        STATE.tx_waker.wake();
    }
}

/// An open UART.
///
/// Dropping it detaches the handler and deinitialises the peripheral, which
/// is what hands UART0 back to whatever had it.
pub struct Uart {
    dev: *mut sys::bflb_device_s,
}

// The handle is a device pointer the SDK owns; it is not tied to a thread.
unsafe impl Send for Uart {}

impl Uart {
    /// Open UART0, route its pins and start the interrupt handler.
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`] if the SDK has no `uart0` device, which means
    /// `board_init()` has not run; [`Error::AlreadyInitialised`] if a `Uart`
    /// is already open, since there is one set of rings;
    /// [`Error::InvalidArgument`] for a zero baud rate, which the vendor
    /// divides by.
    pub fn open(config: &Config) -> Result<Self> {
        if OPEN.swap(true, Ordering::AcqRel) {
            return Err(Error::AlreadyInitialised);
        }
        match Self::start(config) {
            Ok(uart) => Ok(uart),
            Err(e) => {
                OPEN.store(false, Ordering::Release);
                Err(e)
            }
        }
    }

    /// The body of [`Uart::open`], so the caller's claim on [`STATE`] is
    /// released on every failure path rather than at each `return`.
    fn start(config: &Config) -> Result<Self> {
        // SAFETY: a NUL-terminated name, and the SDK returns null when it
        // does not know it.
        let dev = unsafe { sys::bflb_device_get_by_name(c"uart0".as_ptr()) };
        if dev.is_null() {
            return Err(Error::NotFound);
        }
        if config.baudrate == 0 {
            return Err(Error::InvalidArgument);
        }

        route_pins(config)?;

        let cfg = sys::bflb_uart_config_s {
            baudrate: config.baudrate,
            direction: sys::UART_DIRECTION_TXRX,
            data_bits: match config.data_bits {
                DataBits::Five => sys::UART_DATA_BITS_5,
                DataBits::Six => sys::UART_DATA_BITS_6,
                DataBits::Seven => sys::UART_DATA_BITS_7,
                DataBits::Eight => sys::UART_DATA_BITS_8,
            },
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
            tx_fifo_threshold: TX_FIFO_THRESHOLD,
            rx_fifo_threshold: RX_FIFO_THRESHOLD,
        };

        // SAFETY: `dev` came from the SDK and `cfg` is a valid config whose
        // layout is asserted against the vendor header at build time.
        unsafe { sys::bflb_uart_init(dev, &cfg) };

        {
            let irq = IrqGuard::new();
            STATE.rx.clear(&irq);
            STATE.tx.clear(&irq);
            STATE.overruns.store(0, Ordering::Relaxed);
        }

        // SAFETY: `dev` is live, and the handler only touches it and `STATE`.
        unsafe {
            sys::bflb_uart_feature_control(dev, sys::UART_CMD_SET_RTO_VALUE, RX_TIMEOUT_BITS);
            // Transmit stays masked: there is nothing to send yet, and the
            // condition is level-triggered.
            sys::bflb_uart_txint_mask(dev, true);
            sys::bflb_uart_rxint_mask(dev, false);
            sys::bflb_irq_attach(irq_num(dev), Some(on_interrupt), dev.cast());
            sys::bflb_irq_enable(irq_num(dev));
        }

        Ok(Uart { dev })
    }

    /// Take what the handler has received, up to `buf.len()`.
    ///
    /// Returns 0 rather than blocking when nothing has arrived.
    pub fn try_read(&mut self, buf: &mut [u8]) -> usize {
        let irq = IrqGuard::new();
        STATE.rx.pop(&irq, buf)
    }

    /// Queue what fits and return how much that was.
    ///
    /// Bytes leave through the interrupt handler, so this does not wait for
    /// the line — only for room in the ring, which it never does either.
    pub fn try_write(&mut self, data: &[u8]) -> usize {
        let irq = IrqGuard::new();
        let n = STATE.tx.push(&irq, data);
        if n > 0 {
            // Unmasking under the same guard is what keeps this from racing
            // the handler's decision to mask on an empty ring.
            // SAFETY: `dev` is live for the lifetime of `self`.
            unsafe { sys::bflb_uart_txint_mask(self.dev, false) };
        }
        n
    }

    /// Whether anything has been received and not yet read.
    pub fn can_read(&self) -> bool {
        let irq = IrqGuard::new();
        STATE.rx.len(&irq) > 0
    }

    /// Bytes the handler had to drop because the receive ring was full, and
    /// clear the count.
    ///
    /// Non-zero means the reader is not keeping up with the line; the bytes
    /// are gone, and nothing else reports them.
    pub fn overruns(&self) -> usize {
        STATE.overruns.swap(0, Ordering::Relaxed)
    }
}

/// Receive at least one byte.
///
/// Only with an executor to be woken from the handler: the wakers are part of
/// the embassy front end, and without it [`Uart::try_read`] and
/// [`Uart::try_write`] are the whole interface.
#[cfg(feature = "embassy-net")]
impl Uart {
    /// Wait for bytes and take up to `buf.len()` of them.
    ///
    /// Resolves as soon as anything has arrived, so a caller gets a keystroke
    /// without waiting for a full buffer.
    pub async fn read(&mut self, buf: &mut [u8]) -> usize {
        core::future::poll_fn(|cx| {
            // Register first, then look: the handler may run between the two,
            // and this way it cannot deliver into a gap where nobody is
            // registered and nothing has been seen.
            STATE.rx_waker.register(cx.waker());
            let n = self.try_read(buf);
            if n > 0 {
                core::task::Poll::Ready(n)
            } else {
                core::task::Poll::Pending
            }
        })
        .await
    }

    /// Queue every byte, waiting for ring space as the handler drains it.
    pub async fn write(&mut self, data: &[u8]) {
        let mut rest = data;
        while !rest.is_empty() {
            let n = core::future::poll_fn(|cx| {
                STATE.tx_waker.register(cx.waker());
                let n = self.try_write(rest);
                if n > 0 {
                    core::task::Poll::Ready(n)
                } else {
                    core::task::Poll::Pending
                }
            })
            .await;
            rest = &rest[n..];
        }
    }
}

impl Drop for Uart {
    fn drop(&mut self) {
        // SAFETY: `dev` is live and was initialised by `open`.
        unsafe {
            sys::bflb_uart_rxint_mask(self.dev, true);
            sys::bflb_uart_txint_mask(self.dev, true);
            sys::bflb_irq_disable(irq_num(self.dev));
            sys::bflb_irq_detach(irq_num(self.dev));
            sys::bflb_uart_deinit(self.dev);
        }
        OPEN.store(false, Ordering::Release);
    }
}

/// The device's interrupt number.
fn irq_num(dev: *mut sys::bflb_device_s) -> c_int {
    // SAFETY: `dev` is a live handle owned by the SDK, and the field offset
    // is asserted against the vendor header at build time.
    c_int::from(unsafe { (*dev).irq_num })
}

/// Route the configured GPIOs to UART0.
fn route_pins(config: &Config) -> Result<()> {
    if config.rx_pin.is_none() && config.tx_pin.is_none() {
        return Ok(());
    }
    // SAFETY: as the `uart0` lookup above.
    let gpio = unsafe { sys::bflb_device_get_by_name(c"gpio".as_ptr()) };
    if gpio.is_null() {
        return Err(Error::NotFound);
    }
    if let Some(pin) = config.rx_pin {
        // SAFETY: `gpio` is live, and the function only writes the pin's own
        // mux register.
        unsafe { sys::bflb_gpio_uart_init(gpio, pin, sys::GPIO_UART_FUNC_UART0_RX) };
    }
    if let Some(pin) = config.tx_pin {
        // SAFETY: as above.
        unsafe { sys::bflb_gpio_uart_init(gpio, pin, sys::GPIO_UART_FUNC_UART0_TX) };
    }
    Ok(())
}
