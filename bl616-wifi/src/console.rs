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
//!
//! # Why there is a lock here
//!
//! The SDK's `bflb_console_write` takes no lock and keeps the state for its
//! CRLF translation in a global. Two tasks printing at once therefore
//! interleave *by the character*, not by the line — a WiFi log line arriving
//! while the application prints turns both into something like
//! `[e[m0bma0ss[y0] dmn[s0 momk`, which is readable by eye and useless to
//! anything that parses the output.
//!
//! So every console write in the firmware is funnelled through one recursive
//! mutex. The linker's `--wrap` puts [`console_write`] in front of the SDK's
//! copy, which covers the vendor's `printf` and its log macros; the Rust
//! side takes the same mutex for the whole of a `println!`, so a line and
//! its newline cannot be split either.
//!
//! Two cases deliberately skip the lock, because taking a mutex in them is
//! either illegal or impossible: an interrupt handler, and anything printed
//! before the scheduler starts. Both are single-threaded in practice — the
//! boot banner has nothing to race with, and a handler that prints is
//! already accepting the consequences.
//!
//! One gap worth knowing about: `--wrap` only redirects calls that cross a
//! translation unit, so the SDK's own `_console_write_r` — the `write(2)`
//! path behind `fwrite` and friends — still reaches the unlocked copy
//! directly. Nothing in this firmware prints that way; `printf` does not.
//!
//! # Measuring, before adding more of this
//!
//! The `console-probe` feature counts every write and its shape, and every
//! format string the SDK's formatter is given. It is what established that
//! this firmware's console traffic is one byte per call and never passes
//! through `printf` — and so that wrapping anything further would buy
//! nothing. Reach for it before adding another interposition.

use core::ffi::c_void;
use core::fmt::{self, Write};
use core::sync::atomic::{AtomicUsize, Ordering};

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

/// The console mutex, or 0 before anything has needed one.
///
/// Recursive, because the guard is held across `printf` calls that go on to
/// take it again inside [`console_write`].
static LOCK: AtomicUsize = AtomicUsize::new(0);

/// Whether a mutex may be taken at all right now.
fn lockable() -> bool {
    // Volatile: the counter is written by the trap entry code, which the
    // compiler cannot see.
    let in_interrupt = unsafe { core::ptr::read_volatile(&raw const sys::TrapNetCounter) != 0 };
    // SAFETY: a plain read of the kernel's own state, valid at any time.
    let running = unsafe { sys::xTaskGetSchedulerState() } == sys::TASK_SCHEDULER_RUNNING;
    running && !in_interrupt
}

/// The console mutex, created on first use.
///
/// Returns null when there is no mutex and no way to make one, which is the
/// caller's cue to write unlocked rather than not at all: losing the output
/// would be worse than interleaving it.
fn lock() -> sys::QueueHandle_t {
    let existing = LOCK.load(Ordering::Acquire);
    if existing != 0 {
        return existing as sys::QueueHandle_t;
    }
    if !lockable() {
        return core::ptr::null_mut();
    }

    // SAFETY: creates a kernel object and hands back its handle.
    let fresh = unsafe { sys::xQueueCreateMutex(sys::QUEUE_TYPE_RECURSIVE_MUTEX) };
    if fresh.is_null() {
        return core::ptr::null_mut();
    }
    match LOCK.compare_exchange(0, fresh as usize, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => fresh,
        Err(won) => {
            // Another task got there first; keep theirs and return ours.
            // SAFETY: `fresh` is ours, was just created, and nothing else
            // has ever seen it.
            unsafe { sys::vQueueDelete(fresh) };
            won as sys::QueueHandle_t
        }
    }
}

/// Holds the console for as long as it is alive.
pub struct Guard(sys::QueueHandle_t);

impl Guard {
    /// Take the console, or return a guard over nothing when it cannot be
    /// taken. Either way the caller may print.
    #[must_use]
    pub fn take() -> Guard {
        if !lockable() {
            return Guard(core::ptr::null_mut());
        }
        let m = lock();
        if !m.is_null() {
            // SAFETY: `m` is a live recursive mutex; waiting forever is
            // right here, since the holder only ever holds it for one line.
            unsafe { sys::xQueueTakeMutexRecursive(m, sys::TickType_t::MAX) };
        }
        Guard(m)
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: taken by `Guard::take`, and given back exactly once.
            unsafe { sys::xQueueGiveMutexRecursive(self.0) };
        }
    }
}

// ------------------------------------------------------------------- probe
//
// What is writing to the console, and in what sizes. Behind a feature
// because it costs a table update on every write; the point is to answer
// one question — whether a caller really emits a lone escape sequence, or
// whether a longer write is being truncated below this layer — and then to
// go away again.

/// Distinct (size, first four bytes) shapes remembered.
#[cfg(feature = "console-probe")]
const PROBE_SLOTS: usize = 16;

#[cfg(feature = "console-probe")]
mod probe {
    use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

    pub static CALLS: AtomicUsize = AtomicUsize::new(0);
    pub static BYTES: AtomicUsize = AtomicUsize::new(0);
    /// Writes whose shape did not fit the table.
    pub static OTHER: AtomicUsize = AtomicUsize::new(0);

    /// One remembered shape: the write's length, its first four bytes, and
    /// how often it has been seen. `len` of 0 means the slot is free.
    pub struct Slot {
        pub len: AtomicU32,
        pub head: [AtomicU32; 4],
        pub count: AtomicU32,
    }

    impl Slot {
        #[allow(clippy::declare_interior_mutable_const)]
        pub const NEW: Slot = Slot {
            len: AtomicU32::new(0),
            head: [
                AtomicU32::new(0),
                AtomicU32::new(0),
                AtomicU32::new(0),
                AtomicU32::new(0),
            ],
            count: AtomicU32::new(0),
        };

        pub fn matches(&self, len: u32, head: &[u8; 4]) -> bool {
            self.len.load(Ordering::Relaxed) == len
                && (0..4).all(|i| self.head[i].load(Ordering::Relaxed) == u32::from(head[i]))
        }

        pub fn claim(&self, len: u32, head: &[u8; 4]) {
            self.len.store(len, Ordering::Relaxed);
            for (cell, byte) in self.head.iter().zip(head) {
                cell.store(u32::from(*byte), Ordering::Relaxed);
            }
        }
    }
}

#[cfg(feature = "console-probe")]
static PROBE: [probe::Slot; PROBE_SLOTS] = [const { probe::Slot::NEW }; PROBE_SLOTS];

/// Remember one write's shape.
///
/// Races between writers can misplace a count; for telling "a hundred a
/// second" from "none" that does not matter, and a lock here would change
/// the timing being measured.
#[cfg(feature = "console-probe")]
fn probe_record(data: *const c_void, size: usize) {
    use core::sync::atomic::Ordering;

    probe::CALLS.fetch_add(1, Ordering::Relaxed);
    probe::BYTES.fetch_add(size, Ordering::Relaxed);

    let mut head = [0u8; 4];
    for (i, slot) in head.iter_mut().enumerate() {
        if i < size {
            // SAFETY: `data` is valid for `size` bytes, and `i < size`.
            *slot = unsafe { *data.cast::<u8>().add(i) };
        }
    }
    let len = u32::try_from(size).unwrap_or(u32::MAX);

    for slot in &PROBE {
        if slot.matches(len, &head) {
            slot.count.fetch_add(1, Ordering::Relaxed);
            return;
        }
        if slot.len.load(Ordering::Relaxed) == 0 {
            slot.claim(len, &head);
            slot.count.fetch_add(1, Ordering::Relaxed);
            return;
        }
    }
    probe::OTHER.fetch_add(1, Ordering::Relaxed);
}

/// Format strings seen by [`__wrap_console_vsnprintf`], with counts.
///
/// The write probe can only say *what* bytes went out; a format string is a
/// pointer into rodata, so this says *who* sent them — look the address up
/// in the ELF and the caller names itself.
#[cfg(feature = "console-probe")]
static FMTS: [probe::Slot; PROBE_SLOTS] = [const { probe::Slot::NEW }; PROBE_SLOTS];

/// Remember one format string by address.
#[cfg(feature = "console-probe")]
fn probe_fmt(fmt: *const core::ffi::c_char) {
    use core::sync::atomic::Ordering;

    let addr = fmt as usize as u32;
    // The address goes in `len`, which is only a discriminator here.
    for slot in &FMTS {
        if slot.len.load(Ordering::Relaxed) == addr {
            slot.count.fetch_add(1, Ordering::Relaxed);
            return;
        }
        if slot.len.load(Ordering::Relaxed) == 0 {
            slot.len.store(addr, Ordering::Relaxed);
            // The first four bytes of the string itself, so the common case
            // needs no lookup at all.
            for (i, cell) in slot.head.iter().enumerate() {
                // SAFETY: a NUL-terminated C string; stop at the terminator.
                let byte = unsafe { *fmt.add(i).cast::<u8>() };
                cell.store(u32::from(byte), Ordering::Relaxed);
                if byte == 0 {
                    break;
                }
            }
            slot.count.fetch_add(1, Ordering::Relaxed);
            return;
        }
    }
}

/// Print what the probe has seen, and clear it.
///
/// Snapshots first: reporting is itself console traffic, and counting that
/// would drown the thing being measured.
#[cfg(feature = "console-probe")]
pub fn probe_report() {
    use core::sync::atomic::Ordering;

    let calls = probe::CALLS.swap(0, Ordering::Relaxed);
    let bytes = probe::BYTES.swap(0, Ordering::Relaxed);
    let other = probe::OTHER.swap(0, Ordering::Relaxed);

    let mut shapes = [(0u32, [0u8; 4], 0u32); PROBE_SLOTS];
    for (out, slot) in shapes.iter_mut().zip(&PROBE) {
        out.0 = slot.len.load(Ordering::Relaxed);
        for (byte, cell) in out.1.iter_mut().zip(&slot.head) {
            *byte = cell.load(Ordering::Relaxed) as u8;
        }
        out.2 = slot.count.swap(0, Ordering::Relaxed);
    }

    let mut fmts = [(0u32, [0u8; 4], 0u32); PROBE_SLOTS];
    for (out, slot) in fmts.iter_mut().zip(&FMTS) {
        out.0 = slot.len.load(Ordering::Relaxed);
        for (byte, cell) in out.1.iter_mut().zip(&slot.head) {
            *byte = cell.load(Ordering::Relaxed) as u8;
        }
        out.2 = slot.count.swap(0, Ordering::Relaxed);
    }

    crate::println!("[probe] {calls} writes, {bytes} bytes, {other} unrecorded");
    for (addr, head, count) in fmts {
        if count == 0 {
            continue;
        }
        crate::println!(
            "[probe]   fmt {addr:#010x}  {:02x} {:02x} {:02x} {:02x}  x{count}",
            head[0],
            head[1],
            head[2],
            head[3]
        );
    }
    for (len, head, count) in shapes {
        if count == 0 {
            continue;
        }
        crate::println!(
            "[probe]   len {len:3}  head {:02x} {:02x} {:02x} {:02x}  x{count}",
            head[0],
            head[1],
            head[2],
            head[3]
        );
    }
}

/// The console write every `printf` in the firmware ends up in.
///
/// `--wrap=bflb_console_write` at link time renames the SDK's own out of the
/// way; this takes the lock and calls it.
///
/// # Safety
///
/// Called by the C library with the buffer it was given. Forwards it
/// unchanged.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __wrap_bflb_console_write(data: *const c_void, size: usize) -> isize {
    #[cfg(feature = "console-probe")]
    probe_record(data, size);
    let _guard = Guard::take();
    // SAFETY: the arguments are the C library's own, passed straight
    // through to the implementation it was going to call anyway.
    unsafe { sys::__real_bflb_console_write(data, size) }
}

/// The vendor's `printf`, recorded and then passed on.
///
/// Only built for the probe. It exists to answer whether console traffic
/// comes through the SDK's formatter at all — on this firmware it does not,
/// which is why nothing wraps it in an ordinary build.
///
/// # Safety
///
/// Called by the C library with its own format string and `va_list`, both
/// passed through untouched.
#[cfg(feature = "console-probe")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __wrap_console_vsnprintf(
    fmt: *const core::ffi::c_char,
    args: *mut c_void,
) -> core::ffi::c_int {
    probe_fmt(fmt);
    let _guard = Guard::take();
    // SAFETY: the arguments are the C library's own, forwarded to the
    // implementation it was going to call anyway.
    unsafe { sys::__real_console_vsnprintf(fmt, args) }
}

/// Write to the console. Same shape as `core::write!`'s target.
#[doc(hidden)]
pub fn _print(args: fmt::Arguments<'_>) {
    // Held across the whole of the formatted output, so a value that formats
    // into several chunks still arrives as one piece.
    let _guard = Guard::take();
    let _ = Console.write_fmt(args);
}

/// As [`_print`], and a newline, without letting go in between.
#[doc(hidden)]
pub fn _println(args: fmt::Arguments<'_>) {
    let _guard = Guard::take();
    let _ = Console.write_fmt(args);
    let _ = Console.write_str("\n");
}

/// Print to the board console.
#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => { $crate::console::_print(::core::format_args!($($arg)*)) };
}

/// Print to the board console, with a newline.
///
/// The line and its newline go out under one lock, so another task cannot
/// print between them.
#[macro_export]
macro_rules! println {
    () => { $crate::print!("\n") };
    ($($arg:tt)*) => { $crate::console::_println(::core::format_args!($($arg)*)) };
}
