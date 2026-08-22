// SPDX-FileCopyrightText: 2026 Roman Valls Guimera <brainstorm@nopcode.org>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Hosting embassy on FreeRTOS: a time driver, a critical section, and an
//! executor that runs as an ordinary task.
//!
//! embassy-net needs an executor and a time driver, and neither has to wait
//! for the FreeRTOS replacement in Stage 3 — an executor is perfectly happy
//! as one task among others. When that stage lands, only the three `sys::`
//! calls below change.
//!
//! # Why not `arch-riscv32`
//!
//! embassy-executor ships a RISC-V executor whose run loop parks the hart in
//! `wfi`. That is right on bare metal and wrong here: it halts the core rather
//! than yielding, so every other FreeRTOS task waits on an interrupt to free
//! it. This drives [`embassy_executor::raw::Executor`] instead and blocks on a
//! task notification, which is what a well-behaved task does.
//!
//! # Why the pender cannot simply notify
//!
//! `__pender` runs wherever a waker is woken, and the blob frees TX buffers
//! from interrupt context — where the non-ISR FreeRTOS calls are not allowed.
//! There is no reliable interrupt-context flag on this port (`TrapNetCounter`
//! belongs to the C906 port; the E907 build does not define it), so rather
//! than depend on detecting it, correctness here never rests on it:
//!
//! * the pender always sets [`PENDING`], which is safe from any context;
//! * the executor task waits with a bounded timeout, so a missed notification
//!   costs latency and nothing else;
//! * the notification is sent only when interrupts are enabled, which rules
//!   out both interrupt context and critical sections.
//!
//! The wake that matters for throughput — a received frame — arrives on the
//! blob's RX task with interrupts enabled, so it takes the fast path.

use core::cell::RefCell;
use core::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use core::task::Waker;

use critical_section::Mutex;
use embassy_time_queue_utils::Queue;

use crate::runtime;
use bl616_wifi_sys as sys;

/// Longest the executor task will sleep without being told anything happened.
///
/// Only a wake that could not send a notification — one raised in interrupt
/// context — waits this long, and nothing on the throughput path does.
const BACKSTOP_MS: u32 = 20;

/// FreeRTOS notification action `eIncrement`, so a notification raised between
/// the pending check and the wait is counted rather than lost.
const E_INCREMENT: u8 = 2;

static PENDING: AtomicBool = AtomicBool::new(false);
static EXEC_TASK: AtomicPtr<core::ffi::c_void> = AtomicPtr::new(core::ptr::null_mut());

// ----------------------------------------------------------- critical section

/// Single-hart critical section over `mstatus.MIE`.
///
/// The chip has one hart, so masking interrupts is sufficient, and the
/// previous state has to be restored rather than blindly re-enabled: these
/// nest, and FreeRTOS takes them too.
struct SingleHart;
critical_section::set_impl!(SingleHart);

unsafe impl critical_section::Impl for SingleHart {
    unsafe fn acquire() -> bool {
        let mstatus: usize;
        // Clear MIE (bit 3) and return what it was, atomically.
        unsafe { core::arch::asm!("csrrci {}, mstatus, 8", out(reg) mstatus, options(nomem, nostack)) };
        mstatus & 0x8 != 0
    }

    unsafe fn release(was_enabled: bool) {
        if was_enabled {
            unsafe { core::arch::asm!("csrsi mstatus, 8", options(nomem, nostack)) };
        }
    }
}

/// Whether interrupts are enabled right now.
///
/// False inside an interrupt handler and inside a critical section — both
/// places where the plain FreeRTOS calls must not be used.
fn interrupts_enabled() -> bool {
    let mstatus: usize;
    unsafe { core::arch::asm!("csrr {}, mstatus", out(reg) mstatus, options(nomem, nostack)) };
    mstatus & 0x8 != 0
}

// ------------------------------------------------------------- time driver

struct FreeRtosTime {
    queue: Mutex<RefCell<Queue>>,
}

embassy_time_driver::time_driver_impl!(
    static DRIVER: FreeRtosTime = FreeRtosTime {
        queue: Mutex::new(RefCell::new(Queue::new()))
    }
);

impl embassy_time_driver::Driver for FreeRtosTime {
    fn now(&self) -> u64 {
        // The tick rate is configured to 1 kHz and `tick-hz-1_000` matches it,
        // so embassy ticks and milliseconds are the same unit.
        runtime::uptime_ms()
    }

    fn schedule_wake(&self, at: u64, waker: &Waker) {
        critical_section::with(|cs| {
            let mut q = self.queue.borrow(cs).borrow_mut();
            if q.schedule_wake(at, waker) {
                // The earliest deadline moved closer; the executor may be
                // asleep past it.
                pend();
            }
        });
    }
}

/// Dispatch expired timers and report when the next one is due.
fn next_expiration(now: u64) -> u64 {
    critical_section::with(|cs| DRIVER.queue.borrow(cs).borrow_mut().next_expiration(now))
}

// ------------------------------------------------------------------ pender

/// Mark work pending and, when it is safe to, wake the executor task.
fn pend() {
    PENDING.store(true, Ordering::Release);
    if !interrupts_enabled() {
        return;
    }
    let task = EXEC_TASK.load(Ordering::Acquire);
    if !task.is_null() {
        unsafe {
            sys::xTaskGenericNotify(task as _, 0, 0, E_INCREMENT, core::ptr::null_mut());
        }
    }
}

#[export_name = "__pender"]
fn __pender(_context: *mut ()) {
    pend();
}

// ---------------------------------------------------------------- executor

/// Run an embassy executor on this task, forever.
///
/// Call it from a FreeRTOS task of your own — typically the application task,
/// after the radio is up. `init` receives the spawner.
///
/// # Panics
///
/// If called twice: there is one `__pender`, so there is one executor.
pub fn run(init: impl FnOnce(embassy_executor::Spawner)) -> ! {
    let task = unsafe { sys::xTaskGetCurrentTaskHandle() };
    assert!(
        EXEC_TASK
            .compare_exchange(
                core::ptr::null_mut(),
                task as *mut core::ffi::c_void,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok(),
        "one executor: __pender can only wake one task"
    );

    // Leaked deliberately: `raw::Executor::poll` requires the executor to
    // outlive every task it runs, and this function never returns.
    let executor: &'static mut embassy_executor::raw::Executor = alloc::boxed::Box::leak(
        alloc::boxed::Box::new(embassy_executor::raw::Executor::new(core::ptr::null_mut())),
    );

    init(executor.spawner());

    loop {
        // Clear before polling: anything raised during the poll must survive
        // into the wait below rather than being swallowed here.
        PENDING.store(false, Ordering::Release);
        unsafe { executor.poll() };

        let now = runtime::uptime_ms();
        let due = next_expiration(now);
        let wait_ms = due.saturating_sub(now).min(BACKSTOP_MS as u64) as u32;

        if PENDING.load(Ordering::Acquire) || wait_ms == 0 {
            continue;
        }
        unsafe {
            // Clear the count on the way out so each wait consumes one
            // notification rather than returning immediately forever.
            sys::xTaskGenericNotifyWait(0, 0, u32::MAX, core::ptr::null_mut(), ms_to_ticks(wait_ms));
        }
    }
}

fn ms_to_ticks(ms: u32) -> u32 {
    // configTICK_RATE_HZ is 1000 on this build, but do not assume it.
    ms.saturating_mul(runtime::TICK_RATE_HZ) / 1000
}

extern crate alloc;
