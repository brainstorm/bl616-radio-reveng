// SPDX-FileCopyrightText: 2026 Roman Valls Guimera <brainstorm@nopcode.org>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! The RV32 port: the part that cannot be tested anywhere but the board.
//!
//! # Which port this has to match, which I got wrong once
//!
//! The SDK ships two RISC-V ports and builds one of them. An earlier version
//! of this file was written against `c906/portASM.S`, whose live handler is
//! `Mtspend_Handler` and whose yield is a store to `0xe000_0000`. That file is
//! **not compiled**: `Mtspend_Handler` does not appear in the built
//! `libfreertos.a`, and the object that is there references
//! `pTrapNetCounter`, which only `common/portASM.S` touches. The build uses
//! the common port, so this follows the common port.
//!
//! The difference is not cosmetic. The real design has three entry points and
//! yields with `ecall`, not a peripheral write:
//!
//! * `freertos_risc_v_exception_handler` — an `ecall` (mcause 11) is the
//!   yield, and goes straight to [`vTaskSwitchContext`]. Anything else is a
//!   real fault.
//! * `freertos_risc_v_interrupt_handler` — saves context and calls the
//!   platform's own dispatcher, which is where every peripheral lands.
//! * `freertos_risc_v_mtimer_interrupt_handler` — the tick, driven by the
//!   machine timer's compare register.
//!
//! # The frame
//!
//! `portCONTEXT_SIZE` is 31 words on RV32, laid out from the saved stack
//! pointer as:
//!
//! ```text
//!   0    mepc
//!   1    mstatus
//!   2    x1 (ra)
//!   3..29  x5..x31
//!   30   critical nesting depth
//! ```
//!
//! with the floating-point registers in a block below it.
//!
//! **The floating-point half is not optional.** The ABI is `ilp32f` and the
//! PHY and MAC use the F registers; a switch that saves only the integer file
//! corrupts them on every preemption, and that does not crash — it degrades
//! the radio.
//!
//! The vendor saves the FPU block only when `mstatus.FS` says the task
//! dirtied it. This saves it unconditionally: the cost is 32 stores on a
//! switch, and the failure mode of getting dirty-tracking wrong is silent
//! numerical corruption in the PHY. That is a bad trade to make for cycles.
//!
//! # Status
//!
//! Written against the correct port and assembled, but never run. Nothing
//! links it.

use core::ffi::c_void;

use crate::port::{Port, StackPtr};
use crate::task::Tcb;

/// Words in a saved context: 32 integer-side, 32 floating-point.
pub const FRAME_WORDS: usize = 64;

/// Word offsets within the frame.
const OFF_MEPC: usize = 0;
const OFF_MSTATUS: usize = 1;
const OFF_RA: usize = 2;
/// a0 is x10; x5 sits at word 3, so x10 is five words further on.
const OFF_A0: usize = 8;
const OFF_CRITICAL_NESTING: usize = 30;
/// 31 integer words plus 32 floating-point ones.
pub const FRAME_WORDS_TOTAL: usize = 63;

/// The task the context switch will save into and restore from.
///
/// Read and written by assembly at a fixed name, and the saved stack pointer
/// must be the first member of [`Tcb`].
#[unsafe(no_mangle)]
pub static mut pxCurrentTCB: *mut Tcb = core::ptr::null_mut();

// `vTaskSwitchContext` is called from the assembly above, not from Rust, so
// there is no declaration to make here -- naming it would only add a symbol
// nothing references.

core::arch::global_asm!(
    r#"
    .section .text.bl616_rtos_port, "ax", @progbits

/* Save: floating point first, then the 31-word integer frame. */
.macro SAVE_CONTEXT
    addi  sp, sp, -128
    fsw   f0,   0(sp)
    fsw   f1,   4(sp)
    fsw   f2,   8(sp)
    fsw   f3,  12(sp)
    fsw   f4,  16(sp)
    fsw   f5,  20(sp)
    fsw   f6,  24(sp)
    fsw   f7,  28(sp)
    fsw   f8,  32(sp)
    fsw   f9,  36(sp)
    fsw   f10,  40(sp)
    fsw   f11,  44(sp)
    fsw   f12,  48(sp)
    fsw   f13,  52(sp)
    fsw   f14,  56(sp)
    fsw   f15,  60(sp)
    fsw   f16,  64(sp)
    fsw   f17,  68(sp)
    fsw   f18,  72(sp)
    fsw   f19,  76(sp)
    fsw   f20,  80(sp)
    fsw   f21,  84(sp)
    fsw   f22,  88(sp)
    fsw   f23,  92(sp)
    fsw   f24,  96(sp)
    fsw   f25, 100(sp)
    fsw   f26, 104(sp)
    fsw   f27, 108(sp)
    fsw   f28, 112(sp)
    fsw   f29, 116(sp)
    fsw   f30, 120(sp)
    fsw   f31, 124(sp)
    addi  sp, sp, -124
    sw    x1,   8(sp)
    sw    x5,  12(sp)
    sw    x6,  16(sp)
    sw    x7,  20(sp)
    sw    x8,  24(sp)
    sw    x9,  28(sp)
    sw    x10,  32(sp)
    sw    x11,  36(sp)
    sw    x12,  40(sp)
    sw    x13,  44(sp)
    sw    x14,  48(sp)
    sw    x15,  52(sp)
    sw    x16,  56(sp)
    sw    x17,  60(sp)
    sw    x18,  64(sp)
    sw    x19,  68(sp)
    sw    x20,  72(sp)
    sw    x21,  76(sp)
    sw    x22,  80(sp)
    sw    x23,  84(sp)
    sw    x24,  88(sp)
    sw    x25,  92(sp)
    sw    x26,  96(sp)
    sw    x27, 100(sp)
    sw    x28, 104(sp)
    sw    x29, 108(sp)
    sw    x30, 112(sp)
    sw    x31, 116(sp)
    csrr  t0, mepc
    sw    t0, 0(sp)
    csrr  t0, mstatus
    sw    t0, 4(sp)
    la    t0, xCriticalNesting
    lw    t0, 0(t0)
    sw    t0, 120(sp)
    /* Note the trap depth, which is what xPortIsInsideInterrupt reads. */
    la    t0, TrapNetCounter
    lw    t1, 0(t0)
    addi  t1, t1, 1
    sw    t1, 0(t0)
    la    t1, pxCurrentTCB
    lw    t1, 0(t1)
    sw    sp, 0(t1)
.endm

.macro RESTORE_CONTEXT
    la    t1, pxCurrentTCB
    lw    t1, 0(t1)
    lw    sp, 0(t1)
    la    t0, TrapNetCounter
    lw    t1, 0(t0)
    addi  t1, t1, -1
    sw    t1, 0(t0)
    lw    t0, 120(sp)
    la    t1, xCriticalNesting
    sw    t0, 0(t1)
    lw    t0, 4(sp)
    csrw  mstatus, t0
    lw    t0, 0(sp)
    csrw  mepc, t0
    lw    x1,   8(sp)
    lw    x5,  12(sp)
    lw    x6,  16(sp)
    lw    x7,  20(sp)
    lw    x8,  24(sp)
    lw    x9,  28(sp)
    lw    x10,  32(sp)
    lw    x11,  36(sp)
    lw    x12,  40(sp)
    lw    x13,  44(sp)
    lw    x14,  48(sp)
    lw    x15,  52(sp)
    lw    x16,  56(sp)
    lw    x17,  60(sp)
    lw    x18,  64(sp)
    lw    x19,  68(sp)
    lw    x20,  72(sp)
    lw    x21,  76(sp)
    lw    x22,  80(sp)
    lw    x23,  84(sp)
    lw    x24,  88(sp)
    lw    x25,  92(sp)
    lw    x26,  96(sp)
    lw    x27, 100(sp)
    lw    x28, 104(sp)
    lw    x29, 108(sp)
    lw    x30, 112(sp)
    lw    x31, 116(sp)
    addi  sp, sp, 124
    flw   f0,   0(sp)
    flw   f1,   4(sp)
    flw   f2,   8(sp)
    flw   f3,  12(sp)
    flw   f4,  16(sp)
    flw   f5,  20(sp)
    flw   f6,  24(sp)
    flw   f7,  28(sp)
    flw   f8,  32(sp)
    flw   f9,  36(sp)
    flw   f10,  40(sp)
    flw   f11,  44(sp)
    flw   f12,  48(sp)
    flw   f13,  52(sp)
    flw   f14,  56(sp)
    flw   f15,  60(sp)
    flw   f16,  64(sp)
    flw   f17,  68(sp)
    flw   f18,  72(sp)
    flw   f19,  76(sp)
    flw   f20,  80(sp)
    flw   f21,  84(sp)
    flw   f22,  88(sp)
    flw   f23,  92(sp)
    flw   f24,  96(sp)
    flw   f25, 100(sp)
    flw   f26, 104(sp)
    flw   f27, 108(sp)
    flw   f28, 112(sp)
    flw   f29, 116(sp)
    flw   f30, 120(sp)
    flw   f31, 124(sp)
    addi  sp, sp, 128
    mret
.endm

    /* Vectored entry. mtvec points here in direct mode, so this is where a
       trap arrives when the platform has not routed it to one of the three
       specific handlers below. Save once, then decide: the interrupt bit is
       the sign bit of mcause. */
    .global freertos_risc_v_trap_handler
    .align 4
freertos_risc_v_trap_handler:
    SAVE_CONTEXT
    csrr  a0, mcause
    bltz  a0, 2f                    /* negative: asynchronous, an interrupt */
    li    t0, 11
    bne   a0, t0, 3f                /* not an ecall: a real fault */
    lw    t0, 0(sp)                 /* ecall returns past itself */
    addi  t0, t0, 4
    sw    t0, 0(sp)
    call  vTaskSwitchContext
    RESTORE_CONTEXT
2:
    andi  t0, a0, 0x1f              /* interrupt number */
    li    t1, 7                     /* machine timer */
    bne   t0, t1, 4f
    call  bl616_rtos_tick
    RESTORE_CONTEXT
4:
    call  freertos_risc_v_application_interrupt_handler
    RESTORE_CONTEXT
3:
    call  bl616_rtos_fault
    RESTORE_CONTEXT

    .global freertos_risc_v_exception_handler
    .align 4
freertos_risc_v_exception_handler:
    SAVE_CONTEXT
    csrr  a0, mcause
    li    t0, 11                    /* environment call: this is a yield */
    bne   a0, t0, 1f
    /* ecall returns to the instruction after it, not to it. */
    lw    t0, 0(sp)
    addi  t0, t0, 4
    sw    t0, 0(sp)
    call  vTaskSwitchContext
    RESTORE_CONTEXT
1:
    call  bl616_rtos_fault
    RESTORE_CONTEXT

    .global freertos_risc_v_interrupt_handler
    .align 4
freertos_risc_v_interrupt_handler:
    SAVE_CONTEXT
    call  freertos_risc_v_application_interrupt_handler
    RESTORE_CONTEXT

    .global freertos_risc_v_mtimer_interrupt_handler
    .align 4
freertos_risc_v_mtimer_interrupt_handler:
    SAVE_CONTEXT
    call  bl616_rtos_tick
    RESTORE_CONTEXT
"#
);

/// The RV32 port.
pub struct RiscvPort;

/// Where a task returns to if its entry function ever returns.
///
/// FreeRTOS calls this a configuration error; there is nowhere to go, and
/// falling off the end of a stack is worse than stopping.
extern "C" fn task_exited() -> ! {
    loop {
        core::hint::spin_loop();
    }
}

unsafe impl Port for RiscvPort {
    unsafe fn init_stack(
        top: StackPtr,
        entry: extern "C" fn(*mut c_void),
        arg: *mut c_void,
    ) -> StackPtr {
        // Align down to 16 bytes, then reserve one frame.
        let aligned = (top as usize) & !0xf;
        let frame = (aligned - FRAME_WORDS * 4) as *mut usize;
        unsafe {
            core::ptr::write_bytes(frame, 0, FRAME_WORDS);
            // mret jumps here.
            frame.add(OFF_MEPC).write(entry as *const () as usize);
            // MPP = machine mode, MPIE set: interrupts on once the task runs.
            frame.add(OFF_MSTATUS).write(0x1880);
            frame.add(OFF_CRITICAL_NESTING).write(0);
            // The single argument, in a0.
            frame.add(OFF_A0).write(arg as usize);
            // If the task returns, it returns to somewhere that stops.
            frame.add(OFF_RA).write(task_exited as *const () as usize);
        }
        frame
    }

    fn yield_now() {
        // An environment call traps to the exception handler, which reads
        // mcause 11 and switches. This is why a yield is safe to ask for
        // anywhere: the switch happens on the way out of the trap, not inside
        // whatever asked for it.
        unsafe { core::arch::asm!("ecall", options(nostack)) };
    }

    fn enter_critical() -> usize {
        let mstatus: usize;
        unsafe {
            core::arch::asm!("csrrci {}, mstatus, 8", out(reg) mstatus, options(nomem, nostack))
        };
        mstatus & 0x8
    }

    unsafe fn exit_critical(state: usize) {
        if state != 0 {
            unsafe { core::arch::asm!("csrsi mstatus, 8", options(nomem, nostack)) };
        }
    }

    fn in_interrupt() -> bool {
        unsafe extern "C" {
            static TrapNetCounter: i32;
        }
        unsafe { core::ptr::read_volatile(&raw const TrapNetCounter) != 0 }
    }

    unsafe fn start_first_task(_sp: StackPtr) -> ! {
        // Entering the first task is the same operation as switching to it:
        // request a switch and let the handler restore a context that was
        // never saved, which is exactly what init_stack built.
        Self::yield_now();
        loop {
            core::hint::spin_loop();
        }
    }
}

/// Nesting depth of `vTaskEnterCritical`, saved and restored with the
/// context so it belongs to the task rather than the core.
#[unsafe(no_mangle)]
pub static mut xCriticalNesting: usize = 0;

/// Trap depth. The platform's `xPortIsInsideInterrupt()` reads this, and so
/// does the RTOS adapter, so the handlers above have to maintain it.
#[unsafe(no_mangle)]
pub static mut TrapNetCounter: i32 = 0;

/// An exception that is not a yield. There is no handler for a fault here
/// and continuing would compound it.
#[unsafe(no_mangle)]
pub extern "C" fn bl616_rtos_fault() {
    loop {
        core::hint::spin_loop();
    }
}

/// The machine timer interrupt: advance the scheduler's idea of time.
#[unsafe(no_mangle)]
pub extern "C" fn bl616_rtos_tick() {
    unsafe extern "C" {
        fn xTaskIncrementTick() -> i32;
    }
    // The compare register has to be pushed forward or the interrupt
    // re-fires immediately.
    advance_mtimer_compare();
    if unsafe { xTaskIncrementTick() } != 0 {
        unsafe extern "C" {
            fn vTaskSwitchContext();
        }
        unsafe { vTaskSwitchContext() };
    }
}

/// Machine timer compare register, set up by the platform before the
/// scheduler starts.
#[unsafe(no_mangle)]
pub static mut pullMachineTimerCompareRegister: *mut u32 = core::ptr::null_mut();
#[unsafe(no_mangle)]
pub static mut ullNextTime: u64 = 0;
#[unsafe(no_mangle)]
pub static mut uxTimerIncrementsForOneTick: usize = 0;

/// Move the compare register one tick further on.
///
/// Written as two 32-bit stores in the order the RISC-V spec requires: the
/// low half is set to all ones first so the pair never describes a time in
/// the past while it is half-written.
fn advance_mtimer_compare() {
    unsafe {
        let cmp = pullMachineTimerCompareRegister;
        if cmp.is_null() {
            return;
        }
        ullNextTime = ullNextTime.wrapping_add(uxTimerIncrementsForOneTick as u64);
        let next = ullNextTime;
        core::ptr::write_volatile(cmp, u32::MAX);
        core::ptr::write_volatile(cmp.add(1), (next >> 32) as u32);
        core::ptr::write_volatile(cmp, next as u32);
    }
}
