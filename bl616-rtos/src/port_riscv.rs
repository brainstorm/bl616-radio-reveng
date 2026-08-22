// SPDX-FileCopyrightText: 2026 Roman Valls Guimera <brainstorm@nopcode.org>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! The RV32 port: the part that cannot be tested anywhere but the board.
//!
//! # What this chip actually needs
//!
//! Less than a RISC-V port usually does, and finding that out was most of the
//! work. The vendor's `portASM.S` contains a full trap handler that decodes
//! `mcause` and dispatches exceptions — and all of it is inside `#if 0`. The
//! live handler is `Mtspend_Handler`, and it does exactly one thing: save the
//! context, call [`switch_context`], restore the next one. Peripheral
//! interrupts and the tick never come through here at all; they go through
//! the SoC's own vectored table, and the tick reaches the scheduler as an
//! ordinary call from the platform's timer handler.
//!
//! So this port is a context switch, a way to ask for one, and a stack
//! initialiser. Nothing else.
//!
//! # Asking for a switch
//!
//! Writing 1 to `0xe000_0000` raises the T-Head software interrupt, which
//! vectors straight here; the handler clears it by writing 0 before
//! returning. That is why a yield is not immediate — it happens on the way
//! out of whatever is running, which is what makes it safe to call from
//! inside a driver.
//!
//! # The frame, which must agree with itself
//!
//! Laid out in words from the saved stack pointer, matching the vendor's so
//! the shape is one already known to work on this core:
//!
//! ```text
//!   0    x1 (ra)
//!   1    x3 (gp)      2  x4 (tp)
//!   3..29  x5..x31    (t0-t2, s0-s11, a0-a7, t3-t6)
//!   30   mepc
//!   31   padding, to keep the frame 16-byte aligned
//!   32..63  f31..f0
//! ```
//!
//! **The floating-point half is not optional.** The ABI is `ilp32f` and the
//! PHY and MAC code uses the F registers; a switch that saves only the
//! integer file corrupts them across every preemption, and it does not crash
//! — it degrades the radio.

use core::ffi::c_void;

use crate::port::{Port, StackPtr};
use crate::task::Tcb;

/// Words in a saved context: 32 integer-side, 32 floating-point.
pub const FRAME_WORDS: usize = 64;

/// Word offsets within the frame.
const OFF_RA: usize = 0;
const OFF_A0: usize = 8;
const OFF_MEPC: usize = 30;

/// T-Head software-interrupt trigger. Writing 1 requests a switch; the
/// handler writes 0 to acknowledge.
const MTSPEND: *mut u32 = 0xe000_0000 as *mut u32;

/// The task the context switch will save into and restore from.
///
/// Read and written by assembly at a fixed name, and the saved stack pointer
/// must be the first member of [`Tcb`].
#[unsafe(no_mangle)]
pub static mut pxCurrentTCB: *mut Tcb = core::ptr::null_mut();

unsafe extern "C" {
    /// Chosen by the scheduler; the handler calls this between saving and
    /// restoring.
    fn vTaskSwitchContext();
}

core::arch::global_asm!(
    r#"
    .section .text.mtspend_handler, "ax", @progbits
    .global freertos_risc_v_trap_handler
    .global Mtspend_Handler
    .align 8
freertos_risc_v_trap_handler:
Mtspend_Handler:
    /* Floating point first, so it sits above the integer frame. */
    addi  sp, sp, -128
    fsw   f31,   0(sp)
    fsw   f30,   4(sp)
    fsw   f29,   8(sp)
    fsw   f28,  12(sp)
    fsw   f27,  16(sp)
    fsw   f26,  20(sp)
    fsw   f25,  24(sp)
    fsw   f24,  28(sp)
    fsw   f23,  32(sp)
    fsw   f22,  36(sp)
    fsw   f21,  40(sp)
    fsw   f20,  44(sp)
    fsw   f19,  48(sp)
    fsw   f18,  52(sp)
    fsw   f17,  56(sp)
    fsw   f16,  60(sp)
    fsw   f15,  64(sp)
    fsw   f14,  68(sp)
    fsw   f13,  72(sp)
    fsw   f12,  76(sp)
    fsw   f11,  80(sp)
    fsw   f10,  84(sp)
    fsw   f9,   88(sp)
    fsw   f8,   92(sp)
    fsw   f7,   96(sp)
    fsw   f6,  100(sp)
    fsw   f5,  104(sp)
    fsw   f4,  108(sp)
    fsw   f3,  112(sp)
    fsw   f2,  116(sp)
    fsw   f1,  120(sp)
    fsw   f0,  124(sp)

    addi  sp, sp, -128
    sw    x1,    0(sp)
    sw    x3,    4(sp)
    sw    x4,    8(sp)
    sw    x5,   12(sp)
    sw    x6,   16(sp)
    sw    x7,   20(sp)
    sw    x8,   24(sp)
    sw    x9,   28(sp)
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
    sw    t0,  120(sp)

    /* Hand the stack pointer to the outgoing task. */
    la    a1, pxCurrentTCB
    lw    a1, 0(a1)
    sw    sp, 0(a1)

    jal   vTaskSwitchContext

    /* And take the incoming one's. */
    la    a1, pxCurrentTCB
    lw    a1, 0(a1)
    lw    sp, 0(a1)

    /* Acknowledge the software interrupt before leaving, or it re-enters
       immediately. */
    li    t0, 0xe0000000
    li    t2, 0x0
    sw    t2, 0(t0)

    /* MPP=machine, MPIE set: interrupts on again after mret. */
    li    t0, 0x1880
    csrs  mstatus, t0

    lw    t0,  120(sp)
    csrw  mepc, t0
    lw    x1,    0(sp)
    lw    x3,    4(sp)
    lw    x4,    8(sp)
    lw    x5,   12(sp)
    lw    x6,   16(sp)
    lw    x7,   20(sp)
    lw    x8,   24(sp)
    lw    x9,   28(sp)
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
    addi  sp, sp, 128

    flw   f31,   0(sp)
    flw   f30,   4(sp)
    flw   f29,   8(sp)
    flw   f28,  12(sp)
    flw   f27,  16(sp)
    flw   f26,  20(sp)
    flw   f25,  24(sp)
    flw   f24,  28(sp)
    flw   f23,  32(sp)
    flw   f22,  36(sp)
    flw   f21,  40(sp)
    flw   f20,  44(sp)
    flw   f19,  48(sp)
    flw   f18,  52(sp)
    flw   f17,  56(sp)
    flw   f16,  60(sp)
    flw   f15,  64(sp)
    flw   f14,  68(sp)
    flw   f13,  72(sp)
    flw   f12,  76(sp)
    flw   f11,  80(sp)
    flw   f10,  84(sp)
    flw   f9,   88(sp)
    flw   f8,   92(sp)
    flw   f7,   96(sp)
    flw   f6,  100(sp)
    flw   f5,  104(sp)
    flw   f4,  108(sp)
    flw   f3,  112(sp)
    flw   f2,  116(sp)
    flw   f1,  120(sp)
    flw   f0,  124(sp)
    addi  sp, sp, 128

    mret
    .size Mtspend_Handler, . - Mtspend_Handler
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
            frame.add(OFF_MEPC).write(entry as usize);
            // The single argument, in a0.
            frame.add(OFF_A0).write(arg as usize);
            // If the task returns, it returns to somewhere that stops.
            frame.add(OFF_RA).write(task_exited as usize);
        }
        frame
    }

    fn yield_now() {
        unsafe { core::ptr::write_volatile(MTSPEND, 1) };
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
