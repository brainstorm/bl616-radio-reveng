// SPDX-FileCopyrightText: 2026 Roman Valls Guimera <brainstorm@nopcode.org>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! What the scheduler needs from the hardware.
//!
//! Everything the scheduler cannot decide for itself lives behind this trait:
//! switching stacks, masking interrupts, and asking for a context switch from
//! somewhere a switch cannot happen directly. The host tests supply a fake
//! one, which is the only reason the scheduler logic can be tested at all.

/// A saved execution context, as the port understands it.
pub type StackPtr = *mut usize;

/// The hardware operations the scheduler depends on.
///
/// # Safety
///
/// Implementations perform context switches and interrupt masking. Getting
/// any of it wrong corrupts execution in ways no type can catch, which is why
/// this is a trait with exactly one real implementation rather than an
/// extension point.
pub unsafe trait Port {
    /// Build an initial stack so that switching to it starts `entry(arg)`.
    ///
    /// # Safety
    ///
    /// `top` must be the highest address of an allocated, aligned stack.
    unsafe fn init_stack(top: StackPtr, entry: extern "C" fn(*mut core::ffi::c_void), arg: *mut core::ffi::c_void) -> StackPtr;

    /// Ask for a context switch at the next opportunity.
    ///
    /// Not necessarily immediate: on RISC-V this raises a software interrupt,
    /// so the switch happens on the way out of the current handler.
    fn yield_now();

    /// Mask interrupts, returning the previous state.
    fn enter_critical() -> usize;

    /// Restore what [`Port::enter_critical`] returned.
    ///
    /// # Safety
    ///
    /// `state` must be the value from the matching `enter_critical`.
    unsafe fn exit_critical(state: usize);

    /// Whether the caller is inside an interrupt handler.
    fn in_interrupt() -> bool;

    /// Start the first task. Never returns.
    ///
    /// # Safety
    ///
    /// The scheduler must have chosen a current task first.
    unsafe fn start_first_task(sp: StackPtr) -> !;
}
