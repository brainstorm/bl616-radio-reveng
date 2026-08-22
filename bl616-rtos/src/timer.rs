// SPDX-FileCopyrightText: 2026 Roman Valls Guimera <brainstorm@nopcode.org>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Software timers, and the daemon task that runs them.
//!
//! FreeRTOS runs timer callbacks on a dedicated task rather than in the tick
//! interrupt, and that is not an implementation detail: the callbacks here
//! belong to lwIP and the supplicant, and they block. Running them from the
//! tick would block the tick.
//!
//! `xTimerPendFunctionCall` shares the same task, which is why it exists at
//! all — it is how an interrupt hands work to a context that may block.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::ffi::{c_char, c_void};

/// A software timer.
pub struct Timer {
    pub name: *const c_char,
    pub period: u32,
    pub auto_reload: bool,
    pub id: *mut c_void,
    pub callback: Option<extern "C" fn(*mut Timer)>,
    pub active: bool,
    /// Tick at which it next fires.
    pub due: u64,
}

/// Work handed to the daemon by `xTimerPendFunctionCall`.
pub struct PendedCall {
    pub func: extern "C" fn(*mut c_void, u32),
    pub arg: *mut c_void,
    pub value: u32,
}

/// Everything the daemon owns. Reached only with interrupts masked.
pub struct TimerService {
    pub timers: Vec<Box<Timer>>,
    pub pended: Vec<PendedCall>,
}

impl Default for TimerService {
    fn default() -> Self {
        Self::new()
    }
}

impl TimerService {
    pub const fn new() -> Self {
        TimerService {
            timers: Vec::new(),
            pended: Vec::new(),
        }
    }

    /// Timers due at or before `now`, removed from the active set.
    ///
    /// Auto-reload timers are rescheduled from their previous deadline rather
    /// than from now, so a late daemon does not make a periodic timer drift.
    pub fn take_due(&mut self, now: u64) -> Vec<*mut Timer> {
        let mut fired = Vec::new();
        for t in self.timers.iter_mut() {
            if !t.active || t.due > now {
                continue;
            }
            fired.push(&mut **t as *mut Timer);
            if t.auto_reload {
                t.due += t.period.max(1) as u64;
            } else {
                t.active = false;
            }
        }
        fired
    }

    /// How long until the next timer is due, for the daemon's sleep.
    pub fn next_delay(&self, now: u64) -> Option<u64> {
        self.timers
            .iter()
            .filter(|t| t.active)
            .map(|t| t.due.saturating_sub(now))
            .min()
    }
}
