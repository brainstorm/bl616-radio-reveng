// SPDX-FileCopyrightText: 2026 Roman Valls Guimera <brainstorm@nopcode.org>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! A preemptive scheduler for RV32, sized to what the BL616 WiFi blobs need.
//!
//! Stage 3 of the pure-Rust roadmap. The blobs themselves only ever call the
//! `rtos_*` layer, which is already Rust — but the SDK's C substrate calls
//! FreeRTOS directly in 57 places, and this is what has to satisfy those.
//!
//! # Shape of the thing
//!
//! The scheduler is split so that the part that can be tested is tested. The
//! logic here — who runs next, who is blocked on what, when a timeout
//! expires, what priority a mutex holder should be lent — is ordinary Rust
//! over a [`Port`] trait, and the host tests drive it with a fake port that
//! records switches instead of performing them. The real port is a few
//! hundred lines of assembly that cannot be tested anywhere but the board.
//!
//! That split matters because a scheduler fails silently. A wrong decision
//! here does not crash: it produces a task that runs slightly too rarely, a
//! priority inversion under load, or a timeout that fires early — the kind of
//! fault that presents on a radio as poor throughput a week later.
//!
//! # Deliberate simplifications
//!
//! FreeRTOS keeps a bitmap of ready priorities and an intrusive list per
//! priority. This keeps one array of tasks and scans it. With the fifteen or
//! so tasks this system runs, at a 1 kHz tick, the scan is a rounding error,
//! and it removes the entire class of bug where a task is on the wrong list
//! or on two of them.

#![no_std]

extern crate alloc;

pub mod port;
pub mod queue;
pub mod task;

pub use port::Port;
pub use task::{Scheduler, TaskHandle, TaskState};

/// Priorities the scheduler supports, matching `configMAX_PRIORITIES`.
///
/// The blobs create tasks up to priority 30, so this cannot be trimmed
/// without moving them.
pub const MAX_PRIORITIES: u32 = 32;

/// Tick rate, matching `configTICK_RATE_HZ`.
pub const TICK_RATE_HZ: u32 = 1000;
