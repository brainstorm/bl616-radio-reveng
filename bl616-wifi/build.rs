// SPDX-FileCopyrightText: 2026 Roman Valls Guimera <brainstorm@nopcode.org>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Replays the C link line for this crate's examples.
//!
//! The logic lives in `bl616-link` because an application crate has to do the
//! same thing, and two copies of the GC-root anchor lists would drift.

fn main() {
    bl616_link::emit();
}
