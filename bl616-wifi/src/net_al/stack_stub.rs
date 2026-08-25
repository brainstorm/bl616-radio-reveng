// SPDX-FileCopyrightText: 2026 Roman Valls Guimera <brainstorm@nopcode.org>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! The control surface `net_al` needs when the IP stack is not ours.
//!
//! Under the embassy front end the application owns the stack, so there is no
//! poll task to send commands to and no sockets to open — but the blob still
//! calls `net_al_ext_dhcp_connect`, `net_al_dhcpd_start` and friends, and
//! still expects answers. This provides the same items [`super::stack`] does,
//! keeping the bookkeeping and dropping the socket work.
//!
//! It exists so that the embassy build does not have to pull smoltcp at all.
//! A consumer such as ssh-stamp already brings its own smoltcp through
//! embassy-net, and two major versions of it in one binary is not a
//! theoretical problem — the `managed` crate is shared between them, so a
//! feature enabled on one silently breaks pattern matching in the other.
//!
//! # What the blob is told
//!
//! Every request succeeds. The blob uses these results to decide whether to
//! carry on configuring the interface, and refusing here aborts the very
//! steps that would have supplied an address — the same reason
//! `net_al_dhcpd_start` returns 0 in the smoltcp front end even before an
//! address exists.

use core::ffi::c_void;
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

use super::events;

/// Requests from the blob's tasks. Kept identical to the smoltcp front end's
/// so `net_al` does not have to care which is compiled in.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Command {
    None = 0,
    DhcpClientStart = 1,
    DhcpClientStop = 2,
    DhcpServerStart = 3,
    DhcpServerStop = 4,
}

pub const RESULT_PENDING: u32 = 0;
pub const RESULT_OK: u32 = 1;
pub const RESULT_FAILED: u32 = 2;

/// The interface the application's stack is bound to, for
/// [`super::set_vif_addr`] and the vendor address getters.
static TARGET_IF: AtomicUsize = AtomicUsize::new(0);
/// The soft-AP pool the blob asked for, so an application can serve it.
static DHCPD_POOL: AtomicU32 = AtomicU32::new(0);

/// Nothing to start: the application runs its own stack.
pub fn start() {}

/// Every command is accepted. See the module docs on why refusing is worse.
pub fn request(_cmd: Command, _timeout_ms: u32) -> bool {
    true
}

pub fn set_target(net_if: *mut c_void) {
    TARGET_IF.store(net_if as usize, Ordering::Release);
}

/// The interface the blob last named, or null.
pub fn target() -> *mut c_void {
    TARGET_IF.load(Ordering::Acquire) as *mut c_void
}

pub fn set_dhcpd_pool(start: u16, limit: u16) {
    DHCPD_POOL.store(((start as u32) << 16) | limit as u32, Ordering::Release);
}

/// First host number and count the blob asked the soft-AP to serve.
///
/// An application that wants to run a DHCP server -- `bl616-dhcp` has the
/// protocol, free of any stack -- reads the pool from here rather than
/// hard-coding one.
pub fn dhcpd_pool() -> (u16, u16) {
    let v = DHCPD_POOL.load(Ordering::Acquire);
    ((v >> 16) as u16, v as u16)
}

/// The application's stack obtains the lease, so this only has to not block.
///
/// Blocking here stalls the blob's WPA task, which is the task that delivers
/// received frames -- the DHCP client then waits for traffic its own caller
/// is preventing. That cost a long debugging session once already.
pub fn start_dhcp_client_async() {}

pub fn post_got_ip() {
    events::post_got_ip();
}
