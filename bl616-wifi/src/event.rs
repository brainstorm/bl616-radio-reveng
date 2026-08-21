// SPDX-FileCopyrightText: 2026 Roman Valls Guimera <brainstorm@nopcode.org>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! WiFi state changes.
//!
//! The vendor stack reports state changes on an asynchronous event bus. The
//! callback for that bus runs inside the FreeRTOS timer daemon task with the
//! scheduler suspended (`platform_bouffalo_sdk.c` posts it via
//! `xTimerPendFunctionCall` between `vTaskSuspendAll`/`xTaskResumeAll`), so it
//! must never block.
//!
//! That constraint shapes the API: the callback only sets bits in a lock-free
//! latch, and [`wait`] polls the latch from an ordinary task. If you want the
//! events themselves — with their payload, in order — install a handler with
//! [`set_handler`], and keep it short.

use core::ffi::c_void;
use core::sync::atomic::{AtomicPtr, AtomicU32, Ordering};

use bl616_wifi_sys as sys;

/// A WiFi state change.
///
/// Variants map one-to-one onto the vendor's `CODE_WIFI_ON_*` codes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u32)]
#[non_exhaustive]
pub enum Event {
    /// Radio firmware is up. The WiFi manager is started in response to this.
    InitDone = sys::CODE_WIFI_ON_INIT_DONE,
    /// WiFi manager task is running; the stack is ready for commands.
    MgmrDone = sys::CODE_WIFI_ON_MGMR_DONE,
    /// Association complete (WPA handshake done). No IP yet.
    Connected = sys::CODE_WIFI_ON_CONNECTED,
    /// Disassociated, whether we asked for it or not.
    Disconnected = sys::CODE_WIFI_ON_DISCONNECT,
    /// Association in progress.
    Connecting = sys::CODE_WIFI_ON_CONNECTING,
    /// DHCP lease acquired (or a static address applied).
    GotIp = sys::CODE_WIFI_ON_GOT_IP,
    /// The DHCP lease expired or was released.
    LostIp = sys::CODE_WIFI_ON_LOST_IP,
    /// Associated, but DHCP never answered.
    GotIpTimeout = sys::CODE_WIFI_ON_GOT_IP_TIMEOUT,
    /// Scan results are ready.
    ScanDone = sys::CODE_WIFI_ON_SCAN_DONE,
    /// Soft-AP is beaconing.
    ApStarted = sys::CODE_WIFI_ON_AP_STARTED,
    /// Soft-AP has stopped.
    ApStopped = sys::CODE_WIFI_ON_AP_STOPPED,
    /// A station associated with our soft-AP.
    ApStaAdded = sys::CODE_WIFI_ON_AP_STA_ADD,
    /// A station left our soft-AP.
    ApStaRemoved = sys::CODE_WIFI_ON_AP_STA_DEL,
    /// Connection parameters were rejected before the air ever got involved.
    ParamsError = sys::CODE_WIFI_ON_PARAMS_ERROR,
}

impl Event {
    /// The vendor's numeric code for this event.
    pub const fn code(self) -> u32 {
        self as u32
    }

    /// Recognise a vendor code. Unknown codes yield `None`; the vendor stack
    /// defines more of them than are useful to model here.
    pub fn from_code(code: u32) -> Option<Self> {
        use Event::*;
        Some(match code {
            sys::CODE_WIFI_ON_INIT_DONE => InitDone,
            sys::CODE_WIFI_ON_MGMR_DONE => MgmrDone,
            sys::CODE_WIFI_ON_CONNECTED => Connected,
            sys::CODE_WIFI_ON_DISCONNECT => Disconnected,
            sys::CODE_WIFI_ON_CONNECTING => Connecting,
            sys::CODE_WIFI_ON_GOT_IP => GotIp,
            sys::CODE_WIFI_ON_LOST_IP => LostIp,
            sys::CODE_WIFI_ON_GOT_IP_TIMEOUT => GotIpTimeout,
            sys::CODE_WIFI_ON_SCAN_DONE => ScanDone,
            sys::CODE_WIFI_ON_AP_STARTED => ApStarted,
            sys::CODE_WIFI_ON_AP_STOPPED => ApStopped,
            sys::CODE_WIFI_ON_AP_STA_ADD => ApStaAdded,
            sys::CODE_WIFI_ON_AP_STA_DEL => ApStaRemoved,
            sys::CODE_WIFI_ON_PARAMS_ERROR => ParamsError,
            _ => return None,
        })
    }
}

/// A user event handler. Runs with the scheduler suspended: no blocking, no
/// allocation that could block, no calls back into [`crate::Wifi`].
pub type Handler = fn(event: Event, value: u32);

/// Sticky record of every code seen so far, two 32-bit words covering codes
/// 0..=63. Sticky rather than a queue because the callback cannot block and a
/// dropped edge would deadlock the waiter.
static LATCH: [AtomicU32; 2] = [AtomicU32::new(0), AtomicU32::new(0)];
static HANDLER: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Install a handler for every WiFi event. Replaces any previous handler.
pub fn set_handler(handler: Handler) {
    HANDLER.store(handler as *mut (), Ordering::Release);
}

/// Remove the event handler.
pub fn clear_handler() {
    HANDLER.store(core::ptr::null_mut(), Ordering::Release);
}

fn latch_set(code: u32) {
    if code < 64 {
        LATCH[(code / 32) as usize].fetch_or(1 << (code % 32), Ordering::SeqCst);
    }
}

/// Test and clear one code.
fn latch_take(code: u32) -> bool {
    if code >= 64 {
        return false;
    }
    let bit = 1u32 << (code % 32);
    LATCH[(code / 32) as usize].fetch_and(!bit, Ordering::SeqCst) & bit != 0
}

/// Forget any of `events` recorded so far.
///
/// Call this immediately before kicking off an operation, so that a stale
/// `Disconnected` from the previous attempt cannot satisfy the next wait.
pub fn clear(events: &[Event]) {
    for e in events {
        latch_take(e.code());
    }
}

/// Block until one of `events` has been seen, or `timeout_ms` elapses.
///
/// The matching event is consumed. Returns `None` on timeout.
///
/// Must be called from a task — it sleeps. A `timeout_ms` of 0 polls once.
pub fn wait(events: &[Event], timeout_ms: u32) -> Option<Event> {
    const POLL_MS: u32 = 10;
    let mut waited = 0;
    loop {
        for e in events {
            if latch_take(e.code()) {
                return Some(*e);
            }
        }
        if waited >= timeout_ms {
            return None;
        }
        crate::runtime::delay_ms(POLL_MS.min(timeout_ms - waited));
        waited += POLL_MS;
    }
}

/// Register with the vendor event bus.
///
/// [`crate::runtime::start`] does this for you. It is public for code that
/// drives the bring-up sequence itself — see `examples/bringup.rs`. Calling it
/// twice registers two filters, so do not mix the two.
pub fn register() {
    unsafe {
        sys::async_register_event_filter(
            sys::EV_WIFI as usize,
            Some(on_event),
            core::ptr::null_mut(),
        );
    }
}

/// The vendor bus callback. Scheduler is suspended here.
unsafe extern "C" fn on_event(ev: sys::async_input_event_t, _priv: *mut c_void) {
    if ev.is_null() {
        return;
    }
    let (code, value) = unsafe { ((*ev).code as u32, (*ev).value) };

    // The manager task must be started from the event callback itself, the
    // way every examples/wifi/* project does it, so that it comes up in the
    // order the blob expects.
    if code == sys::CODE_WIFI_ON_INIT_DONE {
        unsafe { sys::wifi_mgmr_task_start() };
    }

    latch_set(code);

    let handler = HANDLER.load(Ordering::Acquire);
    if !handler.is_null() {
        if let Some(event) = Event::from_code(code) {
            let handler: Handler = unsafe { core::mem::transmute(handler) };
            handler(event, value);
        }
    }
}
