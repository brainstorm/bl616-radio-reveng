// SPDX-FileCopyrightText: 2026 Roman Valls Guimera <brainstorm@nopcode.org>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Boot sequence and the FreeRTOS task your program runs in.
//!
//! The order here is not arbitrary — it is the one every `examples/wifi/*`
//! project in BouffaloSDK uses, and the blobs assume it:
//!
//! 1. `board_init()` — clocks, pinmux, console UART, heap.
//! 2. `rfparam_init()` — per-chip RF calibration out of efuse and the `rftlv`
//!    region of flash. Skip it and the PHY comes up detuned, or not at all.
//! 3. `tcpip_init()` — lwIP core task, before anything can hand it packets.
//! 4. WiFi firmware task — registers the event filter, then `wifi_task_create()`
//!    and `fhost_init()`.
//! 5. `vTaskStartScheduler()`.

use core::ffi::{c_char, c_void};
use core::sync::atomic::{AtomicI32, Ordering};

use bl616_wifi_sys as sys;

/// Stack for the application task, in 32-bit words. 8 KiB: the WiFi stack
/// runs in its own tasks, but `printf` and the TLS code are stack-hungry.
pub const APP_STACK_WORDS: u32 = 2048;
/// Priority of the application task. Below the radio task so bring-up wins
/// any tie.
pub const APP_PRIORITY: u32 = 5;
/// Stack for the radio bring-up task, in 32-bit words. The vendor gives the
/// equivalent task 1024; this one also runs `rfparam_init` and `tcpip_init`.
pub const RADIO_STACK_WORDS: u32 = 2048;
/// Priority of the radio bring-up task, matching the vendor's.
pub const RADIO_PRIORITY: u32 = 10;
/// How long to wait for a USB-CDC host to enumerate before printing anything.
///
/// Only used with the `usb-console` feature, where earlier output is dropped
/// rather than buffered.
#[cfg(feature = "usb-console")]
pub const CONSOLE_SETTLE_MS: u32 = 2_500;

/// Declare the firmware entry point.
///
/// Expands to a `#[no_mangle] extern "C" fn main()` that calls
/// [`start`] with your function. The BouffaloSDK startup code
/// (`ENTRY(__start)` in the generated linker script) calls `main`.
///
/// ```no_run
/// # #![no_std]
/// # #![no_main]
/// bl616_wifi::main!(app);
///
/// fn app() -> ! {
///     loop {}
/// }
/// ```
#[macro_export]
macro_rules! main {
    ($app:path) => {
        #[no_mangle]
        pub extern "C" fn main() -> ::core::ffi::c_int {
            $crate::runtime::start($app)
        }
    };
}

/// Bring up board, radio and network stack, then start the scheduler and run
/// `app` as a task. Never returns.
///
/// Prefer [`main!`], which declares the entry point for you.
pub fn start(app: fn() -> !) -> ! {
    unsafe {
        sys::board_init();

        // Everything else happens in tasks.
        //
        // Doing the radio bring-up before `vTaskStartScheduler()` — which is
        // what BouffaloSDK's own examples/wifi/* main() does — resets a BL616
        // a few seconds in, every time, and takes the console with it before
        // it can say why. Run the identical sequence from a task and it comes
        // up cleanly. `examples/bringup.rs` is the bisect that established
        // this; it is also why the banner below prints from a task, where a
        // USB-CDC console is alive to carry it.
        spawn(
            radio_task,
            c"wifi init".as_ptr(),
            RADIO_STACK_WORDS,
            core::ptr::null_mut(),
            RADIO_PRIORITY,
        );
        spawn(
            app_task,
            c"app".as_ptr(),
            APP_STACK_WORDS,
            app as *mut c_void,
            APP_PRIORITY,
        );

        sys::vTaskStartScheduler();
    }

    // vTaskStartScheduler only returns if the idle task could not be created.
    panic!("FreeRTOS scheduler failed to start (out of heap?)");
}

/// Bring up the board and run `app` as a task, with the radio left alone.
///
/// Same as [`start`] minus RF calibration, lwIP and the WiFi firmware — so
/// what runs is the SDK's board init, FreeRTOS, and your task.
///
/// This is the bring-up bisect tool: if a board runs this but not [`start`],
/// the fault is in the radio path rather than in the image, the linker script
/// or the console. `examples/hello.rs` is exactly this.
pub fn start_without_radio(app: fn() -> !) -> ! {
    unsafe {
        sys::board_init();

        crate::println!();
        crate::println!(
            "bl616-wifi {} — board only, radio not started",
            env!("CARGO_PKG_VERSION")
        );

        spawn(
            app_task,
            c"app".as_ptr(),
            APP_STACK_WORDS,
            app as *mut c_void,
            APP_PRIORITY,
        );

        sys::vTaskStartScheduler();
    }

    panic!("FreeRTOS scheduler failed to start (out of heap?)");
}

/// `rfparam_init`'s result, or [`i32::MIN`] before it has been attempted.
static RF_STATUS: AtomicI32 = AtomicI32::new(i32::MIN);

/// Result of RF calibration, or `None` if [`start`] has not reached it yet.
///
/// Anything other than `Some(0)` means the PHY has no usable calibration data
/// — normally a missing or unflashed `rftlv` region — and the radio will not
/// work. [`crate::Wifi::init`] turns that into [`crate::Error::RfInit`] rather
/// than letting you wait out a timeout for it.
pub fn rf_status() -> Option<i32> {
    match RF_STATUS.load(Ordering::SeqCst) {
        i32::MIN => None,
        status => Some(status),
    }
}

unsafe fn spawn(
    entry: unsafe extern "C" fn(*mut c_void),
    name: *const c_char,
    stack_words: u32,
    arg: *mut c_void,
    priority: u32,
) {
    let rc = unsafe {
        sys::xTaskCreate(
            Some(entry),
            name,
            stack_words as _,
            arg,
            priority as _,
            core::ptr::null_mut(),
        )
    };
    assert!(rc == 1, "xTaskCreate failed (out of heap?)");
}

/// Radio bring-up, in the order the blobs expect, from a task.
///
/// `rfparam_init` reads per-chip calibration out of efuse and the `rftlv`
/// region; `tcpip_init` starts lwIP; then the WiFi firmware and the
/// fully-hosted control path. Ends by deleting itself.
unsafe extern "C" fn radio_task(_arg: *mut c_void) {
    // A USB-CDC console drops everything written before the host enumerates
    // the device, so without this the banner -- and any early failure -- is
    // simply gone by the time a terminal attaches. Costs a moment at boot and
    // makes bring-up legible.
    #[cfg(feature = "usb-console")]
    delay_ms(CONSOLE_SETTLE_MS);

    crate::println!();
    crate::println!(
        "bl616-wifi {} — BouffaloSDK WiFi 6 stack",
        env!("CARGO_PKG_VERSION")
    );

    RF_STATUS.store(
        unsafe { sys::rfparam_init(0, core::ptr::null_mut(), 0) },
        Ordering::SeqCst,
    );
    unsafe { sys::tcpip_init(None, core::ptr::null_mut()) };

    if rf_status() == Some(0) {
        crate::event::register();
        unsafe {
            sys::wifi_task_create();
            sys::fhost_init();
        }
    } else {
        // Handing an uncalibrated PHY to the MAC hangs inside the blob rather
        // than returning an error anybody can read.
        crate::println!(
            "[wifi] rfparam_init failed ({:?}) — radio not started",
            rf_status()
        );
    }

    unsafe { sys::vTaskDelete(core::ptr::null_mut()) };
    unreachable!()
}

unsafe extern "C" fn app_task(arg: *mut c_void) {
    let app: fn() -> ! = unsafe { core::mem::transmute(arg) };
    app()
}

/// FreeRTOS tick rate, read out of `csdk/FreeRTOSConfig.h` at build time by
/// bl616-wifi-sys rather than assumed here.
pub const TICK_RATE_HZ: u32 = sys::TICK_RATE_HZ;

/// Convert milliseconds to scheduler ticks, rounding up so that a non-zero
/// delay never becomes a busy spin.
const fn ms_to_ticks(ms: u32) -> u32 {
    (ms as u64 * TICK_RATE_HZ as u64).div_ceil(1000) as u32
}

/// Sleep the calling task.
///
/// Must be called from a task, never from an interrupt or an event handler.
pub fn delay_ms(ms: u32) {
    unsafe { sys::vTaskDelay(ms_to_ticks(ms) as _) }
}

/// Restart the chip.
///
/// A full system reset rather than a CPU-only one: the radio and the USB
/// peripheral hold state that a CPU reset leaves behind, and coming back up
/// with a half-initialised MAC is harder to diagnose than a clean boot.
pub fn reset() -> ! {
    unsafe { sys::GLB_SW_System_Reset() };
    // The reset is not instantaneous; do not let execution run on into
    // whatever follows.
    loop {
        core::hint::spin_loop();
    }
}

/// Milliseconds since the scheduler started.
pub fn uptime_ms() -> u64 {
    unsafe { sys::xTaskGetTickCount() as u64 * 1000 / TICK_RATE_HZ as u64 }
}

/// Bytes still free in the SDK heap.
///
/// Worth printing during bring-up: the WiFi stack's high-water mark lands
/// during association, and running out there fails in unhelpful ways.
pub fn free_heap() -> usize {
    unsafe { sys::kfree_size(0) as usize }
}
