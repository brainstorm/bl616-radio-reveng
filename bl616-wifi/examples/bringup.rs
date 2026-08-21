// SPDX-FileCopyrightText: 2026 Roman Valls Guimera <brainstorm@nopcode.org>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Radio bring-up, one step at a time, narrated to the console.
//!
//! [`bl616_wifi::runtime::start`] performs this same sequence in one go before
//! the scheduler starts. When it does not survive that, the useful question is
//! *which call* did not survive — so this runs the steps from a task, printing
//! before and after each one and pausing long enough for the console to drain.
//!
//! Read it as: the last line printed is the call that did not return.
//!
//! ```sh
//! cargo xtask flash --example bringup --features usb-console
//! ```

#![no_std]
#![no_main]

use bl616_wifi::{delay_ms, event, println, runtime, sys, ApConfig, Wifi};

#[no_mangle]
pub extern "C" fn main() -> core::ffi::c_int {
    runtime::start_without_radio(app)
}

/// Long enough for the USB console task to drain the ring before the next
/// call gets a chance to take the CPU down with it.
fn settle() {
    delay_ms(400);
}

fn app() -> ! {
    println!();
    println!(
        "[bringup] scheduler is running, heap {} B",
        runtime::free_heap()
    );
    settle();

    println!("[bringup] 1/5 rfparam_init ...");
    settle();
    let rc = unsafe { sys::rfparam_init(0, core::ptr::null_mut(), 0) };
    println!(
        "[bringup] 1/5 rfparam_init -> {rc}, heap {} B",
        runtime::free_heap()
    );
    settle();

    println!("[bringup] 2/5 tcpip_init ...");
    settle();
    unsafe { sys::tcpip_init(None, core::ptr::null_mut()) };
    println!(
        "[bringup] 2/5 tcpip_init done, heap {} B",
        runtime::free_heap()
    );
    settle();

    println!("[bringup] 3/5 async_register_event_filter ...");
    settle();
    event::set_handler(|e, v| println!("[event] {e:?} ({v})"));
    event::register();
    println!("[bringup] 3/5 event filter registered");
    settle();

    println!("[bringup] 4/5 wifi_task_create ...");
    settle();
    unsafe { sys::wifi_task_create() };
    println!(
        "[bringup] 4/5 wifi_task_create done, heap {} B",
        runtime::free_heap()
    );
    settle();

    println!("[bringup] 5/5 fhost_init ...");
    settle();
    let rc = unsafe { sys::fhost_init() };
    println!(
        "[bringup] 5/5 fhost_init -> {rc}, heap {} B",
        runtime::free_heap()
    );
    settle();

    println!("[bringup] waiting for the radio to report in ...");
    match event::wait(&[event::Event::InitDone], 20_000) {
        Some(_) => println!("[bringup] INIT_DONE"),
        None => println!("[bringup] no INIT_DONE within 20s"),
    }
    match event::wait(&[event::Event::MgmrDone], 20_000) {
        Some(_) => println!("[bringup] MGMR_DONE"),
        None => println!("[bringup] no MGMR_DONE within 20s"),
    }

    println!("[bringup] starting WPA2 AP ...");
    settle();
    // Wifi::init would refuse here: this example drove the bring-up by hand,
    // so the runtime never recorded an RF status for it to check.
    let wifi = unsafe { Wifi::assume_initialised() };
    match wifi.start_ap(&ApConfig::wpa2("bl616-ap", "bl616wifi").on_channel(6)) {
        Ok(()) => println!("[bringup] AP started: bl616-ap on channel 6, 192.168.4.1"),
        Err(e) => println!("[bringup] AP start failed: {e}"),
    }

    println!("[bringup] survived the full sequence; idling");
    let mut tick = 0u32;
    loop {
        println!("[bringup] alive {tick}s  heap {} B", runtime::free_heap());
        tick += 1;
        delay_ms(1000);
    }
}
