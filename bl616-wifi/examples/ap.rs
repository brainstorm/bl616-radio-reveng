// SPDX-FileCopyrightText: 2026 Roman Valls Guimera <brainstorm@nopcode.org>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! WPA2 access point: beacon an SSID, authenticate stations, hand out leases.
//!
//! Configuration comes from the environment at build time:
//!
//! ```sh
//! AP_SSID='bl616-ap' AP_PSK='rustrust' cargo xtask flash --example ap
//! ```
//!
//! Once it is up, join `bl616-ap` from a laptop or phone. You should get an
//! address in 192.168.4.0/24 and be able to ping 192.168.4.1.

#![no_std]
#![no_main]

use bl616_wifi::net::MacAddr;
use bl616_wifi::{delay_ms, main, println, runtime, ApConfig, Wifi};

/// Set at build time; the defaults exist so the example still compiles.
const SSID: &str = match option_env!("AP_SSID") {
    Some(s) => s,
    None => "bl616-ap",
};
const PSK: &str = match option_env!("AP_PSK") {
    Some(s) => s,
    None => "bl616wifi",
};
const CHANNEL: u8 = 6;

main!(app);

fn app() -> ! {
    bl616_wifi::shell::start();

    // Station joins and leaves arrive as events; print them so the console
    // shows who is on the network.
    bl616_wifi::event::set_handler(|event, value| {
        println!("[event] {event:?} ({value})");
    });

    // Retry rather than halt: a slow first boot is a bad reason to need a
    // power cycle, and the console tells you if it is something worse.
    let wifi = loop {
        match Wifi::init() {
            Ok(wifi) => break wifi,
            Err(e) => println!("[ap] wifi init failed: {e} — retrying"),
        }
    };

    println!("[ap] mac {}", MacAddr(wifi.ap_mac()));
    println!("[ap] heap free {} bytes", runtime::free_heap());

    let config = ApConfig::wpa2(SSID, PSK).on_channel(CHANNEL);

    loop {
        match wifi.start_ap(&config) {
            Ok(()) => break,
            Err(e) => {
                println!("[ap] start failed: {e} — retrying in 5s");
                delay_ms(5_000);
            }
        }
    }

    println!(
        "[ap] up: ssid {:?}  wpa2  ch {}  {}/{}",
        SSID,
        CHANNEL,
        config.address,
        config.netmask.prefix_len()
    );
    println!(
        "[ap] dhcp pool: .{}..{}  ({} leases)",
        config.dhcp_start,
        config.dhcp_start + config.dhcp_limit - 1,
        config.dhcp_limit
    );
    println!("[ap] join {SSID:?} then ping {}", config.address);
    println!("[ap] heap free {} bytes", runtime::free_heap());

    loop {
        delay_ms(10_000);
        println!(
            "[ap] up {}s  heap {} B",
            runtime::uptime_ms() / 1000,
            runtime::free_heap()
        );
    }
}
