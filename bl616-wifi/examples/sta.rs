// SPDX-FileCopyrightText: 2026 Roman Valls Guimera <brainstorm@nopcode.org>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! WPA2 station: join a network, take a DHCP lease, then report link health.
//!
//! Credentials come from the environment at build time:
//!
//! ```sh
//! WIFI_SSID='my-network' WIFI_PSK='my-passphrase' cargo xtask flash --example sta
//! ```
//!
//! The vendor CLI is also live on the console, so `wifi_scan`, `wifi_state`
//! and `wifi_sta_info` work if you want a second opinion on what the radio
//! thinks is happening.

#![no_std]
#![no_main]

use bl616_wifi::net::MacAddr;
use bl616_wifi::{delay_ms, main, println, runtime, Event, StaConfig, Wifi};

/// Set at build time; the defaults exist so the example still compiles.
const SSID: &str = match option_env!("WIFI_SSID") {
    Some(s) => s,
    None => "bl616-test",
};
const PSK: &str = match option_env!("WIFI_PSK") {
    Some(s) => s,
    None => "changeme123",
};

main!(app);

fn app() -> ! {
    // Vendor CLI on the same UART — invaluable when a join fails and you want
    // to know whether the AP is even visible.
    bl616_wifi::shell::start();

    // Log every state change as it happens. This runs in the timer daemon
    // task with the scheduler suspended, so it does nothing but print.
    bl616_wifi::event::set_handler(|event, value| {
        println!("[event] {event:?} ({value})");
    });

    // Retry rather than halt: a slow first boot is a bad reason to need a
    // power cycle, and the console tells you if it is something worse.
    let wifi = loop {
        match Wifi::init() {
            Ok(wifi) => break wifi,
            Err(e) => println!("[sta] wifi init failed: {e} — retrying"),
        }
    };

    println!("[sta] mac {}", MacAddr(wifi.sta_mac()));
    println!("[sta] heap free {} bytes", runtime::free_heap());

    // A scan proves the PHY works before any credential can be blamed.
    if let Err(e) = wifi.scan_and_print(10_000) {
        println!("[sta] scan failed: {e} (continuing)");
    }

    println!("[sta] joining {SSID:?} ...");
    let config = StaConfig::wpa2(SSID, PSK);

    let ip = loop {
        match wifi.connect(&config) {
            Ok(ip) => break ip,
            Err(e) => {
                println!("[sta] join failed: {e} — retrying in 5s");
                delay_ms(5_000);
            }
        }
    };

    println!("[sta] up: {ip}");
    println!("[sta] heap free {} bytes", runtime::free_heap());
    println!("[sta] try: ping {}", ip.address);

    // Ping the gateway from here. The access point isolates its clients, so
    // nothing else on the network can ping this board -- an outbound echo is
    // the only end-to-end proof of the Rust stack available on this network.
    #[cfg(feature = "rust-net")]
    bl616_wifi::net_al::ping_start();

    // Keep reconnecting on our own rather than leaning on the stack's
    // auto-reconnect, so the console shows what is going on.
    loop {
        delay_ms(5_000);

        if !wifi.is_connected() {
            println!("[sta] link down, rejoining ...");
            bl616_wifi::event::clear(&[Event::Disconnected]);
            match wifi.connect(&config) {
                Ok(ip) => println!("[sta] back up: {ip}"),
                Err(e) => println!("[sta] rejoin failed: {e}"),
            }
            continue;
        }

        let rssi = wifi.rssi().unwrap_or(0);
        let channel = wifi.channel().unwrap_or(0);
        println!(
            "[sta] up {}s  rssi {rssi} dBm  ch {channel}  heap {} B",
            runtime::uptime_ms() / 1000,
            runtime::free_heap()
        );

        #[cfg(feature = "rust-net")]
        {
            let (tx, rx, rtt) = bl616_wifi::net_al::ping_stats();
            println!("[sta] gateway ping: {rx}/{tx} replies, last {rtt} ms");
        }
    }
}
