// SPDX-FileCopyrightText: 2026 Roman Valls Guimera <brainstorm@nopcode.org>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! WPA2 station whose IP stack is embassy-net, not ours.
//!
//! This is the arrangement the crate is aimed at: the application owns the
//! stack and this crate supplies the device. `bl616_wifi` contributes the
//! `Driver`, an embassy time driver over the FreeRTOS tick, and an executor
//! that runs as an ordinary FreeRTOS task — the radio blobs keep their own
//! threads and know nothing about any of it.
//!
//! ```sh
//! WIFI_SSID='my-network' WIFI_PSK='my-passphrase' \
//!   cargo xtask flash --example embassy_sta --features embassy-net,usb-console
//! ```
//!
//! Two details differ from `sta.rs` and both are deliberate:
//!
//! * the join asks the blob **not** to run DHCP, because embassy-net does it;
//! * the lease is published back with `net_al::set_vif_addr`, or the vendor
//!   API and the blob keep reporting no address while the stack has one.

#![no_std]
#![no_main]

use bl616_wifi::net::MacAddr;
use bl616_wifi::net_al::embassy::WifiDriver;
use bl616_wifi::{main, println, runtime, StaConfig, Wifi};
use embassy_net::{Config, StackResources};
use static_cell::StaticCell;

const SSID: &str = match option_env!("WIFI_SSID") {
    Some(s) => s,
    None => "bl616-test",
};
const PSK: &str = match option_env!("WIFI_PSK") {
    Some(s) => s,
    None => "changeme123",
};

/// Sockets embassy-net may have open at once: DHCP and DNS, plus room.
const SOCKETS: usize = 4;

main!(app);

fn app() -> ! {
    bl616_wifi::shell::start();
    bl616_wifi::event::set_handler(|event, value| {
        println!("[event] {event:?} ({value})");
    });

    let wifi = loop {
        match Wifi::init() {
            Ok(wifi) => break wifi,
            Err(e) => println!("[embassy] wifi init failed: {e} — retrying"),
        }
    };
    println!("[embassy] mac {}", MacAddr(wifi.sta_mac()));

    // Associate only. `dhcp: false` stops the blob starting its own client,
    // which would race embassy-net for the same exchange.
    let config = StaConfig::wpa2(SSID, PSK).without_dhcp();
    loop {
        match wifi.connect(&config) {
            Ok(_) => break,
            Err(e) => {
                println!("[embassy] join failed: {e} — retrying");
                bl616_wifi::delay_ms(5_000);
            }
        }
    }
    println!("[embassy] associated; handing the network over to embassy-net");

    // The blob registers the station as interface 0 during bring-up, so the
    // driver can bind now that the join has returned.
    let driver = loop {
        match WifiDriver::new(0) {
            Some(d) => break d,
            None => bl616_wifi::delay_ms(100),
        }
    };

    // The seed randomises port and sequence-number choice. There is no RNG
    // wired up here, so mix the MAC with the clock -- enough to stop two
    // boards agreeing, which is all it is protecting against.
    let mac = driver.mac();
    let seed = u64::from_le_bytes([mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], 0, 0])
        ^ runtime::uptime_ms().wrapping_mul(0x9E37_79B9);

    // Never returns: this task becomes the executor.
    bl616_wifi::embassy_rt::run(move |spawner| {
        // StaticCell gives the resources a 'static lifetime, which is what
        // makes the runner 'static and lets it move into a task by value.
        static RESOURCES: StaticCell<StackResources<SOCKETS>> = StaticCell::new();
        let resources = RESOURCES.init(StackResources::new());
        let (stack, runner) =
            embassy_net::new(driver, Config::dhcpv4(Default::default()), resources, seed);

        // The runner *is* the stack: without it polling, nothing moves.
        spawner.must_spawn(net_runner(runner));
        spawner.must_spawn(net(stack));
    })
}

/// Drive the stack.
#[embassy_executor::task]
async fn net_runner(mut runner: embassy_net::Runner<'static, WifiDriver>) -> ! {
    runner.run().await
}

#[embassy_executor::task]
async fn net(stack: embassy_net::Stack<'static>) {
    println!("[embassy] waiting for a lease ...");
    stack.wait_config_up().await;

    let Some(v4) = stack.config_v4() else {
        println!("[embassy] configured, but no IPv4 -- unexpected");
        return;
    };
    let addr = v4.address.address().octets();
    let gw = v4.gateway.map(|g| g.octets()).unwrap_or([0; 4]);
    let dns = v4.dns_servers.first().map(|d| d.octets()).unwrap_or([0; 4]);
    println!(
        "[embassy] lease {}.{}.{}.{}/{} via {}.{}.{}.{}",
        addr[0],
        addr[1],
        addr[2],
        addr[3],
        v4.address.prefix_len(),
        gw[0],
        gw[1],
        gw[2],
        gw[3]
    );

    // Tell the blob what the stack decided, so wifi_sta_ip4_addr_get and the
    // vendor CLI agree with us.
    let mask = (!0u32) << (32 - v4.address.prefix_len());
    bl616_wifi::net_al::set_vif_addr(
        0,
        u32::from_le_bytes(addr),
        u32::from_le_bytes(mask.to_be_bytes()),
        u32::from_le_bytes(gw),
        u32::from_le_bytes(dns),
    );

    // A DNS query is the end-to-end proof available on this network: the
    // access point isolates its clients, so nothing else can reach this
    // board, but the gateway answers on port 53. It exercises UDP out and
    // back through the driver, the wakers and the time driver.
    loop {
        match stack
            .dns_query("example.com", embassy_net::dns::DnsQueryType::A)
            .await
        {
            Ok(addrs) => println!("[embassy] dns ok: {} answer(s)", addrs.len()),
            Err(e) => println!("[embassy] dns failed: {e:?}"),
        }
        embassy_time::Timer::after_secs(5).await;
        println!(
            "[embassy] up {}s  heap {} B",
            runtime::uptime_ms() / 1000,
            runtime::free_heap()
        );
    }
}
