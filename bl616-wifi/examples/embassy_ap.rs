// SPDX-FileCopyrightText: 2026 Roman Valls Guimera <brainstorm@nopcode.org>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! WPA2 soft-AP whose IP stack is embassy-net, not ours.
//!
//! The counterpart to `embassy_sta.rs`, and the one that exercises the most:
//! the driver's RX and TX paths, both wakers, the executor hosted on
//! FreeRTOS, the time driver, the critical section, and the DHCP server in
//! `bl616-dhcp` — this time over embassy-net's UDP socket rather than
//! smoltcp's, which is the port the whole crate split was meant to make cheap.
//!
//! ```sh
//! cargo xtask flash --example embassy_ap --features embassy-net,usb-console
//! ```
//!
//! Join the network from a laptop or phone; it should lease an address and
//! answer ping. embassy-net has no DHCP server of its own, which is exactly
//! why `bl616-dhcp` exists.

#![no_std]
#![no_main]

use bl616_dhcp::{Leases, CLIENT_PORT, SERVER_PORT};
use bl616_wifi::net::MacAddr;
use bl616_wifi::net_al::embassy::WifiDriver;
use bl616_wifi::{delay_ms, main, println, runtime, ApConfig, Wifi};
use embassy_net::udp::{PacketMetadata, UdpSocket};
use embassy_net::{Config, IpEndpoint, StackResources, StaticConfigV4};
use embassy_net::{Ipv4Address, Ipv4Cidr};
use static_cell::StaticCell;

const SSID: &str = match option_env!("WIFI_SSID") {
    Some(s) => s,
    None => "bl616-embassy",
};
const PSK: &str = match option_env!("WIFI_PSK") {
    Some(s) => s,
    None => "bl616test",
};
const CHANNEL: u8 = 6;

/// DHCP server, plus room.
const SOCKETS: usize = 3;

main!(app);

fn app() -> ! {
    bl616_wifi::shell::start();
    bl616_wifi::event::set_handler(|event, value| {
        println!("[event] {event:?} ({value})");
    });

    let wifi = loop {
        match Wifi::init() {
            Ok(wifi) => break wifi,
            Err(e) => println!("[embassy-ap] wifi init failed: {e} — retrying"),
        }
    };
    println!("[embassy-ap] mac {}", MacAddr(wifi.sta_mac()));

    let config = ApConfig::wpa2(SSID, PSK).on_channel(CHANNEL);
    loop {
        match wifi.start_ap(&config) {
            Ok(()) => break,
            Err(e) => {
                println!("[embassy-ap] start failed: {e} — retrying in 5s");
                delay_ms(5_000);
            }
        }
    }
    println!(
        "[embassy-ap] up: ssid {:?} ch {} {}/{}",
        SSID,
        CHANNEL,
        config.address,
        config.netmask.prefix_len()
    );

    // The blob registers the station first and the soft-AP second, so the AP
    // is slot 1 -- binding blindly to slot 0 serves the wrong interface, which
    // is a mistake this project has already made once. Give it a moment to
    // appear, then fall back rather than spin forever.
    delay_ms(500);
    let (idx, driver) = loop {
        if let Some(d) = WifiDriver::new(1) {
            break (1, d);
        }
        if let Some(d) = WifiDriver::new(0) {
            break (0, d);
        }
        delay_ms(100);
    };
    println!("[embassy-ap] driver bound to interface {idx}");

    let addr = config.address.as_raw().to_le_bytes();
    let mask = config.netmask.as_raw().to_le_bytes();
    let prefix = config.netmask.prefix_len();

    // wifi_mgmr_ap_start does not push ap_ipaddr through net_al, and under
    // this front end nothing else writes it either, so the blob and the
    // vendor CLI would report no address at all.
    bl616_wifi::net_al::set_vif_addr(
        idx,
        config.address.as_raw(),
        config.netmask.as_raw(),
        config.address.as_raw(),
        0,
    );

    let pool_start = config.dhcp_start as u16;
    let pool_limit = config.dhcp_limit as u16;
    println!(
        "[embassy-ap] join {SSID:?}, then ping {}.{}.{}.{}",
        addr[0], addr[1], addr[2], addr[3]
    );

    bl616_wifi::embassy_rt::run(move |spawner| {
        static RESOURCES: StaticCell<StackResources<SOCKETS>> = StaticCell::new();
        let resources = RESOURCES.init(StackResources::new());

        let v4 = StaticConfigV4 {
            address: Ipv4Cidr::new(Ipv4Address::new(addr[0], addr[1], addr[2], addr[3]), prefix as u8),
            // An access point is the edge of its own network: nothing to
            // forward to, and the DHCP options point clients back at us.
            gateway: None,
            dns_servers: Default::default(),
        };
        let seed = runtime::uptime_ms().wrapping_mul(0x9E37_79B9) ^ u64::from(addr[3]);
        let (stack, runner) = embassy_net::new(driver, Config::ipv4_static(v4), resources, seed);

        spawner.spawn(net_runner(runner).expect("task pool exhausted"));
        spawner.spawn(dhcp_server(
            stack,
            u32::from_le_bytes(addr),
            u32::from_le_bytes(mask),
            pool_start,
            pool_limit,
        ).expect("task pool exhausted"));
        spawner.spawn(heartbeat().expect("task pool exhausted"));
    })
}

/// Drive the stack. Without this polling, nothing moves.
#[embassy_executor::task]
async fn net_runner(mut runner: embassy_net::Runner<'static, WifiDriver>) -> ! {
    runner.run().await
}

/// Serve DHCP, so a station that associates can actually configure itself.
#[embassy_executor::task]
async fn dhcp_server(
    stack: embassy_net::Stack<'static>,
    server: u32,
    mask: u32,
    start: u16,
    limit: u16,
) {
    let Some(mut leases) = Leases::new(server, mask, start, limit) else {
        println!("[embassy-ap] dhcp: refusing an unusable pool");
        return;
    };

    // Deliberately static: the socket borrows these for as long as it lives,
    // and this task never returns.
    static RX_META: StaticCell<[PacketMetadata; 8]> = StaticCell::new();
    static TX_META: StaticCell<[PacketMetadata; 8]> = StaticCell::new();
    static RX_BUF: StaticCell<[u8; 1500]> = StaticCell::new();
    static TX_BUF: StaticCell<[u8; 1500]> = StaticCell::new();
    let mut sock = UdpSocket::new(
        stack,
        RX_META.init([PacketMetadata::EMPTY; 8]),
        RX_BUF.init([0; 1500]),
        TX_META.init([PacketMetadata::EMPTY; 8]),
        TX_BUF.init([0; 1500]),
    );
    if let Err(e) = sock.bind(SERVER_PORT) {
        println!("[embassy-ap] dhcp: bind failed: {e:?}");
        return;
    }
    println!("[embassy-ap] dhcp: serving pool .{}..{}", start, start + limit - 1);

    let mut req = [0u8; 1024];
    let mut reply = [0u8; 548];
    loop {
        let Ok((n, _from)) = sock.recv_from(&mut req).await else {
            continue;
        };
        let Some(len) = leases.handle(&req[..n], &mut reply) else {
            continue;
        };
        // Always broadcast: the client has no address yet, so a unicast reply
        // would need an ARP entry it cannot answer.
        let to = IpEndpoint::new(Ipv4Address::BROADCAST.into(), CLIENT_PORT);
        if let Err(e) = sock.send_to(&reply[..len], to).await {
            println!("[embassy-ap] dhcp: send failed: {e:?}");
        }
    }
}

#[embassy_executor::task]
async fn heartbeat() {
    loop {
        embassy_time::Timer::after_secs(10).await;
        let (inflight, peak, dry, rx, dropped) = bl616_wifi::net_al::stats();
        println!(
            "[embassy-ap] up {}s  heap {} B  rx={rx} drop={dropped} tx_inflight={inflight} peak={peak} dry={dry}",
            runtime::uptime_ms() / 1000,
            runtime::free_heap()
        );
    }
}
