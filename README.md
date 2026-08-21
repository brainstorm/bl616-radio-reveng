<!--
SPDX-FileCopyrightText: 2026 Roman Valls Guimera <brainstorm@nopcode.org>

SPDX-License-Identifier: GPL-3.0-or-later
-->

# bl616-wifi

WPA2 WiFi for the Bouffalo BL616, from Rust. Station and access point,
`cargo build` to `cargo xtask flash`, no C project to babysit.

```rust
#![no_std]
#![no_main]

use bl616_wifi::{main, println, StaConfig, Wifi};

main!(app);

fn app() -> ! {
    let wifi = Wifi::init().unwrap();
    let ip = wifi.connect(&StaConfig::wpa2("my-network", "my-passphrase")).unwrap();
    println!("up: {ip}");
    loop { bl616_wifi::delay_ms(1000); }
}
```

**Both modes are verified on hardware** (Sipeed M0S Dock). AP: a laptop
associated over WPA2-PSK, took `192.168.4.2` from the on-board DHCP server,
and pinged `192.168.4.1` 5/5 at ~2.9 ms. STA: joined a WPA2 network with a
full EAPOL 1-4 handshake, took `192.168.87.22/24` by DHCP, answered 6/6 pings
and held -48 dBm.

This is a safe Rust surface over Bouffalo's WiFi stack, not a from-scratch
driver — the 802.11 MAC and PHY ship only as blobs. the engineering notes is
the engineering record: what is open, what is not, the ABI traps, and the
roadmap toward a purer-Rust crate.

## Setup

```sh
rustup target add riscv32imafc-unknown-none-elf

# T-Head GCC 10.2 (Xuantie V2.6.1) -> ~/.local/opt, symlinked into ~/.local/bin
cargo xtask setup

git clone --depth 1 https://github.com/bouffalolab/bouffalo_sdk vendor/bouffalo_sdk
# ...or point at an existing clone:  export BL_SDK_BASE=/path/to/bouffalo_sdk
```

Also needs `cmake`, `make`, `python3` and `clang` (for bindgen's libclang).

The toolchain is not interchangeable. The vendor archives are `-mabi=ilp32f`
with GCC-LTO objects inside, so the Rust target must be `riscv32imafc`
(**not** `riscv32imac`, which is soft-float ABI) and the GCC driver must run
the link. Both are set up in [`.cargo/config.toml`](.cargo/config.toml) with
the reasoning next to each flag.

## Build and flash

```sh
AP_SSID=bl616-ap AP_PSK=bl616wifi cargo xtask flash --example ap
WIFI_SSID=my-network WIFI_PSK=my-passphrase cargo xtask flash --example sta

cargo xtask monitor                # console
cargo xtask build --example ap     # stop after producing target/bl616/ap/
```

Add `--features usb-console` to put the console on the BL616's own USB port
instead of UART0 — no TTL adapter needed, which is what you want on an M0S
Dock.

**Bootloader:** hold BOOT while plugging in the USB-C cable; it enumerates as
`349b:6160 Bouffalo CDC DEMO`. **To run new firmware:** unplug and plug back
in without touching BOOT. There is no software reset over the ROM link.

The console is UART0 on **GPIO21 (TX) / GPIO22 (RX) at 2000000 baud** by
default (needs a TTL-USB adapter), or USB-CDC with `--features usb-console`.
Either way the vendor CLI is on it too: `wifi_scan`, `wifi_state`,
`wifi_sta_info`.

## API

```rust
let wifi = Wifi::init()?;                     // waits for the radio firmware

// Station — returns once DHCP has completed, so the stack is usable
let ip = wifi.connect(&StaConfig::wpa2("network", "passphrase"))?;
wifi.rssi(); wifi.channel(); wifi.is_connected();
wifi.scan_and_print(10_000)?;                 // cheapest proof the PHY works

// Access point — 192.168.4.1/24, vendor DHCP server, 16 leases from .2
wifi.start_ap(&ApConfig::wpa2("bl616-ap", "passphrase").on_channel(6))?;
```

Both configs are builders: `.with_akm(Akm::Wpa3)`, `.with_bssid(..)`,
`.on_freq(2437)`, `.without_dhcp()`, `.hidden()`, `.with_network(..)`,
`.without_dhcp_server()`.

Events come from the vendor's async bus, whose callback runs in the FreeRTOS
timer daemon with the scheduler suspended — so it only latches, and `Wifi`
methods poll from your task. For the events themselves, install a handler and
keep it short:

```rust
bl616_wifi::event::set_handler(|event, value| println!("[event] {event:?} ({value})"));
```

| Feature | Default | |
|---|---|---|
| `alloc` | yes | global allocator over the SDK's TLSF heap |
| `panic-handler` | yes | print the panic to the console and halt |
| `usb-console` | no | console on USB-CDC instead of UART0 |

## Examples

| | |
|---|---|
| `ap` | WPA2 access point with DHCP — the verified path |
| `sta` | WPA2 station, DHCP, reconnect, link stats |
| `hello` | board + FreeRTOS + console, radio untouched |
| `bringup` | radio init one call at a time, narrated to the console |

`hello` and `bringup` are bring-up instruments, not toys. If a board runs
`hello` but not `ap`, the fault is in the radio path; `bringup` then names the
exact call that fails. See "Debugging lessons" in the engineering notes — in
particular that a running BL616 does *not* answer as `349b:6160`, and that you
must read the CDC console with plain `cat` plus
`stty -F /dev/ttyACM0 -echo` — *without* a baud rate, which wedges the port
and makes a healthy board look dead.

## Using it from your own crate

`cargo:rustc-link-arg` only applies to the package that emitted it, so any
crate producing a BL616 binary needs this `build.rs`:

```rust
fn main() {
    let path = std::env::var("DEP_BL616_WIFI_CSDK_LINK_ARGS").unwrap();
    for arg in std::fs::read_to_string(path).unwrap().lines() {
        println!("cargo:rustc-link-arg={arg}");
    }
}
```

That variable comes from `bl616-wifi-sys`'s `links` metadata, so depend on
**both** `bl616-wifi` and `bl616-wifi-sys`, and copy
[`.cargo/config.toml`](.cargo/config.toml) across.

## Layout

```
bl616-wifi/        the crate you use, plus examples/
bl616-wifi-sys/    bindgen FFI; build.rs drives the C build and replays the link
  csdk/            a BouffaloSDK project: defconfig, FreeRTOSConfig.h, lwipopts
xtask/             build / image / flash / setup
the engineering notes            engineering record and roadmap
```

## Licensing

GPL-3.0-or-later. The Bouffalo archives it links against are not
GPL-compatible: **source is fine, binaries are not redistributable.** Build
locally. See the engineering notes.
