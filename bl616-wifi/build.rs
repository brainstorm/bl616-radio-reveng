// SPDX-FileCopyrightText: 2026 Roman Valls Guimera <brainstorm@nopcode.org>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Re-emit the C substrate's link line for this package's binaries.
//!
//! `cargo:rustc-link-arg` applies only to the targets of the package whose
//! build script emitted it, so bl616-wifi-sys cannot link our examples for us.
//! It writes the argument list to a file and advertises the path through its
//! `links` metadata instead; all that is left is to replay it.
//!
//! Any crate producing a BL616 binary needs this same build script — see the
//! "Using it from your own crate" section of the README.

use std::{env, fs};

/// Entry points the vendor blobs call into, which must survive
/// `--gc-sections`.
///
/// The vendor's own implementations live in a `--whole-archive` C object and
/// are anchored by references the linker can see. Ours are `#[no_mangle]`
/// functions in a Rust rlib, and the linker will happily prune any of them it
/// cannot see a *live* reference to — which silently deleted
/// `net_buf_tx_info` and `net_if_vif_info`, i.e. the whole TX description
/// path, while still linking successfully. `--undefined` makes each one a GC
/// root, the same trick the vendor link line uses for `fw_header`.
const NET_AL_EXPORTS: &[&str] = &[
    "net_init",
    "net_ip_chksum",
    "net_if_add",
    "net_if_get_mac_addr",
    "net_if_find_from_name",
    "net_if_get_name",
    "net_if_vif_info",
    "net_if_up_cb",
    "net_if_down_cb",
    "net_al_link_set",
    "net_buf_tx_alloc",
    "net_buf_tx_alloc_fill",
    "net_buf_tx_alloc_ref",
    "net_buf_tx_info",
    "net_buf_tx_all_shram",
    "net_buf_tx_free",
    "net_buf_tx_cat",
    "net_al_tx_init",
    "net_al_tx_cfm",
    "net_al_tx_do_sta_del",
    "net_al_tx_req",
    "net_al_input",
    "net_al_rx_resend",
    "net_l2_send",
    "net_l2_socket_create",
    "net_l2_socket_delete",
    "net_al_ext_set_vif_ip",
    "net_al_ext_get_vif_ip",
    "net_al_ext_dhcp_connect",
    "net_al_ext_dhcp_disconnect",
    "net_al_dhcpd_start",
    "net_al_dhcpd_stop",
    "net_al_set_ipv6_enable",
];

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    let path = env::var("DEP_BL616_WIFI_CSDK_LINK_ARGS")
        .expect("bl616-wifi-sys did not publish link_args (is it a direct dependency?)");
    println!("cargo:rerun-if-changed={path}");

    let args = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read link args from {path}: {e}"));

    for arg in args.lines().filter(|l| !l.is_empty()) {
        println!("cargo:rustc-link-arg={arg}");
    }

    if env::var_os("CARGO_FEATURE_RUST_NET").is_some() {
        for sym in NET_AL_EXPORTS {
            println!("cargo:rustc-link-arg=-Wl,--undefined={sym}");
        }
    }
}
