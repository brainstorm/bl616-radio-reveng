// SPDX-FileCopyrightText: 2026 Roman Valls Guimera <brainstorm@nopcode.org>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Replaying the BouffaloSDK link line into a Rust binary.
//!
//! `bl616-wifi-sys` builds the C substrate and publishes the linker command
//! CMake would have used. Cargo hands `DEP_*` metadata only to *direct*
//! dependents of the crate declaring `links`, and `cargo:rustc-link-arg` does
//! not cross package boundaries either -- so every crate that finally links a
//! firmware binary has to replay those arguments itself.
//!
//! That is what this is for. `bl616-wifi` calls it for its own examples, and
//! so must any application crate producing a BL616 binary: call
//! `bl616_link::emit()` from its `build.rs`. The calling crate needs
//! `bl616-wifi-sys` as a **direct** dependency, or the metadata is invisible
//! and this panics saying so.
//!
//! # Why the anchors matter
//!
//! Most of what follows is `-Wl,--undefined=` for symbols Rust defines and C
//! calls. They are `#[no_mangle]` functions in an rlib that nothing in Rust
//! references, so `--gc-sections` is entitled to delete them -- and it does,
//! silently, leaving a link that succeeds and a firmware that does not work.
//! A successful link proves nothing here; check with `nm`.

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

/// Emit the link arguments and GC-root anchors for a BL616 firmware binary.
///
/// # Panics
///
/// If `bl616-wifi-sys` is not a direct dependency of the calling crate, or if
/// the link-argument file it published cannot be read.
pub fn emit() {
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

    if env::var_os("CARGO_FEATURE_RUST_CRYPTO").is_some() {
        for sym in CRYPTO_EXPORTS {
            println!("cargo:rustc-link-arg=-Wl,--undefined={sym}");
        }
    }

    if env::var_os("CARGO_FEATURE_RUST_RTOS").is_some() {
        for sym in RTOS_EXPORTS {
            println!("cargo:rustc-link-arg=-Wl,--undefined={sym}");
        }
    }

}

/// The symbols `crypto_mbedtls_misc.c` defines, which `bl616-crypto` replaces.
///
/// Anchoring every one matters twice over. The obvious reason is the same as
/// for the net_al exports: these are `#[no_mangle]` functions in an rlib that
/// nothing in Rust calls, so `--gc-sections` is entitled to drop them.
///
/// The second is subtler. Archive members are pulled in whole and on demand,
/// so leaving even one unanchored means the linker still needs it, pulls
/// `crypto_mbedtls_misc.c.obj` in to get it, and every other symbol here
/// collides with the copy that came along for the ride. The set goes in
/// together or the link fails — which is the loud failure, and the good one.
const CRYPTO_EXPORTS: &[&str] = &[
    "aes_128_cbc_decrypt",
    "aes_128_cbc_encrypt",
    "aes_128_ctr_encrypt",
    "aes_ctr_encrypt",
    "aes_decrypt",
    "aes_decrypt_deinit",
    "aes_decrypt_init",
    "aes_encrypt",
    "aes_encrypt_deinit",
    "aes_encrypt_init",
    "crypto_cipher_decrypt",
    "crypto_cipher_deinit",
    "crypto_cipher_encrypt",
    "crypto_cipher_init",
    "crypto_dh_init",
    "crypto_global_deinit",
    "crypto_global_init",
    "crypto_hash_finish",
    "crypto_hash_init",
    "crypto_hash_update",
    "crypto_mod_exp",
    "hmac_md5",
    "hmac_md5_vector",
    "hmac_sha1",
    "hmac_sha1_vector",
    "hmac_sha256",
    "hmac_sha256_vector",
    "hmac_sha384",
    "hmac_sha384_vector",
    "md5_vector",
    "sha1_vector",
    "sha256_vector",
    "sha384_vector",
    "sha512_vector",
];


/// The symbols `rtos_al.c` defines, which `bl616-wifi::rtos_al` replaces.
///
/// The twelve `fhost_*_priority` entries are `const int` data rather than
/// functions, and matter just as much: the blobs read them to decide what
/// priority to create their tasks at. Dropping one would leave a task at
/// whatever the linker happened to leave there.
const RTOS_EXPORTS: &[&str] = &[
    "rtos_al_ms2tick",
    "rtos_now",
    "rtos_task_get_handle",
    "rtos_get_task_handle",
    "rtos_task_create",
    "rtos_task_delete",
    "rtos_task_suspend",
    "rtos_task_init_notification",
    "rtos_task_wait_notification",
    "rtos_task_notify",
    "rtos_priority_set",
    "rtos_queue_create",
    "rtos_queue_delete",
    "rtos_queue_is_empty",
    "rtos_queue_is_full",
    "rtos_queue_cnt",
    "rtos_queue_write",
    "rtos_queue_read",
    "rtos_semaphore_create",
    "rtos_semaphore_delete",
    "rtos_semaphore_get_count",
    "rtos_semaphore_wait",
    "rtos_semaphore_signal",
    "rtos_mutex_create",
    "rtos_mutex_delete",
    "rtos_mutex_lock",
    "rtos_mutex_unlock",
    "rtos_protect",
    "rtos_unprotect",
    "rtos_trace_task",
    "rtos_trace_mem",
    "vApplicationStackOverflowHook",
    "fhost_tcpip_priority",
    "fhost_wifi_priority",
    "fhost_wifi_priority_high",
    "fhost_cntrl_priority",
    "fhost_rx_priority",
    "fhost_tx_priority",
    "fhost_wpa_priority",
    "fhost_ipc_priority",
    "fhost_iperf_priority",
    "fhost_connect_priority",
    "fhost_tg_priority",
    "fhost_ping_priority",
];
