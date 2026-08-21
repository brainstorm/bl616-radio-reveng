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
}
