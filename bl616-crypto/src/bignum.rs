// SPDX-FileCopyrightText: 2026 Roman Valls Guimera <brainstorm@nopcode.org>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Modular exponentiation, for Diffie-Hellman.
//!
//! These two live in the same C object as the hashes, so they have to be
//! replaced alongside them even though they want big-integer arithmetic
//! rather than a digest — see the crate docs on why the set is all or
//! nothing.

use core::ffi::c_int;

/// Placeholder: implemented in the next commit.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_mod_exp(
    _base: *const u8,
    _base_len: usize,
    _power: *const u8,
    _power_len: usize,
    _modulus: *const u8,
    _modulus_len: usize,
    _result: *mut u8,
    _result_len: *mut usize,
) -> c_int {
    -1
}

/// Placeholder: implemented in the next commit.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_dh_init(
    _generator: u8,
    _prime: *const u8,
    _prime_len: usize,
    _privkey: *mut u8,
    _pubkey: *mut u8,
) -> c_int {
    -1
}
