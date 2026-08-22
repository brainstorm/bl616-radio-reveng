// SPDX-FileCopyrightText: 2026 Roman Valls Guimera <brainstorm@nopcode.org>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Modular exponentiation, and the Diffie-Hellman setup built on it.
//!
//! These two live in the same C object as the hashes, so they have to be
//! replaced alongside them even though they want big-integer arithmetic
//! rather than a digest — see the crate docs on why the set is all or
//! nothing.
//!
//! `crypto-bigint` is used rather than an arbitrary-precision library because
//! the exponent here is a Diffie-Hellman private key: the work has to be
//! constant-time with respect to it, and `pow_mod` is.

use alloc::boxed::Box;
use core::ffi::c_int;
use core::slice;

use crypto_bigint::{BoxedUint, Odd};

unsafe extern "C" {
    /// The supplicant's randomness, from `src/utils/os_*.c`. Using it rather
    /// than a private source keeps DH keys on whatever entropy the rest of
    /// the supplicant already trusts.
    fn os_get_random(buf: *mut u8, len: usize) -> c_int;
}

/// Limbs are machine words, so a precision has to be a whole number of them.
/// 64 is a multiple of both the 32-bit target's limb and the host's, which
/// keeps the tests meaningful.
fn precision_for(bytes: usize) -> u32 {
    ((bytes as u32) * 8).next_multiple_of(64).max(64)
}

/// `result = base^power mod modulus`, big-endian throughout.
///
/// Matches what the mbedTLS implementation does rather than what the header
/// says, because that is what the supplicant is working against today:
/// `mbedtls_mpi_write_binary` writes **exactly** `*result_len` bytes,
/// zero-padded on the left, and leaves `*result_len` alone. A caller that
/// passes a buffer too small for the value gets an error, not a truncation.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_mod_exp(
    base: *const u8,
    base_len: usize,
    power: *const u8,
    power_len: usize,
    modulus: *const u8,
    modulus_len: usize,
    result: *mut u8,
    result_len: *mut usize,
) -> c_int {
    if base.is_null()
        || power.is_null()
        || modulus.is_null()
        || result.is_null()
        || result_len.is_null()
        || modulus_len == 0
    {
        return -1;
    }
    let base = unsafe { slice::from_raw_parts(base, base_len) };
    let power = unsafe { slice::from_raw_parts(power, power_len) };
    let modulus = unsafe { slice::from_raw_parts(modulus, modulus_len) };
    let out_len = unsafe { *result_len };

    // The base can legitimately be wider than the modulus, so carry enough
    // precision for it and let the reduction inside pow_mod deal with it.
    let prec = precision_for(base_len.max(modulus_len));
    let (Ok(b), Ok(m)) = (
        BoxedUint::from_be_slice(base, prec),
        BoxedUint::from_be_slice(modulus, prec),
    ) else {
        return -1;
    };
    let Ok(e) = BoxedUint::from_be_slice(power, precision_for(power_len)) else {
        return -1;
    };

    // Montgomery arithmetic needs an odd modulus. Every modulus this is
    // called with is a Diffie-Hellman or RSA one, so it is an odd prime or a
    // product of them; refusing is better than quietly returning nonsense.
    let m: Option<Odd<BoxedUint>> = Odd::new(m).into();
    let Some(m) = m else {
        return -1;
    };

    let value = b.pow_mod(&e, &m);
    let bytes: Box<[u8]> = value.to_be_bytes();

    // Left-pad, or refuse if the value genuinely does not fit.
    let significant = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    let needed = bytes.len() - significant;
    if needed > out_len {
        return -1;
    }
    let pad = out_len - needed;
    unsafe {
        core::ptr::write_bytes(result, 0, pad);
        core::ptr::copy_nonoverlapping(bytes.as_ptr().add(significant), result.add(pad), needed);
    }
    0
}

/// Pick a Diffie-Hellman private key and derive the public value.
///
/// `privkey` and `pubkey` are both `prime_len` bytes. The private value is
/// forced below the prime the same crude way the C does — by clearing the top
/// byte when it compares greater — which is worth keeping rather than
/// improving, because the peer's implementation is not the thing being
/// changed here.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_dh_init(
    generator: u8,
    prime: *const u8,
    prime_len: usize,
    privkey: *mut u8,
    pubkey: *mut u8,
) -> c_int {
    if prime.is_null() || privkey.is_null() || pubkey.is_null() || prime_len == 0 {
        return -1;
    }
    if unsafe { os_get_random(privkey, prime_len) } < 0 {
        return -1;
    }

    let priv_slice = unsafe { slice::from_raw_parts_mut(privkey, prime_len) };
    let prime_slice = unsafe { slice::from_raw_parts(prime, prime_len) };
    if &priv_slice[..] > prime_slice {
        priv_slice[0] = 0;
    }

    let mut pubkey_len = prime_len;
    let g = [generator];
    unsafe {
        crypto_mod_exp(
            g.as_ptr(),
            1,
            privkey,
            prime_len,
            prime,
            prime_len,
            pubkey,
            &mut pubkey_len,
        )
    }
}
