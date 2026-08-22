// SPDX-FileCopyrightText: 2026 Roman Valls Guimera <brainstorm@nopcode.org>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Modular exponentiation and Diffie-Hellman.

use bl616_crypto::{crypto_dh_init, crypto_mod_exp};

/// The supplicant's RNG, which the crate calls but does not provide. A test
/// binary has to stand in for it; a counter is fine here because none of
/// these tests depend on the values being unpredictable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn os_get_random(buf: *mut u8, len: usize) -> i32 {
    let s = unsafe { core::slice::from_raw_parts_mut(buf, len) };
    for (i, b) in s.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(7).wrapping_add(3);
    }
    0
}

fn hex(s: &str) -> Vec<u8> {
    let s: String = s.split_whitespace().collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn mod_exp(base: &[u8], power: &[u8], modulus: &[u8], out_len: usize) -> Option<Vec<u8>> {
    let mut out = vec![0u8; out_len];
    let mut len = out_len;
    let rc = unsafe {
        crypto_mod_exp(
            base.as_ptr(),
            base.len(),
            power.as_ptr(),
            power.len(),
            modulus.as_ptr(),
            modulus.len(),
            out.as_mut_ptr(),
            &mut len,
        )
    };
    (rc == 0).then_some(out)
}

/// RFC 3526 group 5, the 1536-bit MODP group the supplicant uses.
const GROUP5_PRIME: &str = "
    FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
    29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
    EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
    E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
    EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
    C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
    83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
    670C354E 4ABC9804 F1746C08 CA237327 FFFFFFFF FFFFFFFF";

#[test]
fn small_values_are_right() {
    // The textbook example: 5^6 mod 23 = 8.
    assert_eq!(mod_exp(&[5], &[6], &[23], 1).unwrap(), vec![8]);
    // 2^10 mod 1001 = 23.
    assert_eq!(mod_exp(&[2], &[10], &hex("03e9"), 2).unwrap(), hex("0017"));
    // An exponent of zero is one, whatever the base.
    assert_eq!(mod_exp(&hex("beef"), &[0], &[23], 1).unwrap(), vec![1]);
}

#[test]
fn a_base_wider_than_the_modulus_is_reduced_not_rejected() {
    // 65535 mod 23 = 8, and 8^2 = 64 = 18 (mod 23).
    assert_eq!(mod_exp(&hex("ffff"), &[2], &[23], 1).unwrap(), vec![18]);
}

#[test]
fn the_result_is_left_padded_to_the_buffer_it_was_given() {
    // mbedtls_mpi_write_binary writes the full width, zero-padded, and this
    // has to match: callers size the buffer and expect a fixed-width answer.
    let out = mod_exp(&[5], &[6], &[23], 8).unwrap();
    assert_eq!(out, vec![0, 0, 0, 0, 0, 0, 0, 8]);
}

#[test]
fn a_buffer_too_small_for_the_value_is_an_error() {
    // 2^10 mod 1001 = 23, which needs one byte; ask for zero.
    let mut out = [0u8; 1];
    let mut len = 0usize;
    let m = hex("03e9");
    let rc = unsafe {
        crypto_mod_exp(
            [2u8].as_ptr(),
            1,
            [10u8].as_ptr(),
            1,
            m.as_ptr(),
            m.len(),
            out.as_mut_ptr(),
            &mut len,
        )
    };
    assert_eq!(rc, -1);
}

#[test]
fn an_even_modulus_is_refused_rather_than_answered_wrongly() {
    // Montgomery arithmetic needs an odd modulus. Every real caller passes a
    // DH or RSA modulus, which is odd; a wrong answer would be worse than a
    // refusal.
    assert!(mod_exp(&[5], &[6], &[24], 1).is_none());
}

#[test]
fn a_diffie_hellman_exchange_agrees_on_both_sides() {
    let p = hex(GROUP5_PRIME);
    let g = [2u8];
    let a = hex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
    let b = hex("fedcba98765432100123456789abcdeffedcba98765432100123456789abcdef");

    let big_a = mod_exp(&g, &a, &p, p.len()).unwrap();
    let big_b = mod_exp(&g, &b, &p, p.len()).unwrap();
    assert_ne!(big_a, big_b);

    // (g^a)^b == (g^b)^a, which is the whole point.
    let secret_1 = mod_exp(&big_a, &b, &p, p.len()).unwrap();
    let secret_2 = mod_exp(&big_b, &a, &p, p.len()).unwrap();
    assert_eq!(secret_1, secret_2);
    assert_eq!(secret_1.len(), p.len(), "fixed width, left-padded");
    assert!(secret_1.iter().any(|&x| x != 0), "not a degenerate zero");
}

#[test]
fn dh_init_returns_a_public_value_matching_its_private_one() {
    let p = hex(GROUP5_PRIME);
    let mut privkey = vec![0u8; p.len()];
    let mut pubkey = vec![0u8; p.len()];

    let rc = unsafe {
        crypto_dh_init(2, p.as_ptr(), p.len(), privkey.as_mut_ptr(), pubkey.as_mut_ptr())
    };
    assert_eq!(rc, 0);
    assert!(privkey.iter().any(|&x| x != 0), "a private key was chosen");

    // The public value must be exactly g^priv mod p.
    let expected = mod_exp(&[2], &privkey, &p, p.len()).unwrap();
    assert_eq!(pubkey, expected);
}

#[test]
fn dh_init_keeps_the_private_value_below_the_prime() {
    // The C clears the top byte when the random value compares greater than
    // the prime. Group 5 starts with 0xFF, so a random value rarely trips it;
    // use a prime that starts low so the path is actually taken.
    let p = hex("0100000000000000000000000000000000000000000000000000000000000003");
    let mut privkey = vec![0u8; p.len()];
    let mut pubkey = vec![0u8; p.len()];
    let rc = unsafe {
        crypto_dh_init(2, p.as_ptr(), p.len(), privkey.as_mut_ptr(), pubkey.as_mut_ptr())
    };
    assert_eq!(rc, 0);
    assert!(privkey[..] < p[..], "private value must be below the prime");
}

#[test]
fn null_arguments_are_errors_not_crashes() {
    let mut out = [0u8; 4];
    let mut len = 4usize;
    let rc = unsafe {
        crypto_mod_exp(
            core::ptr::null(),
            1,
            [1u8].as_ptr(),
            1,
            [23u8].as_ptr(),
            1,
            out.as_mut_ptr(),
            &mut len,
        )
    };
    assert_eq!(rc, -1);
    let rc = unsafe {
        crypto_dh_init(2, core::ptr::null(), 0, out.as_mut_ptr(), out.as_mut_ptr())
    };
    assert_eq!(rc, -1);
}
