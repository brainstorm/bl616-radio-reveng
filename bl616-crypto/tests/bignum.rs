// SPDX-FileCopyrightText: 2026 Roman Valls Guimera <brainstorm@nopcode.org>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Modular exponentiation and Diffie-Hellman.

use bl616_crypto::{crypto_dh_init, crypto_mod_exp};

/// The supplicant's RNG, which the crate calls but does not provide. A
/// counter is fine here: nothing below depends on the values being
/// unpredictable.
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

/// Textbook values, a base wider than the modulus (reduced rather than
/// rejected), and the fixed-width zero-padded output the mbedTLS
/// implementation gives -- callers size the buffer and expect that width.
#[test]
fn modular_exponentiation() {
    assert_eq!(mod_exp(&[5], &[6], &[23], 1).unwrap(), vec![8]);
    assert_eq!(mod_exp(&[2], &[10], &hex("03e9"), 2).unwrap(), hex("0017"));
    // An exponent of zero is one, whatever the base.
    assert_eq!(mod_exp(&hex("beef"), &[0], &[23], 1).unwrap(), vec![1]);
    // 65535 mod 23 = 8, and 8^2 = 64 = 18 (mod 23).
    assert_eq!(mod_exp(&hex("ffff"), &[2], &[23], 1).unwrap(), vec![18]);
    assert_eq!(mod_exp(&[5], &[6], &[23], 8).unwrap(), vec![0, 0, 0, 0, 0, 0, 0, 8]);
}

/// A buffer too small for the value is an error, not a truncation. An even
/// modulus is refused: Montgomery arithmetic needs an odd one, every real
/// caller passes a DH or RSA modulus, and a wrong answer would be worse.
#[test]
fn modexp_refusals() {
    let m = hex("03e9");
    let mut out = [0u8; 1];
    let mut len = 0usize;
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

    assert!(mod_exp(&[5], &[6], &[24], 1).is_none());
}

/// `(g^a)^b == (g^b)^a`, which is the whole point.
#[test]
fn diffie_hellman_exchange() {
    let p = hex(GROUP5_PRIME);
    let a = hex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
    let b = hex("fedcba98765432100123456789abcdeffedcba98765432100123456789abcdef");

    let big_a = mod_exp(&[2], &a, &p, p.len()).unwrap();
    let big_b = mod_exp(&[2], &b, &p, p.len()).unwrap();
    assert_ne!(big_a, big_b);

    let secret_1 = mod_exp(&big_a, &b, &p, p.len()).unwrap();
    let secret_2 = mod_exp(&big_b, &a, &p, p.len()).unwrap();
    assert_eq!(secret_1, secret_2);
    assert_eq!(secret_1.len(), p.len(), "fixed width, left-padded");
    assert!(secret_1.iter().any(|&x| x != 0), "not a degenerate zero");
}

/// The public value is exactly `g^priv mod p`, and the private value stays
/// below the prime -- the C clears the top byte when it compares greater, so
/// the second case uses a prime starting low enough to take that path.
#[test]
fn dh_init() {
    let p = hex(GROUP5_PRIME);
    let mut privkey = vec![0u8; p.len()];
    let mut pubkey = vec![0u8; p.len()];
    let rc =
        unsafe { crypto_dh_init(2, p.as_ptr(), p.len(), privkey.as_mut_ptr(), pubkey.as_mut_ptr()) };
    assert_eq!(rc, 0);
    assert!(privkey.iter().any(|&x| x != 0));
    assert_eq!(pubkey, mod_exp(&[2], &privkey, &p, p.len()).unwrap());

    let low = hex("0100000000000000000000000000000000000000000000000000000000000003");
    let mut privkey = vec![0u8; low.len()];
    let mut pubkey = vec![0u8; low.len()];
    let rc = unsafe {
        crypto_dh_init(2, low.as_ptr(), low.len(), privkey.as_mut_ptr(), pubkey.as_mut_ptr())
    };
    assert_eq!(rc, 0);
    assert!(privkey[..] < low[..]);
}

#[test]
fn null_arguments() {
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
    assert_eq!(
        unsafe { crypto_dh_init(2, core::ptr::null(), 0, out.as_mut_ptr(), out.as_mut_ptr()) },
        -1
    );
}
