// SPDX-FileCopyrightText: 2026 Roman Valls Guimera <brainstorm@nopcode.org>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Published test vectors, plus the behaviour around them that a C ABI
//! replacement gets wrong: scatter/gather input, short buffers, null
//! contexts.
//!
//! Sources: FIPS-197 (AES), NIST SP 800-38A (CBC, CTR), RFC 1321/3174/6234
//! (digests), RFC 2202 and 4231 (HMAC).

use bl616_crypto::*;

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// Call a `*_vector` entry point with a single buffer.
fn digest(
    f: unsafe extern "C" fn(usize, *const *const u8, *const usize, *mut u8) -> i32,
    data: &[u8],
    out: &mut [u8],
) {
    let addr = [data.as_ptr()];
    let len = [data.len()];
    assert_eq!(unsafe { f(1, addr.as_ptr(), len.as_ptr(), out.as_mut_ptr()) }, 0);
}

const SHA1_ABC: &str = "a9993e364706816aba3e25717850c26c9cd0d89d";

#[test]
fn digests() {
    let mut out = [0u8; 64];
    digest(md5_vector, b"abc", &mut out);
    assert_eq!(&out[..16], &hex("900150983cd24fb0d6963f7d28e17f72")[..]);
    digest(sha1_vector, b"abc", &mut out);
    assert_eq!(&out[..20], &hex(SHA1_ABC)[..]);
    digest(sha256_vector, b"abc", &mut out);
    assert_eq!(
        &out[..32],
        &hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")[..]
    );
    digest(sha384_vector, b"abc", &mut out);
    assert_eq!(&out[..48], &hex("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7")[..]);
    digest(sha512_vector, b"abc", &mut out);
    assert_eq!(&out[..64], &hex("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f")[..]);
}

/// The supplicant nearly always passes several pieces, and a zero-length one
/// with a null pointer is legal -- a wild read if the length is not checked
/// first.
#[test]
fn scatter_gather_input() {
    let mut out = [0u8; 20];
    let parts: [*const u8; 3] = [b"a".as_ptr(), b"b".as_ptr(), b"c".as_ptr()];
    let lens = [1usize, 1, 1];
    assert_eq!(
        unsafe { sha1_vector(3, parts.as_ptr(), lens.as_ptr(), out.as_mut_ptr()) },
        0
    );
    assert_eq!(&out[..], &hex(SHA1_ABC)[..]);

    let with_empty: [*const u8; 2] = [b"abc".as_ptr(), core::ptr::null()];
    let lens = [3usize, 0];
    assert_eq!(
        unsafe { sha1_vector(2, with_empty.as_ptr(), lens.as_ptr(), out.as_mut_ptr()) },
        0
    );
    assert_eq!(&out[..], &hex(SHA1_ABC)[..]);
}

/// RFC 2202 and 4231, including the over-long key that must be hashed down
/// rather than rejected.
#[test]
fn hmacs() {
    let key20 = vec![0x0bu8; 20];
    let data = b"Hi There";
    let mut out = [0u8; 64];

    let k16 = vec![0x0bu8; 16];
    assert_eq!(
        unsafe { hmac_md5(k16.as_ptr(), 16, data.as_ptr(), data.len(), out.as_mut_ptr()) },
        0
    );
    assert_eq!(&out[..16], &hex("9294727a3638bb1c13f48ef8158bfc9d")[..]);

    assert_eq!(
        unsafe { hmac_sha1(key20.as_ptr(), 20, data.as_ptr(), data.len(), out.as_mut_ptr()) },
        0
    );
    assert_eq!(&out[..20], &hex("b617318655057264e28bc0b6fb378c8ef146be00")[..]);

    assert_eq!(
        unsafe { hmac_sha256(key20.as_ptr(), 20, data.as_ptr(), data.len(), out.as_mut_ptr()) },
        0
    );
    assert_eq!(
        &out[..32],
        &hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")[..]
    );

    assert_eq!(
        unsafe { hmac_sha384(key20.as_ptr(), 20, data.as_ptr(), data.len(), out.as_mut_ptr()) },
        0
    );
    assert_eq!(&out[..48], &hex("afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6")[..]);

    let long = vec![0xaau8; 131];
    let msg = b"Test Using Larger Than Block-Size Key - Hash Key First";
    assert_eq!(
        unsafe { hmac_sha256(long.as_ptr(), 131, msg.as_ptr(), msg.len(), out.as_mut_ptr()) },
        0
    );
    assert_eq!(
        &out[..32],
        &hex("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54")[..]
    );
}

/// FIPS-197 for all three key lengths, and a refusal for anything else rather
/// than a guess.
#[test]
fn aes_block() {
    let plain = hex("00112233445566778899aabbccddeeff");
    for (key_hex, want_hex) in [
        ("000102030405060708090a0b0c0d0e0f", "69c4e0d86a7b0430d8cdb78070b4c55a"),
        ("000102030405060708090a0b0c0d0e0f1011121314151617", "dda97ca4864cdfe06eaf70a0ec0d7191"),
        ("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "8ea2b7ca516745bfeafc49904b496089"),
    ] {
        let key = hex(key_hex);
        let ctx = unsafe { aes_encrypt_init(key.as_ptr(), key.len()) };
        assert!(!ctx.is_null());
        let mut ct = [0u8; 16];
        assert_eq!(unsafe { aes_encrypt(ctx, plain.as_ptr(), ct.as_mut_ptr()) }, 0);
        unsafe { aes_encrypt_deinit(ctx) };
        assert_eq!(&ct[..], &hex(want_hex)[..]);

        let ctx = unsafe { aes_decrypt_init(key.as_ptr(), key.len()) };
        let mut pt = [0u8; 16];
        assert_eq!(unsafe { aes_decrypt(ctx, ct.as_ptr(), pt.as_mut_ptr()) }, 0);
        unsafe { aes_decrypt_deinit(ctx) };
        assert_eq!(&pt[..], &plain[..]);
    }

    for len in [0usize, 8, 15, 17, 33] {
        let key = vec![0u8; len.max(1)];
        assert!(unsafe { aes_encrypt_init(key.as_ptr(), len) }.is_null(), "length {len}");
    }
}

/// SP 800-38A F.2 and F.5. CBC takes whole blocks only -- the caller does its
/// own padding -- while CTR is a stream and must accept any length.
#[test]
fn aes_modes() {
    let key = hex("2b7e151628aed2a6abf7158809cf4f3c");
    let iv = hex("000102030405060708090a0b0c0d0e0f");
    let plain = hex("6bc1bee22e409f96e93d7e117393172a");

    let mut buf = plain.clone();
    assert_eq!(
        unsafe { aes_128_cbc_encrypt(key.as_ptr(), iv.as_ptr(), buf.as_mut_ptr(), buf.len()) },
        0
    );
    assert_eq!(buf, hex("7649abac8119b246cee98e9b12e9197d"));
    assert_eq!(
        unsafe { aes_128_cbc_decrypt(key.as_ptr(), iv.as_ptr(), buf.as_mut_ptr(), buf.len()) },
        0
    );
    assert_eq!(buf, plain);

    let mut partial = [0u8; 20];
    assert_eq!(
        unsafe { aes_128_cbc_encrypt(key.as_ptr(), iv.as_ptr(), partial.as_mut_ptr(), 20) },
        -1
    );

    let counter = hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    let mut buf = plain.clone();
    assert_eq!(
        unsafe { aes_128_ctr_encrypt(key.as_ptr(), counter.as_ptr(), buf.as_mut_ptr(), buf.len()) },
        0
    );
    assert_eq!(buf, hex("874d6191b620e3261bef6864990db6ce"));
    // CTR is its own inverse.
    assert_eq!(
        unsafe { aes_128_ctr_encrypt(key.as_ptr(), counter.as_ptr(), buf.as_mut_ptr(), buf.len()) },
        0
    );
    assert_eq!(buf, plain);

    let mut short = hex("6bc1bee22e409f96");
    assert_eq!(
        unsafe { aes_128_ctr_encrypt(key.as_ptr(), counter.as_ptr(), short.as_mut_ptr(), 8) },
        0
    );
    assert_eq!(short, hex("874d6191b620e326"));
}

/// Streaming must agree with the one-shot form, for a plain hash and a keyed
/// one.
#[test]
fn streaming_hashes() {
    const SHA1: u8 = 1;
    const HMAC_SHA256: u8 = 5;

    let ctx = unsafe { crypto_hash_init(SHA1, core::ptr::null(), 0) };
    assert!(!ctx.is_null());
    unsafe {
        crypto_hash_update(ctx, b"a".as_ptr(), 1);
        crypto_hash_update(ctx, b"bc".as_ptr(), 2);
    }
    let mut out = [0u8; 32];
    let mut len = 20usize;
    assert_eq!(unsafe { crypto_hash_finish(ctx, out.as_mut_ptr(), &mut len) }, 0);
    assert_eq!(len, 20);
    assert_eq!(&out[..20], &hex(SHA1_ABC)[..]);

    let key = vec![0x0bu8; 20];
    let ctx = unsafe { crypto_hash_init(HMAC_SHA256, key.as_ptr(), key.len()) };
    unsafe {
        crypto_hash_update(ctx, b"Hi ".as_ptr(), 3);
        crypto_hash_update(ctx, b"There".as_ptr(), 5);
    }
    let mut len = 32usize;
    assert_eq!(unsafe { crypto_hash_finish(ctx, out.as_mut_ptr(), &mut len) }, 0);
    assert_eq!(
        &out[..],
        &hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")[..]
    );
}

/// A short buffer reports the size it needed and writes nothing; discarding a
/// context still frees it; an unknown algorithm is refused.
#[test]
fn hash_context_contract() {
    const SHA256: u8 = 4;

    let ctx = unsafe { crypto_hash_init(SHA256, core::ptr::null(), 0) };
    let mut out = [0u8; 8];
    let mut len = out.len();
    assert_eq!(unsafe { crypto_hash_finish(ctx, out.as_mut_ptr(), &mut len) }, -1);
    assert_eq!(len, 32);
    assert_eq!(out, [0u8; 8]);

    // crypto_hash_finish(ctx, NULL, NULL) is how the supplicant discards one.
    let ctx = unsafe { crypto_hash_init(SHA256, core::ptr::null(), 0) };
    assert_eq!(
        unsafe { crypto_hash_finish(ctx, core::ptr::null_mut(), core::ptr::null_mut()) },
        0
    );

    for alg in [8u8, 9, 200] {
        assert!(unsafe { crypto_hash_init(alg, core::ptr::null(), 0) }.is_null(), "alg {alg}");
    }
}

/// AES round trips; the broken ciphers the supplicant can ask for are
/// refused rather than quietly substituted.
#[test]
fn cipher_contract() {
    const AES: u8 = 1;
    let key = hex("2b7e151628aed2a6abf7158809cf4f3c");
    let iv = hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    let plain = b"the quick brown fox";

    let enc = unsafe { crypto_cipher_init(AES, iv.as_ptr(), key.as_ptr(), key.len()) };
    assert!(!enc.is_null());
    let mut ct = vec![0u8; plain.len()];
    assert_eq!(
        unsafe { crypto_cipher_encrypt(enc, plain.as_ptr(), ct.as_mut_ptr(), plain.len()) },
        0
    );
    unsafe { crypto_cipher_deinit(enc) };
    assert_ne!(&ct[..], &plain[..]);

    let dec = unsafe { crypto_cipher_init(AES, iv.as_ptr(), key.as_ptr(), key.len()) };
    let mut pt = vec![0u8; ct.len()];
    assert_eq!(
        unsafe { crypto_cipher_decrypt(dec, ct.as_ptr(), pt.as_mut_ptr(), ct.len()) },
        0
    );
    unsafe { crypto_cipher_deinit(dec) };
    assert_eq!(&pt[..], &plain[..]);

    // 3DES, DES, RC2, RC4: none selected here, all broken.
    for alg in [0u8, 2, 3, 4, 5] {
        assert!(
            unsafe { crypto_cipher_init(alg, iv.as_ptr(), key.as_ptr(), key.len()) }.is_null(),
            "alg {alg}"
        );
    }
}

/// A null context is an error, and freeing null is a no-op, as in the C.
#[test]
fn null_contexts() {
    let mut buf = [0u8; 16];
    assert_eq!(unsafe { aes_encrypt(core::ptr::null_mut(), buf.as_ptr(), buf.as_mut_ptr()) }, -1);
    assert_eq!(unsafe { aes_decrypt(core::ptr::null_mut(), buf.as_ptr(), buf.as_mut_ptr()) }, -1);
    assert_eq!(
        unsafe { crypto_cipher_encrypt(core::ptr::null_mut(), buf.as_ptr(), buf.as_mut_ptr(), 16) },
        -1
    );
    unsafe {
        aes_encrypt_deinit(core::ptr::null_mut());
        crypto_cipher_deinit(core::ptr::null_mut());
    }
}

/// The Rust wrappers and the C entry points are the same primitives; a
/// divergence would be invisible until something used the wrong one.
#[test]
fn rust_wrappers_match_the_c_abi() {
    let mut via_c = [0u8; 32];
    digest(sha256_vector, b"abc", &mut via_c);
    assert_eq!(bl616_crypto::hash::sha256(b"abc"), via_c);

    let key = vec![0x0bu8; 20];
    let data = b"Hi There";
    let mut via_c = [0u8; 32];
    unsafe {
        hmac_sha256(key.as_ptr(), 20, data.as_ptr(), data.len(), via_c.as_mut_ptr());
    }
    assert_eq!(bl616_crypto::hash::hmac_sha256(&key, data), via_c);

    let mut via_c = [0u8; 20];
    digest(sha1_vector, b"abc", &mut via_c);
    assert_eq!(bl616_crypto::hash::sha1(b"abc"), via_c);
}
