// SPDX-FileCopyrightText: 2026 Roman Valls Guimera <brainstorm@nopcode.org>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Published test vectors for the crypto backend.
//!
//! Every entry point here is a pure function with a standard answer, so the
//! whole replacement can be verified before the radio is involved. Sources
//! are named per test: FIPS-197 for AES, NIST SP 800-38A for the modes,
//! RFC 1321/3174/6234 for the digests, RFC 2202 and 4231 for the HMACs.

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
    let rc = unsafe { f(1, addr.as_ptr(), len.as_ptr(), out.as_mut_ptr()) };
    assert_eq!(rc, 0);
}

#[test]
fn digests_match_the_standard_answers() {
    let mut out = [0u8; 64];

    digest(md5_vector, b"abc", &mut out);
    assert_eq!(&out[..16], &hex("900150983cd24fb0d6963f7d28e17f72")[..], "MD5, RFC 1321");

    digest(sha1_vector, b"abc", &mut out);
    assert_eq!(
        &out[..20],
        &hex("a9993e364706816aba3e25717850c26c9cd0d89d")[..],
        "SHA-1, RFC 3174"
    );

    digest(sha256_vector, b"abc", &mut out);
    assert_eq!(
        &out[..32],
        &hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")[..],
        "SHA-256"
    );

    digest(sha384_vector, b"abc", &mut out);
    assert_eq!(
        &out[..48],
        &hex("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7")[..],
        "SHA-384"
    );

    digest(sha512_vector, b"abc", &mut out);
    assert_eq!(
        &out[..64],
        &hex("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f")[..],
        "SHA-512"
    );
}

#[test]
fn a_scattered_message_hashes_like_a_contiguous_one() {
    // The supplicant almost always passes several pieces; getting the
    // concatenation wrong is invisible against single-buffer tests.
    let parts: [&[u8]; 3] = [b"a", b"b", b"c"];
    let addr: Vec<*const u8> = parts.iter().map(|p| p.as_ptr()).collect();
    let len: Vec<usize> = parts.iter().map(|p| p.len()).collect();
    let mut out = [0u8; 20];
    let rc = unsafe { sha1_vector(3, addr.as_ptr(), len.as_ptr(), out.as_mut_ptr()) };
    assert_eq!(rc, 0);
    assert_eq!(&out[..], &hex("a9993e364706816aba3e25717850c26c9cd0d89d")[..]);
}

#[test]
fn an_empty_element_is_not_a_null_dereference() {
    // A zero-length piece with a null pointer is legal in this API and turns
    // into a wild read if the length is not checked first.
    let parts: [*const u8; 2] = [b"abc".as_ptr(), core::ptr::null()];
    let len = [3usize, 0];
    let mut out = [0u8; 20];
    let rc = unsafe { sha1_vector(2, parts.as_ptr(), len.as_ptr(), out.as_mut_ptr()) };
    assert_eq!(rc, 0);
    assert_eq!(&out[..], &hex("a9993e364706816aba3e25717850c26c9cd0d89d")[..]);
}

#[test]
fn hmacs_match_rfc_2202_and_4231() {
    let key20 = vec![0x0bu8; 20];
    let key16 = vec![0x0bu8; 16];
    let data = b"Hi There";
    let mut out = [0u8; 64];

    let rc = unsafe {
        hmac_md5(key16.as_ptr(), 16, data.as_ptr(), data.len(), out.as_mut_ptr())
    };
    assert_eq!(rc, 0);
    assert_eq!(&out[..16], &hex("9294727a3638bb1c13f48ef8158bfc9d")[..], "RFC 2202 #1");

    let rc = unsafe {
        hmac_sha1(key20.as_ptr(), 20, data.as_ptr(), data.len(), out.as_mut_ptr())
    };
    assert_eq!(rc, 0);
    assert_eq!(
        &out[..20],
        &hex("b617318655057264e28bc0b6fb378c8ef146be00")[..],
        "RFC 2202 #1"
    );

    let rc = unsafe {
        hmac_sha256(key20.as_ptr(), 20, data.as_ptr(), data.len(), out.as_mut_ptr())
    };
    assert_eq!(rc, 0);
    assert_eq!(
        &out[..32],
        &hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")[..],
        "RFC 4231 #1"
    );

    let rc = unsafe {
        hmac_sha384(key20.as_ptr(), 20, data.as_ptr(), data.len(), out.as_mut_ptr())
    };
    assert_eq!(rc, 0);
    assert_eq!(
        &out[..48],
        &hex("afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6")[..],
        "RFC 4231 #1"
    );
}

#[test]
fn a_key_longer_than_the_block_is_hashed_down() {
    // RFC 4231 #6: 131-byte key, which HMAC must reduce rather than reject.
    let key = vec![0xaau8; 131];
    let data = b"Test Using Larger Than Block-Size Key - Hash Key First";
    let mut out = [0u8; 32];
    let rc = unsafe {
        hmac_sha256(key.as_ptr(), key.len(), data.as_ptr(), data.len(), out.as_mut_ptr())
    };
    assert_eq!(rc, 0);
    assert_eq!(
        &out[..],
        &hex("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54")[..]
    );
}

#[test]
fn aes_single_block_matches_fips_197() {
    let plain = hex("00112233445566778899aabbccddeeff");
    for (key_hex, want_hex) in [
        ("000102030405060708090a0b0c0d0e0f", "69c4e0d86a7b0430d8cdb78070b4c55a"),
        (
            "000102030405060708090a0b0c0d0e0f1011121314151617",
            "dda97ca4864cdfe06eaf70a0ec0d7191",
        ),
        (
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "8ea2b7ca516745bfeafc49904b496089",
        ),
    ] {
        let key = hex(key_hex);
        let want = hex(want_hex);

        let ctx = unsafe { aes_encrypt_init(key.as_ptr(), key.len()) };
        assert!(!ctx.is_null(), "key length {}", key.len());
        let mut ct = [0u8; 16];
        assert_eq!(unsafe { aes_encrypt(ctx, plain.as_ptr(), ct.as_mut_ptr()) }, 0);
        unsafe { aes_encrypt_deinit(ctx) };
        assert_eq!(&ct[..], &want[..], "encrypt, {} bit", key.len() * 8);

        let ctx = unsafe { aes_decrypt_init(key.as_ptr(), key.len()) };
        let mut pt = [0u8; 16];
        assert_eq!(unsafe { aes_decrypt(ctx, ct.as_ptr(), pt.as_mut_ptr()) }, 0);
        unsafe { aes_decrypt_deinit(ctx) };
        assert_eq!(&pt[..], &plain[..], "decrypt, {} bit", key.len() * 8);
    }
}

#[test]
fn an_unusable_aes_key_length_is_refused_not_guessed() {
    for len in [0usize, 8, 15, 17, 33] {
        let key = vec![0u8; len.max(1)];
        let ctx = unsafe { aes_encrypt_init(key.as_ptr(), len) };
        assert!(ctx.is_null(), "length {len} must be refused");
    }
}

#[test]
fn cbc_matches_sp_800_38a() {
    let key = hex("2b7e151628aed2a6abf7158809cf4f3c");
    let iv = hex("000102030405060708090a0b0c0d0e0f");
    let plain = hex("6bc1bee22e409f96e93d7e117393172a");
    let want = hex("7649abac8119b246cee98e9b12e9197d");

    let mut buf = plain.clone();
    let rc = unsafe { aes_128_cbc_encrypt(key.as_ptr(), iv.as_ptr(), buf.as_mut_ptr(), buf.len()) };
    assert_eq!(rc, 0);
    assert_eq!(buf, want, "F.2.1 CBC-AES128.Encrypt");

    let rc = unsafe { aes_128_cbc_decrypt(key.as_ptr(), iv.as_ptr(), buf.as_mut_ptr(), buf.len()) };
    assert_eq!(rc, 0);
    assert_eq!(buf, plain, "F.2.2 CBC-AES128.Decrypt");
}

#[test]
fn a_partial_cbc_block_is_refused() {
    let key = hex("2b7e151628aed2a6abf7158809cf4f3c");
    let iv = hex("000102030405060708090a0b0c0d0e0f");
    let mut buf = [0u8; 20];
    let rc = unsafe { aes_128_cbc_encrypt(key.as_ptr(), iv.as_ptr(), buf.as_mut_ptr(), 20) };
    assert_eq!(rc, -1, "CBC cannot pad here; the caller does that");
}

#[test]
fn ctr_matches_sp_800_38a() {
    let key = hex("2b7e151628aed2a6abf7158809cf4f3c");
    let counter = hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    let plain = hex("6bc1bee22e409f96e93d7e117393172a");
    let want = hex("874d6191b620e3261bef6864990db6ce");

    let mut buf = plain.clone();
    let rc =
        unsafe { aes_128_ctr_encrypt(key.as_ptr(), counter.as_ptr(), buf.as_mut_ptr(), buf.len()) };
    assert_eq!(rc, 0);
    assert_eq!(buf, want, "F.5.1 CTR-AES128.Encrypt");

    // CTR is its own inverse.
    let rc =
        unsafe { aes_128_ctr_encrypt(key.as_ptr(), counter.as_ptr(), buf.as_mut_ptr(), buf.len()) };
    assert_eq!(rc, 0);
    assert_eq!(buf, plain);
}

#[test]
fn ctr_handles_a_length_that_is_not_a_whole_block() {
    // Unlike CBC, CTR is a stream and must accept any length.
    let key = hex("2b7e151628aed2a6abf7158809cf4f3c");
    let counter = hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    let want = hex("874d6191b620e326");
    let mut buf = hex("6bc1bee22e409f96");
    let rc = unsafe { aes_128_ctr_encrypt(key.as_ptr(), counter.as_ptr(), buf.as_mut_ptr(), 8) };
    assert_eq!(rc, 0);
    assert_eq!(buf, want);
}

#[test]
fn streaming_hash_agrees_with_the_one_shot_form() {
    const SHA1: u8 = 1;
    let ctx = unsafe { crypto_hash_init(SHA1, core::ptr::null(), 0) };
    assert!(!ctx.is_null());
    unsafe {
        crypto_hash_update(ctx, b"a".as_ptr(), 1);
        crypto_hash_update(ctx, b"bc".as_ptr(), 2);
    }
    let mut out = [0u8; 20];
    let mut len = out.len();
    let rc = unsafe { crypto_hash_finish(ctx, out.as_mut_ptr(), &mut len) };
    assert_eq!(rc, 0);
    assert_eq!(len, 20);
    assert_eq!(&out[..], &hex("a9993e364706816aba3e25717850c26c9cd0d89d")[..]);
}

#[test]
fn streaming_hmac_agrees_with_the_one_shot_form() {
    const HMAC_SHA256: u8 = 5;
    let key = vec![0x0bu8; 20];
    let ctx = unsafe { crypto_hash_init(HMAC_SHA256, key.as_ptr(), key.len()) };
    assert!(!ctx.is_null());
    unsafe {
        crypto_hash_update(ctx, b"Hi ".as_ptr(), 3);
        crypto_hash_update(ctx, b"There".as_ptr(), 5);
    }
    let mut out = [0u8; 32];
    let mut len = out.len();
    assert_eq!(unsafe { crypto_hash_finish(ctx, out.as_mut_ptr(), &mut len) }, 0);
    assert_eq!(
        &out[..],
        &hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")[..]
    );
}

#[test]
fn a_short_output_buffer_reports_the_size_instead_of_overflowing() {
    const SHA256: u8 = 4;
    let ctx = unsafe { crypto_hash_init(SHA256, core::ptr::null(), 0) };
    let mut out = [0u8; 8];
    let mut len = out.len();
    let rc = unsafe { crypto_hash_finish(ctx, out.as_mut_ptr(), &mut len) };
    assert_eq!(rc, -1);
    assert_eq!(len, 32, "must report what it needed");
    assert_eq!(out, [0u8; 8], "and must not have written anything");
}

#[test]
fn abandoning_a_hash_frees_it() {
    // crypto_hash_finish(ctx, NULL, NULL) is how the supplicant discards a
    // context; it must still consume it rather than leak.
    const SHA256: u8 = 4;
    let ctx = unsafe { crypto_hash_init(SHA256, core::ptr::null(), 0) };
    let rc = unsafe { crypto_hash_finish(ctx, core::ptr::null_mut(), core::ptr::null_mut()) };
    assert_eq!(rc, 0);
}

#[test]
fn an_unknown_hash_algorithm_is_refused() {
    for alg in [8u8, 9, 200] {
        let ctx = unsafe { crypto_hash_init(alg, core::ptr::null(), 0) };
        assert!(ctx.is_null(), "alg {alg}");
    }
}

#[test]
fn cipher_round_trips() {
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
}

#[test]
fn an_unsupported_cipher_is_refused() {
    let key = hex("2b7e151628aed2a6abf7158809cf4f3c");
    let iv = hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    // 3DES, DES, RC2, RC4 -- none selected by any configuration here.
    for alg in [0u8, 2, 3, 4, 5] {
        let c = unsafe { crypto_cipher_init(alg, iv.as_ptr(), key.as_ptr(), key.len()) };
        assert!(c.is_null(), "alg {alg}");
    }
}

#[test]
fn a_null_context_is_an_error_not_a_crash() {
    let mut buf = [0u8; 16];
    assert_eq!(unsafe { aes_encrypt(core::ptr::null_mut(), buf.as_ptr(), buf.as_mut_ptr()) }, -1);
    assert_eq!(unsafe { aes_decrypt(core::ptr::null_mut(), buf.as_ptr(), buf.as_mut_ptr()) }, -1);
    assert_eq!(
        unsafe { crypto_cipher_encrypt(core::ptr::null_mut(), buf.as_ptr(), buf.as_mut_ptr(), 16) },
        -1
    );
    // Freeing null is a no-op, as the C does.
    unsafe {
        aes_encrypt_deinit(core::ptr::null_mut());
        crypto_cipher_deinit(core::ptr::null_mut());
    }
}
