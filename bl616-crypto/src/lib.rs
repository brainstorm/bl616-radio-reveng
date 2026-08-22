// SPDX-FileCopyrightText: 2026 Roman Valls Guimera <brainstorm@nopcode.org>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! wpa_supplicant's crypto backend, in Rust.
//!
//! This replaces `src/wpa_crypto/crypto_mbedtls_misc.c` — the 33 entry points
//! the supplicant calls for hashing, HMAC and AES — with RustCrypto behind
//! the same C ABI. `crypto_mbedtls.c`, which is nothing but `crypto_bignum_*`
//! and `crypto_ec_*` for SAE/WPA3, is left alone for now.
//!
//! # Why this is the stage worth doing off-hardware
//!
//! Everything here is a pure function with published test vectors, so it can
//! be verified completely on the host before a board is involved at all —
//! FIPS-197 for AES, RFC 1321 for MD5, RFC 3174 for SHA-1, RFC 2202 and 4231
//! for the HMACs. That is a rare property in this project, where most bugs
//! only appear once a real access point is talking to the radio.
//!
//! # All or nothing
//!
//! The linker pulls objects out of an archive whole. Supply 31 of these 33
//! and the linker still needs the other two, pulls
//! `crypto_mbedtls_misc.c.obj` in to get them, and every symbol here becomes
//! a duplicate definition. So the set is replaced together or not at all,
//! which is why `crypto_mod_exp` and `crypto_dh_init` are here too despite
//! wanting bignum arithmetic rather than a hash.

#![no_std]
#![allow(clippy::missing_safety_doc)]

extern crate alloc;

use alloc::boxed::Box;
use core::ffi::{c_int, c_void};
use core::slice;

use aes::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit, KeyIvInit, StreamCipher};
use aes::{Aes128, Aes192, Aes256};
use digest::{Digest, Mac};
use hmac::{Hmac, SimpleHmac};

mod bignum;
pub use bignum::{crypto_dh_init, crypto_mod_exp};

/// Gather the scatter/gather argument pairs the `*_vector` entry points take.
///
/// # Safety
///
/// `addr` and `len` must each point to `num_elem` readable entries, and each
/// `addr[i]` to `len[i]` readable bytes.
unsafe fn chunks<'a>(
    num_elem: usize,
    addr: *const *const u8,
    len: *const usize,
) -> impl Iterator<Item = &'a [u8]> {
    let addrs = unsafe { slice::from_raw_parts(addr, num_elem) };
    let lens = unsafe { slice::from_raw_parts(len, num_elem) };
    (0..num_elem).map(move |i| {
        if lens[i] == 0 {
            &[][..]
        } else {
            unsafe { slice::from_raw_parts(addrs[i], lens[i]) }
        }
    })
}

/// Hash a scatter/gather list into `mac`.
macro_rules! vector_fn {
    ($name:ident, $hash:ty, $out:expr) => {
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $name(
            num_elem: usize,
            addr: *const *const u8,
            len: *const usize,
            mac: *mut u8,
        ) -> c_int {
            let mut h = <$hash>::new();
            for c in unsafe { chunks(num_elem, addr, len) } {
                h.update(c);
            }
            let out = h.finalize();
            unsafe { core::ptr::copy_nonoverlapping(out.as_ptr(), mac, $out) };
            0
        }
    };
}

vector_fn!(md5_vector, md5::Md5, 16);
vector_fn!(sha1_vector, sha1::Sha1, 20);
vector_fn!(sha256_vector, sha2::Sha256, 32);
vector_fn!(sha384_vector, sha2::Sha384, 48);
vector_fn!(sha512_vector, sha2::Sha512, 64);

/// HMAC over a scatter/gather list, plus the single-buffer convenience form.
///
/// MD5 and SHA-1 need `SimpleHmac` rather than `Hmac`: the specialised type
/// requires the hash to expose a block-level API that only the SHA-2 family
/// implements here.
macro_rules! hmac_fns {
    ($vector:ident, $single:ident, $mac:ty, $out:expr) => {
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $vector(
            key: *const u8,
            key_len: usize,
            num_elem: usize,
            addr: *const *const u8,
            len: *const usize,
            mac: *mut u8,
        ) -> c_int {
            let key = if key_len == 0 {
                &[][..]
            } else {
                unsafe { slice::from_raw_parts(key, key_len) }
            };
            // Any key length is valid for HMAC; longer than a block is hashed
            // down, which the implementation handles.
            let Ok(mut h) = <$mac>::new_from_slice(key) else {
                return -1;
            };
            for c in unsafe { chunks(num_elem, addr, len) } {
                h.update(c);
            }
            let out = h.finalize().into_bytes();
            unsafe { core::ptr::copy_nonoverlapping(out.as_ptr(), mac, $out) };
            0
        }

        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $single(
            key: *const u8,
            key_len: usize,
            data: *const u8,
            data_len: usize,
            mac: *mut u8,
        ) -> c_int {
            let addr = [data];
            let len = [data_len];
            unsafe { $vector(key, key_len, 1, addr.as_ptr(), len.as_ptr(), mac) }
        }
    };
}

hmac_fns!(hmac_md5_vector, hmac_md5, SimpleHmac<md5::Md5>, 16);
hmac_fns!(hmac_sha1_vector, hmac_sha1, SimpleHmac<sha1::Sha1>, 20);
hmac_fns!(hmac_sha256_vector, hmac_sha256, Hmac<sha2::Sha256>, 32);
hmac_fns!(hmac_sha384_vector, hmac_sha384, Hmac<sha2::Sha384>, 48);

// ---------------------------------------------------------------------- AES

/// An AES key schedule, as handed back to C through a `void *`.
enum AesKey {
    K128(Box<Aes128>),
    K192(Box<Aes192>),
    K256(Box<Aes256>),
}

impl AesKey {
    fn new(key: &[u8]) -> Option<Self> {
        Some(match key.len() {
            16 => AesKey::K128(Box::new(Aes128::new_from_slice(key).ok()?)),
            24 => AesKey::K192(Box::new(Aes192::new_from_slice(key).ok()?)),
            32 => AesKey::K256(Box::new(Aes256::new_from_slice(key).ok()?)),
            _ => return None,
        })
    }
}

/// Build a key schedule for single-block encryption.
///
/// Returns null on an unusable key length, which is what the callers check.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn aes_encrypt_init(key: *const u8, len: usize) -> *mut c_void {
    if key.is_null() {
        return core::ptr::null_mut();
    }
    match AesKey::new(unsafe { slice::from_raw_parts(key, len) }) {
        Some(k) => Box::into_raw(Box::new(k)) as *mut c_void,
        None => core::ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn aes_encrypt(ctx: *mut c_void, plain: *const u8, crypt: *mut u8) -> c_int {
    if ctx.is_null() {
        return -1;
    }
    let key = unsafe { &*(ctx as *const AesKey) };
    let mut block = [0u8; 16];
    unsafe { core::ptr::copy_nonoverlapping(plain, block.as_mut_ptr(), 16) };
    let b = (&mut block).into();
    match key {
        AesKey::K128(k) => k.encrypt_block(b),
        AesKey::K192(k) => k.encrypt_block(b),
        AesKey::K256(k) => k.encrypt_block(b),
    }
    unsafe { core::ptr::copy_nonoverlapping(block.as_ptr(), crypt, 16) };
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn aes_encrypt_deinit(ctx: *mut c_void) {
    if !ctx.is_null() {
        drop(unsafe { Box::from_raw(ctx as *mut AesKey) });
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn aes_decrypt_init(key: *const u8, len: usize) -> *mut c_void {
    unsafe { aes_encrypt_init(key, len) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn aes_decrypt(ctx: *mut c_void, crypt: *const u8, plain: *mut u8) -> c_int {
    if ctx.is_null() {
        return -1;
    }
    let key = unsafe { &*(ctx as *const AesKey) };
    let mut block = [0u8; 16];
    unsafe { core::ptr::copy_nonoverlapping(crypt, block.as_mut_ptr(), 16) };
    let b = (&mut block).into();
    match key {
        AesKey::K128(k) => k.decrypt_block(b),
        AesKey::K192(k) => k.decrypt_block(b),
        AesKey::K256(k) => k.decrypt_block(b),
    }
    unsafe { core::ptr::copy_nonoverlapping(block.as_ptr(), plain, 16) };
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn aes_decrypt_deinit(ctx: *mut c_void) {
    unsafe { aes_encrypt_deinit(ctx) }
}

type Aes128CbcEnc = cbc::Encryptor<Aes128>;
type Aes128CbcDec = cbc::Decryptor<Aes128>;
type Aes128Ctr = ctr::Ctr128BE<Aes128>;
type Aes192Ctr = ctr::Ctr128BE<Aes192>;
type Aes256Ctr = ctr::Ctr128BE<Aes256>;

/// CBC encrypt in place. The supplicant only ever passes whole blocks; it
/// does its own padding.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn aes_128_cbc_encrypt(
    key: *const u8,
    iv: *const u8,
    data: *mut u8,
    data_len: usize,
) -> c_int {
    if data_len % 16 != 0 {
        return -1;
    }
    let key = unsafe { slice::from_raw_parts(key, 16) };
    let iv = unsafe { slice::from_raw_parts(iv, 16) };
    let buf = unsafe { slice::from_raw_parts_mut(data, data_len) };
    let Ok(enc) = Aes128CbcEnc::new_from_slices(key, iv) else {
        return -1;
    };
    // NoPadding: the supplicant hands over whole blocks and does its own
    // padding, so nothing may be added or removed here.
    use cipher::block_padding::NoPadding;
    use cipher::BlockModeEncrypt;
    if enc.encrypt_padded::<NoPadding>(buf, data_len).is_err() {
        return -1;
    }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn aes_128_cbc_decrypt(
    key: *const u8,
    iv: *const u8,
    data: *mut u8,
    data_len: usize,
) -> c_int {
    if data_len % 16 != 0 {
        return -1;
    }
    let key = unsafe { slice::from_raw_parts(key, 16) };
    let iv = unsafe { slice::from_raw_parts(iv, 16) };
    let buf = unsafe { slice::from_raw_parts_mut(data, data_len) };
    let Ok(dec) = Aes128CbcDec::new_from_slices(key, iv) else {
        return -1;
    };
    use cipher::block_padding::NoPadding;
    use cipher::BlockModeDecrypt;
    if dec.decrypt_padded::<NoPadding>(buf).is_err() {
        return -1;
    }
    0
}

/// CTR with any AES key length; `nonce` is the full 16-byte initial counter.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn aes_ctr_encrypt(
    key: *const u8,
    key_len: usize,
    nonce: *const u8,
    data: *mut u8,
    data_len: usize,
) -> c_int {
    let key = unsafe { slice::from_raw_parts(key, key_len) };
    let nonce = unsafe { slice::from_raw_parts(nonce, 16) };
    let buf = unsafe { slice::from_raw_parts_mut(data, data_len) };
    match key_len {
        16 => match Aes128Ctr::new_from_slices(key, nonce) {
            Ok(mut c) => c.apply_keystream(buf),
            Err(_) => return -1,
        },
        24 => match Aes192Ctr::new_from_slices(key, nonce) {
            Ok(mut c) => c.apply_keystream(buf),
            Err(_) => return -1,
        },
        32 => match Aes256Ctr::new_from_slices(key, nonce) {
            Ok(mut c) => c.apply_keystream(buf),
            Err(_) => return -1,
        },
        _ => return -1,
    }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn aes_128_ctr_encrypt(
    key: *const u8,
    nonce: *const u8,
    data: *mut u8,
    data_len: usize,
) -> c_int {
    unsafe { aes_ctr_encrypt(key, 16, nonce, data, data_len) }
}

// ------------------------------------------------- crypto_hash / crypto_cipher

/// `enum crypto_hash_alg`, which `-fshort-enums` makes one byte wide.
const CRYPTO_HASH_ALG_MD5: u8 = 0;
const CRYPTO_HASH_ALG_SHA1: u8 = 1;
const CRYPTO_HASH_ALG_HMAC_MD5: u8 = 2;
const CRYPTO_HASH_ALG_HMAC_SHA1: u8 = 3;
const CRYPTO_HASH_ALG_SHA256: u8 = 4;
const CRYPTO_HASH_ALG_HMAC_SHA256: u8 = 5;
const CRYPTO_HASH_ALG_SHA384: u8 = 6;
const CRYPTO_HASH_ALG_SHA512: u8 = 7;

/// A streaming hash or HMAC, behind `struct crypto_hash *`.
enum HashCtx {
    Md5(md5::Md5),
    Sha1(sha1::Sha1),
    Sha256(sha2::Sha256),
    Sha384(sha2::Sha384),
    Sha512(sha2::Sha512),
    HmacMd5(SimpleHmac<md5::Md5>),
    HmacSha1(SimpleHmac<sha1::Sha1>),
    HmacSha256(Hmac<sha2::Sha256>),
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_hash_init(
    alg: u8,
    key: *const u8,
    key_len: usize,
) -> *mut c_void {
    let k = || {
        if key.is_null() || key_len == 0 {
            &[][..]
        } else {
            unsafe { slice::from_raw_parts(key, key_len) }
        }
    };
    let ctx = match alg {
        CRYPTO_HASH_ALG_MD5 => HashCtx::Md5(md5::Md5::new()),
        CRYPTO_HASH_ALG_SHA1 => HashCtx::Sha1(sha1::Sha1::new()),
        CRYPTO_HASH_ALG_SHA256 => HashCtx::Sha256(sha2::Sha256::new()),
        CRYPTO_HASH_ALG_SHA384 => HashCtx::Sha384(sha2::Sha384::new()),
        CRYPTO_HASH_ALG_SHA512 => HashCtx::Sha512(sha2::Sha512::new()),
        CRYPTO_HASH_ALG_HMAC_MD5 => match SimpleHmac::new_from_slice(k()) {
            Ok(h) => HashCtx::HmacMd5(h),
            Err(_) => return core::ptr::null_mut(),
        },
        CRYPTO_HASH_ALG_HMAC_SHA1 => match SimpleHmac::new_from_slice(k()) {
            Ok(h) => HashCtx::HmacSha1(h),
            Err(_) => return core::ptr::null_mut(),
        },
        CRYPTO_HASH_ALG_HMAC_SHA256 => match Hmac::new_from_slice(k()) {
            Ok(h) => HashCtx::HmacSha256(h),
            Err(_) => return core::ptr::null_mut(),
        },
        _ => return core::ptr::null_mut(),
    };
    Box::into_raw(Box::new(ctx)) as *mut c_void
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_hash_update(ctx: *mut c_void, data: *const u8, len: usize) {
    if ctx.is_null() || data.is_null() {
        return;
    }
    let c = unsafe { &mut *(ctx as *mut HashCtx) };
    let d = unsafe { slice::from_raw_parts(data, len) };
    match c {
        HashCtx::Md5(h) => h.update(d),
        HashCtx::Sha1(h) => h.update(d),
        HashCtx::Sha256(h) => h.update(d),
        HashCtx::Sha384(h) => h.update(d),
        HashCtx::Sha512(h) => h.update(d),
        HashCtx::HmacMd5(h) => Mac::update(h, d),
        HashCtx::HmacSha1(h) => Mac::update(h, d),
        HashCtx::HmacSha256(h) => Mac::update(h, d),
    }
}

/// Finish, or free without finishing when `hash` is null — the contract
/// `crypto_hash_finish` documents, and the reason it always consumes the
/// context.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_hash_finish(
    ctx: *mut c_void,
    hash: *mut u8,
    len: *mut usize,
) -> c_int {
    if ctx.is_null() {
        return -2;
    }
    let c = unsafe { Box::from_raw(ctx as *mut HashCtx) };
    if hash.is_null() || len.is_null() {
        return 0;
    }

    let mut out = [0u8; 64];
    let n = match *c {
        HashCtx::Md5(h) => copy_out(&h.finalize(), &mut out),
        HashCtx::Sha1(h) => copy_out(&h.finalize(), &mut out),
        HashCtx::Sha256(h) => copy_out(&h.finalize(), &mut out),
        HashCtx::Sha384(h) => copy_out(&h.finalize(), &mut out),
        HashCtx::Sha512(h) => copy_out(&h.finalize(), &mut out),
        HashCtx::HmacMd5(h) => copy_out(&h.finalize().into_bytes(), &mut out),
        HashCtx::HmacSha1(h) => copy_out(&h.finalize().into_bytes(), &mut out),
        HashCtx::HmacSha256(h) => copy_out(&h.finalize().into_bytes(), &mut out),
    };

    // The caller passes in the room it has and gets back what was written.
    if unsafe { *len } < n {
        unsafe { *len = n };
        return -1;
    }
    unsafe {
        core::ptr::copy_nonoverlapping(out.as_ptr(), hash, n);
        *len = n;
    }
    0
}

fn copy_out(src: &[u8], dst: &mut [u8; 64]) -> usize {
    dst[..src.len()].copy_from_slice(src);
    src.len()
}

/// `enum crypto_cipher_alg`.
const CRYPTO_CIPHER_ALG_AES: u8 = 1;

/// A cipher stream, behind `struct crypto_cipher *`.
///
/// Only AES is wired up: the supplicant's other options are 3DES, DES, RC2
/// and RC4, none of which any configuration here selects, and all of which
/// are broken.
struct CipherCtx {
    enc: Aes128Ctr,
    dec: Aes128Ctr,
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_cipher_init(
    alg: u8,
    iv: *const u8,
    key: *const u8,
    key_len: usize,
) -> *mut c_void {
    if alg != CRYPTO_CIPHER_ALG_AES || key_len != 16 || iv.is_null() || key.is_null() {
        return core::ptr::null_mut();
    }
    let key = unsafe { slice::from_raw_parts(key, key_len) };
    let iv = unsafe { slice::from_raw_parts(iv, 16) };
    let (Ok(enc), Ok(dec)) = (
        Aes128Ctr::new_from_slices(key, iv),
        Aes128Ctr::new_from_slices(key, iv),
    ) else {
        return core::ptr::null_mut();
    };
    Box::into_raw(Box::new(CipherCtx { enc, dec })) as *mut c_void
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_cipher_encrypt(
    ctx: *mut c_void,
    plain: *const u8,
    crypt: *mut u8,
    len: usize,
) -> c_int {
    if ctx.is_null() {
        return -1;
    }
    let c = unsafe { &mut *(ctx as *mut CipherCtx) };
    unsafe { core::ptr::copy_nonoverlapping(plain, crypt, len) };
    c.enc.apply_keystream(unsafe { slice::from_raw_parts_mut(crypt, len) });
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_cipher_decrypt(
    ctx: *mut c_void,
    crypt: *const u8,
    plain: *mut u8,
    len: usize,
) -> c_int {
    if ctx.is_null() {
        return -1;
    }
    let c = unsafe { &mut *(ctx as *mut CipherCtx) };
    unsafe { core::ptr::copy_nonoverlapping(crypt, plain, len) };
    c.dec.apply_keystream(unsafe { slice::from_raw_parts_mut(plain, len) });
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn crypto_cipher_deinit(ctx: *mut c_void) {
    if !ctx.is_null() {
        drop(unsafe { Box::from_raw(ctx as *mut CipherCtx) });
    }
}

/// Nothing to set up: there is no global state and no entropy pool to seed.
#[unsafe(no_mangle)]
pub extern "C" fn crypto_global_init() -> c_int {
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn crypto_global_deinit() {}
