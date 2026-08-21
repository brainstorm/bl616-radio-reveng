// SPDX-FileCopyrightText: 2026 Roman Valls Guimera <brainstorm@nopcode.org>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Fixed-capacity NUL-terminated strings.
//!
//! The vendor API takes `char *` everywhere, and the interesting cases (SSID,
//! passphrase, AKM list, country code) all have hard length limits. Copying
//! into a stack buffer keeps them alive for the duration of the call without
//! needing an allocator, and rejects the two ways a `&str` can be unusable as
//! a C string: too long, or containing an interior NUL.

use core::ffi::c_char;

use crate::error::{Error, Result};

/// A `&str` copied into `N` bytes plus a terminator.
pub struct CBuf<const N: usize> {
    buf: [u8; N],
    len: usize,
}

impl<const N: usize> CBuf<N> {
    /// Copy `s`, or return `None` if it does not fit in `N - 1` bytes or
    /// contains an interior NUL.
    pub fn new(s: &str) -> Option<Self> {
        let bytes = s.as_bytes();
        if bytes.len() >= N || bytes.contains(&0) {
            return None;
        }
        let mut buf = [0u8; N];
        buf[..bytes.len()].copy_from_slice(bytes);
        Some(CBuf {
            buf,
            len: bytes.len(),
        })
    }

    /// Copy `s` if it is `Some` and fits.
    ///
    /// `None` in, `Ok(None)` out — the vendor API uses a null pointer to mean
    /// "unset" in every place this is used.
    pub fn maybe(s: Option<&str>) -> Result<Option<Self>> {
        match s {
            None => Ok(None),
            Some(s) => Self::new(s).map(Some).ok_or(Error::InvalidArgument),
        }
    }

    /// Pointer to the NUL-terminated bytes. Valid while `self` is alive.
    pub fn as_ptr(&self) -> *const c_char {
        self.buf.as_ptr() as *const c_char
    }

    /// Mutable pointer, for the vendor's non-const `char *` parameters. The
    /// stack never actually writes through these.
    pub fn as_mut_ptr(&self) -> *mut c_char {
        self.buf.as_ptr() as *mut c_char
    }

    /// Length in bytes, excluding the terminator.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the string is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// Pointer for an optional buffer: the string, or null.
pub fn opt_ptr<const N: usize>(b: &Option<CBuf<N>>) -> *mut c_char {
    match b {
        Some(b) => b.as_mut_ptr(),
        None => core::ptr::null_mut(),
    }
}

/// SSID: 32 bytes on the air, plus a terminator.
pub type Ssid = CBuf<33>;
/// WPA passphrase: 8..=63 characters, plus a terminator.
pub type Passphrase = CBuf<65>;
/// AKM list, e.g. `"WPA2"` or `"WPA2,WPA3"`.
pub type AkmStr = CBuf<16>;
/// ISO country code, e.g. `"US"`.
pub type CountryCode = CBuf<4>;
/// BSSID in `aa:bb:cc:dd:ee:ff` form.
pub type BssidStr = CBuf<18>;
