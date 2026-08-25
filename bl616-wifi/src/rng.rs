// SPDX-FileCopyrightText: 2026 Roman Valls Guimera <brainstorm@nopcode.org>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! The hardware random number generator.
//!
//! The BL616 has a real TRNG in its security engine, and `liblhal.a` exposes
//! it. That distinction matters: this is suitable for generating keys, not
//! just for seeding a port number or a stack's sequence numbers.
//!
//! An application wiring this to `getrandom`'s custom backend, or to a HAL's
//! RNG trait, should route through here rather than reaching for the WiFi
//! supplicant's `os_get_random` — that one exists to serve the supplicant and
//! is only as good as whatever the blob seeded it with.

use crate::error::{Error, Result};

/// Fill `buf` with random bytes from the hardware generator.
///
/// # Errors
///
/// Returns [`Error::Vendor`] if the generator reports a failure, which on this
/// part means the security engine is not clocked or is busy. A caller that
/// needs entropy for a key must treat that as fatal rather than falling back
/// to something weaker.
pub fn fill(buf: &mut [u8]) -> Result<()> {
    if buf.is_empty() {
        return Ok(());
    }
    // SAFETY: the buffer is valid for `len` bytes by construction.
    let rc = unsafe { bl616_wifi_sys::bflb_trng_readlen(buf.as_mut_ptr(), buf.len() as u32) };
    if rc == 0 {
        Ok(())
    } else {
        Err(Error::Vendor(rc))
    }
}

/// A random `u32`, for seeds where a failure has no sensible recovery.
///
/// # Errors
///
/// As [`fill`].
pub fn u32() -> Result<u32> {
    let mut b = [0u8; 4];
    fill(&mut b)?;
    Ok(u32::from_le_bytes(b))
}

/// A random `u64`.
///
/// # Errors
///
/// As [`fill`].
pub fn u64() -> Result<u64> {
    let mut b = [0u8; 8];
    fill(&mut b)?;
    Ok(u64::from_le_bytes(b))
}
