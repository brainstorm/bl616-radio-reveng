// SPDX-FileCopyrightText: 2026 Roman Valls Guimera <brainstorm@nopcode.org>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Raw access to the SPI flash the firmware runs from.
//!
//! Thin wrappers over the vendor's `bflb_flash_*`, which take offsets into
//! the flash rather than memory addresses. The usual NOR rules apply and are
//! not hidden here: a write can clear bits but never set them, so a region
//! must be erased before it can be rewritten, and erase works a sector at a
//! time.
//!
//! # Danger
//!
//! There is no partition table consulted here and no bounds checking beyond
//! what the vendor does. Writing to the wrong offset overwrites the
//! bootloader or the firmware image, and the failure appears at the next
//! reset rather than at the call. Callers should know their layout.

use crate::error::{Error, Result};

/// Erase granularity. Erasing anything erases whole sectors.
pub const SECTOR_SIZE: u32 = 4096;

/// Read `buf.len()` bytes from `offset`.
///
/// # Errors
///
/// [`Error::Vendor`] if the flash controller reports a failure.
pub fn read(offset: u32, buf: &mut [u8]) -> Result<()> {
    if buf.is_empty() {
        return Ok(());
    }
    // SAFETY: the buffer is valid for `len` bytes by construction.
    let rc = unsafe { bl616_wifi_sys::bflb_flash_read(offset, buf.as_mut_ptr(), buf.len() as u32) };
    if rc == 0 { Ok(()) } else { Err(Error::Vendor(rc)) }
}

/// Write `data` at `offset`.
///
/// The target must already be erased: this cannot set a bit back to one.
///
/// # Errors
///
/// [`Error::Vendor`] if the flash controller reports a failure.
pub fn write(offset: u32, data: &[u8]) -> Result<()> {
    if data.is_empty() {
        return Ok(());
    }
    // SAFETY: the buffer is valid for `len` bytes by construction.
    let rc = unsafe { bl616_wifi_sys::bflb_flash_write(offset, data.as_ptr(), data.len() as u32) };
    if rc == 0 { Ok(()) } else { Err(Error::Vendor(rc)) }
}

/// Erase `len` bytes from `offset`, rounded out to whole sectors by the
/// hardware.
///
/// # Errors
///
/// [`Error::Vendor`] if the flash controller reports a failure.
pub fn erase(offset: u32, len: u32) -> Result<()> {
    if len == 0 {
        return Ok(());
    }
    let rc = unsafe { bl616_wifi_sys::bflb_flash_erase(offset, len) };
    if rc == 0 { Ok(()) } else { Err(Error::Vendor(rc)) }
}
