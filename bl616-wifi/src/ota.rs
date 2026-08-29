// SPDX-FileCopyrightText: 2026 Roman Valls Guimera <brainstorm@nopcode.org>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Over-the-air updates, against the two firmware slots Boot2 knows about.
//!
//! The partition table names two slots for the firmware and says which one
//! is live. An update writes the image into the other one and then publishes
//! a table that swaps them; the running image is never touched, so a
//! transfer that dies half way costs nothing but the spare slot's contents.
//! [`bl616_pt`] does the encoding and is tested on the host — this module is
//! only the flash sequencing.
//!
//! ```no_run
//! # fn main() -> Result<(), bl616_wifi::error::Error> {
//! let mut ota = bl616_wifi::ota::Ota::begin()?;
//! ota.write(0, b"...")?;          // offsets from the start of the slot
//! ota.commit()?;                  // the next boot runs it
//! # Ok(()) }
//! ```
//!
//! # Sequential only
//!
//! [`Ota::write`] appends: each call must start where the last one ended.
//! Erasing happens a sector ahead of the writes rather than all at once,
//! because erasing a megabyte and a half up front would stall everything
//! else for many seconds. That trade is what makes the order a rule instead
//! of a preference — a write that jumped backwards would land in a sector
//! that has already been written, and NOR flash cannot set a bit back.
//!
//! # This blocks
//!
//! Every erase and write suspends execution from flash for its duration.
//! The radio keeps its own timers, but a long transfer is visible to the
//! rest of the firmware; this is the same bargain the configuration store
//! makes, just for a great deal more data.
//!
//! # Confirming a boot
//!
//! Boot2 can count attempts at a freshly published image and fall back if
//! the count runs out. [`confirm_boot`] clears that counter and should be
//! called once the new firmware is satisfied it works.

use bl616_pt::{Table, TableId};

use crate::error::{Error, Result};
use crate::flash;

/// An update in progress: which slot it is going to, and how far it has got.
pub struct Ota {
    /// The live table, as read. Left untouched until [`Ota::commit`].
    table: Table,
    /// Which copy it came from; the update goes to the other one.
    id: TableId,
    /// Flash offset of the slot being written.
    target: u32,
    /// How much the slot holds.
    capacity: u32,
    /// Bytes of the slot that have been erased, from `target`.
    erased: u32,
    /// Bytes written, which is where the next write has to start.
    written: u32,
}

impl Ota {
    /// Read the partition table and take the slot that is not running.
    ///
    /// # Errors
    ///
    /// [`Error::Partition`] if neither copy of the table validates, if it
    /// has no firmware entry, or if that entry has no second slot — a
    /// single-slot layout cannot be updated in place, and saying so here is
    /// better than discovering it after a megabyte of upload.
    pub fn begin() -> Result<Ota> {
        let (id, table) = read_active_table()?;
        let fw = table
            .entry(bl616_pt::ENTRY_TYPE_FW)
            .map_err(Error::Partition)?;
        let (target, capacity) = fw.spare_slot().ok_or(Error::Partition(
            // A table whose firmware entry has one slot is well formed; it
            // just has nowhere to put an update.
            bl616_pt::Error::NotFound,
        ))?;

        Ok(Ota {
            table,
            id,
            target,
            capacity,
            erased: 0,
            written: 0,
        })
    }

    /// How large an image the spare slot takes.
    #[must_use]
    pub fn capacity(&self) -> u32 {
        self.capacity
    }

    /// Where the image is going, for logging.
    #[must_use]
    pub fn target_address(&self) -> u32 {
        self.target
    }

    /// Append `data` at `offset` bytes into the slot.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidArgument`] if `offset` is not where the last write
    /// ended, or if the image would not fit; [`Error::Vendor`] from the
    /// flash itself.
    pub fn write(&mut self, offset: u32, data: &[u8]) -> Result<()> {
        if offset != self.written {
            return Err(Error::InvalidArgument);
        }
        let len = u32::try_from(data.len()).map_err(|_| Error::InvalidArgument)?;
        let end = offset.checked_add(len).ok_or(Error::InvalidArgument)?;
        if end > self.capacity {
            return Err(Error::InvalidArgument);
        }

        self.erase_through(end)?;
        flash::write(self.target + offset, data)?;
        self.written = end;
        Ok(())
    }

    /// Erase whole sectors until `end` is covered.
    fn erase_through(&mut self, end: u32) -> Result<()> {
        if end <= self.erased {
            return Ok(());
        }
        // Round up to the sector the last byte falls in, and clamp: the slot
        // may not be a whole number of sectors.
        let wanted = end
            .div_ceil(flash::SECTOR_SIZE)
            .saturating_mul(flash::SECTOR_SIZE)
            .min(self.capacity);
        flash::erase(self.target + self.erased, wanted - self.erased)?;
        self.erased = wanted;
        Ok(())
    }

    /// Publish a table that boots what was just written.
    ///
    /// One sector write, to the copy of the table that is not live. Until it
    /// lands the board still boots the old image; after it lands it boots
    /// the new one. There is no state in between that boots neither.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidArgument`] if nothing was written; [`Error::Partition`]
    /// if the table cannot be re-encoded, and [`Error::Vendor`] from the flash.
    pub fn commit(self) -> Result<()> {
        if self.written == 0 {
            return Err(Error::InvalidArgument);
        }
        let next = self
            .table
            .with_firmware_slot_swapped(self.written)
            .map_err(Error::Partition)?;
        write_table(self.id.other(), &next)
    }
}

/// Tell Boot2 the running image works.
///
/// A no-op unless the image is on probation, so it is cheap to call on every
/// boot and that is how it is meant to be used.
///
/// # Errors
///
/// [`Error::Partition`] if the table cannot be read or re-encoded, and
/// [`Error::Vendor`] from the flash.
pub fn confirm_boot() -> Result<()> {
    let (id, table) = read_active_table()?;
    let Some(next) = table.with_boot_confirmed().map_err(Error::Partition)? else {
        return Ok(());
    };
    // The vendor writes this one back over the live copy rather than the
    // spare: it is not a new layout, only the retry counter being cleared,
    // and keeping the age ordering intact matters more than the redundancy.
    write_table(id, &next)
}

/// Read both copies and return whichever Boot2 would use.
fn read_active_table() -> Result<(TableId, Table)> {
    let mut buf = [0u8; bl616_pt::TABLE_SIZE];

    flash::read(bl616_pt::TABLE0_ADDRESS, &mut buf)?;
    let zero = Table::parse(&buf).ok();

    flash::read(bl616_pt::TABLE1_ADDRESS, &mut buf)?;
    let one = Table::parse(&buf).ok();

    bl616_pt::active(zero, one).map_err(Error::Partition)
}

/// Erase one sector and write a table into it.
fn write_table(id: TableId, table: &Table) -> Result<()> {
    let at = id.address();
    flash::erase(at, flash::SECTOR_SIZE)?;
    flash::write(at, table.as_bytes())
}
