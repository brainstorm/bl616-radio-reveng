// SPDX-FileCopyrightText: 2026 Roman Valls Guimera <brainstorm@nopcode.org>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! The BL616 partition table, as Boot2 reads it.
//!
//! Two copies live at 0xE000 and 0xF000. Each is a 16-byte header, sixteen
//! 36-byte entries and a CRC32 over the entries that are in use; the header
//! carries its own CRC32 and an *age*, and Boot2 boots whichever valid copy
//! has the higher one. Entries of type 0 (`FW`) carry two slots, and the
//! entry's `active_index` says which of them is the firmware.
//!
//! That is the whole of the A/B update mechanism on this part: write the
//! image into the slot that is not running, then publish a table that names
//! the other slot. The publish is a single sector write of a structure whose
//! CRCs must both be right — a table that fails validation is ignored, and a
//! board with two invalid copies does not boot. So the encoding lives here,
//! in a crate that builds and is tested on the host, rather than beside the
//! flash driver where it could only be exercised on hardware.
//!
//! # What this crate does not do
//!
//! It never touches flash. Callers read 596 bytes, hand them to [`Table::parse`],
//! and write [`Table::as_bytes`] back; the sequencing, erase and write are
//! [`crate`]-free and belong to the platform.

#![no_std]

/// Where the two copies live.
pub const TABLE0_ADDRESS: u32 = 0xE000;
pub const TABLE1_ADDRESS: u32 = 0xF000;

/// `BFLB_PT_MAGIC_CODE`, "BFPT" little-endian.
pub const MAGIC: u32 = 0x5450_4642;

/// `PT_ENTRY_MAX`: entries the on-flash structure has room for.
pub const ENTRY_MAX: usize = 16;
/// `sizeof(pt_table_entry_config)`.
pub const ENTRY_SIZE: usize = 36;
/// `sizeof(pt_table_config)`.
pub const HEADER_SIZE: usize = 16;
/// `sizeof(pt_table_stuff_config)`: header, every entry slot, entries CRC.
pub const TABLE_SIZE: usize = HEADER_SIZE + ENTRY_MAX * ENTRY_SIZE + 4;

/// The firmware entry's type, which is how the table is searched: names are
/// advisory, `type` is what Boot2 and the vendor's own updater match on.
pub const ENTRY_TYPE_FW: u8 = 0;

/// The high byte of an entry's `age` counts boot attempts of an image that
/// has not yet reported success; the low 24 bits are the age proper.
const AGE_BOOT_RETRY_MASK: u32 = 0xFF00_0000;
const AGE_VALUE_MASK: u32 = 0x00FF_FFFF;

/// Which copy of the table a value came from, and therefore which one an
/// update has to be written to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TableId {
    Zero,
    One,
}

impl TableId {
    /// The copy that is not this one. An update is always published to the
    /// other copy, so a power cut mid-write leaves the running table intact.
    #[must_use]
    pub fn other(self) -> TableId {
        match self {
            TableId::Zero => TableId::One,
            TableId::One => TableId::Zero,
        }
    }

    /// Flash address of this copy.
    #[must_use]
    pub fn address(self) -> u32 {
        match self {
            TableId::Zero => TABLE0_ADDRESS,
            TableId::One => TABLE1_ADDRESS,
        }
    }
}

/// Why a table was rejected, or an update refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Error {
    /// Not `sizeof(pt_table_stuff_config)` bytes.
    Truncated,
    /// The magic is not `BFPT`; usually an erased or unwritten sector.
    BadMagic,
    /// More entries claimed than the structure holds.
    EntryCount,
    /// The header's own CRC32 does not match.
    HeaderCrc,
    /// The CRC32 over the entries does not match.
    EntriesCrc,
    /// No entry of the requested type.
    NotFound,
    /// Neither copy validated, so there is nothing to update.
    NoValidTable,
}

/// One partition entry, decoded.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Entry {
    pub kind: u8,
    pub device: u8,
    /// Which of the two slots holds the live image.
    pub active_index: u8,
    /// Start of each slot. The second is zero for a single-slot partition.
    pub start_address: [u32; 2],
    /// Capacity of each slot.
    pub max_len: [u32; 2],
    /// Length of the image in the active slot.
    pub len: u32,
    /// Boot-retry counter in the high byte, age in the low 24 bits.
    pub age: u32,
}

impl Entry {
    /// The slot that is not running: where an update is written.
    ///
    /// `None` when the partition has no second slot, which is how a table
    /// without room for an update says so.
    #[must_use]
    pub fn spare_slot(&self) -> Option<(u32, u32)> {
        let spare = usize::from(self.active_index & 1 ^ 1);
        let (addr, len) = (self.start_address[spare], self.max_len[spare]);
        if addr == 0 || len == 0 {
            None
        } else {
            Some((addr, len))
        }
    }

    /// The slot the running image was loaded from.
    #[must_use]
    pub fn active_slot(&self) -> (u32, u32) {
        let active = usize::from(self.active_index & 1);
        (self.start_address[active], self.max_len[active])
    }

    /// Whether Boot2 is still counting attempts at this image.
    #[must_use]
    pub fn boot_pending(&self) -> bool {
        self.age & AGE_BOOT_RETRY_MASK != 0
    }

    fn decode(bytes: &[u8]) -> Entry {
        Entry {
            kind: bytes[0],
            device: bytes[1],
            active_index: bytes[2],
            start_address: [u32_at(bytes, 12), u32_at(bytes, 16)],
            max_len: [u32_at(bytes, 20), u32_at(bytes, 24)],
            len: u32_at(bytes, 28),
            age: u32_at(bytes, 32),
        }
    }
}

/// A validated copy of the table, kept as the bytes it was read as.
///
/// Holding the raw image rather than a decoded struct is deliberate: an
/// update rewrites the whole structure, and every byte this code does not
/// understand — the name field, the entries it does not touch, the unused
/// tail — has to survive the round trip unchanged.
#[derive(Clone, PartialEq, Eq)]
pub struct Table {
    bytes: [u8; TABLE_SIZE],
}

impl core::fmt::Debug for Table {
    /// Age and entry count, not 596 bytes of it.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Table")
            .field("age", &self.age())
            .field("entries", &self.entry_count())
            .finish()
    }
}

impl Table {
    /// Validate `bytes` as a partition table.
    ///
    /// # Errors
    ///
    /// [`Error::BadMagic`] for an erased or foreign sector, and the CRC
    /// errors for a corrupt one. A rejected copy is not fatal on its own —
    /// the other copy is the point of there being two.
    pub fn parse(bytes: &[u8]) -> Result<Table, Error> {
        let bytes: [u8; TABLE_SIZE] = bytes
            .get(..TABLE_SIZE)
            .ok_or(Error::Truncated)?
            .try_into()
            .map_err(|_| Error::Truncated)?;

        if u32_at(&bytes, 0) != MAGIC {
            return Err(Error::BadMagic);
        }
        let count = usize::from(u16_at(&bytes, 6));
        if count > ENTRY_MAX {
            return Err(Error::EntryCount);
        }
        // The header's CRC covers the header without the CRC word itself.
        if u32_at(&bytes, 12) != crc32(&bytes[..HEADER_SIZE - 4]) {
            return Err(Error::HeaderCrc);
        }
        // The entries' CRC covers only the entries in use, and sits directly
        // after them rather than at a fixed offset.
        let entries = &bytes[HEADER_SIZE..HEADER_SIZE + count * ENTRY_SIZE];
        if u32_at(&bytes, HEADER_SIZE + count * ENTRY_SIZE) != crc32(entries) {
            return Err(Error::EntriesCrc);
        }

        Ok(Table { bytes })
    }

    /// The table's age. The higher of two valid copies is the live one.
    #[must_use]
    pub fn age(&self) -> u32 {
        u32_at(&self.bytes, 8)
    }

    /// How many entries are in use.
    #[must_use]
    pub fn entry_count(&self) -> usize {
        usize::from(u16_at(&self.bytes, 6))
    }

    /// The first entry of this type.
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`] if the table has no such entry.
    pub fn entry(&self, kind: u8) -> Result<Entry, Error> {
        self.entry_index(kind)
            .map(|i| Entry::decode(&self.bytes[HEADER_SIZE + i * ENTRY_SIZE..]))
    }

    fn entry_index(&self, kind: u8) -> Result<usize, Error> {
        (0..self.entry_count())
            .find(|i| self.bytes[HEADER_SIZE + i * ENTRY_SIZE] == kind)
            .ok_or(Error::NotFound)
    }

    /// Replace an entry, bump the table's age and refresh both CRCs.
    ///
    /// The result is what gets written to the *other* copy; this one is left
    /// as it was read, so a caller that fails half way has not lost the
    /// table it is running from.
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`] if no entry of that type exists. Entries are
    /// never added: the table is written by the flashing tool, and a runtime
    /// update that grew it would be writing a layout nothing else agreed to.
    pub fn with_entry(&self, entry: &Entry) -> Result<Table, Error> {
        let index = self.entry_index(entry.kind)?;
        let mut next = self.clone();
        let at = HEADER_SIZE + index * ENTRY_SIZE;

        // Only the mutable fields are written back: `name` and any padding
        // stay exactly as they were read.
        next.bytes[at] = entry.kind;
        next.bytes[at + 1] = entry.device;
        next.bytes[at + 2] = entry.active_index;
        put_u32(&mut next.bytes, at + 12, entry.start_address[0]);
        put_u32(&mut next.bytes, at + 16, entry.start_address[1]);
        put_u32(&mut next.bytes, at + 20, entry.max_len[0]);
        put_u32(&mut next.bytes, at + 24, entry.max_len[1]);
        put_u32(&mut next.bytes, at + 28, entry.len);
        put_u32(&mut next.bytes, at + 32, entry.age);

        let age = next.age().wrapping_add(1);
        put_u32(&mut next.bytes, 8, age);
        let header_crc = crc32(&next.bytes[..HEADER_SIZE - 4]);
        put_u32(&mut next.bytes, 12, header_crc);

        let count = next.entry_count();
        let entries_crc = crc32(&next.bytes[HEADER_SIZE..HEADER_SIZE + count * ENTRY_SIZE]);
        put_u32(
            &mut next.bytes,
            HEADER_SIZE + count * ENTRY_SIZE,
            entries_crc,
        );

        Ok(next)
    }

    /// Point the firmware entry at its spare slot, with `len` bytes in it.
    ///
    /// The age is incremented so a rollback that restores an older table
    /// loses to this one, and the boot-retry byte is left alone: it is
    /// Boot2's, not ours.
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`] if there is no firmware entry.
    pub fn with_firmware_slot_swapped(&self, len: u32) -> Result<Table, Error> {
        let mut fw = self.entry(ENTRY_TYPE_FW)?;
        fw.active_index = fw.active_index & 1 ^ 1;
        fw.len = len;
        fw.age = fw.age.wrapping_add(1);
        self.with_entry(&fw)
    }

    /// Clear the firmware entry's boot-retry byte, if it is set.
    ///
    /// This is what tells Boot2 the running image came up: without it an
    /// image that boots but never reports success is eventually rolled back.
    /// `Ok(None)` when there was nothing to clear, which is the usual case
    /// and means no write is needed.
    ///
    /// # Errors
    ///
    /// [`Error::NotFound`] if there is no firmware entry.
    pub fn with_boot_confirmed(&self) -> Result<Option<Table>, Error> {
        let mut fw = self.entry(ENTRY_TYPE_FW)?;
        if !fw.boot_pending() {
            return Ok(None);
        }
        fw.age &= AGE_VALUE_MASK;
        self.with_entry(&fw).map(Some)
    }

    /// The bytes to write to flash.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; TABLE_SIZE] {
        &self.bytes
    }
}

/// Pick the copy Boot2 would boot from.
///
/// Both valid means the higher age wins, and ties go to copy 0 — the same
/// order the vendor's own reader uses, so this agrees with what has already
/// booted.
///
/// # Errors
///
/// [`Error::NoValidTable`] when neither copy validates.
pub fn active(zero: Option<Table>, one: Option<Table>) -> Result<(TableId, Table), Error> {
    match (zero, one) {
        (Some(a), Some(b)) => {
            if a.age() >= b.age() {
                Ok((TableId::Zero, a))
            } else {
                Ok((TableId::One, b))
            }
        }
        (Some(a), None) => Ok((TableId::Zero, a)),
        (None, Some(b)) => Ok((TableId::One, b)),
        (None, None) => Err(Error::NoValidTable),
    }
}

/// CRC-32, as the vendor's `bflb_soft_crc32` computes it: the ordinary
/// reflected one with a 0xFFFFFFFF seed and a final inversion.
#[must_use]
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

fn u16_at(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

fn put_u32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The 4 MB layout the vendor ships for this board, as the flashing tool
    /// writes it: Boot2, a two-slot FW, and the single-slot partitions after
    /// it. Enough of the real thing to exercise slot selection.
    fn build(age: u32, active_index: u8, fw_len: u32, fw_age: u32) -> [u8; TABLE_SIZE] {
        let mut bytes = [0u8; TABLE_SIZE];
        put_u32(&mut bytes, 0, MAGIC);
        bytes[4..6].copy_from_slice(&2u16.to_le_bytes()); // version
        bytes[6..8].copy_from_slice(&3u16.to_le_bytes()); // entryCnt
        put_u32(&mut bytes, 8, age);

        let mut entry = |i: usize, kind: u8, name: &[u8], slots: [(u32, u32); 2], len, age| {
            let at = HEADER_SIZE + i * ENTRY_SIZE;
            bytes[at] = kind;
            bytes[at + 2] = if i == 1 { active_index } else { 0 };
            bytes[at + 3..at + 3 + name.len()].copy_from_slice(name);
            put_u32(&mut bytes, at + 12, slots[0].0);
            put_u32(&mut bytes, at + 16, slots[1].0);
            put_u32(&mut bytes, at + 20, slots[0].1);
            put_u32(&mut bytes, at + 24, slots[1].1);
            put_u32(&mut bytes, at + 28, len);
            put_u32(&mut bytes, at + 32, age);
        };
        entry(0, 16, b"Boot2", [(0, 0xE000), (0, 0)], 0, 0);
        entry(
            1,
            ENTRY_TYPE_FW,
            b"FW",
            [(0x1_0000, 0x20_0000), (0x21_0000, 0x16_8000)],
            fw_len,
            fw_age,
        );
        entry(2, 5, b"DATA", [(0x3F_3000, 0x5000), (0, 0)], 0, 0);

        let header_crc = crc32(&bytes[..HEADER_SIZE - 4]);
        put_u32(&mut bytes, 12, header_crc);
        let entries_crc = crc32(&bytes[HEADER_SIZE..HEADER_SIZE + 3 * ENTRY_SIZE]);
        put_u32(&mut bytes, HEADER_SIZE + 3 * ENTRY_SIZE, entries_crc);
        bytes
    }

    /// The check vector every other CRC here rests on. `bflb_soft_crc32` is
    /// CRC-32/ISO-HDLC, whose standard answer for "123456789" is this.
    #[test]
    fn crc32_matches_the_standard_vector() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn parses_a_table_and_finds_the_firmware() {
        let table = Table::parse(&build(7, 0, 0x1000, 1)).unwrap();
        assert_eq!(table.age(), 7);
        assert_eq!(table.entry_count(), 3);

        let fw = table.entry(ENTRY_TYPE_FW).unwrap();
        assert_eq!(fw.active_slot(), (0x1_0000, 0x20_0000));
        assert_eq!(fw.spare_slot(), Some((0x21_0000, 0x16_8000)));
        assert_eq!(fw.len, 0x1000);
    }

    #[test]
    fn a_partition_with_one_slot_has_no_spare() {
        let table = Table::parse(&build(1, 0, 0, 0)).unwrap();
        assert_eq!(table.entry(5).unwrap().spare_slot(), None);
    }

    #[test]
    fn rejects_a_blank_or_corrupt_sector() {
        assert_eq!(Table::parse(&[0xFF; TABLE_SIZE]), Err(Error::BadMagic));
        assert_eq!(Table::parse(&[0u8; 8]), Err(Error::Truncated));

        let mut bytes = build(1, 0, 0, 0);
        bytes[9] ^= 0x01; // age, which the header CRC covers
        assert_eq!(Table::parse(&bytes), Err(Error::HeaderCrc));

        let mut bytes = build(1, 0, 0, 0);
        bytes[HEADER_SIZE + ENTRY_SIZE + 12] ^= 0x01; // the FW start address
        assert_eq!(Table::parse(&bytes), Err(Error::EntriesCrc));

        let mut bytes = build(1, 0, 0, 0);
        bytes[6..8].copy_from_slice(&17u16.to_le_bytes());
        assert_eq!(Table::parse(&bytes), Err(Error::EntryCount));
    }

    #[test]
    fn the_higher_age_is_the_live_copy() {
        let old = Table::parse(&build(3, 0, 0, 0)).unwrap();
        let new = Table::parse(&build(4, 0, 0, 0)).unwrap();

        let (id, _) = active(Some(old.clone()), Some(new.clone())).unwrap();
        assert_eq!(id, TableId::One);
        let (id, _) = active(Some(new.clone()), Some(old.clone())).unwrap();
        assert_eq!(id, TableId::Zero);
        // A tie goes to copy 0, as the vendor's reader does it.
        let (id, _) = active(Some(old.clone()), Some(old.clone())).unwrap();
        assert_eq!(id, TableId::Zero);

        assert_eq!(active(None, Some(old)).unwrap().0, TableId::One);
        assert_eq!(active(None, None).unwrap_err(), Error::NoValidTable);
    }

    #[test]
    fn swapping_slots_publishes_a_table_that_still_validates() {
        let table = Table::parse(&build(9, 0, 0x1000, 4)).unwrap();
        let next = table.with_firmware_slot_swapped(0x2_5000).unwrap();

        // Reparsing is the real check: both CRCs were recomputed, or Boot2
        // would ignore what we just wrote.
        let next = Table::parse(next.as_bytes()).unwrap();
        assert_eq!(next.age(), 10);

        let fw = next.entry(ENTRY_TYPE_FW).unwrap();
        assert_eq!(fw.active_index, 1);
        assert_eq!(fw.age, 5);
        assert_eq!(fw.len, 0x2_5000);
        assert_eq!(fw.active_slot(), (0x21_0000, 0x16_8000));
        assert_eq!(fw.spare_slot(), Some((0x1_0000, 0x20_0000)));

        // And back again, so a board running from slot 1 can update too.
        let back =
            Table::parse(next.with_firmware_slot_swapped(0x1000).unwrap().as_bytes()).unwrap();
        assert_eq!(back.entry(ENTRY_TYPE_FW).unwrap().active_index, 0);
        assert_eq!(back.age(), 11);
    }

    #[test]
    fn swapping_leaves_every_other_entry_alone() {
        let table = Table::parse(&build(1, 0, 0, 0)).unwrap();
        let next = table.with_firmware_slot_swapped(64).unwrap();

        for kind in [16, 5] {
            assert_eq!(table.entry(kind).unwrap(), next.entry(kind).unwrap());
        }
        // Including the name bytes, which nothing here decodes.
        let name = HEADER_SIZE + ENTRY_SIZE + 3;
        assert_eq!(
            &table.as_bytes()[name..name + 9],
            &next.as_bytes()[name..name + 9]
        );
    }

    #[test]
    fn confirming_the_boot_clears_only_the_retry_byte() {
        // Nothing pending: no write to make.
        let settled = Table::parse(&build(1, 0, 0, 0x20)).unwrap();
        assert!(settled.with_boot_confirmed().unwrap().is_none());

        let pending = Table::parse(&build(1, 0, 0, 0x0300_0020)).unwrap();
        assert!(pending.entry(ENTRY_TYPE_FW).unwrap().boot_pending());

        let confirmed = pending.with_boot_confirmed().unwrap().unwrap();
        let confirmed = Table::parse(confirmed.as_bytes()).unwrap();
        let fw = confirmed.entry(ENTRY_TYPE_FW).unwrap();
        assert_eq!(fw.age, 0x20);
        assert!(!fw.boot_pending());
        // The slot is untouched: this reports success, it does not switch.
        assert_eq!(fw.active_index, 0);
    }

    #[test]
    fn an_update_is_written_to_the_other_copy() {
        assert_eq!(TableId::Zero.other(), TableId::One);
        assert_eq!(TableId::One.other(), TableId::Zero);
        assert_eq!(TableId::Zero.address(), TABLE0_ADDRESS);
        assert_eq!(TableId::One.address(), TABLE1_ADDRESS);
    }

    #[test]
    fn refuses_to_touch_an_entry_that_is_not_there() {
        let table = Table::parse(&build(1, 0, 0, 0)).unwrap();
        assert_eq!(table.entry(99), Err(Error::NotFound));
    }
}
