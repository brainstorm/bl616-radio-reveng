// SPDX-FileCopyrightText: 2026 Roman Valls Guimera <brainstorm@nopcode.org>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Failure modes of the WiFi stack.

use core::fmt;

pub type Result<T> = core::result::Result<T, Error>;

/// What went wrong.
#[derive(Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// [`crate::Wifi::init`] was called more than once.
    AlreadyInitialised,
    /// A parameter did not fit the vendor stack's limits — an SSID longer
    /// than 32 bytes, a passphrase longer than 63, a NUL byte in either.
    InvalidArgument,
    /// The stack accepted the request but never reported the outcome.
    Timeout,
    /// RF calibration failed, so the PHY has nothing usable to transmit with.
    /// Almost always a missing or unflashed `rftlv` region.
    RfInit(i32),
    /// The AP refused us, or dropped us during association. Wrong passphrase
    /// is by far the most common cause.
    ConnectionFailed,
    /// Associated, but no DHCP lease arrived before the deadline.
    DhcpTimeout,
    /// The SDK does not know a device by that name, which means
    /// `board_init()` has not run or the peripheral is not built in.
    NotFound,
    /// The vendor call returned a non-zero status.
    Vendor(i32),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::AlreadyInitialised => f.write_str("WiFi already initialised"),
            Error::InvalidArgument => f.write_str("invalid argument"),
            Error::Timeout => f.write_str("timed out waiting for the WiFi stack"),
            Error::RfInit(rc) => {
                write!(f, "RF calibration failed ({rc}); check the rftlv partition")
            }
            Error::ConnectionFailed => f.write_str("association failed"),
            Error::DhcpTimeout => f.write_str("DHCP timed out"),
            Error::NotFound => write!(f, "no such device (board_init not run?)"),
            Error::Vendor(rc) => write!(f, "vendor call failed ({rc})"),
        }
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
