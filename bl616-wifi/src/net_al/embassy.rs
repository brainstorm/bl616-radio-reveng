// SPDX-FileCopyrightText: 2026 Roman Valls Guimera <brainstorm@nopcode.org>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! The MAC as an [`embassy_net_driver::Driver`].
//!
//! embassy-net owns its own smoltcp instance, so it does not consume the
//! `Interface` in [`super::stack`] — it consumes the layer underneath: the RX
//! ring in [`super::iface`] and the shared-RAM TX pool in [`super::txbuf`].
//! Those are shared with the smoltcp front end; only the consumer differs.
//!
//! # Polled versus woken
//!
//! This is the one real difference from the smoltcp device, and getting it
//! wrong looks like a stack that receives nothing. smoltcp's `receive` is
//! called on a timer, so returning `None` costs a 5 ms retry. embassy-net
//! calls this once and then sleeps: if it returns `None` without arming
//! `cx.waker()`, nothing will ever wake it again. `iface::RX_WAKER` is woken
//! by the blob's arrival path and `txbuf::TX_WAKER` when a buffer is freed.
//!
//! # One consumer
//!
//! The ring is single-consumer, so the smoltcp poll task is not started when
//! this front end is compiled in — see `stack::start`.

use core::task::Context;

use embassy_net_driver::{Capabilities, Driver, HardwareAddress, LinkState, RxToken, TxToken};

use super::iface::{self, NetIf, RX_FRAME_MAX};
use super::txbuf;

/// MTU the vendor MAC presents.
const MTU: usize = 1500;

/// The device handed to `embassy_net::Stack`.
pub struct WifiDriver {
    net_if: *mut NetIf,
    /// Landing area for a popped frame, reused across calls so the big buffer
    /// is not a stack temporary.
    scratch: alloc::boxed::Box<[u8; RX_FRAME_MAX]>,
}

impl WifiDriver {
    /// Bind to an interface the blob has registered.
    ///
    /// Returns `None` until the blob has added one, which happens during
    /// `wifi_mgmr` bring-up — poll after the interface is up.
    pub fn new(index: usize) -> Option<Self> {
        let net_if = iface::by_index(index)?;
        Some(WifiDriver {
            net_if,
            scratch: alloc::boxed::Box::new([0u8; RX_FRAME_MAX]),
        })
    }

    /// The MAC address the blob assigned to this interface.
    pub fn mac(&self) -> [u8; 6] {
        unsafe { (*self.net_if).mac }
    }
}

pub struct WifiRxToken<'a> {
    frame: &'a mut [u8],
}

impl RxToken for WifiRxToken<'_> {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        f(self.frame)
    }
}

pub struct WifiTxToken {
    net_if: *mut NetIf,
}

impl TxToken for WifiTxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        // `transmit` already established there was a free buffer, and this
        // call is infallible by contract -- but the pool is lock-free and the
        // blob frees from interrupt context, so the slot can still be gone.
        // Building into scratch and dropping it is the same outcome as a
        // collision; the peer retransmits.
        let Some(buf) = txbuf::alloc() else {
            let mut scratch = [0u8; MTU + 14];
            let n = len.min(scratch.len());
            return f(&mut scratch[..n]);
        };

        let result = unsafe {
            let frame = (*buf).frame_ptr();
            let n = len.min(txbuf::MAX_FRAME);
            let slice = core::slice::from_raw_parts_mut(frame, n);
            let r = f(slice);
            (*buf).len = n as u16;
            r
        };

        let rc = unsafe {
            super::fhost_tx_start(
                self.net_if as *mut core::ffi::c_void,
                buf as *mut core::ffi::c_void,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        };
        if rc != 0 {
            unsafe { txbuf::free(buf) };
        }
        result
    }
}

impl Driver for WifiDriver {
    type RxToken<'a>
        = WifiRxToken<'a>
    where
        Self: 'a;
    type TxToken<'a>
        = WifiTxToken
    where
        Self: 'a;

    fn receive(&mut self, cx: &mut Context) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        // Arm the waker before looking. The other order loses a frame that
        // arrives between the failed pop and the registration, and the stack
        // then sleeps with a full ring.
        iface::RX_WAKER.register(cx.waker());
        let (len, _iface) = iface::rx_pop(&mut self.scratch[..])?;
        Some((
            WifiRxToken {
                frame: &mut self.scratch[..len],
            },
            WifiTxToken {
                net_if: self.net_if,
            },
        ))
    }

    fn transmit(&mut self, cx: &mut Context) -> Option<Self::TxToken<'_>> {
        txbuf::TX_WAKER.register(cx.waker());
        if txbuf::free_count() == 0 {
            return None;
        }
        Some(WifiTxToken {
            net_if: self.net_if,
        })
    }

    fn link_state(&mut self, cx: &mut Context) -> LinkState {
        // The blob reports link changes through net_if_up_cb/net_if_down_cb,
        // which is not a waking path -- so keep the stack polling us by
        // waking on every frame, which is when a state change matters.
        iface::RX_WAKER.register(cx.waker());
        if unsafe { (*self.net_if).link_up.load(core::sync::atomic::Ordering::Acquire) } {
            LinkState::Up
        } else {
            LinkState::Down
        }
    }

    fn capabilities(&self) -> Capabilities {
        let mut caps = Capabilities::default();
        caps.max_transmission_unit = MTU;
        // One buffer per frame, so the pool depth is the burst ceiling.
        caps.max_burst_size = Some(txbuf::POOL_SIZE);
        caps
    }

    fn hardware_address(&self) -> HardwareAddress {
        HardwareAddress::Ethernet(self.mac())
    }
}

extern crate alloc;
