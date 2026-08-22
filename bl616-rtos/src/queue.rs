// SPDX-FileCopyrightText: 2026 Roman Valls Guimera <brainstorm@nopcode.org>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Queues, and the semaphores and mutexes built on them.
//!
//! FreeRTOS makes all three one object, and so does this: a semaphore is a
//! queue of zero-sized items where the count is the occupancy, and a mutex is
//! a binary semaphore that remembers its holder so priority can be inherited.
//! Keeping that shape matters because the C calls them interchangeably —
//! `vQueueDelete` frees all three.

use alloc::vec::Vec;
use core::ffi::c_void;

/// What a queue is being used as.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum QueueKind {
    Base,
    BinarySemaphore,
    CountingSemaphore,
    Mutex,
    RecursiveMutex,
}

/// A queue, semaphore or mutex.
pub struct Queue {
    pub kind: QueueKind,
    /// Bytes per item; zero for semaphores.
    pub item_size: usize,
    pub capacity: usize,
    /// Item storage, `capacity * item_size` bytes, used as a ring.
    storage: Vec<u8>,
    head: usize,
    count: usize,
    /// For mutexes: who holds it, and how deeply if recursive.
    pub holder: Option<*mut crate::task::Tcb>,
    pub recursive_depth: u32,
}

impl Queue {
    pub fn new(capacity: usize, item_size: usize, kind: QueueKind) -> Self {
        let count = match kind {
            // A mutex starts available; everything else starts empty.
            QueueKind::Mutex | QueueKind::RecursiveMutex => 1,
            _ => 0,
        };
        Queue {
            kind,
            item_size,
            capacity: capacity.max(1),
            storage: alloc::vec![0u8; capacity.max(1) * item_size],
            head: 0,
            count,
            holder: None,
            recursive_depth: 0,
        }
    }

    /// Counting semaphore with an initial count.
    pub fn counting(max: usize, initial: usize) -> Self {
        let mut q = Queue::new(max, 0, QueueKind::CountingSemaphore);
        q.count = initial.min(max);
        q
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn is_full(&self) -> bool {
        self.count >= self.capacity
    }

    pub fn spaces(&self) -> usize {
        self.capacity - self.count
    }

    /// Append an item. Returns false when full.
    ///
    /// # Safety
    ///
    /// `item` must point to `item_size` readable bytes, or be null for a
    /// semaphore.
    pub unsafe fn push_back(&mut self, item: *const c_void) -> bool {
        if self.is_full() {
            return false;
        }
        if self.item_size > 0 && !item.is_null() {
            let slot = (self.head + self.count) % self.capacity;
            let dst = self.storage.as_mut_ptr().wrapping_add(slot * self.item_size);
            unsafe { core::ptr::copy_nonoverlapping(item as *const u8, dst, self.item_size) };
        }
        self.count += 1;
        true
    }

    /// Insert at the front, for `queueSEND_TO_FRONT`.
    ///
    /// # Safety
    ///
    /// As [`Queue::push_back`].
    pub unsafe fn push_front(&mut self, item: *const c_void) -> bool {
        if self.is_full() {
            return false;
        }
        self.head = (self.head + self.capacity - 1) % self.capacity;
        if self.item_size > 0 && !item.is_null() {
            let dst = self
                .storage
                .as_mut_ptr()
                .wrapping_add(self.head * self.item_size);
            unsafe { core::ptr::copy_nonoverlapping(item as *const u8, dst, self.item_size) };
        }
        self.count += 1;
        true
    }

    /// Remove the oldest item. Returns false when empty.
    ///
    /// # Safety
    ///
    /// `out` must point to `item_size` writable bytes, or be null.
    pub unsafe fn pop_front(&mut self, out: *mut c_void) -> bool {
        if self.is_empty() {
            return false;
        }
        if self.item_size > 0 && !out.is_null() {
            let src = self
                .storage
                .as_ptr()
                .wrapping_add(self.head * self.item_size);
            unsafe { core::ptr::copy_nonoverlapping(src, out as *mut u8, self.item_size) };
        }
        self.head = (self.head + 1) % self.capacity;
        self.count -= 1;
        true
    }

    /// Read the oldest item without removing it.
    ///
    /// # Safety
    ///
    /// As [`Queue::pop_front`].
    pub unsafe fn peek(&self, out: *mut c_void) -> bool {
        if self.is_empty() {
            return false;
        }
        if self.item_size > 0 && !out.is_null() {
            let src = self
                .storage
                .as_ptr()
                .wrapping_add(self.head * self.item_size);
            unsafe { core::ptr::copy_nonoverlapping(src, out as *mut u8, self.item_size) };
        }
        true
    }

    /// Discard everything, as `xQueueGenericReset` does.
    pub fn reset(&mut self) {
        self.head = 0;
        self.count = match self.kind {
            QueueKind::Mutex | QueueKind::RecursiveMutex => 1,
            _ => 0,
        };
    }

    pub fn is_mutex(&self) -> bool {
        matches!(self.kind, QueueKind::Mutex | QueueKind::RecursiveMutex)
    }
}
