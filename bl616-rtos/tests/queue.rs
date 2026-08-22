// SPDX-FileCopyrightText: 2026 Roman Valls Guimera <brainstorm@nopcode.org>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Queue, semaphore and mutex storage behaviour.

use bl616_rtos::queue::{Queue, QueueKind};
use core::ffi::c_void;

fn push(q: &mut Queue, v: u32) -> bool {
    unsafe { q.push_back(&v as *const u32 as *const c_void) }
}
fn push_front(q: &mut Queue, v: u32) -> bool {
    unsafe { q.push_front(&v as *const u32 as *const c_void) }
}
fn pop(q: &mut Queue) -> Option<u32> {
    let mut v = 0u32;
    unsafe { q.pop_front(&mut v as *mut u32 as *mut c_void) }.then_some(v)
}

#[test]
fn items_come_back_in_order() {
    let mut q = Queue::new(4, 4, QueueKind::Base);
    assert!(push(&mut q, 1));
    assert!(push(&mut q, 2));
    assert!(push(&mut q, 3));
    assert_eq!(pop(&mut q), Some(1));
    assert_eq!(pop(&mut q), Some(2));
    assert_eq!(pop(&mut q), Some(3));
    assert_eq!(pop(&mut q), None);
}

#[test]
fn a_full_queue_refuses_rather_than_overwriting() {
    let mut q = Queue::new(2, 4, QueueKind::Base);
    assert!(push(&mut q, 1));
    assert!(push(&mut q, 2));
    assert!(!push(&mut q, 3), "the third item must be refused");
    assert_eq!(q.len(), 2);
    assert_eq!(pop(&mut q), Some(1), "and must not have displaced the first");
}

#[test]
fn the_ring_wraps_without_losing_or_reordering() {
    // The bug this catches is an index that wraps for writes but not reads.
    let mut q = Queue::new(3, 4, QueueKind::Base);
    for round in 0..10u32 {
        assert!(push(&mut q, round * 3));
        assert!(push(&mut q, round * 3 + 1));
        assert_eq!(pop(&mut q), Some(round * 3));
        assert_eq!(pop(&mut q), Some(round * 3 + 1));
    }
    assert!(q.is_empty());
}

#[test]
fn send_to_front_jumps_the_queue() {
    let mut q = Queue::new(4, 4, QueueKind::Base);
    push(&mut q, 1);
    push(&mut q, 2);
    assert!(push_front(&mut q, 99));
    assert_eq!(pop(&mut q), Some(99));
    assert_eq!(pop(&mut q), Some(1));
    assert_eq!(pop(&mut q), Some(2));
}

#[test]
fn send_to_front_wraps_below_zero_correctly() {
    // head is 0 here, so the front insert has to wrap to the top of the ring.
    let mut q = Queue::new(3, 4, QueueKind::Base);
    assert!(push_front(&mut q, 7));
    assert_eq!(pop(&mut q), Some(7));
}

#[test]
fn peek_leaves_the_item_in_place() {
    let mut q = Queue::new(2, 4, QueueKind::Base);
    push(&mut q, 42);
    let mut v = 0u32;
    assert!(unsafe { q.peek(&mut v as *mut u32 as *mut c_void) });
    assert_eq!(v, 42);
    assert_eq!(q.len(), 1, "peek must not consume");
    assert_eq!(pop(&mut q), Some(42));
}

#[test]
fn a_binary_semaphore_starts_empty() {
    let q = Queue::new(1, 0, QueueKind::BinarySemaphore);
    assert!(q.is_empty(), "taking one before a give must block");
}

#[test]
fn a_counting_semaphore_starts_at_its_initial_count() {
    let q = Queue::counting(5, 3);
    assert_eq!(q.len(), 3);
    assert!(!q.is_full());
}

#[test]
fn a_counting_semaphore_will_not_exceed_its_maximum() {
    let mut q = Queue::counting(2, 2);
    assert!(q.is_full());
    assert!(!unsafe { q.push_back(core::ptr::null()) });
    assert_eq!(q.len(), 2);
}

#[test]
fn a_mutex_starts_available() {
    // The opposite of a binary semaphore, and getting it backwards deadlocks
    // the first task that takes one.
    let q = Queue::new(1, 0, QueueKind::Mutex);
    assert_eq!(q.len(), 1);
    assert!(q.is_mutex());
}

#[test]
fn reset_restores_the_starting_count_for_each_kind() {
    let mut q = Queue::new(4, 4, QueueKind::Base);
    push(&mut q, 1);
    push(&mut q, 2);
    q.reset();
    assert!(q.is_empty());
    assert_eq!(pop(&mut q), None);

    let mut m = Queue::new(1, 0, QueueKind::Mutex);
    unsafe { m.pop_front(core::ptr::null_mut()) };
    assert!(m.is_empty());
    m.reset();
    assert_eq!(m.len(), 1, "a reset mutex is available again");
}

#[test]
fn zero_sized_items_do_not_touch_storage() {
    let mut q = Queue::new(3, 0, QueueKind::CountingSemaphore);
    assert!(unsafe { q.push_back(core::ptr::null()) });
    assert!(unsafe { q.push_back(core::ptr::null()) });
    assert_eq!(q.len(), 2);
    assert!(unsafe { q.pop_front(core::ptr::null_mut()) });
    assert_eq!(q.len(), 1);
}

#[test]
fn spaces_tracks_occupancy() {
    let mut q = Queue::new(3, 4, QueueKind::Base);
    assert_eq!(q.spaces(), 3);
    push(&mut q, 1);
    assert_eq!(q.spaces(), 2);
    pop(&mut q);
    assert_eq!(q.spaces(), 3);
}
