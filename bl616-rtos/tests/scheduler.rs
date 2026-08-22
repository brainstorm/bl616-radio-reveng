// SPDX-FileCopyrightText: 2026 Roman Valls Guimera <brainstorm@nopcode.org>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Scheduling decisions, tested where they can be observed.
//!
//! A scheduler does not fail loudly. A wrong choice here shows up on hardware
//! as a task that runs a little too rarely, or a priority inversion that only
//! bites under load — so the decisions are pulled out and checked directly.

use bl616_rtos::task::{BlockedOn, Scheduler, TaskState};

const STACK: usize = 64;

#[test]
fn the_highest_priority_ready_task_runs() {
    let mut s = Scheduler::new();
    let _low = s.create("low", 5, STACK);
    let high = s.create("high", 20, STACK);
    let _mid = s.create("mid", 10, STACK);
    assert_eq!(s.pick_next(), Some(high));
}

#[test]
fn a_blocked_task_is_not_chosen() {
    let mut s = Scheduler::new();
    let low = s.create("low", 5, STACK);
    let high = s.create("high", 20, STACK);
    s.set_current(high);
    s.block_current(BlockedOn::Time, Some(10));
    assert_eq!(s.pick_next(), Some(low), "the blocked high task must be skipped");
}

#[test]
fn equal_priorities_do_not_ping_pong() {
    // Ties go to the running task, or two equal tasks swap on every tick and
    // spend their time context switching.
    let mut s = Scheduler::new();
    let a = s.create("a", 10, STACK);
    let _b = s.create("b", 10, STACK);
    s.set_current(a);
    assert_eq!(s.pick_next(), Some(a));
}

#[test]
fn a_delay_expires_on_the_right_tick_and_not_before() {
    let mut s = Scheduler::new();
    let t = s.create("t", 10, STACK);
    s.set_current(t);
    s.block_current(BlockedOn::Time, Some(3));

    for tick in 1..3 {
        s.tick();
        assert_eq!(
            s.get(t).unwrap().state,
            TaskState::Blocked,
            "woke early at tick {tick}"
        );
    }
    s.tick();
    assert_eq!(s.get(t).unwrap().state, TaskState::Ready);
}

#[test]
fn a_timeout_is_not_reported_as_success() {
    // The distinction between "the queue had something" and "time ran out" is
    // the return value of every blocking call in the system.
    let mut s = Scheduler::new();
    let t = s.create("t", 10, STACK);
    s.set_current(t);
    s.block_current(BlockedOn::Object(0x1234 as *const _), Some(2));
    s.tick();
    s.tick();
    let task = s.get(t).unwrap();
    assert_eq!(task.state, TaskState::Ready);
    assert!(!task.wait_succeeded, "a timeout must not look like a wake-up");
}

#[test]
fn being_woken_by_the_object_reports_success() {
    let mut s = Scheduler::new();
    let t = s.create("t", 10, STACK);
    s.set_current(t);
    s.block_current(BlockedOn::Object(0x1234 as *const _), Some(50));
    s.wake(t);
    let task = s.get(t).unwrap();
    assert_eq!(task.state, TaskState::Ready);
    assert!(task.wait_succeeded);
}

#[test]
fn an_indefinite_wait_is_never_timed_out() {
    let mut s = Scheduler::new();
    let t = s.create("t", 10, STACK);
    s.set_current(t);
    s.block_current(BlockedOn::Object(0x99 as *const _), None);
    for _ in 0..10_000 {
        s.tick();
    }
    assert_eq!(s.get(t).unwrap().state, TaskState::Blocked);
}

#[test]
fn a_release_hands_off_to_the_highest_priority_waiter() {
    let obj = 0xabc as *const core::ffi::c_void;
    let mut s = Scheduler::new();
    let low = s.create("low", 5, STACK);
    let high = s.create("high", 25, STACK);
    let mid = s.create("mid", 15, STACK);

    for t in [low, high, mid] {
        s.set_current(t);
        s.block_current(BlockedOn::Object(obj), None);
    }
    assert_eq!(s.highest_waiter(obj), Some(high));
}

#[test]
fn waiters_on_another_object_are_not_woken() {
    let a = 0xa as *const core::ffi::c_void;
    let b = 0xb as *const core::ffi::c_void;
    let mut s = Scheduler::new();
    let t = s.create("t", 10, STACK);
    s.set_current(t);
    s.block_current(BlockedOn::Object(a), None);
    assert_eq!(s.highest_waiter(b), None);
    assert_eq!(s.highest_waiter(a), Some(t));
}

#[test]
fn priority_inheritance_lifts_the_holder_and_restores_it() {
    let mut s = Scheduler::new();
    let holder = s.create("holder", 5, STACK);
    // A high-priority task waits on a mutex the low-priority one holds.
    assert!(s.inherit_priority(holder, 25));
    assert_eq!(s.get(holder).unwrap().priority, 25);
    assert_eq!(s.get(holder).unwrap().base_priority, 5, "the base is remembered");

    // Still held: no restoration yet.
    s.get_mut(holder).unwrap().mutexes_held = 1;
    assert!(!s.disinherit_priority(holder));
    assert_eq!(s.get(holder).unwrap().priority, 25);

    s.get_mut(holder).unwrap().mutexes_held = 0;
    assert!(s.disinherit_priority(holder));
    assert_eq!(s.get(holder).unwrap().priority, 5);
}

#[test]
fn inheritance_never_lowers_a_priority() {
    let mut s = Scheduler::new();
    let holder = s.create("holder", 20, STACK);
    assert!(!s.inherit_priority(holder, 10), "a lower waiter must change nothing");
    assert_eq!(s.get(holder).unwrap().priority, 20);
}

#[test]
fn no_switch_happens_while_scheduling_is_suspended() {
    let mut s = Scheduler::new();
    s.suspend_all();
    assert!(!s.switch_allowed());
    assert!(!s.request_yield(), "a yield must be deferred, not performed");
    // ... and the deferred switch is owed when scheduling resumes.
    assert!(s.resume_all());
    assert!(s.switch_allowed());
}

#[test]
fn suspension_nests() {
    let mut s = Scheduler::new();
    s.suspend_all();
    s.suspend_all();
    s.request_yield();
    assert!(!s.resume_all(), "still suspended one level deep");
    assert!(s.resume_all(), "now the switch is owed");
}

#[test]
fn resuming_without_a_pending_yield_asks_for_nothing() {
    let mut s = Scheduler::new();
    s.suspend_all();
    assert!(!s.resume_all());
}

#[test]
fn a_tick_preempts_an_equal_priority_peer() {
    // Time slicing: with two runnable tasks at the same priority, the tick
    // has to offer the other one a turn.
    let mut s = Scheduler::new();
    let a = s.create("a", 10, STACK);
    let _b = s.create("b", 10, STACK);
    s.set_current(a);
    assert!(s.tick(), "an equal-priority peer should force a switch");
}

#[test]
fn a_tick_with_nothing_else_runnable_does_not_switch() {
    let mut s = Scheduler::new();
    let a = s.create("a", 10, STACK);
    let low = s.create("low", 1, STACK);
    s.set_current(a);
    // Only a lower-priority task exists, so there is nothing to switch to.
    assert!(!s.tick());
    let _ = low;
}

#[test]
fn deleted_tasks_are_reclaimed_but_never_the_running_one() {
    let mut s = Scheduler::new();
    let a = s.create("a", 10, STACK);
    let b = s.create("b", 10, STACK);
    s.set_current(a);
    s.get_mut(a).unwrap().state = TaskState::Deleted;
    s.get_mut(b).unwrap().state = TaskState::Deleted;
    s.reap();
    // `a` is still running on its own stack; freeing it now would pull the
    // ground out from under the very code doing the freeing.
    assert!(s.get(a).is_some(), "the running task must survive its own deletion");
    assert!(s.get(b).is_none());
}

#[test]
fn priorities_are_clamped_to_the_configured_maximum() {
    let mut s = Scheduler::new();
    let t = s.create("t", 999, STACK);
    assert_eq!(s.get(t).unwrap().priority, bl616_rtos::MAX_PRIORITIES - 1);
}

#[test]
fn task_count_ignores_deleted_tasks() {
    let mut s = Scheduler::new();
    let a = s.create("a", 10, STACK);
    s.create("b", 10, STACK);
    assert_eq!(s.task_count(), 2);
    s.get_mut(a).unwrap().state = TaskState::Deleted;
    assert_eq!(s.task_count(), 1);
}
