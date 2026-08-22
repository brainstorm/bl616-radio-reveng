// SPDX-FileCopyrightText: 2026 Roman Valls Guimera <brainstorm@nopcode.org>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! The FreeRTOS C API, bound to the scheduler.
//!
//! 57 symbols: what the SDK's C substrate references from outside
//! `libfreertos.a`. Everything else FreeRTOS defines is internal and leaves
//! with it.
//!
//! # One lock, taken by masking interrupts
//!
//! The scheduler is a single global reached only with interrupts masked.
//! That is the same discipline FreeRTOS uses and it is the right one here:
//! the blobs call this from tasks and from interrupt handlers, and there is
//! one core, so masking is both necessary and sufficient. Nothing in the
//! critical sections below blocks or allocates.
//!
//! # How blocking works
//!
//! A blocking call marks the task blocked, drops the lock, and asks for a
//! switch. Execution resumes inside the same function when the scheduler
//! chooses this task again, at which point `wait_succeeded` says whether the
//! object became available or the timeout expired. The retry loop matters:
//! being woken is not the same as winning the object, because a
//! higher-priority task can take it first.

use alloc::boxed::Box;
use core::ffi::{c_char, c_void};

use crate::port::Port;
use crate::port_riscv::{pxCurrentTCB, RiscvPort};
use crate::queue::{Queue, QueueKind};
use crate::task::{BlockedOn, Scheduler, TaskState, Tcb};

type BaseType = i32;
type UBaseType = u32;
type TickType = u32;

const PD_TRUE: BaseType = 1;
const PD_FALSE: BaseType = 0;
/// `errQUEUE_EMPTY` and `errQUEUE_FULL` are both zero, like `pdFAIL`.
const ERR_QUEUE: BaseType = 0;
/// Wait forever.
const MAX_DELAY: TickType = TickType::MAX;

/// The scheduler, reached only under [`lock`].
static mut SCHEDULER: Scheduler = Scheduler::new();

/// Run `f` with interrupts masked and the scheduler in hand.
fn lock<R>(f: impl FnOnce(&mut Scheduler) -> R) -> R {
    let state = RiscvPort::enter_critical();
    let r = f(unsafe { &mut *core::ptr::addr_of_mut!(SCHEDULER) });
    unsafe { RiscvPort::exit_critical(state) };
    r
}

/// Publish the chosen task where the context switch can find it.
fn publish_current(s: &Scheduler) {
    if let Some(c) = s.current() {
        unsafe { pxCurrentTCB = c };
    }
}

fn ticks_to_opt(t: TickType) -> Option<u64> {
    if t == MAX_DELAY {
        None
    } else {
        Some(t as u64)
    }
}

// ----------------------------------------------------------------- switching

/// Choose the next task. Called from the context-switch assembly, which has
/// already saved the outgoing context.
#[unsafe(no_mangle)]
pub extern "C" fn vTaskSwitchContext() {
    // Already inside the handler with interrupts masked, so no lock is taken
    // here: doing so would re-enable them on the way out.
    let s = unsafe { &mut *core::ptr::addr_of_mut!(SCHEDULER) };
    if !s.switch_allowed() {
        s.request_yield();
        return;
    }
    if let Some(next) = s.pick_next() {
        s.set_current(next);
        publish_current(s);
    }
}

/// Advance time. Called from the platform's timer interrupt.
#[unsafe(no_mangle)]
pub extern "C" fn xTaskIncrementTick() -> BaseType {
    let s = unsafe { &mut *core::ptr::addr_of_mut!(SCHEDULER) };
    let want_switch = s.tick();
    if want_switch && s.switch_allowed() {
        PD_TRUE
    } else {
        if want_switch {
            s.request_yield();
        }
        PD_FALSE
    }
}

// --------------------------------------------------------------------- tasks

/// # Safety
///
/// `name` must be a NUL-terminated string; `created` may be null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xTaskCreate(
    code: Option<extern "C" fn(*mut c_void)>,
    name: *const c_char,
    stack_words: u16,
    params: *mut c_void,
    priority: UBaseType,
    created: *mut *mut Tcb,
) -> BaseType {
    let Some(entry) = code else { return PD_FALSE };
    let name = unsafe { cstr(name) };

    let handle = lock(|s| {
        let h = s.create(name, priority, stack_words as usize);
        if let Some(t) = s.get_mut(h) {
            let top = t.stack_top();
            t.stack_ptr = unsafe { RiscvPort::init_stack(top, entry, params) };
        }
        h
    });

    if !created.is_null() {
        unsafe { *created = handle };
    }
    // A new task may outrank the running one.
    if lock(|s| s.is_running() && s.request_yield()) {
        RiscvPort::yield_now();
    }
    PD_TRUE
}

/// # Safety
///
/// `task` must be a live handle, or null for the caller.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vTaskDelete(task: *mut Tcb) {
    let is_self = lock(|s| {
        let target = if task.is_null() { s.current() } else { Some(task) };
        let Some(target) = target else { return false };
        if let Some(t) = s.get_mut(target) {
            t.state = TaskState::Deleted;
        }
        s.current() == Some(target)
    });
    lock(|s| s.reap());
    if is_self {
        RiscvPort::yield_now();
        loop {
            core::hint::spin_loop();
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn vTaskDelay(ticks: TickType) {
    if ticks == 0 {
        RiscvPort::yield_now();
        return;
    }
    lock(|s| s.block_current(BlockedOn::Time, Some(ticks as u64)));
    RiscvPort::yield_now();
}

#[unsafe(no_mangle)]
pub extern "C" fn vTaskStartScheduler() {
    let sp = lock(|s| {
        s.set_running(true);
        let next = s.pick_next()?;
        s.set_current(next);
        publish_current(s);
        s.get(next).map(|t| t.stack_ptr)
    });
    if let Some(sp) = sp {
        unsafe { RiscvPort::start_first_task(sp) }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn xTaskGetCurrentTaskHandle() -> *mut Tcb {
    lock(|s| s.current().unwrap_or(core::ptr::null_mut()))
}

/// # Safety
///
/// `name` must be NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xTaskGetHandle(name: *const c_char) -> *mut Tcb {
    let want = unsafe { cstr(name) };
    lock(|s| {
        for t in s.iter() {
            if t.name == want {
                return t as *const Tcb as *mut Tcb;
            }
        }
        core::ptr::null_mut()
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn xTaskGetTickCount() -> TickType {
    lock(|s| s.tick_count() as TickType)
}

#[unsafe(no_mangle)]
pub extern "C" fn xTaskGetTickCountFromISR() -> TickType {
    let s = unsafe { &*core::ptr::addr_of!(SCHEDULER) };
    s.tick_count() as TickType
}

/// `taskSCHEDULER_NOT_STARTED` = 1, `taskSCHEDULER_RUNNING` = 2,
/// `taskSCHEDULER_SUSPENDED` = 0.
#[unsafe(no_mangle)]
pub extern "C" fn xTaskGetSchedulerState() -> BaseType {
    lock(|s| {
        if !s.is_running() {
            1
        } else if s.switch_allowed() {
            2
        } else {
            0
        }
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn vTaskSuspendAll() {
    lock(|s| s.suspend_all());
}

#[unsafe(no_mangle)]
pub extern "C" fn xTaskResumeAll() -> BaseType {
    let owed = lock(|s| s.resume_all());
    if owed {
        RiscvPort::yield_now();
        return PD_TRUE;
    }
    PD_FALSE
}

#[unsafe(no_mangle)]
pub extern "C" fn vTaskEnterCritical() {
    // Nesting is tracked by the port's saved state, kept in a counter so the
    // outermost exit is the one that re-enables.
    let state = RiscvPort::enter_critical();
    unsafe {
        if CRITICAL_NESTING == 0 {
            CRITICAL_SAVED = state;
        }
        CRITICAL_NESTING += 1;
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn vTaskExitCritical() {
    unsafe {
        if CRITICAL_NESTING == 0 {
            return;
        }
        CRITICAL_NESTING -= 1;
        if CRITICAL_NESTING == 0 {
            RiscvPort::exit_critical(CRITICAL_SAVED);
        }
    }
}

static mut CRITICAL_NESTING: u32 = 0;
static mut CRITICAL_SAVED: usize = 0;

/// # Safety
///
/// `task` must be live, or null for the caller.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vTaskPrioritySet(task: *mut Tcb, priority: UBaseType) {
    let switch = lock(|s| {
        let target = if task.is_null() { s.current() } else { Some(task) };
        let Some(target) = target else { return false };
        if let Some(t) = s.get_mut(target) {
            t.base_priority = priority.min(crate::MAX_PRIORITIES - 1);
            // Do not drop a priority that is currently lent by inheritance.
            if t.mutexes_held == 0 || priority > t.priority {
                t.priority = t.base_priority;
            }
        }
        s.request_yield()
    });
    if switch {
        RiscvPort::yield_now();
    }
}

/// # Safety
///
/// `task` must be live, or null for the caller.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn uxTaskPriorityGet(task: *mut Tcb) -> UBaseType {
    lock(|s| {
        let target = if task.is_null() { s.current() } else { Some(task) };
        target.and_then(|h| s.get(h)).map_or(0, |t| t.priority)
    })
}

/// `eRunning` 0, `eReady` 1, `eBlocked` 2, `eSuspended` 3, `eDeleted` 4.
///
/// # Safety
///
/// `task` must be live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn eTaskGetState(task: *mut Tcb) -> u8 {
    lock(|s| {
        let running = s.current() == Some(task);
        match s.get(task).map(|t| t.state) {
            Some(TaskState::Ready) if running => 0,
            Some(TaskState::Ready) => 1,
            Some(TaskState::Blocked) => 2,
            Some(TaskState::Suspended) => 3,
            _ => 4,
        }
    })
}

/// # Safety
///
/// `task` must be live, or null for the caller.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pcTaskGetName(task: *mut Tcb) -> *const c_char {
    lock(|s| {
        let target = if task.is_null() { s.current() } else { Some(task) };
        target
            .and_then(|h| s.get(h))
            .map_or(core::ptr::null(), |t| t.name.as_ptr() as *const c_char)
    })
}

/// # Safety
///
/// `task` must be live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vTaskSetTaskNumber(task: *mut Tcb, number: UBaseType) {
    lock(|s| {
        if let Some(t) = s.get_mut(task) {
            t.task_number = number;
        }
    });
}

#[unsafe(no_mangle)]
pub extern "C" fn uxTaskGetNumberOfTasks() -> UBaseType {
    lock(|s| s.task_count() as UBaseType)
}

/// # Safety
///
/// `task` must be live; `index` must be within the configured slot count.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vTaskSetThreadLocalStoragePointerAndDelCallback(
    task: *mut Tcb,
    _index: BaseType,
    value: *mut c_void,
    _cb: *mut c_void,
) {
    lock(|s| {
        let target = if task.is_null() { s.current() } else { Some(task) };
        if let Some(t) = target.and_then(|h| s.get_mut(h)) {
            t.tls = value;
        }
    });
}

/// # Safety
///
/// As above.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pvTaskGetThreadLocalStoragePointer(
    task: *mut Tcb,
    _index: BaseType,
) -> *mut c_void {
    lock(|s| {
        let target = if task.is_null() { s.current() } else { Some(task) };
        target
            .and_then(|h| s.get(h))
            .map_or(core::ptr::null_mut(), |t| t.tls)
    })
}

// ------------------------------------------------------------ notifications

/// `eIncrement` is 2; the other actions set or overwrite the value.
///
/// # Safety
///
/// `task` must be live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xTaskGenericNotify(
    task: *mut Tcb,
    _index: UBaseType,
    value: u32,
    action: u8,
    previous: *mut u32,
) -> BaseType {
    let switch = lock(|s| {
        let Some(t) = s.get_mut(task) else {
            return false;
        };
        if !previous.is_null() {
            unsafe { *previous = t.notify_value };
        }
        match action {
            1 => t.notify_value |= value,     // eSetBits
            2 => t.notify_value += 1,         // eIncrement
            3 => t.notify_value = value,      // eSetValueWithOverwrite
            4 => {
                if t.notify_pending {
                    return false;
                }
                t.notify_value = value;
            }
            _ => {}
        }
        t.notify_pending = true;
        let waiting = t.state == TaskState::Blocked
            && t.blocked_on == Some(BlockedOn::Notification);
        if waiting {
            s.wake(task);
            return s.request_yield();
        }
        false
    });
    if switch {
        RiscvPort::yield_now();
    }
    PD_TRUE
}

/// # Safety
///
/// `task` must be live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vTaskGenericNotifyGiveFromISR(
    task: *mut Tcb,
    index: UBaseType,
    higher_woken: *mut BaseType,
) {
    let switch = unsafe {
        xTaskGenericNotify(task, index, 0, 2, core::ptr::null_mut()) == PD_TRUE
    };
    if !higher_woken.is_null() {
        unsafe { *higher_woken = switch as BaseType };
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ulTaskGenericNotifyTake(
    _index: UBaseType,
    clear_on_exit: BaseType,
    ticks: TickType,
) -> u32 {
    loop {
        let taken = lock(|s| {
            let cur = s.current()?;
            let t = s.get_mut(cur)?;
            if t.notify_value > 0 {
                let v = t.notify_value;
                if clear_on_exit != PD_FALSE {
                    t.notify_value = 0;
                } else {
                    t.notify_value -= 1;
                }
                t.notify_pending = false;
                return Some(v);
            }
            None
        });
        if let Some(v) = taken {
            return v;
        }
        if ticks == 0 {
            return 0;
        }
        let blocked = lock(|s| {
            s.block_current(BlockedOn::Notification, ticks_to_opt(ticks));
            s.current().is_some()
        });
        if !blocked {
            return 0;
        }
        RiscvPort::yield_now();
        // Woken: either the notification arrived or the wait timed out.
        let timed_out = lock(|s| {
            s.current()
                .and_then(|c| s.get(c))
                .is_some_and(|t| !t.wait_succeeded)
        });
        if timed_out {
            return lock(|s| {
                s.current()
                    .and_then(|c| s.get(c))
                    .map_or(0, |t| t.notify_value)
            });
        }
    }
}

// ------------------------------------------------------------------- queues

fn queue_handle(q: Box<Queue>) -> *mut Queue {
    Box::into_raw(q)
}

#[unsafe(no_mangle)]
pub extern "C" fn xQueueGenericCreate(
    length: UBaseType,
    item_size: UBaseType,
    queue_type: u8,
) -> *mut Queue {
    let kind = match queue_type {
        3 => QueueKind::BinarySemaphore,
        2 => QueueKind::CountingSemaphore,
        1 | 4 => QueueKind::Mutex,
        _ => QueueKind::Base,
    };
    queue_handle(Box::new(Queue::new(
        length as usize,
        item_size as usize,
        kind,
    )))
}

#[unsafe(no_mangle)]
pub extern "C" fn xQueueCreateMutex(queue_type: u8) -> *mut Queue {
    let kind = if queue_type == 4 {
        QueueKind::RecursiveMutex
    } else {
        QueueKind::Mutex
    };
    queue_handle(Box::new(Queue::new(1, 0, kind)))
}

/// Static creation is given a caller-provided buffer we do not need; the
/// allocation is ours either way, which is behaviourally identical here.
#[unsafe(no_mangle)]
pub extern "C" fn xQueueCreateMutexStatic(queue_type: u8, _storage: *mut c_void) -> *mut Queue {
    xQueueCreateMutex(queue_type)
}

#[unsafe(no_mangle)]
pub extern "C" fn xQueueCreateCountingSemaphore(
    max: UBaseType,
    initial: UBaseType,
) -> *mut Queue {
    queue_handle(Box::new(Queue::counting(max as usize, initial as usize)))
}

/// # Safety
///
/// `queue` must have come from one of the create functions.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vQueueDelete(queue: *mut Queue) {
    if !queue.is_null() {
        drop(unsafe { Box::from_raw(queue) });
    }
}

/// # Safety
///
/// `queue` must be live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xQueueGenericReset(queue: *mut Queue, _new: BaseType) -> BaseType {
    lock(|_| {
        if let Some(q) = unsafe { queue.as_mut() } {
            q.reset();
        }
    });
    PD_TRUE
}

/// # Safety
///
/// `queue` must be live and `item` valid for its item size.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xQueueGenericSend(
    queue: *mut Queue,
    item: *const c_void,
    ticks: TickType,
    position: BaseType,
) -> BaseType {
    let mut ticks = ticks;
    loop {
        let (sent, switch) = lock(|s| {
            let Some(q) = (unsafe { queue.as_mut() }) else {
                return (false, false);
            };
            let ok = if position == 1 {
                unsafe { q.push_front(item) }
            } else {
                unsafe { q.push_back(item) }
            };
            if !ok {
                return (false, false);
            }
            // Hand the item to whoever has been waiting longest at the
            // highest priority, rather than letting a low-priority task that
            // happens to run first take it.
            if let Some(w) = s.highest_waiter(queue as *const c_void) {
                s.wake(w);
                return (true, s.request_yield());
            }
            (true, false)
        });
        if sent {
            if switch {
                RiscvPort::yield_now();
            }
            return PD_TRUE;
        }
        if ticks == 0 {
            return ERR_QUEUE;
        }
        lock(|s| s.block_current(BlockedOn::Object(queue as *const c_void), ticks_to_opt(ticks)));
        RiscvPort::yield_now();
        if lock(|s| {
            s.current()
                .and_then(|c| s.get(c))
                .is_some_and(|t| !t.wait_succeeded)
        }) {
            return ERR_QUEUE;
        }
        // Woken because space appeared; try again, and do not wait a second
        // full timeout if it is gone.
        ticks = 0;
    }
}

/// # Safety
///
/// As [`xQueueGenericSend`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xQueueGenericSendFromISR(
    queue: *mut Queue,
    item: *const c_void,
    higher_woken: *mut BaseType,
    position: BaseType,
) -> BaseType {
    let (sent, switch) = lock(|s| {
        let Some(q) = (unsafe { queue.as_mut() }) else {
            return (false, false);
        };
        let ok = if position == 1 {
            unsafe { q.push_front(item) }
        } else {
            unsafe { q.push_back(item) }
        };
        if !ok {
            return (false, false);
        }
        if let Some(w) = s.highest_waiter(queue as *const c_void) {
            s.wake(w);
            return (true, true);
        }
        (true, false)
    });
    if !higher_woken.is_null() {
        unsafe { *higher_woken = switch as BaseType };
    }
    if sent {
        PD_TRUE
    } else {
        ERR_QUEUE
    }
}

/// # Safety
///
/// `queue` must be live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xQueueGiveFromISR(
    queue: *mut Queue,
    higher_woken: *mut BaseType,
) -> BaseType {
    unsafe { xQueueGenericSendFromISR(queue, core::ptr::null(), higher_woken, 0) }
}

/// # Safety
///
/// `queue` must be live and `buffer` valid for its item size.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xQueueReceive(
    queue: *mut Queue,
    buffer: *mut c_void,
    ticks: TickType,
) -> BaseType {
    let mut ticks = ticks;
    loop {
        let (got, switch) = lock(|s| {
            let Some(q) = (unsafe { queue.as_mut() }) else {
                return (false, false);
            };
            if !unsafe { q.pop_front(buffer) } {
                return (false, false);
            }
            // Space appeared: a blocked sender may proceed.
            if let Some(w) = s.highest_waiter(queue as *const c_void) {
                s.wake(w);
                return (true, s.request_yield());
            }
            (true, false)
        });
        if got {
            if switch {
                RiscvPort::yield_now();
            }
            return PD_TRUE;
        }
        if ticks == 0 {
            return ERR_QUEUE;
        }
        lock(|s| s.block_current(BlockedOn::Object(queue as *const c_void), ticks_to_opt(ticks)));
        RiscvPort::yield_now();
        if lock(|s| {
            s.current()
                .and_then(|c| s.get(c))
                .is_some_and(|t| !t.wait_succeeded)
        }) {
            return ERR_QUEUE;
        }
        ticks = 0;
    }
}

/// # Safety
///
/// As [`xQueueReceive`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xQueueReceiveFromISR(
    queue: *mut Queue,
    buffer: *mut c_void,
    higher_woken: *mut BaseType,
) -> BaseType {
    let (got, switch) = lock(|s| {
        let Some(q) = (unsafe { queue.as_mut() }) else {
            return (false, false);
        };
        if !unsafe { q.pop_front(buffer) } {
            return (false, false);
        }
        if let Some(w) = s.highest_waiter(queue as *const c_void) {
            s.wake(w);
            return (true, true);
        }
        (true, false)
    });
    if !higher_woken.is_null() {
        unsafe { *higher_woken = switch as BaseType };
    }
    if got {
        PD_TRUE
    } else {
        ERR_QUEUE
    }
}

/// Take a semaphore or mutex.
///
/// # Safety
///
/// `queue` must be live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xQueueSemaphoreTake(queue: *mut Queue, ticks: TickType) -> BaseType {
    let mut ticks = ticks;
    loop {
        let taken = lock(|s| {
            let Some(q) = (unsafe { queue.as_mut() }) else {
                return false;
            };
            if unsafe { q.pop_front(core::ptr::null_mut()) } {
                if q.is_mutex() {
                    q.holder = s.current();
                    if let Some(cur) = s.current() {
                        if let Some(t) = s.get_mut(cur) {
                            t.mutexes_held += 1;
                        }
                    }
                }
                return true;
            }
            false
        });
        if taken {
            return PD_TRUE;
        }
        if ticks == 0 {
            return ERR_QUEUE;
        }
        // Lend the holder our priority, or a high-priority task can wait
        // behind mid-priority work that keeps preempting the holder.
        let switch = lock(|s| {
            let q = unsafe { queue.as_mut() };
            let holder = q.and_then(|q| if q.is_mutex() { q.holder } else { None });
            let mine = s
                .current()
                .and_then(|c| s.get(c))
                .map_or(0, |t| t.priority);
            let lifted = holder.is_some_and(|h| s.inherit_priority(h, mine));
            s.block_current(BlockedOn::Object(queue as *const c_void), ticks_to_opt(ticks));
            lifted
        });
        let _ = switch;
        RiscvPort::yield_now();
        if lock(|s| {
            s.current()
                .and_then(|c| s.get(c))
                .is_some_and(|t| !t.wait_succeeded)
        }) {
            return ERR_QUEUE;
        }
        ticks = 0;
    }
}

/// # Safety
///
/// `queue` must be a live recursive mutex.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xQueueTakeMutexRecursive(
    queue: *mut Queue,
    ticks: TickType,
) -> BaseType {
    let reentered = lock(|s| {
        let Some(q) = (unsafe { queue.as_mut() }) else {
            return false;
        };
        if q.holder.is_some() && q.holder == s.current() {
            q.recursive_depth += 1;
            return true;
        }
        false
    });
    if reentered {
        return PD_TRUE;
    }
    unsafe { xQueueSemaphoreTake(queue, ticks) }
}

/// # Safety
///
/// `queue` must be a live recursive mutex held by the caller.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xQueueGiveMutexRecursive(queue: *mut Queue) -> BaseType {
    let unwound = lock(|s| {
        let Some(q) = (unsafe { queue.as_mut() }) else {
            return false;
        };
        if q.holder == s.current() && q.recursive_depth > 0 {
            q.recursive_depth -= 1;
            return true;
        }
        false
    });
    if unwound {
        return PD_TRUE;
    }
    unsafe { give(queue) }
}

/// Release a semaphore or mutex.
///
/// # Safety
///
/// `queue` must be live.
unsafe fn give(queue: *mut Queue) -> BaseType {
    let (ok, switch) = lock(|s| {
        let Some(q) = (unsafe { queue.as_mut() }) else {
            return (false, false);
        };
        if q.is_mutex() {
            if let Some(cur) = s.current() {
                if let Some(t) = s.get_mut(cur) {
                    t.mutexes_held = t.mutexes_held.saturating_sub(1);
                }
                s.disinherit_priority(cur);
            }
            q.holder = None;
        }
        if !unsafe { q.push_back(core::ptr::null()) } {
            return (false, false);
        }
        if let Some(w) = s.highest_waiter(queue as *const c_void) {
            s.wake(w);
            return (true, s.request_yield());
        }
        (true, false)
    });
    if switch {
        RiscvPort::yield_now();
    }
    if ok {
        PD_TRUE
    } else {
        ERR_QUEUE
    }
}

/// # Safety
///
/// `queue` must be live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn uxQueueMessagesWaiting(queue: *mut Queue) -> UBaseType {
    lock(|_| unsafe { queue.as_ref() }.map_or(0, |q| q.len() as UBaseType))
}

/// # Safety
///
/// `queue` must be live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn uxQueueMessagesWaitingFromISR(queue: *mut Queue) -> UBaseType {
    unsafe { queue.as_ref() }.map_or(0, |q| q.len() as UBaseType)
}

/// # Safety
///
/// `queue` must be live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xQueueIsQueueEmptyFromISR(queue: *mut Queue) -> BaseType {
    unsafe { queue.as_ref() }.map_or(PD_TRUE, |q| q.is_empty() as BaseType)
}

/// # Safety
///
/// `queue` must be live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xQueueIsQueueFullFromISR(queue: *mut Queue) -> BaseType {
    unsafe { queue.as_ref() }.map_or(PD_FALSE, |q| q.is_full() as BaseType)
}

// -------------------------------------------------------------------- heap

/// # Safety
///
/// Standard allocator contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pvPortMalloc(size: usize) -> *mut c_void {
    unsafe { crate::heap::alloc(size) }
}

/// # Safety
///
/// `ptr` must have come from [`pvPortMalloc`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vPortFree(ptr: *mut c_void) {
    unsafe { crate::heap::free(ptr) }
}

// ------------------------------------------------------------------- misc

/// # Safety
///
/// `p` must be NUL-terminated.
unsafe fn cstr<'a>(p: *const c_char) -> &'a str {
    if p.is_null() {
        return "";
    }
    let bytes = unsafe { core::ffi::CStr::from_ptr(p) }.to_bytes();
    core::str::from_utf8(bytes).unwrap_or("")
}

/// A failed `configASSERT`. There is no sensible continuation.
#[unsafe(no_mangle)]
pub extern "C" fn vAssertCalled() -> ! {
    loop {
        core::hint::spin_loop();
    }
}

// ------------------------------------------------------------------ timers

use crate::timer::{PendedCall, Timer, TimerService};

static mut TIMERS: TimerService = TimerService::new();
static mut TIMER_TASK: *mut Tcb = core::ptr::null_mut();

fn with_timers<R>(f: impl FnOnce(&mut TimerService) -> R) -> R {
    let state = RiscvPort::enter_critical();
    let r = f(unsafe { &mut *core::ptr::addr_of_mut!(TIMERS) });
    unsafe { RiscvPort::exit_critical(state) };
    r
}

/// # Safety
///
/// `name` outlives the timer; `callback` must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xTimerCreate(
    name: *const c_char,
    period: TickType,
    auto_reload: BaseType,
    id: *mut c_void,
    callback: Option<extern "C" fn(*mut Timer)>,
) -> *mut Timer {
    let t = Box::new(Timer {
        name,
        period: period.max(1),
        auto_reload: auto_reload != PD_FALSE,
        id,
        callback,
        active: false,
        due: 0,
    });
    with_timers(|s| {
        s.timers.push(t);
        let last = s.timers.len() - 1;
        &mut *s.timers[last] as *mut Timer
    })
}

/// # Safety
///
/// `timer` must be live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pvTimerGetTimerID(timer: *const Timer) -> *mut c_void {
    unsafe { timer.as_ref() }.map_or(core::ptr::null_mut(), |t| t.id)
}

/// Start, stop, reset, re-period or delete a timer.
///
/// # Safety
///
/// `timer` must be live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn xTimerGenericCommand(
    timer: *mut Timer,
    command: BaseType,
    optional_value: TickType,
    _higher_woken: *mut BaseType,
    _ticks_to_wait: TickType,
) -> BaseType {
    let now = lock(|s| s.tick_count());
    with_timers(|s| {
        let Some(t) = (unsafe { timer.as_mut() }) else {
            return PD_FALSE;
        };
        // The FROM_ISR commands are the same operations; the difference in
        // FreeRTOS is only which queue send is used to reach the daemon, and
        // there is no queue here.
        match command {
            // START, START_DONT_TRACE, RESET, and their ISR forms.
            0 | 1 | 2 | 6 | 7 => {
                t.active = true;
                // The value carries the time the command was issued.
                let base = if optional_value == 0 {
                    now
                } else {
                    optional_value as u64
                };
                t.due = base + t.period as u64;
            }
            3 | 8 => t.active = false,
            4 | 9 => {
                t.period = optional_value.max(1);
                t.due = now + t.period as u64;
                t.active = true;
            }
            5 => {
                t.active = false;
                let target = timer as *const Timer;
                s.timers
                    .retain(|b| !core::ptr::eq(&**b as *const Timer, target));
            }
            _ => {}
        }
        PD_TRUE
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn xTimerGetTimerDaemonTaskHandle() -> *mut Tcb {
    unsafe { TIMER_TASK }
}

/// Hand a call to the daemon, which is how an interrupt reaches a context
/// that is allowed to block.
#[unsafe(no_mangle)]
pub extern "C" fn xTimerPendFunctionCall(
    func: Option<extern "C" fn(*mut c_void, u32)>,
    arg: *mut c_void,
    value: u32,
    _ticks: TickType,
) -> BaseType {
    let Some(func) = func else { return PD_FALSE };
    with_timers(|s| s.pended.push(PendedCall { func, arg, value }));
    PD_TRUE
}

/// Also spelled `xTimerPendFunctionCallFromISR`; the work is identical.
#[unsafe(no_mangle)]
pub extern "C" fn xTimerPendFunctionCallFromISR(
    func: Option<extern "C" fn(*mut c_void, u32)>,
    arg: *mut c_void,
    value: u32,
    _higher_woken: *mut BaseType,
) -> BaseType {
    xTimerPendFunctionCall(func, arg, value, 0)
}

/// The daemon task: run due timers and pended calls, then sleep until the
/// next deadline.
extern "C" fn timer_daemon(_arg: *mut c_void) {
    loop {
        let now = lock(|s| s.tick_count());

        let due = with_timers(|s| s.take_due(now));
        for t in due {
            let cb = unsafe { t.as_ref() }.and_then(|t| t.callback);
            if let Some(cb) = cb {
                cb(t);
            }
        }

        let calls = with_timers(|s| core::mem::take(&mut s.pended));
        for c in calls {
            (c.func)(c.arg, c.value);
        }

        // Sleep until the next deadline, but wake often enough to notice
        // pended work that arrived meanwhile.
        let delay = with_timers(|s| s.next_delay(now)).unwrap_or(10).clamp(1, 10);
        vTaskDelay(delay as TickType);
    }
}

/// Start the daemon. FreeRTOS calls this from `vTaskStartScheduler`.
#[unsafe(no_mangle)]
pub extern "C" fn xTimerCreateTimerTask() -> BaseType {
    let mut handle: *mut Tcb = core::ptr::null_mut();
    let rc = unsafe {
        xTaskCreate(
            Some(timer_daemon),
            c"Tmr Svc".as_ptr(),
            512,
            core::ptr::null_mut(),
            crate::MAX_PRIORITIES - 2,
            &mut handle,
        )
    };
    unsafe { TIMER_TASK = handle };
    rc
}

// ----------------------------------------------------------- introspection

/// `TaskStatus_t`, matching FreeRTOS's `task.h` field for field.
///
/// The shell writes an array of these and reads them back, so the layout is
/// not ours to choose. `eCurrentState` is an enum, which `-fshort-enums`
/// makes one byte — the padding that follows is what makes the rest line up.
#[repr(C)]
pub struct TaskStatus {
    pub handle: *mut Tcb,
    pub name: *const c_char,
    pub task_number: UBaseType,
    pub current_state: u8,
    pub current_priority: UBaseType,
    pub base_priority: UBaseType,
    pub run_time_counter: u32,
    pub stack_base: *const usize,
    pub stack_high_water_mark: u16,
}

/// # Safety
///
/// `array` must have room for `size` entries.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn uxTaskGetSystemState(
    array: *mut TaskStatus,
    size: UBaseType,
    total_run_time: *mut u32,
) -> UBaseType {
    if !total_run_time.is_null() {
        unsafe { *total_run_time = 0 };
    }
    lock(|s| {
        let mut n = 0u32;
        for t in s.iter() {
            if n >= size {
                break;
            }
            if t.state == TaskState::Deleted {
                continue;
            }
            let handle = t as *const Tcb as *mut Tcb;
            let running = s.current() == Some(handle);
            unsafe {
                array.add(n as usize).write(TaskStatus {
                    handle,
                    name: t.name.as_ptr() as *const c_char,
                    task_number: t.task_number,
                    current_state: match t.state {
                        TaskState::Ready if running => 0,
                        TaskState::Ready => 1,
                        TaskState::Blocked => 2,
                        TaskState::Suspended => 3,
                        TaskState::Deleted => 4,
                    },
                    current_priority: t.priority,
                    base_priority: t.base_priority,
                    run_time_counter: 0,
                    stack_base: t.stack_base(),
                    stack_high_water_mark: 0,
                });
            }
            n += 1;
        }
        n
    })
}

/// Write the `ps`-style table the vendor shell prints.
///
/// # Safety
///
/// `buffer` must have room; FreeRTOS's contract is roughly 40 bytes per task,
/// and this stays well inside that.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vTaskList(buffer: *mut c_char) {
    if buffer.is_null() {
        return;
    }
    let mut out = buffer.cast::<u8>();
    let mut put = |bytes: &[u8]| {
        for &b in bytes {
            unsafe {
                out.write(b);
                out = out.add(1);
            }
        }
    };
    lock(|s| {
        for t in s.iter() {
            if t.state == TaskState::Deleted {
                continue;
            }
            let running = s.current() == Some(t as *const Tcb as *mut Tcb);
            let state = match t.state {
                TaskState::Ready if running => b'X',
                TaskState::Ready => b'R',
                TaskState::Blocked => b'B',
                TaskState::Suspended => b'S',
                TaskState::Deleted => b'D',
            };
            let name = t.name.as_bytes();
            put(&name[..name.len().min(16)]);
            put(b"\t");
            put(&[state]);
            put(b"\t");
            put(&[b'0' + (t.priority % 10) as u8]);
            put(b"\r\n");
        }
    });
    unsafe { out.write(0) };
}

/// Visit every task handle. Used by the platform's low-power bookkeeping.
///
/// # Safety
///
/// `cb` must be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vTaskHandleForeachFromISR(
    cb: Option<extern "C" fn(*mut Tcb, *mut c_void)>,
    arg: *mut c_void,
) {
    let Some(cb) = cb else { return };
    // Called from an interrupt, so no lock: interrupts are already masked and
    // taking one would re-enable them on the way out.
    let s = unsafe { &*core::ptr::addr_of!(SCHEDULER) };
    for t in s.iter() {
        if t.state != TaskState::Deleted {
            cb(t as *const Tcb as *mut Tcb, arg);
        }
    }
}

/// newlib's per-thread `errno`.
///
/// One slot rather than one per task. Nothing in this system inspects errno
/// across a blocking call, and a shared slot is what the SDK's own newlib
/// configuration assumes.
#[unsafe(no_mangle)]
pub extern "C" fn __errno() -> *mut i32 {
    static mut ERRNO: i32 = 0;
    core::ptr::addr_of_mut!(ERRNO)
}
