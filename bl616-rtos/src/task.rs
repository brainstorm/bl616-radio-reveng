// SPDX-FileCopyrightText: 2026 Roman Valls Guimera <brainstorm@nopcode.org>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Tasks, and the decision of which one runs.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::ffi::c_void;

use crate::port::StackPtr;

/// Identifies a task. This is what C sees as `TaskHandle_t`.
pub type TaskHandle = *mut Tcb;

/// What a task is doing.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TaskState {
    /// Runnable, or running.
    Ready,
    /// Waiting for a deadline, an object, or both.
    Blocked,
    /// Removed from scheduling until resumed.
    Suspended,
    /// Finished; the slot is reclaimed by the idle task.
    Deleted,
}

/// Why a task is blocked, which decides what can wake it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BlockedOn {
    /// A plain delay, woken only by the tick.
    Time,
    /// A queue, semaphore or mutex, identified by address.
    Object(*const c_void),
    /// A direct-to-task notification.
    Notification,
}

/// A task control block.
///
/// `stack_ptr` is first and stays first: the context switch writes it from
/// assembly at a fixed offset of zero.
#[repr(C)]
pub struct Tcb {
    /// Saved stack pointer. Offset 0, by contract with the port.
    pub stack_ptr: StackPtr,
    pub name: String,
    /// The priority the task was created with.
    pub base_priority: u32,
    /// The priority it runs at, which is higher while it holds a mutex a
    /// higher-priority task is waiting for.
    pub priority: u32,
    pub state: TaskState,
    pub blocked_on: Option<BlockedOn>,
    /// Tick at which a timeout expires. `None` means wait forever.
    pub wake_at: Option<u64>,
    /// Set when the wait ended because the object became available rather
    /// than because time ran out.
    pub wait_succeeded: bool,
    /// Direct-to-task notification value and pending state.
    pub notify_value: u32,
    pub notify_pending: bool,
    /// `vTaskSetTaskNumber`, which the vendor shell prints.
    pub task_number: u32,
    /// The single thread-local slot the configuration allows.
    pub tls: *mut c_void,
    /// Mutexes currently held, for priority inheritance bookkeeping.
    pub mutexes_held: u32,
    /// The stack allocation, kept so it is freed with the task.
    stack: Vec<usize>,
}

// The scheduler owns these and is only entered with interrupts masked.
unsafe impl Send for Tcb {}

impl Tcb {
    fn new(name: &str, priority: u32, stack_words: usize) -> Box<Tcb> {
        Box::new(Tcb {
            stack_ptr: core::ptr::null_mut(),
            name: String::from(name),
            base_priority: priority,
            priority,
            state: TaskState::Ready,
            blocked_on: None,
            wake_at: None,
            wait_succeeded: false,
            notify_value: 0,
            notify_pending: false,
            task_number: 0,
            tls: core::ptr::null_mut(),
            mutexes_held: 0,
            stack: alloc::vec![0usize; stack_words],
        })
    }

    /// Highest address of the stack, where a context is built.
    pub fn stack_top(&mut self) -> StackPtr {
        let len = self.stack.len();
        unsafe { self.stack.as_mut_ptr().add(len) }
    }

    /// Lowest address, for overflow checking.
    pub fn stack_base(&self) -> *const usize {
        self.stack.as_ptr()
    }
}

/// The scheduler.
pub struct Scheduler {
    /// Boxed deliberately, against clippy's advice. `TaskHandle` is a raw
    /// pointer into a TCB and C holds those pointers indefinitely, so the
    /// TCBs must not move — which is exactly what a `Vec<Tcb>` does when it
    /// grows. The indirection is the point.
    #[allow(clippy::vec_box)]
    tasks: Vec<Box<Tcb>>,
    current: Option<TaskHandle>,
    tick: u64,
    /// `vTaskSuspendAll` nesting. Above zero, no switch happens.
    suspend_depth: u32,
    /// A switch was wanted while suspended, and is owed once resumed.
    yield_pending: bool,
    running: bool,
}

impl Default for Scheduler {
    fn default() -> Self {
        Self::new()
    }
}

impl Scheduler {
    pub const fn new() -> Self {
        Scheduler {
            tasks: Vec::new(),
            current: None,
            tick: 0,
            suspend_depth: 0,
            yield_pending: false,
            running: false,
        }
    }

    pub fn tick_count(&self) -> u64 {
        self.tick
    }

    pub fn is_running(&self) -> bool {
        self.running
    }

    pub fn set_running(&mut self, running: bool) {
        self.running = running;
    }

    pub fn current(&self) -> Option<TaskHandle> {
        self.current
    }

    pub fn set_current(&mut self, handle: TaskHandle) {
        self.current = Some(handle);
    }

    pub fn task_count(&self) -> usize {
        self.tasks.iter().filter(|t| t.state != TaskState::Deleted).count()
    }

    /// Create a task. Returns its handle.
    pub fn create(&mut self, name: &str, priority: u32, stack_words: usize) -> TaskHandle {
        let priority = priority.min(crate::MAX_PRIORITIES - 1);
        let mut tcb = Tcb::new(name, priority, stack_words);
        let handle: TaskHandle = &mut *tcb;
        self.tasks.push(tcb);
        handle
    }

    pub fn get(&self, handle: TaskHandle) -> Option<&Tcb> {
        self.tasks
            .iter()
            .find(|t| core::ptr::eq(&***t as *const Tcb, handle))
            .map(|t| &**t)
    }

    pub fn get_mut(&mut self, handle: TaskHandle) -> Option<&mut Tcb> {
        self.tasks
            .iter_mut()
            .find(|t| core::ptr::eq(&***t as *const Tcb, handle))
            .map(|t| &mut **t)
    }

    pub fn iter(&self) -> impl Iterator<Item = &Tcb> {
        self.tasks.iter().map(|t| &**t)
    }

    /// The highest-priority runnable task.
    ///
    /// Ties go to the task that is already running, which is what stops a
    /// pair of equal-priority tasks from ping-ponging on every tick.
    pub fn pick_next(&self) -> Option<TaskHandle> {
        let mut best: Option<(&Box<Tcb>, u32)> = None;
        for t in self.tasks.iter() {
            if t.state != TaskState::Ready {
                continue;
            }
            let is_current = self
                .current
                .is_some_and(|c| core::ptr::eq(&**t as *const Tcb, c));
            match best {
                None => best = Some((t, t.priority)),
                Some((_, p)) if t.priority > p => best = Some((t, t.priority)),
                Some((b, p)) if t.priority == p && is_current => {
                    let best_is_current = self
                        .current
                        .is_some_and(|c| core::ptr::eq(&**b as *const Tcb, c));
                    if !best_is_current {
                        best = Some((t, t.priority));
                    }
                }
                _ => {}
            }
        }
        best.map(|(t, _)| &**t as *const Tcb as TaskHandle)
    }

    /// Whether a switch is currently allowed.
    pub fn switch_allowed(&self) -> bool {
        self.suspend_depth == 0
    }

    pub fn suspend_all(&mut self) {
        self.suspend_depth += 1;
    }

    /// Returns true if a switch is owed now that scheduling has resumed.
    pub fn resume_all(&mut self) -> bool {
        if self.suspend_depth > 0 {
            self.suspend_depth -= 1;
        }
        if self.suspend_depth == 0 && self.yield_pending {
            self.yield_pending = false;
            return true;
        }
        false
    }

    /// Note that a switch is wanted; returns whether it can happen now.
    pub fn request_yield(&mut self) -> bool {
        if self.suspend_depth > 0 {
            self.yield_pending = true;
            return false;
        }
        true
    }

    /// Block the current task.
    pub fn block_current(&mut self, on: BlockedOn, timeout_ticks: Option<u64>) {
        let now = self.tick;
        let Some(cur) = self.current else { return };
        if let Some(t) = self.get_mut(cur) {
            t.state = TaskState::Blocked;
            t.blocked_on = Some(on);
            t.wake_at = timeout_ticks.map(|d| now + d);
            t.wait_succeeded = false;
        }
    }

    /// Wake a task, recording that its wait succeeded.
    pub fn wake(&mut self, handle: TaskHandle) {
        if let Some(t) = self.get_mut(handle) {
            if t.state == TaskState::Blocked {
                t.state = TaskState::Ready;
                t.blocked_on = None;
                t.wake_at = None;
                t.wait_succeeded = true;
            }
        }
    }

    /// The highest-priority task blocked on `object`, which is the one a
    /// release should hand ownership to.
    pub fn highest_waiter(&self, object: *const c_void) -> Option<TaskHandle> {
        let mut best: Option<(&Box<Tcb>, u32)> = None;
        for t in self.tasks.iter() {
            if t.state != TaskState::Blocked {
                continue;
            }
            if t.blocked_on != Some(BlockedOn::Object(object)) {
                continue;
            }
            match best {
                None => best = Some((t, t.priority)),
                Some((_, p)) if t.priority > p => best = Some((t, t.priority)),
                _ => {}
            }
        }
        best.map(|(t, _)| &**t as *const Tcb as TaskHandle)
    }

    /// Advance time by one tick, waking anything whose timeout expired.
    ///
    /// Returns true if a switch is warranted — either something woke, or the
    /// running task should be preempted by an equal or higher priority peer.
    pub fn tick(&mut self) -> bool {
        self.tick += 1;
        let now = self.tick;

        let mut woke = false;
        for t in self.tasks.iter_mut() {
            if t.state != TaskState::Blocked {
                continue;
            }
            if let Some(at) = t.wake_at {
                if now >= at {
                    t.state = TaskState::Ready;
                    t.blocked_on = None;
                    t.wake_at = None;
                    // Timed out: the object never became available. Callers
                    // distinguish the two cases by this flag, and getting it
                    // backwards turns a timeout into a false success.
                    t.wait_succeeded = false;
                    woke = true;
                }
            }
        }

        if woke {
            return true;
        }
        // Round-robin between equal priorities, which is what
        // configUSE_TIME_SLICING asks for.
        let Some(cur) = self.current else { return false };
        let Some(cur_prio) = self.get(cur).map(|t| t.priority) else {
            return false;
        };
        self.tasks.iter().any(|t| {
            t.state == TaskState::Ready
                && t.priority >= cur_prio
                && !core::ptr::eq(&**t as *const Tcb, cur)
        })
    }

    /// Lend `holder` the priority of `waiter` if that is higher.
    ///
    /// Returns true if the holder's priority changed. Without this a
    /// low-priority task holding a mutex can be preempted indefinitely by
    /// mid-priority work while a high-priority task waits on it — the
    /// inversion that makes a radio miss deadlines under load.
    pub fn inherit_priority(&mut self, holder: TaskHandle, waiter_priority: u32) -> bool {
        if let Some(h) = self.get_mut(holder) {
            if waiter_priority > h.priority {
                h.priority = waiter_priority;
                return true;
            }
        }
        false
    }

    /// Drop a lent priority when the last mutex is released.
    pub fn disinherit_priority(&mut self, holder: TaskHandle) -> bool {
        if let Some(h) = self.get_mut(holder) {
            if h.mutexes_held == 0 && h.priority != h.base_priority {
                h.priority = h.base_priority;
                return true;
            }
        }
        false
    }

    /// Reclaim finished tasks.
    pub fn reap(&mut self) {
        let current = self.current;
        self.tasks.retain(|t| {
            let is_current = current.is_some_and(|c| core::ptr::eq(&**t as *const Tcb, c));
            t.state != TaskState::Deleted || is_current
        });
    }
}
