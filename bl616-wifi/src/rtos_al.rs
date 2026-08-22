// SPDX-FileCopyrightText: 2026 Roman Valls Guimera <brainstorm@nopcode.org>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! The blobs' RTOS abstraction layer, in Rust.
//!
//! `libfhost` and `libmacsw` do not call FreeRTOS directly. They call 31
//! `rtos_*` functions and read 12 `fhost_*_priority` constants, and the SDK
//! satisfies those from `macsw_os_adapter/src/rtos_al.c`. This is that file,
//! rewritten, and it is the seam Stage 3 turns on: the blobs' idea of an
//! operating system is exactly this surface, so a Rust scheduler replaces
//! what is *below* these functions without the blobs noticing.
//!
//! Today everything below still forwards to FreeRTOS, which is the point of
//! doing it in this order — the seam moves into Rust first, and the thing
//! behind it changes second.
//!
//! # Return conventions, which are not the obvious ones
//!
//! The vendor's code returns `res == errQUEUE_EMPTY` and `res == errQUEUE_FULL`
//! from several functions. Both of those constants are 0, and FreeRTOS returns
//! `pdTRUE` (1) on success, so these functions return **0 for success and 1
//! for timeout or failure** — the opposite of the `pdPASS` convention they
//! look like they are forwarding. Getting this backwards would make every
//! blocking wait appear to fail.
//!
//! # Interrupt context
//!
//! Each of these takes an explicit `isr` flag from the caller rather than
//! detecting anything, and the flag chooses the `FromISR` variant. That is the
//! blobs' contract, so it is reproduced exactly.

// Every function here is an entry point the blobs call, so the safety
// contract is theirs, not ours: it is fixed by `rtos_al.h` and cannot be
// restated usefully per function. The module docs cover what is assumed of
// callers -- valid handles, and an honest `isr` flag.
#![allow(clippy::missing_safety_doc)]

use core::ffi::{c_char, c_int, c_void};

use bl616_wifi_sys as sys;

/// Task priorities the blobs read directly as `const int`.
///
/// These are rodata symbols in the object being replaced, not function calls,
/// so they have to exist with the same values or the blobs' tasks come up at
/// the wrong priorities and the failure is a timing one -- the worst kind to
/// debug on a radio. The values were read out of the compiled object rather
/// than the header, because `fhost_rx_priority` is conditional on build
/// configuration and this build resolves it to 27, not the 30 that
/// `CONFIG_HIGH_PERFORMANCE` would give.
macro_rules! priority {
    ($($name:ident = $value:expr;)*) => {
        $(
            #[unsafe(no_mangle)]
            pub static $name: c_int = $value;
        )*
    };
}

priority! {
    fhost_tcpip_priority = 28;
    fhost_wifi_priority = 27;
    fhost_wifi_priority_high = 30;
    fhost_cntrl_priority = 27;
    fhost_rx_priority = 27;
    fhost_tx_priority = 29;
    fhost_wpa_priority = 26;
    fhost_ipc_priority = 29;
    fhost_iperf_priority = 27;
    fhost_connect_priority = 25;
    fhost_tg_priority = 26;
    fhost_ping_priority = 27;
}

/// A negative timeout means "wait forever", which is `portMAX_DELAY`.
fn ticks(timeout_ms: c_int) -> sys::TickType_t {
    if timeout_ms < 0 {
        sys::TickType_t::MAX
    } else {
        ms_to_ticks(timeout_ms as u32)
    }
}

fn ms_to_ticks(ms: u32) -> sys::TickType_t {
    (ms as u64 * sys::TICK_RATE_HZ as u64 / 1000) as sys::TickType_t
}

/// Whether the caller is inside an interrupt handler, as
/// `xPortIsInsideInterrupt()` determines it.
fn in_interrupt() -> bool {
    unsafe { core::ptr::read_volatile(&raw const sys::TrapNetCounter) != 0 }
}

// ------------------------------------------------------------------- time

#[unsafe(no_mangle)]
pub extern "C" fn rtos_al_ms2tick(ms: c_int) -> u32 {
    ms_to_ticks(ms.max(0) as u32)
}

#[unsafe(no_mangle)]
pub extern "C" fn rtos_now(isr: bool) -> u32 {
    unsafe {
        if isr {
            sys::xTaskGetTickCountFromISR()
        } else {
            sys::xTaskGetTickCount()
        }
    }
}

// ------------------------------------------------------------------ tasks

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtos_task_get_handle(task_name: *const c_char) -> *mut c_void {
    unsafe {
        if task_name.is_null() {
            sys::xTaskGetCurrentTaskHandle() as *mut c_void
        } else {
            sys::xTaskGetHandle(task_name) as *mut c_void
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn rtos_get_task_handle() -> *mut c_void {
    unsafe { sys::xTaskGetCurrentTaskHandle() as *mut c_void }
}

/// Returns 0 on success and 1 on failure, like the C.
#[allow(clippy::too_many_arguments)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtos_task_create(
    func: *mut c_void,
    name: *const c_char,
    task_id: u8,
    stack_depth: u16,
    params: *mut c_void,
    prio: u32,
    task_handle: *mut *mut c_void,
) -> c_int {
    let mut handle: sys::TaskHandle_t = core::ptr::null_mut();
    let res = unsafe {
        sys::xTaskCreate(
            core::mem::transmute::<*mut c_void, sys::TaskFunction_t>(func),
            name,
            stack_depth,
            params,
            prio,
            &mut handle,
        )
    };
    // pdFAIL is 0; anything else is pdPASS.
    if res == 0 {
        return 1;
    }
    // The build has configUSE_TRACE_FACILITY on -- vTaskSetTaskNumber is in
    // the image -- and the vendor shell's `ps` prints these ids.
    unsafe { sys::vTaskSetTaskNumber(handle, task_id as u32) };
    if !task_handle.is_null() {
        unsafe { *task_handle = handle as *mut c_void };
    }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtos_task_delete(task_handle: *mut c_void) {
    /// `eDeleted` in `eTaskState`.
    const E_DELETED: u8 = 4;
    let handle = if task_handle.is_null() {
        unsafe { sys::xTaskGetCurrentTaskHandle() }
    } else {
        task_handle as sys::TaskHandle_t
    };
    if unsafe { sys::eTaskGetState(handle) } != E_DELETED {
        unsafe { sys::vTaskDelete(handle) };
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn rtos_task_suspend(duration: c_int) {
    if duration <= 0 {
        return;
    }
    unsafe { sys::vTaskDelay(ms_to_ticks(duration as u32)) };
}

/// Nothing to do: FreeRTOS gives every task its notification slot.
#[unsafe(no_mangle)]
pub extern "C" fn rtos_task_init_notification(_task: *mut c_void) -> c_int {
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn rtos_task_wait_notification(timeout: c_int) -> c_int {
    // pdTRUE: clear the count on exit, so each wait consumes one notification.
    unsafe { sys::ulTaskGenericNotifyTake(0, 1, ticks(timeout)) as c_int }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtos_task_notify(task: *mut c_void, isr: bool) {
    let handle = task as sys::TaskHandle_t;
    if isr {
        let mut woken = 0;
        unsafe { sys::vTaskGenericNotifyGiveFromISR(handle, 0, &mut woken) };
    } else {
        // eIncrement, so notifications accumulate rather than overwrite.
        unsafe { sys::xTaskGenericNotify(handle, 0, 0, 2, core::ptr::null_mut()) };
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtos_priority_set(handle: *mut c_void, priority: u32) {
    unsafe { sys::vTaskPrioritySet(handle as sys::TaskHandle_t, priority) };
}

// ----------------------------------------------------------------- queues

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtos_queue_create(
    elt_size: c_int,
    nb_elt: c_int,
    queue: *mut *mut c_void,
) -> c_int {
    let q = unsafe {
        sys::xQueueGenericCreate(nb_elt as u32, elt_size as u32, sys::QUEUE_TYPE_BASE)
    };
    unsafe { *queue = q as *mut c_void };
    if q.is_null() {
        -1
    } else {
        0
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtos_queue_delete(queue: *mut c_void) {
    unsafe { sys::vQueueDelete(queue as sys::QueueHandle_t) };
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtos_queue_is_empty(queue: *mut c_void) -> bool {
    let q = queue as sys::QueueHandle_t;
    if in_interrupt() {
        return unsafe { sys::xQueueIsQueueEmptyFromISR(q) } != 0;
    }
    unsafe { sys::uxQueueMessagesWaiting(q) == 0 }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtos_queue_is_full(queue: *mut c_void) -> bool {
    // The FromISR form is safe from a task too: it does not block, and the
    // vendor calls it from both with interrupts masked around it.
    critical(|| unsafe { sys::xQueueIsQueueFullFromISR(queue as sys::QueueHandle_t) } != 0)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtos_queue_cnt(queue: *mut c_void) -> c_int {
    critical(|| unsafe { sys::uxQueueMessagesWaitingFromISR(queue as sys::QueueHandle_t) } as c_int)
}

/// Returns 0 when the message was queued, 1 when the queue was full.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtos_queue_write(
    queue: *mut c_void,
    msg: *mut c_void,
    timeout: c_int,
    isr: bool,
) -> c_int {
    let q = queue as sys::QueueHandle_t;
    let res = if isr {
        let mut woken = 0;
        unsafe { sys::xQueueGenericSendFromISR(q, msg, &mut woken, sys::QUEUE_SEND_TO_BACK) }
    } else {
        unsafe { sys::xQueueGenericSend(q, msg, ticks(timeout), sys::QUEUE_SEND_TO_BACK) }
    };
    // errQUEUE_FULL is 0.
    (res == 0) as c_int
}

/// Returns 0 when a message was received, 1 on timeout.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtos_queue_read(
    queue: *mut c_void,
    msg: *mut c_void,
    timeout: c_int,
    isr: bool,
) -> c_int {
    let q = queue as sys::QueueHandle_t;
    let res = if isr {
        let mut woken = 0;
        unsafe { sys::xQueueReceiveFromISR(q, msg, &mut woken) }
    } else {
        unsafe { sys::xQueueReceive(q, msg, ticks(timeout)) }
    };
    // errQUEUE_EMPTY is 0.
    (res == 0) as c_int
}

// ------------------------------------------------------------- semaphores

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtos_semaphore_create(
    semaphore: *mut *mut c_void,
    max_count: c_int,
    init_count: c_int,
) -> c_int {
    let s = if max_count == 1 {
        // A binary semaphore starts empty, so an initial count of one has to
        // be given to it explicitly.
        let s = unsafe {
            sys::xQueueGenericCreate(1, 0, sys::QUEUE_TYPE_BINARY_SEMAPHORE)
        };
        if !s.is_null() && init_count != 0 {
            unsafe {
                sys::xQueueGenericSend(
                    s,
                    core::ptr::null(),
                    0,
                    sys::QUEUE_SEND_TO_BACK,
                )
            };
        }
        s
    } else {
        unsafe { sys::xQueueCreateCountingSemaphore(max_count as u32, init_count as u32) }
    };
    unsafe { *semaphore = s as *mut c_void };
    if s.is_null() {
        -1
    } else {
        0
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtos_semaphore_delete(semaphore: *mut c_void) {
    unsafe { sys::vQueueDelete(semaphore as sys::QueueHandle_t) };
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtos_semaphore_get_count(semaphore: *mut c_void) -> c_int {
    unsafe { sys::uxQueueMessagesWaiting(semaphore as sys::QueueHandle_t) as c_int }
}

/// Returns 0 when the semaphore was taken, 1 on timeout.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtos_semaphore_wait(semaphore: *mut c_void, timeout: c_int) -> c_int {
    let res = unsafe { sys::xQueueSemaphoreTake(semaphore as sys::QueueHandle_t, ticks(timeout)) };
    (res == 0) as c_int
}

/// Returns 0 when signalled, 1 when the semaphore was already full.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtos_semaphore_signal(semaphore: *mut c_void, isr: bool) -> c_int {
    let s = semaphore as sys::QueueHandle_t;
    let res = if isr {
        let mut woken = 0;
        unsafe { sys::xQueueGiveFromISR(s, &mut woken) }
    } else {
        unsafe { sys::xQueueGenericSend(s, core::ptr::null(), 0, sys::QUEUE_SEND_TO_BACK) }
    };
    (res == 0) as c_int
}

// ----------------------------------------------------------------- mutexes

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtos_mutex_create(mutex: *mut *mut c_void) -> c_int {
    // A mutex, not a binary semaphore: this one carries priority
    // inheritance, and the blobs hold it across contended sections.
    let m = unsafe { sys::xQueueCreateMutex(1) };
    unsafe { *mutex = m as *mut c_void };
    if m.is_null() {
        -1
    } else {
        0
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtos_mutex_delete(mutex: *mut c_void) {
    unsafe { sys::vQueueDelete(mutex as sys::QueueHandle_t) };
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtos_mutex_lock(mutex: *mut c_void) {
    unsafe {
        sys::xQueueSemaphoreTake(mutex as sys::QueueHandle_t, sys::TickType_t::MAX);
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtos_mutex_unlock(mutex: *mut c_void) {
    unsafe {
        sys::xQueueGenericSend(
            mutex as sys::QueueHandle_t,
            core::ptr::null(),
            0,
            sys::QUEUE_SEND_TO_BACK,
        );
    }
}

// -------------------------------------------------------- critical sections

fn critical<R>(f: impl FnOnce() -> R) -> R {
    unsafe { sys::vTaskEnterCritical() };
    let r = f();
    unsafe { sys::vTaskExitCritical() };
    r
}

/// The return value is a token for `rtos_unprotect`, and the vendor always
/// returns 1 rather than the previous state -- these nest through FreeRTOS's
/// own counter, not through anything carried here.
#[unsafe(no_mangle)]
pub extern "C" fn rtos_protect() -> u32 {
    unsafe { sys::vTaskEnterCritical() };
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn rtos_unprotect(_protect: u32) {
    unsafe { sys::vTaskExitCritical() };
}

// -------------------------------------------------------------------- misc

/// Tracing hooks the blobs call and the vendor leaves empty.
#[unsafe(no_mangle)]
pub extern "C" fn rtos_trace_task(_id: c_int, _task: *mut c_void) {}

#[unsafe(no_mangle)]
pub extern "C" fn rtos_trace_mem(_id: c_int, _ptr: *mut c_void, _size: c_int, _free_size: c_int) {}

/// FreeRTOS calls this when a task overruns its stack, which is not
/// recoverable: the corruption has already happened.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vApplicationStackOverflowHook(
    _task: *mut c_void,
    name: *const c_char,
) -> ! {
    if name.is_null() {
        crate::println!("[rtos] stack overflow in an unnamed task");
    } else {
        let name = unsafe { core::ffi::CStr::from_ptr(name) };
        crate::println!("[rtos] stack overflow in task {name:?}");
    }
    loop {
        core::hint::spin_loop();
    }
}
