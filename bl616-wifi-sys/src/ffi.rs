// SPDX-FileCopyrightText: 2026 Roman Valls Guimera <brainstorm@nopcode.org>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! The FFI boundary, written out by hand.
//!
//! This replaces 2781 lines of generated bindings with the 57 declarations
//! that are actually used. The point is not the line count: it is that the
//! boundary between Rust and four megabytes of vendor C is the thing every
//! remaining stage has to reason about, and it should be readable, reviewable
//! and diffable rather than regenerated behind a `libclang` dependency.
//!
//! # How this stays honest
//!
//! Hand-written FFI rots silently — a struct gains a field in a new SDK and
//! the next call scribbles past the end of it. So the C compiler is kept as
//! the oracle: `build.rs` compiles a file of `_Static_assert`s against the
//! vendor headers, checking the size and alignment of every type declared
//! here and the offset of every field. Change the SDK in a way that matters
//! and the build fails, loudly, pointing at the field.
//!
//! Two conventions matter and are easy to get wrong:
//!
//! * **The SDK compiles with `-fshort-enums`.** A C enum small enough to fit
//!   is a single byte, not a word — `eNotifyAction` below is `u8` for that
//!   reason, and getting it wrong corrupts the argument after it.
//! * **Everything is `ilp32f`**: `long` and pointers are 32 bits.

use core::ffi::{c_char, c_int, c_long, c_ulong, c_void};

// ------------------------------------------------------------ FreeRTOS types

pub type BaseType_t = i32;
pub type UBaseType_t = u32;
pub type TickType_t = u32;
pub type StackType_t = u32;

/// Opaque task control block; only ever held by pointer.
#[repr(C)]
pub struct tskTaskControlBlock {
    _opaque: [u8; 0],
}
pub type TaskHandle_t = *mut tskTaskControlBlock;
pub type TaskFunction_t = Option<unsafe extern "C" fn(arg: *mut c_void)>;

/// `eNotifyAction`. One byte, because of `-fshort-enums`.
pub type eNotifyAction = u8;

/// `bflb_uart_config_s`. Passed to `bflb_uart_init` by pointer, so the layout
/// is checked against the header by `build.rs` like the others.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct bflb_uart_config_s {
    pub baudrate: u32,
    pub direction: u8,
    pub data_bits: u8,
    pub stop_bits: u8,
    pub parity: u8,
    pub bit_order: u8,
    pub flow_ctrl: u8,
    pub tx_fifo_threshold: u8,
    pub rx_fifo_threshold: u8,
}

/// `queueQUEUE_TYPE_MUTEX` and `queueQUEUE_TYPE_RECURSIVE_MUTEX`, which is
/// what `xQueueCreateMutex` distinguishes them by.
pub const QUEUE_TYPE_MUTEX: u8 = 1;
pub const QUEUE_TYPE_RECURSIVE_MUTEX: u8 = 4;

/// What `xTaskGetSchedulerState` returns.
pub const TASK_SCHEDULER_SUSPENDED: BaseType_t = 0;
pub const TASK_SCHEDULER_NOT_STARTED: BaseType_t = 1;
pub const TASK_SCHEDULER_RUNNING: BaseType_t = 2;

/// `UART_DIRECTION_TXRX`.
pub const UART_DIRECTION_TXRX: u8 = 3;
/// `UART_DATA_BITS_5` .. `_8`.
pub const UART_DATA_BITS_5: u8 = 0;
pub const UART_DATA_BITS_6: u8 = 1;
pub const UART_DATA_BITS_7: u8 = 2;
pub const UART_DATA_BITS_8: u8 = 3;
/// `UART_STOP_BITS_1`.
pub const UART_STOP_BITS_1: u8 = 1;
/// `UART_STOP_BITS_2`.
pub const UART_STOP_BITS_2: u8 = 3;
/// `UART_PARITY_NONE`, `_ODD`, `_EVEN`.
pub const UART_PARITY_NONE: u8 = 0;
pub const UART_PARITY_ODD: u8 = 1;
pub const UART_PARITY_EVEN: u8 = 2;
/// `UART_FLOWCTRL_NONE`.
pub const UART_FLOWCTRL_NONE: u8 = 0;

// Interrupt status bits, as `bflb_uart_get_intstatus` reports them. The two
// FIFO bits are level-triggered on the FIFO count and have no `INTCLR` bit:
// they are cleared by draining the receive FIFO or filling the transmit one,
// which is why a handler that has nothing left to send has to mask instead.
/// `UART_INTSTS_TX_FIFO`: the transmit FIFO fell below its threshold.
pub const UART_INTSTS_TX_FIFO: u32 = 1 << 2;
/// `UART_INTSTS_RX_FIFO`: the receive FIFO reached its threshold.
pub const UART_INTSTS_RX_FIFO: u32 = 1 << 3;
/// `UART_INTSTS_RTO`: the line went idle with bytes still in the receive
/// FIFO, which is what delivers a short burst that never reaches threshold.
pub const UART_INTSTS_RTO: u32 = 1 << 4;
/// `UART_INTCLR_RTO`.
pub const UART_INTCLR_RTO: u32 = 1 << 4;
/// `UART_CMD_SET_RTO_VALUE`, in bit periods.
pub const UART_CMD_SET_RTO_VALUE: c_int = 0x07;

/// `GPIO_UART_FUNC_UART0_TX` / `_RX`, the UART0 signals a pin can carry.
pub const GPIO_UART_FUNC_UART0_TX: u8 = 2;
pub const GPIO_UART_FUNC_UART0_RX: u8 = 3;

/// `struct bflb_device_s`, the LHAL device handle.
///
/// Not opaque, because the interrupt path needs `irq_num`: the SDK hands out
/// one of these per peripheral and the IRQ number to attach a handler to is
/// inside it. Layout checked against the header like the others.
#[repr(C)]
pub struct bflb_device_s {
    pub name: *const c_char,
    pub reg_base: u32,
    pub irq_num: u8,
    pub idx: u8,
    pub sub_idx: u8,
    pub dev_type: u8,
    pub user_data: *mut c_void,
}

/// `irq_callback`. Two bytes of `#ifdef` in `bflb_irq.h` pick between two
/// signatures; BouffaloSDK does not define `BL_IOT_SDK`, so it is this one.
pub type irq_callback = Option<unsafe extern "C" fn(irq: c_int, arg: *mut c_void)>;

// -------------------------------------------------------------- event system

/// Intrusive list head inside [`async_input_event`].
#[repr(C)]
#[derive(Copy, Clone)]
pub struct async_input_event_entry {
    pub sle_next: *mut async_input_event,
}

/// One event posted to the async event system.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct async_input_event {
    pub entry: async_input_event_entry,
    pub type_: usize,
    pub finish: Option<unsafe extern "C" fn(arg: *mut async_input_event)>,
    pub size: u16,
    pub code: u16,
    pub value: c_ulong,
}

pub type async_input_event_t = *mut async_input_event;
pub type async_event_cb =
    Option<unsafe extern "C" fn(event: async_input_event_t, private_data: *mut c_void)>;

/// Event group: WiFi.
pub const EV_WIFI: u32 = 2;

pub const CODE_WIFI_ON_INIT_DONE: u32 = 1;
pub const CODE_WIFI_ON_MGMR_DONE: u32 = 2;
pub const CODE_WIFI_ON_CONNECTED: u32 = 4;
pub const CODE_WIFI_ON_DISCONNECT: u32 = 5;
pub const CODE_WIFI_ON_GOT_IP: u32 = 7;
pub const CODE_WIFI_ON_CONNECTING: u32 = 8;
pub const CODE_WIFI_ON_SCAN_DONE: u32 = 9;
pub const CODE_WIFI_ON_AP_STARTED: u32 = 11;
pub const CODE_WIFI_ON_AP_STOPPED: u32 = 12;
pub const CODE_WIFI_ON_AP_STA_ADD: u32 = 21;
pub const CODE_WIFI_ON_AP_STA_DEL: u32 = 22;
pub const CODE_WIFI_ON_LOST_IP: u32 = 26;
pub const CODE_WIFI_ON_GOT_IP_TIMEOUT: u32 = 28;
pub const CODE_WIFI_ON_PARAMS_ERROR: u32 = 32;

// ---------------------------------------------------------- WiFi manager types

#[repr(C)]
#[derive(Copy, Clone)]
pub struct wifi_mgmr_scan_params {
    pub ssid_length: u8,
    pub ssid_array: [u8; 32],
    pub bssid: [u8; 6],
    pub bssid_set_flag: u8,
    pub probe_cnt: u8,
    pub channels_cnt: c_int,
    pub channels: [u8; 14],
    pub duration: u32,
    pub passive: bool,
    pub extra_ies: *const u8,
    pub extra_ies_len: u16,
}
pub type wifi_mgmr_scan_params_t = wifi_mgmr_scan_params;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct wifi_mgmr_ap_params {
    pub ssid: *mut c_char,
    pub key: *mut c_char,
    pub akm: *mut c_char,
    pub channel: u8,
    pub type_: u8,
    pub use_ipcfg: bool,
    pub use_dhcpd: bool,
    pub start: c_int,
    pub limit: c_int,
    pub ap_ipaddr: u32,
    pub ap_mask: u32,
    pub ap_max_inactivity: u32,
    pub hidden_ssid: bool,
    pub isolation: bool,
    pub bcn_interval: c_int,
    pub ap_vendor_elements: *mut c_char,
    pub bcn_mode: u8,
    pub bcn_timer: c_int,
    pub disable_wmm: bool,
}
pub type wifi_mgmr_ap_params_t = wifi_mgmr_ap_params;

pub type tcpip_init_done_fn = Option<unsafe extern "C" fn(arg: *mut c_void)>;

// ------------------------------------------------------------------ functions

unsafe extern "C" {
    /// Interrupt nesting depth, non-zero inside a handler.
    ///
    /// The port's `xPortIsInsideInterrupt()` is a `portFORCE_INLINE` reading
    /// exactly this, so it has no symbol of its own to call — but the counter
    /// it reads is a real global, and the vendor's own `rtos_al.c` relies on
    /// it. Reading it is how Rust asks the same question.
    pub static TrapNetCounter: BaseType_t;
}

unsafe extern "C" {
    // --- board and peripherals
    pub fn board_init();
    pub fn bflb_device_get_by_name(name: *const c_char) -> *mut bflb_device_s;
    pub fn shell_init_with_task(shell: *mut bflb_device_s);

    /// Hardware true random number generator.
    ///
    /// Returns 0 on success. The BL616's TRNG is a real entropy source, which
    /// matters for anything generating keys rather than just seeding a port
    /// number.
    pub fn bflb_trng_readlen(data: *mut u8, len: u32) -> c_int;

    // --- SPI flash, for anything that has to survive a reboot.
    //
    // Addresses are offsets into the flash, not memory addresses; erase works
    // in sectors and write cannot clear a bit, which is the usual NOR
    // contract.
    pub fn bflb_flash_read(addr: u32, data: *mut u8, len: u32) -> c_int;
    pub fn bflb_flash_write(addr: u32, data: *const u8, len: u32) -> c_int;
    pub fn bflb_flash_erase(addr: u32, len: u32) -> c_int;

    /// Reset the whole SoC, peripherals included, and start again from the
    /// boot ROM. Does not return.
    pub fn GLB_SW_System_Reset();

    // --- UART
    pub fn bflb_uart_init(dev: *mut bflb_device_s, config: *const bflb_uart_config_s);
    pub fn bflb_uart_deinit(dev: *mut bflb_device_s);
    /// Returns the byte, or -1 when the receive FIFO is empty.
    pub fn bflb_uart_getchar(dev: *mut bflb_device_s) -> c_int;
    /// Blocks until every byte is in the transmit FIFO.
    pub fn bflb_uart_put_block(dev: *mut bflb_device_s, data: *mut u8, len: u32) -> c_int;
    pub fn bflb_uart_rxavailable(dev: *mut bflb_device_s) -> bool;
    /// Returns 0 once the byte is in the transmit FIFO, without waiting for
    /// the line. Check [`bflb_uart_txready`] first.
    pub fn bflb_uart_putchar(dev: *mut bflb_device_s, ch: c_int) -> c_int;
    /// Whether the transmit FIFO has room for another byte.
    pub fn bflb_uart_txready(dev: *mut bflb_device_s) -> bool;
    /// Unmask (`false`) or mask (`true`) the transmit FIFO interrupt.
    pub fn bflb_uart_txint_mask(dev: *mut bflb_device_s, mask: bool);
    /// Unmask (`false`) or mask (`true`) the receive FIFO and receive-timeout
    /// interrupts together.
    pub fn bflb_uart_rxint_mask(dev: *mut bflb_device_s, mask: bool);
    pub fn bflb_uart_get_intstatus(dev: *mut bflb_device_s) -> u32;
    pub fn bflb_uart_int_clear(dev: *mut bflb_device_s, int_clear: u32);
    pub fn bflb_uart_feature_control(dev: *mut bflb_device_s, cmd: c_int, arg: usize) -> c_int;

    // --- Interrupts. The SDK owns the vector table; attaching here is what
    // every vendor example does, and the trap entry that dispatches to it is
    // the same one `TrapNetCounter` counts.
    pub fn bflb_irq_attach(irq: c_int, isr: irq_callback, arg: *mut c_void) -> c_int;
    pub fn bflb_irq_detach(irq: c_int) -> c_int;
    pub fn bflb_irq_enable(irq: c_int);
    pub fn bflb_irq_disable(irq: c_int);
    /// Disable interrupts and return the previous `mstatus`.
    pub fn bflb_irq_save() -> usize;
    pub fn bflb_irq_restore(flags: usize);

    // --- GPIO
    /// Route `pin` to a UART signal, e.g. [`GPIO_UART_FUNC_UART0_RX`].
    pub fn bflb_gpio_uart_init(dev: *mut bflb_device_s, pin: u8, uart_func: u8);

    // --- C runtime, as provided by the SDK's allocator
    pub fn malloc(size: usize) -> *mut c_void;
    pub fn free(ptr: *mut c_void);
    pub fn printf(fmt: *const c_char, ...) -> c_int;
    /// Bytes free in the SDK heap.
    pub fn kfree_size(heap_id: u32) -> usize;

    // --- FreeRTOS
    pub fn xTaskCreate(
        pxTaskCode: TaskFunction_t,
        pcName: *const c_char,
        usStackDepth: u16,
        pvParameters: *mut c_void,
        uxPriority: UBaseType_t,
        pxCreatedTask: *mut TaskHandle_t,
    ) -> BaseType_t;
    pub fn vTaskDelete(xTaskToDelete: TaskHandle_t);
    pub fn vTaskDelay(xTicksToDelay: TickType_t);
    pub fn vTaskStartScheduler();
    pub fn xTaskGetTickCount() -> TickType_t;
    pub fn xTaskGetCurrentTaskHandle() -> TaskHandle_t;
    pub fn xTaskGenericNotify(
        xTaskToNotify: TaskHandle_t,
        uxIndexToNotify: UBaseType_t,
        ulValue: u32,
        eAction: eNotifyAction,
        pulPreviousNotificationValue: *mut u32,
    ) -> BaseType_t;
    pub fn xTaskGenericNotifyFromISR(
        xTaskToNotify: TaskHandle_t,
        uxIndexToNotify: UBaseType_t,
        ulValue: u32,
        eAction: eNotifyAction,
        pulPreviousNotificationValue: *mut u32,
        pxHigherPriorityTaskWoken: *mut BaseType_t,
    ) -> BaseType_t;
    pub fn xTaskGenericNotifyWait(
        uxIndexToWaitOn: UBaseType_t,
        ulBitsToClearOnEntry: u32,
        ulBitsToClearOnExit: u32,
        pulNotificationValue: *mut u32,
        xTicksToWait: TickType_t,
    ) -> BaseType_t;

    // --- radio bring-up
    pub fn rfparam_init(base_addr: u32, rf_para: *mut c_void, apply_flag: u32) -> i32;
    pub fn fhost_init() -> c_int;
    pub fn wifi_task_create();
    pub fn wifi_mgmr_task_start() -> c_int;
    pub fn tcpip_init(tcpip_init_done: tcpip_init_done_fn, arg: *mut c_void);

    // --- events
    pub fn async_register_event_filter(
        type_: usize,
        cb: async_event_cb,
        priv_: *mut c_void,
    ) -> c_int;

    // --- station
    pub fn wifi_sta_connect(
        ssid: *const c_char,
        key: *const c_char,
        bssid: *const c_char,
        akm_str: *const c_char,
        pmf_cfg: u8,
        freq1: u16,
        freq2: u16,
        use_dhcp: u8,
    ) -> c_int;
    pub fn wifi_sta_disconnect() -> c_int;
    pub fn wifi_sta_ip4_addr_get(
        addr: *mut u32,
        mask: *mut u32,
        gw: *mut u32,
        dns: *mut u32,
    ) -> c_int;
    pub fn wifi_mgmr_sta_mac_get(mac: *mut u8) -> c_int;
    pub fn wifi_mgmr_sta_rssi_get(rssi: *mut c_int) -> c_int;
    pub fn wifi_mgmr_sta_channel_get(channel: *mut u8) -> c_int;
    pub fn wifi_mgmr_sta_state_get() -> c_int;
    pub fn wifi_mgmr_sta_ip_set(ip: u32, mask: u32, gw: u32, dns: u32) -> c_int;
    pub fn wifi_mgmr_sta_autoconnect_enable() -> c_int;
    pub fn wifi_mgmr_sta_autoconnect_disable() -> c_int;
    pub fn wifi_mgmr_sta_scan(config: *const wifi_mgmr_scan_params_t) -> c_int;
    pub fn wifi_mgmr_sta_scanlist() -> c_int;
    pub fn wifi_mgmr_sta_scanlist_nums_get() -> u32;

    // --- access point
    pub fn wifi_mgmr_ap_start(config: *const wifi_mgmr_ap_params_t) -> c_int;
    pub fn wifi_mgmr_ap_stop() -> c_int;
    pub fn wifi_mgmr_ap_mac_get(mac: *mut u8) -> c_int;

    // --- regulatory
    pub fn wifi_mgmr_set_country_code(country_code: *mut c_char) -> c_int;
}


// --- FreeRTOS queues and semaphores
//
// The macro-only spellings (`xSemaphoreTake`, `xQueueCreate`, ...) do not
// exist as symbols; every one is a macro over the handful of generic
// functions below, which is what the RTOS adapter has to call.

/// Opaque queue/semaphore handle. `SemaphoreHandle_t` is the same type.
#[repr(C)]
pub struct QueueDefinition {
    _opaque: [u8; 0],
}
pub type QueueHandle_t = *mut QueueDefinition;
pub type SemaphoreHandle_t = QueueHandle_t;

/// `queueQUEUE_TYPE_BASE`, the type argument for a plain queue.
pub const QUEUE_TYPE_BASE: u8 = 0;
/// `queueQUEUE_TYPE_BINARY_SEMAPHORE`.
pub const QUEUE_TYPE_BINARY_SEMAPHORE: u8 = 3;
/// `queueSEND_TO_BACK`, the copy position for a normal send.
pub const QUEUE_SEND_TO_BACK: BaseType_t = 0;

unsafe extern "C" {
    pub fn xQueueGenericCreate(
        uxQueueLength: UBaseType_t,
        uxItemSize: UBaseType_t,
        ucQueueType: u8,
    ) -> QueueHandle_t;
    pub fn xQueueCreateMutex(ucQueueType: u8) -> QueueHandle_t;
    pub fn xQueueTakeMutexRecursive(xMutex: QueueHandle_t, xTicksToWait: TickType_t) -> BaseType_t;
    pub fn xQueueGiveMutexRecursive(xMutex: QueueHandle_t) -> BaseType_t;
    pub fn xQueueCreateCountingSemaphore(
        uxMaxCount: UBaseType_t,
        uxInitialCount: UBaseType_t,
    ) -> QueueHandle_t;
    pub fn vQueueDelete(xQueue: QueueHandle_t);
    pub fn xQueueGenericSend(
        xQueue: QueueHandle_t,
        pvItemToQueue: *const c_void,
        xTicksToWait: TickType_t,
        xCopyPosition: BaseType_t,
    ) -> BaseType_t;
    pub fn xQueueGenericSendFromISR(
        xQueue: QueueHandle_t,
        pvItemToQueue: *const c_void,
        pxHigherPriorityTaskWoken: *mut BaseType_t,
        xCopyPosition: BaseType_t,
    ) -> BaseType_t;
    pub fn xQueueGiveFromISR(
        xQueue: QueueHandle_t,
        pxHigherPriorityTaskWoken: *mut BaseType_t,
    ) -> BaseType_t;
    pub fn xQueueReceive(
        xQueue: QueueHandle_t,
        pvBuffer: *mut c_void,
        xTicksToWait: TickType_t,
    ) -> BaseType_t;
    pub fn xQueueReceiveFromISR(
        xQueue: QueueHandle_t,
        pvBuffer: *mut c_void,
        pxHigherPriorityTaskWoken: *mut BaseType_t,
    ) -> BaseType_t;
    pub fn xQueueSemaphoreTake(xQueue: QueueHandle_t, xTicksToWait: TickType_t) -> BaseType_t;
    pub fn uxQueueMessagesWaiting(xQueue: QueueHandle_t) -> UBaseType_t;
    pub fn uxQueueMessagesWaitingFromISR(xQueue: QueueHandle_t) -> UBaseType_t;
    pub fn xQueueIsQueueEmptyFromISR(xQueue: QueueHandle_t) -> BaseType_t;
    pub fn xQueueIsQueueFullFromISR(xQueue: QueueHandle_t) -> BaseType_t;

    // --- tasks, beyond what the runtime already uses
    pub fn xTaskGetHandle(pcNameToQuery: *const c_char) -> TaskHandle_t;
    pub fn vTaskPrioritySet(xTask: TaskHandle_t, uxNewPriority: UBaseType_t);
    pub fn vTaskSetTaskNumber(xTask: TaskHandle_t, uxHandle: UBaseType_t);
    pub fn eTaskGetState(xTask: TaskHandle_t) -> u8;
    pub fn ulTaskGenericNotifyTake(
        uxIndexToWaitOn: UBaseType_t,
        xClearCountOnExit: BaseType_t,
        xTicksToWait: TickType_t,
    ) -> u32;
    pub fn vTaskGenericNotifyGiveFromISR(
        xTaskToNotify: TaskHandle_t,
        uxIndexToNotify: UBaseType_t,
        pxHigherPriorityTaskWoken: *mut BaseType_t,
    );
    pub fn vTaskEnterCritical();
    pub fn vTaskExitCritical();
    pub fn xTaskGetTickCountFromISR() -> TickType_t;
    /// [`TASK_SCHEDULER_SUSPENDED`], [`TASK_SCHEDULER_NOT_STARTED`] or
    /// [`TASK_SCHEDULER_RUNNING`].
    pub fn xTaskGetSchedulerState() -> BaseType_t;

    /// The console write the linker's `--wrap` renamed out of the way.
    ///
    /// Every `printf` in the firmware, C and Rust alike, ends up here. The
    /// SDK's own copy takes no lock and keeps the CRLF translation state in
    /// a global, so two tasks writing at once interleave by the character;
    /// `crate::console` supplies the `__wrap_` half that serialises them.
    pub fn __real_bflb_console_write(data: *const c_void, size: usize) -> isize;

    /// The formatter behind the vendor's `printf`, renamed by `--wrap` when
    /// the `console-probe` feature asks for it.
    ///
    /// Only the probe uses it: measurement showed the SDK's `printf` is not
    /// on the hot path of this firmware's console traffic, so wrapping it in
    /// a production build would buy nothing. Recording which format strings
    /// pass through here is how that was established.
    ///
    /// `args` is a `va_list`, opaque here and passed straight through; on
    /// this ABI it is one pointer-sized value.
    pub fn __real_console_vsnprintf(fmt: *const c_char, args: *mut c_void) -> c_int;

}

// --------------------------------------------------------- layout assertions
//
// What the C compiler says these types look like, measured from the vendor
// headers by `build.rs`. Nothing below is transcribed: if a future SDK moves
// a field, the assertion that names it fails.

mod layout {
    include!(concat!(env!("OUT_DIR"), "/layout.rs"));
}

const _: () = assert!(core::mem::size_of::<c_long>() == 4, "ilp32f: long is 32 bits");

macro_rules! check {
    ($ty:ty, $size:ident, $align:ident $(, $field:ident => $off:ident)* $(,)?) => {
        const _: () = {
            assert!(core::mem::size_of::<$ty>() == layout::$size);
            assert!(core::mem::align_of::<$ty>() == layout::$align);
            $(assert!(core::mem::offset_of!($ty, $field) == layout::$off);)*
        };
    };
}

check!(
    wifi_mgmr_ap_params,
    AP_PARAMS_SIZE,
    AP_PARAMS_ALIGN,
    ssid => AP_PARAMS_OFF_SSID,
    key => AP_PARAMS_OFF_KEY,
    akm => AP_PARAMS_OFF_AKM,
    channel => AP_PARAMS_OFF_CHANNEL,
    type_ => AP_PARAMS_OFF_TYPE,
    use_ipcfg => AP_PARAMS_OFF_USE_IPCFG,
    use_dhcpd => AP_PARAMS_OFF_USE_DHCPD,
    start => AP_PARAMS_OFF_START,
    limit => AP_PARAMS_OFF_LIMIT,
    ap_ipaddr => AP_PARAMS_OFF_AP_IPADDR,
    ap_mask => AP_PARAMS_OFF_AP_MASK,
    ap_max_inactivity => AP_PARAMS_OFF_AP_MAX_INACTIVITY,
    hidden_ssid => AP_PARAMS_OFF_HIDDEN_SSID,
    isolation => AP_PARAMS_OFF_ISOLATION,
    bcn_interval => AP_PARAMS_OFF_BCN_INTERVAL,
    ap_vendor_elements => AP_PARAMS_OFF_AP_VENDOR_ELEMENTS,
    bcn_mode => AP_PARAMS_OFF_BCN_MODE,
    bcn_timer => AP_PARAMS_OFF_BCN_TIMER,
    disable_wmm => AP_PARAMS_OFF_DISABLE_WMM,
);

check!(
    wifi_mgmr_scan_params,
    SCAN_PARAMS_SIZE,
    SCAN_PARAMS_ALIGN,
    ssid_length => SCAN_PARAMS_OFF_SSID_LENGTH,
    ssid_array => SCAN_PARAMS_OFF_SSID_ARRAY,
    bssid => SCAN_PARAMS_OFF_BSSID,
    bssid_set_flag => SCAN_PARAMS_OFF_BSSID_SET_FLAG,
    probe_cnt => SCAN_PARAMS_OFF_PROBE_CNT,
    channels_cnt => SCAN_PARAMS_OFF_CHANNELS_CNT,
    channels => SCAN_PARAMS_OFF_CHANNELS,
    duration => SCAN_PARAMS_OFF_DURATION,
    passive => SCAN_PARAMS_OFF_PASSIVE,
    extra_ies => SCAN_PARAMS_OFF_EXTRA_IES,
    extra_ies_len => SCAN_PARAMS_OFF_EXTRA_IES_LEN,
);

check!(
    bflb_uart_config_s,
    UART_CONFIG_SIZE,
    UART_CONFIG_ALIGN,
    baudrate => UART_CONFIG_OFF_BAUDRATE,
    direction => UART_CONFIG_OFF_DIRECTION,
    data_bits => UART_CONFIG_OFF_DATA_BITS,
    stop_bits => UART_CONFIG_OFF_STOP_BITS,
    parity => UART_CONFIG_OFF_PARITY,
    bit_order => UART_CONFIG_OFF_BIT_ORDER,
    flow_ctrl => UART_CONFIG_OFF_FLOW_CTRL,
    tx_fifo_threshold => UART_CONFIG_OFF_TX_FIFO_THRESHOLD,
    rx_fifo_threshold => UART_CONFIG_OFF_RX_FIFO_THRESHOLD,
);

check!(
    bflb_device_s,
    DEVICE_SIZE,
    DEVICE_ALIGN,
    name => DEVICE_OFF_NAME,
    reg_base => DEVICE_OFF_REG_BASE,
    irq_num => DEVICE_OFF_IRQ_NUM,
    idx => DEVICE_OFF_IDX,
    sub_idx => DEVICE_OFF_SUB_IDX,
    dev_type => DEVICE_OFF_DEV_TYPE,
    user_data => DEVICE_OFF_USER_DATA,
);

check!(
    async_input_event,
    ASYNC_EVENT_SIZE,
    ASYNC_EVENT_ALIGN,
    entry => ASYNC_EVENT_OFF_ENTRY,
    type_ => ASYNC_EVENT_OFF_TYPE,
    finish => ASYNC_EVENT_OFF_FINISH,
    size => ASYNC_EVENT_OFF_SIZE,
    code => ASYNC_EVENT_OFF_CODE,
    value => ASYNC_EVENT_OFF_VALUE,
);
