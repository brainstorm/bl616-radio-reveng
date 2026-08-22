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

/// Opaque LHAL device handle.
#[repr(C)]
pub struct bflb_device_s {
    _opaque: [u8; 0],
}

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
