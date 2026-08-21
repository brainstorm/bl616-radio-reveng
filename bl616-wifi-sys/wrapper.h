/*
 * SPDX-FileCopyrightText: 2026 Roman Valls Guimera <brainstorm@nopcode.org>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * bindgen entry point. Everything the Rust side of bl616-wifi needs to reach
 * into the BouffaloSDK C substrate, in the order the SDK itself includes it.
 */

#include <stdbool.h>
#include <stdint.h>

/* RTOS + platform */
#include "FreeRTOS.h"
#include "task.h"
#include "timers.h"

/* Board / low-level HAL */
#include "board.h"
#include "bflb_uart.h"
#include "bflb_gpio.h"
#include "bflb_mtimer.h"

/* Heap accounting (kfree_size) */
#include "mm.h"

/* RF calibration data from efuse + flash rftlv */
#include "rfparam_adapter.h"

/* Asynchronous event bus the WiFi manager posts state changes on */
#include "async_event.h"

/* TCP/IP */
#include "lwip/tcpip.h"
#include "lwip/netif.h"
#include "lwip/ip4_addr.h"
#include "lwip/inet.h"

/* WiFi 6 "fully hosted" stack */
#include "fhost_api.h"
#include "wifi_mgmr_ext.h"
#include "wifi_mgmr.h"

/* Vendor CLI, handy during hardware bring-up */
#include "shell.h"

/*
 * Declared in the fhost blob / SDK glue but not in any installed header.
 * Both are part of the canonical bring-up sequence used by every
 * examples/wifi/* project.
 */
extern void wifi_task_create(void);
extern void shell_init_with_task(struct bflb_device_s *shell);
