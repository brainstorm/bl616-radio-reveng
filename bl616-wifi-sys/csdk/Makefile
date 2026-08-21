# SPDX-FileCopyrightText: 2026 Roman Valls Guimera <brainstorm@nopcode.org>
#
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Standard BouffaloSDK project makefile. BL_SDK_BASE is supplied by
# bl616-wifi-sys/build.rs (or by hand, if you want to poke at the C side).

SDK_DEMO_PATH ?= $(abspath .)
BL_SDK_BASE   ?= $(abspath ./../../vendor/bouffalo_sdk)

export BL_SDK_BASE

include $(BL_SDK_BASE)/project.build
