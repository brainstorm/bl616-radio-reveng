# SPDX-FileCopyrightText: 2026 Roman Valls Guimera <brainstorm@nopcode.org>
#
# SPDX-License-Identifier: GPL-3.0-or-later
#
# The C substrate for bl616-wifi: FreeRTOS + lwIP + the Bouffalo WiFi 6
# stack (fhost + macsw + phyrf blobs). Rust links against the archives this
# produces; the ELF it produces itself is a throwaway that only exists so
# CMake emits a complete link.txt for build.rs to read.

cmake_minimum_required(VERSION 3.15)

find_package(bouffalo_sdk REQUIRED HINTS $ENV{BL_SDK_BASE})

sdk_add_compile_definitions(-DCONFIG_CLI_CMD_ENABLE)
sdk_add_compile_definitions(-DHIGH_PERFORMANCE_PBUF=1)

sdk_set_main_file(main.c)

project(bl616_wifi)
