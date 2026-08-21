/*
 * SPDX-FileCopyrightText: 2026 Roman Valls Guimera <brainstorm@nopcode.org>
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Placeholder main() for the C-side link only.
 *
 * The firmware's real main() is `bl616_wifi::rt::main` on the Rust side.
 * build.rs drops this object from the final link line — it exists so that
 * CMake can complete its own link step and emit a link.txt describing the
 * full archive set.
 */

int main(void)
{
    return 0;
}
