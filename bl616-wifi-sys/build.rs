// SPDX-FileCopyrightText: 2026 Roman Valls Guimera <brainstorm@nopcode.org>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Builds the C substrate (`csdk/`) with BouffaloSDK's own CMake build, then
//! teaches rustc how to link against it and generates FFI bindings.
//!
//! Three things come out of the CMake build and all three are consumed here
//! rather than duplicated:
//!
//! * `CMakeFiles/*.elf.dir/link.txt` — the exact archive set and link flags,
//!   including the generated linker script. Reused verbatim minus the C
//!   `main.c.obj` (Rust supplies `main`).
//! * `CMakeFiles/*.elf.dir/flags.make` — the `-D`/`-I` set the headers must be
//!   parsed with, fed straight to bindgen.
//! * `build_out/lib/*.a` plus the vendor blobs — linked whole-archive, the way
//!   the vendor does it.

use std::collections::HashSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let csdk_dir = manifest_dir.join("csdk");

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=wrapper.h");
    println!("cargo:rerun-if-changed=csdk");
    println!("cargo:rerun-if-env-changed=BL_SDK_BASE");
    println!("cargo:rerun-if-env-changed=BL616_TOOLCHAIN_BIN");
    println!("cargo:rerun-if-env-changed=BL616_CHIP");
    println!("cargo:rerun-if-env-changed=BL616_BOARD");

    let sdk = find_sdk(&manifest_dir);
    let toolchain_bin = find_toolchain();
    let chip = env::var("BL616_CHIP").unwrap_or_else(|_| "bl616".into());
    let board = env::var("BL616_BOARD").unwrap_or_else(|_| "bl616dk".into());

    // BouffaloSDK's CMake glues BUILD_DIR onto CMAKE_CURRENT_SOURCE_DIR when
    // it names the generated linker script, so BUILD_DIR has to stay relative
    // to the project. Copy the project into OUT_DIR and build it there, and
    // both that constraint and `cargo clean` are satisfied.
    let project_dir = out_dir.join("csdk");
    copy_dir(&csdk_dir, &project_dir);
    let build_dir = project_dir.join("build");
    build_csdk(&project_dir, &sdk, &toolchain_bin, &chip, &board);

    let link_txt = find_elf_link_txt(&build_dir.join("CMakeFiles")).unwrap_or_else(|| {
        panic!(
            "no <target>.elf.dir/link.txt under {} — the C substrate build did not reach the link step",
            build_dir.join("CMakeFiles").display()
        )
    });
    let flags_make = link_txt.with_file_name("flags.make");

    emit_tick_rate(&csdk_dir);
    emit_link_args(&link_txt, &build_dir, &out_dir);
    generate_bindings(&manifest_dir, &out_dir, &flags_make, &toolchain_bin);

    // Consumers (xtask, mostly) need to find the SDK and the generated linker
    // script without re-deriving any of this.
    println!("cargo:sdk={}", sdk.display());
    println!("cargo:board={board}");
    println!("cargo:chip={chip}");
    println!("cargo:toolchain_bin={}", toolchain_bin.display());
    println!("cargo:csdk_build={}", build_dir.display());
}

/// BouffaloSDK checkout: `$BL_SDK_BASE`, else `vendor/bouffalo_sdk`, else a
/// sibling clone next to this repository.
fn find_sdk(manifest_dir: &Path) -> PathBuf {
    let workspace = manifest_dir.parent().unwrap();
    let candidates: Vec<PathBuf> = env::var_os("BL_SDK_BASE")
        .map(PathBuf::from)
        .into_iter()
        .chain([
            workspace.join("vendor/bouffalo_sdk"),
            workspace.join("../bouffalo_sdk"),
        ])
        .collect();

    for c in &candidates {
        if c.join("project.build").is_file() {
            return fs::canonicalize(c).unwrap();
        }
    }

    panic!(
        "BouffaloSDK not found. Set BL_SDK_BASE, or clone it into vendor/bouffalo_sdk:\n  \
         git clone https://github.com/bouffalolab/bouffalo_sdk vendor/bouffalo_sdk\n\
         Looked in: {candidates:?}"
    );
}

/// T-Head GCC 10.2 (Xuantie V2.6.1) — the toolchain the vendor blobs were
/// compiled with. `$BL616_TOOLCHAIN_BIN`, else whatever is on `PATH`.
fn find_toolchain() -> PathBuf {
    if let Some(dir) = env::var_os("BL616_TOOLCHAIN_BIN") {
        let dir = PathBuf::from(dir);
        assert!(
            dir.join("riscv64-unknown-elf-gcc").is_file(),
            "BL616_TOOLCHAIN_BIN={} has no riscv64-unknown-elf-gcc",
            dir.display()
        );
        return dir;
    }

    let found = Command::new("sh")
        .args(["-c", "command -v riscv64-unknown-elf-gcc"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| PathBuf::from(String::from_utf8_lossy(&o.stdout).trim().to_string()));

    match found {
        Some(gcc) => fs::canonicalize(&gcc)
            .unwrap_or(gcc)
            .parent()
            .unwrap()
            .to_path_buf(),
        None => panic!(
            "riscv64-unknown-elf-gcc not on PATH. Install the T-Head toolchain \
             (`cargo xtask setup`) or point BL616_TOOLCHAIN_BIN at its bin/ directory."
        ),
    }
}

fn copy_dir(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap_or_else(|e| panic!("cannot create {}: {e}", to.display()));
    for entry in fs::read_dir(from)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", from.display()))
        .flatten()
    {
        let src = entry.path();
        let dst = to.join(entry.file_name());
        if src.is_dir() {
            copy_dir(&src, &dst);
        } else {
            // Only rewrite when the content differs: an unconditional copy
            // would bump mtimes and make every build a full C rebuild.
            let new = fs::read(&src).unwrap();
            if fs::read(&dst).ok().as_deref() != Some(&new[..]) {
                fs::write(&dst, &new)
                    .unwrap_or_else(|e| panic!("cannot write {}: {e}", dst.display()));
            }
        }
    }
}

fn build_csdk(project_dir: &Path, sdk: &Path, toolchain_bin: &Path, chip: &str, board: &str) {
    let jobs = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .to_string();

    let path = match env::var_os("PATH") {
        Some(p) => {
            let mut dirs = vec![toolchain_bin.to_path_buf()];
            dirs.extend(env::split_paths(&p));
            env::join_paths(dirs).unwrap()
        }
        None => toolchain_bin.as_os_str().to_os_string(),
    };

    // `cmake_cache` reconfigures from scratch; the second invocation is the
    // one that actually compiles. Deliberately *not* `make` (the default
    // target), which would also run post_build/combine on the throwaway ELF.
    let mut configure = Command::new("make");
    configure
        .arg("-C")
        .arg(project_dir)
        .arg("cmake_cache")
        .arg(format!("CHIP={chip}"))
        .arg(format!("BOARD={board}"))
        .env("BL_SDK_BASE", sdk)
        .env("PATH", &path);

    // BouffaloSDK collects every CONFIG_* make variable, command-line ones
    // included, so features can extend defconfig without editing it.
    if env::var_os("CARGO_FEATURE_USB_CONSOLE").is_some() {
        configure.args([
            "CONFIG_BSP_CONSOLE_USB_CDC=y",
            "CONFIG_CHERRYUSB=y",
            "CONFIG_CHERRYUSB_OSAL=freertos",
            "CONFIG_CHERRYUSB_DEVICE=y",
            "CONFIG_CHERRYUSB_DEVICE_CDC_ACM=y",
        ]);
    }

    run(&mut configure, "configure the C substrate");

    run(
        Command::new("make")
            .arg("-C")
            .arg(project_dir.join("build"))
            .arg("-j")
            .arg(&jobs)
            .env("BL_SDK_BASE", sdk)
            .env("PATH", &path),
        "build the C substrate",
    );
}

fn run(cmd: &mut Command, what: &str) {
    let status = cmd
        .status()
        .unwrap_or_else(|e| panic!("failed to spawn `{cmd:?}` to {what}: {e}"));
    assert!(status.success(), "failed to {what} ({status})");
}

/// Find the link line for the *executable* target.
///
/// CMake writes a `link.txt` for every target it links, including the static
/// libraries, and directory order is not stable across a fresh configure. Only
/// the one under `<name>.elf.dir` carries the linker script and the archive
/// set; taking the first match found a library's instead, on a cold build.
fn find_elf_link_txt(root: &Path) -> Option<PathBuf> {
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).ok()?.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let is_link_txt = path.file_name().map(|f| f == "link.txt").unwrap_or(false);
            let in_elf_dir = dir
                .file_name()
                .map(|d| d.to_string_lossy().ends_with(".elf.dir"))
                .unwrap_or(false);
            if is_link_txt && in_elf_dir {
                return Some(path);
            }
        }
    }
    None
}

/// `configTICK_RATE_HZ` is `((TickType_t)1000)` — a cast expression bindgen
/// will not fold — so read it out of FreeRTOSConfig.h and hand it to the Rust
/// side as an environment variable instead of hardcoding it twice.
fn emit_tick_rate(csdk_dir: &Path) {
    let path = csdk_dir.join("FreeRTOSConfig.h");
    let text =
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));

    let hz = text
        .lines()
        .find_map(|l| {
            let rest = l.trim().strip_prefix("#define configTICK_RATE_HZ")?;
            rest.chars()
                .filter(|c| c.is_ascii_digit())
                .collect::<String>()
                .parse::<u32>()
                .ok()
        })
        .expect("no configTICK_RATE_HZ in csdk/FreeRTOSConfig.h");

    assert!(hz > 0, "configTICK_RATE_HZ must be positive");
    println!("cargo:rustc-env=BL616_TICK_RATE_HZ={hz}");
}

/// Split a shell-quoted command line the way `sh` would, so that defines
/// carrying quoted strings (`-DBFLB_GIT_SUFFIX="\" 5cd17516\""`) survive.
fn shell_split(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut started = false;
    let mut chars = line.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            c if c.is_whitespace() => {
                if started {
                    out.push(core::mem::take(&mut cur));
                    started = false;
                }
            }
            '\'' => {
                started = true;
                for c in chars.by_ref() {
                    if c == '\'' {
                        break;
                    }
                    cur.push(c);
                }
            }
            '"' => {
                started = true;
                while let Some(c) = chars.next() {
                    match c {
                        '"' => break,
                        // Inside double quotes the shell only unescapes these.
                        '\\' if matches!(chars.peek(), Some('"' | '\\' | '$' | '`')) => {
                            cur.push(chars.next().unwrap())
                        }
                        c => cur.push(c),
                    }
                }
            }
            '\\' => {
                started = true;
                if let Some(c) = chars.next() {
                    cur.push(c);
                }
            }
            c => {
                started = true;
                cur.push(c);
            }
        }
    }
    if started {
        out.push(cur);
    }
    out
}

/// Replay CMake's link line as rustc link args.
///
/// Everything is kept except the compiler itself, the `-o <elf>` pair and the
/// stub `main.c.obj` — Rust brings its own `main`. `--whole-archive` matters:
/// most of what the WiFi stack needs is pulled in by constructor sections and
/// linker-script `KEEP`s rather than by symbol reference.
fn emit_link_args(link_txt: &Path, build_dir: &Path, out_dir: &Path) {
    let line = fs::read_to_string(link_txt)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", link_txt.display()));

    let tokens = shell_split(&line);
    let mut args = Vec::new();
    let mut skip_next = false;

    for tok in tokens.iter().skip(1) {
        if skip_next {
            skip_next = false;
            continue;
        }
        if tok == "-o" {
            skip_next = true;
            continue;
        }
        if tok.ends_with("main.c.obj") {
            continue;
        }
        // CMake writes a link map next to its own throwaway ELF; replaying
        // that would have every Rust binary clobber the same file.
        // --cref only makes sense alongside that map, and without it the
        // cross-reference table drowns any real linker error.
        if tok.starts_with("-Wl,-Map=") || tok == "-Wl,--cref" {
            continue;
        }
        // Archive paths are relative to the CMake build directory, and the
        // linker will be run from somewhere else entirely.
        let absolute = build_dir.join(tok);
        if !tok.starts_with('-') && absolute.is_file() {
            args.push(absolute.to_string_lossy().into_owned());
            continue;
        }
        args.push(tok.clone());
    }

    // rustc links with -nodefaultlibs, so the GCC driver never adds -lgcc.
    // The vendor MAC and the TLSF allocator both call __ffssi2, and libgcc in
    // turn wants memcpy/abort out of libc: a group settles the cycle.
    args.extend(
        [
            "-Wl,--start-group",
            "-lc",
            "-lm",
            "-lgcc",
            "-Wl,--end-group",
        ]
        .map(str::to_string),
    );

    assert!(
        args.iter().any(|a| a.starts_with("-T")),
        "no linker script in {} — the C substrate build is incomplete",
        link_txt.display()
    );

    for arg in &args {
        println!("cargo:rustc-link-arg={arg}");
    }

    // `cargo:rustc-link-arg` only applies to the emitting package's own
    // targets, so hand dependents the list to re-emit from their own build
    // script. See bl616-wifi/build.rs.
    let path = out_dir.join("link-args.txt");
    fs::write(&path, args.join("\n"))
        .unwrap_or_else(|e| panic!("cannot write {}: {e}", path.display()));
    println!("cargo:link_args={}", path.display());
}

/// Point `clang-sys` at one specific libclang, and report where that clang
/// keeps its freestanding headers (`stdbool.h` and friends).
fn setup_libclang() -> Option<PathBuf> {
    let resource_dir = Command::new("clang")
        .arg("-print-resource-dir")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| PathBuf::from(String::from_utf8_lossy(&o.stdout).trim().to_string()));

    if env::var_os("LIBCLANG_PATH").is_none() {
        // Pin the library to the same major version as the driver above,
        // rather than letting clang-sys pick from however many Debian has
        // installed side by side.
        let major = resource_dir
            .as_ref()
            .and_then(|d| d.file_name())
            .map(|n| n.to_string_lossy().into_owned());

        let mut chosen = None;
        if let Some(major) = &major {
            for dir in ["/usr/lib/x86_64-linux-gnu", "/usr/lib64", "/usr/lib"] {
                let candidate = Path::new(dir).join(format!("libclang-{major}.so.1"));
                if candidate.is_file() {
                    chosen = Some(candidate);
                    break;
                }
            }
        }
        match chosen {
            Some(lib) => env::set_var("LIBCLANG_PATH", lib),
            None => {
                for dir in ["/usr/lib/x86_64-linux-gnu", "/usr/lib64", "/usr/lib"] {
                    if fs::read_dir(dir)
                        .map(|mut d| {
                            d.any(|e| {
                                e.map(|e| e.file_name().to_string_lossy().starts_with("libclang"))
                                    .unwrap_or(false)
                            })
                        })
                        .unwrap_or(false)
                    {
                        env::set_var("LIBCLANG_PATH", dir);
                        break;
                    }
                }
            }
        }
    }

    resource_dir
        .map(|d| d.join("include"))
        .filter(|d| d.is_dir())
}

/// bindgen over the vendor headers, using the exact `-D`/`-I` set CMake
/// compiled the C substrate with (including the generated `autoconf.h`).
fn generate_bindings(manifest_dir: &Path, out_dir: &Path, flags_make: &Path, toolchain_bin: &Path) {
    let clang_builtin_includes = setup_libclang();

    let flags = fs::read_to_string(flags_make)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", flags_make.display()));

    let mut clang_args = vec![
        // Layout must be computed for the target, not the host.
        "--target=riscv32-unknown-none-elf".to_string(),
        // The SDK compiles with -fshort-enums; getting this wrong silently
        // changes the size of half the config structs.
        "-fshort-enums".to_string(),
        "-ffreestanding".to_string(),
        "-nostdinc".to_string(),
    ];

    // clang's own freestanding headers first, then newlib, then the SDK's.
    // -nostdinc above keeps host glibc out of a cross-compilation.
    if let Some(dir) = clang_builtin_includes {
        clang_args.push(format!("-isystem{}", dir.display()));
    }
    for inc in newlib_includes(toolchain_bin) {
        clang_args.push(format!("-isystem{}", inc.display()));
    }

    let mut seen = HashSet::new();
    for raw in flags.lines() {
        let Some(rest) = raw
            .strip_prefix("C_DEFINES =")
            .or_else(|| raw.strip_prefix("C_INCLUDES ="))
        else {
            // `-include .../autoconf.h` lives in C_FLAGS; the rest of C_FLAGS
            // is GCC codegen noise clang would reject.
            if let Some(rest) = raw.strip_prefix("C_FLAGS =") {
                let toks = shell_split(rest);
                let mut it = toks.iter();
                while let Some(tok) = it.next() {
                    if tok == "-include" {
                        if let Some(hdr) = it.next() {
                            clang_args.push("-include".into());
                            clang_args.push(hdr.clone());
                        }
                    }
                }
            }
            continue;
        };
        for tok in shell_split(rest) {
            if seen.insert(tok.clone()) {
                clang_args.push(tok);
            }
        }
    }

    let bindings = bindgen::Builder::default()
        .header(manifest_dir.join("wrapper.h").to_string_lossy())
        .clang_args(&clang_args)
        .use_core()
        .ctypes_prefix("::core::ffi")
        .derive_default(true)
        .derive_debug(false)
        .layout_tests(false)
        .generate_comments(false)
        .prepend_enum_name(false)
        // The SDK's headers reach into newlib and lwIP; keeping everything
        // would drag in a few thousand items nobody calls.
        .allowlist_function("wifi_.*")
        .allowlist_function("fhost_.*")
        .allowlist_function("rfparam_.*")
        .allowlist_function("board_.*")
        .allowlist_function("bflb_.*")
        .allowlist_function("async_.*")
        .allowlist_function("net_al_.*")
        .allowlist_function("netif_.*")
        .allowlist_function("dhcpd_.*")
        .allowlist_function("tcpip_init")
        .allowlist_function("shell_init_with_task")
        .allowlist_function("x?Task.*")
        .allowlist_function("vTask.*")
        .allowlist_function("pvPortMalloc|vPortFree")
        .allowlist_function("malloc|free|calloc|realloc|printf|putchar|puts|snprintf")
        .allowlist_function("kfree_size|kmalloc|kfree|mm_sec_keydump")
        .allowlist_type("wifi_.*")
        .allowlist_type("fhost_.*")
        .allowlist_type("async_.*")
        .allowlist_type("bflb_device_s")
        .allowlist_type("netif")
        .allowlist_type("ip4_addr")
        .allowlist_var("CODE_WIFI_.*")
        .allowlist_var("EV_WIFI")
        .allowlist_var("MGMR_.*")
        .allowlist_var("WIFI_EVENT_.*")
        .allowlist_var("MAX_FIXED_CHANNELS_LIMIT")
        .allowlist_var("MAX_AP_SCAN")
        .allowlist_var("configTICK_RATE_HZ")
        .generate()
        .unwrap_or_else(|e| {
            panic!("bindgen failed on the BouffaloSDK headers: {e}\nclang args: {clang_args:?}")
        });

    bindings
        .write_to_file(out_dir.join("bindings.rs"))
        .expect("cannot write bindings.rs");
}

fn newlib_includes(toolchain_bin: &Path) -> Vec<PathBuf> {
    let mut dirs = Vec::new();

    // Standard bare-metal GCC layout: <prefix>/riscv64-unknown-elf/include
    if let Some(prefix) = toolchain_bin.parent() {
        let inc = prefix.join("riscv64-unknown-elf/include");
        if inc.is_dir() {
            dirs.push(inc);
        }
    }

    // ...and whatever the driver itself claims, for other layouts.
    if let Some(out) = Command::new("riscv64-unknown-elf-gcc")
        .arg("-print-sysroot")
        .output()
        .ok()
        .filter(|o| o.status.success())
    {
        let sysroot = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !sysroot.is_empty() {
            let inc = PathBuf::from(sysroot).join("include");
            if inc.is_dir() && !dirs.contains(&inc) {
                dirs.push(inc);
            }
        }
    }

    dirs
}
