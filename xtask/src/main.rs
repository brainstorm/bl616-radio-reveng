// SPDX-FileCopyrightText: 2026 Roman Valls Guimera <brainstorm@nopcode.org>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Build, image and flash helper.
//!
//! `cargo build` produces an ELF; a BL616 wants a flash image with a
//! bootheader, a partition table, boot2 and the RF factory parameters beside
//! it. Those last steps are BouffaloSDK's `bflb_fw_post_proc` and
//! `BLFlashCommand`, and this is the glue that drives them.
//!
//! ```text
//! cargo xtask build  --example ap
//! cargo xtask flash  --example ap [--port /dev/ttyACM0] [--baud 2000000]
//! cargo xtask monitor [--port /dev/ttyUSB0] [--baud 2000000]
//! cargo xtask setup
//! ```

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

const TARGET: &str = "riscv32imafc-unknown-none-elf";
const DEFAULT_CHIP: &str = "bl616";
const DEFAULT_BOARD: &str = "bl616dk";
/// BouffaloSDK's console default, and what `csdk/` is built with.
const DEFAULT_BAUD: &str = "2000000";
const TOOLCHAIN_REPO: &str = "https://github.com/bouffalolab/toolchain_gcc_t-head_linux";

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("build") => cmd_build(&args[1..]).map(|_| ()),
        Some("flash") => cmd_flash(&args[1..]),
        Some("monitor") => cmd_monitor(&args[1..]),
        Some("setup") => cmd_setup(),
        Some("help" | "--help" | "-h") | None => {
            usage();
            return ExitCode::SUCCESS;
        }
        Some(other) => Err(format!("unknown command {other:?}")),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("\nerror: {e}");
            ExitCode::FAILURE
        }
    }
}

fn usage() {
    eprintln!(
        "\
bl616-wifi build helper

USAGE:
    cargo xtask build   --example <name> [--features <list>] [--debug]
    cargo xtask build   --elf <path>
    cargo xtask flash   --example <name> [--features <list>] [--port <dev>] [--baud <rate>] [--erase-all]
    cargo xtask flash   --elf <path> [--port <dev>] [--baud <rate>] [--erase-all]
    cargo xtask monitor [--port <dev>] [--baud <rate>]
    cargo xtask setup

EXAMPLES:
    WIFI_SSID=home WIFI_PSK=secret cargo xtask flash --example sta
    AP_SSID=bl616-ap AP_PSK=rustrust cargo xtask flash --example ap --features usb-console

ENVIRONMENT:
    BL_SDK_BASE           BouffaloSDK checkout (default: ../bouffalo_sdk or vendor/bouffalo_sdk)
    BL616_BOARD           board config to image against (default: {DEFAULT_BOARD})
    BL616_PORT            serial port (default: first /dev/ttyACM* then /dev/ttyUSB*)"
    );
}

// ---------------------------------------------------------------- commands

struct Artifacts {
    /// Flash image with bootheader and RF parameters appended.
    firmware: PathBuf,
    /// Directory holding firmware, boot2, partition table and mfg image.
    dir: PathBuf,
}

fn cmd_build(args: &[String]) -> Result<Artifacts, String> {
    // `--elf` post-processes a binary somebody else built. An application
    // living outside this workspace -- ssh-stamp, say -- links its own
    // firmware and still needs the bootheader written and the image packed,
    // which is what everything below `objcopy` does.
    if let Some(path) = flag(args, "--elf") {
        let elf = PathBuf::from(&path);
        if !elf.is_file() {
            return Err(format!("no ELF at {}", elf.display()));
        }
        let root = workspace_root();
        let sdk = find_sdk(&root)?;
        let board = env::var("BL616_BOARD").unwrap_or_else(|_| DEFAULT_BOARD.into());
        let name = elf
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "firmware".into());
        return post_process(&root, &sdk, &board, &elf, &name);
    }

    let example = flag(args, "--example").ok_or("missing --example <name> or --elf <path>")?;
    let release = !args.iter().any(|a| a == "--debug");
    let root = workspace_root();
    let sdk = find_sdk(&root)?;
    let board = env::var("BL616_BOARD").unwrap_or_else(|_| DEFAULT_BOARD.into());

    // 1. Rust + the C substrate.
    let mut cargo = Command::new(env::var("CARGO").unwrap_or_else(|_| "cargo".into()));
    cargo
        .current_dir(&root)
        .args(["build", "-p", "bl616-wifi", "--example", &example]);
    if release {
        cargo.arg("--release");
    }
    if let Some(features) = flag(args, "--features") {
        cargo.args(["--features", &features]);
    }
    cargo.env("BL_SDK_BASE", &sdk);
    run(&mut cargo, "build the example")?;

    let profile = if release { "release" } else { "debug" };
    let elf = root
        .join("target")
        .join(TARGET)
        .join(profile)
        .join("examples")
        .join(&example);
    if !elf.is_file() {
        return Err(format!("no ELF at {}", elf.display()));
    }

    // 2. ELF -> raw image.
    post_process(&root, &sdk, &board, &elf, &example)
}

/// Turn a linked ELF into a flashable image.
///
/// `objcopy` to a raw binary, then the vendor's `bflb_fw_post_proc` to write
/// the bootheader the boot ROM reads. Without that header the chip does not
/// start, which is why an application outside this workspace cannot simply
/// flash its own ELF.
fn post_process(
    root: &Path,
    sdk: &Path,
    board: &str,
    elf: &Path,
    name: &str,
) -> Result<Artifacts, String> {
    let dir = root.join("target/bl616").join(name);
    fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    let bin = dir.join(format!("{name}.bin"));
    run(
        Command::new("riscv64-unknown-elf-objcopy")
            .arg("-Obinary")
            .arg(elf)
            .arg(&bin),
        "convert the ELF to a raw image",
    )?;

    // 3. Bootheader, partition table, boot2, mfg, and the RF factory
    //    parameters appended to the image — without which rfparam_init fails
    //    and the PHY never comes up.
    let post_proc = sdk.join("tools/bflb_tools/bflb_fw_post_proc/bflb_fw_post_proc-ubuntu");
    if !post_proc.is_file() {
        return Err(format!("{} not found", post_proc.display()));
    }
    run(
        Command::new(&post_proc)
            .current_dir(&dir)
            .arg(format!("--chipname={DEFAULT_CHIP}"))
            .arg(format!("--imgfile={}", bin.display()))
            .arg("--appkeys=shared")
            .arg(format!(
                "--brdcfgdir={}",
                sdk.join("bsp/board").join(board).join("config").display()
            )),
        "post-process the flash image",
    )?;

    println!("\nimage:  {}", bin.display());
    println!("size:   {} bytes", fs::metadata(&bin).map(|m| m.len()).unwrap_or(0));
    Ok(Artifacts { firmware: bin, dir })
}

fn cmd_flash(args: &[String]) -> Result<(), String> {
    let artifacts = cmd_build(args)?;
    let root = workspace_root();
    let sdk = find_sdk(&root)?;

    let port = match flag(args, "--port").or_else(|| env::var("BL616_PORT").ok()) {
        Some(p) => p,
        None => guess_port()?,
    };
    let baud = flag(args, "--baud").unwrap_or_else(|| DEFAULT_BAUD.into());
    let erase = if args.iter().any(|a| a == "--erase-all") {
        2
    } else {
        1
    };

    // The tool takes a flash layout, not a list of files. Globs are absolute
    // so it does not matter where it is invoked from.
    let cfg = artifacts.dir.join("flash_prog_cfg.ini");
    let dir = artifacts.dir.display();
    let name = artifacts
        .firmware
        .file_name()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    fs::write(
        &cfg,
        format!(
            "\
[cfg]
erase = {erase}
skip_mode = 0x0, 0x0
boot2_isp_mode = 0

[boot2]
filedir = {dir}/boot2_*.bin
address = 0x000000

[partition]
filedir = {dir}/partition*.bin
address = 0xE000

[FW]
filedir = {dir}/{name}
address = @partition
"
        ),
    )
    .map_err(|e| format!("cannot write {}: {e}", cfg.display()))?;

    let flash_cmd = sdk.join("tools/bflb_tools/bouffalo_flash_cube/BLFlashCommand-ubuntu");
    if !flash_cmd.is_file() {
        return Err(format!("{} not found", flash_cmd.display()));
    }

    println!("\nflashing {port} at {baud} baud");
    println!("hold BOOT and tap RST first if the board is not already in the ROM bootloader");
    run(
        Command::new(&flash_cmd)
            .current_dir(&artifacts.dir)
            .arg("--interface=uart")
            .arg(format!("--baudrate={baud}"))
            .arg(format!("--port={port}"))
            .arg(format!("--chipname={DEFAULT_CHIP}"))
            .arg(format!("--config={}", cfg.display())),
        "flash the board",
    )?;

    println!("\ndone — tap RST to leave the bootloader and run the firmware");
    Ok(())
}

fn cmd_monitor(args: &[String]) -> Result<(), String> {
    let port = match flag(args, "--port").or_else(|| env::var("BL616_PORT").ok()) {
        Some(p) => p,
        None => guess_port()?,
    };
    let baud = flag(args, "--baud").unwrap_or_else(|| DEFAULT_BAUD.into());

    // Console output is on UART0 (GPIO 21 TX / 22 RX) unless the firmware was
    // built with the usb-console feature, in which case it is on the same
    // USB-C port used for flashing.
    for (tool, args) in [
        ("picocom", vec!["--baud".into(), baud.clone(), port.clone()]),
        ("screen", vec![port.clone(), baud.clone()]),
        ("cu", vec!["-l".into(), port.clone(), "-s".into(), baud.clone()]),
    ] {
        if which(tool).is_some() {
            println!("{tool} {}", args.join(" "));
            return run(Command::new(tool).args(&args), "run the terminal");
        }
    }

    Err(format!(
        "no terminal program found. Install picocom, or run:\n  \
         screen {port} {baud}"
    ))
}

fn cmd_setup() -> Result<(), String> {
    let home = env::var("HOME").map_err(|_| "HOME is not set")?;
    let prefix = PathBuf::from(&home).join(".local/opt/bouffalo-riscv-toolchain");
    let bindir = PathBuf::from(&home).join(".local/bin");

    if prefix.join("bin/riscv64-unknown-elf-gcc").is_file() {
        println!("toolchain already installed at {}", prefix.display());
    } else {
        println!("cloning the T-Head toolchain into {} (~1 GiB)", prefix.display());
        fs::create_dir_all(prefix.parent().unwrap())
            .map_err(|e| format!("cannot create {}: {e}", prefix.display()))?;
        run(
            Command::new("git")
                .args(["clone", "--depth", "1", TOOLCHAIN_REPO])
                .arg(&prefix),
            "clone the toolchain",
        )?;
        let _ = fs::remove_dir_all(prefix.join(".git"));
    }

    fs::create_dir_all(&bindir).map_err(|e| format!("cannot create {}: {e}", bindir.display()))?;
    for entry in fs::read_dir(prefix.join("bin"))
        .map_err(|e| format!("cannot read the toolchain bin directory: {e}"))?
        .flatten()
    {
        let name = entry.file_name();
        if name.to_string_lossy().starts_with("riscv64-unknown-elf-") {
            let link = bindir.join(&name);
            let _ = fs::remove_file(&link);
            std::os::unix::fs::symlink(entry.path(), &link)
                .map_err(|e| format!("cannot link {}: {e}", link.display()))?;
        }
    }
    println!("symlinked riscv64-unknown-elf-* into {}", bindir.display());

    let root = workspace_root();
    match find_sdk(&root) {
        Ok(sdk) => println!("BouffaloSDK: {}", sdk.display()),
        Err(_) => println!(
            "BouffaloSDK not found — clone it and set BL_SDK_BASE:\n  \
             git clone https://github.com/bouffalolab/bouffalo_sdk {}",
            root.join("vendor/bouffalo_sdk").display()
        ),
    }

    if which("riscv64-unknown-elf-gcc").is_none() {
        println!(
            "\nwarning: {} is not on PATH — add it to your shell profile",
            bindir.display()
        );
    }
    Ok(())
}

// ----------------------------------------------------------------- helpers

fn workspace_root() -> PathBuf {
    // xtask lives at <root>/xtask.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask has no parent directory")
        .to_path_buf()
}

fn find_sdk(root: &Path) -> Result<PathBuf, String> {
    let candidates: Vec<PathBuf> = env::var_os("BL_SDK_BASE")
        .map(PathBuf::from)
        .into_iter()
        .chain([root.join("vendor/bouffalo_sdk"), root.join("../bouffalo_sdk")])
        .collect();

    candidates
        .iter()
        .find(|c| c.join("project.build").is_file())
        .map(|c| fs::canonicalize(c).unwrap_or_else(|_| c.clone()))
        .ok_or_else(|| format!("BouffaloSDK not found; looked in {candidates:?}"))
}

/// A BL616 in its ROM bootloader shows up as a CDC device; an external
/// TTL-USB adapter shows up as ttyUSB.
fn guess_port() -> Result<String, String> {
    let mut found = Vec::new();
    for prefix in ["ttyACM", "ttyUSB"] {
        if let Ok(entries) = fs::read_dir("/dev") {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if name.starts_with(prefix) {
                    found.push(format!("/dev/{name}"));
                }
            }
        }
        if !found.is_empty() {
            found.sort();
            return Ok(found.remove(0));
        }
    }
    Err("no /dev/ttyACM* or /dev/ttyUSB* found — pass --port".into())
}

fn flag(args: &[String], name: &str) -> Option<String> {
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == name {
            return it.next().cloned();
        }
        if let Some(v) = a.strip_prefix(&format!("{name}=")) {
            return Some(v.to_string());
        }
    }
    None
}

fn which(tool: &str) -> Option<PathBuf> {
    env::var_os("PATH").and_then(|paths| {
        env::split_paths(&paths)
            .map(|d| d.join(tool))
            .find(|p| p.is_file())
    })
}

fn run(cmd: &mut Command, what: &str) -> Result<(), String> {
    let status = cmd
        .status()
        .map_err(|e| format!("cannot run {:?} to {what}: {e}", cmd.get_program()))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("failed to {what} ({status})"))
    }
}
