#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import os
import shutil
import subprocess
import sys

# Hyperbole is the official build script for Rysteria.
# Environment variables:
#   RY_APP_PLATFORMS: comma-separated os/arch pairs to build
#                     (e.g. "linux/amd64,windows/amd64-avx")
#                     Overrides platforms.txt when set.

DESC = "Hyperbole is the official build script for Rysteria."
BUILD_DIR = "build"
BINARY_NAME = "rysteria"

# Maps (os, arch) -> (rust_target_triple, extra_env)
#
# Linux has two variants:
#   linux/<arch>       — glibc (gnu), native-friendly, for development
#   linux/<arch>-musl  — musl, fully static, for distribution/release
# Platforms without a stable musl tier (s390x, riscv64, loong64) have gnu only.
#
# Cross-compilation notes:
#   - linux/*  : supported via `cross` on any host
#   - windows/*: supported via `cargo xwin` on Linux/macOS (MSVC toolchain)
#   - darwin/*  : requires macOS host (no redistributable SDK for cross)
#   - freebsd/*: supported via `cross` on Linux
#   - android/*: supported via `cross` (NDK bundled in cross images)
PLATFORM_MAP = {
    # Windows (MSVC toolchain — requires cargo-xwin for cross-compilation)
    ("windows", "amd64"):         ("x86_64-pc-windows-msvc",         {}),
    ("windows", "amd64-avx"):     ("x86_64-pc-windows-msvc",         {"RUSTFLAGS": "-C target-cpu=x86-64-v3"}),
    ("windows", "386"):           ("i686-pc-windows-msvc",            {}),
    ("windows", "arm64"):         ("aarch64-pc-windows-msvc",         {}),
    # macOS (requires macOS host or osxcross)
    ("darwin",  "amd64"):         ("x86_64-apple-darwin",            {}),
    ("darwin",  "amd64-avx"):     ("x86_64-apple-darwin",            {"RUSTFLAGS": "-C target-cpu=x86-64-v3"}),
    ("darwin",  "arm64"):         ("aarch64-apple-darwin",            {}),
    # Linux — gnu (glibc, native-friendly)
    ("linux",   "amd64"):         ("x86_64-unknown-linux-gnu",       {}),
    ("linux",   "amd64-avx"):     ("x86_64-unknown-linux-gnu",       {"RUSTFLAGS": "-C target-cpu=x86-64-v3"}),
    ("linux",   "386"):           ("i686-unknown-linux-gnu",          {}),
    ("linux",   "arm64"):         ("aarch64-unknown-linux-gnu",       {}),
    ("linux",   "armv7"):         ("armv7-unknown-linux-gnueabihf",   {}),
    ("linux",   "armv6"):         ("arm-unknown-linux-gnueabihf",     {}),
    ("linux",   "armv5"):         ("arm-unknown-linux-gnueabi",       {}),
    ("linux",   "s390x"):         ("s390x-unknown-linux-gnu",         {}),
    ("linux",   "mipsle"):        ("mipsel-unknown-linux-gnu",        {}),
    ("linux",   "riscv64"):       ("riscv64gc-unknown-linux-gnu",     {}),
    ("linux",   "loong64"):       ("loongarch64-unknown-linux-gnu",   {}),
    # Linux — musl (static, for distribution/release)
    ("linux",   "amd64-musl"):     ("x86_64-unknown-linux-musl",     {}),
    ("linux",   "amd64-avx-musl"): ("x86_64-unknown-linux-musl",     {"RUSTFLAGS": "-C target-cpu=x86-64-v3"}),
    ("linux",   "386-musl"):       ("i686-unknown-linux-musl",        {}),
    ("linux",   "arm64-musl"):     ("aarch64-unknown-linux-musl",     {}),
    ("linux",   "armv7-musl"):     ("armv7-unknown-linux-musleabihf", {}),
    ("linux",   "armv6-musl"):     ("arm-unknown-linux-musleabihf",   {}),
    ("linux",   "armv5-musl"):     ("arm-unknown-linux-musleabi",     {}),
    ("linux",   "mipsle-musl"):    ("mipsel-unknown-linux-musl",      {}),
    # Note: s390x / riscv64 / loong64 have no stable musl target
    # Android
    ("android", "arm64"):     ("aarch64-linux-android",           {}),
    ("android", "armv7"):     ("armv7-linux-androideabi",         {}),
    ("android", "386"):       ("i686-linux-android",              {}),
    ("android", "amd64"):     ("x86_64-linux-android",            {}),
    # FreeBSD
    ("freebsd", "amd64"):     ("x86_64-unknown-freebsd",          {}),
    ("freebsd", "amd64-avx"): ("x86_64-unknown-freebsd",          {"RUSTFLAGS": "-C target-cpu=x86-64-v3"}),
    ("freebsd", "arm64"):     ("aarch64-unknown-freebsd",          {}),
}


def check_command(args):
    try:
        subprocess.check_call(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except Exception:
        return False


def check_build_env():
    if not check_command(["git", "--version"]):
        print("Git is not installed.")
        return False
    if not check_command(["git", "rev-parse", "--is-inside-work-tree"]):
        print("Not inside a Git repository. Please run from the project root.")
        return False
    if not check_command(["cargo", "--version"]):
        print("Cargo is not installed. Please install Rust.")
        return False
    return True


def get_host_target():
    """Return the host Rust target triple, e.g. x86_64-unknown-linux-gnu."""
    try:
        output = subprocess.check_output(
            ["rustc", "-vV"], stderr=subprocess.DEVNULL
        ).decode()
        for line in output.splitlines():
            if line.startswith("host:"):
                return line.split(":", 1)[1].strip()
    except Exception:
        pass
    return None


def cargo_cmd_for(target_triple):
    """
    Return a command prefix list for building the given target triple.
      - Native target        -> ["cargo"]
      - *-windows-msvc       -> ["cargo", "xwin"]  (requires cargo-xwin)
      - everything else      -> ["cross"]           (requires cross)
    """
    host = get_host_target()
    if host and host == target_triple:
        return ["cargo"]
    if "windows-msvc" in target_triple:
        if check_command(["cargo", "xwin", "--version"]):
            return ["cargo", "xwin"]
        print(
            f"  Warning: MSVC target {target_triple} requires 'cargo-xwin'.\n"
            "           Install it with: cargo install cargo-xwin"
        )
        return ["cargo"]
    # darwin targets cross-compile natively via Apple's toolchain; cross is not needed.
    if "apple-darwin" in target_triple:
        return ["cargo"]
    # Linux targets: use cargo-zigbuild (zig as C cross-compiler, no Docker, no glibc issues).
    if "linux" in target_triple:
        if check_command(["cargo", "zigbuild", "--version"]):
            return ["cargo", "zigbuild"]
        print(
            f"  Warning: cross-compiling to {target_triple} requires 'cargo-zigbuild'.\n"
            "           Install it with: cargo install cargo-zigbuild"
        )
        return ["cargo"]
    # Android, FreeBSD, etc.: use cross (Docker-based).
    if check_command(["cross", "--version"]):
        return ["cross"]
    print(
        f"  Warning: cross-compiling to {target_triple} requires 'cross'.\n"
        "           Install it with: cargo install cross --git https://github.com/cross-rs/cross"
    )
    return ["cargo"]



def load_platforms_txt():
    """Parse platforms.txt and return a list of (os, arch) tuples."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(script_dir, "platforms.txt")
    result = []
    try:
        with open(path) as f:
            for line in f:
                line = line.split("#", 1)[0].strip()
                if not line:
                    continue
                parts = line.split("/")
                if len(parts) == 2:
                    result.append((parts[0].strip(), parts[1].strip()))
    except FileNotFoundError:
        print(f"Warning: platforms.txt not found at {path}")
    return result


def get_build_platforms():
    """
    Platform resolution order:
      1. RY_APP_PLATFORMS=all  -> load platforms.txt
      2. RY_APP_PLATFORMS=<comma-separated os/arch pairs>
      3. Native host default (with preferred arch variant)
    """
    env_val = os.environ.get("RY_APP_PLATFORMS", "").strip()
    if env_val == "all":
        return load_platforms_txt()
    if env_val:
        result = []
        for item in env_val.split(","):
            item = item.strip()
            if not item:
                continue
            parts = item.split("/")
            if len(parts) == 2:
                result.append((parts[0], parts[1]))
        return result

    # Default: native host, with preferred arch variants per host triple.
    # e.g. x86_64-unknown-linux-gnu defaults to amd64-avx rather than plain amd64.
    NATIVE_PREFERRED = {
        "x86_64-unknown-linux-gnu":  ("linux",   "amd64-avx"),
        "x86_64-pc-windows-msvc":    ("windows", "amd64-avx"),
    }
    host = get_host_target()
    if host:
        if host in NATIVE_PREFERRED:
            return [NATIVE_PREFERRED[host]]
        for (os_name, arch), (triple, _) in PLATFORM_MAP.items():
            if triple == host:
                return [(os_name, arch)]
    return [("linux", "amd64-avx")]


def output_name(os_name, arch):
    name = f"{BINARY_NAME}-{os_name}-{arch}"
    if os_name == "windows":
        name += ".exe"
    return name


def remap_path_flags():
    """
    Return RUSTFLAGS entries that strip the build machine's absolute path prefix
    from the Rust parts of the binary.  Rust embeds source paths in panic messages
    via the file!() macro; --remap-path-prefix rewrites them at compile time.

    A single remap of "{project_root}/" -> "" handles all embedded paths uniformly:
      src/foo.rs               (project source)
      .cargo/registry/src/...  (dependency source)
    """
    project_root = os.path.dirname(os.path.abspath(__file__))
    return [f"--remap-path-prefix={project_root}/="]


def strip_build_paths_from_binary(binary_path, project_root):
    """
    Remove build-machine absolute paths from embedded C string literals in-place.

    C dependencies (e.g. aws-lc-sys / BoringSSL) use __FILE__ in assertions,
    which embeds full source paths as null-terminated strings in .rdata/.rodata.
    --remap-path-prefix only covers rustc; the C compiler (clang-cl in MSVC mode)
    ignores CFLAGS/-ffile-prefix-map in cross-compilation setups.

    We patch the binary directly: for each embedded absolute path we find the
    null terminator, shift the relative portion to start at the same pointer
    address, and zero-fill the vacated bytes.  The pointer itself is unchanged,
    so no relocation or section-size adjustment is needed.

    Example (prefix = '/home/user/proj/', prefix_len = 16):
      before: /home/user/proj/.cargo/registry/src/foo.c NUL
      after:  .cargo/registry/src/foo.c NUL [16 zero bytes] NUL
    """
    prefix = (project_root.rstrip("/") + "/").encode("utf-8")
    prefix_len = len(prefix)

    with open(binary_path, "rb") as f:
        data = bytearray(f.read())

    count = 0
    i = 0
    n = len(data)
    while i < n - prefix_len:
        if data[i : i + prefix_len] == prefix:
            # Find the null terminator of this C string.
            j = i + prefix_len
            while j < n and data[j] != 0:
                j += 1
            # Shift the relative portion to start at i, zero-fill the gap.
            rel_start = i + prefix_len
            rel_len = j - rel_start
            if rel_len > 0:
                data[i : i + rel_len] = data[rel_start:j]
            data[i + rel_len : i + rel_len + prefix_len] = b"\x00" * prefix_len
            count += 1
            i += rel_len + 1
        else:
            i += 1

    if count > 0:
        with open(binary_path, "wb") as f:
            f.write(data)
        print(f"  Patched {count} embedded path(s)")


def cmd_build(release=True, os_filter=None):
    if not check_build_env():
        return

    os.makedirs(BUILD_DIR, exist_ok=True)

    platforms = get_build_platforms()
    if os_filter:
        allowed = {s.strip() for s in os_filter.split(",")}
        platforms = [(o, a) for o, a in platforms if o in allowed]
    if not platforms:
        print("No platforms to build.")
        return

    profile_dir = "release" if release else "debug"
    failed = []

    for os_name, arch in platforms:
        key = (os_name, arch)
        if key not in PLATFORM_MAP:
            print(f"Unknown platform: {os_name}/{arch} — skipping")
            continue

        target_triple, extra_env = PLATFORM_MAP[key]
        tool = cargo_cmd_for(target_triple)

        print(f"Building {os_name}/{arch} ({target_triple})...")

        cmd = tool + ["build", "--target", target_triple]
        if release:
            cmd.append("--release")

        env = os.environ.copy()
        for k, v in extra_env.items():
            if k == "RUSTFLAGS" and k in env and env[k]:
                env[k] = env[k] + " " + v
            else:
                env[k] = v

        # Strip build machine paths from Rust source paths in release binaries.
        # Applied after extra_env so per-platform RUSTFLAGS are already merged.
        # C/C++ paths (aws-lc-sys) are handled by strip_build_paths_from_binary()
        # after the build, because -ffile-prefix-map is not reliably forwarded to
        # clang-cl by cargo-xwin in MSVC cross-compilation mode.
        if release:
            remap_rust = " ".join(remap_path_flags())
            if env.get("RUSTFLAGS"):
                env["RUSTFLAGS"] = env["RUSTFLAGS"] + " " + remap_rust
            else:
                env["RUSTFLAGS"] = remap_rust

        try:
            subprocess.check_call(cmd, env=env)
        except subprocess.CalledProcessError:
            print(f"  FAILED: {os_name}/{arch}")
            failed.append(f"{os_name}/{arch}")
            continue

        ext = ".exe" if os_name == "windows" else ""
        src = os.path.join("target", target_triple, profile_dir, BINARY_NAME + ext)
        dst = os.path.join(BUILD_DIR, output_name(os_name, arch))

        try:
            shutil.copy2(src, dst)
        except FileNotFoundError:
            print(f"  Warning: binary not found at {src}")
            failed.append(f"{os_name}/{arch}")
            continue

        if release:
            project_root = os.path.dirname(os.path.abspath(__file__))
            strip_build_paths_from_binary(dst, project_root)

        size_kb = os.path.getsize(dst) // 1024
        print(f"  -> {dst} ({size_kb} KB)")

    if failed:
        print(f"\nFailed builds: {', '.join(failed)}")
        sys.exit(1)
    else:
        print("\nAll builds succeeded.")


def cmd_test():
    if not check_build_env():
        return
    try:
        subprocess.check_call(["cargo", "test"])
    except subprocess.CalledProcessError:
        print("Tests failed.")
        sys.exit(1)


def cmd_format():
    if not check_command(["rustfmt", "--version"]):
        print("rustfmt is not installed.")
        return
    try:
        subprocess.check_call(["cargo", "fmt"])
        print("Done.")
    except subprocess.CalledProcessError:
        print("Failed to format code.")


def cmd_clean():
    if os.path.exists(BUILD_DIR):
        shutil.rmtree(BUILD_DIR)
        print(f"Removed {BUILD_DIR}/")
    try:
        subprocess.check_call(["cargo", "clean"])
        print("Cargo build cache cleaned.")
    except subprocess.CalledProcessError:
        pass


def cmd_about():
    print(DESC)
    print()

    host = get_host_target()
    print(f"Host target : {host or 'unknown'}")

    cross_ok = check_command(["cross", "--version"])
    print(f"cross       : {'available' if cross_ok else 'not found (needed for cross-compilation)'}")
    print()

    print("Supported platforms:")
    col = max(len(f"{o}/{a}") for o, a in PLATFORM_MAP) + 2
    for (os_name, arch), (triple, extra) in sorted(PLATFORM_MAP.items()):
        label = f"{os_name}/{arch}"
        suffix = ""
        if extra.get("RUSTFLAGS"):
            suffix = f"  RUSTFLAGS={extra['RUSTFLAGS']}"
        print(f"  {label:<{col}} {triple}{suffix}")


def main():
    parser = argparse.ArgumentParser(description=DESC)
    p_cmd = parser.add_subparsers(dest="command")
    p_cmd.required = True

    # build
    p_build = p_cmd.add_parser("build", help="Build the binary for target platforms")
    p_build.add_argument(
        "--dev", action="store_true",
        help="Build debug (non-release) version"
    )
    p_build.add_argument(
        "--os", dest="os_filter", default=None,
        metavar="OS[,OS...]",
        help="Comma-separated OS names to build (e.g. linux,windows,darwin). "
             "Filters the platform list after RY_APP_PLATFORMS resolution."
    )

    # test
    p_cmd.add_parser("test", help="Run cargo test")

    # format
    p_cmd.add_parser("format", help="Format code with cargo fmt")

    # clean
    p_cmd.add_parser("clean", help="Remove build/ and cargo build cache")

    # about
    p_cmd.add_parser("about", help="Show tool and platform information")

    args = parser.parse_args()

    if args.command == "build":
        cmd_build(release=not args.dev, os_filter=args.os_filter)
    elif args.command == "test":
        cmd_test()
    elif args.command == "format":
        cmd_format()
    elif args.command == "clean":
        cmd_clean()
    elif args.command == "about":
        cmd_about()


if __name__ == "__main__":
    main()
