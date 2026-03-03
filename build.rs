fn main() {
    println!("cargo:rerun-if-env-changed=TARGET");
    println!("cargo:rerun-if-env-changed=RUSTFLAGS");
    println!("cargo:rerun-if-env-changed=CARGO_ENCODED_RUSTFLAGS");

    let git_hash = std::env::var("GIT_HASH")
        .ok()
        .or_else(git_hash_from_cmd)
        .unwrap_or_else(|| "unknown".to_string());
    let build_timestamp = build_timestamp();
    let toolchain = std::env::var("RUSTC_VERSION")
        .ok()
        .or_else(rustc_version_from_cmd)
        .map(|v| normalize_toolchain(&v))
        .unwrap_or_else(|| "rustc unknown".to_string());
    let target = std::env::var("TARGET").unwrap_or_else(|_| "unknown-target".to_string());
    let profile = std::env::var("PROFILE").unwrap_or_else(|_| "unknown".to_string());
    let (platform, architecture) = parse_target(&target);
    let target_cpu = detect_target_cpu(&target);
    let lock_contents = read_lockfile();
    let quinn_ver = package_version(lock_contents.as_deref(), "quinn");
    let h3_quinn_ver = package_version(lock_contents.as_deref(), "h3-quinn");
    let h3_ver = package_version(lock_contents.as_deref(), "h3");
    let tokio_ver = package_version(lock_contents.as_deref(), "tokio");

    // Embed build-time version information
    println!("cargo:rustc-env=BUILD_GIT_HASH={}", git_hash);
    println!("cargo:rustc-env=BUILD_TIMESTAMP={}", build_timestamp);
    println!(
        "cargo:rustc-env=BUILD_TOOLCHAIN={} {}/{}",
        toolchain, platform, architecture
    );
    println!("cargo:rustc-env=BUILD_PROFILE={}", profile);
    println!("cargo:rustc-env=BUILD_PLATFORM={platform}");
    println!("cargo:rustc-env=BUILD_ARCH={architecture}");
    println!("cargo:rustc-env=BUILD_TARGET_CPU={target_cpu}");
    println!(
        "cargo:rustc-env=BUILD_LIB_QUINN={}",
        quinn_ver.unwrap_or_else(|| "unknown".to_string())
    );
    println!(
        "cargo:rustc-env=BUILD_LIB_H3_QUINN={}",
        h3_quinn_ver.unwrap_or_else(|| "unknown".to_string())
    );
    println!(
        "cargo:rustc-env=BUILD_LIB_H3={}",
        h3_ver.unwrap_or_else(|| "unknown".to_string())
    );
    println!(
        "cargo:rustc-env=BUILD_LIB_TOKIO={}",
        tokio_ver.unwrap_or_else(|| "unknown".to_string())
    );
}

fn build_timestamp() -> String {
    if let Ok(epoch) = std::env::var("SOURCE_DATE_EPOCH") {
        let epoch = epoch.trim();
        if !epoch.is_empty()
            && epoch != "0"
            && let Some(ts) = rfc3339_from_epoch(epoch)
        {
            return ts;
        }
    }
    rfc3339_now_from_cmd().unwrap_or_else(|| "unknown".to_string())
}

fn rfc3339_from_epoch(epoch: &str) -> Option<String> {
    let output = std::process::Command::new("date")
        .args(["-u", "-d", &format!("@{epoch}"), "+%Y-%m-%dT%H:%M:%SZ"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let ts = String::from_utf8(output.stdout).ok()?.trim().to_string();
    if ts.is_empty() { None } else { Some(ts) }
}

fn rfc3339_now_from_cmd() -> Option<String> {
    let output = std::process::Command::new("date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let ts = String::from_utf8(output.stdout).ok()?.trim().to_string();
    if ts.is_empty() { None } else { Some(ts) }
}

fn read_lockfile() -> Option<String> {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").ok()?;
    let lock_path = std::path::Path::new(&manifest_dir).join("Cargo.lock");
    std::fs::read_to_string(lock_path).ok()
}

fn package_version(lock_contents: Option<&str>, package: &str) -> Option<String> {
    let lock_contents = lock_contents?;
    let mut current_name: Option<String> = None;

    for line in lock_contents.lines() {
        let trimmed = line.trim();
        if trimmed == "[[package]]" {
            current_name = None;
            continue;
        }

        if let Some(name) = parse_toml_string(trimmed, "name") {
            current_name = Some(name);
            continue;
        }

        if let Some(version) = parse_toml_string(trimmed, "version") {
            if current_name.as_deref() == Some(package) {
                return Some(version);
            }
        }
    }
    None
}

fn parse_toml_string(line: &str, key: &str) -> Option<String> {
    let prefix = format!("{key} = \"");
    if !line.starts_with(&prefix) {
        return None;
    }
    let rest = &line[prefix.len()..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn parse_target(target: &str) -> (String, String) {
    let mut parts = target.split('-');
    let arch = parts.next().unwrap_or("unknown");
    let mut platform = "unknown";
    for p in parts {
        if matches!(
            p,
            "linux" | "windows" | "darwin" | "android" | "freebsd" | "netbsd" | "openbsd"
        ) {
            platform = p;
            break;
        }
    }
    (platform.to_string(), arch.to_string())
}

fn normalize_toolchain(value: &str) -> String {
    let mut it = value.split_whitespace();
    match (it.next(), it.next()) {
        (Some(name), Some(ver)) => format!("{name} {ver}"),
        _ => value.trim().to_string(),
    }
}

fn git_hash_from_cmd() -> Option<String> {
    let output = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let hash = String::from_utf8(output.stdout).ok()?.trim().to_string();
    if hash.is_empty() { None } else { Some(hash) }
}

fn rustc_version_from_cmd() -> Option<String> {
    let output = std::process::Command::new("rustc")
        .arg("--version")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let version = String::from_utf8(output.stdout).ok()?.trim().to_string();
    if version.is_empty() {
        None
    } else {
        Some(version)
    }
}

fn detect_target_cpu(target: &str) -> String {
    target_cpu_from_encoded_rustflags()
        .or_else(target_cpu_from_rustflags)
        .or_else(|| rustc_default_target_cpu(target))
        .unwrap_or_else(|| "unknown".to_string())
}

fn target_cpu_from_encoded_rustflags() -> Option<String> {
    let flags = std::env::var("CARGO_ENCODED_RUSTFLAGS").ok()?;
    let args: Vec<String> = flags
        .split('\u{1f}')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect();
    find_target_cpu_in_args(&args)
}

fn target_cpu_from_rustflags() -> Option<String> {
    let flags = std::env::var("RUSTFLAGS").ok()?;
    let args: Vec<String> = flags
        .split_whitespace()
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect();
    find_target_cpu_in_args(&args)
}

fn find_target_cpu_in_args(args: &[String]) -> Option<String> {
    let mut detected: Option<String> = None;
    let mut i = 0usize;
    while i < args.len() {
        let arg = args[i].as_str();
        if let Some(v) = arg.strip_prefix("-Ctarget-cpu=") {
            if !v.is_empty() {
                detected = Some(v.to_string());
            }
            i += 1;
            continue;
        }
        if arg == "-Ctarget-cpu" {
            if let Some(v) = args.get(i + 1) {
                if !v.is_empty() {
                    detected = Some(v.to_string());
                }
            }
            i += 2;
            continue;
        }
        if arg == "-C" {
            if let Some(next) = args.get(i + 1) {
                if let Some(v) = next.strip_prefix("target-cpu=") {
                    if !v.is_empty() {
                        detected = Some(v.to_string());
                    }
                } else if next == "target-cpu" {
                    if let Some(v) = args.get(i + 2) {
                        if !v.is_empty() {
                            detected = Some(v.to_string());
                        }
                    }
                    i += 3;
                    continue;
                }
            }
            i += 2;
            continue;
        }
        i += 1;
    }
    detected
}

fn rustc_default_target_cpu(target: &str) -> Option<String> {
    let output = std::process::Command::new("rustc")
        .args(["--print", "target-cpus", "--target", target])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8(output.stdout).ok()?;
    for line in stdout.lines() {
        if line.contains("This is the default target CPU for the current build target") {
            let name = line.split_whitespace().next()?.trim();
            if !name.is_empty() {
                return Some(name.to_string());
            }
        }
    }
    None
}
