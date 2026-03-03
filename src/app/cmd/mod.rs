use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub mod client;
pub mod server;

pub(crate) type BoxError = Box<dyn std::error::Error + Send + Sync>;

pub(crate) fn resolve_config_path(explicit: Option<PathBuf>) -> io::Result<PathBuf> {
    if let Some(path) = explicit {
        return Ok(path);
    }

    let mut candidates = vec![
        PathBuf::from("./config.yaml"),
        PathBuf::from("./config.yml"),
    ];

    if let Some(home) = std::env::var_os("HOME") {
        candidates.push(PathBuf::from(home).join(".rysteria/config.yaml"));
    }
    candidates.push(PathBuf::from("/etc/rysteria/config.yaml"));

    for path in candidates {
        if path.exists() {
            return Ok(path);
        }
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "no config file found (checked ./config.yaml, ./config.yml, $HOME/.rysteria/config.yaml, /etc/rysteria/config.yaml)",
    ))
}

pub(crate) fn read_config_file(path: &Path) -> io::Result<String> {
    fs::read_to_string(path)
}

pub(crate) fn parse_bandwidth_bps(input: &str) -> Result<u64, String> {
    let s = input.trim();
    if s.is_empty() {
        return Err("invalid bandwidth format".to_string());
    }

    let lower = s.to_ascii_lowercase();
    let mut split = 0usize;
    for (idx, ch) in lower.char_indices() {
        if !ch.is_ascii_digit() {
            split = idx;
            break;
        }
    }
    // Go StringToBps behavior: pure digits or missing numeric prefix are invalid.
    if split == 0 {
        return Err("invalid bandwidth format".to_string());
    }

    let value: u64 = lower[..split]
        .parse()
        .map_err(|_| "invalid bandwidth value".to_string())?;
    let unit = lower[split..].trim();

    let mul_bits: u64 = match unit {
        "b" | "bps" => 1,
        "k" | "kb" | "kbps" => 1_000,
        "m" | "mb" | "mbps" => 1_000_000,
        "g" | "gb" | "gbps" => 1_000_000_000,
        "t" | "tb" | "tbps" => 1_000_000_000_000,
        _ => return Err(format!("unsupported bandwidth unit: {unit}")),
    };

    let bits = value
        .checked_mul(mul_bits)
        .ok_or_else(|| "bandwidth value overflow".to_string())?;
    Ok(bits / 8)
}

#[cfg(test)]
mod tests {
    use super::parse_bandwidth_bps;

    #[test]
    fn parse_bandwidth_matches_go_string_to_bps_rules() {
        let cases = [
            ("800 bps", Some(100)),
            ("800 kbps", Some(100_000)),
            ("800 mbps", Some(100_000_000)),
            ("800 gbps", Some(100_000_000_000)),
            ("800 tbps", Some(100_000_000_000_000)),
            ("100m", Some(12_500_000)),
            ("2G", Some(250_000_000)),
            ("100mbps", Some(12_500_000)),
            ("damn", None),
            ("6444", None),
            ("5.4 mbps", None),
            ("kbps", None),
            ("1234 5678 gbps", None),
            ("", None),
        ];

        for (input, want) in cases {
            let got = parse_bandwidth_bps(input);
            match want {
                Some(v) => assert_eq!(got.unwrap(), v, "input={input}"),
                None => assert!(got.is_err(), "input={input}, got={got:?}"),
            }
        }
    }
}
