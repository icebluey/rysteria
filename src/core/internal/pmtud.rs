/// Path MTU Discovery availability flag.
///
/// Go equivalent: hysteria/core/internal/pmtud/avail.go (Linux/Windows/macOS = false)
///               hysteria/core/internal/pmtud/unavail.go (others = true)
///
/// Returns `false` (PMTUD enabled) on platforms that support it,
/// `true` (PMTUD disabled) on unsupported platforms.
#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
pub const DISABLE_PATH_MTU_DISCOVERY: bool = false;

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
pub const DISABLE_PATH_MTU_DISCOVERY: bool = true;
