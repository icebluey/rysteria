pub const SPEEDTEST_DEST: &str = "@speedtest";

pub fn is_speedtest_destination(addr: &str) -> bool {
    let host = addr.rsplit_once(':').map(|(h, _)| h).unwrap_or(addr);
    host.eq_ignore_ascii_case(SPEEDTEST_DEST)
}
