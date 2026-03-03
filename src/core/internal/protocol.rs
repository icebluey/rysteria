/// Wire-level protocol implementation for Hysteria 2.
///
/// All formats are byte-for-byte compatible with Go Hysteria 2.
/// References: hysteria/core/internal/protocol/
use crate::core::errors::ProtocolError;
use rand::RngExt;

// ──────────────────────────────────────────────────────────────────────────────
// Protocol constants (must match Go exactly)
// ──────────────────────────────────────────────────────────────────────────────

/// Custom HTTP/3 frame type used for TCP proxy streams.
pub const FRAME_TYPE_TCP_REQUEST: u64 = 0x401;

/// Maximum length of an address string ("host:port").
pub const MAX_ADDRESS_LENGTH: u64 = 2048;
/// Maximum length of a message string in TCP response.
pub const MAX_MESSAGE_LENGTH: u64 = 2048;
/// Maximum length of padding bytes.
pub const MAX_PADDING_LENGTH: u64 = 4096;
/// Maximum QUIC datagram payload size (bytes).
pub const MAX_DATAGRAM_FRAME_SIZE: u64 = 1200;
/// Maximum UDP datagram size.
pub const MAX_UDP_SIZE: usize = 4096;

/// Default per-stream receive window (8 MiB).
/// Go: `DefaultStreamReceiveWindow = 8 * 1024 * 1024`
pub const DEFAULT_STREAM_RECEIVE_WINDOW: u64 = 8 * 1024 * 1024;
/// Default connection-level receive window (20 MiB = 8 MiB × 5/2).
/// Go: `DefaultConnReceiveWindow = DefaultStreamReceiveWindow * 5 / 2`
pub const DEFAULT_CONN_RECEIVE_WINDOW: u64 = DEFAULT_STREAM_RECEIVE_WINDOW * 5 / 2;

/// HTTP/3 auth endpoint host (wire-level; must NOT be changed to "rysteria").
pub const URL_HOST: &str = "hysteria";
/// HTTP/3 auth endpoint path.
pub const URL_PATH: &str = "/auth";
/// HTTP status code for successful authentication.
pub const STATUS_AUTH_OK: u16 = 233;

/// Auth header sent by client.
pub const HEADER_AUTH: &str = "Hysteria-Auth";
/// UDP-enabled header sent by server in auth response.
pub const HEADER_UDP_ENABLED: &str = "Hysteria-UDP";
/// CC receive-rate header (both directions).
pub const HEADER_CC_RX: &str = "Hysteria-CC-RX";
/// Anti-replay padding header.
pub const HEADER_PADDING: &str = "Hysteria-Padding";

/// Alphanumeric characters used for random padding.
pub const PADDING_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

// Padding ranges [min, max) — half-open intervals matching Go.
const AUTH_REQ_PADDING_MIN: usize = 256;
const AUTH_REQ_PADDING_MAX: usize = 2048;
const AUTH_RESP_PADDING_MIN: usize = 256;
const AUTH_RESP_PADDING_MAX: usize = 2048;
const TCP_REQ_PADDING_MIN: usize = 64;
const TCP_REQ_PADDING_MAX: usize = 512;
const TCP_RESP_PADDING_MIN: usize = 128;
const TCP_RESP_PADDING_MAX: usize = 1024;

// RFC 9000 Section 16 varint boundaries
const MAX_VARINT_1: u64 = 63;
const MAX_VARINT_2: u64 = 16_383;
const MAX_VARINT_4: u64 = 1_073_741_823;
const MAX_VARINT_8: u64 = 4_611_686_018_427_387_903;

// ──────────────────────────────────────────────────────────────────────────────
// QUIC Varint (RFC 9000 Section 16)
// ──────────────────────────────────────────────────────────────────────────────

/// Returns the number of bytes needed to encode `v` as a QUIC varint.
pub fn varint_len(v: u64) -> usize {
    if v <= MAX_VARINT_1 {
        1
    } else if v <= MAX_VARINT_2 {
        2
    } else if v <= MAX_VARINT_4 {
        4
    } else {
        8
    }
}

/// Encodes `v` as a QUIC varint, writing into `buf`. Returns bytes written.
/// Panics if `buf` is too small or `v` exceeds the 62-bit maximum.
pub fn varint_put(buf: &mut [u8], v: u64) -> usize {
    if v <= MAX_VARINT_1 {
        buf[0] = v as u8;
        1
    } else if v <= MAX_VARINT_2 {
        buf[0] = (v >> 8) as u8 | 0x40;
        buf[1] = v as u8;
        2
    } else if v <= MAX_VARINT_4 {
        buf[0] = (v >> 24) as u8 | 0x80;
        buf[1] = (v >> 16) as u8;
        buf[2] = (v >> 8) as u8;
        buf[3] = v as u8;
        4
    } else if v <= MAX_VARINT_8 {
        buf[0] = (v >> 56) as u8 | 0xc0;
        buf[1] = (v >> 48) as u8;
        buf[2] = (v >> 40) as u8;
        buf[3] = (v >> 32) as u8;
        buf[4] = (v >> 24) as u8;
        buf[5] = (v >> 16) as u8;
        buf[6] = (v >> 8) as u8;
        buf[7] = v as u8;
        8
    } else {
        panic!("{:#x} does not fit in 62 bits", v);
    }
}

/// Appends a QUIC varint to a `Vec<u8>`.
pub fn varint_append(buf: &mut Vec<u8>, v: u64) {
    let len = varint_len(v);
    let start = buf.len();
    buf.resize(start + len, 0);
    varint_put(&mut buf[start..], v);
}

/// Reads a QUIC varint from the front of `buf`.
///
/// Returns `(value, bytes_consumed)` on success.
pub fn varint_read(buf: &[u8]) -> Result<(u64, usize), ProtocolError> {
    if buf.is_empty() {
        return Err(ProtocolError::InsufficientData);
    }
    let tag = buf[0] >> 6;
    match tag {
        0 => Ok((buf[0] as u64, 1)),
        1 => {
            if buf.len() < 2 {
                return Err(ProtocolError::InsufficientData);
            }
            let v = ((buf[0] as u64 & 0x3f) << 8) | buf[1] as u64;
            Ok((v, 2))
        }
        2 => {
            if buf.len() < 4 {
                return Err(ProtocolError::InsufficientData);
            }
            let v = ((buf[0] as u64 & 0x3f) << 24)
                | ((buf[1] as u64) << 16)
                | ((buf[2] as u64) << 8)
                | buf[3] as u64;
            Ok((v, 4))
        }
        3 => {
            if buf.len() < 8 {
                return Err(ProtocolError::InsufficientData);
            }
            let v = ((buf[0] as u64 & 0x3f) << 56)
                | ((buf[1] as u64) << 48)
                | ((buf[2] as u64) << 40)
                | ((buf[3] as u64) << 32)
                | ((buf[4] as u64) << 24)
                | ((buf[5] as u64) << 16)
                | ((buf[6] as u64) << 8)
                | buf[7] as u64;
            Ok((v, 8))
        }
        _ => unreachable!(),
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Padding generation
// ──────────────────────────────────────────────────────────────────────────────

/// Generates a random alphanumeric padding string of length in `[min, max)`.
///
/// Matches Go: `padding.String()` using `math/rand`.
pub fn gen_padding(min: usize, max: usize) -> Vec<u8> {
    let mut rng = rand::rng();
    let n = rng.random_range(min..max);
    (0..n)
        .map(|_| PADDING_CHARS[rng.random_range(0..PADDING_CHARS.len())])
        .collect()
}

/// Padding for HTTP/3 auth request: [256, 2048)
pub fn auth_request_padding() -> Vec<u8> {
    gen_padding(AUTH_REQ_PADDING_MIN, AUTH_REQ_PADDING_MAX)
}

/// Padding for HTTP/3 auth response: [256, 2048)
pub fn auth_response_padding() -> Vec<u8> {
    gen_padding(AUTH_RESP_PADDING_MIN, AUTH_RESP_PADDING_MAX)
}

/// Padding for TCP proxy request: [64, 512)
pub fn tcp_request_padding() -> Vec<u8> {
    gen_padding(TCP_REQ_PADDING_MIN, TCP_REQ_PADDING_MAX)
}

/// Padding for TCP proxy response: [128, 1024)
pub fn tcp_response_padding() -> Vec<u8> {
    gen_padding(TCP_RESP_PADDING_MIN, TCP_RESP_PADDING_MAX)
}

// ──────────────────────────────────────────────────────────────────────────────
// TCP Proxy Request
//
// Go: hysteria/core/internal/protocol/proxy.go — WriteTCPRequest / ReadTCPRequest
//
// Wire format (written by client):
//   [varint] 0x401           ← FrameTypeTCPRequest
//   [varint] addr_len
//   [bytes]  addr            ← "host:port" UTF-8
//   [varint] padding_len
//   [bytes]  padding
//
// ReadTCPRequest reads starting from addr_len (frame type already consumed).
// ──────────────────────────────────────────────────────────────────────────────

/// Serializes a full TCP proxy request (including the 0x401 frame type varint).
///
/// Go equivalent: `WriteTCPRequest` (which includes the frame type).
pub fn write_tcp_request(addr: &str) -> Vec<u8> {
    let padding = tcp_request_padding();
    let addr_bytes = addr.as_bytes();
    let total = varint_len(FRAME_TYPE_TCP_REQUEST)
        + varint_len(addr_bytes.len() as u64)
        + addr_bytes.len()
        + varint_len(padding.len() as u64)
        + padding.len();

    let mut buf = vec![0u8; total];
    let mut pos = 0;
    pos += varint_put(&mut buf[pos..], FRAME_TYPE_TCP_REQUEST);
    pos += varint_put(&mut buf[pos..], addr_bytes.len() as u64);
    buf[pos..pos + addr_bytes.len()].copy_from_slice(addr_bytes);
    pos += addr_bytes.len();
    pos += varint_put(&mut buf[pos..], padding.len() as u64);
    buf[pos..pos + padding.len()].copy_from_slice(&padding);
    buf
}

/// Reads a TCP proxy request from `buf` (frame type already consumed).
///
/// Go equivalent: `ReadTCPRequest`.
/// Returns `(address, bytes_consumed)`.
pub fn read_tcp_request(buf: &[u8]) -> Result<(String, usize), ProtocolError> {
    let mut pos = 0;

    let (addr_len, n) = varint_read(&buf[pos..])?;
    pos += n;
    if addr_len == 0 || addr_len > MAX_ADDRESS_LENGTH {
        return Err(ProtocolError::InvalidAddressLength);
    }
    let addr_len = addr_len as usize;
    if buf[pos..].len() < addr_len {
        return Err(ProtocolError::InsufficientData);
    }
    let address = std::str::from_utf8(&buf[pos..pos + addr_len])
        .map_err(|_| ProtocolError::InvalidUtf8)?
        .to_string();
    pos += addr_len;

    let (padding_len, n) = varint_read(&buf[pos..])?;
    pos += n;
    if padding_len > MAX_PADDING_LENGTH {
        return Err(ProtocolError::InvalidPaddingLength);
    }
    let padding_len = padding_len as usize;
    if buf[pos..].len() < padding_len {
        return Err(ProtocolError::InsufficientData);
    }
    pos += padding_len;

    Ok((address, pos))
}

// ──────────────────────────────────────────────────────────────────────────────
// TCP Proxy Response
//
// Go: hysteria/core/internal/protocol/proxy.go — WriteTCPResponse / ReadTCPResponse
//
// Wire format (written by server):
//   [u8]     status          ← 0x00 = OK, 0x01 = Error
//   [varint] msg_len
//   [bytes]  message         ← UTF-8 error message (empty on OK)
//   [varint] padding_len
//   [bytes]  padding
// ──────────────────────────────────────────────────────────────────────────────

/// Serializes a TCP proxy response.
///
/// Go equivalent: `WriteTCPResponse`.
pub fn write_tcp_response(ok: bool, msg: &str) -> Vec<u8> {
    let padding = tcp_response_padding();
    let msg_bytes = msg.as_bytes();
    let total = 1
        + varint_len(msg_bytes.len() as u64)
        + msg_bytes.len()
        + varint_len(padding.len() as u64)
        + padding.len();

    let mut buf = vec![0u8; total];
    buf[0] = if ok { 0x00 } else { 0x01 };
    let mut pos = 1;
    pos += varint_put(&mut buf[pos..], msg_bytes.len() as u64);
    if !msg_bytes.is_empty() {
        buf[pos..pos + msg_bytes.len()].copy_from_slice(msg_bytes);
        pos += msg_bytes.len();
    }
    pos += varint_put(&mut buf[pos..], padding.len() as u64);
    buf[pos..pos + padding.len()].copy_from_slice(&padding);
    buf
}

/// Reads a TCP proxy response from `buf`.
///
/// Go equivalent: `ReadTCPResponse`.
/// Returns `(ok, message, bytes_consumed)`.
pub fn read_tcp_response(buf: &[u8]) -> Result<(bool, String, usize), ProtocolError> {
    if buf.is_empty() {
        return Err(ProtocolError::InsufficientData);
    }
    let status = buf[0];
    let ok = status == 0x00;
    let mut pos = 1;

    let (msg_len, n) = varint_read(&buf[pos..])?;
    pos += n;
    if msg_len > MAX_MESSAGE_LENGTH {
        return Err(ProtocolError::InvalidMessageLength);
    }
    let msg_len = msg_len as usize;
    if buf[pos..].len() < msg_len {
        return Err(ProtocolError::InsufficientData);
    }
    let message = if msg_len > 0 {
        std::str::from_utf8(&buf[pos..pos + msg_len])
            .map_err(|_| ProtocolError::InvalidUtf8)?
            .to_string()
    } else {
        String::new()
    };
    pos += msg_len;

    let (padding_len, n) = varint_read(&buf[pos..])?;
    pos += n;
    if padding_len > MAX_PADDING_LENGTH {
        return Err(ProtocolError::InvalidPaddingLength);
    }
    let padding_len = padding_len as usize;
    if buf[pos..].len() < padding_len {
        return Err(ProtocolError::InsufficientData);
    }
    pos += padding_len;

    Ok((ok, message, pos))
}

// ──────────────────────────────────────────────────────────────────────────────
// UDP Message
//
// Go: hysteria/core/internal/protocol/proxy.go — UDPMessage / ParseUDPMessage
//
// Wire format:
//   [u32 BE]  session_id
//   [u16 BE]  pkt_id
//   [u8]      frag_id
//   [u8]      frag_count
//   [varint]  addr_len
//   [bytes]   addr           ← "host:port" UTF-8
//   [bytes]   data           ← everything remaining
// ──────────────────────────────────────────────────────────────────────────────

/// A Hysteria UDP relay message.
#[derive(Debug, Clone, PartialEq)]
pub struct UdpMessage {
    pub session_id: u32,
    pub pkt_id: u16,
    pub frag_id: u8,
    pub frag_count: u8,
    pub addr: String,
    pub data: Vec<u8>,
}

impl UdpMessage {
    /// Size of the fixed-width header fields (session_id + pkt_id + frag_id + frag_count).
    const FIXED_HEADER: usize = 4 + 2 + 1 + 1; // = 8

    /// Returns the serialized header size (fixed + varint addr_len + addr bytes).
    pub fn header_size(&self) -> usize {
        Self::FIXED_HEADER + varint_len(self.addr.len() as u64) + self.addr.len()
    }

    /// Returns the total serialized size.
    pub fn size(&self) -> usize {
        self.header_size() + self.data.len()
    }

    /// Serializes the message into `buf`. Returns bytes written, or -1 if buffer too small.
    ///
    /// Go equivalent: `UDPMessage.Serialize`.
    pub fn serialize(&self, buf: &mut [u8]) -> isize {
        let sz = self.size();
        if buf.len() < sz {
            return -1;
        }
        buf[0..4].copy_from_slice(&self.session_id.to_be_bytes());
        buf[4..6].copy_from_slice(&self.pkt_id.to_be_bytes());
        buf[6] = self.frag_id;
        buf[7] = self.frag_count;
        let addr_bytes = self.addr.as_bytes();
        let mut pos = 8;
        pos += varint_put(&mut buf[pos..], addr_bytes.len() as u64);
        buf[pos..pos + addr_bytes.len()].copy_from_slice(addr_bytes);
        pos += addr_bytes.len();
        buf[pos..pos + self.data.len()].copy_from_slice(&self.data);
        sz as isize
    }

    /// Serializes the message to a new `Vec<u8>`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![0u8; self.size()];
        self.serialize(&mut buf);
        buf
    }
}

/// Parses a UDP message from raw bytes.
///
/// Go equivalent: `ParseUDPMessage`.
/// Validation exactly matches Go: addr_len must be (0, 2048] and payload non-empty.
pub fn parse_udp_message(msg: &[u8]) -> Result<UdpMessage, ProtocolError> {
    if msg.len() < UdpMessage::FIXED_HEADER {
        return Err(ProtocolError::InsufficientData);
    }

    let mut session_id_bytes = [0u8; 4];
    session_id_bytes.copy_from_slice(&msg[0..4]);
    let session_id = u32::from_be_bytes(session_id_bytes);
    let mut pkt_id_bytes = [0u8; 2];
    pkt_id_bytes.copy_from_slice(&msg[4..6]);
    let pkt_id = u16::from_be_bytes(pkt_id_bytes);
    let frag_id = msg[6];
    let frag_count = msg[7];

    let (addr_len, n) = varint_read(&msg[8..])?;
    // Go: if lAddr == 0 || lAddr > MaxMessageLength { return error }
    if addr_len == 0 || addr_len > MAX_MESSAGE_LENGTH {
        return Err(ProtocolError::InvalidAddressLength);
    }

    // Position of the bytes after the varint
    let addr_start = 8 + n;
    let remaining = &msg[addr_start..];

    // Go: if len(bs) <= int(lAddr) { return error }
    // CRITICAL: use <= not <. Data must be at least 1 byte after addr.
    if remaining.len() <= addr_len as usize {
        return Err(ProtocolError::InvalidMessageLength);
    }

    let addr_len = addr_len as usize;
    let addr = std::str::from_utf8(&remaining[..addr_len])
        .map_err(|_| ProtocolError::InvalidUtf8)?
        .to_string();
    let data = remaining[addr_len..].to_vec();

    Ok(UdpMessage {
        session_id,
        pkt_id,
        frag_id,
        frag_count,
        addr,
        data,
    })
}

// ──────────────────────────────────────────────────────────────────────────────
// HTTP/3 Auth Structures
//
// Go: hysteria/core/internal/protocol/http.go
// ──────────────────────────────────────────────────────────────────────────────

/// What the client sends in the HTTP/3 POST /auth request headers.
#[derive(Debug, Clone)]
pub struct AuthRequest {
    /// Authentication credential string.
    pub auth: String,
    /// Client's maximum receive bandwidth in bytes/sec. 0 = unknown.
    pub rx: u64,
}

/// What the server sends back in the HTTP/3 233 response headers.
#[derive(Debug, Clone)]
pub struct AuthResponse {
    /// Whether UDP relay is enabled.
    pub udp_enabled: bool,
    /// Server's maximum receive bandwidth in bytes/sec. 0 = unlimited.
    pub rx: u64,
    /// If true, server requests client to use automatic bandwidth detection (BBR).
    pub rx_auto: bool,
}

impl AuthRequest {
    /// Creates an `AuthRequest` from HTTP header values.
    ///
    /// Go equivalent: `AuthRequestFromHeader`.
    pub fn from_headers(auth: &str, cc_rx: &str) -> Self {
        let rx = cc_rx.parse::<u64>().unwrap_or(0);
        Self {
            auth: auth.to_string(),
            rx,
        }
    }

    /// Generates the `Hysteria-Padding` value for this request.
    pub fn padding() -> String {
        String::from_utf8(auth_request_padding()).unwrap_or_default()
    }
}

impl AuthResponse {
    /// Creates an `AuthResponse` from HTTP header values.
    ///
    /// Go equivalent: `AuthResponseFromHeader`.
    pub fn from_headers(udp_enabled: &str, cc_rx: &str) -> Self {
        let udp_enabled = udp_enabled.parse::<bool>().unwrap_or(false);
        let (rx, rx_auto) = if cc_rx == "auto" {
            (0, true)
        } else {
            (cc_rx.parse::<u64>().unwrap_or(0), false)
        };
        Self {
            udp_enabled,
            rx,
            rx_auto,
        }
    }

    /// Generates the `Hysteria-CC-RX` header value for this response.
    ///
    /// Go equivalent: `AuthResponseToHeader` CC-RX value.
    pub fn cc_rx_header_value(&self) -> String {
        if self.rx_auto {
            "auto".to_string()
        } else {
            self.rx.to_string()
        }
    }

    /// Generates the `Hysteria-Padding` value for this response.
    pub fn padding() -> String {
        String::from_utf8(auth_response_padding()).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Varint ──────────────────────────────────────────────────────────────

    #[test]
    fn varint_roundtrip_1byte() {
        for v in [0u64, 1, 10, 63] {
            let mut buf = [0u8; 8];
            let written = varint_put(&mut buf, v);
            assert_eq!(written, 1, "v={}", v);
            let (decoded, read) = varint_read(&buf[..written]).unwrap();
            assert_eq!(decoded, v);
            assert_eq!(read, 1);
        }
    }

    #[test]
    fn varint_roundtrip_2byte() {
        for v in [64u64, 256, 16383] {
            let mut buf = [0u8; 8];
            let written = varint_put(&mut buf, v);
            assert_eq!(written, 2, "v={}", v);
            let (decoded, read) = varint_read(&buf[..written]).unwrap();
            assert_eq!(decoded, v);
            assert_eq!(read, 2);
        }
    }

    #[test]
    fn varint_roundtrip_4byte() {
        for v in [16384u64, 1_000_000, 1_073_741_823] {
            let mut buf = [0u8; 8];
            let written = varint_put(&mut buf, v);
            assert_eq!(written, 4, "v={}", v);
            let (decoded, read) = varint_read(&buf[..written]).unwrap();
            assert_eq!(decoded, v);
            assert_eq!(read, 4);
        }
    }

    #[test]
    fn varint_roundtrip_8byte() {
        for v in [1_073_741_824u64, 4_611_686_018_427_387_903] {
            let mut buf = [0u8; 8];
            let written = varint_put(&mut buf, v);
            assert_eq!(written, 8, "v={}", v);
            let (decoded, read) = varint_read(&buf[..written]).unwrap();
            assert_eq!(decoded, v);
            assert_eq!(read, 8);
        }
    }

    #[test]
    fn varint_known_value() {
        // From RFC 9000 Section 16 examples
        // Value 494878333 = 0x1D_7F_3E_7D in 4-byte form
        // First byte tag = 0b10 → 0x80 | 0x1D = 0x9D
        let v: u64 = 494_878_333;
        let mut buf = [0u8; 8];
        let n = varint_put(&mut buf, v);
        assert_eq!(n, 4);
        assert_eq!(buf[0], 0x9d);
        assert_eq!(buf[1], 0x7f);
        assert_eq!(buf[2], 0x3e);
        assert_eq!(buf[3], 0x7d);
        let (decoded, _) = varint_read(&buf[..4]).unwrap();
        assert_eq!(decoded, v);
    }

    // ── TCP Request ─────────────────────────────────────────────────────────

    #[test]
    fn tcp_request_roundtrip() {
        let addr = "example.com:8080";
        let wire = write_tcp_request(addr);

        // First varint must be FRAME_TYPE_TCP_REQUEST = 0x401
        let (ft, ft_len) = varint_read(&wire).unwrap();
        assert_eq!(ft, FRAME_TYPE_TCP_REQUEST);

        // read_tcp_request starts after frame type
        let (decoded_addr, _) = read_tcp_request(&wire[ft_len..]).unwrap();
        assert_eq!(decoded_addr, addr);
    }

    #[test]
    fn tcp_request_addr_too_long() {
        // Encode addr_len = MAX_ADDRESS_LENGTH + 1
        let mut buf = Vec::new();
        varint_append(&mut buf, MAX_ADDRESS_LENGTH + 1);
        assert!(read_tcp_request(&buf).is_err());
    }

    #[test]
    fn tcp_request_addr_zero_len() {
        let mut buf = Vec::new();
        varint_append(&mut buf, 0);
        assert!(read_tcp_request(&buf).is_err());
    }

    // ── TCP Response ────────────────────────────────────────────────────────

    #[test]
    fn tcp_response_ok_roundtrip() {
        let wire = write_tcp_response(true, "");
        let (ok, msg, _) = read_tcp_response(&wire).unwrap();
        assert!(ok);
        assert!(msg.is_empty());
    }

    #[test]
    fn tcp_response_err_roundtrip() {
        let wire = write_tcp_response(false, "connection refused");
        let (ok, msg, _) = read_tcp_response(&wire).unwrap();
        assert!(!ok);
        assert_eq!(msg, "connection refused");
    }

    #[test]
    fn tcp_response_status_byte() {
        let ok_wire = write_tcp_response(true, "");
        assert_eq!(ok_wire[0], 0x00);

        let err_wire = write_tcp_response(false, "err");
        assert_eq!(err_wire[0], 0x01);
    }

    // ── UDP Message ─────────────────────────────────────────────────────────

    #[test]
    fn udp_message_roundtrip() {
        let msg = UdpMessage {
            session_id: 0xDEAD_BEEF,
            pkt_id: 42,
            frag_id: 0,
            frag_count: 1,
            addr: "192.168.1.1:53".to_string(),
            data: vec![1, 2, 3, 4, 5],
        };
        let bytes = msg.to_bytes();
        let decoded = parse_udp_message(&bytes).unwrap();
        assert_eq!(decoded.session_id, msg.session_id);
        assert_eq!(decoded.pkt_id, msg.pkt_id);
        assert_eq!(decoded.frag_id, msg.frag_id);
        assert_eq!(decoded.frag_count, msg.frag_count);
        assert_eq!(decoded.addr, msg.addr);
        assert_eq!(decoded.data, msg.data);
    }

    #[test]
    fn udp_message_fixed_header_layout() {
        let msg = UdpMessage {
            session_id: 0x0102_0304,
            pkt_id: 0x0506,
            frag_id: 0x07,
            frag_count: 0x08,
            addr: "x:1".to_string(),
            data: vec![0xFF],
        };
        let bytes = msg.to_bytes();
        // session_id big-endian
        assert_eq!(&bytes[0..4], &[0x01, 0x02, 0x03, 0x04]);
        // pkt_id big-endian
        assert_eq!(&bytes[4..6], &[0x05, 0x06]);
        // frag_id, frag_count
        assert_eq!(bytes[6], 0x07);
        assert_eq!(bytes[7], 0x08);
    }

    #[test]
    fn udp_message_zero_addr_rejected() {
        // Build a message with addr_len = 0
        let mut buf = vec![0u8; 9]; // 8 fixed + 1 varint
        buf[8] = 0; // varint 0
        assert!(parse_udp_message(&buf).is_err());
    }

    #[test]
    fn udp_message_no_data_rejected() {
        // addr_len > 0 but no data bytes after addr: len(bs) == addr_len → error
        let msg = UdpMessage {
            session_id: 1,
            pkt_id: 0,
            frag_id: 0,
            frag_count: 1,
            addr: "x:1".to_string(),
            data: vec![0xFF],
        };
        let mut bytes = msg.to_bytes();
        // Truncate to header + addr, removing data
        let header_sz = msg.header_size();
        bytes.truncate(header_sz);
        assert!(parse_udp_message(&bytes).is_err());
    }

    // ── Auth Structures ─────────────────────────────────────────────────────

    #[test]
    fn auth_request_from_headers() {
        let req = AuthRequest::from_headers("secret", "1000000");
        assert_eq!(req.auth, "secret");
        assert_eq!(req.rx, 1_000_000);
    }

    #[test]
    fn auth_request_rx_zero_on_bad_parse() {
        let req = AuthRequest::from_headers("secret", "notanumber");
        assert_eq!(req.rx, 0);
    }

    #[test]
    fn auth_response_rx_auto() {
        let resp = AuthResponse::from_headers("true", "auto");
        assert!(resp.udp_enabled);
        assert!(resp.rx_auto);
        assert_eq!(resp.rx, 0);
        assert_eq!(resp.cc_rx_header_value(), "auto");
    }

    #[test]
    fn auth_response_rx_numeric() {
        let resp = AuthResponse::from_headers("false", "5000000");
        assert!(!resp.udp_enabled);
        assert!(!resp.rx_auto);
        assert_eq!(resp.rx, 5_000_000);
        assert_eq!(resp.cc_rx_header_value(), "5000000");
    }

    #[test]
    fn padding_in_valid_range() {
        for _ in 0..20 {
            let p = auth_request_padding();
            assert!(p.len() >= AUTH_REQ_PADDING_MIN && p.len() < AUTH_REQ_PADDING_MAX);
            let p = auth_response_padding();
            assert!(p.len() >= AUTH_RESP_PADDING_MIN && p.len() < AUTH_RESP_PADDING_MAX);
            let p = tcp_request_padding();
            assert!(p.len() >= TCP_REQ_PADDING_MIN && p.len() < TCP_REQ_PADDING_MAX);
            let p = tcp_response_padding();
            assert!(p.len() >= TCP_RESP_PADDING_MIN && p.len() < TCP_RESP_PADDING_MAX);
        }
    }

    #[test]
    fn padding_chars_are_alphanumeric() {
        for _ in 0..5 {
            let p = gen_padding(10, 20);
            for &b in &p {
                assert!(
                    b.is_ascii_alphanumeric(),
                    "non-alphanumeric byte: {}",
                    b as char
                );
            }
        }
    }
}
