use std::io;
use std::net::{IpAddr, SocketAddr};
use std::ops::RangeInclusive;
use std::str::FromStr;
use std::time::Duration;

use aws_lc_rs::{aead, hkdf};
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::core::server::{RecvStreamReader, RequestHook};

const SNIFF_DEFAULT_TIMEOUT: Duration = Duration::from_secs(4);
const MAX_HTTP_SNIFF_BYTES: usize = 8192;
const QUIC_V1: u32 = 0x0000_0001;
const QUIC_V2: u32 = 0x6b33_43cf;
const QUIC_MAX_PACKET_NUMBER: u64 = 2;

const QUIC_SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c,
    0xad, 0xcc, 0xbb, 0x7f, 0x0a,
];
const QUIC_SALT_V2: [u8; 20] = [
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d,
    0xcb, 0xf9, 0xbd, 0x2e, 0xd9,
];

#[derive(Debug, Clone, Default)]
pub struct PortUnion {
    any: bool,
    ranges: Vec<RangeInclusive<u16>>,
}

impl PortUnion {
    pub fn any() -> Self {
        Self {
            any: true,
            ranges: Vec::new(),
        }
    }

    pub fn parse(raw: &str) -> io::Result<Self> {
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("all") {
            return Ok(Self::any());
        }

        let mut ranges = Vec::new();
        for part in trimmed.split(',') {
            let p = part.trim();
            if p.is_empty() {
                continue;
            }
            if let Some((a, b)) = p.split_once('-') {
                let a = a.trim().parse::<u16>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, format!("invalid port: {p}"))
                })?;
                let b = b.trim().parse::<u16>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, format!("invalid port: {p}"))
                })?;
                let (start, end) = if a <= b { (a, b) } else { (b, a) };
                ranges.push(start..=end);
            } else {
                let v = p.parse::<u16>().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, format!("invalid port: {p}"))
                })?;
                ranges.push(v..=v);
            }
        }

        Ok(Self { any: false, ranges })
    }

    pub fn contains(&self, port: u16) -> bool {
        if self.any {
            return true;
        }
        self.ranges.iter().any(|r| r.contains(&port))
    }
}

#[derive(Debug, Clone)]
pub struct Sniffer {
    pub timeout: Duration,
    pub rewrite_domain: bool,
    pub tcp_ports: Option<PortUnion>,
    pub udp_ports: Option<PortUnion>,
}

impl Default for Sniffer {
    fn default() -> Self {
        Self {
            timeout: SNIFF_DEFAULT_TIMEOUT,
            rewrite_domain: false,
            tcp_ports: None,
            udp_ports: None,
        }
    }
}

impl Sniffer {
    pub fn check(&self, is_udp: bool, req_addr: &str) -> bool {
        if req_addr.starts_with('@') {
            return false;
        }

        let (host, port) = match split_host_port(req_addr) {
            Some(v) => v,
            None => return false,
        };

        if !self.rewrite_domain && host.parse::<IpAddr>().is_err() {
            return false;
        }

        if is_udp {
            self.udp_ports.as_ref().is_none_or(|p| p.contains(port))
        } else {
            self.tcp_ports.as_ref().is_none_or(|p| p.contains(port))
        }
    }

    pub async fn tcp<R>(&self, stream: &mut R, req_addr: &mut String) -> io::Result<Vec<u8>>
    where
        R: AsyncRead + Unpin,
    {
        let timeout = if self.timeout.is_zero() {
            SNIFF_DEFAULT_TIMEOUT
        } else {
            self.timeout
        };

        let mut pre = vec![0u8; 3];
        let n = match read_full_with_timeout(stream, &mut pre, timeout).await {
            Ok(n) => n,
            Err((n, _)) => return Ok(pre[..n].to_vec()),
        };

        if n < 3 {
            return Ok(pre[..n].to_vec());
        }

        if is_http_prefix(&pre) {
            return self.sniff_http(stream, pre, req_addr).await;
        }

        if is_tls_prefix(&pre) {
            return self.sniff_tls(stream, pre, req_addr).await;
        }

        Ok(pre)
    }

    pub fn udp(&self, payload: &[u8], req_addr: &mut String) -> io::Result<()> {
        let quic_client_hello = extract_quic_initial_crypto_payload(payload)
            .and_then(|p| parse_tls_client_hello_sni(&p));
        let raw_tls_client_hello = parse_tls_client_hello_sni(payload);

        if let Some(server_name) = quic_client_hello.or(raw_tls_client_hello) {
            rewrite_addr_host(req_addr, &server_name)?;
        }
        Ok(())
    }

    async fn sniff_http<R>(
        &self,
        stream: &mut R,
        mut buf: Vec<u8>,
        req_addr: &mut String,
    ) -> io::Result<Vec<u8>>
    where
        R: AsyncRead + Unpin,
    {
        while buf.len() < MAX_HTTP_SNIFF_BYTES {
            if find_header_ending(&buf).is_some() {
                break;
            }
            let mut chunk = vec![0u8; 512];
            let n = stream.read(&mut chunk).await?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
        }

        if let Some(host) = parse_http_host(&buf) {
            let _ = rewrite_addr_host(req_addr, &host);
        }

        Ok(buf)
    }

    async fn sniff_tls<R>(
        &self,
        stream: &mut R,
        mut pre: Vec<u8>,
        req_addr: &mut String,
    ) -> io::Result<Vec<u8>>
    where
        R: AsyncRead + Unpin,
    {
        let mut rest = [0u8; 2];
        let n = match read_full(stream, &mut rest).await {
            Ok(n) => n,
            Err((n, _)) => {
                pre.extend_from_slice(&rest[..n]);
                return Ok(pre);
            }
        };
        pre.extend_from_slice(&rest[..n]);

        let content_len = u16::from_be_bytes(rest) as usize;
        let mut content = vec![0u8; content_len];
        let n = match read_full(stream, &mut content).await {
            Ok(n) => n,
            Err((n, _)) => {
                pre.extend_from_slice(&content[..n]);
                return Ok(pre);
            }
        };
        if n < content_len {
            pre.extend_from_slice(&content[..n]);
            return Ok(pre);
        }
        pre.extend_from_slice(&content[..n]);

        if let Some(server_name) = parse_tls_client_hello_sni(&content) {
            let _ = rewrite_addr_host(req_addr, &server_name);
        }

        Ok(pre)
    }
}

async fn read_full<R>(stream: &mut R, buf: &mut [u8]) -> Result<usize, (usize, io::Error)>
where
    R: AsyncRead + Unpin,
{
    let mut n = 0usize;
    while n < buf.len() {
        match stream.read(&mut buf[n..]).await {
            Ok(0) => {
                return Err((
                    n,
                    io::Error::new(io::ErrorKind::UnexpectedEof, "early eof while sniffing"),
                ));
            }
            Ok(m) => n += m,
            Err(err) => return Err((n, err)),
        }
    }
    Ok(n)
}

async fn read_full_with_timeout<R>(
    stream: &mut R,
    buf: &mut [u8],
    timeout: Duration,
) -> Result<usize, (usize, io::Error)>
where
    R: AsyncRead + Unpin,
{
    let deadline = tokio::time::Instant::now() + timeout;
    let mut n = 0usize;
    while n < buf.len() {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return Err((
                n,
                io::Error::new(io::ErrorKind::TimedOut, "sniff timeout"),
            ));
        }
        let remain = deadline.saturating_duration_since(now);
        match tokio::time::timeout(remain, stream.read(&mut buf[n..])).await {
            Ok(Ok(0)) => {
                return Err((
                    n,
                    io::Error::new(io::ErrorKind::UnexpectedEof, "early eof while sniffing"),
                ));
            }
            Ok(Ok(m)) => n += m,
            Ok(Err(err)) => return Err((n, err)),
            Err(_) => {
                return Err((
                    n,
                    io::Error::new(io::ErrorKind::TimedOut, "sniff timeout"),
                ));
            }
        }
    }
    Ok(n)
}

#[async_trait::async_trait]
impl RequestHook for Sniffer {
    fn check(&self, is_udp: bool, req_addr: &str) -> bool {
        Sniffer::check(self, is_udp, req_addr)
    }

    async fn tcp(
        &self,
        stream: &mut RecvStreamReader,
        req_addr: &mut String,
    ) -> io::Result<Vec<u8>> {
        Sniffer::tcp(self, stream, req_addr).await
    }

    fn udp(&self, data: &[u8], req_addr: &mut String) -> io::Result<()> {
        Sniffer::udp(self, data, req_addr)
    }
}

fn split_host_port(addr: &str) -> Option<(String, u16)> {
    if let Ok(sa) = SocketAddr::from_str(addr) {
        return Some((sa.ip().to_string(), sa.port()));
    }
    let (host, port) = addr.rsplit_once(':')?;
    let port = port.parse::<u16>().ok()?;
    Some((host.to_string(), port))
}

fn rewrite_addr_host(req_addr: &mut String, new_host: &str) -> io::Result<()> {
    let (_, port) = split_host_port(req_addr).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid request address: {req_addr}"),
        )
    })?;
    *req_addr = format!("{}:{}", new_host, port);
    Ok(())
}

fn is_http_prefix(buf: &[u8]) -> bool {
    if buf.len() < 3 {
        return false;
    }
    buf[..3].iter().all(|b| b.is_ascii_alphabetic())
}

fn is_tls_prefix(buf: &[u8]) -> bool {
    if buf.len() < 3 {
        return false;
    }
    (buf[0] == 0x16 || buf[0] == 0x17) && buf[1] == 0x03 && buf[2] <= 0x09
}

fn find_header_ending(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn parse_http_host(buf: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(buf).ok()?;
    for line in text.lines() {
        let mut parts = line.splitn(2, ':');
        let k = parts.next()?.trim();
        if !k.eq_ignore_ascii_case("host") {
            continue;
        }
        let v = parts.next()?.trim();
        if v.is_empty() {
            return None;
        }
        if v.starts_with('[') {
            if let Some(end) = v.find(']') {
                return Some(v[..=end].to_string());
            }
        }
        if let Some((host, _port)) = v.rsplit_once(':') {
            if !host.contains(':') {
                return Some(host.to_string());
            }
        }
        return Some(v.to_string());
    }
    None
}

fn parse_tls_client_hello_sni(data: &[u8]) -> Option<String> {
    if data.len() < 42 {
        return None;
    }

    let mut i = 0usize;

    if data[i] != 0x01 {
        return None;
    }
    i += 1;

    if i + 3 > data.len() {
        return None;
    }
    let hs_len = ((data[i] as usize) << 16) | ((data[i + 1] as usize) << 8) | data[i + 2] as usize;
    i += 3;
    if i + hs_len > data.len() {
        return None;
    }

    i += 2;
    i += 32;

    if i >= data.len() {
        return None;
    }
    let sid_len = data[i] as usize;
    i += 1 + sid_len;
    if i + 2 > data.len() {
        return None;
    }

    let cs_len = u16::from_be_bytes([data[i], data[i + 1]]) as usize;
    i += 2 + cs_len;
    if i >= data.len() {
        return None;
    }

    let comp_len = data[i] as usize;
    i += 1 + comp_len;
    if i + 2 > data.len() {
        return None;
    }

    let ext_len = u16::from_be_bytes([data[i], data[i + 1]]) as usize;
    i += 2;
    let ext_end = i + ext_len;
    if ext_end > data.len() {
        return None;
    }

    while i + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([data[i], data[i + 1]]);
        let ext_size = u16::from_be_bytes([data[i + 2], data[i + 3]]) as usize;
        i += 4;
        if i + ext_size > ext_end {
            return None;
        }

        if ext_type == 0 {
            if ext_size < 2 {
                return None;
            }
            let mut j = i;
            let list_len = u16::from_be_bytes([data[j], data[j + 1]]) as usize;
            j += 2;
            let list_end = j + list_len;
            if list_end > i + ext_size {
                return None;
            }
            while j + 3 <= list_end {
                let name_type = data[j];
                let name_len = u16::from_be_bytes([data[j + 1], data[j + 2]]) as usize;
                j += 3;
                if j + name_len > list_end {
                    return None;
                }
                if name_type == 0 {
                    let host = std::str::from_utf8(&data[j..j + name_len])
                        .ok()?
                        .to_string();
                    if !host.is_empty() {
                        return Some(host);
                    }
                }
                j += name_len;
            }
        }

        i += ext_size;
    }

    None
}

#[derive(Debug)]
struct QuicInitialHeader {
    version: u32,
    dst_connection_id: Vec<u8>,
    length: usize,
    packet_number_offset: usize,
}

fn extract_quic_initial_crypto_payload(packet: &[u8]) -> Option<Vec<u8>> {
    let header = parse_quic_initial_header(packet)?;
    if !(header.version == QUIC_V1 || header.version == QUIC_V2) {
        return None;
    }
    if header.packet_number_offset == 0 || header.length == 0 {
        return None;
    }
    let packet_end = header.packet_number_offset.checked_add(header.length)?;
    if packet_end > packet.len() {
        return None;
    }

    let (packet_key, header_key, iv) = derive_quic_initial_client_keys(
        header.version,
        &header.dst_connection_id,
    )?;

    let mut protected = packet[..packet_end].to_vec();
    let sample_offset = header.packet_number_offset.checked_add(4)?;
    if sample_offset + 16 > protected.len() {
        return None;
    }
    let sample = &protected[sample_offset..sample_offset + 16];
    let mask = header_key.new_mask(sample).ok()?;

    protected[0] ^= mask[0] & 0x0f;
    let packet_number_len = (protected[0] & 0x03) + 1;
    let pn_len = packet_number_len as usize;
    if header.packet_number_offset + pn_len > protected.len() {
        return None;
    }

    let mut truncated_pn = 0u64;
    for i in 0..pn_len {
        protected[header.packet_number_offset + i] ^= mask[1 + i];
        truncated_pn = (truncated_pn << 8) | protected[header.packet_number_offset + i] as u64;
    }
    let packet_number = decode_packet_number(QUIC_MAX_PACKET_NUMBER, truncated_pn, packet_number_len);

    let header_bytes_end = header.packet_number_offset + pn_len;
    let header_bytes = protected[..header_bytes_end].to_vec();
    let mut ciphertext = protected[header_bytes_end..].to_vec();

    let nonce = quic_nonce(&iv, packet_number);
    let nonce = aead::Nonce::assume_unique_for_key(nonce);
    let plaintext = packet_key
        .open_in_place(nonce, aead::Aad::from(header_bytes.as_slice()), &mut ciphertext)
        .ok()?;

    let frames = extract_quic_crypto_frames(plaintext)?;
    assemble_quic_crypto_frames(frames)
}

fn parse_quic_initial_header(packet: &[u8]) -> Option<QuicInitialHeader> {
    if packet.len() < 7 {
        return None;
    }
    let first = packet[0];
    if first & 0x80 == 0 {
        return None;
    }

    let version = u32::from_be_bytes([packet[1], packet[2], packet[3], packet[4]]);
    if version != 0 && first & 0x40 == 0 {
        return None;
    }

    let mut i = 5usize;
    let dcid_len = *packet.get(i)? as usize;
    i += 1;
    let dst_connection_id = packet.get(i..i + dcid_len)?.to_vec();
    i += dcid_len;

    let scid_len = *packet.get(i)? as usize;
    i += 1 + scid_len;

    let initial_packet_type = if version == QUIC_V2 { 0b01 } else { 0b00 };
    let long_type = (first >> 4) & 0b11;
    if long_type != initial_packet_type {
        return None;
    }

    let token_len = read_quic_varint(packet, &mut i)? as usize;
    i = i.checked_add(token_len)?;
    if i > packet.len() {
        return None;
    }

    let length = read_quic_varint(packet, &mut i)? as usize;
    Some(QuicInitialHeader {
        version,
        dst_connection_id,
        length,
        packet_number_offset: i,
    })
}

fn derive_quic_initial_client_keys(
    version: u32,
    dst_connection_id: &[u8],
) -> Option<(aead::LessSafeKey, aead::quic::HeaderProtectionKey, [u8; 12])> {
    let salt = if version == QUIC_V2 {
        QUIC_SALT_V2.as_slice()
    } else {
        QUIC_SALT_V1.as_slice()
    };

    let hkdf_salt = hkdf::Salt::new(hkdf::HKDF_SHA256, salt);
    let initial_secret = hkdf_salt.extract(dst_connection_id);
    let client_secret = hkdf_expand_label_sha256(&initial_secret, "client in", &[], 32)?;
    let client_prk = hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, &client_secret);

    let key_label = if version == QUIC_V2 {
        "quicv2 key"
    } else {
        "quic key"
    };
    let iv_label = if version == QUIC_V2 {
        "quicv2 iv"
    } else {
        "quic iv"
    };
    let hp_label = if version == QUIC_V2 {
        "quicv2 hp"
    } else {
        "quic hp"
    };

    let key_bytes = hkdf_expand_label_sha256(&client_prk, key_label, &[], 16)?;
    let iv_bytes = hkdf_expand_label_sha256(&client_prk, iv_label, &[], 12)?;
    let hp_bytes = hkdf_expand_label_sha256(&client_prk, hp_label, &[], 16)?;

    let unbound = aead::UnboundKey::new(&aead::AES_128_GCM, &key_bytes).ok()?;
    let packet_key = aead::LessSafeKey::new(unbound);
    let header_key = aead::quic::HeaderProtectionKey::new(&aead::quic::AES_128, &hp_bytes).ok()?;
    let iv: [u8; 12] = iv_bytes.try_into().ok()?;

    Some((packet_key, header_key, iv))
}

fn hkdf_expand_label_sha256(
    prk: &hkdf::Prk,
    label: &str,
    context: &[u8],
    len: usize,
) -> Option<Vec<u8>> {
    struct HkdfLen(usize);
    impl hkdf::KeyType for HkdfLen {
        fn len(&self) -> usize {
            self.0
        }
    }

    if label.len() > (u8::MAX as usize).saturating_sub(6) || context.len() > u8::MAX as usize {
        return None;
    }

    let mut info = Vec::with_capacity(2 + 1 + 6 + label.len() + 1 + context.len());
    info.extend_from_slice(&(len as u16).to_be_bytes());
    info.push((6 + label.len()) as u8);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label.as_bytes());
    info.push(context.len() as u8);
    info.extend_from_slice(context);

    let mut out = vec![0u8; len];
    prk.expand(&[&info], HkdfLen(len))
        .ok()?
        .fill(&mut out)
        .ok()?;
    Some(out)
}

fn quic_nonce(iv: &[u8; 12], packet_number: u64) -> [u8; 12] {
    let mut nonce = *iv;
    let pn_bytes = packet_number.to_be_bytes();
    for i in 0..8 {
        nonce[12 - 8 + i] ^= pn_bytes[i];
    }
    nonce
}

fn decode_packet_number(largest: u64, truncated: u64, packet_number_len: u8) -> u64 {
    let expected = largest + 1;
    let win = 1u64 << (packet_number_len * 8);
    let hwin = win / 2;
    let mask = win - 1;
    let candidate = (expected & !mask) | truncated;
    if candidate <= expected.saturating_sub(hwin) && candidate < ((1u64 << 62) - win) {
        candidate + win
    } else if candidate > expected + hwin && candidate >= win {
        candidate - win
    } else {
        candidate
    }
}

fn extract_quic_crypto_frames(payload: &[u8]) -> Option<Vec<(u64, Vec<u8>)>> {
    const FRAME_PADDING: u64 = 0x00;
    const FRAME_PING: u64 = 0x01;
    const FRAME_CRYPTO: u64 = 0x06;

    let mut i = 0usize;
    let mut frames = Vec::new();
    while i < payload.len() {
        let frame_type = read_quic_varint(payload, &mut i)?;
        if frame_type == FRAME_PADDING || frame_type == FRAME_PING {
            continue;
        }
        if frame_type != FRAME_CRYPTO {
            return None;
        }
        let offset = read_quic_varint(payload, &mut i)?;
        let data_len = read_quic_varint(payload, &mut i)? as usize;
        let data = payload.get(i..i + data_len)?.to_vec();
        i += data_len;
        frames.push((offset, data));
    }
    Some(frames)
}

fn assemble_quic_crypto_frames(mut frames: Vec<(u64, Vec<u8>)>) -> Option<Vec<u8>> {
    if frames.is_empty() {
        return None;
    }
    if frames.len() == 1 {
        return Some(frames.remove(0).1);
    }

    frames.sort_by_key(|(offset, _)| *offset);
    for idx in 1..frames.len() {
        let prev_end = frames[idx - 1].0 + frames[idx - 1].1.len() as u64;
        if frames[idx].0 != prev_end {
            return None;
        }
    }

    let total_len = (frames.last()?.0 + frames.last()?.1.len() as u64) as usize;
    let mut out = vec![0u8; total_len];
    for (offset, data) in frames {
        out[offset as usize..offset as usize + data.len()].copy_from_slice(&data);
    }
    Some(out)
}

fn read_quic_varint(data: &[u8], index: &mut usize) -> Option<u64> {
    let first = *data.get(*index)?;
    let prefix = first >> 6;
    let size = 1usize << prefix;
    if *index + size > data.len() {
        return None;
    }

    let mut value = (first & 0x3f) as u64;
    for b in &data[*index + 1..*index + size] {
        value = (value << 8) | (*b as u64);
    }
    *index += size;
    Some(value)
}

#[cfg(test)]
mod tests {
    use super::{PortUnion, Sniffer};
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use tokio::io::AsyncWriteExt;

    #[test]
    fn parse_port_union() {
        let p = PortUnion::parse("80,443,1000-1002").expect("parse");
        assert!(p.contains(80));
        assert!(p.contains(1001));
        assert!(!p.contains(1003));
    }

    #[test]
    fn sniff_udp_quic_client_hello_rewrites_domain() {
        let sniffer = Sniffer::default();
        let mut req_addr = "2.3.4.5:443".to_string();
        let packet = STANDARD.decode("ygAAAAEIwugWgPS7ulYAAES8hY891uwgGE9GG4CPOLd+nsDe28raso24lCSFmlFwYQG1uF39ikbL13/R9ZTghYmTl+jEbr6F9TxxRiOgpTmKRmh6aKZiIiVfy5pVRckovaI8lq0WRoW9xoFNTyYtQP8TVJ3bLCK+zUqpquEQSyWf7CE43ywayyMpE9UlIoPXFWCoopXLM1SvzdQ+17P51N9KR7m4emti4DWWTBLMQOvrwd2HEEkbiZdRO1wf6ZXJlIat5dN0R/6uod60OFPO+u+awvq67MoMReC7+5I/xWI+xx6o4JpnZNn6YPG8Gqi8hS6doNcAAdtD8h5eMLuHCCgkpX3QVjjfWtcOhtw9xKjU43HhUPwzUTv+JDLgwuTQCTmlfYlb3B+pk4b2I9si0tJ0SBuYaZ2VQPtZbj2hpGXw3gn11pbN8xsbKkQL50+Scd4dGJxWQlGaJHeaU5WOCkxLXc635z8m5XO/CBHVYPGp4pfwfwNUgbe5WF+3MaUIlDB8dMfsnrO0BmZPo379jVx0SFLTAiS8wAdHib1WNEY8qKYnTWuiyxYg1GZEhJt0nXmI+8f0eJq42DgHBWC+Rf5rRBr/Sf25o3mFAmTUaul0Woo9/CIrpT73B63N91xd9A77i4ru995YG8l9Hen+eLtpDU9Q9376nwMDYBzeYG9U/Rn0Urbm6q4hmAgV/xlNJ2rAyDS+yLnwqD6I0PRy8bZJEttcidb/SkOyrpgMiAzWeT+SO+c/k+Y8H0UTRa05faZUrhuUaym9wAcaIVRA6nFI+fejfjVp+7afFv+kWn3vCqQEij+CRHuxkltrixZMD2rfYj6NUW7TTYBtPRtuV/V0ZIDjRR26vr4K+0D84+l3c0mA/l6nmpP5kkco3nmpdjtQN6sGXL7+5o0nnsftX5d6/n5mLyEpP+AEDl1zk3iqkS62RsITwql6DMMoGbSDdUpMclCIeM0vlo3CkxGMO7QA9ruVeNddkL3EWMivl+uxO43sXEEqYQHVl4N75y63t05GOf7/gm9Kb/BJ8MpG9ViEkVYaskQCzi3D8bVpzo8FfTj8te8B6c3ikc/cm7r8k0ZcZpr+YiLGDYq+0ilHxpqJfmq8dPkSvxdzLcUSvy7+LMQ/TTobRSF7L4JhtDKck0+00vl9H35Tkh9N+MsVtpKdWyoqZ4XaK2Nx1M6AieczXpdFc0y7lYPoUfF4IeW8WzeVUclol5ElYjkyFz/lDOGAe1bF2g5AYaGWCPiGleVZknNdD5ihB8W8Mfkt1pEwq2S97AHrppqkf/VoIfZzeqH8wUFw8fDDrZIpnoa0rW7HfwIQaqJhPCyB9Z6TVbV4x9UWmaHfVAcinCK/7o10dtaj3rvEqcUC/iPceGq3Tqv/p9GGNJ+Ci2JBjXqNxYr893Llk75VdPD9pM6y1SM0P80oXNy32VMtafkFFST8GpvvqWcxUJ93kzaY8RmU1g3XFOImSU2utU6+FUQ2Pn5uLwcfT2cTYfTpPGh+WXjSbZ6trqdEMEsLHybuPo2UN4WpVLXVQma3kSaHQggcLlEip8GhEUAy/xCb2eKqhI4HkDpDjwDnDVKufWlnRaOHf58cc8Woi+WT8JTOkHC+nBEG6fKRPHDG08U5yayIQIjI").expect("decode");

        sniffer.udp(&packet, &mut req_addr).expect("sniff udp");
        assert_eq!(req_addr, "www.notion.so:443");
    }

    #[tokio::test]
    async fn sniff_tcp_keeps_partial_prefix_on_short_read() {
        let sniffer = Sniffer::default();
        let mut req_addr = "1.2.3.4:80".to_string();
        let (mut writer, mut reader) = tokio::io::duplex(16);
        writer.write_all(b"GE").await.expect("write");
        writer.shutdown().await.expect("shutdown");

        let putback = sniffer.tcp(&mut reader, &mut req_addr).await.expect("sniff");
        assert_eq!(putback, b"GE");
    }

    #[tokio::test]
    async fn sniff_tcp_tls_keeps_partial_length_bytes_on_short_read() {
        let sniffer = Sniffer::default();
        let mut req_addr = "1.2.3.4:443".to_string();
        let (mut writer, mut reader) = tokio::io::duplex(16);
        // TLS prefix + only one length byte (total 4 bytes).
        writer
            .write_all(&[0x16, 0x03, 0x03, 0x00])
            .await
            .expect("write");
        writer.shutdown().await.expect("shutdown");

        let putback = sniffer.tcp(&mut reader, &mut req_addr).await.expect("sniff");
        assert_eq!(putback, vec![0x16, 0x03, 0x03, 0x00]);
    }

    #[tokio::test]
    async fn sniff_tcp_tls_keeps_partial_content_on_short_read() {
        let sniffer = Sniffer::default();
        let mut req_addr = "1.2.3.4:443".to_string();
        let (mut writer, mut reader) = tokio::io::duplex(32);
        // TLS prefix + declared length=4 + only 2 payload bytes.
        writer
            .write_all(&[0x16, 0x03, 0x03, 0x00, 0x04, 0xaa, 0xbb])
            .await
            .expect("write");
        writer.shutdown().await.expect("shutdown");

        let putback = sniffer.tcp(&mut reader, &mut req_addr).await.expect("sniff");
        assert_eq!(putback, vec![0x16, 0x03, 0x03, 0x00, 0x04, 0xaa, 0xbb]);
    }
}
