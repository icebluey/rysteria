use std::fmt;
use std::io::{self, IoSliceMut};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};

use crate::extras::obfs::{SM_SALT_LEN, SalamanderObfuscator};

/// UDP socket wrapper that applies Salamander obfuscation/deobfuscation
/// to QUIC packets at the socket boundary.
pub struct ObfsUdpSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    obfs: Arc<SalamanderObfuscator>,
}

impl fmt::Debug for ObfsUdpSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObfsUdpSocket").finish_non_exhaustive()
    }
}

impl ObfsUdpSocket {
    pub fn new(inner: Arc<dyn AsyncUdpSocket>, obfs: SalamanderObfuscator) -> Self {
        Self {
            inner,
            obfs: Arc::new(obfs),
        }
    }
}

impl AsyncUdpSocket for ObfsUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        if transmit.contents.is_empty() {
            return self.inner.try_send(transmit);
        }

        let mut encoded = Vec::new();
        let new_segment_size = if let Some(segment_size) = transmit.segment_size {
            if segment_size == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid UDP segment size: 0",
                ));
            }
            let estimated = transmit
                .contents
                .len()
                .saturating_add((transmit.contents.len() / segment_size + 1) * SM_SALT_LEN);
            encoded.reserve(estimated);
            for chunk in transmit.contents.chunks(segment_size) {
                let start = encoded.len();
                encoded.resize(start + chunk.len() + SM_SALT_LEN, 0);
                let n = self.obfs.obfuscate(chunk, &mut encoded[start..]);
                if n == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "failed to obfuscate UDP segment",
                    ));
                }
                encoded.truncate(start + n);
            }
            Some(segment_size.saturating_add(SM_SALT_LEN))
        } else {
            encoded.resize(transmit.contents.len() + SM_SALT_LEN, 0);
            let n = self.obfs.obfuscate(transmit.contents, &mut encoded);
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "failed to obfuscate UDP packet",
                ));
            }
            encoded.truncate(n);
            None
        };

        let wrapped = Transmit {
            destination: transmit.destination,
            ecn: transmit.ecn,
            contents: &encoded,
            segment_size: new_segment_size,
            src_ip: transmit.src_ip,
        };
        self.inner.try_send(&wrapped)
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let recv = match self.inner.poll_recv(cx, bufs, meta) {
            Poll::Ready(Ok(n)) => n,
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Pending => return Poll::Pending,
        };

        for i in 0..recv {
            let len = meta[i].len;
            if len == 0 {
                continue;
            }
            let stride = meta[i].stride;
            let data = &mut bufs[i][..len];
            if stride == 0 || stride >= len {
                let mut plain = vec![0u8; len];
                let n = self.obfs.deobfuscate(data, &mut plain);
                if n == 0 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid Salamander UDP packet",
                    )));
                }
                data[..n].copy_from_slice(&plain[..n]);
                meta[i].len = n;
                meta[i].stride = n;
                continue;
            }

            // GRO path: decode each segment individually and compact in place.
            let mut decoded = vec![0u8; len];
            let mut out = 0usize;
            let mut off = 0usize;
            let mut decoded_stride = 0usize;
            while off < len {
                let end = (off + stride).min(len);
                let mut plain = vec![0u8; end - off];
                let n = self.obfs.deobfuscate(&data[off..end], &mut plain);
                if n == 0 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid Salamander UDP segment",
                    )));
                }
                if decoded_stride == 0 {
                    decoded_stride = n;
                }
                decoded[out..out + n].copy_from_slice(&plain[..n]);
                out += n;
                off += stride;
            }
            data[..out].copy_from_slice(&decoded[..out]);
            meta[i].len = out;
            meta[i].stride = if decoded_stride > 0 {
                decoded_stride
            } else {
                out
            };
        }

        Poll::Ready(Ok(recv))
    }

    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}
