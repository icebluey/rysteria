/// UDP fragmentation and defragmentation.
///
/// Go equivalent: hysteria/core/internal/frag/frag.go
use crate::core::internal::protocol::UdpMessage;
use rand::RngExt;

// ──────────────────────────────────────────────────────────────────────────────
// PacketID assignment
// ──────────────────────────────────────────────────────────────────────────────

/// Generates a random packet ID for fragmented packets.
///
/// PacketID = 0 is reserved for non-fragmented packets.
/// Range: [1, 65535] (inclusive).
///
/// Go: `uint16(rand.Intn(0xFFFF)) + 1`
pub fn new_frag_packet_id() -> u16 {
    // rand.Intn(0xFFFF) → [0, 65534], +1 → [1, 65535]
    let mut rng = rand::rng();
    (rng.random_range(0u32..0xFFFF) + 1) as u16
}

// ──────────────────────────────────────────────────────────────────────────────
// Fragmentation (sender side)
// ──────────────────────────────────────────────────────────────────────────────

/// Fragments a UDP message into pieces that fit within `max_size` bytes each.
///
/// Go equivalent: `FragUDPMessage`.
///
/// If the message already fits, returns a single-element vec with a clone.
/// Caller must assign a non-zero PacketID to the returned messages beforehand
/// (this function preserves whatever pkt_id is set on the input).
pub fn frag_udp_message(m: &UdpMessage, max_size: usize) -> Vec<UdpMessage> {
    if m.size() <= max_size {
        return vec![m.clone()];
    }

    let full_payload = &m.data;
    let max_payload_size = max_size - m.header_size();
    // Ceiling division: (len + max - 1) / max
    let frag_count = (full_payload.len() + max_payload_size - 1) / max_payload_size;
    debug_assert!(
        frag_count <= 255,
        "frag_count {} exceeds u8 max (255)",
        frag_count
    );

    let mut frags = Vec::with_capacity(frag_count);
    let mut off = 0usize;
    let mut frag_id = 0u8;

    while off < full_payload.len() {
        let payload_size = (full_payload.len() - off).min(max_payload_size);
        let mut frag = m.clone();
        frag.frag_id = frag_id;
        frag.frag_count = frag_count as u8;
        frag.data = full_payload[off..off + payload_size].to_vec();
        frags.push(frag);
        off += payload_size;
        frag_id += 1;
    }
    frags
}

// ──────────────────────────────────────────────────────────────────────────────
// Defragmentation (receiver side)
// ──────────────────────────────────────────────────────────────────────────────

/// Reassembles fragmented UDP messages.
///
/// Go equivalent: `Defragger` struct and `Feed` method.
///
/// Tracks one in-flight packet at a time. If a new PacketID arrives while
/// a previous packet is incomplete, the previous state is discarded.
#[derive(Debug, Default)]
pub struct Defragger {
    pkt_id: u16,
    frags: Vec<Option<UdpMessage>>,
    count: u8,   // number of fragments received
    size: usize, // total data bytes accumulated
}

impl Defragger {
    /// Creates a new, empty defragger.
    pub fn new() -> Self {
        Self::default()
    }

    /// Feeds one fragment to the defragger.
    ///
    /// Returns `Some(assembled_message)` when all fragments have been received,
    /// or `None` if more fragments are needed (or the fragment is invalid).
    ///
    /// Go equivalent: `(*Defragger).Feed`.
    pub fn feed(&mut self, m: UdpMessage) -> Option<UdpMessage> {
        // Non-fragmented: pass through immediately (FragCount <= 1)
        if m.frag_count <= 1 {
            return Some(m);
        }

        // Invalid frag_id
        if m.frag_id >= m.frag_count {
            return None;
        }

        // New packet ID or different frag_count: reset state
        if m.pkt_id != self.pkt_id || m.frag_count as usize != self.frags.len() {
            self.pkt_id = m.pkt_id;
            self.frags = vec![None; m.frag_count as usize];
            self.size = m.data.len();
            self.count = 1;
            // Save index before moving m (frag_id is Copy but borrow checker needs the hint)
            let frag_id = m.frag_id as usize;
            self.frags[frag_id] = Some(m);
            return None;
        }

        // Same packet, new fragment — only accept if slot is empty
        if self.frags[m.frag_id as usize].is_none() {
            self.size += m.data.len();
            self.count += 1;
            self.frags[m.frag_id as usize] = Some(m.clone());

            if self.count as usize == self.frags.len() {
                // All fragments received — assemble
                let mut data = Vec::with_capacity(self.size);
                for frag in &self.frags {
                    if let Some(frag) = frag.as_ref() {
                        data.extend_from_slice(&frag.data);
                    } else {
                        return None;
                    }
                }
                // Use the last fragment as template (it carries correct session/addr)
                let mut assembled = m;
                assembled.data = data;
                assembled.frag_id = 0;
                assembled.frag_count = 1;
                return Some(assembled);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::internal::protocol::MAX_DATAGRAM_FRAME_SIZE;

    fn make_msg(data: Vec<u8>) -> UdpMessage {
        UdpMessage {
            session_id: 1,
            pkt_id: 0,
            frag_id: 0,
            frag_count: 1,
            addr: "127.0.0.1:53".to_string(),
            data,
        }
    }

    // ── FragUDPMessage ───────────────────────────────────────────────────────

    #[test]
    fn no_frag_when_small_enough() {
        let msg = make_msg(vec![0xAB; 100]);
        let frags = frag_udp_message(&msg, MAX_DATAGRAM_FRAME_SIZE as usize);
        assert_eq!(frags.len(), 1);
        assert_eq!(frags[0].data, msg.data);
    }

    #[test]
    fn frag_large_message() {
        let data = vec![0xCD; 3000];
        let msg = make_msg(data.clone());
        let frags = frag_udp_message(&msg, MAX_DATAGRAM_FRAME_SIZE as usize);

        // Must be fragmented
        assert!(frags.len() > 1);
        // All fragments have the same frag_count
        let fc = frags[0].frag_count;
        assert_eq!(fc as usize, frags.len());

        // frag_ids are consecutive
        for (i, f) in frags.iter().enumerate() {
            assert_eq!(f.frag_id as usize, i);
        }

        // Reassembled data matches original
        let reassembled: Vec<u8> = frags.iter().flat_map(|f| f.data.iter().copied()).collect();
        assert_eq!(reassembled, data);
    }

    #[test]
    fn each_frag_fits_in_max_size() {
        let max = MAX_DATAGRAM_FRAME_SIZE as usize;
        let msg = make_msg(vec![0u8; 5000]);
        let frags = frag_udp_message(&msg, max);
        for f in &frags {
            assert!(f.size() <= max, "frag size {} > max {}", f.size(), max);
        }
    }

    // ── Defragger ────────────────────────────────────────────────────────────

    #[test]
    fn non_fragmented_pass_through() {
        let mut d = Defragger::new();
        let msg = make_msg(vec![1, 2, 3]);
        let result = d.feed(msg.clone());
        assert!(result.is_some());
        assert_eq!(result.unwrap().data, vec![1, 2, 3]);
    }

    #[test]
    fn two_fragment_reassembly() {
        let mut d = Defragger::new();
        let msg = UdpMessage {
            session_id: 1,
            pkt_id: 100,
            frag_id: 0,
            frag_count: 2,
            addr: "host:1".to_string(),
            data: vec![1, 2, 3],
        };
        let msg2 = UdpMessage {
            frag_id: 1,
            data: vec![4, 5, 6],
            ..msg.clone()
        };

        assert!(d.feed(msg).is_none());
        let result = d.feed(msg2).unwrap();
        assert_eq!(result.data, vec![1, 2, 3, 4, 5, 6]);
        assert_eq!(result.frag_id, 0);
        assert_eq!(result.frag_count, 1);
    }

    #[test]
    fn new_packet_id_discards_old_state() {
        let mut d = Defragger::new();
        // Start receiving packet 100
        let f1 = UdpMessage {
            session_id: 1,
            pkt_id: 100,
            frag_id: 0,
            frag_count: 3,
            addr: "host:1".to_string(),
            data: vec![1],
        };
        d.feed(f1);

        // Interrupt with a new packet 200
        let f_new = UdpMessage {
            pkt_id: 200,
            frag_id: 0,
            frag_count: 2,
            data: vec![10],
            ..UdpMessage {
                session_id: 1,
                pkt_id: 200,
                frag_id: 0,
                frag_count: 2,
                addr: "host:1".to_string(),
                data: vec![10],
            }
        };
        assert!(d.feed(f_new).is_none());
        // Previous state (pkt_id=100) is gone; pkt_id=200 is now current
    }

    #[test]
    fn invalid_frag_id_discarded() {
        let mut d = Defragger::new();
        let bad = UdpMessage {
            session_id: 1,
            pkt_id: 42,
            frag_id: 5, // >= frag_count
            frag_count: 3,
            addr: "x:1".to_string(),
            data: vec![0],
        };
        assert!(d.feed(bad).is_none());
    }

    #[test]
    fn frag_reassembly_order_independence() {
        let data: Vec<u8> = (0u8..=15).collect();
        let msg = make_msg(data.clone());
        // Force fragmentation into 4 pieces with tiny max_size
        let max_size = msg.header_size() + 4;
        let mut frags = frag_udp_message(&msg, max_size);
        // Assign pkt_id
        for f in &mut frags {
            f.pkt_id = 999;
        }

        // Feed in reverse order
        frags.reverse();
        let mut d = Defragger::new();
        let mut result = None;
        for f in frags {
            result = d.feed(f);
        }
        assert!(result.is_some());
        assert_eq!(result.unwrap().data, data);
    }

    #[test]
    fn new_frag_packet_id_range() {
        for _ in 0..100 {
            let id = new_frag_packet_id();
            assert!(id >= 1, "pkt_id must be >= 1, got {}", id);
            // id is u16, so id <= 0xFFFF is always true by type
        }
    }
}
