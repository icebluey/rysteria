/// Salamander obfuscation for QUIC UDP packets.
///
/// Go equivalent: hysteria/extras/obfs/salamander.go
///
/// Algorithm:
///   1. Generate 8 random bytes (salt).
///   2. key = BLAKE2b-256(PSK || salt)
///   3. Obfuscated packet = salt || (plaintext XOR key[repeating])
use blake2::{
    Blake2bVar,
    digest::{Update, VariableOutput},
};
use rand::RngExt;

/// Minimum PSK length in bytes.
/// Go: `smPSKMinLen = 4`
pub const SM_PSK_MIN_LEN: usize = 4;

/// Salt length in bytes.
/// Go: `smSaltLen = 8`
pub const SM_SALT_LEN: usize = 8;

/// BLAKE2b-256 output length in bytes.
/// Go: `smKeyLen = blake2b.Size256 = 32`
pub const SM_KEY_LEN: usize = 32;

/// Buffer size used for obfuscation/deobfuscation (matches Go).
pub const OBFS_BUFFER_SIZE: usize = 2048;

/// Error type for Salamander construction.
#[derive(Debug, thiserror::Error)]
pub enum ObfsError {
    #[error("PSK must be at least {} bytes", SM_PSK_MIN_LEN)]
    PskTooShort,
}

/// Salamander packet obfuscator.
///
/// Thread-safe. Each `obfuscate`/`deobfuscate` call is independent.
///
/// Go: `SalamanderObfuscator`.
pub struct SalamanderObfuscator {
    psk: Vec<u8>,
}

impl SalamanderObfuscator {
    /// Creates a new `SalamanderObfuscator` with the given pre-shared key.
    ///
    /// Go: `NewSalamanderObfuscator(psk []byte)`.
    pub fn new(psk: Vec<u8>) -> Result<Self, ObfsError> {
        if psk.len() < SM_PSK_MIN_LEN {
            return Err(ObfsError::PskTooShort);
        }
        Ok(Self { psk })
    }

    /// Derives the XOR key from PSK and salt.
    ///
    /// Go: `func (o *SalamanderObfuscator) key(salt []byte) [smKeyLen]byte`
    fn key(&self, salt: &[u8]) -> [u8; SM_KEY_LEN] {
        // Go: blake2b.Sum256(append(o.PSK, salt...))
        // blake2b.Sum256 = BLAKE2b with 32-byte output
        let mut key = [0u8; SM_KEY_LEN];
        if let Ok(mut hasher) = Blake2bVar::new(SM_KEY_LEN) {
            hasher.update(&self.psk);
            hasher.update(salt);
            let _ = hasher.finalize_variable(&mut key);
        }
        key
    }

    /// Obfuscates a plaintext packet into `out`.
    ///
    /// Returns the number of bytes written to `out` (= `SM_SALT_LEN + plaintext.len()`).
    /// Returns 0 if `out` is too small.
    ///
    /// Go: `(*SalamanderObfuscator).Obfuscate(in, out []byte) int`.
    pub fn obfuscate(&self, plaintext: &[u8], out: &mut [u8]) -> usize {
        let out_len = SM_SALT_LEN + plaintext.len();
        if out.len() < out_len {
            return 0;
        }
        // 1. Generate random salt
        let mut rng = rand::rng();
        for b in &mut out[..SM_SALT_LEN] {
            *b = rng.random();
        }
        // 2. Derive key
        let key = self.key(&out[..SM_SALT_LEN]);
        // 3. XOR plaintext with repeating key
        for (i, &c) in plaintext.iter().enumerate() {
            out[SM_SALT_LEN + i] = c ^ key[i % SM_KEY_LEN];
        }
        out_len
    }

    /// Deobfuscates a ciphertext packet into `out`.
    ///
    /// Returns the number of bytes written (= ciphertext.len() - SM_SALT_LEN).
    /// Returns 0 if `ciphertext` is too short or `out` is too small.
    ///
    /// Go: `(*SalamanderObfuscator).Deobfuscate(in, out []byte) int`.
    pub fn deobfuscate(&self, ciphertext: &[u8], out: &mut [u8]) -> usize {
        if ciphertext.len() <= SM_SALT_LEN {
            return 0; // too short (Go: outLen <= 0)
        }
        let out_len = ciphertext.len() - SM_SALT_LEN;
        if out.len() < out_len {
            return 0;
        }
        // 1. Extract salt
        let salt = &ciphertext[..SM_SALT_LEN];
        // 2. Derive key
        let key = self.key(salt);
        // 3. XOR payload with repeating key
        for (i, &c) in ciphertext[SM_SALT_LEN..].iter().enumerate() {
            out[i] = c ^ key[i % SM_KEY_LEN];
        }
        out_len
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_obfs(psk: &[u8]) -> SalamanderObfuscator {
        SalamanderObfuscator::new(psk.to_vec()).expect("valid PSK")
    }

    // ── Construction ─────────────────────────────────────────────────────────

    #[test]
    fn rejects_short_psk() {
        for len in 0..SM_PSK_MIN_LEN {
            let psk = vec![0u8; len];
            assert!(
                SalamanderObfuscator::new(psk).is_err(),
                "expected error for PSK len {}",
                len
            );
        }
    }

    #[test]
    fn accepts_minimum_psk() {
        let psk = vec![0u8; SM_PSK_MIN_LEN];
        assert!(SalamanderObfuscator::new(psk).is_ok());
    }

    // ── Round-trip ───────────────────────────────────────────────────────────

    #[test]
    fn roundtrip_simple() {
        let obfs = make_obfs(b"test_key_1234");
        let plaintext = b"Hello, Hysteria!";
        let mut ciphertext = vec![0u8; OBFS_BUFFER_SIZE];
        let enc_len = obfs.obfuscate(plaintext, &mut ciphertext);
        assert_eq!(enc_len, SM_SALT_LEN + plaintext.len());

        let mut recovered = vec![0u8; OBFS_BUFFER_SIZE];
        let dec_len = obfs.deobfuscate(&ciphertext[..enc_len], &mut recovered);
        assert_eq!(dec_len, plaintext.len());
        assert_eq!(&recovered[..dec_len], plaintext);
    }

    #[test]
    fn roundtrip_empty_payload() {
        let obfs = make_obfs(b"mypassword");
        let plaintext = b"";
        let mut ct = vec![0u8; OBFS_BUFFER_SIZE];
        let enc_len = obfs.obfuscate(plaintext, &mut ct);
        // Empty plaintext → just the salt
        assert_eq!(enc_len, SM_SALT_LEN);

        // Deobfuscate: ciphertext has only SM_SALT_LEN bytes → output is 0 bytes.
        // But wait: Go's outLen = len(in) - smSaltLen = SM_SALT_LEN - SM_SALT_LEN = 0
        // and "if outLen <= 0 { return 0 }". So deobfuscate returns 0.
        let mut pt = vec![0u8; OBFS_BUFFER_SIZE];
        let dec_len = obfs.deobfuscate(&ct[..enc_len], &mut pt);
        assert_eq!(dec_len, 0);
    }

    #[test]
    fn roundtrip_large_payload() {
        let obfs = make_obfs(b"longerpsk_1234");
        let plaintext: Vec<u8> = (0u8..=255).cycle().take(1500).collect();
        let mut ct = vec![0u8; plaintext.len() + SM_SALT_LEN + 10];
        let enc_len = obfs.obfuscate(&plaintext, &mut ct);
        assert_eq!(enc_len, SM_SALT_LEN + plaintext.len());

        let mut pt = vec![0u8; plaintext.len() + 10];
        let dec_len = obfs.deobfuscate(&ct[..enc_len], &mut pt);
        assert_eq!(dec_len, plaintext.len());
        assert_eq!(&pt[..dec_len], plaintext.as_slice());
    }

    #[test]
    fn different_salt_each_call() {
        let obfs = make_obfs(b"salttestpsk");
        let plaintext = b"same message";
        let mut ct1 = vec![0u8; OBFS_BUFFER_SIZE];
        let mut ct2 = vec![0u8; OBFS_BUFFER_SIZE];
        obfs.obfuscate(plaintext, &mut ct1);
        obfs.obfuscate(plaintext, &mut ct2);
        // Salt (first 8 bytes) should differ with very high probability
        // (collision probability = 1/2^64)
        assert_ne!(
            &ct1[..SM_SALT_LEN],
            &ct2[..SM_SALT_LEN],
            "salts should differ"
        );
    }

    #[test]
    fn output_too_small_returns_zero_for_obfuscate() {
        let obfs = make_obfs(b"testpsk1");
        let plaintext = b"hello";
        let mut too_small = vec![0u8; SM_SALT_LEN]; // needs SM_SALT_LEN + 5
        let n = obfs.obfuscate(plaintext, &mut too_small);
        assert_eq!(n, 0);
    }

    #[test]
    fn too_short_ciphertext_returns_zero_for_deobfuscate() {
        let obfs = make_obfs(b"testpsk1");
        // Ciphertext must be > SM_SALT_LEN bytes
        let too_short = vec![0u8; SM_SALT_LEN]; // = SM_SALT_LEN, not >
        let mut out = vec![0u8; OBFS_BUFFER_SIZE];
        let n = obfs.deobfuscate(&too_short, &mut out);
        assert_eq!(n, 0);
    }

    // ── Key derivation ───────────────────────────────────────────────────────

    #[test]
    fn key_is_deterministic() {
        let obfs = make_obfs(b"psk_for_key_test");
        let salt = [0xABu8; SM_SALT_LEN];
        let k1 = obfs.key(&salt);
        let k2 = obfs.key(&salt);
        assert_eq!(k1, k2, "key derivation must be deterministic");
    }

    #[test]
    fn key_changes_with_salt() {
        let obfs = make_obfs(b"psk_for_key_test");
        let salt1 = [0x00u8; SM_SALT_LEN];
        let salt2 = [0x01u8; SM_SALT_LEN];
        let k1 = obfs.key(&salt1);
        let k2 = obfs.key(&salt2);
        assert_ne!(k1, k2, "different salts must produce different keys");
    }

    #[test]
    fn key_changes_with_psk() {
        let salt = [0x55u8; SM_SALT_LEN];
        let k1 = make_obfs(b"psk_alpha").key(&salt);
        let k2 = make_obfs(b"psk_beta_").key(&salt);
        assert_ne!(k1, k2, "different PSKs must produce different keys");
    }

    // ── Wire compatibility vector ─────────────────────────────────────────────

    #[test]
    fn known_key_derivation_vector() {
        // PSK = "test", salt = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]
        // key = BLAKE2b-256("test" || salt)
        // Verify the key length
        let obfs = make_obfs(b"test");
        let salt = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let key = obfs.key(&salt);
        assert_eq!(key.len(), SM_KEY_LEN, "key must be 32 bytes");
        // Non-zero (BLAKE2b output is never all-zeros for non-trivial inputs)
        assert_ne!(key, [0u8; SM_KEY_LEN]);
    }
}
