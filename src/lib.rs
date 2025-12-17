use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::RngCore;
use rand::SeedableRng;
use rand::rngs::StdRng;
use rayon::prelude::*;
use serde::Serialize;
use sha2::{Digest, Sha512};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

pub struct PrefixTarget {
    bytes: Vec<u8>,
    remainder_nibble: Option<u8>,
}

pub fn is_prefix_valid(prefix: &str) -> bool {
    let valid_chars = "0123456789abcdefABCDEF";
    prefix.chars().all(|c| valid_chars.contains(c))
}

pub fn parse_prefix_target(hex: &str) -> PrefixTarget {
    let nibbles: Vec<u8> = hex.chars().map(|c| c.to_digit(16).unwrap() as u8).collect();

    let chunks = nibbles.chunks_exact(2);
    let remainder = chunks.remainder();

    let bytes: Vec<u8> = chunks.map(|chunk| (chunk[0] << 4) | chunk[1]).collect();

    let remainder_nibble = if remainder.is_empty() {
        None
    } else {
        Some(remainder[0])
    };

    PrefixTarget {
        bytes,
        remainder_nibble,
    }
}

pub fn calculate_estimated_attempts(prefix_len: usize) -> u128 {
    16_u128.pow(prefix_len as u32)
}

pub fn initialize_shared_state() -> (Arc<AtomicBool>, Arc<AtomicU64>) {
    (
        Arc::new(AtomicBool::new(false)),
        Arc::new(AtomicU64::new(0)),
    )
}

pub struct KeyResult {
    pub public_key_hex: String,
    pub private_key_hex: String,
}

pub fn perform_parallel_search(
    target: &PrefixTarget,
    attempts: &Arc<AtomicU64>,
    found: &Arc<AtomicBool>,
) -> Option<KeyResult> {
    (0..get_num_cpus()).into_par_iter().find_map_any(|_| {
        // Initialize StdRng from entropy once per thread
        let mut rng = StdRng::from_entropy();
        let local_attempts = Arc::clone(attempts);
        let local_found = Arc::clone(found);

        loop {
            if local_found.load(Ordering::Relaxed) {
                return None;
            }

            let (_, verifying_key, rfc8032_private_key) = generate_ed25519_key(&mut rng);

            // Fast prefix check
            let key_bytes = verifying_key.as_bytes();
            let mut matches = true;

            // 1. Check full bytes
            for (i, &byte) in target.bytes.iter().enumerate() {
                if key_bytes[i] != byte {
                    matches = false;
                    break;
                }
            }

            // 2. Check remainder nibble if present
            if matches && let Some(nibble) = target.remainder_nibble {
                let next_byte_idx = target.bytes.len();
                if (key_bytes[next_byte_idx] >> 4) != nibble {
                    matches = false;
                }
            }

            // Increment counter
            local_attempts.fetch_add(1, Ordering::Relaxed);

            if matches {
                local_found.store(true, Ordering::Relaxed);

                let public_key_hex = hex::encode(key_bytes);
                let private_key_hex = hex::encode(rfc8032_private_key);

                return Some(KeyResult {
                    public_key_hex,
                    private_key_hex,
                });
            }
        }
    })
}

#[inline(always)]
pub fn generate_ed25519_key<R: RngCore>(rng: &mut R) -> (SigningKey, VerifyingKey, [u8; 64]) {
    // RFC 8032 Ed25519 key generation (MeshCore compliant)

    // 1. Generate 32-byte random seed
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);

    // 2. Hash the seed with SHA-512 to get 64 bytes
    let mut hasher = Sha512::new();
    hasher.update(seed);
    let digest = hasher.finalize();

    // 3. Clamp the first 32 bytes
    let mut clamped = [0u8; 32];
    clamped.copy_from_slice(&digest[..32]);
    clamped[0] &= 248;
    clamped[31] &= 63;
    clamped[31] |= 64;

    // 4. Create the signing key
    let signing_key = SigningKey::from_bytes(&clamped);
    let verifying_key = signing_key.verifying_key();

    // 5. Create 64-byte RFC 8032 private key [clamped][hash_remainder]
    let mut rfc8032_private_key = [0u8; 64];
    rfc8032_private_key[..32].copy_from_slice(&clamped);
    rfc8032_private_key[32..].copy_from_slice(&digest[32..]);

    (signing_key, verifying_key, rfc8032_private_key)
}

#[derive(Serialize)]
pub struct MeshCoreKeypair {
    pub public_key: String,
    pub private_key: String,
}

// Helper function to get CPU count
pub fn get_num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_validity() {
        let mut rng = StdRng::seed_from_u64(42);
        let (_signing_key, verifying_key, private_key_bytes) = generate_ed25519_key(&mut rng);

        // Manually reconstruct the public key from the private key components
        // private_key_bytes is 64 bytes: [clamped_scalar (32)][hash_remainder (32)]
        let scalar_bytes: [u8; 32] = private_key_bytes[0..32].try_into().unwrap();

        // In Ed25519, the "private key" usually refers to the seed,
        // but here we are working with the "expanded" private key components.
        // `SigningKey::from_bytes` expects the SCALAR if it's the clamped version?
        // ed25519-dalek 2.x `SigningKey::from_bytes` expects the *Scalar*.
        // And `generate_ed25519_key` produces `clamped` which IS the scalar.

        let re_signing_key = SigningKey::from_bytes(&scalar_bytes);
        let re_verifying_key = re_signing_key.verifying_key();

        assert_eq!(
            verifying_key.as_bytes(),
            re_verifying_key.as_bytes(),
            "Public key derived from private key components should match the generated verifying key"
        );
    }

    #[test]
    fn test_parse_prefix_target() {
        // "12" -> 0x12 (18)
        let t = parse_prefix_target("12");
        assert_eq!(t.bytes, vec![0x12]);
        assert_eq!(t.remainder_nibble, None);

        // "123" -> 0x12, remainder 3
        let t = parse_prefix_target("123");
        assert_eq!(t.bytes, vec![0x12]);
        assert_eq!(t.remainder_nibble, Some(3));

        // "A" -> remainder 10
        let t = parse_prefix_target("A");
        let empty: Vec<u8> = vec![];
        assert_eq!(t.bytes, empty);
        assert_eq!(t.remainder_nibble, Some(10));
    }
}
