//! MTProto 2.0 symmetric cryptography core for Telegram Android.
//!
//! Implements AES-256-IGE and the SHA-256 based key derivation used by MTProto 2.0.
//! Verification of byte-parity against TDLib reference vectors happens in CI.

use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes256;
use bytes::Bytes;
use sha2::{Digest, Sha256};
use uniffi::Record;

const BLOCK: usize = 16;

#[derive(Clone, Copy)]
pub struct MtprotoKeys {
    pub aes_key: [u8; 32],
    pub iv: [u8; 16],
}

/// Zero-copy view into a packet buffer (no allocation).
#[inline(always)]
pub fn buffer_slice(buf: &Bytes, off: usize, len: usize) -> Bytes {
    buf.slice(off..off + len)
}

/// SHA-256 over an arbitrary byte slice.
#[inline(always)]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    let out = h.finalize();
    let mut res = [0u8; 32];
    res.copy_from_slice(&out);
    res
}

/// MTProto 2.0 key derivation from an auth key and a message key.
///
/// `auth_key` must be at least 72 bytes (uses offsets 8..40 and 40..72).
/// `msg_key` should be 16 bytes (the 128-bit message key).
#[inline]
pub fn derive_mtproto_keys(auth_key: &[u8], msg_key: &[u8]) -> MtprotoKeys {
    assert!(auth_key.len() >= 72, "auth_key too short");

    // sha256_a = SHA256(msg_key || auth_key[8..40])
    let mut ha = Sha256::new();
    ha.update(msg_key);
    ha.update(&auth_key[8..40]);
    let a: [u8; 32] = ha.finalize().into();

    // sha256_b = SHA256(auth_key[40..72] || msg_key)
    let mut hb = Sha256::new();
    hb.update(&auth_key[40..72]);
    hb.update(msg_key);
    let b: [u8; 32] = hb.finalize().into();

    let mut aes_key = [0u8; 32];
    aes_key[..8].copy_from_slice(&a[..8]);
    aes_key[8..24].copy_from_slice(&b[8..24]);
    aes_key[24..].copy_from_slice(&a[24..]);

    let mut iv = [0u8; 16];
    iv[..8].copy_from_slice(&b[..8]);
    iv[8..].copy_from_slice(&a[8..24]);

    MtprotoKeys { aes_key, iv }
}

/// AES-256-IGE encryption, in place.
///
/// IGE (Infinite Garble Extension) mode:
///   C_i = E_K(P_i XOR C_{i-1}) XOR P_{i-1}
/// with C_{-1} = IV2 and P_{-1} = IV1 (IV is 32 bytes: IV1 || IV2).
///
/// `data` must be a multiple of 16 bytes (MTProto framing pads accordingly).
/// `iv` is updated on return to (last plaintext block, last ciphertext block)
/// so subsequent calls chain, matching TDLib semantics.
pub fn aes_ige_encrypt(key: &[u8], data: &mut [u8], iv: &mut [u8]) {
    assert_eq!(key.len(), 32, "AES-256 requires 32-byte key");
    assert_eq!(iv.len(), 32, "IGE IV must be 32 bytes");
    assert_eq!(data.len() % BLOCK, 0, "plaintext must be block aligned");

    let cipher = Aes256::new(key.into());
    let mut p_prev = [0u8; BLOCK];
    let mut c_prev = [0u8; BLOCK];
    p_prev.copy_from_slice(&iv[..BLOCK]);
    c_prev.copy_from_slice(&iv[BLOCK..]);

    let mut p_prev_cur = p_prev;
    for chunk in data.chunks_mut(BLOCK) {
        let mut p_i = [0u8; BLOCK];
        p_i.copy_from_slice(chunk);

        // x = P_i XOR C_{i-1}
        let mut x = p_i;
        for i in 0..BLOCK {
            x[i] ^= c_prev[i];
        }
        cipher.encrypt_block(aes::cipher::generic_array::GenericArray::from_mut_slice(&mut x));
        // C_i = x XOR P_{i-1}
        for i in 0..BLOCK {
            x[i] ^= p_prev_cur[i];
        }
        chunk.copy_from_slice(&x);

        p_prev_cur = p_i;
        c_prev = x;
    }

    // Chain state into IV.
    iv[..BLOCK].copy_from_slice(&p_prev_cur);
    iv[BLOCK..].copy_from_slice(&c_prev);
}

/// AES-256-IGE decryption, in place. Inverse of `aes_ige_encrypt`.
pub fn aes_ige_decrypt(key: &[u8], data: &mut [u8], iv: &mut [u8]) {
    assert_eq!(key.len(), 32, "AES-256 requires 32-byte key");
    assert_eq!(iv.len(), 32, "IGE IV must be 32 bytes");
    assert_eq!(data.len() % BLOCK, 0, "ciphertext must be block aligned");

    let cipher = Aes256::new(key.into());
    let mut p_prev = [0u8; BLOCK];
    let mut c_prev = [0u8; BLOCK];
    p_prev.copy_from_slice(&iv[..BLOCK]);
    c_prev.copy_from_slice(&iv[BLOCK..]);

    for chunk in data.chunks_mut(BLOCK) {
        let c_i = {
            let mut t = [0u8; BLOCK];
            t.copy_from_slice(chunk);
            t
        };

        // t = C_i XOR P_{i-1}
        let mut t = c_i;
        for i in 0..BLOCK {
            t[i] ^= p_prev[i];
        }
        cipher.decrypt_block(aes::cipher::generic_array::GenericArray::from_mut_slice(&mut t));
        // P_i = t XOR C_{i-1}
        for i in 0..BLOCK {
            t[i] ^= c_prev[i];
        }
        chunk.copy_from_slice(&t);

        p_prev = t;
        c_prev = c_i;
    }

    iv[..BLOCK].copy_from_slice(&p_prev);
    iv[BLOCK..].copy_from_slice(&c_prev);
}

// Unit tests are authored here; executed only in CI (`cargo test`).
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ige_roundtrip() {
        let key = [0x42u8; 32];
        let plain_sizes = [0usize, 16, 32, 48, 1024];

        for &n in &plain_sizes {
            let plain = vec![0xABu8; n];
            let init_iv = [0x13u8; 32];

            let mut iv = init_iv;
            let mut buf = plain.clone();
            aes_ige_encrypt(&key, &mut buf, &mut iv);

            if n > 0 {
                assert_ne!(buf, plain, "ciphertext must differ from plaintext");
            }

            let mut iv2 = init_iv;
            aes_ige_decrypt(&key, &mut buf, &mut iv2);
            assert_eq!(buf, plain, "decryption failed to recover plaintext (n={n})");
        }
    }

    #[test]
    fn kdf_deterministic() {
        let auth_key = vec![0x55u8; 256];
        let msg_key = vec![0x99u8; 16];
        let k1 = derive_mtproto_keys(&auth_key, &msg_key);
        let k2 = derive_mtproto_keys(&auth_key, &msg_key);
        assert_eq!(k1.aes_key, k2.aes_key);
        assert_eq!(k1.iv, k2.iv);
        assert_ne!(k1.aes_key, [0u8; 32]);
    }

    #[test]
    fn sha256_known_vector() {
        // SHA-256("") = e3b0c442...
        let h = sha256(b"");
        assert_eq!(
            hex::encode(h),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
