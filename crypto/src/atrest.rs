//! At-rest encryption primitives (M2 Layer 1, ADR-015).
//!
//! The Master Store Key (MSK) is derived from the user's passphrase with Argon2id and seals
//! the persisted MLS session state with XChaCha20-Poly1305. This AEAD is INDEPENDENT of the
//! MLS ciphersuite (ADR-007), so MLS can migrate to a post-quantum suite without touching
//! stored state. Deletion of stored state means destroying the MSK, never overwriting bytes
//! (flash caveat, NIST SP 800-88).
//!
//! HONEST LIMITS (ADR-015): the derivation is passphrase-only, so a powered-off disk image
//! permits an offline Argon2id-bounded brute-force of the passphrase. The MSK bytes are handed
//! to JS so the at-rest layer can also seal per-message history (vault.ts); in a browser there
//! is no hardware enclave, so the MSK lives in WASM/JS heap, which is best-effort to scrub.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use wasm_bindgen::prelude::*;

const NONCE_LEN: usize = 24;
const KEY_LEN: usize = 32;

// Explicit Argon2id parameters (not library defaults): the at-rest derivation is the SOLE
// barrier for a passphrase-only powered-off-disk brute-force (ADR-015), so the cost is set well
// above the OWASP minimum and is pinned here so a silent upstream default change cannot weaken
// it. ~64 MiB, 3 passes. Stated as a concrete work factor in honest-limits.
const ARGON_M_KIB: u32 = 65536; // 64 MiB
const ARGON_T_COST: u32 = 3;
const ARGON_P_COST: u32 = 1;

// Authenticated format-version byte, bound as AEAD associated data so a future version or AEAD
// change is an explicit authentication failure rather than an opaque wrong-key error.
const FORMAT_VERSION: u8 = 1;

fn argon2id() -> Result<Argon2<'static>, String> {
    let params = Params::new(ARGON_M_KIB, ARGON_T_COST, ARGON_P_COST, Some(KEY_LEN))
        .map_err(|e| format!("argon2 params: {e}"))?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

/// Derive a 32-byte MSK from a passphrase and salt using Argon2id with pinned hardened params.
pub(crate) fn derive_master_key_inner(passphrase: &str, salt: &[u8]) -> Result<[u8; KEY_LEN], String> {
    if salt.len() < 8 {
        return Err("salt must be at least 8 bytes".to_string());
    }
    let mut out = [0u8; KEY_LEN];
    argon2id()?
        .hash_password_into(passphrase.as_bytes(), salt, &mut out)
        .map_err(|e| format!("argon2: {e}"))?;
    Ok(out)
}

/// Seal `plaintext` under the MSK. Output is `nonce || ciphertext`; a format-version byte is
/// bound as authenticated associated data.
pub(crate) fn seal(msk: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = cipher_for(msk)?;
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, Payload { msg: plaintext, aad: &[FORMAT_VERSION] })
        .map_err(|_| "seal failed".to_string())?;
    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(nonce.as_slice());
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Open a `nonce || ciphertext` blob under the MSK. Fails on the wrong key, tampering, or a
/// mismatched format version.
pub(crate) fn open(msk: &[u8], sealed: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = cipher_for(msk)?;
    if sealed.len() < NONCE_LEN {
        return Err("sealed blob too short".to_string());
    }
    let (nonce_bytes, ciphertext) = sealed.split_at(NONCE_LEN);
    let nonce = XNonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, Payload { msg: ciphertext, aad: &[FORMAT_VERSION] })
        .map_err(|_| "open failed (wrong key or tampered)".to_string())
}

fn cipher_for(msk: &[u8]) -> Result<XChaCha20Poly1305, String> {
    if msk.len() != KEY_LEN {
        return Err(format!("msk must be {KEY_LEN} bytes"));
    }
    Ok(XChaCha20Poly1305::new(Key::from_slice(msk)))
}

/// Derive the MSK in WASM. Returns the 32 raw bytes; JS imports them for the per-message
/// at-rest layer (vault.ts) and passes them to Conversation.exportSealed / fromSealed.
#[wasm_bindgen(js_name = deriveMasterKey)]
pub fn derive_master_key(passphrase: &str, salt: &[u8]) -> Result<Vec<u8>, JsError> {
    derive_master_key_inner(passphrase, salt)
        .map(|k| k.to_vec())
        .map_err(|e| JsError::new(&e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_is_deterministic_per_salt() {
        let salt = b"saltsalt";
        let a = derive_master_key_inner("correct horse", salt).unwrap();
        let b = derive_master_key_inner("correct horse", salt).unwrap();
        assert_eq!(a, b);
        let c = derive_master_key_inner("correct horse", b"different").unwrap();
        assert_ne!(a, c);
        let d = derive_master_key_inner("wrong passphrase", salt).unwrap();
        assert_ne!(a, d);
    }

    #[test]
    fn seal_open_roundtrip_and_wrong_key_fails() {
        let msk = [7u8; 32];
        let sealed = seal(&msk, b"mls state bytes").unwrap();
        assert_eq!(open(&msk, &sealed).unwrap(), b"mls state bytes");

        let wrong = [9u8; 32];
        assert!(open(&wrong, &sealed).is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let msk = [3u8; 32];
        let mut sealed = seal(&msk, b"data").unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0xFF;
        assert!(open(&msk, &sealed).is_err());
    }

    // Pin the Argon2id work factor so a silent upstream default change cannot weaken the sole
    // at-rest barrier (ADR-015). If this fails, the security floor changed deliberately or not.
    #[test]
    fn argon_params_are_the_pinned_hardened_values() {
        let a = argon2id().unwrap();
        let p = a.params();
        assert_eq!(p.m_cost(), ARGON_M_KIB);
        assert_eq!(p.t_cost(), ARGON_T_COST);
        assert_eq!(p.p_cost(), ARGON_P_COST);
    }
}
