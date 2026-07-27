//! QR-based device provisioning box (ADR-022, add-a-device-by-QR).
//!
//! In the QR pairing flow the existing authorized device (D1) SCANS the new device's (D2) QR, so D2's
//! MLS signature key AND a fresh ephemeral X25519 public key reach D1 OPTICALLY, never over the gateway.
//! D1 signs the device certificate for the scanned key and returns the Grant SEALED to D2's ephemeral
//! public key, published to D2's reply mailbox. Because the ephemeral public key travelled optically
//! (gateway-blind), only the scanner (D1) can produce a Grant that D2 is able to open: a malicious
//! gateway can neither read the Grant nor forge a competing one (it never learns the ephemeral key it
//! would have to seal to). This yields mutual authentication from a single scan and replaces the 6-word
//! verification code.
//!
//! The box is a standard ECIES construction: a fresh SENDER ephemeral X25519 keypair, X25519 ECDH to the
//! recipient's ephemeral public key, a SHA-256 KDF binding BOTH public keys (so a box cannot be
//! re-targeted), and the crate's XChaCha20-Poly1305 AEAD (atrest::seal). Output layout:
//! `sender_ephemeral_public(32) || nonce || ciphertext`.

use crate::atrest;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

const BOX_KDF_DOMAIN: &[u8] = b"deaddrop-provision-box-v1";
const X25519_LEN: usize = 32;

fn random_32() -> Result<[u8; 32], String> {
    let mut b = [0u8; 32];
    getrandom::getrandom(&mut b).map_err(|e| format!("entropy: {e}"))?;
    Ok(b)
}

/// A fresh ephemeral X25519 keypair for ONE QR pairing attempt: `secret(32) || public(32)`. The new
/// device keeps the secret in memory only and puts the public key in its QR; both are discarded when
/// pairing finishes.
pub(crate) fn ephemeral_keypair() -> Result<Vec<u8>, String> {
    let secret = StaticSecret::from(random_32()?);
    let public = PublicKey::from(&secret);
    let mut out = Vec::with_capacity(2 * X25519_LEN);
    out.extend_from_slice(&secret.to_bytes());
    out.extend_from_slice(public.as_bytes());
    Ok(out)
}

/// Bind the AEAD key to the ECDH secret AND both ephemeral public keys, so a box is cryptographically
/// tied to this exact sender/recipient pair and cannot be spliced or re-targeted.
fn box_key(shared: &[u8], sender_pub: &[u8], recip_pub: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(BOX_KDF_DOMAIN);
    h.update(shared);
    h.update(sender_pub);
    h.update(recip_pub);
    h.finalize().into()
}

/// Seal `plaintext` to the recipient's ephemeral X25519 public key. Output:
/// `sender_ephemeral_public(32) || (nonce || ciphertext)`.
pub(crate) fn seal_to_pub(recip_pub: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let recip: [u8; 32] = recip_pub
        .try_into()
        .map_err(|_| "recipient key must be 32 bytes".to_string())?;
    let recip_key = PublicKey::from(recip);
    let eph_secret = StaticSecret::from(random_32()?);
    let eph_pub = PublicKey::from(&eph_secret);
    let shared = eph_secret.diffie_hellman(&recip_key);
    let key = box_key(shared.as_bytes(), eph_pub.as_bytes(), &recip);
    let sealed = atrest::seal(&key, plaintext)?;
    let mut out = Vec::with_capacity(X25519_LEN + sealed.len());
    out.extend_from_slice(eph_pub.as_bytes());
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// Open a sealed box with the recipient's ephemeral X25519 secret. Fails on the wrong key or tampering.
pub(crate) fn open_to_priv(recip_secret: &[u8], sealed_box: &[u8]) -> Result<Vec<u8>, String> {
    let sk: [u8; 32] = recip_secret
        .try_into()
        .map_err(|_| "recipient secret must be 32 bytes".to_string())?;
    if sealed_box.len() < X25519_LEN {
        return Err("sealed box too short".to_string());
    }
    let (sender_pub_bytes, sealed) = sealed_box.split_at(X25519_LEN);
    let sender_pub: [u8; 32] = sender_pub_bytes
        .try_into()
        .map_err(|_| "malformed sealed box".to_string())?;
    let recip = StaticSecret::from(sk);
    let recip_pub = PublicKey::from(&recip);
    let shared = recip.diffie_hellman(&PublicKey::from(sender_pub));
    let key = box_key(shared.as_bytes(), &sender_pub, recip_pub.as_bytes());
    atrest::open(&key, sealed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keypair() -> (Vec<u8>, Vec<u8>) {
        let kp = ephemeral_keypair().unwrap();
        (kp[0..32].to_vec(), kp[32..64].to_vec())
    }

    #[test]
    fn seal_open_roundtrips() {
        let (secret, public) = keypair();
        let grant = b"account-pub || epoch || cert (the sealed provisioning grant)";
        let sealed = seal_to_pub(&public, grant).unwrap();
        // Layout: sender ephemeral public (32) precedes the AEAD blob.
        assert!(sealed.len() > 32);
        assert_eq!(open_to_priv(&secret, &sealed).unwrap(), grant);
    }

    #[test]
    fn a_different_recipient_key_cannot_open_the_box() {
        let (_secret, public) = keypair();
        let (other_secret, _other_public) = keypair();
        let sealed = seal_to_pub(&public, b"grant").unwrap();
        // Only the holder of the recipient secret can open it (gateway-blind ephemeral key = unforgeable).
        assert!(open_to_priv(&other_secret, &sealed).is_err());
    }

    #[test]
    fn tampering_with_the_box_fails_to_open() {
        let (secret, public) = keypair();
        let mut sealed = seal_to_pub(&public, b"grant").unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0xff; // flip a ciphertext byte
        assert!(open_to_priv(&secret, &sealed).is_err());
        // Flipping the sender ephemeral public key also breaks the KDF binding.
        let mut sealed2 = seal_to_pub(&public, b"grant").unwrap();
        sealed2[0] ^= 0xff;
        assert!(open_to_priv(&secret, &sealed2).is_err());
    }

    #[test]
    fn two_seals_of_the_same_plaintext_differ() {
        // A fresh sender ephemeral keypair + nonce each time, so no two boxes are identical.
        let (_secret, public) = keypair();
        let a = seal_to_pub(&public, b"grant").unwrap();
        let b = seal_to_pub(&public, b"grant").unwrap();
        assert_ne!(a, b); // fresh sender ephemeral + nonce, so no two boxes are identical
    }

    #[test]
    fn a_bad_length_key_is_rejected() {
        assert!(seal_to_pub(&[0u8; 10], b"x").is_err());
        assert!(open_to_priv(&[0u8; 10], &[0u8; 64]).is_err());
        assert!(open_to_priv(&[0u8; 32], &[0u8; 4]).is_err()); // box too short
    }
}
