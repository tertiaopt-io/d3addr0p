//! Account Authorization Key (AAK) device-authorization primitives (ADR-022 P2/P4).
//!
//! The AAK is a per-account Ed25519 key derived from a recovery secret that is shown to the user
//! once and NEVER sent to the server. It signs a certificate over each device's MLS signature key,
//! so any group member can verify a device was authorized by the holder of the account's AAK. This
//! closes the silent-extra-reader hole: a leaked passphrase or a compelled server cannot forge an
//! AAK signature, so an unauthorized device cannot be added to a conversation without every member's
//! crypto core rejecting the commit fail-closed.
//!
//! Each certificate carries a `cert_epoch` (an account-level monotonic counter). The gate rejects a
//! certificate whose epoch is below the account's trusted floor, so a future revoke (P6) that bumps
//! the epoch locks out devices certified under an old epoch. All certificates ship at epoch 0 today;
//! P6 owns the first bump. The field MUST exist now or revoke could not be retrofitted without
//! re-issuing every certificate and breaking the at-rest credential format.
//!
//! Provisioning (model b) uses a Short Authentication String: a 66-bit digest over the full
//! transcript (a fresh session nonce, BOTH device keys, and the cert epoch), rendered as six words by
//! the app layer. The seed-holder's signer refuses to certify any key whose SAS digest does not match
//! the one the user confirmed, so a relay cannot make the user confirm one key while another is
//! signed. Decimal codes and device-key-only binding were both found grindable/spliceable in review.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

/// Domain separation for device certificates.
const CERT_DOMAIN: &[u8] = b"deaddrop-device-cert-v1";
/// Domain separation for the provisioning short-authentication-string digest.
const SAS_DOMAIN: &[u8] = b"deaddrop-vcode-v2";
/// Domain separation for the CONTACT identity phrase (ONE account key, rendered per side). Distinct
/// from SAS_DOMAIN so a provisioning transcript can never be replayed as a contact phrase or vice
/// versa, and versioned so a future scheme change cannot silently collide with this one.
const CONTACT_IDENT_DOMAIN: &[u8] = b"deaddrop-contact-ident-v1";
/// Iteration count for the contact identity digest. Each candidate an attacker tests costs this many
/// hashes, multiplying an offline search by ~2^12 on top of the rendered width. Signal's safety
/// number uses the same trick (5200 iterations) for the same reason.
const CONTACT_IDENT_ROUNDS: u32 = 5200;

/// Marks an authorized credential identity: `magic | aak_pub(32) | cert_epoch(8) | cert(64) | label`.
/// A legacy or v1 identity lacks this magic and parses as unauthorized (fail-closed).
const AUTH_ID_MAGIC: &[u8; 4] = b"DDA2";
const AAK_PUB_LEN: usize = 32;
const EPOCH_LEN: usize = 8;
const CERT_LEN: usize = 64;
const AUTH_ID_PREFIX: usize = 4 + AAK_PUB_LEN + EPOCH_LEN + CERT_LEN;

/// Derive the Account Authorization Key from a 32-byte recovery secret. Deterministic.
pub(crate) fn aak_from_seed(seed: &[u8]) -> Result<SigningKey, String> {
    let arr: [u8; 32] = seed
        .try_into()
        .map_err(|_| "recovery secret must be 32 bytes".to_string())?;
    Ok(SigningKey::from_bytes(&arr))
}

/// The AAK public key (the account's stable cryptographic identity), 32 bytes.
pub(crate) fn aak_public(aak: &SigningKey) -> Vec<u8> {
    aak.verifying_key().to_bytes().to_vec()
}

fn cert_message(cert_epoch: u64, device_sig_key: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(CERT_DOMAIN.len() + EPOCH_LEN + device_sig_key.len());
    m.extend_from_slice(CERT_DOMAIN);
    m.extend_from_slice(&cert_epoch.to_be_bytes());
    m.extend_from_slice(device_sig_key);
    m
}

/// Sign a device authorization certificate at `cert_epoch` over the device's MLS signature key.
pub(crate) fn sign_device_cert(aak: &SigningKey, cert_epoch: u64, device_sig_key: &[u8]) -> Vec<u8> {
    aak.sign(&cert_message(cert_epoch, device_sig_key))
        .to_bytes()
        .to_vec()
}

/// Verify a device certificate. True only when `cert` is a valid AAK signature (under `aak_pub`) over
/// `(cert_epoch, device_sig_key)`. Fail-closed on any malformed input.
pub(crate) fn verify_device_cert(aak_pub: &[u8], cert_epoch: u64, device_sig_key: &[u8], cert: &[u8]) -> bool {
    let pk: [u8; 32] = match aak_pub.try_into() {
        Ok(p) => p,
        Err(_) => return false,
    };
    let vk = match VerifyingKey::from_bytes(&pk) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let sig_bytes: [u8; 64] = match cert.try_into() {
        Ok(s) => s,
        Err(_) => return false,
    };
    vk.verify_strict(&cert_message(cert_epoch, device_sig_key), &Signature::from_bytes(&sig_bytes))
        .is_ok()
}

/// The provisioning SAS digest: SHA-256 over the full transcript. Both devices compute the same value
/// regardless of role (the two device keys are sorted). The app layer renders the first 66 bits as
/// six words for the user to compare out of band.
pub(crate) fn sas_digest(session_nonce: &[u8], key_a: &[u8], key_b: &[u8], cert_epoch: u64) -> [u8; 32] {
    let (lo, hi) = if key_a <= key_b { (key_a, key_b) } else { (key_b, key_a) };
    let mut h = Sha256::new();
    h.update(SAS_DOMAIN);
    h.update(session_nonce);
    h.update(lo);
    h.update(hi);
    h.update(cert_epoch.to_be_bytes());
    h.finalize().into()
}

/// The contact identity digest: an iterated hash of ONE account's authority public key.
///
/// Per side on purpose. An earlier design hashed BOTH keys into a single shared phrase, which looked
/// symmetric and convenient and was broken: because a man in the middle chooses the key he shows to
/// each side, he does not need a preimage on a fixed phrase, only a COLLISION between two sets he
/// generates himself. That is a birthday search at half the rendered width, and at six words it was
/// hours of offline work, which defeats the exact attack this feature exists to stop.
///
/// Deriving each side's words from that side's key alone makes the honest keys FIXED targets: the
/// attacker must find a second preimage for each direction independently, and both people compare
/// both halves. The iteration count multiplies the cost of every candidate he tests.
pub(crate) fn contact_ident_digest(aak: &[u8]) -> [u8; 32] {
    let mut acc: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(CONTACT_IDENT_DOMAIN);
        h.update(aak);
        h.finalize().into()
    };
    // Each round rebinds the key, so a shortcut through the chain still has to know it.
    for _ in 0..CONTACT_IDENT_ROUNDS {
        let mut h = Sha256::new();
        h.update(CONTACT_IDENT_DOMAIN);
        h.update(acc);
        h.update(aak);
        acc = h.finalize().into();
    }
    acc
}

/// An authorized credential identity: the account key, the certificate epoch, the certificate, and
/// the local display label.
pub(crate) struct AuthIdentity {
    pub aak_pub: Vec<u8>,
    pub cert_epoch: u64,
    pub cert: Vec<u8>,
    #[allow(dead_code)] // surfaced to the UI in a later phase (roster acknowledgement)
    pub label: Vec<u8>,
}

/// Encode the structured identity carried in a device's MLS credential.
pub(crate) fn encode_auth_identity(aak_pub: &[u8], cert_epoch: u64, cert: &[u8], label: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(AUTH_ID_PREFIX + label.len());
    out.extend_from_slice(AUTH_ID_MAGIC);
    out.extend_from_slice(aak_pub);
    out.extend_from_slice(&cert_epoch.to_be_bytes());
    out.extend_from_slice(cert);
    out.extend_from_slice(label);
    out
}

/// Parse an authorized credential identity, or None for a legacy/label-only/v1 one (fail-closed).
pub(crate) fn parse_auth_identity(identity: &[u8]) -> Option<AuthIdentity> {
    if identity.len() < AUTH_ID_PREFIX || &identity[0..4] != AUTH_ID_MAGIC {
        return None;
    }
    let aak_pub = identity[4..4 + AAK_PUB_LEN].to_vec();
    let epoch_bytes: [u8; 8] = identity[4 + AAK_PUB_LEN..4 + AAK_PUB_LEN + EPOCH_LEN].try_into().ok()?;
    let cert = identity[4 + AAK_PUB_LEN + EPOCH_LEN..AUTH_ID_PREFIX].to_vec();
    Some(AuthIdentity {
        aak_pub,
        cert_epoch: u64::from_be_bytes(epoch_bytes),
        cert,
        label: identity[AUTH_ID_PREFIX..].to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aak_is_deterministic_from_the_recovery_secret() {
        let seed = [3u8; 32];
        assert_eq!(aak_public(&aak_from_seed(&seed).unwrap()), aak_public(&aak_from_seed(&seed).unwrap()));
        assert_ne!(aak_public(&aak_from_seed(&seed).unwrap()), aak_public(&aak_from_seed(&[4u8; 32]).unwrap()));
        assert!(aak_from_seed(&[0u8; 31]).is_err());
    }

    #[test]
    fn a_valid_cert_verifies_and_anything_tampered_fails() {
        let aak = aak_from_seed(&[7u8; 32]).unwrap();
        let aak_pub = aak_public(&aak);
        let device_key = [9u8; 32];
        let cert = sign_device_cert(&aak, 0, &device_key);
        assert!(verify_device_cert(&aak_pub, 0, &device_key, &cert));

        // Wrong epoch, wrong device key, wrong account key, and a tampered cert all fail.
        assert!(!verify_device_cert(&aak_pub, 1, &device_key, &cert));
        assert!(!verify_device_cert(&aak_pub, 0, &[8u8; 32], &cert));
        assert!(!verify_device_cert(&aak_public(&aak_from_seed(&[1u8; 32]).unwrap()), 0, &device_key, &cert));
        let mut bad = cert.clone();
        bad[0] ^= 0xff;
        assert!(!verify_device_cert(&aak_pub, 0, &device_key, &bad));
        assert!(!verify_device_cert(&[0u8; 10], 0, &device_key, &cert));
    }

    #[test]
    fn identity_encode_parse_roundtrips_with_epoch_and_legacy_is_unauthorized() {
        let id = encode_auth_identity(&[5u8; 32], 7, &[6u8; 64], b"phone");
        let parsed = parse_auth_identity(&id).unwrap();
        assert_eq!(parsed.aak_pub, [5u8; 32]);
        assert_eq!(parsed.cert_epoch, 7);
        assert_eq!(parsed.cert, [6u8; 64]);
        assert_eq!(parsed.label, b"phone");
        assert!(parse_auth_identity(b"just-a-label").is_none());
    }

    #[test]
    fn the_sas_digest_is_symmetric_and_binds_the_whole_transcript() {
        let nonce = [1u8; 32];
        let a = [2u8; 32];
        let b = [3u8; 32];
        // Symmetric in the two device keys (so both ends derive the same words).
        assert_eq!(sas_digest(&nonce, &a, &b, 0), sas_digest(&nonce, &b, &a, 0));
        // A different nonce, key, or epoch yields a different SAS.
        assert_ne!(sas_digest(&nonce, &a, &b, 0), sas_digest(&[9u8; 32], &a, &b, 0));
        assert_ne!(sas_digest(&nonce, &a, &b, 0), sas_digest(&nonce, &a, &[4u8; 32], 0));
        assert_ne!(sas_digest(&nonce, &a, &b, 0), sas_digest(&nonce, &a, &b, 1));
    }
}
