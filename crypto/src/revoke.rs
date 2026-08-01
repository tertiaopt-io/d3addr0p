//! Signed device revocation records (ADR-022 P7).
//!
//! WHY THIS EXISTS, and why the epoch floor could not do it. The floor (conversation.rs raise_floor /
//! effective_floor) is a LOWER BOUND on the epoch a certificate must carry. It cannot exclude a party
//! who chooses the number, and every seed-holder does: revocation is a server-side act (it burns a
//! directory row, kills sessions, deletes key packages) and cannot reach the revoked device's own disk,
//! where its copy of the account seed still sits. So a revoked seed-holder re-certified itself at
//! u32::MAX and was re-admitted by an honest device that had correctly raised its floor. That is proven
//! by `a_revoked_seed_holder_cannot_recertify_its_way_back_in` in conversation.rs.
//!
//! Exclusion needs IDENTITY, not ordering. A revocation record names the revoked device's signature key
//! and is signed by the account key, so the gate can refuse that specific device however high an epoch
//! it mints for itself. The control plane stores these blobs but cannot forge one: it holds no account
//! key. It can withhold them (a liveness failure, not an authorization one) but never fabricate.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

/// Domain separation, distinct from CERT_DOMAIN / SAS_DOMAIN / CONTACT_IDENT_DOMAIN in authz.rs so a
/// record can never be replayed as a device certificate (or vice versa) under any parse confusion.
const RR_DOMAIN: &[u8] = b"deaddrop-device-revoke-v1";
/// Fixed-length framing: no length prefixes, so there is no truncation/overflow parse class at all.
const RR_MAGIC: &[u8; 4] = b"DDR1";
const KEY_LEN: usize = 32;
const SEQ_LEN: usize = 8;
const SIG_LEN: usize = 64;
/// magic(4) | aak_pub(32) | target(32) | issued_seq(8) | sig(64)
pub(crate) const RR_LEN: usize = 4 + KEY_LEN + KEY_LEN + SEQ_LEN + SIG_LEN;

/// The signed message. `aak_pub` is bound in so a record issued by one account can never be replayed
/// under another, even if an attacker splices the blob's plaintext header.
fn rr_message(aak_pub: &[u8], target_sig_key: &[u8], issued_seq: u64) -> Vec<u8> {
    let mut m = Vec::with_capacity(RR_DOMAIN.len() + KEY_LEN + KEY_LEN + SEQ_LEN);
    m.extend_from_slice(RR_DOMAIN);
    m.extend_from_slice(aak_pub);
    m.extend_from_slice(target_sig_key);
    m.extend_from_slice(&issued_seq.to_be_bytes());
    m
}

/// Issue a revocation record for `target_sig_key`. Seed-holder only (the caller must hold the AAK).
///
/// `issued_seq` is ADVISORY: it exists so a management UI can order records for display. It is never a
/// security input, because ordering is exactly what this mechanism refuses to depend on. Two devices
/// that concurrently revoke different targets produce two records that both stand; the set is a union,
/// so there is no merge rule for a hostile server to arbitrate.
pub(crate) fn sign_revocation(aak: &SigningKey, target_sig_key: &[u8], issued_seq: u64) -> Result<Vec<u8>, String> {
    if target_sig_key.len() != KEY_LEN {
        return Err("revocation target must be a 32-byte signature key".to_string());
    }
    let aak_pub = aak.verifying_key().to_bytes().to_vec();
    let sig = aak.sign(&rr_message(&aak_pub, target_sig_key, issued_seq)).to_bytes().to_vec();
    let mut out = Vec::with_capacity(RR_LEN);
    out.extend_from_slice(RR_MAGIC);
    out.extend_from_slice(&aak_pub);
    out.extend_from_slice(target_sig_key);
    out.extend_from_slice(&issued_seq.to_be_bytes());
    out.extend_from_slice(&sig);
    Ok(out)
}

/// Verify a record against the account key we ALREADY trust, returning the revoked device's signature
/// key only on a valid signature.
///
/// `expect_aak_pub` is supplied by the caller from its own verified credential; the blob's copy is only
/// ever COMPARED against it, never trusted. There is no path that yields a target without a signature
/// check, so a caller cannot accidentally treat an unverified blob as a revocation.
pub(crate) fn verify_revocation(expect_aak_pub: &[u8], blob: &[u8]) -> Option<Vec<u8>> {
    if blob.len() != RR_LEN || &blob[0..4] != RR_MAGIC {
        return None;
    }
    let aak_pub = &blob[4..4 + KEY_LEN];
    if aak_pub != expect_aak_pub {
        return None; // a record for a DIFFERENT account says nothing about ours
    }
    let target = &blob[4 + KEY_LEN..4 + 2 * KEY_LEN];
    let seq_bytes: [u8; SEQ_LEN] = blob[4 + 2 * KEY_LEN..4 + 2 * KEY_LEN + SEQ_LEN].try_into().ok()?;
    let issued_seq = u64::from_be_bytes(seq_bytes);
    let sig_bytes: [u8; SIG_LEN] = blob[RR_LEN - SIG_LEN..].try_into().ok()?;
    let pk: [u8; KEY_LEN] = aak_pub.try_into().ok()?;
    let vk = VerifyingKey::from_bytes(&pk).ok()?;
    vk.verify_strict(&rr_message(aak_pub, target, issued_seq), &Signature::from_bytes(&sig_bytes))
        .ok()?;
    Some(target.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authz;

    fn aak(seed_byte: u8) -> SigningKey {
        authz::aak_from_seed(&[seed_byte; 32]).unwrap()
    }

    #[test]
    fn a_record_round_trips_and_names_the_revoked_device() {
        let k = aak(7);
        let target = [9u8; 32];
        let rr = sign_revocation(&k, &target, 3).unwrap();
        assert_eq!(rr.len(), RR_LEN);
        let pubk = authz::aak_public(&k);
        assert_eq!(verify_revocation(&pubk, &rr).unwrap(), target.to_vec());
    }

    #[test]
    fn a_record_from_another_account_is_refused() {
        // The whole point: the control plane may serve us anything. A record signed by a DIFFERENT
        // account key must never revoke one of OUR devices.
        let ours = aak(7);
        let theirs = aak(8);
        let target = [9u8; 32];
        let rr = sign_revocation(&theirs, &target, 1).unwrap();
        assert!(verify_revocation(&authz::aak_public(&ours), &rr).is_none());
    }

    #[test]
    fn a_tampered_or_malformed_record_is_refused() {
        let k = aak(7);
        let pubk = authz::aak_public(&k);
        let rr = sign_revocation(&k, &[9u8; 32], 1).unwrap();

        // Re-pointing the record at a different victim breaks the signature.
        let mut retargeted = rr.clone();
        retargeted[4 + KEY_LEN] ^= 0xff;
        assert!(verify_revocation(&pubk, &retargeted).is_none());

        // So does editing the advisory sequence, which is inside the signed message.
        let mut reseq = rr.clone();
        reseq[4 + 2 * KEY_LEN] ^= 0xff;
        assert!(verify_revocation(&pubk, &reseq).is_none());

        // And a forged signature, a wrong magic, and every truncation.
        let mut forged = rr.clone();
        let n = forged.len();
        forged[n - 1] ^= 0xff;
        assert!(verify_revocation(&pubk, &forged).is_none());
        let mut badmagic = rr.clone();
        badmagic[0] = b'X';
        assert!(verify_revocation(&pubk, &badmagic).is_none());
        for cut in 0..rr.len() {
            assert!(verify_revocation(&pubk, &rr[..cut]).is_none(), "truncation at {cut} must fail");
        }
    }
}
