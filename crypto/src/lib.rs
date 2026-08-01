//! DEAD DROP client crypto core (M1).
//!
//! OpenMLS (RFC 9420) compiled to WASM. ALL cryptography runs in the browser; no server
//! tier ever sees plaintext or keys (brief §4.1). MLS is used for both 1:1 and groups
//! (ADR-006); a 1:1 conversation is a 2-member MLS group.
//!
//! This first slice proves the toolchain path: identity keygen (ADR-008) producing an
//! opaque, no-PII MLS credential + KeyPackage entirely in WASM. Group creation, the gated
//! mutual-accept handshake, and application-message encrypt/decrypt build on top of this.

use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use serde::Serialize;
use tls_codec::Serialize as TlsSerialize;
#[cfg(test)]
use tls_codec::Deserialize as TlsDeserialize;
use wasm_bindgen::prelude::*;

/// The MLS ciphersuite for M1.
///
/// PQ STATUS (ADR-007, verified 2026-06-26): OpenMLS 0.6 DEFINES a post-quantum hybrid
/// ciphersuite, MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519 (X-Wing = ML-KEM-768 + X25519),
/// but `openmls_rust_crypto` 0.3 does NOT implement the X-Wing KEM at runtime ("not
/// implemented: XWingKemDraft1 is not supported by the RustCrypto provider"). So PQ-hybrid is
/// not yet runnable with the default provider. M1 ships the classical ciphersuite below;
/// switching the constant to X-Wing is a one-line change once a provider implements it
/// (newer openmls_rust_crypto, or a custom HPKE provider). Tracked as the open ADR-007 item.
pub(crate) const CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

mod atrest;
mod authz;
mod conversation;
mod provision;
mod revoke;

#[derive(Serialize)]
struct Identity {
    /// Ed25519 signature public key (hex). This IS the opaque identity. No phone, no email,
    /// no PII (ADR-008 / §5.6).
    signature_public_key_hex: String,
    /// A serialized KeyPackage others use to add this identity to a conversation.
    key_package_b64: String,
}

/// Generate a fresh client identity and an initial KeyPackage, fully in WASM.
///
/// `label` is a local, non-identifying display label chosen by the user. It is NOT sent to
/// the server and is not part of the cryptographic identity; the binding identity is the
/// signature key. Recognition is by accepted key (§A.7), never by this label.
#[wasm_bindgen]
pub fn generate_identity(label: &str) -> Result<String, JsError> {
    let id = generate_identity_inner(label).map_err(|e| JsError::new(&e))?;
    serde_json::to_string(&id).map_err(|e| JsError::new(&format!("json: {e}")))
}

/// Platform-independent core so it can be exercised by a native unit test as well as WASM.
fn generate_identity_inner(label: &str) -> Result<Identity, String> {
    let provider = OpenMlsRustCrypto::default();
    let (signer, credential_with_key) = new_identity(label)?;
    let kp_bytes = fresh_key_package_bytes(&provider, &signer, credential_with_key, false)?;
    Ok(Identity {
        signature_public_key_hex: hex(signer.public()),
        key_package_b64: b64(&kp_bytes),
    })
}

/// Create an opaque MLS identity: a signature keypair plus a BasicCredential. No PII (§5.6).
pub(crate) fn new_identity(label: &str) -> Result<(SignatureKeyPair, CredentialWithKey), String> {
    let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm())
        .map_err(|e| format!("signature keygen: {e:?}"))?;
    let credential = BasicCredential::new(label.as_bytes().to_vec());
    let credential_with_key = CredentialWithKey {
        credential: credential.into(),
        signature_key: signer.public().into(),
    };
    Ok((signer, credential_with_key))
}

/// Create an AUTHORIZED MLS identity (ADR-022 P2): the device signature keypair plus a credential
/// whose identity carries the account key and an AAK-signed certificate over the device key. A
/// member receiving this device in a commit can verify it was authorized by the account holder.
pub(crate) fn new_identity_authorized(
    label: &str,
    aak: &ed25519_dalek::SigningKey,
    cert_epoch: u64,
) -> Result<(SignatureKeyPair, CredentialWithKey), String> {
    let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm())
        .map_err(|e| format!("signature keygen: {e:?}"))?;
    // The registering device certifies itself at the account's current epoch (0 at registration; a
    // recovered or post-revoke device certifies at the bumped epoch, ADR-022 P6).
    let cert = authz::sign_device_cert(aak, cert_epoch, signer.public());
    let aak_pub = authz::aak_public(aak);
    let identity = authz::encode_auth_identity(&aak_pub, cert_epoch, &cert, label.as_bytes());
    let credential_with_key = CredentialWithKey {
        credential: BasicCredential::new(identity).into(),
        signature_key: signer.public().into(),
    };
    Ok((signer, credential_with_key))
}

/// Build a KeyPackage and store its private material in `provider`. Returns the serialized
/// public KeyPackage that a peer uses to add this identity to a conversation.
///
/// `last_resort` marks the package with the MLS LastResort extension. This MUST be set for the
/// package the directory serves repeatedly (UserStore keeps exactly one `is_last_resort = 1` row and
/// re-serves it forever, with no `consumed_at` filter): without the extension OpenMLS DELETES the
/// private bundle after the first successful Welcome, so the second claim of that same row yields a
/// Welcome the recipient cannot open (`NoMatchingKeyPackage`) — silently, and with no crash or race
/// required. One-time packages stay unmarked so they are correctly consumed on first use.
pub(crate) fn fresh_key_package_bytes(
    provider: &OpenMlsRustCrypto,
    signer: &SignatureKeyPair,
    credential_with_key: CredentialWithKey,
    last_resort: bool,
) -> Result<Vec<u8>, String> {
    let builder = KeyPackage::builder();
    // A leaf node must DECLARE every extension its key package carries, or validation at the adder
    // rejects it with UnsupportedExtension. Only the last-resort package declares LastResort, so the
    // one-time packages keep the default (empty) capability set.
    let builder = if last_resort {
        builder
            .mark_as_last_resort()
            .leaf_node_capabilities(Capabilities::new(None, None, Some(&[ExtensionType::LastResort]), None, None))
    } else {
        builder
    };
    let bundle = builder
        .build(CIPHERSUITE, provider, signer, credential_with_key)
        .map_err(|e| format!("key package build: {e:?}"))?;
    bundle
        .key_package()
        .tls_serialize_detached()
        .map_err(|e| format!("serialize key package: {e:?}"))
}

/// The MLS group config used everywhere. The ratchet-tree extension is enabled so a Welcome
/// carries the tree and a joiner needs nothing out-of-band.
pub(crate) fn group_create_config() -> MlsGroupCreateConfig {
    MlsGroupCreateConfig::builder()
        .ciphersuite(CIPHERSUITE)
        .use_ratchet_tree_extension(true)
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_keygen_produces_ed25519_key_and_keypackage() {
        let id = generate_identity_inner("alice-local-label").expect("keygen");
        // Ed25519 public key is 32 bytes -> 64 hex chars. Opaque, no PII.
        assert_eq!(id.signature_public_key_hex.len(), 64);
        assert!(id.key_package_b64.len() > 0);
    }

    #[test]
    fn two_identities_differ() {
        let a = generate_identity_inner("x").expect("keygen a");
        let b = generate_identity_inner("x").expect("keygen b");
        // Fresh randomness each time, even with the same label.
        assert_ne!(a.signature_public_key_hex, b.signature_public_key_hex);
    }

    // Full 1:1 round-trip: a 1:1 conversation is a 2-member MLS group (ADR-006). Proves group
    // creation, Welcome-based join (ratchet tree carried in-band), and application messages in
    // both directions, all through OpenMLS. Everything here is what runs in the browser.
    #[test]
    fn two_party_mls_roundtrip() {
        // Alice and Bob each have their own provider (their own device/storage).
        let alice_p = OpenMlsRustCrypto::default();
        let bob_p = OpenMlsRustCrypto::default();

        let (alice_signer, alice_cwk) = new_identity("alice").unwrap();
        let (bob_signer, bob_cwk) = new_identity("bob").unwrap();

        // Bob publishes a KeyPackage; private material is stored in Bob's provider.
        let bob_kp_bytes = fresh_key_package_bytes(&bob_p, &bob_signer, bob_cwk, false).unwrap();
        let bob_kp_in = KeyPackageIn::tls_deserialize_exact(&bob_kp_bytes).unwrap();
        let bob_kp = bob_kp_in
            .validate(alice_p.crypto(), ProtocolVersion::Mls10)
            .unwrap();

        // Alice creates the group and adds Bob.
        let cfg = group_create_config();
        let mut alice_group =
            MlsGroup::new(&alice_p, &alice_signer, &cfg, alice_cwk).unwrap();

        let (_commit, welcome_out, _group_info) = alice_group
            .add_members(&alice_p, &alice_signer, &[bob_kp])
            .unwrap();
        alice_group.merge_pending_commit(&alice_p).unwrap();

        // Bob joins from the Welcome.
        let welcome_bytes = welcome_out.tls_serialize_detached().unwrap();
        let welcome_in = MlsMessageIn::tls_deserialize(&mut welcome_bytes.as_slice()).unwrap();
        let welcome = match welcome_in.extract() {
            MlsMessageBodyIn::Welcome(w) => w,
            _ => panic!("expected a Welcome"),
        };
        let staged =
            StagedWelcome::new_from_welcome(&bob_p, cfg.join_config(), welcome, None).unwrap();
        let mut bob_group = staged.into_group(&bob_p).unwrap();

        // Alice -> Bob.
        let msg = alice_group
            .create_message(&alice_p, &alice_signer, b"meet at the dead drop")
            .unwrap();
        let msg_bytes = msg.tls_serialize_detached().unwrap();
        let in_msg = MlsMessageIn::tls_deserialize(&mut msg_bytes.as_slice()).unwrap();
        let processed = bob_group
            .process_message(&bob_p, in_msg.try_into_protocol_message().unwrap())
            .unwrap();
        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(app) => {
                assert_eq!(app.into_bytes(), b"meet at the dead drop");
            }
            _ => panic!("expected an application message"),
        }

        // Bob -> Alice (proves both directions ratchet correctly).
        let reply = bob_group
            .create_message(&bob_p, &bob_signer, b"understood")
            .unwrap();
        let reply_bytes = reply.tls_serialize_detached().unwrap();
        let reply_in = MlsMessageIn::tls_deserialize(&mut reply_bytes.as_slice()).unwrap();
        let processed2 = alice_group
            .process_message(&alice_p, reply_in.try_into_protocol_message().unwrap())
            .unwrap();
        match processed2.into_content() {
            ProcessedMessageContent::ApplicationMessage(app) => {
                assert_eq!(app.into_bytes(), b"understood");
            }
            _ => panic!("expected an application message"),
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn b64(bytes: &[u8]) -> String {
    // Minimal standard base64 without pulling a crate; keeps the dependency surface small.
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(T[((n >> 18) & 63) as usize] as char);
        out.push(T[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 { T[((n >> 6) & 63) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { T[(n & 63) as usize] as char } else { '=' });
    }
    out
}
