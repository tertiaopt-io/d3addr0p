//! Stateful 1:1 conversation Session API (M1, wasm-facing).
//!
//! A `Conversation` owns ALL secret state for one MLS group (a 1:1 is a 2-member group,
//! ADR-006). Private material lives ONLY inside this struct (the OpenMlsRustCrypto provider's
//! in-memory storage and the SignatureKeyPair). All struct fields are private, so wasm-bindgen
//! emits no getters: the Ed25519 private key, HPKE init secrets, and epoch/message secrets are
//! unreachable from JS. Only opaque public handles cross the boundary: hex public keys, public
//! KeyPackages, MLS Welcomes, and application ciphertext.
//!
//! IN-MEMORY ONLY (M1). This deliberately has NO snapshot / from_snapshot / persistence. The
//! adversarial design review proved that persisting in M1 would be both incorrect and unsafe:
//!   - the receive ratchet advances in memory and is NOT written back by `process_message`, so
//!     a storage snapshot would be stale (durability bug) and a reload could re-derive keys for
//!     already-read messages (forward-secrecy break, P1/P7);
//!   - OpenMLS never stores the SignatureKeyPair, so a reloaded session could not sign;
//!   - the serialized state is plaintext private keys, which at rest violates P3/P7.
//! Persistence is therefore deferred to M2, where an AEAD-encrypting StorageProvider under a
//! destroyable master key (crypto-erase) handles all of this correctly. See ADR-016.

use std::collections::HashMap;

use ed25519_dalek::SigningKey;
use openmls::framing::errors::{MessageDecryptionError, SecretTreeError};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;
use sha2::{Digest, Sha256};
use tls_codec::Deserialize as TlsDeserialize;
use tls_codec::Serialize as TlsSerialize;
use wasm_bindgen::prelude::*;
use zeroize::Zeroize;

use crate::authz::{self, parse_auth_identity, verify_device_cert};
use crate::{fresh_key_package_bytes, group_create_config, new_identity, new_identity_authorized, CIPHERSUITE};

/// One conversation's MLS group plus the per-group state the gate and the staged-add machinery need.
/// All slots in a Conversation share ONE provider storage (OpenMLS keys group state by GroupId), so
/// holding N slots is cheap and they are cryptographically independent (separate epochs and secrets).
/// A staged commit BUILT but NOT yet merged into a group (ADR-022 concurrency): while set, this device
/// stays on epoch N until it learns which epoch-N commit the FIFO gateway ordered first. `receive_inner`
/// compares `commit()` to recognize our OWN echoed commit (confirm by merging) from a competing commit
/// that won the race (abort by clearing, then adopt theirs). Add and Remove share the single OpenMLS
/// pending-commit slot per group. PERSISTED across reloads via the sealed container's trailing pendings
/// section (the wire bytes are unreproducible), paired with the StagedCommit OpenMLS keeps in storage, so
/// a committer that crashes mid-confirmation resumes the same commit instead of forking itself.
enum Pending {
    // `welcome` rides along so a reloaded committer can re-deliver it: a crash BEFORE the publish would
    // otherwise confirm the roster while the added device never receives its (unreproducible) Welcome.
    Add { commit: Vec<u8>, welcome: Vec<u8>, added: Vec<u8> },
    Remove { commit: Vec<u8>, removed: Vec<u8> },
}
impl Pending {
    fn commit(&self) -> &[u8] {
        match self {
            Pending::Add { commit, .. } | Pending::Remove { commit, .. } => commit,
        }
    }
    /// The (added, removed) membership delta to surface when this staged commit merges.
    fn membership(&self) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
        match self {
            Pending::Add { added, .. } => (vec![added.clone()], vec![]),
            Pending::Remove { removed, .. } => (vec![], vec![removed.clone()]),
        }
    }
}

/// How many throwaway encrypts one epoch may spend flushing the receive ratchet. OpenMLS peers accept a
/// send-generation jump up to `maximum_forward_distance` (1000 by default), so this stays far below it:
/// even a conversation where we only ever listen keeps every peer able to decrypt our next real message.
const FLUSH_BURN_BUDGET: u32 = 200;

pub(crate) struct GroupSlot {
    group: MlsGroup,
    // The account keys trusted in THIS conversation (this account plus the peer), each with a minimum
    // certificate epoch. Established from this group's roster at bootstrap/join. A commit that adds a
    // device into this group must present a certificate under one of these AND at or above its floor, or
    // the gate rejects it. Empty => unauthorized mode (gate off) for the legacy 2-member path. PER-GROUP:
    // a different conversation has a different roster and so a different trusted set.
    trusted_aaks: Vec<(Vec<u8>, u64)>,
    // A staged Add or Remove commit awaiting confirmation (see the Pending enum above). PER-GROUP: each
    // conversation can have one commit in flight independently. Persisted across reloads (the sealed
    // container's pendings section + the StagedCommit in provider storage) so a mid-confirm crash resumes
    // the SAME commit rather than re-staging a distinct one and forking.
    pending: Option<Pending>,
    // How many throwaway encrypts flush_receive_ratchet has spent on THIS group IN flush_epoch. Each one
    // advances our own send generation by 1, and a peer refuses a jump beyond its forward distance (1000
    // by default), so the cap keeps us inside that window. A real send does NOT reset it (see the NOTE in
    // encrypt_inner: our own send proves nothing about what the peer received). Both fields are persisted,
    // or the cap would silently become per page load.
    flush_burns: u32,
    // The MLS epoch flush_burns was counted in. Generations restart at 0 in a new epoch, so the budget is
    // scoped to one epoch and refills when the group advances to the next. Without this the count only
    // ever rose and the protection permanently disabled itself after 200 flushes in the group's LIFETIME.
    flush_epoch: u64,
}

#[wasm_bindgen]
pub struct Conversation {
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    credential: CredentialWithKey,
    // The open conversations, keyed by MLS group id bytes. One device holds MANY groups at once (one per
    // conversation); the device identity below is shared across all of them. Replaces the former single
    // `group: Option<MlsGroup>`.
    groups: HashMap<Vec<u8>, GroupSlot>,
    // The local label, kept so a reloaded session can rebuild the credential. Non-PII.
    label: Vec<u8>,
    // Account Authorization Key (ADR-022 P2): present for an authorized identity. It signs this
    // account's device certs and is the root the gate verifies added devices against. None for a
    // legacy/unauthorized identity (the pre-multi-device 2-member path). DEVICE-GLOBAL.
    aak: Option<SigningKey>,
    // The HIGH-WATER certificate epoch ever seen for each account (ADR-022 P6, anti-rollback). DEVICE-
    // GLOBAL and monotonic: unlike a slot's trusted_aaks (recomputed per conversation from the roster, so
    // a stale or server-deflated roster could LOWER it), this only ever RISES and persists across
    // reloads, ACROSS ALL GROUPS. The gate floors at the MAX of the two, so once this device has seen an
    // account at epoch N in ANY conversation, a compelled server or an offline device cannot walk it back
    // below N to re-admit a revoked, old-epoch device in ANOTHER conversation. First contact is
    // trust-on-first-use (acknowledged out of band, P7).
    account_floors: Vec<(Vec<u8>, u64)>,
    // ADR-022 P7: the signed revocation records this device has accepted for OUR OWN account, as raw
    // 140-byte blobs (see revoke.rs). DEVICE-GLOBAL and APPEND-ONLY: a record, once verified, is never
    // dropped, so a hostile control plane can withhold records (a liveness failure that leaves the old
    // floor behavior in place) but can never retract one it has already served.
    //
    // This is what actually EXCLUDES a device. account_floors above is a lower bound and cannot: a
    // revoked seed-holder still has the account seed on its own disk and simply re-certifies itself at
    // a higher epoch. The floor is kept because it still defends the cert-only majority against a
    // rollback of their credentials, but authorization now turns on identity, not ordering.
    revocations: Vec<Vec<u8>>,
}

/// The most revocation records one device will hold for its account. Mirrors the control plane's own
/// cap (UserStore::MAX_REVOCATIONS). Generous, because a record only exists because a real device was
/// revoked, but finite, so the gate's per-add verification cost is bounded no matter what is served.
const MAX_REVOCATIONS: usize = 512;

/// Prefix on a `receive` error message that marks the frame PERMANENTLY unprocessable, so the client
/// acks it (drops it from the bus) instead of holding it for redelivery. Mirrored in the client as
/// the poison-drop marker. See receive_inner.
const DROP_PREFIX: &str = "drop:";

fn js(e: String) -> JsError {
    JsError::new(&e)
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

// Stable, dependency-free length-prefixed container for the sealed export: the storage map
// entries (binary keys/values), the serialized signer, the label, and the group id. This is
// decoded only AFTER the AEAD authenticates the blob, but it is still written defensively
// against self-corruption (no overflow, no attacker-controlled allocation).
fn put_bytes(out: &mut Vec<u8>, b: &[u8]) -> Result<(), String> {
    let len = u32::try_from(b.len()).map_err(|_| "container section too large".to_string())?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(b);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn encode_container(
    entries: &[(Vec<u8>, Vec<u8>)],
    signer: &[u8],
    label: &[u8],
    gid: &[u8],
    aak_seed: &[u8],
    trusted: &[Vec<u8>],
    cred_identity: &[u8],
    account_floors: &[Vec<u8>],
    // Multi-group (the conversations): each as (group_id, [aak_pub||epoch]). New writers leave the legacy
    // single `gid`/`trusted` above EMPTY and put every conversation here; old single-group blobs carry the
    // legacy `gid`/`trusted` and have no entry here. Appended after the floors, so old readers stop before it.
    groups: &[(Vec<u8>, Vec<Vec<u8>>)],
    // Staged commits awaiting confirmation, one per conversation at most: (group_id, kind [1=Add 2=Remove],
    // target device signature key, the OUTGOING commit wire bytes, the Welcome wire bytes [empty for a
    // Remove]). OpenMLS persists the StagedCommit's post-merge diff in the storage entries above, but NOT
    // the outgoing ciphertexts (randomized, unreproducible), and the echo-confirm path matches on exact
    // bytes, so a reloaded committer needs the original wire bytes both to recognize its own echo and to
    // re-publish the commit AND the added device's Welcome. Appended LAST, so pre-fix readers stop before
    // it and pre-fix blobs simply lack it (decode returns empty).
    pendings: &[(Vec<u8>, u8, Vec<u8>, Vec<u8>, Vec<u8>)],
    // Per-group flush counters (group_id, burns, epoch). Appended after the pendings; see the write site.
    flush_burns: &[(Vec<u8>, u32, u64)],
    // ADR-022 P7: the accepted signed revocation records, raw blobs. Appended after the flush counters.
    revocations: &[Vec<u8>],
) -> Result<Vec<u8>, String> {
    let count = u32::try_from(entries.len()).map_err(|_| "too many entries".to_string())?;
    let mut out = Vec::new();
    out.extend_from_slice(&count.to_be_bytes());
    for (k, v) in entries {
        put_bytes(&mut out, k)?;
        put_bytes(&mut out, v)?;
    }
    put_bytes(&mut out, signer)?;
    put_bytes(&mut out, label)?;
    put_bytes(&mut out, gid)?;
    // ADR-022 P2: persist the account key (so a reloaded device can still authorize) and the trusted
    // account keys (so the gate survives reload). Appended after gid; older blobs lack them.
    put_bytes(&mut out, aak_seed)?;
    let tcount = u32::try_from(trusted.len()).map_err(|_| "too many trusted keys".to_string())?;
    out.extend_from_slice(&tcount.to_be_bytes());
    for t in trusted {
        put_bytes(&mut out, t)?;
    }
    // ADR-022 P6: persist the FULL authorized credential identity (magic|aak|epoch|cert|label), so a
    // reloaded seed-holder keeps its certificate (and its cert epoch) instead of falling back to a
    // label-only, unauthorized credential. Appended after the trusted set; older blobs lack it.
    put_bytes(&mut out, cred_identity)?;
    // ADR-022 P6 anti-rollback: persist the high-water epoch floor per account (each aak_pub || epoch),
    // so it survives reload and a deflated roster cannot walk it back. Appended last.
    let fcount = u32::try_from(account_floors.len()).map_err(|_| "too many floors".to_string())?;
    out.extend_from_slice(&fcount.to_be_bytes());
    for f in account_floors {
        put_bytes(&mut out, f)?;
    }
    // Multi-group conversations (each: group_id, then a length-prefixed list of aak_pub||epoch trusted
    // entries). Appended last so an older single-group reader stops before it (forward-compat is not a
    // goal; the PWA auto-updates). New readers build the per-group slots from this section.
    let gcount = u32::try_from(groups.len()).map_err(|_| "too many groups".to_string())?;
    out.extend_from_slice(&gcount.to_be_bytes());
    for (g, trusted_entries) in groups {
        put_bytes(&mut out, g)?;
        let tc = u32::try_from(trusted_entries.len()).map_err(|_| "too many trusted keys".to_string())?;
        out.extend_from_slice(&tc.to_be_bytes());
        for t in trusted_entries {
            put_bytes(&mut out, t)?;
        }
    }
    // Staged pending commits, appended LAST (see the param doc above). Each: gid, kind (one byte), target
    // signature key, outgoing commit wire bytes, Welcome wire bytes (empty for a Remove).
    let pcount = u32::try_from(pendings.len()).map_err(|_| "too many pending commits".to_string())?;
    out.extend_from_slice(&pcount.to_be_bytes());
    for (g, kind, target, commit, welcome) in pendings {
        put_bytes(&mut out, g)?;
        put_bytes(&mut out, &[*kind])?;
        put_bytes(&mut out, target)?;
        put_bytes(&mut out, commit)?;
        put_bytes(&mut out, welcome)?;
    }
    // Per-group receive-ratchet flush counters, appended LAST. These MUST survive a reload: each flush
    // spends one of our MLS send generations, and the cap is the only thing keeping us inside the peer's
    // forward-distance window. Held only in memory, the cap silently became "per page load" while the
    // generation itself rode along inside the storage entries above, so a device that only ever listens
    // drifted past the peer's limit and its eventual first real message became undecryptable by everyone,
    // permanently and silently. A blob written before this section simply lacks it and decodes to empty,
    // which restarts the count: acceptable once, catastrophic every reload.
    let bcount = u32::try_from(flush_burns.len()).map_err(|_| "too many burn counters".to_string())?;
    out.extend_from_slice(&bcount.to_be_bytes());
    for (g, burns, epoch) in flush_burns {
        put_bytes(&mut out, g)?;
        out.extend_from_slice(&burns.to_be_bytes());
        // The epoch the count belongs to. Without it a reload could not tell a spent budget from one the
        // group has since moved past, and restoring the count alone would strand the group permanently.
        out.extend_from_slice(&epoch.to_be_bytes());
    }
    // ADR-022 P7 revocation records, appended LAST. These are the account's DENYLIST and are the only
    // thing that actually excludes a revoked seed-holder (the epoch floor above is a lower bound and a
    // seed-holder simply mints above it). They MUST survive reload: losing them re-opens the hole until
    // the next successful fetch from a control plane that is free to stall. Each is a self-verifying
    // 140-byte blob, so a lost or truncated section degrades to "not yet known", never to a forgery.
    let rcount = u32::try_from(revocations.len()).map_err(|_| "too many revocations".to_string())?;
    out.extend_from_slice(&rcount.to_be_bytes());
    for r in revocations {
        put_bytes(&mut out, r)?;
    }
    Ok(out)
}

fn take_u32(b: &[u8], pos: &mut usize) -> Result<usize, String> {
    // Compare against remaining length rather than summing, so nothing can overflow on wasm32.
    if b.len() - *pos < 4 {
        return Err("container truncated".to_string());
    }
    let n = u32::from_be_bytes(b[*pos..*pos + 4].try_into().unwrap()) as usize;
    *pos += 4;
    Ok(n)
}

fn take_u64(b: &[u8], pos: &mut usize) -> Result<u64, String> {
    if b.len() - *pos < 8 {
        return Err("container truncated".to_string());
    }
    let n = u64::from_be_bytes(b[*pos..*pos + 8].try_into().unwrap());
    *pos += 8;
    Ok(n)
}

fn take_bytes(b: &[u8], pos: &mut usize) -> Result<Vec<u8>, String> {
    let n = take_u32(b, pos)?;
    if b.len() - *pos < n {
        return Err("container truncated".to_string());
    }
    let v = b[*pos..*pos + n].to_vec();
    *pos += n;
    Ok(v)
}

/// Decode the trailing staged-pendings section leniently: any malformed or truncated entry yields an
/// EMPTY list rather than an error, because this section is an optional recovery hint and a decode
/// failure here must never brick the whole vault (see the call site in decode_container).
/// Returns the staged pendings AND the offset just past them, so the trailing flush-counter section can
/// be read next. On a malformed tail it yields an empty list and an offset PAST THE END of the buffer,
/// which is what actually makes the following section decode as empty. Returning the original offset
/// (an earlier cut) did not: the burns decoder would have read the pendings bytes it just rejected and
/// could interpret them as a valid section.
fn decode_pendings(b: &[u8], mut pos: usize) -> (Vec<(Vec<u8>, u8, Vec<u8>, Vec<u8>, Vec<u8>)>, usize) {
    let start = pos;
    let parse = |pos: &mut usize| -> Result<Vec<(Vec<u8>, u8, Vec<u8>, Vec<u8>, Vec<u8>)>, String> {
        if *pos >= b.len() {
            return Ok(Vec::new());
        }
        let pcount = take_u32(b, pos)?;
        let mut pendings = Vec::new();
        for _ in 0..pcount {
            let g = take_bytes(b, pos)?;
            let kind_bytes = take_bytes(b, pos)?;
            let target = take_bytes(b, pos)?;
            let commit = take_bytes(b, pos)?;
            let welcome = take_bytes(b, pos)?;
            let kind = *kind_bytes.first().ok_or_else(|| "empty pending kind".to_string())?;
            pendings.push((g, kind, target, commit, welcome));
        }
        Ok(pendings)
    };
    let _ = start;
    match parse(&mut pos) {
        Ok(p) => (p, pos),
        Err(_) => (Vec::new(), b.len()), // past the end: the next section decodes as empty, not garbage
    }
}

/// The per-group receive-ratchet flush counters written by encode_container. Absent (older blob) or
/// malformed decodes to empty, which restarts the count for that group. Returns the offset just past
/// the section so the trailing revocations can be read next; on a malformed tail the offset is PAST THE
/// END, so the next section decodes as empty rather than re-reading the bytes just rejected (the same
/// discipline as decode_pendings).
fn decode_flush_burns(b: &[u8], mut pos: usize) -> (Vec<(Vec<u8>, u32, u64)>, usize) {
    let parse = |pos: &mut usize| -> Result<Vec<(Vec<u8>, u32, u64)>, String> {
        if *pos >= b.len() {
            return Ok(Vec::new());
        }
        let bcount = take_u32(b, pos)?;
        let mut out = Vec::new();
        for _ in 0..bcount {
            let g = take_bytes(b, pos)?;
            let burns = u32::try_from(take_u32(b, pos)?).map_err(|_| "burn count overflow".to_string())?;
            let epoch = take_u64(b, pos)?;
            out.push((g, burns, epoch));
        }
        Ok(out)
    };
    match parse(&mut pos) {
        Ok(v) => (v, pos),
        Err(_) => (Vec::new(), b.len()),
    }
}

/// The trailing ADR-022 P7 revocation-record section. Absent (an older blob) or malformed decodes to
/// EMPTY rather than Err, for the same reason decode_pendings is lenient: a hard failure here would
/// fail the whole from_sealed and drop the device to a fresh identity, which is strictly worse than
/// re-fetching the records from the control plane. Every record is re-verified against our own account
/// key at ingest, so an empty or partial read costs liveness, never soundness.
fn decode_revocations(b: &[u8], mut pos: usize) -> Vec<Vec<u8>> {
    let parse = |pos: &mut usize| -> Result<Vec<Vec<u8>>, String> {
        if *pos >= b.len() {
            return Ok(Vec::new());
        }
        let rcount = take_u32(b, pos)?;
        let mut out = Vec::new();
        for _ in 0..rcount {
            out.push(take_bytes(b, pos)?);
        }
        Ok(out)
    };
    parse(&mut pos).unwrap_or_default()
}

type DecodedContainer = (
    Vec<(Vec<u8>, Vec<u8>)>, // storage entries
    Vec<u8>,                 // signer
    Vec<u8>,                 // label
    Vec<u8>,                 // legacy single group id (empty for a new multi-group blob)
    Vec<u8>,                 // aak seed
    Vec<Vec<u8>>,            // legacy single trusted set (empty for a new multi-group blob)
    Vec<u8>,                 // credential identity
    Vec<Vec<u8>>,            // account floors (device-global)
    Vec<(Vec<u8>, Vec<Vec<u8>>)>, // multi-group conversations: (group_id, [aak_pub||epoch])
    Vec<(Vec<u8>, u8, Vec<u8>, Vec<u8>, Vec<u8>)>, // staged pendings: (group_id, kind, target, commit, welcome)
    Vec<(Vec<u8>, u32, u64)>, // per-group receive-ratchet flush counters (group_id, burns, epoch)
    Vec<Vec<u8>>,            // ADR-022 P7 signed revocation records (raw blobs, re-verified at load)
);

/// One conversation's reload metadata: its group id and its parsed (account, epoch) trusted set.
type GroupMeta = (Vec<u8>, Vec<(Vec<u8>, u64)>);

#[allow(clippy::type_complexity)]
fn decode_container(b: &[u8]) -> Result<DecodedContainer, String> {
    let mut pos = 0;
    let n = take_u32(b, &mut pos)?;
    // No with_capacity(n): a bogus count must not pre-allocate. The loop is bounded by the
    // truncation checks in take_bytes.
    let mut entries = Vec::new();
    for _ in 0..n {
        let k = take_bytes(b, &mut pos)?;
        let v = take_bytes(b, &mut pos)?;
        entries.push((k, v));
    }
    let signer = take_bytes(b, &mut pos)?;
    let label = take_bytes(b, &mut pos)?;
    let gid = take_bytes(b, &mut pos)?;
    // Back-compat: a pre-multi-device blob ends after gid. A newer blob appends the AAK seed and the
    // trusted account keys.
    let (aak_seed, trusted) = if pos < b.len() {
        let seed = take_bytes(b, &mut pos)?;
        let tcount = take_u32(b, &mut pos)?;
        let mut trusted = Vec::new();
        for _ in 0..tcount {
            trusted.push(take_bytes(b, &mut pos)?);
        }
        (seed, trusted)
    } else {
        (Vec::new(), Vec::new())
    };
    // Back-compat: a blob written before P6 ends after the trusted keys. A newer blob appends the
    // authorized credential identity so the certificate (and its epoch) survive reload.
    let cred_identity = if pos < b.len() { take_bytes(b, &mut pos)? } else { Vec::new() };
    // Back-compat: the high-water account floors are appended last; a blob written before anti-rollback
    // lacks them (the floors then seed from the credential's own epoch on first recompute).
    let account_floors = if pos < b.len() {
        let fcount = take_u32(b, &mut pos)?;
        let mut floors = Vec::new();
        for _ in 0..fcount {
            floors.push(take_bytes(b, &mut pos)?);
        }
        floors
    } else {
        Vec::new()
    };
    // Back-compat: the multi-group conversations section is appended last. An old single-group blob ends
    // after account_floors (no section here, and its legacy `gid`/`trusted` above carry its one group).
    let groups = if pos < b.len() {
        let gcount = take_u32(b, &mut pos)?;
        let mut groups = Vec::new();
        for _ in 0..gcount {
            let g = take_bytes(b, &mut pos)?;
            let tc = take_u32(b, &mut pos)?;
            let mut tser = Vec::new();
            for _ in 0..tc {
                tser.push(take_bytes(b, &mut pos)?);
            }
            groups.push((g, tser));
        }
        groups
    } else {
        Vec::new()
    };
    // Back-compat: the staged pending commits are appended last; a blob written before the crash-window
    // fix simply ends after the groups (the reloaded device then has no pending, exactly as before).
    // LENIENT by design: the pendings section is the ONLY optional recovery hint, and it is strictly less
    // important than the account identity + groups decoded above. A malformed or truncated pendings
    // section (which no correct writer produces, but a future writer bug might) must NEVER fail the whole
    // decode: a failed from_sealed makes loadSelf fall back to a FRESH identity and the login flow then
    // reseals over the real vault within seconds. So any error inside this section degrades to "no
    // pending" (equivalent to the pre-fix self-heal), never Err.
    let (pendings, after_pendings) = decode_pendings(b, pos);
    let (flush_burns, after_burns) = decode_flush_burns(b, after_pendings);
    let revocations = decode_revocations(b, after_burns);
    Ok((entries, signer, label, gid, aak_seed, trusted, cred_identity, account_floors, groups, pendings, flush_burns, revocations))
}

/// A length-prefixed list of byte strings (count, then each as u32-len + bytes), used to pass a list
/// of KeyPackages in and return the (commit, welcome) pair out across the wasm boundary.
fn encode_list(items: &[Vec<u8>]) -> Result<Vec<u8>, String> {
    let count = u32::try_from(items.len()).map_err(|_| "too many items".to_string())?;
    let mut out = Vec::new();
    out.extend_from_slice(&count.to_be_bytes());
    for it in items {
        put_bytes(&mut out, it)?;
    }
    Ok(out)
}

fn decode_list(b: &[u8], pos: &mut usize) -> Result<Vec<Vec<u8>>, String> {
    let n = take_u32(b, pos)?;
    let mut items = Vec::new();
    for _ in 0..n {
        items.push(take_bytes(b, pos)?);
    }
    Ok(items)
}

fn hex_to_bytes(s: &str) -> Result<Vec<u8>, String> {
    // Operate on raw bytes with a nibble validator: never index a &str by a len()-derived range,
    // which would panic on a non-ASCII char boundary (a wasm trap, violating the crate's fail-closed
    // "Errs, never panics" contract). Any non-hex byte returns Err.
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return Err("odd hex length".to_string());
    }
    fn nibble(b: u8) -> Result<u8, String> {
        match b {
            b'0'..=b'9' => Ok(b - b'0'),
            b'a'..=b'f' => Ok(b - b'a' + 10),
            b'A'..=b'F' => Ok(b - b'A' + 10),
            _ => Err("bad hex".to_string()),
        }
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        out.push((nibble(pair[0])? << 4) | nibble(pair[1])?);
    }
    Ok(out)
}

/// Collect the (account key, minimum certificate epoch) pairs trusted by a group's roster: an account
/// is included iff at least one of its devices presents a credential whose AAK certificate verifies over
/// that device's signature key. A free function (no &self) so the per-group recompute can call it while
/// holding only an immutable borrow of one slot, then update the device-global floors separately.
fn gather_roster_trusted(group: &MlsGroup) -> Vec<(Vec<u8>, u64)> {
    let mut trusted: Vec<(Vec<u8>, u64)> = Vec::new();
    for m in group.members() {
        let identity = match BasicCredential::try_from(m.credential.clone()) {
            Ok(bc) => bc.identity().to_vec(),
            Err(_) => continue,
        };
        if let Some(ai) = parse_auth_identity(&identity) {
            if verify_device_cert(&ai.aak_pub, ai.cert_epoch, &m.signature_key, &ai.cert) {
                // The per-conversation floor is the lowest valid certificate epoch present for the
                // account; P6 raises it on revoke and re-issuance.
                match trusted.iter_mut().find(|(k, _)| k == &ai.aak_pub) {
                    Some(entry) => {
                        if ai.cert_epoch < entry.1 {
                            entry.1 = ai.cert_epoch;
                        }
                    }
                    None => trusted.push((ai.aak_pub, ai.cert_epoch)),
                }
            }
        }
    }
    trusted
}

/// The result of receiving one inbound MLS message in the N-member group: it may be application
/// data, a membership change we ingest (with the added/removed signature keys for the caller's
/// authorization check), our own eviction, or a bare proposal we do not adopt.
#[derive(Debug)]
pub(crate) enum Received {
    /// An application message, with whether its MLS-authenticated sender is a device of OUR OWN account
    /// (so the caller can adopt an own-identity update from a sibling, vs storing a peer's). The flag is
    /// crypto-authenticated: the sender leaf signed the message and its credential carries the sender's
    /// account key, which the gate already vetted. A peer cannot forge being our account.
    Application { plaintext: Vec<u8>, from_own_account: bool },
    MembershipChanged { added: Vec<Vec<u8>>, removed: Vec<Vec<u8>> },
    Evicted,
    Proposal,
}

/// Encode a `Received` for JS: a one-byte tag then the payload. 0=application (flag byte 1=from our own
/// account, then plaintext), 1=membership change (added list then removed list), 2=evicted, 3=proposal.
fn encode_received(r: &Received) -> Result<Vec<u8>, String> {
    Ok(match r {
        Received::Application { plaintext, from_own_account } => {
            let mut o = vec![0u8, u8::from(*from_own_account)];
            o.extend_from_slice(plaintext);
            o
        }
        Received::MembershipChanged { added, removed } => {
            let mut o = vec![1u8];
            o.extend_from_slice(&encode_list(added)?);
            o.extend_from_slice(&encode_list(removed)?);
            o
        }
        Received::Evicted => vec![2u8],
        Received::Proposal => vec![3u8],
    })
}

/// The provisioning verification-code digest (ADR-022 P4, model b), exposed so the app renders the
/// SAME value the seed-holder's signer guard recomputes. Inputs: the session nonce, the account
/// public key, the new device's signature key (all hex), and the certificate epoch. The app maps the
/// returned 32-byte digest's first 66 bits to six words for the user to compare out of band.
#[wasm_bindgen(js_name = sasDigestHex)]
pub fn sas_digest_hex(
    session_nonce_hex: &str,
    account_pub_hex: &str,
    device_key_hex: &str,
    cert_epoch: u32,
) -> Result<String, JsError> {
    let nonce = hex_to_bytes(session_nonce_hex).map_err(js)?;
    let account_pub = hex_to_bytes(account_pub_hex).map_err(js)?;
    let device_key = hex_to_bytes(device_key_hex).map_err(js)?;
    Ok(hex(&authz::sas_digest(&nonce, &account_pub, &device_key, u64::from(cert_epoch))))
}

/// The contact identity digest for ONE account key (hex). Each side of a conversation renders its own
/// key's words and both people compare both halves, so a man in the middle faces two independent
/// second preimages against fixed targets rather than one birthday collision he controls. Rejects
/// anything that is not exactly a 32-byte key, so a truncated or empty value can never render a
/// confident-looking phrase.
#[wasm_bindgen(js_name = contactIdentDigestHex)]
pub fn contact_ident_digest_hex(aak_hex: &str) -> Result<String, JsError> {
    let a = hex_to_bytes(aak_hex).map_err(js)?;
    if a.len() != 32 {
        return Err(js("contact identity digest needs a 32-byte account key".to_string()));
    }
    Ok(hex(&authz::contact_ident_digest(&a)))
}

/// Generate a fresh ephemeral X25519 keypair for a QR pairing attempt: `secret(32) || public(32)`. The
/// new device keeps the secret in memory and puts the public key in its QR (add-a-device-by-QR).
#[wasm_bindgen(js_name = provisionEphemeralKeypair)]
pub fn provision_ephemeral_keypair() -> Result<Vec<u8>, JsError> {
    crate::provision::ephemeral_keypair().map_err(js)
}

/// Seal a provisioning grant to the new device's ephemeral X25519 public key. Output layout:
/// `sender_ephemeral_public(32) || nonce || ciphertext`. Only the holder of the matching ephemeral
/// secret can open it, so a gateway that never saw the (optically transmitted) public key cannot forge
/// or read it.
#[wasm_bindgen(js_name = provisionSealToPub)]
pub fn provision_seal_to_pub(recip_pub: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, JsError> {
    crate::provision::seal_to_pub(recip_pub, plaintext).map_err(js)
}

/// Open a sealed provisioning grant with the recipient device's ephemeral X25519 secret. Fails on the
/// wrong key or any tampering.
#[wasm_bindgen(js_name = provisionOpenToPriv)]
pub fn provision_open_to_priv(recip_secret: &[u8], sealed_box: &[u8]) -> Result<Vec<u8>, JsError> {
    crate::provision::open_to_priv(recip_secret, sealed_box).map_err(js)
}

#[wasm_bindgen]
impl Conversation {
    /// Build a fresh opaque identity with no group yet. `label` is local-only and non-PII; the
    /// binding identity is the signature public key (ADR-008).
    #[wasm_bindgen(constructor)]
    pub fn new(label: &str) -> Result<Conversation, JsError> {
        Self::new_inner(label).map_err(js)
    }

    /// Build an AUTHORIZED identity (multi-device, ADR-022 P2). `recovery_seed_hex` is the account's
    /// 32-byte recovery secret as 64 hex chars; it is generated in JS, sealed under the MSK, and
    /// never sent to the server. This device's credential carries an AAK-signed certificate.
    #[wasm_bindgen(js_name = newAuthorized)]
    pub fn new_authorized(label: &str, recovery_seed_hex: &str, cert_epoch: u32) -> Result<Conversation, JsError> {
        let seed = hex_to_bytes(recovery_seed_hex).map_err(js)?;
        Self::new_authorized_at_epoch_inner(label, &seed, cert_epoch as u64).map_err(js)
    }

    /// Recovery: turn this (unauthorized) device into an authorized seed-holder by supplying the
    /// account recovery secret, certifying at the account's current epoch. The MLS signer is unchanged,
    /// so the device key and bootstrap mailbox stay stable.
    #[wasm_bindgen(js_name = recoverWithSeed)]
    pub fn recover_with_seed(&mut self, recovery_seed_hex: &str, cert_epoch: u32) -> Result<(), JsError> {
        let seed = hex_to_bytes(recovery_seed_hex).map_err(js)?;
        self.recover_with_seed_inner(&seed, cert_epoch as u64).map_err(js)
    }

    /// P6 epoch bump: re-certify this device at `cert_epoch` using the account key it already holds
    /// (seed-holder only). After a revoke, every remaining seed-holder device re-certifies at the new
    /// epoch and re-publishes key packages, so the trusted floor rises and the revoked device's
    /// old-epoch certificate is rejected by the gate.
    #[wasm_bindgen(js_name = reauthorizeAtEpoch)]
    pub fn reauthorize_at_epoch(&mut self, cert_epoch: u32) -> Result<(), JsError> {
        self.recredential_at_epoch_inner(cert_epoch as u64).map_err(js)
    }

    /// This device's own certificate epoch (0 if unauthorized). The app compares it to the account's
    /// current epoch to decide whether this device must re-certify.
    #[wasm_bindgen(js_name = certEpoch)]
    pub fn cert_epoch(&self) -> u32 {
        self.cert_epoch_inner() as u32
    }

    /// ADR-022 P7. Seed-holder: issue a signed revocation record naming `deviceSigKeyHex`, adopt it on
    /// this device immediately, and return it as hex for the caller to publish so every other device of
    /// the account learns it. This, not the epoch, is what excludes the device: the gate refuses a
    /// named key however high an epoch it mints for itself.
    #[wasm_bindgen(js_name = revokeDevice)]
    pub fn revoke_device(&mut self, device_sig_key_hex: &str, issued_seq: u32) -> Result<String, JsError> {
        self.revoke_device_inner(device_sig_key_hex, u64::from(issued_seq)).map_err(js)
    }

    /// ADR-022 P7. Accept one revocation record fetched from the control plane. Returns true if it was
    /// new. Errs on a record that does not verify under THIS account's key, so a hostile or buggy
    /// control plane can withhold records (costing liveness) but never inject one.
    #[wasm_bindgen(js_name = ingestRevocation)]
    pub fn ingest_revocation(&mut self, record_hex: &str) -> Result<bool, JsError> {
        let blob = hex_to_bytes(record_hex).map_err(js)?;
        self.ingest_revocation_inner(&blob).map_err(js)
    }

    /// How many revocation records this device holds for its own account. This is the DERIVED epoch:
    /// every device with the same records computes the same number offline, so the app can show it and
    /// compare it against the control plane's counter without treating that counter as authoritative.
    #[wasm_bindgen(js_name = revokedCount)]
    pub fn revoked_count(&self) -> u32 {
        self.revoked_device_keys().len() as u32
    }

    /// Whether this account has revoked `deviceSigKeyHex`, per the records this device holds. Used by
    /// the UI to mark a device row and to keep a revoked key out of a pairing attempt.
    #[wasm_bindgen(js_name = isDeviceRevoked)]
    pub fn is_device_revoked(&self, device_sig_key_hex: &str) -> bool {
        match hex_to_bytes(device_sig_key_hex) {
            Ok(k) => self.is_revoked(&k),
            Err(_) => false,
        }
    }

    /// This device's effective epoch floor for its own account: the highest certificate epoch it has
    /// ever accepted, which is also the lowest it will now certify at. Exposed so a stuck pairing can be
    /// diagnosed by READING the number rather than inferring it from a rejection.
    #[wasm_bindgen(js_name = accountFloor)]
    pub fn account_floor(&self) -> u32 {
        match self.our_account_pub() {
            Some(a) => self.effective_floor(&a, 0) as u32,
            None => 0,
        }
    }

    /// This account's authorization-key public value (its stable cryptographic identity) as hex, or
    /// an empty string for a legacy/unauthorized identity. Peers verify this out of band.
    #[wasm_bindgen(js_name = accountKeyHex)]
    pub fn account_key_hex(&self) -> String {
        self.aak.as_ref().map(|k| hex(&authz::aak_public(k))).unwrap_or_default()
    }

    /// Seed-holder: authorize another device (model b), guarded by the confirmed verification-code
    /// digest so only the key the user verified can be certified. Returns accountPublicKey(32) ||
    /// certEpoch(8) || certificate(64) as hex, to publish to the new device's reply mailbox.
    #[wasm_bindgen(js_name = authorizeDevice)]
    pub fn authorize_device(
        &self,
        device_sig_key_hex: &str,
        cert_epoch: u32,
        session_nonce_hex: &str,
        confirmed_sas_hex: &str,
    ) -> Result<String, JsError> {
        self.authorize_device_inner(device_sig_key_hex, u64::from(cert_epoch), session_nonce_hex, confirmed_sas_hex)
            .map_err(js)
    }

    /// Seed-holder: authorize a device whose signature key was obtained by SCANNING its QR (add-a-device
    /// -by-QR). There is NO 6-word verification code here: the optical scan IS the out-of-band
    /// authentication (D1 read the key off D2's own screen, never over the gateway), so there is nothing
    /// for a relay to substitute. Returns the Grant `accountPublicKey(32) || certEpoch(8) || cert(64)`
    /// as bytes; the caller SEALS it to the new device's ephemeral key before publishing it. The caller
    /// MUST pass only a key it obtained from the trusted optical scan, never a gateway-relayed one.
    #[wasm_bindgen(js_name = authorizeScannedDevice)]
    pub fn authorize_scanned_device(&self, device_sig_key: &[u8], cert_epoch: u32) -> Result<Vec<u8>, JsError> {
        self.authorize_scanned_device_inner(device_sig_key, u64::from(cert_epoch)).map_err(js)
    }

    /// New device: adopt a certificate issued by a seed-holder, becoming an authorized member of the
    /// account (model b). Fail-closed: rejects a certificate that does not authorize our own key.
    #[wasm_bindgen(js_name = adoptCertificate)]
    pub fn adopt_certificate(&mut self, aak_pub_hex: &str, cert_epoch: u32, cert_hex: &str) -> Result<(), JsError> {
        self.adopt_certificate_inner(aak_pub_hex, u64::from(cert_epoch), cert_hex).map_err(js)
    }

    /// Our own Ed25519 signature public key as 64 hex chars. Public material only.
    #[wasm_bindgen(js_name = signaturePublicKeyHex)]
    pub fn signature_public_key_hex(&self) -> String {
        hex(self.signer.public())
    }

    /// A stable, opaque per-MAILBOX delivery-cursor tag for the gateway's hold-until-ack bus. Derived
    /// as SHA-256 over a domain tag, this device's SECRET signing key, and the mailbox subject, so:
    /// it is STABLE across reloads (the signer is restored identically), it is UNLINKABLE across
    /// mailboxes without the device secret (two subjects yield unrelated tags), and it is not
    /// reversible to the device's public bootstrap key. Used instead of the raw bootstrap key so a
    /// snapshot of the gateway's in-memory consumer registry (taken while the device is offline)
    /// cannot be read as a device-to-conversation map. Truncated to 16 bytes (32 hex chars): ample
    /// collision resistance for a per-mailbox cursor, well under the gateway's id length cap.
    #[wasm_bindgen(js_name = mailboxTag)]
    pub fn mailbox_tag(&self, subject: &str) -> String {
        // The device secret is the serialized signing keypair (private + public): the same bytes
        // export_sealed persists and from_sealed restores identically, so the tag is stable across
        // reloads, and it is one-way hashed so nothing about the private key leaks.
        let secret = serde_json::to_vec(&self.signer).unwrap_or_default();
        let mut h = Sha256::new();
        h.update(b"deaddrop-consumer-cursor-v1");
        h.update((secret.len() as u32).to_be_bytes());
        h.update(&secret);
        h.update(subject.as_bytes());
        hex(&h.finalize()[..16])
    }

    /// Mint a fresh public KeyPackage (private parts stored in our provider) for a peer to add
    /// us. A fresh package per conversation; KeyPackages are single-use in MLS.
    ///
    /// The caller MUST persist this device's sealed state before publishing the returned public half
    /// (see the client's `freshKeyPackages`): the private material lives only in the provider's
    /// in-memory storage map until a reseal writes it down, and a published package whose private
    /// half did not survive a reload is a Welcome nobody can open.
    #[wasm_bindgen(js_name = keyPackage)]
    pub fn key_package(&self) -> Result<Vec<u8>, JsError> {
        fresh_key_package_bytes(&self.provider, &self.signer, self.credential.clone(), false).map_err(js)
    }

    /// Mint the LAST-RESORT KeyPackage: the one the directory re-serves after the one-time packages
    /// are drained. It carries the MLS LastResort extension so OpenMLS does NOT delete the private
    /// bundle after a join, making the package genuinely reusable — which is what the server already
    /// assumes (UserStore keeps one permanently claimable `is_last_resort = 1` row).
    #[wasm_bindgen(js_name = keyPackageLastResort)]
    pub fn key_package_last_resort(&self) -> Result<Vec<u8>, JsError> {
        fresh_key_package_bytes(&self.provider, &self.signer, self.credential.clone(), true).map_err(js)
    }

    /// Group-CREATOR path (the accepter): create a 1:1 conversation, add the peer from their public
    /// KeyPackage, and return a length-prefixed [welcome, group_id]: the MLS Welcome for the peer to
    /// join, and this conversation's id (the stable key for every subsequent operation).
    #[wasm_bindgen(js_name = createAndAdd)]
    pub fn create_and_add(&mut self, peer_key_package: &[u8]) -> Result<Vec<u8>, JsError> {
        let (welcome, gid) = self.create_and_add_inner(peer_key_package).map_err(js)?;
        encode_list(&[welcome, gid]).map_err(js)
    }

    /// Group-JOINER path: join from a Welcome and return the joined conversation's id (hex).
    #[wasm_bindgen(js_name = joinFromWelcome)]
    pub fn join_from_welcome(&mut self, welcome_bytes: &[u8]) -> Result<String, JsError> {
        let gid = self.join_from_welcome_inner(welcome_bytes).map_err(js)?;
        Ok(hex(&gid))
    }

    /// Encrypt one application message in a conversation. The returned bytes ARE `Envelope.payload`.
    pub fn encrypt(&mut self, conversation_id: &str, plaintext: &[u8]) -> Result<Vec<u8>, JsError> {
        self.encrypt_inner(conversation_id, plaintext).map_err(js)
    }

    /// Decrypt one inbound ciphertext in a conversation. Errs (never panics) on bad, duplicate, or
    /// out-of-epoch ciphertext. Application-message only; the N-member path uses `receive`.
    pub fn decrypt(&mut self, conversation_id: &str, ciphertext: &[u8]) -> Result<Vec<u8>, JsError> {
        self.decrypt_inner(conversation_id, ciphertext).map_err(js)
    }

    /// Group-CREATOR for an N-member conversation: create a NEW group and add every other member
    /// (the peer's devices and our own sibling devices) from their KeyPackages in ONE commit.
    /// `key_packages_blob` is a length-prefixed list of KeyPackages. Returns [welcome, group_id].
    #[wasm_bindgen(js_name = createGroup)]
    pub fn create_group(&mut self, key_packages_blob: &[u8]) -> Result<Vec<u8>, JsError> {
        let mut pos = 0;
        let kps = decode_list(key_packages_blob, &mut pos).map_err(js)?;
        let (welcome, gid) = self.create_group_inner(&kps).map_err(js)?;
        encode_list(&[welcome, gid]).map_err(js)
    }

    /// As createGroup, with the self-group BIRTH gate: every added package must chain to our account.
    /// Used only by the hidden own-devices self-group creation path.
    #[wasm_bindgen(js_name = createSelfGroup)]
    pub fn create_self_group(&mut self, key_packages_blob: &[u8]) -> Result<Vec<u8>, JsError> {
        let mut pos = 0;
        let kps = decode_list(key_packages_blob, &mut pos).map_err(js)?;
        let (welcome, gid) = self.create_self_group_inner(&kps).map_err(js)?;
        encode_list(&[welcome, gid]).map_err(js)
    }

    /// Whether one key package would pass the self-group birth gate. The client pre-filters founding
    /// targets so one stale package cannot abort the whole mint.
    #[wasm_bindgen(js_name = keyPackageSelfEligible)]
    pub fn key_package_self_eligible(&self, key_package: &[u8]) -> bool {
        self.key_package_self_eligible_inner(key_package)
    }

    /// Group-CREATOR for a SOLO conversation whose only member is this device: the private own-devices
    /// "self-group" that carries Note to Self and the buddy-list sync. Unlike `createGroup` this admits
    /// no one, so there is NO Welcome; it returns just the group_id. It exists so a single-device account
    /// still has a self-group; siblings fold in later through the normal staged-add path, so it grows
    /// into the multi-device self-group without ever having held a peer. Requires an authorized
    /// credential (an account key), so the resulting group is a self-conversation on this device.
    #[wasm_bindgen(js_name = createSelf)]
    pub fn create_self(&mut self) -> Result<Vec<u8>, JsError> {
        self.create_self_inner().map_err(js)
    }

    /// Add one member to an EXISTING conversation. Returns a length-prefixed [commit, welcome]: publish
    /// the commit to the group mailbox so current members advance, deliver the welcome to the new member.
    #[wasm_bindgen(js_name = addMember)]
    pub fn add_member(&mut self, conversation_id: &str, key_package: &[u8]) -> Result<Vec<u8>, JsError> {
        let (commit, welcome) = self.add_member_inner(conversation_id, key_package).map_err(js)?;
        encode_list(&[commit, welcome]).map_err(js)
    }

    /// STAGE an add without merging (ADR-022 concurrency, the fork-free add path) in one conversation.
    /// Returns [commit, welcome]; this device stays on that group's epoch N until the commit is confirmed
    /// (its own echo seen in `receive`) or aborted (a competing commit wins).
    #[wasm_bindgen(js_name = stageAdd)]
    pub fn stage_add(&mut self, conversation_id: &str, key_package: &[u8]) -> Result<Vec<u8>, JsError> {
        let (commit, welcome) = self.stage_add_inner(conversation_id, key_package).map_err(js)?;
        encode_list(&[commit, welcome]).map_err(js)
    }

    /// CONFIRM a staged add in one conversation (merge its pending commit). Idempotent.
    #[wasm_bindgen(js_name = confirmAdd)]
    pub fn confirm_add(&mut self, conversation_id: &str) -> Result<(), JsError> {
        self.confirm_add_inner(conversation_id).map_err(js)
    }

    /// ABORT a staged add in one conversation (clear its pending commit), staying on epoch N. Idempotent.
    #[wasm_bindgen(js_name = abortAdd)]
    pub fn abort_add(&mut self, conversation_id: &str) -> Result<(), JsError> {
        self.abort_add_inner(conversation_id).map_err(js)
    }

    /// Remove a member (device) by signature key from one conversation. Returns the commit to publish so
    /// every remaining member rotates the group secrets (forward-secure exclusion).
    #[wasm_bindgen(js_name = removeMember)]
    pub fn remove_member(&mut self, conversation_id: &str, sig_key_hex: &str) -> Result<Vec<u8>, JsError> {
        self.remove_member_inner(conversation_id, sig_key_hex).map_err(js)
    }

    /// STAGE a Remove: build the removal commit but do NOT merge until its own echo confirms it (fork-free,
    /// like stageAdd). Returns the raw commit to publish (no welcome). Used by the peer-revoke self-heal.
    #[wasm_bindgen(js_name = stageRemove)]
    pub fn stage_remove(&mut self, conversation_id: &str, sig_key_hex: &str) -> Result<Vec<u8>, JsError> {
        self.stage_remove_inner(conversation_id, sig_key_hex).map_err(js)
    }

    /// CONFIRM a staged Remove (merge its pending commit). Idempotent; a no-op unless a Remove is staged.
    #[wasm_bindgen(js_name = confirmRemove)]
    pub fn confirm_remove(&mut self, conversation_id: &str) -> Result<(), JsError> {
        self.confirm_remove_inner(conversation_id).map_err(js)
    }

    /// ABORT a staged Remove (clear its pending commit), staying on epoch N. Idempotent; Remove-only.
    #[wasm_bindgen(js_name = abortRemove)]
    pub fn abort_remove(&mut self, conversation_id: &str) -> Result<(), JsError> {
        self.abort_remove_inner(conversation_id).map_err(js)
    }

    /// The staged commit awaiting confirmation in one conversation, if any: 0 = none, 1 = Add, 2 = Remove.
    /// Used by the reload re-arm to find conversations whose in-flight commit survived a crash/reload.
    #[wasm_bindgen(js_name = pendingKind)]
    pub fn pending_kind(&self, conversation_id: &str) -> Result<u32, JsError> {
        self.pending_kind_inner(conversation_id).map_err(js)
    }

    /// The staged commit's target device signature key (hex), or '' when nothing is staged.
    #[wasm_bindgen(js_name = pendingTarget)]
    pub fn pending_target(&self, conversation_id: &str) -> Result<String, JsError> {
        self.pending_target_inner(conversation_id).map_err(js)
    }

    /// The staged commit's outgoing wire bytes (to re-publish on reload), or empty when nothing is staged.
    #[wasm_bindgen(js_name = pendingCommit)]
    pub fn pending_commit_bytes(&self, conversation_id: &str) -> Result<Vec<u8>, JsError> {
        self.pending_commit_inner(conversation_id).map_err(js)
    }

    /// The staged Add's Welcome wire bytes (to re-deliver on reload), or empty for none / a Remove.
    #[wasm_bindgen(js_name = pendingWelcome)]
    pub fn pending_welcome(&self, conversation_id: &str) -> Result<Vec<u8>, JsError> {
        self.pending_welcome_inner(conversation_id).map_err(js)
    }

    /// Receive one inbound MLS message, ROUTING it to the right conversation by the group id inside.
    /// Returns a length-prefixed [group_id, tagged_received_blob]: the caller maps the group id to its
    /// channel and dispatches on the tag, authorizing added members before trusting the new roster.
    pub fn receive(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, JsError> {
        let (gid, received) = self.receive_inner(ciphertext).map_err(js)?;
        let blob = encode_received(&received).map_err(js)?;
        encode_list(&[gid, blob]).map_err(js)
    }

    /// One conversation's roster as sorted signature-key hex strings (all members, including us).
    pub fn roster(&self, conversation_id: &str) -> Result<Vec<String>, JsError> {
        self.roster_hex_inner(conversation_id).map_err(js)
    }

    /// The ids (hex) of every open conversation. Used to restore all groups on reconnect.
    #[wasm_bindgen(js_name = listConversations)]
    pub fn list_conversations(&self) -> Vec<String> {
        self.list_conversations_inner()
    }

    /// Close (locally drop) one conversation: remove its group and delete its MLS state from storage,
    /// so the sealed export no longer carries it and a reload cannot revive it. Strictly user-initiated
    /// (never automatic: an offline real peer is indistinguishable from a dead channel). Refuses the
    /// hidden own-devices self-group; idempotent for an unknown id. The group is never notified.
    #[wasm_bindgen(js_name = closeConversation)]
    pub fn close_conversation(&mut self, conversation_id: &str) -> Result<(), JsError> {
        self.close_conversation_inner(conversation_id).map_err(js)
    }

    /// Whether this held conversation provably has NO reachable recipient: at least one non-own member
    /// is certless (a pre-authorization orphan or legacy label-only leaf) and NO member verifies under
    /// another account. A verified foreign device, even one that never comes online, keeps the channel
    /// linked (a real peer conversation must never be flagged dead on liveness). Advisory only.
    #[wasm_bindgen(js_name = channelUnlinked)]
    pub fn channel_unlinked(&self, conversation_id: &str) -> Result<bool, JsError> {
        self.channel_unlinked_inner(conversation_id).map_err(js)
    }

    /// SG2 self-heal: abandon an own-devices group that is provably DEAD (unlinked), so a poisoned
    /// self-group cannot strand the account. Refuses a peer conversation and refuses a self-group that
    /// still has any verified sibling. Returns true when it abandoned one.
    #[wasm_bindgen(js_name = abandonDeadSelfGroup)]
    pub fn abandon_dead_self_group(&mut self, conversation_id: &str, recorded_self: bool) -> Result<bool, JsError> {
        self.abandon_dead_self_group_inner(conversation_id, recorded_self).map_err(js)
    }

    /// Persist the advanced receive ratchet for one conversation (see flush_receive_ratchet_inner).
    /// Returns false when this epoch's flush budget is spent, so the caller can skip the re-seal.
    #[wasm_bindgen(js_name = flushReceiveRatchet)]
    pub fn flush_receive_ratchet(&mut self, conversation_id: &str) -> Result<bool, JsError> {
        self.flush_receive_ratchet_inner(conversation_id).map_err(js)
    }

    /// The distinct FOREIGN account authority keys (hex, sorted) present in this conversation, counting
    /// only members whose device certificates verify. This is what contact verification pins: a buddy's
    /// account key, not any one device. Empty on a legacy device, for the self-group, or when no foreign
    /// member verifies (fail-safe: nothing to verify beats a wrong anchor).
    #[wasm_bindgen(js_name = peerAccountKeys)]
    pub fn peer_account_keys(&self, conversation_id: &str) -> Result<Vec<String>, JsError> {
        self.peer_account_keys_inner(conversation_id).map_err(js)
    }

    /// True iff every member of this conversation is one of OUR OWN account's devices (the hidden
    /// self-group that syncs our buddy list across our devices). Cryptographically grounded, so the client
    /// can hide it from the conversation list and target buddy-list syncs to it without a device-list cache.
    #[wasm_bindgen(js_name = isSelfConversation)]
    pub fn is_self_conversation(&self, conversation_id: &str) -> Result<bool, JsError> {
        self.is_self_conversation_inner(conversation_id).map_err(js)
    }

    /// STRICT self classification: like isSelfConversation, without the own-leaf exemption. Used only to
    /// PREFER a fully certified self-group during canonical-group selection; hiding still uses the
    /// exempted predicate.
    #[wasm_bindgen(js_name = isSelfConversationStrict)]
    pub fn is_self_conversation_strict(&self, conversation_id: &str) -> Result<bool, JsError> {
        self.is_self_conversation_strict_inner(conversation_id).map_err(js)
    }

    /// READ-ONLY diagnostic: the reason a conversation is or is not a self-group ("self" when it is).
    /// Makes no decision and grants no access; it exists so a stuck self-classification can be diagnosed
    /// by reading the cause rather than guessing at MLS rosters the keyless gateway cannot show.
    #[wasm_bindgen(js_name = selfClassificationReason)]
    pub fn self_classification_reason_js(&self, conversation_id: &str) -> String {
        self.self_classification_reason(conversation_id)
    }

    /// Whether OUR OWN current credential carries a verifying device certificate, i.e. a group minted
    /// RIGHT NOW would classify strict. Gates the certified-replacement mint: a legacy label-only
    /// seed-holder must not mint (its replacement would be lenient-only too, and the mint would repeat
    /// forever), while a certified one mints exactly once and terminates.
    #[wasm_bindgen(js_name = credentialCertified)]
    pub fn credential_certified(&self) -> bool {
        self.credential_certified_inner()
    }

    /// One conversation's per-epoch group mailbox every member subscribes to and publishes to. Derived
    /// from that group's exporter secret, so it is opaque to the server and ROTATES every epoch.
    #[wasm_bindgen(js_name = groupMailbox)]
    pub fn group_mailbox(&self, conversation_id: &str) -> Result<String, JsError> {
        self.group_mailbox_inner(conversation_id).map_err(js)
    }

    /// The single other member's Ed25519 key (hex) in a 1:1 conversation, for the §5.7 key-substitution
    /// cross-check. Errs if the conversation is unknown or its roster is not exactly two members.
    #[wasm_bindgen(js_name = peerSignatureKeyHex)]
    pub fn peer_signature_key_hex(&self, conversation_id: &str) -> Result<String, JsError> {
        self.peer_signature_key_hex_inner(conversation_id).map_err(js)
    }

    /// Our own inbound mailbox in a conversation (the opaque routing key we subscribe to). Sealed sender
    /// (P2): derived from that group's exporter secret keyed by our signature key, so it is unpredictable
    /// to the server and ROTATES every epoch. The peer computes the same value as their `peerMailbox`.
    #[wasm_bindgen(js_name = selfMailbox)]
    pub fn self_mailbox(&self, conversation_id: &str) -> Result<String, JsError> {
        self.self_mailbox_inner(conversation_id).map_err(js)
    }

    /// The peer's inbound mailbox in a conversation (where we publish to reach them).
    #[wasm_bindgen(js_name = peerMailbox)]
    pub fn peer_mailbox(&self, conversation_id: &str) -> Result<String, JsError> {
        self.peer_mailbox_inner(conversation_id).map_err(js)
    }

    /// Export the session state, AEAD-sealed under the MSK, for durable persistence (M2 Layer 1).
    #[wasm_bindgen(js_name = exportSealed)]
    pub fn export_sealed(&self, msk: &[u8]) -> Result<Vec<u8>, JsError> {
        self.export_sealed_inner(msk).map_err(js)
    }

    /// Reconstruct a Conversation from a sealed export. Fails on the wrong MSK or tampering.
    #[wasm_bindgen(js_name = fromSealed)]
    pub fn from_sealed(msk: &[u8], sealed: &[u8]) -> Result<Conversation, JsError> {
        Self::from_sealed_inner(msk, sealed).map_err(js)
    }

    /// Best-effort in-memory crypto-erase of this session. Honest limit: the foreign
    /// SignatureKeyPair exposes no zeroizing API, and WASM linear memory may already have
    /// copied bytes during reallocation, so this is best-effort. The real at-rest defense is
    /// the M2 encrypt-under-destroyable-key design, not heap zeroization.
    #[wasm_bindgen(js_name = wipe)]
    pub fn wipe(&mut self) {
        // Delete EVERY open conversation from storage, then drop the handles.
        for slot in self.groups.values_mut() {
            let _ = slot.group.delete(self.provider.storage());
        }
        self.groups.clear();
        // Zeroize every key AND value still held in the provider's in-memory storage map (the keys can
        // encode group ids and leaf material), then clear it.
        if let Ok(mut values) = self.provider.storage().values.write() {
            let mut drained: Vec<(Vec<u8>, Vec<u8>)> = values.drain().collect();
            for (k, v) in drained.iter_mut() {
                k.zeroize();
                v.zeroize();
            }
        }
        // Reach the signing key: replace the SignatureKeyPair with throwaway material so the
        // original private Vec is dropped (freed). The foreign type cannot be byte-scrubbed,
        // so this is best-effort; the durable defense is destroying the MSK (the persisted
        // copy is sealed under it). Clear the label too.
        if let Ok(throwaway) = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm()) {
            self.signer = throwaway;
        }
        self.label.zeroize();
        // Drop the account key (ed25519-dalek zeroizes it on drop).
        self.aak = None;
    }
}

// Platform-independent cores: natively unit-testable, no wasm types. Errors are short,
// non-sensitive strings (never key bytes, plaintext, or routing data).
impl Conversation {
    pub(crate) fn new_inner(label: &str) -> Result<Self, String> {
        let provider = OpenMlsRustCrypto::default();
        let (signer, credential) = new_identity(label)?;
        Ok(Self {
            provider,
            signer,
            credential,
            groups: HashMap::new(),
            label: label.as_bytes().to_vec(),
            aak: None,
            account_floors: Vec::new(),
            revocations: Vec::new(),
        })
    }

    /// Build an AUTHORIZED identity rooted in an Account Authorization Key derived from `seed` (the
    /// account's recovery secret), certified at epoch 0. The account key signs this device's
    /// certificate and is trusted from the outset, so the gate admits this account's devices and
    /// rejects others (ADR-022 P2).
    pub(crate) fn new_authorized_inner(label: &str, seed: &[u8]) -> Result<Self, String> {
        Self::new_authorized_at_epoch_inner(label, seed, 0)
    }

    /// As `new_authorized_inner`, but certifying at `cert_epoch`. The registering device uses 0; a
    /// device built from the recovery seed when revokes have already happened uses the bumped epoch so
    /// it is admitted at or above the current floor (ADR-022 P6).
    pub(crate) fn new_authorized_at_epoch_inner(label: &str, seed: &[u8], cert_epoch: u64) -> Result<Self, String> {
        let aak = authz::aak_from_seed(seed)?;
        let provider = OpenMlsRustCrypto::default();
        let (signer, credential) = new_identity_authorized(label, &aak, cert_epoch)?;
        // Seed the device-global high-water floor with our own account; per-group trusted sets are
        // established when each conversation is created or joined (recompute_trusted_for).
        let account_floors = vec![(authz::aak_public(&aak), cert_epoch)];
        Ok(Self {
            provider,
            signer,
            credential,
            groups: HashMap::new(),
            label: label.as_bytes().to_vec(),
            aak: Some(aak),
            account_floors,
            revocations: Vec::new(),
        })
    }

    /// Re-sign OUR OWN credential at `cert_epoch` using the account key we already hold, keeping the
    /// same MLS signer (so the device key and bootstrap mailbox stay stable). Raises our trusted floor
    /// for our own account. Used by recovery and by the P6 epoch bump after a revoke.
    pub(crate) fn recredential_at_epoch_inner(&mut self, cert_epoch: u64) -> Result<(), String> {
        // An honest device that has learned it was revoked stops here instead of re-minting a credential
        // every device of this account (including itself) will refuse. NOT a security control: a device
        // whose owner is the attacker runs whatever code it likes and can strip this check. What stops
        // the attacker is check_added_leaf on the OTHER devices, which is why that gate, not this one,
        // is the property the tests assert.
        if self.is_revoked(self.signer.public()) {
            return Err("this device was revoked by its account and cannot re-authorize".to_string());
        }
        let aak_pub = {
            let aak = self
                .aak
                .as_ref()
                .ok_or_else(|| "this device has no account key to re-authorize with".to_string())?;
            authz::aak_public(aak)
        };
        // Never certify below what we last saw. Same rule and same reasoning as the scanned-device mint:
        // raising is safe, lowering issues a credential our own gate would deny. The recovery path hands
        // us the control plane's counter, which can lag our floor (or be deflated by a compelled server)
        // and, until P7, could silently mint a doomed credential from the correct recovery secret.
        let cert_epoch = cert_epoch.max(self.effective_floor(&aak_pub, 0));
        let aak = self.aak.as_ref().expect("checked above");
        let cert = authz::sign_device_cert(aak, cert_epoch, self.signer.public());
        let identity = authz::encode_auth_identity(&aak_pub, cert_epoch, &cert, &self.label);
        self.credential = CredentialWithKey {
            credential: BasicCredential::new(identity).into(),
            signature_key: self.signer.public().into(),
        };
        // Anti-rollback: re-certifying our own account to a new epoch raises our device-global floor, so
        // the gate in every open conversation admits us at or above the new epoch (no per-group update
        // needed; the gate floors at the MAX of the slot's trusted set and this device-global high-water).
        self.raise_floor(&aak_pub, cert_epoch);
        Ok(())
    }

    /// Recovery path: become an authorized seed-holder on THIS device by supplying the recovery
    /// secret. Adopts the account key from the seed and self-signs a certificate at `cert_epoch` over
    /// our existing MLS signer, so the device key (and its directory entry) stay stable. A device that
    /// recovers learns the seed; that is the user's deliberate choice for a fully trusted device.
    pub(crate) fn recover_with_seed_inner(&mut self, seed: &[u8], cert_epoch: u64) -> Result<(), String> {
        let aak = authz::aak_from_seed(seed)?;
        self.aak = Some(aak);
        self.recredential_at_epoch_inner(cert_epoch)
    }

    /// This device's own certificate epoch (0 for an unauthorized or legacy identity).
    pub(crate) fn cert_epoch_inner(&self) -> u64 {
        let identity = match BasicCredential::try_from(self.credential.credential.clone()) {
            Ok(bc) => bc.identity().to_vec(),
            Err(_) => return 0,
        };
        parse_auth_identity(&identity).map(|ai| ai.cert_epoch).unwrap_or(0)
    }

    /// Export the whole session state, AEAD-sealed under the MSK (M2 Layer 1, ADR-015). The
    /// returned bytes are what JS persists to IndexedDB (inside the owning Worker); they are
    /// opaque without the MSK. Includes the storage map, the SignatureKeyPair (OpenMLS never
    /// stores it), the label, and the group id for reload.
    pub(crate) fn export_sealed_inner(&self, msk: &[u8]) -> Result<Vec<u8>, String> {
        let entries: Vec<(Vec<u8>, Vec<u8>)> = {
            let values = self
                .provider
                .storage()
                .values
                .read()
                .map_err(|_| "storage lock".to_string())?;
            values.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
        };
        let signer_bytes =
            serde_json::to_vec(&self.signer).map_err(|e| format!("serialize signer: {e}"))?;
        let aak_seed: Vec<u8> = self.aak.as_ref().map(|k| k.to_bytes().to_vec()).unwrap_or_default();
        // The full authorized credential identity (or label-only for an unauthorized device), so a
        // reload restores the exact certificate and cert epoch (ADR-022 P6) rather than dropping to a
        // label-only credential.
        let cred_identity = BasicCredential::try_from(self.credential.credential.clone())
            .map(|bc| bc.identity().to_vec())
            .unwrap_or_default();
        // Serialize the device-global high-water account floors as aak_pub || epoch(8, big-endian).
        let ser_floor = |(k, e): (&Vec<u8>, &u64)| -> Vec<u8> {
            let mut v = k.clone();
            v.extend_from_slice(&e.to_be_bytes());
            v
        };
        let floors_ser: Vec<Vec<u8>> = self.account_floors.iter().map(|(k, e)| ser_floor((k, e))).collect();
        // Every open conversation as (group_id, [aak_pub||epoch]). The provider storage dump (entries)
        // already holds all groups' MLS state; this records which to load and each one's trusted set.
        let groups_ser: Vec<(Vec<u8>, Vec<Vec<u8>>)> = self
            .groups
            .iter()
            .map(|(gid, slot)| {
                let trusted: Vec<Vec<u8>> = slot.trusted_aaks.iter().map(|(k, e)| ser_floor((k, e))).collect();
                (gid.clone(), trusted)
            })
            .collect();
        // Any staged commit awaiting confirmation rides along (gid, kind, target, outgoing wire bytes), so
        // a crash between stage and confirm no longer strands the committer: the reload reconstructs the
        // pending (OpenMLS restored the StagedCommit via the entries above) and the client re-publishes
        // these exact bytes and re-arms the confirm backstop.
        let pendings_ser: Vec<(Vec<u8>, u8, Vec<u8>, Vec<u8>, Vec<u8>)> = self
            .groups
            .iter()
            .filter_map(|(gid, slot)| match &slot.pending {
                Some(Pending::Add { commit, welcome, added }) => {
                    Some((gid.clone(), 1u8, added.clone(), commit.clone(), welcome.clone()))
                }
                Some(Pending::Remove { commit, removed }) => {
                    Some((gid.clone(), 2u8, removed.clone(), commit.clone(), Vec::new()))
                }
                None => None,
            })
            .collect();
        // Legacy single `gid`/`trusted` are left EMPTY by this (multi-group) writer; all conversations
        // ride the trailing groups section. Old single-group blobs (legacy fields set) still load.
        // The flush counters, so the cap is per EPOCH and not per page load (see encode_container).
        let burns_ser: Vec<(Vec<u8>, u32, u64)> = self
            .groups
            .iter()
            .filter(|(_, slot)| slot.flush_burns > 0)
            .map(|(gid, slot)| (gid.clone(), slot.flush_burns, slot.flush_epoch))
            .collect();
        let container = encode_container(
            &entries,
            &signer_bytes,
            &self.label,
            &[],
            &aak_seed,
            &[],
            &cred_identity,
            &floors_ser,
            &groups_ser,
            &pendings_ser,
            &burns_ser,
            &self.revocations,
        )?;
        crate::atrest::seal(msk, &container)
    }

    /// Reconstruct a live Conversation from a sealed export. This is the ADR-016 deferred reload,
    /// now under encryption. ACCEPTED RESIDUAL (ADR-015): OpenMLS 0.6 never persists the advanced
    /// receive ratchet, so a reload loads a stale ratchet; see honest-limits.
    pub(crate) fn from_sealed_inner(msk: &[u8], sealed: &[u8]) -> Result<Self, String> {
        let container = crate::atrest::open(msk, sealed)?;
        let (entries, signer_bytes, label, gid, aak_seed, trusted, cred_identity, floors_raw, groups_raw, pendings_raw, burns_raw, revocations_raw) =
            decode_container(&container)?;

        let provider = OpenMlsRustCrypto::default();
        {
            let mut values = provider
                .storage()
                .values
                .write()
                .map_err(|_| "storage lock".to_string())?;
            for (k, v) in entries {
                values.insert(k, v);
            }
        }

        let signer: SignatureKeyPair =
            serde_json::from_slice(&signer_bytes).map_err(|e| format!("deserialize signer: {e}"))?;
        // Restore the FULL authorized credential identity if present, so a reloaded seed-holder keeps
        // its certificate and cert epoch. A pre-P6 blob (or an unauthorized identity) has none, so we
        // fall back to a label-only credential, exactly as before.
        let credential = CredentialWithKey {
            credential: BasicCredential::new(if cred_identity.is_empty() { label.clone() } else { cred_identity }).into(),
            signature_key: signer.public().into(),
        };

        let aak = if aak_seed.is_empty() {
            None
        } else {
            Some(authz::aak_from_seed(&aak_seed)?)
        };
        // Both the trusted sets and the high-water floors are serialized as aak_pub || epoch(8, BE).
        let parse_floors = |raw: Vec<Vec<u8>>| -> Vec<(Vec<u8>, u64)> {
            raw.into_iter()
                .filter_map(|v| {
                    if v.len() < 8 {
                        return None;
                    }
                    let split = v.len() - 8;
                    let epoch_bytes: [u8; 8] = v[split..].try_into().ok()?;
                    Some((v[..split].to_vec(), u64::from_be_bytes(epoch_bytes)))
                })
                .collect()
        };
        let legacy_trusted = parse_floors(trusted);
        // A pre-anti-rollback blob has no stored floors; seed the high-water mark from the legacy trusted
        // set so monotonicity still holds going forward (it can only rise from there).
        let mut account_floors = parse_floors(floors_raw);
        if account_floors.is_empty() {
            account_floors = legacy_trusted.clone();
        }
        // Build the per-conversation slots. A legacy single-group blob carries ONE conversation in the
        // top-level gid + trusted; a multi-group blob carries each in groups_raw. Dedup defensively in
        // case a legacy blob was re-sealed with both. A referenced group missing from storage (corrupt or
        // partial) is skipped so the device identity and the other conversations still load.
        let mut metas: Vec<GroupMeta> = Vec::new();
        if !gid.is_empty() {
            metas.push((gid.clone(), legacy_trusted));
        }
        for (g, tser) in groups_raw {
            if !metas.iter().any(|(existing, _)| existing == &g) {
                metas.push((g, parse_floors(tser)));
            }
        }
        let mut groups = HashMap::new();
        for (g, trusted_aaks) in metas {
            let group_id = GroupId::from_slice(&g);
            if let Some(loaded) =
                MlsGroup::load(provider.storage(), &group_id).map_err(|e| format!("load group: {e:?}"))?
            {
                // Reconstruct a staged commit that was in flight when this blob was sealed, so a reloaded
                // committer can recognize its own echo (or re-publish) instead of stranding on epoch N and
                // then FORKING itself by re-staging a second, distinct commit. Guarded on the restored
                // OpenMLS pending commit actually existing in storage: if it does not (a mismatched or
                // stale section), the pending stays None and the pre-fix self-heal behavior applies.
                let pending = pendings_raw
                    .iter()
                    .find(|(pg, _, _, _, _)| pg == &g)
                    .filter(|_| loaded.pending_commit().is_some())
                    .and_then(|(_, kind, target, commit, welcome)| match kind {
                        1 => Some(Pending::Add {
                            commit: commit.clone(),
                            welcome: welcome.clone(),
                            added: target.clone(),
                        }),
                        2 => Some(Pending::Remove { commit: commit.clone(), removed: target.clone() }),
                        _ => None,
                    });
                // Restore the flush counter AND the epoch it was counted in, so the cap bounds the whole
                // epoch and not just this page load. Absent (a blob written before this section) means a
                // fresh count in epoch 0, which is the one case where restarting is legitimate; the epoch
                // check at the point of use corrects it on the first flush anyway.
                let (flush_burns, flush_epoch) = burns_raw
                    .iter()
                    .find(|(bg, _, _)| bg == &g)
                    .map(|(_, n, e)| (*n, *e))
                    .unwrap_or((0, 0));
                groups.insert(g, GroupSlot { group: loaded, trusted_aaks, pending, flush_burns, flush_epoch });
            }
        }
        let mut restored = Self {
            provider,
            signer,
            credential,
            groups,
            label,
            aak,
            account_floors,
            // Restored verbatim. These bytes came out of a container the AEAD already authenticated
            // under our own MSK, so they are our own; and every one is re-verified at the point of USE
            // (revoked_device_keys), which is the check that actually carries the property. Filtering
            // here instead would silently and PERMANENTLY drop the denylist on any load where the
            // credential has not settled yet (our_account_pub is None), which is exactly the moment a
            // device is most exposed. Capped so a corrupt-but-authenticated blob cannot make the gate
            // pay for an unbounded number of signature checks per add.
            revocations: revocations_raw.into_iter().take(MAX_REVOCATIONS).collect(),
        };
        // Re-derive the epoch floor from the records we hold. |S| is the DERIVED epoch: every device
        // with the same record set computes the same number offline, so this survives a reload without
        // asking the control plane, and a server that deflates its own counter cannot walk it back.
        if let Some(our) = restored.our_account_pub() {
            let derived = restored.revoked_device_keys().len() as u64;
            restored.raise_floor(&our, derived);
        }
        // MIGRATION BACKFILL: sealed blobs written by older builds on cert-only devices carry the
        // adopted credential alongside EMPTY per-group trusted sets (the old adopt gated the recompute
        // on holding the account PRIVATE key). Repopulate them at restore, idempotently, so the
        // classify_self trusted conjunct is live on every device with an account anchor. A legacy
        // label-only roster gathers nothing and correctly stays in gate-off mode.
        if restored.our_account_pub().is_some() {
            let empties: Vec<Vec<u8>> = restored
                .groups
                .iter()
                .filter(|(_, slot)| slot.trusted_aaks.is_empty())
                .map(|(gid, _)| gid.clone())
                .collect();
            for gid in empties {
                restored.recompute_trusted_for(&gid);
            }
        }
        Ok(restored)
    }

    /// Adopt a freshly created or joined MlsGroup as a new conversation slot, returning its group id
    /// (the stable conversation key). Guards against a group-id collision (astronomically unlikely with
    /// random 16-byte ids) rather than clobbering an existing conversation. Establishes the per-group
    /// trusted set from the initial roster for an authorized device (trust-on-first-use, ADR-022 P2/P7).
    fn adopt_group(&mut self, group: MlsGroup) -> Result<Vec<u8>, String> {
        let gid = group.group_id().as_slice().to_vec();
        if self.groups.contains_key(&gid) {
            return Err("group id collision".to_string());
        }
        self.groups
            .insert(gid.clone(), GroupSlot { group, trusted_aaks: Vec::new(), pending: None, flush_burns: 0, flush_epoch: 0 });
        // Anchor on our ACCOUNT (private key OR adopted cert), not the private key alone:
        // gather_roster_trusted verifies each member's cert self-contained, so a cert-only device can
        // and must record the formation-time trusted accounts too. Without this its trusted set stays
        // empty and the classify_self trusted conjunct is vacuous there, so a peer conversation whose
        // peer later LEFT could classify self and lose its channel row. Legacy label-only devices
        // (no account anchor at all) still stay empty.
        if self.our_account_pub().is_some() {
            self.recompute_trusted_for(&gid);
        }
        Ok(gid)
    }

    fn create_and_add_inner(&mut self, peer_key_package: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
        let kp_in = KeyPackageIn::tls_deserialize_exact(peer_key_package)
            .map_err(|e| format!("parse peer key package: {e:?}"))?;
        let peer_kp = kp_in
            .validate(self.provider.crypto(), ProtocolVersion::Mls10)
            .map_err(|e| format!("validate peer key package: {e:?}"))?;

        let cfg = group_create_config();
        let mut group = MlsGroup::new(&self.provider, &self.signer, &cfg, self.credential.clone())
            .map_err(|e| format!("create group: {e:?}"))?;

        let (_commit, welcome_out, _group_info) = group
            .add_members(&self.provider, &self.signer, &[peer_kp])
            .map_err(|e| format!("add member: {e:?}"))?;
        group
            .merge_pending_commit(&self.provider)
            .map_err(|e| format!("merge commit: {e:?}"))?;

        let welcome_bytes = welcome_out
            .tls_serialize_detached()
            .map_err(|e| format!("serialize welcome: {e:?}"))?;
        let gid = self.adopt_group(group)?;
        Ok((welcome_bytes, gid))
    }

    fn join_from_welcome_inner(&mut self, welcome_bytes: &[u8]) -> Result<Vec<u8>, String> {
        let msg_in = MlsMessageIn::tls_deserialize(&mut &welcome_bytes[..])
            .map_err(|e| format!("parse welcome: {e:?}"))?;
        let welcome = match msg_in.extract() {
            MlsMessageBodyIn::Welcome(w) => w,
            _ => return Err("expected a Welcome message".to_string()),
        };
        let cfg = group_create_config();
        // Process the Welcome to the point where its group id is readable, BEFORE building the staged
        // group. into_staged_welcome's PublicGroup::from_external writes MLS state into provider storage
        // keyed by the group id, so a rival Welcome for a group id we ALREADY hold (sealed to a different,
        // still-unconsumed key package) would clobber our live group's stored state and wedge us on a dead
        // epoch. Reject a duplicate group id here, before any such write. adopt_group re-checks the id
        // after staging as a backstop; this check is the one that runs early enough to prevent corruption.
        let processed = ProcessedWelcome::new_from_welcome(&self.provider, cfg.join_config(), welcome)
            .map_err(|e| format!("process welcome: {e:?}"))?;
        let gid = processed.unverified_group_info().group_id().as_slice().to_vec();
        if self.groups.contains_key(&gid) {
            return Err("already a member of this group".to_string());
        }
        let staged = processed
            .into_staged_welcome(&self.provider, None)
            .map_err(|e| format!("stage welcome: {e:?}"))?;
        let group = staged
            .into_group(&self.provider)
            .map_err(|e| format!("join group: {e:?}"))?;
        // adopt_group trusts the accounts present in the initial roster (trust-on-first-use; the user
        // verifies them out of band via the roster acknowledgement, ADR-022 P2/P7).
        self.adopt_group(group)
    }

    /// Raise this device's persistent high-water floor for an account; it never lowers. Anti-rollback:
    /// once seen at epoch N (in ANY conversation), the account is never accepted below N again (P6).
    fn raise_floor(&mut self, aak_pub: &[u8], epoch: u64) {
        match self.account_floors.iter_mut().find(|(k, _)| k.as_slice() == aak_pub) {
            Some(entry) => {
                if entry.1 < epoch {
                    entry.1 = epoch;
                }
            }
            None => self.account_floors.push((aak_pub.to_vec(), epoch)),
        }
    }

    /// The effective floor for an account: the MAX of the per-conversation floor and this device's
    /// device-global high-water floor, so a stale or server-deflated roster cannot lower it.
    fn effective_floor(&self, aak_pub: &[u8], conv_floor: u64) -> u64 {
        let global = self
            .account_floors
            .iter()
            .find(|(k, _)| k.as_slice() == aak_pub)
            .map(|(_, e)| *e)
            .unwrap_or(0);
        conv_floor.max(global)
    }

    /// The device signature keys this account has revoked, as proven by the records we hold. Derived
    /// fresh from the stored blobs by re-verifying each one under OUR OWN account key, so there is no
    /// cached set that could drift from the evidence, and a record we cannot verify (a different
    /// account, a corrupted blob) contributes nothing instead of contributing a wrong answer.
    ///
    /// Cost is one Ed25519 verification per stored record per call. That is a handful of microseconds
    /// each, on a list bounded by how many devices the user has ever revoked, on a path that runs when
    /// a device is ADDED to a group. Caching it would trade a real correctness property for nothing.
    fn revoked_device_keys(&self) -> Vec<Vec<u8>> {
        if self.revocations.is_empty() {
            return Vec::new(); // the common case: skip the credential parse entirely
        }
        let our = match self.our_account_pub() {
            Some(a) => a,
            None => return Vec::new(),
        };
        // DEDUPED BY TARGET. Two records naming the same device are legitimate (two seed-holders can
        // revoke it concurrently, and they will pick different advisory sequence numbers, so the bytes
        // differ). Counting both would inflate the derived epoch, which is defined as the number of
        // devices this account has revoked; the set of excluded keys is what carries the meaning.
        let mut out: Vec<Vec<u8>> = Vec::new();
        for blob in &self.revocations {
            if let Some(target) = crate::revoke::verify_revocation(&our, blob) {
                if !out.contains(&target) {
                    out.push(target);
                }
            }
        }
        out
    }

    /// Whether `device_sig_key` is one of OUR OWN account's revoked devices. False for any key we hold
    /// no verifying record for, including every key belonging to a peer account: this denylist speaks
    /// only for the account whose key signed it, and we only ever evaluate it for our own.
    fn is_revoked(&self, device_sig_key: &[u8]) -> bool {
        self.revoked_device_keys().iter().any(|k| k.as_slice() == device_sig_key)
    }

    /// Accept one signed revocation record. Returns true if it was new to this device.
    ///
    /// This is the ONLY entry point into the denylist, and it is fail-closed in the direction that
    /// matters: an unverifiable blob is rejected outright rather than stored "in case", so no amount of
    /// junk from the control plane can grow the list or slow the gate. Records are append-only and
    /// deduped by exact bytes.
    ///
    /// Accepting a record also raises our epoch floor to the number of records we now hold. That count
    /// is the DERIVED epoch: every device with the same record set computes the same number without
    /// asking anyone, so the floor stops being a server-supplied counter that a compelled control plane
    /// could deflate, and becomes a function of evidence both sides can check. It stays a lower bound
    /// (it defends cert-only devices against credential rollback); exclusion is the denylist's job.
    pub(crate) fn ingest_revocation_inner(&mut self, blob: &[u8]) -> Result<bool, String> {
        let our = self
            .our_account_pub()
            .ok_or_else(|| "this device has no account identity to check a revocation against".to_string())?;
        if crate::revoke::verify_revocation(&our, blob).is_none() {
            return Err("revocation record did not verify under this account's key".to_string());
        }
        if self.revocations.iter().any(|r| r.as_slice() == blob) {
            return Ok(false);
        }
        if self.revocations.len() >= MAX_REVOCATIONS {
            return Err("this account is at its revocation record limit".to_string());
        }
        self.revocations.push(blob.to_vec());
        let derived = self.revoked_device_keys().len() as u64;
        self.raise_floor(&our, derived);
        Ok(true)
    }

    /// Seed-holder: issue a revocation record for `device_sig_key` and adopt it locally. Returns the
    /// record as hex for the caller to publish, so every other device of this account learns it.
    ///
    /// Refusing to revoke our OWN key is deliberate. This device would immediately deny itself at its
    /// own gate and could never be re-admitted, and it is the device holding the account key, so the
    /// record it just wrote would be the last thing it ever authored. Revoking the current device is a
    /// separate, server-side flow that ends in a wipe.
    pub(crate) fn revoke_device_inner(&mut self, device_sig_key_hex: &str, issued_seq: u64) -> Result<String, String> {
        let target = hex_to_bytes(device_sig_key_hex)?;
        if target.as_slice() == self.signer.public() {
            return Err("a device cannot revoke itself".to_string());
        }
        let aak = self
            .aak
            .as_ref()
            .ok_or_else(|| "this device cannot revoke others (no account key)".to_string())?;
        let record = crate::revoke::sign_revocation(aak, &target, issued_seq)?;
        self.ingest_revocation_inner(&record)?;
        Ok(hex(&record))
    }

    /// Recompute one conversation's trusted account-key set from its roster: an account is trusted iff
    /// at least one of its devices in that group presents a credential whose AAK certificate verifies
    /// over that device's signature key. Called only when establishing the conversation (create or
    /// join), so the gate's allow-list is the set of accounts present at formation. Floors each account
    /// at the device-global high-water and raises that high-water for any newly-observed-higher epoch.
    fn recompute_trusted_for(&mut self, gid: &[u8]) {
        // Gather (aak, min_epoch) from the roster, releasing the groups borrow before touching floors.
        let mut trusted = match self.groups.get(gid) {
            Some(slot) => gather_roster_trusted(&slot.group),
            None => return,
        };
        for entry in trusted.iter_mut() {
            entry.1 = self.effective_floor(&entry.0, entry.1);
        }
        let raises: Vec<(Vec<u8>, u64)> = trusted.iter().map(|(k, e)| (k.clone(), *e)).collect();
        for (k, e) in raises {
            self.raise_floor(&k, e);
        }
        if let Some(slot) = self.groups.get_mut(gid) {
            slot.trusted_aaks = trusted;
        }
    }

    fn encrypt_inner(&mut self, gid_hex: &str, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let gid = hex_to_bytes(gid_hex)?;
        let slot = self
            .groups
            .get_mut(&gid)
            .ok_or_else(|| "no such conversation".to_string())?;
        let out = slot
            .group
            .create_message(&self.provider, &self.signer, plaintext)
            .map_err(|e| format!("encrypt: {e:?}"))?;
        // NOTE: a real send does NOT refill the flush budget, deliberately. What keeps us inside the
        // peer's window is the generation THE PEER HAS RECEIVED, and our own encrypt establishes no such
        // thing: the message may never be delivered, may be dropped, may sit undelivered for days. An
        // earlier cut reset the counter here, which meant a device could refill its budget indefinitely
        // by sending into the void. An epoch change (a membership commit) is the only thing that
        // genuinely resets the peer's expectations, and it is where the refill happens: see the epoch
        // check in flush_receive_ratchet_inner.
        out.tls_serialize_detached()
            .map_err(|e| format!("serialize message: {e:?}"))
    }

    /// Persist the ADVANCED receive ratchet for one conversation, so a device seized powered-off does
    /// not hand over the keys to messages it has already processed.
    ///
    /// Why this exists: OpenMLS writes its message secrets when it ENCRYPTS or merges a commit, never
    /// when it decrypts. Processing an inbound message advances the ratchet in memory only, so the
    /// sealed at-rest blob keeps a snapshot from the last send or commit. From that snapshot every
    /// application message any member sent in the current epoch is re-derivable, which is exactly the
    /// exposure honest-limits item 10 describes. There is no public "flush" in OpenMLS 0.6, but
    /// encrypting is a flush: we build one message, throw the ciphertext away, and the advanced state
    /// lands in provider storage where export_sealed will pick it up.
    ///
    /// The cost is one of OUR send generations per call. A peer refuses a generation jump beyond its
    /// forward distance, so the budget is capped PER EPOCH: generations restart at 0 when the group
    /// advances, so a membership change refills it, while a plain send does not (see encrypt_inner).
    /// Returns false when this epoch's budget is spent, so the caller can stop re-sealing for nothing.
    pub(crate) fn flush_receive_ratchet_inner(&mut self, gid_hex: &str) -> Result<bool, String> {
        let gid = hex_to_bytes(gid_hex)?;
        let slot = self
            .groups
            .get_mut(&gid)
            .ok_or_else(|| "no such conversation".to_string())?;
        // Refill on an epoch change, checked HERE rather than at each commit-merge site: there are eight
        // of them (own commit, merged peer commit, staged confirm, self-heal, ...) and one missed site
        // would silently reinstate the lifetime cap. Reading the epoch at the point of use cannot miss one.
        let epoch = slot.group.epoch().as_u64();
        if slot.flush_epoch != epoch {
            slot.flush_epoch = epoch;
            slot.flush_burns = 0;
        }
        if slot.flush_burns >= FLUSH_BURN_BUDGET {
            return Ok(false);
        }
        slot.group
            .create_message(&self.provider, &self.signer, b"")
            .map_err(|e| format!("flush: {e:?}"))?;
        slot.flush_burns += 1;
        Ok(true)
    }

    fn decrypt_inner(&mut self, gid_hex: &str, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        let (routed, received) = self.receive_inner(ciphertext)?;
        if hex(&routed) != gid_hex {
            return Err("message for a different conversation".to_string());
        }
        match received {
            Received::Application { plaintext, .. } => Ok(plaintext),
            _ => Err("not an application message".to_string()),
        }
    }

    /// Create a NEW conversation group and add ALL the given members (peer devices + our own siblings)
    /// in one commit. Returns (welcome, group_id): the single Welcome every added member joins from, and
    /// the new conversation's id (the stable key the caller uses for all subsequent operations).
    pub(crate) fn create_group_inner(&mut self, key_packages: &[Vec<u8>]) -> Result<(Vec<u8>, Vec<u8>), String> {
        if key_packages.is_empty() {
            return Err("a group needs at least one other member".to_string());
        }
        let mut validated = Vec::with_capacity(key_packages.len());
        for kp_bytes in key_packages {
            let kp_in = KeyPackageIn::tls_deserialize_exact(kp_bytes)
                .map_err(|e| format!("parse key package: {e:?}"))?;
            let kp = kp_in
                .validate(self.provider.crypto(), ProtocolVersion::Mls10)
                .map_err(|e| format!("validate key package: {e:?}"))?;
            validated.push(kp);
        }
        let cfg = group_create_config();
        let mut group = MlsGroup::new(&self.provider, &self.signer, &cfg, self.credential.clone())
            .map_err(|e| format!("create group: {e:?}"))?;
        let (_commit, welcome_out, _gi) = group
            .add_members(&self.provider, &self.signer, &validated)
            .map_err(|e| format!("add members: {e:?}"))?;
        group
            .merge_pending_commit(&self.provider)
            .map_err(|e| format!("merge commit: {e:?}"))?;
        let welcome = welcome_out
            .tls_serialize_detached()
            .map_err(|e| format!("serialize welcome: {e:?}"))?;
        // adopt_group establishes the gate's allow-list from the roster (the creator verified the peer
        // out of band before fetching their key packages), ADR-022 P2.
        let gid = self.adopt_group(group)?;
        Ok((welcome, gid))
    }

    /// Create the HIDDEN OWN-DEVICES self-group, enforcing the self predicate at BIRTH: every added
    /// key package's credential must chain to OUR account (parse + same account key + verifying cert).
    /// Only the self-group creation path uses this; peer conversations keep the ungated TOFU create
    /// (first contact with a legacy peer must still work). A stale pre-authorization package can
    /// therefore never mint a poisoned self-group again; the caller skips the consumed package and
    /// retries with the next one.
    pub(crate) fn create_self_group_inner(&mut self, key_packages: &[Vec<u8>]) -> Result<(Vec<u8>, Vec<u8>), String> {
        let our = self
            .our_account_pub()
            .ok_or_else(|| "note to self needs an authorized device".to_string())?;
        for kp_bytes in key_packages {
            let kp_in = KeyPackageIn::tls_deserialize_exact(kp_bytes)
                .map_err(|e| format!("parse key package: {e:?}"))?;
            let kp = kp_in
                .validate(self.provider.crypto(), ProtocolVersion::Mls10)
                .map_err(|e| format!("validate key package: {e:?}"))?;
            let sigkey = kp.leaf_node().signature_key().as_slice().to_vec();
            let identity = BasicCredential::try_from(kp.leaf_node().credential().clone())
                .map(|bc| bc.identity().to_vec())
                .unwrap_or_default();
            let ai = parse_auth_identity(&identity)
                .ok_or_else(|| "self-group member without a certificate".to_string())?;
            if ai.aak_pub != our {
                return Err("self-group member from another account".to_string());
            }
            if !verify_device_cert(&ai.aak_pub, ai.cert_epoch, &sigkey, &ai.cert) {
                return Err("self-group member certificate did not verify".to_string());
            }
            // The DENYLIST half of the gate this mirrors (check_added_leaf). Load-bearing here in its
            // own right: the self-group carries the contact graph, so admitting a revoked device would
            // hand the whole buddy list to a device the user has already thrown out.
            if self.is_revoked(&sigkey) {
                return Err("self-group member was revoked by this account".to_string());
            }
            // The FLOOR half: a revoked device's leftover pre-revoke package verifies fine, and only the
            // device-local anti-rollback floor catches it when the directory (an untrusted party) serves
            // it anyway. Still a lower bound, so it backs up the denylist rather than replacing it.
            if ai.cert_epoch < self.effective_floor(&ai.aak_pub, 0) {
                return Err("self-group member certificate epoch below floor".to_string());
            }
        }
        self.create_group_inner(key_packages)
    }

    /// Whether ONE key package would pass the self-group birth gate (parse + our account + verifying
    /// cert + at-or-above floor). The client pre-filters founding targets with this so a single stale
    /// package cannot abort the whole multi-device mint (the birth gate stays as the fail-closed
    /// backstop); the dropped device folds in later via the per-device staged-add heal.
    pub(crate) fn key_package_self_eligible_inner(&self, key_package: &[u8]) -> bool {
        let our = match self.our_account_pub() {
            Some(a) => a,
            None => return false,
        };
        let kp_in = match KeyPackageIn::tls_deserialize_exact(key_package) {
            Ok(k) => k,
            Err(_) => return false,
        };
        let kp = match kp_in.validate(self.provider.crypto(), ProtocolVersion::Mls10) {
            Ok(k) => k,
            Err(_) => return false,
        };
        let sigkey = kp.leaf_node().signature_key().as_slice().to_vec();
        let identity = BasicCredential::try_from(kp.leaf_node().credential().clone())
            .map(|bc| bc.identity().to_vec())
            .unwrap_or_default();
        match parse_auth_identity(&identity) {
            Some(ai) => {
                ai.aak_pub == our
                    && verify_device_cert(&ai.aak_pub, ai.cert_epoch, &sigkey, &ai.cert)
                    && !self.is_revoked(&sigkey)
                    && ai.cert_epoch >= self.effective_floor(&ai.aak_pub, 0)
            }
            None => false,
        }
    }

    /// Create a SOLO group whose only member is this device (no adds, so no Welcome). See `create_self`.
    pub(crate) fn create_self_inner(&mut self) -> Result<Vec<u8>, String> {
        let cfg = group_create_config();
        let group = MlsGroup::new(&self.provider, &self.signer, &cfg, self.credential.clone())
            .map_err(|e| format!("create group: {e:?}"))?;
        // No members to admit: adopt_group registers the group and (when we hold the account key) sets
        // the gate allow-list from the roster, which is just us. is_self_conversation is then true here.
        self.adopt_group(group)
    }

    /// Add one member to an existing conversation. Returns (commit, welcome): commit advances current
    /// members, welcome admits the new one.
    pub(crate) fn add_member_inner(&mut self, gid_hex: &str, key_package: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
        let kp_in = KeyPackageIn::tls_deserialize_exact(key_package)
            .map_err(|e| format!("parse key package: {e:?}"))?;
        let kp = kp_in
            .validate(self.provider.crypto(), ProtocolVersion::Mls10)
            .map_err(|e| format!("validate key package: {e:?}"))?;
        let gid = hex_to_bytes(gid_hex)?;
        // Same adder-side gate as stage_add_inner: this path merges IMMEDIATELY, so an unauthorized
        // leaf admitted here would fork this device from every gate-rejecting receiver on the spot.
        let trusted = self
            .groups
            .get(&gid)
            .ok_or_else(|| "no such conversation".to_string())?
            .trusted_aaks
            .clone();
        if !trusted.is_empty() {
            let sigkey = kp.leaf_node().signature_key().as_slice().to_vec();
            let identity = BasicCredential::try_from(kp.leaf_node().credential().clone())
                .map(|bc| bc.identity().to_vec())
                .unwrap_or_default();
            self.check_added_leaf(&trusted, &sigkey, &identity)?;
        }
        let slot = self
            .groups
            .get_mut(&gid)
            .ok_or_else(|| "no such conversation".to_string())?;
        let (commit, welcome, _gi) = slot
            .group
            .add_members(&self.provider, &self.signer, &[kp])
            .map_err(|e| format!("add member: {e:?}"))?;
        slot.group
            .merge_pending_commit(&self.provider)
            .map_err(|e| format!("merge commit: {e:?}"))?;
        let commit_b = commit
            .tls_serialize_detached()
            .map_err(|e| format!("serialize commit: {e:?}"))?;
        let welcome_b = welcome
            .tls_serialize_detached()
            .map_err(|e| format!("serialize welcome: {e:?}"))?;
        Ok((commit_b, welcome_b))
    }

    /// STAGE an add without merging it (ADR-022 concurrency). Builds the Add commit exactly like
    /// `add_member_inner` but stops short of `merge_pending_commit`, so this device stays on epoch N.
    /// Returns (commit, welcome): publish the commit to the CURRENT group mailbox and deliver the
    /// welcome to the new device. The committer is subscribed to that mailbox, so the FIFO gateway
    /// echoes the commit back; `receive_inner` recognizes our own bytes and confirms (merges), or, if a
    /// competing epoch-N commit arrives first, aborts (clears) and adopts the winner. Either way there
    /// is no fork. The client may also call `confirm_add_inner` on a timeout if no echo arrives.
    pub(crate) fn stage_add_inner(&mut self, gid_hex: &str, key_package: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
        let kp_in = KeyPackageIn::tls_deserialize_exact(key_package)
            .map_err(|e| format!("parse key package: {e:?}"))?;
        let kp = kp_in
            .validate(self.provider.crypto(), ProtocolVersion::Mls10)
            .map_err(|e| format!("validate key package: {e:?}"))?;
        let added_sigkey = kp.leaf_node().signature_key().as_slice().to_vec();
        let gid = hex_to_bytes(gid_hex)?;
        // MIRROR the receive-side gate BEFORE staging: in authorized mode an adder must never build a
        // commit every honest receiver will drop (the adder used to merge it via echo/confirm, forking
        // itself onto a roster with an unauthorized leaf). Plain error: the client skips the consumed
        // package and retries with the next one, draining a poisoned backlog.
        let trusted = self
            .groups
            .get(&gid)
            .ok_or_else(|| "no such conversation".to_string())?
            .trusted_aaks
            .clone();
        if !trusted.is_empty() {
            let identity = BasicCredential::try_from(kp.leaf_node().credential().clone())
                .map(|bc| bc.identity().to_vec())
                .unwrap_or_default();
            self.check_added_leaf(&trusted, &added_sigkey, &identity)?;
        }
        let slot = self
            .groups
            .get_mut(&gid)
            .ok_or_else(|| "no such conversation".to_string())?;
        if slot.pending.is_some() {
            return Err("an add is already in flight".to_string());
        }
        // Clear any pending commit orphaned by a crashed prior session (pending is None here, so any
        // pending commit in storage is a dangling one) so add_members, which errors on a pending commit,
        // can stage cleanly.
        let _ = slot.group.clear_pending_commit(self.provider.storage());
        let (commit, welcome, _gi) = slot
            .group
            .add_members(&self.provider, &self.signer, &[kp])
            .map_err(|e| format!("add member: {e:?}"))?;
        // Deliberately NOT merging: we stay on epoch N until the commit is confirmed.
        let commit_b = commit
            .tls_serialize_detached()
            .map_err(|e| format!("serialize commit: {e:?}"))?;
        let welcome_b = welcome
            .tls_serialize_detached()
            .map_err(|e| format!("serialize welcome: {e:?}"))?;
        slot.pending = Some(Pending::Add { commit: commit_b.clone(), welcome: welcome_b.clone(), added: added_sigkey });
        Ok((commit_b, welcome_b))
    }

    /// CONFIRM the staged add in one conversation by merging its pending commit, advancing to epoch N+1.
    /// Kind-guarded: a no-op unless an Add is staged (the echo path in `receive_inner` may have already
    /// confirmed), so a stray confirmAdd can never merge a staged Remove early. Idempotent. The client
    /// calls this on a timeout when no echo arrived.
    pub(crate) fn confirm_add_inner(&mut self, gid_hex: &str) -> Result<(), String> {
        let gid = hex_to_bytes(gid_hex)?;
        let slot = match self.groups.get_mut(&gid) {
            Some(s) => s,
            None => return Ok(()),
        };
        if !matches!(slot.pending, Some(Pending::Add { .. })) {
            return Ok(());
        }
        slot.pending = None;
        slot.group
            .merge_pending_commit(&self.provider)
            .map_err(|e| format!("merge pending commit: {e:?}"))
    }

    /// ABORT the staged add in one conversation, clearing its pending commit so this device stays on
    /// epoch N with no change (the new device's welcome is simply never confirmed; reconcile retries).
    /// Kind-guarded so a stray abortAdd never clears a published staged Remove (which would strand the
    /// committer at epoch N). Idempotent.
    pub(crate) fn abort_add_inner(&mut self, gid_hex: &str) -> Result<(), String> {
        let gid = hex_to_bytes(gid_hex)?;
        if let Some(slot) = self.groups.get_mut(&gid) {
            if matches!(slot.pending, Some(Pending::Add { .. })) {
                slot.pending = None;
                slot.group
                    .clear_pending_commit(self.provider.storage())
                    .map_err(|e| format!("clear pending commit: {e:?}"))?;
            }
        }
        Ok(())
    }

    /// Remove a member by signature key from one conversation. Returns the commit that rotates the
    /// group secrets so the removed device is locked out of future messages (forward-secure exclusion).
    pub(crate) fn remove_member_inner(&mut self, gid_hex: &str, sig_key_hex: &str) -> Result<Vec<u8>, String> {
        let target = hex_to_bytes(sig_key_hex)?;
        let gid = hex_to_bytes(gid_hex)?;
        let slot = self
            .groups
            .get_mut(&gid)
            .ok_or_else(|| "no such conversation".to_string())?;
        let idx = slot
            .group
            .members()
            .find(|m| m.signature_key == target)
            .map(|m| m.index)
            .ok_or_else(|| "no such member".to_string())?;
        let (commit, _welcome, _gi) = slot
            .group
            .remove_members(&self.provider, &self.signer, &[idx])
            .map_err(|e| format!("remove member: {e:?}"))?;
        slot.group
            .merge_pending_commit(&self.provider)
            .map_err(|e| format!("merge commit: {e:?}"))?;
        commit
            .tls_serialize_detached()
            .map_err(|e| format!("serialize commit: {e:?}"))
    }

    /// STAGE a Remove of one member: build the removal commit but do NOT merge, staying on epoch N until
    /// the commit is confirmed by its own gateway-ordered echo (like `stage_add_inner`). This is the
    /// fork-free removal used by the peer-revoke self-heal: if the publish is lost or a competing commit
    /// wins, the staged remove is cleared and the removal is retried, never merged eagerly. Returns the
    /// serialized commit to publish to the CURRENT group mailbox (no welcome).
    pub(crate) fn stage_remove_inner(&mut self, gid_hex: &str, sig_key_hex: &str) -> Result<Vec<u8>, String> {
        let target = hex_to_bytes(sig_key_hex)?;
        let gid = hex_to_bytes(gid_hex)?;
        let slot = self
            .groups
            .get_mut(&gid)
            .ok_or_else(|| "no such conversation".to_string())?;
        if slot.pending.is_some() {
            return Err("a commit is already in flight".to_string());
        }
        let idx = slot
            .group
            .members()
            .find(|m| m.signature_key == target)
            .map(|m| m.index)
            .ok_or_else(|| "no such member".to_string())?;
        // Clear any pending commit orphaned by a crashed prior session so remove_members can stage cleanly.
        let _ = slot.group.clear_pending_commit(self.provider.storage());
        let (commit, _welcome, _gi) = slot
            .group
            .remove_members(&self.provider, &self.signer, &[idx])
            .map_err(|e| format!("remove member: {e:?}"))?;
        // Deliberately NOT merging: stay on epoch N until this commit is confirmed by its own echo.
        let commit_b = commit
            .tls_serialize_detached()
            .map_err(|e| format!("serialize commit: {e:?}"))?;
        slot.pending = Some(Pending::Remove { commit: commit_b.clone(), removed: target });
        Ok(commit_b)
    }

    /// The staged pending op in one conversation, for the reload re-arm: 0 = none, 1 = Add, 2 = Remove.
    pub(crate) fn pending_kind_inner(&self, gid_hex: &str) -> Result<u32, String> {
        let gid = hex_to_bytes(gid_hex)?;
        Ok(match self.groups.get(&gid).and_then(|s| s.pending.as_ref()) {
            Some(Pending::Add { .. }) => 1,
            Some(Pending::Remove { .. }) => 2,
            None => 0,
        })
    }

    /// The staged commit's target device signature key (hex), or '' when nothing is staged.
    pub(crate) fn pending_target_inner(&self, gid_hex: &str) -> Result<String, String> {
        let gid = hex_to_bytes(gid_hex)?;
        Ok(match self.groups.get(&gid).and_then(|s| s.pending.as_ref()) {
            Some(Pending::Add { added, .. }) => hex(added),
            Some(Pending::Remove { removed, .. }) => hex(removed),
            None => String::new(),
        })
    }

    /// The staged commit's outgoing wire bytes, or empty when nothing is staged.
    pub(crate) fn pending_commit_inner(&self, gid_hex: &str) -> Result<Vec<u8>, String> {
        let gid = hex_to_bytes(gid_hex)?;
        Ok(self
            .groups
            .get(&gid)
            .and_then(|s| s.pending.as_ref())
            .map(|p| p.commit().to_vec())
            .unwrap_or_default())
    }

    /// The staged Add's Welcome wire bytes (to re-deliver to the added device on reload), or empty when
    /// nothing is staged or the pending op is a Remove.
    pub(crate) fn pending_welcome_inner(&self, gid_hex: &str) -> Result<Vec<u8>, String> {
        let gid = hex_to_bytes(gid_hex)?;
        Ok(match self.groups.get(&gid).and_then(|s| s.pending.as_ref()) {
            Some(Pending::Add { welcome, .. }) => welcome.clone(),
            _ => Vec::new(),
        })
    }

    /// CONFIRM a staged Remove by merging its pending commit (epoch N->N+1, rotating the removed device
    /// out). Kind-guarded: a no-op unless a Remove is staged, so a stray confirmRemove can never merge a
    /// staged Add. Idempotent (the echo path may already have confirmed). The client calls this on a
    /// timeout when no echo arrived.
    pub(crate) fn confirm_remove_inner(&mut self, gid_hex: &str) -> Result<(), String> {
        let gid = hex_to_bytes(gid_hex)?;
        let slot = match self.groups.get_mut(&gid) {
            Some(s) => s,
            None => return Ok(()),
        };
        if !matches!(slot.pending, Some(Pending::Remove { .. })) {
            return Ok(());
        }
        slot.pending = None;
        slot.group
            .merge_pending_commit(&self.provider)
            .map_err(|e| format!("merge pending commit: {e:?}"))
    }

    /// ABORT a staged Remove, clearing its pending commit so this device stays on epoch N. Kind-guarded so
    /// it never disturbs a staged Add. Idempotent.
    pub(crate) fn abort_remove_inner(&mut self, gid_hex: &str) -> Result<(), String> {
        if let Some(slot) = self.groups.get_mut(&hex_to_bytes(gid_hex)?) {
            if matches!(slot.pending, Some(Pending::Remove { .. })) {
                slot.pending = None;
                slot.group
                    .clear_pending_commit(self.provider.storage())
                    .map_err(|e| format!("clear pending commit: {e:?}"))?;
            }
        }
        Ok(())
    }

    /// Receive one inbound MLS message and ROUTE it to the right conversation by the group id in the
    /// message. Returns (group_id, Received). The header group id is an UNTRUSTED hint: `process_message`
    /// re-validates the message against that group's keys, and the authorization gate runs ONLY on a
    /// successfully processed commit, so a misrouted or spoofed-group-id message fails process_message and
    /// never reaches the gate (identical security to the single-group model). A message for a group we do
    /// not hold returns a benign Proposal ("ignored") so the caller simply acks and drops it.
    pub(crate) fn receive_inner(&mut self, ciphertext: &[u8]) -> Result<(Vec<u8>, Received), String> {
        // Errors prefixed DROP_PREFIX are PERMANENT: the frame can never be processed regardless of future
        // state (malformed bytes, or a gate-rejected commit that no honest member will ever accept), so the
        // client acks it to drop it from the bus instead of letting hold-until-ack redeliver it forever - a
        // member cannot pin a mailbox with poison. Every OTHER error is transient (e.g. a future-epoch frame
        // we may process once we catch up) and is left un-acked so it can redeliver, bounded by the TTL.
        let msg_in = MlsMessageIn::tls_deserialize(&mut &ciphertext[..])
            .map_err(|e| format!("{DROP_PREFIX}parse message: {e:?}"))?;
        let protocol = msg_in
            .try_into_protocol_message()
            .map_err(|e| format!("{DROP_PREFIX}not a protocol message: {e:?}"))?;
        let gid = protocol.group_id().as_slice().to_vec();
        if !self.groups.contains_key(&gid) {
            return Ok((gid, Received::Proposal)); // not a conversation we hold: ignore
        }
        // Staged-commit echo confirmation, BEFORE process_message (which cannot process our own commit). If
        // THIS group has an Add OR Remove in flight and this is our own commit echoed back by the FIFO
        // gateway, it was ordered first => confirm by merging the pending commit, advancing to epoch N+1.
        {
            let echo = self
                .groups
                .get(&gid)
                .and_then(|s| s.pending.as_ref())
                .filter(|p| ciphertext == p.commit())
                .map(|p| p.membership());
            if let Some((added, removed)) = echo {
                let slot = self.groups.get_mut(&gid).expect("present");
                slot.pending = None;
                slot.group
                    .merge_pending_commit(&self.provider)
                    .map_err(|e| format!("merge pending commit: {e:?}"))?;
                return Ok((gid, Received::MembershipChanged { added, removed }));
            }
        }
        // Process in the routed slot. Remove it so we hold an OWNED slot (no borrow of self.groups) while
        // also borrowing &self.provider and &self.account_floors for the gate (R5: avoids the aliasing
        // hazard of mutably borrowing a HashMap entry and self.provider at once). On error, restore the
        // slot unchanged (process_message does not mutate state on failure), so a bad message never drops
        // a live conversation; on self-eviction, leave it removed.
        let mut slot = self.groups.remove(&gid).expect("present");
        match self.process_in_slot(&mut slot, protocol, ciphertext) {
            Ok((received, evicted)) => {
                if !evicted {
                    self.groups.insert(gid.clone(), slot);
                }
                Ok((gid, received))
            }
            Err(e) => {
                self.groups.insert(gid, slot);
                Err(e)
            }
        }
    }

    /// Our account's PUBLIC authorization key: the value member certificates must verify under for a
    /// group (or sender) to count as our own account. A seed-holder device derives it from the private
    /// key it holds. A CERT-ONLY device (provisioned by QR or six words; adopt_certificate set its
    /// credential but never the private key) reads it from its OWN adopted credential instead,
    /// re-verifying that credential's certificate over our real leaf key first, so corrupted or forged
    /// local credential bytes can never stand in for the account. Only the PUBLIC value is needed by
    /// these checks, and every MEMBER'S cert stays unforgeable without the account SECRET, so the guard
    /// is exactly as strong either way; without this fallback a cert-only device could not recognize
    /// the own-devices self-group and would surface it as a normal peer conversation (with Add).
    /// None for a legacy/unauthorized identity, which keeps every own-account check false there.
    fn our_account_pub(&self) -> Option<Vec<u8>> {
        if let Some(a) = &self.aak {
            return Some(authz::aak_public(a));
        }
        let bc = BasicCredential::try_from(self.credential.credential.clone()).ok()?;
        let ai = parse_auth_identity(bc.identity())?;
        if authz::verify_device_cert(&ai.aak_pub, ai.cert_epoch, self.signer.public(), &ai.cert) {
            Some(ai.aak_pub)
        } else {
            None
        }
    }

    /// Whether a processed message's AUTHENTICATED sender (the leaf that signed it) is a device of OUR
    /// OWN account: its credential carries our account key (held privately, or read from our own
    /// verified certificate on a cert-only device). The MLS layer authenticated the sender and the gate
    /// vetted that account, so a peer cannot forge this. False for an unauthorized (label-only)
    /// identity. Used to adopt an own-identity update from a sibling vs. store a peer's.
    fn message_from_own_account(&self, group: &MlsGroup, processed: &ProcessedMessage) -> bool {
        let our_aak = match self.our_account_pub() {
            Some(a) => a,
            None => return false,
        };
        // The sender must be a current group member, and its CERTIFICATE must verify against our account
        // key over its REAL leaf signature key. Checking only the claimed account key in the free-form
        // credential identity is not enough: a peer can put our account key in those bytes. The cert,
        // signed by the account secret which a peer does not hold, is what makes "from our own account"
        // unforgeable (the same check the roster gate runs in gather_roster_trusted).
        let sender_idx = match processed.sender() {
            Sender::Member(idx) => *idx,
            _ => return false,
        };
        let member = match group.members().find(|m| m.index == sender_idx) {
            Some(m) => m,
            None => return false,
        };
        let identity = match BasicCredential::try_from(member.credential.clone()) {
            Ok(bc) => bc.identity().to_vec(),
            Err(_) => return false,
        };
        match parse_auth_identity(&identity) {
            Some(ai) => {
                ai.aak_pub == our_aak
                    && verify_device_cert(&ai.aak_pub, ai.cert_epoch, &member.signature_key, &ai.cert)
            }
            None => false,
        }
    }

    /// The fail-closed add-gate body (ADR-022 P2), shared verbatim by the RECEIVE side (process_in_slot,
    /// which DROP-prefixes the error) and the ADDER side (stage_add/add_member, plain skip-and-retry
    /// errors): the added leaf must present a certificate that verifies under an account key trusted in
    /// this conversation AND at or above the effective floor. One body, so the two sides can never drift
    /// (an adder merging what receivers reject was exactly the poisoned-leaf ghost origin).
    fn check_added_leaf(&self, trusted: &[(Vec<u8>, u64)], sigkey: &[u8], identity: &[u8]) -> Result<(), String> {
        let ai = parse_auth_identity(identity).ok_or_else(|| "unauthorized device: missing certificate".to_string())?;
        if !verify_device_cert(&ai.aak_pub, ai.cert_epoch, sigkey, &ai.cert) {
            return Err("unauthorized device: certificate did not verify".to_string());
        }
        // ADR-022 P7, THE EXCLUSION CHECK. Ordered before the epoch compare on purpose: the epoch is a
        // lower bound and a revoked SEED-HOLDER sails over any floor by re-certifying itself at a number
        // of its choosing (it still has the seed on its own disk; revocation is a server-side act that
        // cannot reach it). Only naming the device excludes it. Scoped to OUR OWN account because a
        // record signed by our account key says nothing about a peer's devices, and we hold no authority
        // over those.
        if self.our_account_pub().as_deref() == Some(ai.aak_pub.as_slice()) && self.is_revoked(sigkey) {
            return Err("unauthorized device: revoked by this account".to_string());
        }
        let conv_floor = trusted.iter().find(|(k, _)| k == &ai.aak_pub).map(|(_, e)| *e);
        match conv_floor {
            Some(conv_floor) => {
                let floor = self.effective_floor(&ai.aak_pub, conv_floor);
                if ai.cert_epoch < floor {
                    // Carry the NUMBERS. Without them this rejection is opaque: the app can only say
                    // "could not add the new device", and diagnosing a stuck pairing means guessing at
                    // three invisible values (the leaf's epoch, this conversation's floor, and this
                    // device's global high-water). They are not secret; they are counters.
                    return Err(format!(
                        "unauthorized device: certificate epoch below floor (leaf epoch {}, floor {}, conversation floor {})",
                        ai.cert_epoch, floor, conv_floor
                    ));
                }
            }
            None => return Err("unauthorized device: unknown account key".to_string()),
        }
        Ok(())
    }

    /// Process one message against an already-routed, REMOVED slot. Returns (Received, evicted): evicted
    /// is true only when the commit removed US (the slot is deleted and must not be re-inserted).
    fn process_in_slot(
        &mut self,
        slot: &mut GroupSlot,
        protocol: ProtocolMessage,
        _ciphertext: &[u8],
    ) -> Result<(Received, bool), String> {
        let processed = slot
            .group
            .process_message(&self.provider, protocol)
            .map_err(|e| {
                // BH-S3 refinement: UnableToDecrypt(SecretTreeError(RatchetTypeError)) means the frame
                // names OUR OWN leaf as sender in an epoch we hold (only the own leaf carries an
                // EncryptionRatchet), i.e. our own publish echoed back by the fan-out bus. No future
                // state can ever decrypt it on this device, so mark it droppable: the client acks it
                // and the bus stops holding + redelivering it on every reconnect. Every OTHER decrypt
                // failure stays transient and retained: AeadError is also what a future-epoch commit
                // produces and MUST survive until the epoch catches up.
                let own_echo = matches!(
                    &e,
                    ProcessMessageError::ValidationError(ValidationError::UnableToDecrypt(
                        MessageDecryptionError::SecretTreeError(SecretTreeError::RatchetTypeError)
                    ))
                );
                if own_echo {
                    format!("{DROP_PREFIX}own frame: process message: {e:?}")
                } else {
                    format!("process message: {e:?}")
                }
            })?;
        // Capture whether the authenticated sender is one of our own account's devices BEFORE consuming
        // `processed` (only meaningful for an application message; harmless otherwise).
        let from_own_account = self.message_from_own_account(&slot.group, &processed);
        let staged = match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(app) => {
                return Ok((Received::Application { plaintext: app.into_bytes(), from_own_account }, false));
            }
            ProcessedMessageContent::ProposalMessage(_)
            | ProcessedMessageContent::ExternalJoinProposalMessage(_) => {
                return Ok((Received::Proposal, false));
            }
            ProcessedMessageContent::StagedCommitMessage(staged) => staged,
        };
        // Collect the membership delta BEFORE merging (merge consumes the staged commit). For each added
        // device, capture its signature key AND its credential identity for the authorization gate.
        let added_auth: Vec<(Vec<u8>, Vec<u8>)> = staged
            .add_proposals()
            .map(|p| {
                let leaf = p.add_proposal().key_package().leaf_node();
                let sigkey = leaf.signature_key().as_slice().to_vec();
                let identity = BasicCredential::try_from(leaf.credential().clone())
                    .map(|bc| bc.identity().to_vec())
                    .unwrap_or_default();
                (sigkey, identity)
            })
            .collect();
        let added: Vec<Vec<u8>> = added_auth.iter().map(|(k, _)| k.clone()).collect();
        let removed: Vec<Vec<u8>> = staged
            .remove_proposals()
            .filter_map(|p| {
                let idx = p.remove_proposal().removed();
                slot.group.members().find(|m| m.index == idx).map(|m| m.signature_key)
            })
            .collect();
        let self_removed = staged.self_removed();
        if self_removed {
            // We were removed: drop the whole group (which clears any pending commit in storage too).
            let _ = slot.group.delete(self.provider.storage());
            return Ok((Received::Evicted, true));
        }
        // Fail-closed authorization gate (ADR-022 P2): in authorized mode, every device this commit adds
        // must present a certificate that verifies under an account key trusted in THIS conversation AND
        // at or above the effective floor (max of the per-conversation floor and the device-global
        // high-water). A forged/unauthorized/below-floor add is rejected here and the commit is NEVER
        // merged. We do this BEFORE touching our own pending add, so a REJECTED competing commit leaves
        // our staged add intact (the epoch did not advance; we can still confirm our own add).
        if !slot.trusted_aaks.is_empty() {
            for (sigkey, identity) in &added_auth {
                // A gate rejection is PERMANENT (DROP_PREFIX): a commit adding an unauthorized device is
                // rejected identically by every honest member and is never merged, so the client acks it
                // (drops the poison) rather than holding it for redelivery.
                self.check_added_leaf(&slot.trusted_aaks, sigkey, identity)
                    .map_err(|e| format!("{DROP_PREFIX}{e}"))?;
            }
        }
        // The commit is authorized and about to be merged (it WON the epoch). A competing commit reached
        // us while our own Add or Remove to THIS group was in flight: abandon our staged commit (clear the
        // pending commit so merge can advance) and adopt the winner. Never a fork; reconcile re-drives the
        // add or the removal. Only this group's pending commit is touched.
        if slot.pending.take().is_some() {
            let _ = slot.group.clear_pending_commit(self.provider.storage());
        }
        slot.group
            .merge_staged_commit(&self.provider, *staged)
            .map_err(|e| format!("merge staged commit: {e:?}"))?;
        Ok((Received::MembershipChanged { added, removed }, false))
    }

    /// One conversation's roster as sorted signature-key hex strings (every member, including us).
    pub(crate) fn roster_hex_inner(&self, gid_hex: &str) -> Result<Vec<String>, String> {
        let gid = hex_to_bytes(gid_hex)?;
        let slot = self
            .groups
            .get(&gid)
            .ok_or_else(|| "no such conversation".to_string())?;
        let mut keys: Vec<String> = slot.group.members().map(|m| hex(&m.signature_key)).collect();
        keys.sort();
        Ok(keys)
    }

    /// The ids (hex) of every open conversation, for restoring all groups on reconnect.
    pub(crate) fn list_conversations_inner(&self) -> Vec<String> {
        self.groups.keys().map(|g| hex(g)).collect()
    }

    /// True iff EVERY member of this conversation belongs to OUR OWN account (carries the account key we
    /// hold). This identifies the hidden self-group: the private channel that syncs our buddy list (our
    /// contact graph) across our own devices, so it is never surfaced as a peer conversation and the
    /// contact list never rides a roster a peer could read. Cryptographically grounded (each member's
    /// certificate is parsed and its account key compared, the same basis as the per-message
    /// from_own_account flag), so it does not depend on any client-side device-list cache. Returns false
    /// on an unauthorized device (we hold no account key), on an empty group, or the moment any member's
    /// certificate does not carry our account key (a peer is present). Two conjuncts beyond the member
    /// loop: (1) the formation-time trusted_aaks set must contain only our account, so a peer
    /// conversation whose peer devices all left can never classify self (seed-holders only; the set is
    /// empty on a cert-only device, a pre-existing residual); (2) our OWN leaf is exempt from the cert
    /// check (own_leaf_index comes from our own MLS state, and a leaf minted pre-authorization is frozen
    /// certless forever; without the exemption the device's own stale leaf poisons classification and
    /// the real self-group shows as a ghost peer channel). */
    pub(crate) fn close_conversation_inner(&mut self, gid_hex: &str) -> Result<(), String> {
        let gid = hex_to_bytes(gid_hex)?;
        if !self.groups.contains_key(&gid) {
            return Ok(()); // idempotent FIRST: classify_self errors on an unknown id
        }
        if self.classify_self(gid_hex, false)? {
            return Err("refusing to close the own-devices group".to_string());
        }
        // DEFENSE IN DEPTH beyond the lenient classifier (which fail-safes to FALSE in exactly the
        // states where a permanent delete is most dangerous):
        // (1) Pre-cert window: with no account anchor we cannot tell a sibling from a peer. If the
        //     roster holds ANY certified device of SOME account, it could be our own self-group, so
        //     refuse until classification is possible. A legacy label-only group has no such member
        //     and still closes (legacy accounts are not blocked).
        // (2) Formation trust: a group formed to trust ONLY our account is our self-group regardless
        //     of frozen certless leaves (the ghost state); peer conversations carry the peer's aak.
        {
            let slot = self.groups.get(&gid).ok_or_else(|| "no such conversation".to_string())?;
            match self.our_account_pub() {
                None => {
                    let own = slot.group.own_leaf_index();
                    for m in slot.group.members() {
                        if m.index == own {
                            continue;
                        }
                        let certified = BasicCredential::try_from(m.credential.clone())
                            .ok()
                            .and_then(|bc| parse_auth_identity(&bc.identity().to_vec()))
                            .is_some_and(|ai| verify_device_cert(&ai.aak_pub, ai.cert_epoch, &m.signature_key, &ai.cert));
                        if certified {
                            return Err("cannot close while this device's authorization is unsettled".to_string());
                        }
                    }
                }
                Some(our) => {
                    if !slot.trusted_aaks.is_empty() && slot.trusted_aaks.iter().all(|(k, _)| k == &our) {
                        return Err("refusing to close the own-devices group".to_string());
                    }
                }
            }
        }
        if let Some(mut slot) = self.groups.remove(&gid) {
            // Same call the self-eviction path makes: clears the group's MLS state AND any staged
            // pending commit from provider storage, so the sealed export no longer carries it.
            let _ = slot.group.delete(self.provider.storage());
        }
        Ok(())
    }

    /// SG2 SELF-HEAL: abandon a self-group that is provably DEAD, so a poisoned one cannot strand the
    /// account forever. close_conversation_inner deliberately REFUSES to close an own-devices group (a
    /// mis-timed classification must never permanently delete it), which is correct — but it also made
    /// the one unrecoverable state unrecoverable BY THE APP: a self-group holding a frozen certless leaf
    /// can never be repaired in place (MLS never rewrites a leaf credential), never syncs, and the user
    /// had to close it by hand on every device.
    ///
    /// This path is deliberately NARROW, and refuses unless ALL of the following hold, so it can never
    /// become a way to delete a healthy self-group:
    ///   1. we hold an account anchor (otherwise we cannot classify anything: fail closed);
    ///   2. `recorded_self` — the CALLER's durable record that this id is one of its own-devices groups.
    ///      This layer genuinely CANNOT derive that: a peer conversation minted while the peer's leaf was
    ///      still certless is byte-for-byte indistinguishable here from a poisoned self-group (both trust
    ///      only our account and hold one certless member), so deriving it would silently drop a real
    ///      pending peer chat. A test pins exactly that case. The client keeps the recorded set;
    ///   3. the group trusts ONLY our account (formation-time), the crypto-verifiable half of (2);
    ///   4. it is UNLINKED: no member verifies under any account, i.e. it provably has no reachable
    ///      recipient. A self-group with even ONE verified sibling is alive and is REFUSED.
    /// Returns true when it abandoned the group, false when the group was unknown (idempotent).
    pub(crate) fn abandon_dead_self_group_inner(&mut self, gid_hex: &str, recorded_self: bool) -> Result<bool, String> {
        if !recorded_self {
            return Err("not a recorded own-devices group".to_string());
        }
        let gid = hex_to_bytes(gid_hex)?;
        if !self.groups.contains_key(&gid) {
            return Ok(false); // idempotent: nothing to abandon
        }
        let our = self
            .our_account_pub()
            .ok_or_else(|| "cannot abandon while this device's authorization is unsettled".to_string())?;
        {
            let slot = self.groups.get(&gid).ok_or_else(|| "no such conversation".to_string())?;
            // Ours: formed trusting ONLY our account. Anything else is a peer conversation.
            let ours = !slot.trusted_aaks.is_empty() && slot.trusted_aaks.iter().all(|(k, _)| k == &our);
            if !ours {
                return Err("not an own-devices group".to_string());
            }
        }
        // Dead: no member verifies anywhere. A single verified sibling means it still works, so refuse.
        if !self.channel_unlinked_inner(gid_hex)? {
            return Err("this own-devices group is still reachable".to_string());
        }
        if let Some(mut slot) = self.groups.remove(&gid) {
            let _ = slot.group.delete(self.provider.storage());
        }
        Ok(true)
    }

    pub(crate) fn channel_unlinked_inner(&self, gid_hex: &str) -> Result<bool, String> {
        let gid = hex_to_bytes(gid_hex)?;
        let slot = self
            .groups
            .get(&gid)
            .ok_or_else(|| "no such conversation".to_string())?;
        let our_aak = match self.our_account_pub() {
            Some(a) => a,
            None => return Ok(false), // fail-safe: no advisory when we cannot classify anything
        };
        let own = slot.group.own_leaf_index();
        let mut certless_other = false;
        for m in slot.group.members() {
            if m.index == own {
                continue;
            }
            let verified = BasicCredential::try_from(m.credential.clone())
                .ok()
                .and_then(|bc| parse_auth_identity(&bc.identity().to_vec()))
                .filter(|ai| verify_device_cert(&ai.aak_pub, ai.cert_epoch, &m.signature_key, &ai.cert));
            match verified {
                // Our own certed sibling IS a reachable recipient: linked. (Treating it as neutral
                // let a partially-formed self-group read as unreachable, inviting removal.)
                Some(ai) if ai.aak_pub == our_aak => return Ok(false),
                // A verified device of ANOTHER account exists: linked (a real peer, even offline).
                Some(_) => return Ok(false),
                // No member VERIFIES anywhere: a pre-authorization orphan, or a label-only legacy
                // leaf (which may still receive; the advisory copy says "no verified", never "dead").
                None => certless_other = true,
            }
        }
        Ok(certless_other)
    }

    /// The distinct foreign account authority keys among CURRENT members whose certs verify, hex-sorted.
    /// A member with no cert or a non-verifying cert contributes nothing: a forged credential must never
    /// become the key a person is asked to verify. Own-account members (including our own leaf) are
    /// excluded, so the self-group and our siblings inside a peer conversation both yield nothing.
    pub(crate) fn peer_account_keys_inner(&self, gid_hex: &str) -> Result<Vec<String>, String> {
        let gid = hex_to_bytes(gid_hex)?;
        let slot = self
            .groups
            .get(&gid)
            .ok_or_else(|| "no such conversation".to_string())?;
        let our_aak = match self.our_account_pub() {
            Some(a) => a,
            None => return Ok(Vec::new()), // fail-safe: a legacy device cannot anchor verification
        };
        let own = slot.group.own_leaf_index();
        let mut out: Vec<String> = Vec::new();
        for m in slot.group.members() {
            if m.index == own {
                continue;
            }
            let verified = BasicCredential::try_from(m.credential.clone())
                .ok()
                .and_then(|bc| parse_auth_identity(&bc.identity().to_vec()))
                .filter(|ai| verify_device_cert(&ai.aak_pub, ai.cert_epoch, &m.signature_key, &ai.cert));
            if let Some(ai) = verified {
                if ai.aak_pub == our_aak {
                    continue;
                }
                let h = hex(&ai.aak_pub);
                if !out.contains(&h) {
                    out.push(h);
                }
            }
        }
        out.sort();
        Ok(out)
    }

    pub(crate) fn credential_certified_inner(&self) -> bool {
        let identity = match BasicCredential::try_from(self.credential.credential.clone()) {
            Ok(bc) => bc.identity().to_vec(),
            Err(_) => return false,
        };
        match parse_auth_identity(&identity) {
            Some(ai) => verify_device_cert(&ai.aak_pub, ai.cert_epoch, self.signer.public(), &ai.cert),
            None => false,
        }
    }

    pub(crate) fn is_self_conversation_inner(&self, gid_hex: &str) -> Result<bool, String> {
        self.classify_self(gid_hex, false)
    }

    /// STRICT variant: every member INCLUDING our own leaf must carry a verifying certificate under our
    /// account key. Canonical-group selection prefers a strict self-group so a copy that classifies self
    /// only via the own-leaf exemption (our leaf minted pre-cert) can never win a tie against the fully
    /// certified group another device treats as canonical.
    pub(crate) fn is_self_conversation_strict_inner(&self, gid_hex: &str) -> Result<bool, String> {
        self.classify_self(gid_hex, true)
    }

    fn classify_self(&self, gid_hex: &str, strict: bool) -> Result<bool, String> {
        let gid = hex_to_bytes(gid_hex)?;
        let slot = self
            .groups
            .get(&gid)
            .ok_or_else(|| "no such conversation".to_string())?;
        // our_account_pub also covers a CERT-ONLY device (no private account key): it anchors on the
        // account key inside our own verified credential, so such a device still recognizes the
        // self-group instead of mislabeling it as a peer conversation. See our_account_pub for why the
        // guard strength is unchanged.
        let our_aak = match self.our_account_pub() {
            Some(a) => a,
            None => return Ok(false),
        };
        // Every account the group was FORMED to trust must be our own. Without this, a peer conversation
        // whose peer devices all left (their aak still in the formation-time trusted set) would classify
        // self on a roster check alone, and its summary could be hidden and deleted. The set is captured
        // at adopt for any device with an account anchor (seed OR adopted cert) and backfilled when a
        // cert lands after the Welcome; the one residual is a peer that departed before the cert settled.
        if !slot.trusted_aaks.iter().all(|(k, _)| k == &our_aak) {
            return Ok(false);
        }
        let own = slot.group.own_leaf_index();
        let mut any = false;
        for m in slot.group.members() {
            any = true;
            // OWN-LEAF EXEMPTION (lenient mode): our own leaf needs no certificate to prove it is us;
            // its index comes from our own MLS state. A leaf minted from a pre-authorization key package
            // is frozen certless in the roster forever (nothing rewrites leaf credentials), and without
            // the exemption the device's OWN stale leaf poisons classification permanently: the real
            // self-group then shows as a ghost peer channel. Every OTHER member still needs an
            // unforgeable cert under our account secret, so the contact-graph privacy guard holds.
            if !strict && m.index == own {
                continue;
            }
            let identity = match BasicCredential::try_from(m.credential.clone()) {
                Ok(bc) => bc.identity().to_vec(),
                Err(_) => return Ok(false),
            };
            // Each member's CERTIFICATE must verify against our account key over its REAL leaf signature
            // key. Checking only the claimed account key would let a forged credential (our account key in
            // free-form identity bytes over an attacker's own key, with a junk cert) pass, and the buddy
            // list would publish into a group the attacker can read. The cert is unforgeable without the
            // account secret, so this is the load-bearing privacy guard for the contact graph.
            match parse_auth_identity(&identity) {
                Some(ai)
                    if ai.aak_pub == our_aak
                        && verify_device_cert(&ai.aak_pub, ai.cert_epoch, &m.signature_key, &ai.cert) => {}
                _ => return Ok(false),
            }
        }
        Ok(any)
    }

    /// READ-ONLY diagnostic: WHY a conversation is or is not classified as our own-devices self-group.
    /// Mirrors classify_self exactly (lenient mode: our own leaf is exempt), returning a short,
    /// non-sensitive reason string instead of a bool. It CANNOT weaken the privacy guard: it makes no
    /// decision and grants no access; it only names the first member or condition that fails, so a stuck
    /// pairing can be diagnosed by READING the cause instead of guessing at rosters the keyless gateway
    /// cannot show. "self" means every check passed. Never emits key bytes (only member indices).
    fn self_classification_reason(&self, gid_hex: &str) -> String {
        let gid = match hex_to_bytes(gid_hex) {
            Ok(g) => g,
            Err(_) => return "bad conversation id".to_string(),
        };
        let slot = match self.groups.get(&gid) {
            Some(s) => s,
            None => return "no such conversation".to_string(),
        };
        let our_aak = match self.our_account_pub() {
            Some(a) => a,
            None => return "this device has no account anchor (cert not settled)".to_string(),
        };
        // Mirror classify_self's control flow EXACTLY: it does not special-case an empty trusted set. An
        // empty set makes the `.all()` conjunct vacuously true (the documented cert-only-with-departed-
        // peer residual), so classify_self proceeds to the member checks and may still classify self via
        // the own-leaf exemption. An earlier draft early-returned "trusted set empty" here, which
        // DIVERGED from the real decision in that window (the diagnostic said not-self while the group
        // behaved as self). The divergence was in the safe direction, but a diagnostic must not lie about
        // the decision it is diagnosing, so it follows the same path and only names a member that fails.
        if !slot.trusted_aaks.iter().all(|(k, _)| k == &our_aak) {
            return "trusted set includes a foreign account (formed with a peer)".to_string();
        }
        let own = slot.group.own_leaf_index();
        for m in slot.group.members() {
            if m.index == own {
                continue; // own-leaf exemption, same as classify_self lenient mode
            }
            let identity = match BasicCredential::try_from(m.credential.clone()) {
                Ok(bc) => bc.identity().to_vec(),
                Err(_) => return format!("member {} has an unreadable credential", m.index),
            };
            match parse_auth_identity(&identity) {
                None => return format!("member {} has no certificate (legacy/label-only leaf)", m.index),
                Some(ai) if ai.aak_pub != our_aak => {
                    return format!("member {} belongs to a different account", m.index);
                }
                Some(ai) if !verify_device_cert(&ai.aak_pub, ai.cert_epoch, &m.signature_key, &ai.cert) => {
                    return format!("member {} certificate does not verify (epoch {})", m.index, ai.cert_epoch);
                }
                Some(_) => {}
            }
        }
        "self".to_string()
    }

    /// Seed-holder path (ADR-022 P4, provisioning model b): authorize ANOTHER device by signing a
    /// certificate over its signature key at `cert_epoch`. GUARD: recompute the verification-code
    /// digest over the session nonce, this account's key, the key we are about to sign, and the
    /// epoch, and refuse unless it equals the digest the user confirmed out of band. This makes
    /// "confirm one key, sign another" impossible even if a relay swaps payloads after the human
    /// compare. Returns accountPublicKey(32) || certEpoch(8, big-endian) || cert(64), as hex. Errs if
    /// we do not hold the account key.
    pub(crate) fn authorize_device_inner(
        &self,
        device_sig_key_hex: &str,
        cert_epoch: u64,
        session_nonce_hex: &str,
        confirmed_sas_hex: &str,
    ) -> Result<String, String> {
        let aak = self
            .aak
            .as_ref()
            .ok_or_else(|| "this device cannot authorize others (no account key)".to_string())?;
        let device_key = hex_to_bytes(device_sig_key_hex)?;
        let nonce = hex_to_bytes(session_nonce_hex)?;
        let confirmed = hex_to_bytes(confirmed_sas_hex)?;
        // Never re-certify a device this account has revoked. Its key would be denied at our own gate
        // (check_added_leaf), so issuing the certificate would only produce a device that believes it is
        // authorized and can never join anything. A revoked device comes back as a NEW device with a new
        // key, which is what the pairing flow produces anyway.
        if self.is_revoked(&device_key) {
            return Err("that device was revoked; pair it as a new device instead".to_string());
        }
        // Same floor backstop as the scanned path: a certificate below the account floor is dead on
        // arrival. Checked BEFORE the SAS compare so a caller that got the epoch wrong is told so
        // plainly, rather than being sent to fix six words that were never the problem. This path
        // ERRORS rather than clamping, unlike the scanned path: the six-word digest is computed over
        // cert_epoch on BOTH sides, so silently raising it here would break the very compare that makes
        // the ceremony safe.
        let floor = self.effective_floor(&authz::aak_public(aak), 0);
        if cert_epoch < floor {
            return Err(format!(
                "refusing to certify below this account's floor (epoch {cert_epoch} < floor {floor})"
            ));
        }
        let sas = authz::sas_digest(&nonce, &authz::aak_public(aak), &device_key, cert_epoch);
        if sas.as_slice() != confirmed.as_slice() {
            return Err("authorization does not match the confirmed verification code".to_string());
        }
        let cert = authz::sign_device_cert(aak, cert_epoch, &device_key);
        Ok(hex(&authz::aak_public(aak)) + &hex(&cert_epoch.to_be_bytes()) + &hex(&cert))
    }

    /// The QR-scan authorization: sign a certificate for the SCANNED device key with no SAS ceremony
    /// (the scan is the out-of-band authentication). Returns the Grant `aak_pub(32) || epoch(8, BE) ||
    /// cert(64)` as bytes, to be sealed to the new device's ephemeral key by the caller.
    pub(crate) fn authorize_scanned_device_inner(&self, device_sig_key: &[u8], cert_epoch: u64) -> Result<Vec<u8>, String> {
        let aak = self
            .aak
            .as_ref()
            .ok_or_else(|| "this device cannot authorize others (no account key)".to_string())?;
        if device_sig_key.len() != 32 {
            return Err("device signature key must be 32 bytes".to_string());
        }
        // Never re-certify a key this account has revoked: our own gate denies it by identity now, so
        // the certificate would authorize a device that can never join anything. A device the user wants
        // back rejoins as a NEW device with a fresh key, which is what a re-scan produces.
        if self.is_revoked(device_sig_key) {
            return Err("that device was revoked; pair it as a new device instead".to_string());
        }
        // Never mint a certificate our OWN gate would refuse. check_added_leaf rejects a leaf whose
        // cert_epoch is below the account floor, and the floor only rises (raise_floor), so a cert
        // minted below it is dead the instant the new device is staged into any group: pairing reports
        // success, the server row is created, and the add fails forever with no way back. The caller
        // hard-coded 0 here for a long time, which bricked every pairing on any account that had ever
        // revoked a device.
        //
        // CERTIFY AT THE FLOOR rather than erroring. Erroring was the first fix and it is wrong on this
        // path: the caller's epoch comes from the control plane's account counter, our floor is device
        // -local, and any disagreement between the two blocks pairing outright with nothing the user can
        // do about it. Raising is always SAFE (the epoch is a lower bound, so a higher one is strictly
        // more restrictive) and it is the "refuse to certify below what we last saw" rule stated
        // constructively: we never sign below our floor, and we never mint a credential we would deny.
        // The Grant carries the epoch we actually used, so the new device adopts this number, not the
        // one that was asked for. Exclusion does not ride on this value any more; the denylist above
        // does, which is why inflating it here costs nothing.
        let floor = self.effective_floor(&authz::aak_public(aak), 0);
        let cert_epoch = cert_epoch.max(floor);
        let cert = authz::sign_device_cert(aak, cert_epoch, device_sig_key);
        let mut out = Vec::with_capacity(32 + 8 + 64);
        out.extend_from_slice(&authz::aak_public(aak));
        out.extend_from_slice(&cert_epoch.to_be_bytes());
        out.extend_from_slice(&cert);
        Ok(out)
    }

    /// New-device path: adopt a certificate issued by a seed-holder, becoming an authorized member of
    /// that account without ever holding the account key. Verifies fail-closed that the certificate
    /// is valid for OUR OWN signature key at `cert_epoch` under the given account key, then rebuilds
    /// our credential so our key packages carry it. Intended before joining any group.
    pub(crate) fn adopt_certificate_inner(&mut self, aak_pub_hex: &str, cert_epoch: u64, cert_hex: &str) -> Result<(), String> {
        let aak_pub = hex_to_bytes(aak_pub_hex)?;
        let cert = hex_to_bytes(cert_hex)?;
        if !verify_device_cert(&aak_pub, cert_epoch, self.signer.public(), &cert) {
            return Err("certificate does not authorize this device".to_string());
        }
        let identity = authz::encode_auth_identity(&aak_pub, cert_epoch, &cert, &self.label);
        self.credential = CredentialWithKey {
            credential: BasicCredential::new(identity).into(),
            signature_key: self.signer.public().into(),
        };
        // The cert just anchored our account for the first time; groups adopted BEFORE it settled (the
        // normal H1 ordering: Welcomes processed first) carry an empty trusted set. Backfill from the
        // current roster so the classify_self trusted conjunct is live on this device too. Residual: a
        // peer that departed before the cert settled is not recoverable into the set (narrow window).
        let empties: Vec<Vec<u8>> = self
            .groups
            .iter()
            .filter(|(_, slot)| slot.trusted_aaks.is_empty())
            .map(|(gid, _)| gid.clone())
            .collect();
        for gid in empties {
            self.recompute_trusted_for(&gid);
        }
        Ok(())
    }

    /// One conversation's per-epoch group mailbox, shared by all its members (derived from that group's
    /// exporter secret with a fixed context, so every member computes the same value and it rotates per
    /// epoch). Different conversations derive different mailboxes (different group secrets).
    pub(crate) fn group_mailbox_inner(&self, gid_hex: &str) -> Result<String, String> {
        let gid = hex_to_bytes(gid_hex)?;
        let slot = self
            .groups
            .get(&gid)
            .ok_or_else(|| "no such conversation".to_string())?;
        let secret = slot
            .group
            .export_secret(&self.provider, "deaddrop/group-mailbox", b"deaddrop-group-v1", 32)
            .map_err(|e| format!("export secret: {e:?}"))?;
        Ok(hex(&secret))
    }

    fn peer_signature_key_hex_inner(&self, gid_hex: &str) -> Result<String, String> {
        Ok(hex(&self.peer_signature_key(gid_hex)?))
    }

    fn peer_signature_key(&self, gid_hex: &str) -> Result<Vec<u8>, String> {
        let gid = hex_to_bytes(gid_hex)?;
        let slot = self
            .groups
            .get(&gid)
            .ok_or_else(|| "no such conversation".to_string())?;
        let own = slot.group.own_leaf_index();
        let peers: Vec<Vec<u8>> = slot
            .group
            .members()
            .filter(|m| m.index != own)
            .map(|m| m.signature_key)
            .collect();
        match peers.as_slice() {
            [only] => Ok(only.clone()),
            _ => Err(format!("expected exactly one peer, found {}", peers.len())),
        }
    }

    /// Derive an opaque mailbox for `party_key` in one conversation from that group's current epoch
    /// exporter secret. Both parties compute the same value for the same key; it rotates per epoch.
    fn mailbox_for(&self, gid: &[u8], party_key: &[u8]) -> Result<String, String> {
        let slot = self
            .groups
            .get(gid)
            .ok_or_else(|| "no such conversation".to_string())?;
        let secret = slot
            .group
            .export_secret(&self.provider, "deaddrop/mailbox", party_key, 32)
            .map_err(|e| format!("export secret: {e:?}"))?;
        Ok(hex(&secret))
    }

    fn self_mailbox_inner(&self, gid_hex: &str) -> Result<String, String> {
        let gid = hex_to_bytes(gid_hex)?;
        self.mailbox_for(&gid, self.signer.public())
    }

    fn peer_mailbox_inner(&self, gid_hex: &str) -> Result<String, String> {
        let peer_key = self.peer_signature_key(gid_hex)?;
        let gid = hex_to_bytes(gid_hex)?;
        self.mailbox_for(&gid, &peer_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_to_bytes_is_fail_closed_never_panics() {
        assert_eq!(hex_to_bytes("00ff").unwrap(), vec![0x00, 0xff]);
        assert!(hex_to_bytes("abc").is_err()); // odd length
        assert!(hex_to_bytes("zz").is_err()); // non-hex ascii
        assert!(hex_to_bytes("aébc").is_err()); // non-ASCII: must Err, not panic on a char boundary
        assert!(hex_to_bytes("a\u{00ff}").is_err()); // multi-byte char, even byte length
    }

    /// The id (hex) of the single open conversation, for tests that hold exactly one group.
    /// Model a COMPROMISED (or legacy) adder that does not run the adder-side gate for ONE
    /// conversation, so these tests exercise the RECEIVE-side gate (the defense against adders that
    /// bypass client code entirely): clear that slot's trusted set before the malicious stage/add.
    fn ungate(c: &mut Conversation, gid_hex: &str) {
        let gid = hex_to_bytes(gid_hex).unwrap();
        c.groups.get_mut(&gid).unwrap().trusted_aaks.clear();
    }

    fn sole_gid(c: &Conversation) -> String {
        assert_eq!(c.groups.len(), 1, "sole_gid expects exactly one conversation");
        hex(c.groups.keys().next().unwrap())
    }

    // Full 1:1 session round-trip via the Conversation API: accepter creates + adds, offerer
    // joins from the Welcome, then messages flow both directions. Mirrors the lib.rs native
    // round-trip but through the wasm-facing surface.
    fn established_pair() -> (Conversation, Conversation) {
        // Offerer (joiner) publishes a KeyPackage.
        let offerer = Conversation::new_inner("offerer").unwrap();
        let offerer_kp = offerer.key_package().unwrap();

        // Accepter (creator) builds the group and welcomes the offerer.
        let mut accepter = Conversation::new_inner("accepter").unwrap();
        let (welcome, _gid) = accepter.create_and_add_inner(&offerer_kp).unwrap();

        // Offerer joins.
        let mut offerer = offerer;
        offerer.join_from_welcome_inner(&welcome).unwrap();
        (accepter, offerer)
    }

    #[test]
    fn roundtrip_both_directions() {
        let (mut accepter, mut offerer) = established_pair();
        let g = sole_gid(&accepter);

        let ct = accepter.encrypt_inner(&g, b"meet at the dead drop").unwrap();
        assert_eq!(offerer.decrypt_inner(&g, &ct).unwrap(), b"meet at the dead drop");

        let ct2 = offerer.encrypt_inner(&g, b"understood").unwrap();
        assert_eq!(accepter.decrypt_inner(&g, &ct2).unwrap(), b"understood");
    }

    #[test]
    fn peer_key_is_the_other_party_not_self() {
        let (accepter, offerer) = established_pair();
        let ga = sole_gid(&accepter);
        let go = sole_gid(&offerer);
        let accepter_self = accepter.signature_public_key_hex();
        let offerer_self = offerer.signature_public_key_hex();
        // Each side's "peer key" must equal the OTHER party's self key, never its own.
        assert_eq!(accepter.peer_signature_key_hex_inner(&ga).unwrap(), offerer_self);
        assert_eq!(offerer.peer_signature_key_hex_inner(&go).unwrap(), accepter_self);
        assert_ne!(accepter.peer_signature_key_hex_inner(&ga).unwrap(), accepter_self);
    }

    #[test]
    fn cannot_encrypt_before_group_established() {
        let mut lonely = Conversation::new_inner("lonely").unwrap();
        assert!(lonely.encrypt_inner("00", b"hi").is_err());
        assert!(lonely.peer_signature_key_hex_inner("00").is_err());
    }

    #[test]
    fn replayed_ciphertext_is_rejected() {
        let (mut accepter, mut offerer) = established_pair();
        let g = sole_gid(&accepter);
        let ct = accepter.encrypt_inner(&g, b"once").unwrap();
        assert_eq!(offerer.decrypt_inner(&g, &ct).unwrap(), b"once");
        // Replaying the same ciphertext must not yield a second plaintext.
        assert!(offerer.decrypt_inner(&g, &ct).is_err());
    }

    #[test]
    fn wipe_clears_group_and_storage() {
        let (mut accepter, _offerer) = established_pair();
        let g = sole_gid(&accepter);
        assert!(accepter.peer_signature_key_hex_inner(&g).is_ok());
        accepter.wipe();
        assert!(accepter.groups.is_empty());
        // After wipe the conversation can no longer operate.
        assert!(accepter.encrypt_inner(&g, b"after wipe").is_err());
    }

    // M2 Layer 1: a session survives a sealed export + reload under the MSK, INCLUDING the
    // signer (OpenMLS never stores it), so the reloaded session can still sign/encrypt.
    #[test]
    fn sealed_export_reload_preserves_session_and_signer() {
        let (accepter, mut offerer) = established_pair();
        let msk = [42u8; 32];

        // Reload the accepter from a sealed export.
        let sealed = accepter.export_sealed_inner(&msk).unwrap();
        let mut reloaded = Conversation::from_sealed_inner(&msk, &sealed).unwrap();

        // The reloaded session can still SIGN+encrypt (proves signer recovery), and the offerer
        // decrypts it within the same MLS group.
        let gr = sole_gid(&reloaded);
        let go = sole_gid(&offerer);
        let ct = reloaded.encrypt_inner(&gr, b"after reload").unwrap();
        assert_eq!(offerer.decrypt_inner(&go, &ct).unwrap(), b"after reload");
        // Identity is preserved across reload.
        assert_eq!(
            reloaded.signature_public_key_hex(),
            accepter.signature_public_key_hex()
        );
    }

    // PROBE: does a sealed export capture the advanced RECEIVE ratchet, so a reloaded session can
    // keep decrypting NEW messages from the peer? (The code comment warns OpenMLS may not persist
    // the advanced receive ratchet.) This test tells us empirically what reload actually supports.
    #[test]
    fn reload_after_receiving_can_continue_receiving() {
        let (mut accepter, mut offerer) = established_pair();
        let g = sole_gid(&accepter);
        let msk = [7u8; 32];

        // Offerer receives one message (advances the offerer's receive ratchet).
        let ct1 = accepter.encrypt_inner(&g, b"one").unwrap();
        assert_eq!(offerer.decrypt_inner(&g, &ct1).unwrap(), b"one");

        // Offerer reloads AFTER having received.
        let sealed = offerer.export_sealed_inner(&msk).unwrap();
        let mut reloaded = Conversation::from_sealed_inner(&msk, &sealed).unwrap();

        // Accepter sends a NEW message; can the reloaded offerer still decrypt it?
        let ct2 = accepter.encrypt_inner(&g, b"two").unwrap();
        let got = reloaded.decrypt_inner(&g, &ct2);
        assert_eq!(got.unwrap(), b"two", "reloaded session must keep receiving");
    }

    // PROBE: the opaque mailbox derives from group state, so a reloaded session must compute the
    // SAME mailbox (otherwise a reloaded device cannot retrieve messages held for it).
    #[test]
    fn reload_preserves_mailbox() {
        let (accepter, _offerer) = established_pair();
        let g = sole_gid(&accepter);
        let msk = [9u8; 32];
        let before = accepter.self_mailbox_inner(&g).unwrap();
        let sealed = accepter.export_sealed_inner(&msk).unwrap();
        let reloaded = Conversation::from_sealed_inner(&msk, &sealed).unwrap();
        assert_eq!(reloaded.self_mailbox_inner(&g).unwrap(), before);
    }

    // Pins the ADR-015 ACCEPTED RESIDUAL: OpenMLS 0.6 keeps the anti-replay guard in memory, not in
    // the storage map, so a reload loses it and a message already decrypted before the snapshot
    // decrypts AGAIN after reload. This is a known, owner-accepted forward-secrecy residual (bounded
    // by the per-message PMK layer for displayed history; an attacker also needs the retained wire
    // ciphertext). If this test ever starts FAILING (replay rejected after reload), upstream gained
    // receive-ratchet persistence and this is an IMPROVEMENT: flip the assertion and update ADR-015.
    #[test]
    fn reload_replay_residual_is_documented() {
        let (mut accepter, mut offerer) = established_pair();
        let g = sole_gid(&accepter);
        let msk = [11u8; 32];
        let ct1 = accepter.encrypt_inner(&g, b"one").unwrap();
        assert_eq!(offerer.decrypt_inner(&g, &ct1).unwrap(), b"one");

        // Reload AFTER decrypting ct1, then replay ct1 to the reloaded session.
        let sealed = offerer.export_sealed_inner(&msk).unwrap();
        let mut reloaded = Conversation::from_sealed_inner(&msk, &sealed).unwrap();
        let replay = reloaded.decrypt_inner(&g, &ct1);
        assert!(
            replay.is_ok(),
            "accepted residual (ADR-015): replay protection is in-memory only and is lost on reload",
        );
    }

    #[test]
    fn sealed_export_fails_to_open_with_wrong_msk() {
        let (accepter, _offerer) = established_pair();
        let sealed = accepter.export_sealed_inner(&[1u8; 32]).unwrap();
        assert!(Conversation::from_sealed_inner(&[2u8; 32], &sealed).is_err());
    }

    // Sealed sender (P2): each party's inbound mailbox equals what the OTHER party computes as the
    // peer mailbox, so a sender can address the recipient's opaque rotating mailbox without the
    // server learning either identity. The two mailboxes are distinct and opaque.
    #[test]
    fn sealed_sender_mailboxes_agree_across_parties() {
        let (accepter, offerer) = established_pair();
        let ga = sole_gid(&accepter);
        let go = sole_gid(&offerer);
        let a_in = accepter.self_mailbox_inner(&ga);
        let o_in = offerer.self_mailbox_inner(&go);
        // What accepter sends to (peer mailbox) is the offerer's inbound mailbox, and vice versa.
        assert_eq!(accepter.peer_mailbox_inner(&ga).unwrap(), o_in.clone().unwrap());
        assert_eq!(offerer.peer_mailbox_inner(&go).unwrap(), a_in.clone().unwrap());
        // Distinct per party, opaque 64-hex (32 bytes).
        assert_ne!(a_in.clone().unwrap(), o_in.unwrap());
        assert_eq!(a_in.unwrap().len(), 64);
    }

    // ---- N-member group (multi-device, ADR-022 model B / P1) ----

    fn member(label: &str) -> Conversation {
        Conversation::new_inner(label).unwrap()
    }

    /// A 3-member group: A creates it adding B and C in one commit; B and C join from the one Welcome.
    fn established_group_3() -> (Conversation, Conversation, Conversation) {
        let b = member("b");
        let c = member("c");
        let b_kp = b.key_package().unwrap();
        let c_kp = c.key_package().unwrap();
        let mut a = member("a");
        let (welcome, _gid) = a.create_group_inner(&[b_kp, c_kp]).unwrap();
        let mut b = b;
        let mut c = c;
        b.join_from_welcome_inner(&welcome).unwrap();
        c.join_from_welcome_inner(&welcome).unwrap();
        (a, b, c)
    }

    // True simultaneous delivery: every member receives a message, and ANY member can send.
    #[test]
    fn three_member_group_all_receive_and_any_can_send() {
        let (mut a, mut b, mut c) = established_group_3();
        let g = sole_gid(&a);
        let ct = a.encrypt_inner(&g, b"to the group").unwrap();
        // Each member decrypts the same ciphertext independently (the gateway fans it out to all).
        assert_eq!(b.decrypt_inner(&g, &ct).unwrap(), b"to the group");
        assert_eq!(c.decrypt_inner(&g, &ct).unwrap(), b"to the group");
        // A reply from a non-creator reaches everyone else.
        let ct2 = b.encrypt_inner(&g, b"reply from b").unwrap();
        assert_eq!(a.decrypt_inner(&g, &ct2).unwrap(), b"reply from b");
        assert_eq!(c.decrypt_inner(&g, &ct2).unwrap(), b"reply from b");
    }

    // An existing member ingests an Add commit (the core decrypt() change), and the newly added
    // member becomes reachable to everyone.
    #[test]
    fn existing_member_ingests_an_add_and_new_member_is_reachable() {
        let b = member("b");
        let b_kp = b.key_package().unwrap();
        let mut a = member("a");
        let (welcome_ab, _gid) = a.create_group_inner(&[b_kp]).unwrap();
        let g = sole_gid(&a);
        let mut b = b;
        b.join_from_welcome_inner(&welcome_ab).unwrap();

        let c = member("c");
        let c_sig = c.signature_public_key_hex();
        let (commit, welcome_c) = a.add_member_inner(&g, &c.key_package().unwrap()).unwrap();
        match b.receive_inner(&commit).unwrap().1 {
            Received::MembershipChanged { added, removed } => {
                assert!(removed.is_empty());
                assert_eq!(added.iter().map(|k| hex(k)).collect::<Vec<_>>(), vec![c_sig]);
            }
            _ => panic!("expected a membership change"),
        }
        let mut c = c;
        c.join_from_welcome_inner(&welcome_c).unwrap();

        let ct = a.encrypt_inner(&g, b"now three of us").unwrap();
        assert_eq!(b.decrypt_inner(&g, &ct).unwrap(), b"now three of us");
        assert_eq!(c.decrypt_inner(&g, &ct).unwrap(), b"now three of us");
        assert_eq!(a.roster_hex_inner(&g).unwrap().len(), 3);
        assert_eq!(b.roster_hex_inner(&g).unwrap().len(), 3);
    }

    // A Remove rotates the group secrets (forward-secure exclusion): remaining members see the
    // removal, the removed member is evicted and can no longer operate, and the mailbox rotates.
    #[test]
    fn remove_rotates_mailbox_and_evicts_the_removed_member() {
        let (mut a, mut b, mut c) = established_group_3();
        let g = sole_gid(&a);
        let mailbox_before = a.group_mailbox_inner(&g).unwrap();
        let c_sig = c.signature_public_key_hex();

        let commit = a.remove_member_inner(&g, &c_sig).unwrap();
        assert_ne!(a.group_mailbox_inner(&g).unwrap(), mailbox_before, "removal must rotate the epoch");

        match b.receive_inner(&commit).unwrap().1 {
            Received::MembershipChanged { added, removed } => {
                assert!(added.is_empty());
                assert_eq!(removed.iter().map(|k| hex(k)).collect::<Vec<_>>(), vec![c_sig]);
            }
            _ => panic!("expected a membership change"),
        }
        match c.receive_inner(&commit).unwrap().1 {
            Received::Evicted => {}
            _ => panic!("the removed member must be evicted"),
        }
        // A and B agree on the rotated mailbox; the evicted C has no group left.
        assert_eq!(a.group_mailbox_inner(&g).unwrap(), b.group_mailbox_inner(&g).unwrap());
        assert!(c.group_mailbox_inner(&g).is_err());
        let ct = a.encrypt_inner(&g, b"just us now").unwrap();
        assert_eq!(b.decrypt_inner(&g, &ct).unwrap(), b"just us now");
    }

    // A staged Remove stays on epoch N until its OWN echo confirms it (fork-free), then evicts the target
    // and rotates the epoch so the removed device cannot read N+1.
    #[test]
    fn staged_remove_confirms_on_own_echo_and_target_is_gone() {
        let (mut a, mut b, mut c) = established_group_3();
        let g = sole_gid(&a);
        let c_sig = c.signature_public_key_hex();
        let mailbox_before = a.group_mailbox_inner(&g).unwrap();
        let commit = a.stage_remove_inner(&g, &c_sig).unwrap();
        // Staged, not merged: A is still on epoch N and C is still a member locally until the echo.
        assert_eq!(a.group_mailbox_inner(&g).unwrap(), mailbox_before, "staging must not rotate before confirm");
        assert!(a.roster_hex_inner(&g).unwrap().contains(&c_sig), "C is still present until confirm");
        match a.receive_inner(&commit).unwrap().1 {
            Received::MembershipChanged { added, removed } => {
                assert!(added.is_empty());
                assert_eq!(removed.iter().map(|k| hex(k)).collect::<Vec<_>>(), vec![c_sig.clone()]);
            }
            other => panic!("the echo must confirm the staged remove, got {other:?}"),
        }
        assert_ne!(a.group_mailbox_inner(&g).unwrap(), mailbox_before, "confirm must rotate the epoch");
        assert!(!a.roster_hex_inner(&g).unwrap().contains(&c_sig), "C is gone after confirm");
        b.receive_inner(&commit).unwrap();
        match c.receive_inner(&commit).unwrap().1 {
            Received::Evicted => {}
            other => panic!("the removed member must be evicted, got {other:?}"),
        }
        let ct = a.encrypt_inner(&g, b"after the removal").unwrap();
        assert_eq!(b.decrypt_inner(&g, &ct).unwrap(), b"after the removal");
        assert!(c.group_mailbox_inner(&g).is_err(), "the removed device has no group left");
    }

    // Timeout fallback: no echo arrives, so the client confirms the remove explicitly. Idempotent.
    #[test]
    fn staged_remove_confirms_via_explicit_confirm_when_no_echo() {
        let (mut a, mut b, mut c) = established_group_3();
        let g = sole_gid(&a);
        let c_sig = c.signature_public_key_hex();
        let commit = a.stage_remove_inner(&g, &c_sig).unwrap();
        a.confirm_remove_inner(&g).unwrap(); // timeout fallback (no echo seen)
        a.confirm_remove_inner(&g).unwrap(); // idempotent: a second confirm is a no-op
        assert!(!a.roster_hex_inner(&g).unwrap().contains(&c_sig));
        b.receive_inner(&commit).unwrap();
        let _ = c.receive_inner(&commit); // C is evicted
        let ct = a.encrypt_inner(&g, b"confirmed without echo").unwrap();
        assert_eq!(b.decrypt_inner(&g, &ct).unwrap(), b"confirmed without echo");
    }

    // A competing commit that wins the epoch clears A's staged remove: A adopts the winner (no fork). C is
    // NOT removed (A's remove was aborted, not merged), and A can stage a fresh remove.
    #[test]
    fn staged_remove_aborts_on_competing_commit() {
        let (mut a, mut b, c) = established_group_3();
        let ga = sole_gid(&a);
        let gb = sole_gid(&b);
        let c_sig = c.signature_public_key_hex();
        let d = member("d");
        let d_sig = d.signature_public_key_hex();
        // A stages a Remove of C at epoch N; B stages a competing Add of D at epoch N; the FIFO gateway
        // orders B's add first.
        let _remove = a.stage_remove_inner(&ga, &c_sig).unwrap();
        let (commit_b, _welcome_d) = b.stage_add_inner(&gb, &d.key_package().unwrap()).unwrap();
        // A holds a competing staged remove (not its own bytes) => abort the remove, adopt the winner.
        match a.receive_inner(&commit_b).unwrap().1 {
            Received::MembershipChanged { added, removed } => {
                assert!(removed.is_empty(), "A adopted an add, not its aborted remove");
                assert_eq!(added.iter().map(|k| hex(k)).collect::<Vec<_>>(), vec![d_sig]);
            }
            other => panic!("A must abort its remove and adopt the winner, got {other:?}"),
        }
        // No fork: A is on the winner's epoch with D added, and C was NOT removed (the remove was aborted).
        assert!(a.roster_hex_inner(&ga).unwrap().contains(&c_sig), "C stayed: A's remove was aborted");
        // A's staged-remove slot cleared, so A can stage a fresh remove.
        assert!(a.stage_remove_inner(&ga, &c_sig).is_ok(), "the aborted remove must clear the slot");
    }

    // stage_remove refuses an absent member and refuses to stage while any commit is already in flight
    // (add-then-remove and remove-then-add), enforcing the single OpenMLS pending-commit slot.
    #[test]
    fn stage_remove_of_absent_member_and_while_in_flight_err() {
        let (mut a, _b, mut c) = established_group_3();
        let g = sole_gid(&a);
        let c_sig = c.signature_public_key_hex();
        let ghost = member("ghost").signature_public_key_hex();
        assert!(a.stage_remove_inner(&g, &ghost).unwrap_err().contains("no such member"));
        // remove-then-remove
        let _ = a.stage_remove_inner(&g, &c_sig).unwrap();
        assert!(a.stage_remove_inner(&g, &c_sig).unwrap_err().contains("in flight"));
        a.abort_remove_inner(&g).unwrap();
        // add-then-remove: a staged Add blocks a stage_remove
        let d = member("d");
        let _ = a.stage_add_inner(&g, &d.key_package().unwrap()).unwrap();
        assert!(a.stage_remove_inner(&g, &c_sig).unwrap_err().contains("in flight"), "an add in flight blocks a remove");
        a.abort_add_inner(&g).unwrap();
        // remove-then-add: a staged Remove blocks a stage_add
        let _ = a.stage_remove_inner(&g, &c_sig).unwrap();
        let e = member("e");
        assert!(a.stage_add_inner(&g, &e.key_package().unwrap()).is_err(), "a remove in flight blocks an add");
    }

    // The kind-guard: a stray confirmRemove must NEVER merge a staged Add.
    #[test]
    fn confirm_remove_is_a_no_op_when_an_add_is_staged() {
        let (mut a, _b, a_seed, _) = authorized_pair();
        let g = sole_gid(&a);
        let a2 = Conversation::new_authorized_inner("a-phone", &a_seed).unwrap();
        let (commit, _welcome) = a.stage_add_inner(&g, &a2.key_package().unwrap()).unwrap();
        a.confirm_remove_inner(&g).unwrap(); // kind-guarded: must not touch the staged Add
        assert_eq!(a.roster_hex_inner(&g).unwrap().len(), 2, "confirmRemove must not merge the staged add");
        a.receive_inner(&commit).unwrap(); // the add still confirms normally on its own echo
        assert_eq!(a.roster_hex_inner(&g).unwrap().len(), 3);
    }

    // The symmetric kind-guards (H2): a stray confirmAdd/abortAdd must NEVER merge or clear a staged
    // Remove (which would strand the committer at epoch N = fork).
    #[test]
    fn confirm_add_is_a_no_op_when_a_remove_is_staged() {
        let (mut a, _b, mut c) = established_group_3();
        let g = sole_gid(&a);
        let c_sig = c.signature_public_key_hex();
        let commit = a.stage_remove_inner(&g, &c_sig).unwrap();
        a.confirm_add_inner(&g).unwrap(); // kind-guarded: must not merge the staged Remove
        assert!(a.roster_hex_inner(&g).unwrap().contains(&c_sig), "confirmAdd must not merge the staged remove");
        a.receive_inner(&commit).unwrap(); // the remove still confirms normally on its own echo
        assert!(!a.roster_hex_inner(&g).unwrap().contains(&c_sig));
    }

    #[test]
    fn abort_add_is_a_no_op_when_a_remove_is_staged() {
        let (mut a, _b, mut c) = established_group_3();
        let g = sole_gid(&a);
        let c_sig = c.signature_public_key_hex();
        let commit = a.stage_remove_inner(&g, &c_sig).unwrap();
        a.abort_add_inner(&g).unwrap(); // kind-guarded: must NOT clear the published staged Remove
        // The staged remove survived intact and still confirms on its own echo.
        a.receive_inner(&commit).unwrap();
        assert!(!a.roster_hex_inner(&g).unwrap().contains(&c_sig), "abortAdd must not clear the staged remove");
    }

    #[test]
    fn group_mailbox_is_shared_across_all_members() {
        let (a, b, c) = established_group_3();
        let g = sole_gid(&a);
        let m = a.group_mailbox_inner(&g).unwrap();
        assert_eq!(b.group_mailbox_inner(&g).unwrap(), m);
        assert_eq!(c.group_mailbox_inner(&g).unwrap(), m);
        assert_eq!(m.len(), 64);
    }

    // A reloaded member (sealed export + restore) still ingests a later membership commit correctly:
    // membership-commit state DOES persist across reload (merge writes it), unlike the in-memory
    // app-message replay residual (ADR-015).
    #[test]
    fn reloaded_member_still_ingests_a_membership_commit() {
        let b = member("b");
        let b_kp = b.key_package().unwrap();
        let mut a = member("a");
        let (welcome_ab, _gid) = a.create_group_inner(&[b_kp]).unwrap();
        let g = sole_gid(&a);
        let mut b = b;
        b.join_from_welcome_inner(&welcome_ab).unwrap();

        let msk = [5u8; 32];
        let sealed = b.export_sealed_inner(&msk).unwrap();
        let mut b = Conversation::from_sealed_inner(&msk, &sealed).unwrap();

        let c = member("c");
        let (commit, welcome_c) = a.add_member_inner(&g, &c.key_package().unwrap()).unwrap();
        match b.receive_inner(&commit).unwrap().1 {
            Received::MembershipChanged { .. } => {}
            _ => panic!("a reloaded member must ingest the commit"),
        }
        let mut c = c;
        c.join_from_welcome_inner(&welcome_c).unwrap();

        let ct = a.encrypt_inner(&g, b"after reload + add").unwrap();
        assert_eq!(b.decrypt_inner(&g, &ct).unwrap(), b"after reload + add");
        assert_eq!(c.decrypt_inner(&g, &ct).unwrap(), b"after reload + add");
    }

    // ---- Authorized devices + the fail-closed gate (ADR-022 model B / P2) ----

    /// An authorized 1:1 (one device each): A (rooted in a_seed) creates the group adding B (rooted
    /// in b_seed), B joins. Both sides establish the trusted set {A account, B account}.
    fn authorized_pair() -> (Conversation, Conversation, Vec<u8>, Vec<u8>) {
        let a_seed = [10u8; 32];
        let b_seed = [20u8; 32];
        let b = Conversation::new_authorized_inner("b", &b_seed).unwrap();
        let b_kp = b.key_package().unwrap();
        let mut a = Conversation::new_authorized_inner("a", &a_seed).unwrap();
        let (welcome, _gid) = a.create_group_inner(&[b_kp]).unwrap();
        let mut b = b;
        b.join_from_welcome_inner(&welcome).unwrap();
        (a, b, a_seed.to_vec(), b_seed.to_vec())
    }

    /// A structurally-valid KeyPackage whose credential CLAIMS `claimed_aak_pub` but carries a bogus
    /// certificate (not actually signed by that account key). Used to test the gate''s cert check.
    fn forged_authorized_kp(provider: &OpenMlsRustCrypto, claimed_aak_pub: &[u8]) -> Vec<u8> {
        let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm()).unwrap();
        let bogus_cert = vec![0u8; 64];
        let identity = authz::encode_auth_identity(claimed_aak_pub, 0, &bogus_cert, b"forged");
        let cwk = CredentialWithKey {
            credential: BasicCredential::new(identity).into(),
            signature_key: signer.public().into(),
        };
        crate::fresh_key_package_bytes(provider, &signer, cwk, false).unwrap()
    }

    #[test]
    fn authorized_group_delivers_and_establishes_trust() {
        let (mut a, mut b, _, _) = authorized_pair();
        let ga = sole_gid(&a);
        let gb = sole_gid(&b);
        let ct = a.encrypt_inner(&ga, b"hi").unwrap();
        assert_eq!(b.decrypt_inner(&gb, &ct).unwrap(), b"hi");
        // Both accounts are trusted on both sides, and each side advertises a non-empty account key.
        assert_eq!(a.groups.values().next().unwrap().trusted_aaks.len(), 2);
        assert_eq!(b.groups.values().next().unwrap().trusted_aaks.len(), 2);
        assert_eq!(a.account_key_hex().len(), 64);
    }

    #[test]
    fn peer_account_keys_sees_exactly_the_other_account_from_both_ends() {
        let (a, b, _, _) = authorized_pair();
        let ga = sole_gid(&a);
        let gb = sole_gid(&b);
        let from_a = a.peer_account_keys_inner(&ga).unwrap();
        let from_b = b.peer_account_keys_inner(&gb).unwrap();
        assert_eq!(from_a.len(), 1);
        assert_eq!(from_b.len(), 1);
        assert_eq!(from_a[0], b.account_key_hex());
        assert_eq!(from_b[0], a.account_key_hex());
        // Each side's view of the OTHER's key digests to exactly what that other side renders for
        // itself, which is what makes the two halves comparable over the phone.
        assert_eq!(
            authz::contact_ident_digest(&hex_to_bytes(&from_a[0]).unwrap()),
            authz::contact_ident_digest(&hex_to_bytes(&b.account_key_hex()).unwrap())
        );
        assert_eq!(
            authz::contact_ident_digest(&hex_to_bytes(&from_b[0]).unwrap()),
            authz::contact_ident_digest(&hex_to_bytes(&a.account_key_hex()).unwrap())
        );
    }

    #[test]
    fn peer_account_keys_ignores_own_siblings_and_the_self_group() {
        let (mut a, b, a_seed, _) = authorized_pair();
        let ga = sole_gid(&a);
        // A adds its own second device to the peer conversation: still exactly one FOREIGN account.
        let a2 = Conversation::new_authorized_inner("a-phone", &a_seed).unwrap();
        let (_commit, _welcome) = a.add_member_inner(&ga, &a2.key_package().unwrap()).unwrap();
        let keys = a.peer_account_keys_inner(&ga).unwrap();
        assert_eq!(keys, vec![b.account_key_hex()]);
        // A solo self-group has no foreign members at all.
        let mut solo = Conversation::new_authorized_inner("solo", &[7u8; 32]).unwrap();
        let gid = solo.create_self_inner().unwrap();
        let g = hex(&gid);
        assert_eq!(solo.peer_account_keys_inner(&g).unwrap(), Vec::<String>::new());
    }

    #[test]
    fn peer_account_keys_excludes_a_forged_certificate() {
        // A member whose credential CLAIMS an account key but whose cert does not verify must not
        // surface as a verification anchor: pinning a forged key would bless the attacker.
        let (mut a, _b, _, _) = authorized_pair();
        let ga = sole_gid(&a);
        let before = a.peer_account_keys_inner(&ga).unwrap();
        let provider = OpenMlsRustCrypto::default();
        let claimed = [42u8; 32];
        let kp = forged_authorized_kp(&provider, &claimed);
        // The add gate itself refuses the forged member; either way the claimed key never appears.
        let _ = a.add_member_inner(&ga, &kp);
        let after = a.peer_account_keys_inner(&ga).unwrap();
        assert_eq!(before, after);
        assert!(!after.contains(&hex(&claimed)));
    }

    #[test]
    fn flushing_the_receive_ratchet_makes_processed_messages_unrecoverable_after_reload() {
        // The exposure: OpenMLS persists message secrets on SEND, never on receive, so a sealed blob
        // taken from a powered-off device still derives the keys for messages the device already read.
        let msk = [9u8; 32];
        let (mut a, mut b, _, _) = authorized_pair();
        let ga = sole_gid(&a);
        let gb = sole_gid(&b);
        let ct = b.encrypt_inner(&gb, b"the meeting is at noon").unwrap();
        assert_eq!(a.decrypt_inner(&ga, &ct).unwrap(), b"the meeting is at noon");

        // WITHOUT a flush: seal, reload, and the already-read ciphertext decrypts again.
        let stale = a.export_sealed_inner(&msk).unwrap();
        let mut reloaded = Conversation::from_sealed_inner(&msk, &stale).unwrap();
        assert!(
            reloaded.decrypt_inner(&ga, &ct).is_ok(),
            "precondition: the un-flushed blob still recovers a processed message"
        );

        // WITH a flush before sealing: the stored ratchet is past that message and it is gone.
        assert!(a.flush_receive_ratchet_inner(&ga).unwrap());
        let flushed = a.export_sealed_inner(&msk).unwrap();
        let mut after = Conversation::from_sealed_inner(&msk, &flushed).unwrap();
        assert!(
            after.decrypt_inner(&ga, &ct).is_err(),
            "a flushed blob must not recover a message the device already processed"
        );
    }

    #[test]
    #[ignore] // timing probe, run with: cargo test perf_reseal -- --ignored --nocapture
    fn perf_reseal_cost_by_conversation_count() {
        use std::time::Instant;
        let msk = [4u8; 32];
        for n in [1usize, 5, 20, 50] {
            let mut a = Conversation::new_authorized_inner("a", &[10u8; 32]).unwrap();
            for i in 0..n {
                let b = Conversation::new_authorized_inner("b", &[(20 + i) as u8; 32]).unwrap();
                a.create_group_inner(&[b.key_package().unwrap()]).unwrap();
            }
            // A little traffic so the storage map is not empty.
            let gids: Vec<String> = a.groups.keys().map(|g| hex(g)).collect();
            for g in &gids {
                for _ in 0..5 {
                    a.encrypt_inner(g, b"some traffic").unwrap();
                }
            }
            let t = Instant::now();
            let blob = a.export_sealed_inner(&msk).unwrap();
            let seal_us = t.elapsed().as_micros();
            let t2 = Instant::now();
            let _ = Conversation::from_sealed_inner(&msk, &blob).unwrap();
            let load_us = t2.elapsed().as_micros();
            println!("conversations={n:3}  blob={:7} bytes  seal={seal_us:6}us  load={load_us:6}us", blob.len());
        }
    }

    #[test]
    fn the_flush_budget_survives_reload_so_a_lurker_never_drifts_past_a_peer() {
        // The defect: flush_burns lived only in memory while the send generation rode along inside the
        // sealed blob, so the cap was really "per page load". Six sessions of a device that only ever
        // LISTENS pushed its generation past the peer's forward-distance window (1000), and its eventual
        // first real message became undecryptable by everyone, silently and permanently.
        let msk = [3u8; 32];
        let (mut a, mut b, _, _) = authorized_pair();
        let ga = sole_gid(&a);
        let gb = sole_gid(&b);
        for _ in 0..6 {
            while a.flush_receive_ratchet_inner(&ga).unwrap() {}
            let sealed = a.export_sealed_inner(&msk).unwrap();
            a = Conversation::from_sealed_inner(&msk, &sealed).unwrap();
        }
        // After six reloads the budget is still spent, not refreshed six times over.
        assert!(!a.flush_receive_ratchet_inner(&ga).unwrap(), "the cap must survive a reload");
        // And the peer can still read us, which is what the cap exists to guarantee.
        let ct = a.encrypt_inner(&ga, b"still reachable after six reloads").unwrap();
        assert_eq!(b.decrypt_inner(&gb, &ct).unwrap(), b"still reachable after six reloads");
    }

    #[test]
    fn the_flush_budget_is_bounded_per_epoch_and_a_send_does_not_refill_it() {
        // Each flush spends one of our send generations; a peer refuses too large a jump, so the budget
        // is capped. It is capped PER EPOCH: a send must not refill it, because our own encrypt proves
        // nothing about what the peer has RECEIVED, so a device could otherwise refill indefinitely by
        // sending into the void and still drift past the peer's window.
        //
        // The per-epoch half of that used to be aspiration: nothing reset the counter, so the cap was
        // really per group LIFETIME, and after 200 flushes the at-rest protection silently switched
        // itself off forever. This test earlier asserted only the send half, which is how the name
        // stayed true while the code was not. Both halves are asserted now.
        let (mut a, _b, _, _) = authorized_pair();
        let ga = sole_gid(&a);
        for i in 0..FLUSH_BURN_BUDGET {
            assert!(a.flush_receive_ratchet_inner(&ga).unwrap(), "flush {i} must be allowed");
        }
        assert!(!a.flush_receive_ratchet_inner(&ga).unwrap(), "the budget must stop the next flush");
        a.encrypt_inner(&ga, b"a real message").unwrap();
        assert!(!a.flush_receive_ratchet_inner(&ga).unwrap(), "a send must NOT buy the budget back");
    }

    #[test]
    fn an_epoch_change_refills_the_flush_budget_but_a_reload_inside_one_epoch_does_not() {
        // Generations restart at 0 in a new epoch, so the peer's forward-distance window resets with it
        // and a fresh budget is safe. Without this the counter only ever rose and a long-lived
        // conversation permanently lost the protection. The second half is the trap that was already
        // fixed once: the refill must come from the EPOCH advancing, never from a page reload.
        let msk = [9u8; 32];
        let (mut a, mut b, mut c) = established_group_3();
        let ga = sole_gid(&a);
        let gb = sole_gid(&b);
        while a.flush_receive_ratchet_inner(&ga).unwrap() {}
        assert!(!a.flush_receive_ratchet_inner(&ga).unwrap(), "spent");

        // A reload inside the SAME epoch must not hand the budget back.
        let sealed = a.export_sealed_inner(&msk).unwrap();
        let mut a = Conversation::from_sealed_inner(&msk, &sealed).unwrap();
        assert!(!a.flush_receive_ratchet_inner(&ga).unwrap(), "a reload must NOT refill inside one epoch");

        // A membership commit advances the epoch, and now it must.
        let commit = a.remove_member_inner(&ga, &c.signature_public_key_hex()).unwrap();
        b.receive_inner(&commit).unwrap();
        c.receive_inner(&commit).unwrap();
        assert!(a.flush_receive_ratchet_inner(&ga).unwrap(), "a new epoch must refill the budget");

        // And spending the fresh budget still leaves us inside the peer's window.
        while a.flush_receive_ratchet_inner(&ga).unwrap() {}
        let ct = a.encrypt_inner(&ga, b"readable after a refilled budget").unwrap();
        assert_eq!(b.decrypt_inner(&gb, &ct).unwrap(), b"readable after a refilled budget");
    }

    #[test]
    fn a_flushed_sender_is_still_readable_by_its_peer() {
        // The whole budget must not push our send generation past what a peer will accept.
        let (mut a, mut b, _, _) = authorized_pair();
        let ga = sole_gid(&a);
        let gb = sole_gid(&b);
        for _ in 0..FLUSH_BURN_BUDGET {
            a.flush_receive_ratchet_inner(&ga).unwrap();
        }
        let ct = a.encrypt_inner(&ga, b"still reachable").unwrap();
        assert_eq!(b.decrypt_inner(&gb, &ct).unwrap(), b"still reachable");
    }

    #[test]
    fn contact_ident_digest_is_per_key_stable_and_distinct() {
        let k1 = [1u8; 32];
        let k2 = [2u8; 32];
        // Stable: the same key always renders the same words, so two people can compare at any time.
        assert_eq!(authz::contact_ident_digest(&k1), authz::contact_ident_digest(&k1));
        // Distinct per key: a substituted account key produces different words on the other screen.
        assert_ne!(authz::contact_ident_digest(&k1), authz::contact_ident_digest(&k2));
        // The digest depends on the key throughout, not only on the first block: flipping the LAST
        // byte changes it (a chain that dropped the key after round 0 would not catch this).
        let mut k3 = k1;
        k3[31] ^= 0x01;
        assert_ne!(authz::contact_ident_digest(&k1), authz::contact_ident_digest(&k3));
    }

    #[test]
    fn a_man_in_the_middle_cannot_make_both_sides_show_the_same_words() {
        // The attack the pairwise design lost to: Mallory picks BOTH substituted keys. Per side, each
        // honest key is a FIXED target, so the halves Alice and Bob read to each other differ unless
        // Mallory second-preimages each one.
        let (a, b, _, _) = authorized_pair();
        let a_key = hex_to_bytes(&a.account_key_hex()).unwrap();
        let b_key = hex_to_bytes(&b.account_key_hex()).unwrap();
        let m1 = [0xAAu8; 32]; // shown to Alice in place of Bob
        let m2 = [0xBBu8; 32]; // shown to Bob in place of Alice
        // What Alice reads out (her own) vs what Bob expects for her (the key he was handed).
        assert_ne!(authz::contact_ident_digest(&a_key), authz::contact_ident_digest(&m2));
        // What Bob reads out vs what Alice was handed for him.
        assert_ne!(authz::contact_ident_digest(&b_key), authz::contact_ident_digest(&m1));
    }

    #[test]
    fn an_authorized_own_device_add_is_accepted() {
        let (mut a, mut b, a_seed, _) = authorized_pair();
        let ga = sole_gid(&a);
        let gb = sole_gid(&b);
        // A's second device, authorized under A's SAME account key.
        let a2 = Conversation::new_authorized_inner("a-phone", &a_seed).unwrap();
        let (commit, welcome) = a.add_member_inner(&ga, &a2.key_package().unwrap()).unwrap();
        match b.receive_inner(&commit).unwrap().1 {
            Received::MembershipChanged { .. } => {}
            other => panic!("expected an accepted membership change, got {other:?}"),
        }
        let mut a2 = a2;
        a2.join_from_welcome_inner(&welcome).unwrap();
        // The new device receives group traffic from the peer.
        let ct = b.encrypt_inner(&gb, b"to all of A").unwrap();
        let g2 = sole_gid(&a2);
        assert_eq!(a2.decrypt_inner(&g2, &ct).unwrap(), b"to all of A");
    }

    #[test]
    fn an_add_under_an_unknown_account_is_rejected() {
        let (mut a, mut b, _, _) = authorized_pair();
        let ga = sole_gid(&a);
        let gb = sole_gid(&b);
        // A, acting compromised, adds a device authorized under a DIFFERENT, untrusted account key.
        let attacker = Conversation::new_authorized_inner("attacker", &[99u8; 32]).unwrap();
        ungate(&mut a, &ga);
        let (commit, _welcome) = a.add_member_inner(&ga, &attacker.key_package().unwrap()).unwrap();
        let err = b.receive_inner(&commit).unwrap_err();
        assert!(err.contains("unknown account key"), "got: {err}");
        // B did not merge: it still knows only the original two devices, so no silent extra reader.
        assert_eq!(b.roster_hex_inner(&gb).unwrap().len(), 2);
    }

    #[test]
    fn an_add_with_a_forged_certificate_is_rejected() {
        let (mut a, mut b, a_seed, _) = authorized_pair();
        let ga = sole_gid(&a);
        let gb = sole_gid(&b);
        let a_aak_pub = authz::aak_public(&authz::aak_from_seed(&a_seed).unwrap());
        // A device claiming A's account key but with a bogus certificate (attacker lacks A's AAK).
        let forged_kp = forged_authorized_kp(&OpenMlsRustCrypto::default(), &a_aak_pub);
        ungate(&mut a, &ga);
        let (commit, _welcome) = a.add_member_inner(&ga, &forged_kp).unwrap();
        let err = b.receive_inner(&commit).unwrap_err();
        assert!(err.contains("certificate did not verify"), "got: {err}");
        assert_eq!(b.roster_hex_inner(&gb).unwrap().len(), 2);
    }

    #[test]
    fn an_add_with_no_certificate_is_rejected_in_authorized_mode() {
        let (mut a, mut b, _, _) = authorized_pair();
        let ga = sole_gid(&a);
        let gb = sole_gid(&b);
        // A legacy (label-only) device carries no AAK certificate at all.
        let legacy = Conversation::new_inner("legacy").unwrap();
        ungate(&mut a, &ga);
        let (commit, _welcome) = a.add_member_inner(&ga, &legacy.key_package().unwrap()).unwrap();
        let err = b.receive_inner(&commit).unwrap_err();
        assert!(err.contains("missing certificate"), "got: {err}");
        assert_eq!(b.roster_hex_inner(&gb).unwrap().len(), 2);
    }

    // ---- Staged add: fork-free concurrency (ADR-022) ----

    // Happy path: stage an add, see our OWN commit echoed back, confirm (merge). The new device is
    // reachable to everyone and all three converge on one epoch.
    #[test]
    fn staged_add_confirms_on_own_echo_and_new_device_is_reachable() {
        let (mut a, mut b, a_seed, _) = authorized_pair();
        let ga = sole_gid(&a);
        let gb = sole_gid(&b);
        let a2 = Conversation::new_authorized_inner("a-phone", &a_seed).unwrap();
        let a2_sig = a2.signature_public_key_hex();
        let (commit, welcome) = a.stage_add_inner(&ga, &a2.key_package().unwrap()).unwrap();
        // A receives its OWN commit echoed back by the FIFO gateway => confirm (merge), advancing to N+1.
        match a.receive_inner(&commit).unwrap().1 {
            Received::MembershipChanged { added, removed } => {
                assert!(removed.is_empty());
                assert_eq!(added.iter().map(|k| hex(k)).collect::<Vec<_>>(), vec![a2_sig.clone()]);
            }
            other => panic!("the echo must confirm the staged add, got {other:?}"),
        }
        // The peer ingests the same commit through the normal (gated) path.
        match b.receive_inner(&commit).unwrap().1 {
            Received::MembershipChanged { .. } => {}
            other => panic!("the peer must ingest the add, got {other:?}"),
        }
        let mut a2 = a2;
        a2.join_from_welcome_inner(&welcome).unwrap();
        let ct = b.encrypt_inner(&gb, b"to all of A").unwrap();
        let g2 = sole_gid(&a2);
        assert_eq!(a.decrypt_inner(&ga, &ct).unwrap(), b"to all of A");
        assert_eq!(a2.decrypt_inner(&g2, &ct).unwrap(), b"to all of A");
        assert_eq!(a.roster_hex_inner(&ga).unwrap().len(), 3);
        assert_eq!(b.roster_hex_inner(&gb).unwrap().len(), 3);
    }

    // Timeout fallback: no echo arrives, so the client confirms explicitly. confirm is idempotent.
    #[test]
    fn staged_add_confirms_via_explicit_confirm_when_no_echo() {
        let (mut a, mut b, a_seed, _) = authorized_pair();
        let ga = sole_gid(&a);
        let gb = sole_gid(&b);
        let a2 = Conversation::new_authorized_inner("a-phone", &a_seed).unwrap();
        let (commit, welcome) = a.stage_add_inner(&ga, &a2.key_package().unwrap()).unwrap();
        a.confirm_add_inner(&ga).unwrap(); // timeout fallback (no echo seen)
        a.confirm_add_inner(&ga).unwrap(); // idempotent: a second confirm is a no-op
        b.receive_inner(&commit).unwrap();
        let mut a2 = a2;
        a2.join_from_welcome_inner(&welcome).unwrap();
        let ct = a.encrypt_inner(&ga, b"after explicit confirm").unwrap();
        let g2 = sole_gid(&a2);
        assert_eq!(b.decrypt_inner(&gb, &ct).unwrap(), b"after explicit confirm");
        assert_eq!(a2.decrypt_inner(&g2, &ct).unwrap(), b"after explicit confirm");
    }

    // The headline concurrency case: two members stage an add at the SAME epoch. The FIFO gateway
    // orders one first; the loser ABORTS its staged add and adopts the winner. No fork: every member
    // converges on the winner's epoch, and the loser is free to stage again.
    #[test]
    fn two_staged_adds_race_loser_aborts_no_fork() {
        let (mut a, mut b, mut c) = established_group_3();
        let ga = sole_gid(&a);
        let gb = sole_gid(&b);
        let gc = sole_gid(&c);
        let d = member("d");
        let d_sig = d.signature_public_key_hex();
        let e = member("e");
        // Both A and B stage an add at epoch N.
        let (commit_a, welcome_d) = a.stage_add_inner(&ga, &d.key_package().unwrap()).unwrap();
        let (commit_b, _welcome_e) = b.stage_add_inner(&gb, &e.key_package().unwrap()).unwrap();
        // The FIFO gateway orders A's commit first; every member processes commit_a.
        match a.receive_inner(&commit_a).unwrap().1 {
            Received::MembershipChanged { added, .. } => {
                assert_eq!(added.iter().map(|k| hex(k)).collect::<Vec<_>>(), vec![d_sig.clone()]);
            }
            other => panic!("A must confirm its own add on the echo, got {other:?}"),
        }
        // B holds a COMPETING staged add; commit_a is not its own, so B aborts and adopts the winner.
        match b.receive_inner(&commit_a).unwrap().1 {
            Received::MembershipChanged { added, .. } => {
                assert_eq!(added.iter().map(|k| hex(k)).collect::<Vec<_>>(), vec![d_sig.clone()]);
            }
            other => panic!("B must abort its add and adopt the winner, got {other:?}"),
        }
        c.receive_inner(&commit_a).unwrap(); // a bystander member adopts it too
        let mut d = d;
        d.join_from_welcome_inner(&welcome_d).unwrap();
        // Converged: A, B, C, D all decode the next message; no fork.
        let ct = c.encrypt_inner(&gc, b"converged on D").unwrap();
        let gd = sole_gid(&d);
        assert_eq!(a.decrypt_inner(&ga, &ct).unwrap(), b"converged on D");
        assert_eq!(b.decrypt_inner(&gb, &ct).unwrap(), b"converged on D");
        assert_eq!(d.decrypt_inner(&gd, &ct).unwrap(), b"converged on D");
        // B's staged add was cleared by the abort, so B can stage a fresh one (no "already in flight").
        let f = member("f");
        assert!(b.stage_add_inner(&gb, &f.key_package().unwrap()).is_ok(), "the loser's pending add must clear");
        let _ = commit_b; // a now-stale epoch-N commit; never adopted by anyone
    }

    // Forward secrecy holds for a staged-added device exactly as for a merged add: it reads from when
    // it joins onward, never the history before its epoch.
    #[test]
    fn staged_added_device_cannot_read_pre_join_messages() {
        let (mut a, mut b, a_seed, _) = authorized_pair();
        let ga = sole_gid(&a);
        let gb = sole_gid(&b);
        let pre = a.encrypt_inner(&ga, b"before the add").unwrap();
        let a2 = Conversation::new_authorized_inner("a-phone", &a_seed).unwrap();
        let (commit, welcome) = a.stage_add_inner(&ga, &a2.key_package().unwrap()).unwrap();
        a.receive_inner(&commit).unwrap(); // confirm via echo
        b.receive_inner(&commit).unwrap();
        let mut a2 = a2;
        a2.join_from_welcome_inner(&welcome).unwrap();
        let g2 = sole_gid(&a2);
        assert!(a2.decrypt_inner(&g2, &pre).is_err(), "a self-healed device must not read pre-join history");
        let post = b.encrypt_inner(&gb, b"after the add").unwrap();
        assert_eq!(a2.decrypt_inner(&g2, &post).unwrap(), b"after the add");
    }

    // The fail-closed gate is identical for a staged add: an honest peer rejects an add under an
    // unknown account and never merges, so no silent extra reader is admitted.
    #[test]
    fn a_staged_add_under_an_unknown_account_is_rejected_by_peers() {
        let (mut a, mut b, _, _) = authorized_pair();
        let ga = sole_gid(&a);
        let gb = sole_gid(&b);
        let attacker = Conversation::new_authorized_inner("attacker", &[99u8; 32]).unwrap();
        ungate(&mut a, &ga);
        let (commit, _welcome) = a.stage_add_inner(&ga, &attacker.key_package().unwrap()).unwrap();
        let err = b.receive_inner(&commit).unwrap_err();
        assert!(err.contains("unknown account key"), "got: {err}");
        assert_eq!(b.roster_hex_inner(&gb).unwrap().len(), 2, "no silent extra reader admitted");
    }

    // Abort clears the staged add (and refuses a second concurrent stage), leaving the device on its
    // original epoch and able to keep talking, then stage again.
    #[test]
    fn abort_clears_the_staged_add_and_allows_re_stage() {
        let (mut a, mut b, a_seed, _) = authorized_pair();
        let ga = sole_gid(&a);
        let gb = sole_gid(&b);
        let a2 = Conversation::new_authorized_inner("a-phone", &a_seed).unwrap();
        let _ = a.stage_add_inner(&ga, &a2.key_package().unwrap()).unwrap();
        let a3 = Conversation::new_authorized_inner("a-tablet", &a_seed).unwrap();
        assert!(a.stage_add_inner(&ga, &a3.key_package().unwrap()).is_err(), "one add in flight at a time");
        a.abort_add_inner(&ga).unwrap();
        a.abort_add_inner(&ga).unwrap(); // idempotent
        // A never left epoch N: it can still talk to the existing group.
        let ct = a.encrypt_inner(&ga, b"still on epoch N").unwrap();
        assert_eq!(b.decrypt_inner(&gb, &ct).unwrap(), b"still on epoch N");
        // And it can stage a fresh add.
        assert!(a.stage_add_inner(&ga, &a3.key_package().unwrap()).is_ok());
    }

    #[test]
    fn reload_preserves_the_account_key_and_trusted_set() {
        let (a, _b, _, _) = authorized_pair();
        let msk = [33u8; 32];
        let before_account = a.account_key_hex();
        let before_trusted = a.groups.values().next().unwrap().trusted_aaks.clone();
        let sealed = a.export_sealed_inner(&msk).unwrap();
        let reloaded = Conversation::from_sealed_inner(&msk, &sealed).unwrap();
        assert!(!reloaded.account_key_hex().is_empty());
        assert_eq!(reloaded.account_key_hex(), before_account);
        assert_eq!(reloaded.groups.values().next().unwrap().trusted_aaks, before_trusted);
        assert_eq!(reloaded.groups.values().next().unwrap().trusted_aaks.len(), 2);
    }

    #[test]
    fn reload_preserves_the_authorized_credential_so_own_account_stays_trusted() {
        // A seed-holder reloaded from sealed state must keep its AUTHORIZED credential (not drop to a
        // label-only one), or its own account would not be trusted when it forms a new group.
        let d1 = Conversation::new_authorized_inner("d1", &[10u8; 32]).unwrap();
        let msk = [44u8; 32];
        let sealed = d1.export_sealed_inner(&msk).unwrap();
        let mut d1r = Conversation::from_sealed_inner(&msk, &sealed).unwrap();
        assert_eq!(d1r.cert_epoch_inner(), 0);
        // Form a group with a peer of a DIFFERENT account. recompute must trust BOTH accounts: the
        // peer's (from its credential) and our own (from the reloaded device's credential).
        let peer = Conversation::new_authorized_inner("peer", &[20u8; 32]).unwrap();
        let (_welcome, _gid) = d1r.create_group_inner(&[peer.key_package().unwrap()]).unwrap();
        assert_eq!(d1r.groups.values().next().unwrap().trusted_aaks.len(), 2, "the reloaded device's own account must still be trusted");
    }

    #[test]
    fn a_recovered_device_becomes_authorized_under_the_same_account_keeping_its_device_key() {
        let seed = [10u8; 32];
        let mut original = Conversation::new_authorized_inner("d1", &seed).unwrap();
        let mut fresh = Conversation::new_inner("d2").unwrap(); // a brand-new, unauthorized device
        assert!(fresh.account_key_hex().is_empty());
        let device_key_before = fresh.signature_public_key_hex();
        fresh.recover_with_seed_inner(&seed, 0).unwrap();
        // Same account key as the original seed-holder; the device (signature) key is UNCHANGED, so its
        // directory entry and bootstrap mailbox stay stable.
        assert_eq!(fresh.account_key_hex(), original.account_key_hex());
        assert_eq!(fresh.signature_public_key_hex(), device_key_before);
        assert_eq!(fresh.cert_epoch_inner(), 0);
        // The original seed-holder can add the recovered device to a group; the gate accepts it.
        let (welcome, _gid) = original.create_group_inner(&[fresh.key_package().unwrap()]).unwrap();
        let go = sole_gid(&original);
        fresh.join_from_welcome_inner(&welcome).unwrap();
        let gf = sole_gid(&fresh);
        let ct = original.encrypt_inner(&go, b"recovered ok").unwrap();
        assert_eq!(fresh.decrypt_inner(&gf, &ct).unwrap(), b"recovered ok");
    }

    #[test]
    fn the_gate_rejects_a_below_floor_certificate_after_an_epoch_bump() {
        // P6: after a revoke bumps the account epoch and a device re-certifies at epoch 1, a peer's
        // group sets the floor for that account to 1. An old-epoch (0) device of the same account, if
        // someone tries to add it, is rejected by the gate as below the floor.
        let seed = [10u8; 32];
        let mut d_new = Conversation::new_authorized_inner("d-new", &seed).unwrap();
        d_new.recredential_at_epoch_inner(1).unwrap();
        assert_eq!(d_new.cert_epoch_inner(), 1);
        let mut peer = Conversation::new_authorized_inner("peer", &[20u8; 32]).unwrap();
        let (welcome, _gid) = peer.create_group_inner(&[d_new.key_package().unwrap()]).unwrap();
        let gp = sole_gid(&peer);
        d_new.join_from_welcome_inner(&welcome).unwrap();
        // The peer adds an old-epoch (0) device of our account. The committer does not gate itself, but
        // the honest member d_new rejects the below-floor add fail-closed.
        let stale = Conversation::new_authorized_inner("stale", &seed).unwrap(); // epoch 0
        ungate(&mut peer, &gp);
        let (commit, _w) = peer.add_member_inner(&gp, &stale.key_package().unwrap()).unwrap();
        let err = d_new.receive_inner(&commit).unwrap_err();
        assert!(err.contains("below floor"), "expected a below-floor rejection, got: {err}");
    }

    #[test]
    fn the_persistent_floor_is_monotonic_and_a_stale_roster_cannot_walk_it_back() {
        // Anti-rollback: once a device has certified its account at epoch 1, forming a fresh group that
        // also contains a stale epoch-0 sibling must NOT lower the floor back to 0 (which would re-admit
        // an old-epoch, revoked device). The high-water floor persists across reload.
        let seed = [10u8; 32];
        let mut d = Conversation::new_authorized_inner("d", &seed).unwrap();
        d.recredential_at_epoch_inner(1).unwrap(); // post-revoke re-cert to epoch 1
        let own = hex_to_bytes(&d.account_key_hex()).unwrap();
        // Reload to prove the high-water floor survives at-rest.
        let msk = [55u8; 32];
        let sealed = d.export_sealed_inner(&msk).unwrap();
        let mut d = Conversation::from_sealed_inner(&msk, &sealed).unwrap();
        assert_eq!(d.account_floors.iter().find(|(k, _)| k == &own).map(|(_, e)| *e), Some(1));
        // Form a group that includes a STALE epoch-0 sibling of the same account plus a peer.
        let stale = Conversation::new_authorized_inner("stale", &seed).unwrap(); // epoch 0
        let peer = Conversation::new_authorized_inner("peer", &[20u8; 32]).unwrap();
        let (_welcome, _gid) = d.create_group_inner(&[stale.key_package().unwrap(), peer.key_package().unwrap()]).unwrap();
        // The recomputed conversation floor for our account must stay 1, not drop to the stale 0.
        let floor = d.groups.values().next().unwrap().trusted_aaks.iter().find(|(k, _)| k == &own).map(|(_, e)| *e);
        assert_eq!(floor, Some(1), "the stale epoch-0 sibling must not lower the monotonic floor");
    }

    // ---- Device-to-device authorization by certificate transfer (provisioning model b, P4) ----

    /// Split a Grant: accountPublicKey(64 hex) || certEpoch(16 hex) || certificate(128 hex).
    fn split_grant(out: &str) -> (String, u64, String) {
        let epoch_bytes: [u8; 8] = hex_to_bytes(&out[64..80]).unwrap().try_into().unwrap();
        (out[0..64].to_string(), u64::from_be_bytes(epoch_bytes), out[80..].to_string())
    }

    /// Run the seed-holder authorize + new-device adopt handshake with a correct confirmed SAS.
    fn transfer_authorize(d1: &Conversation, d2: &mut Conversation, epoch: u32) -> Result<(), String> {
        let nonce = [0u8; 32];
        let d1_aak = hex_to_bytes(&d1.account_key_hex())?;
        let d2_key = hex_to_bytes(&d2.signature_public_key_hex())?;
        let confirmed = authz::sas_digest(&nonce, &d1_aak, &d2_key, u64::from(epoch));
        let out = d1.authorize_device_inner(
            &d2.signature_public_key_hex(),
            u64::from(epoch),
            &hex(&nonce),
            &hex(&confirmed),
        )?;
        let (aak_pub, ep, cert) = split_grant(&out);
        d2.adopt_certificate_inner(&aak_pub, ep, &cert)
    }

    #[test]
    fn a_seed_holder_authorizes_a_pending_device_which_can_then_join() {
        let mut d1 = Conversation::new_authorized_inner("d1", &[10u8; 32]).unwrap();
        let mut d2 = Conversation::new_inner("d2").unwrap(); // pending: holds no account key
        transfer_authorize(&d1, &mut d2, 0).unwrap();
        // It holds a certificate, not the account key, so it cannot itself authorize further devices.
        assert!(d2.account_key_hex().is_empty());

        // The two devices of one account form a group and the authorized device participates.
        let (welcome, _gid) = d1.create_group_inner(&[d2.key_package().unwrap()]).unwrap();
        let g1 = sole_gid(&d1);
        d2.join_from_welcome_inner(&welcome).unwrap();
        let g2 = sole_gid(&d2);
        let ct = d1.encrypt_inner(&g1, b"hello sibling").unwrap();
        assert_eq!(d2.decrypt_inner(&g2, &ct).unwrap(), b"hello sibling");
        assert_eq!(d1.groups.values().next().unwrap().trusted_aaks.len(), 1); // both devices belong to the same account
    }

    #[test]
    fn the_signer_refuses_a_key_that_does_not_match_the_confirmed_code() {
        let d1 = Conversation::new_authorized_inner("d1", &[10u8; 32]).unwrap();
        let d2 = Conversation::new_inner("d2").unwrap();
        let nonce = [0u8; 32];
        let d1_aak = hex_to_bytes(&d1.account_key_hex()).unwrap();
        // The user confirmed the code for d2, but the call passes a DIFFERENT key to sign.
        let confirmed_for_d2 = authz::sas_digest(&nonce, &d1_aak, &hex_to_bytes(&d2.signature_public_key_hex()).unwrap(), 0);
        let attacker = Conversation::new_inner("attacker").unwrap();
        let res = d1.authorize_device_inner(
            &attacker.signature_public_key_hex(), // sign the attacker's key...
            0,
            &hex(&nonce),
            &hex(&confirmed_for_d2), // ...but the user confirmed d2's code
        );
        assert!(res.is_err()); // the signer refuses
    }

    #[test]
    fn a_certificate_cannot_be_adopted_by_a_different_device() {
        let d1 = Conversation::new_authorized_inner("d1", &[10u8; 32]).unwrap();
        let d2 = Conversation::new_inner("d2").unwrap();
        let nonce = [0u8; 32];
        let d1_aak = hex_to_bytes(&d1.account_key_hex()).unwrap();
        let d2_key = hex_to_bytes(&d2.signature_public_key_hex()).unwrap();
        let confirmed = authz::sas_digest(&nonce, &d1_aak, &d2_key, 0);
        let out = d1
            .authorize_device_inner(&d2.signature_public_key_hex(), 0, &hex(&nonce), &hex(&confirmed))
            .unwrap();
        let (aak_pub, epoch, cert) = split_grant(&out); // a certificate for d2
        let mut d3 = Conversation::new_inner("d3").unwrap(); // a different device
        assert!(d3.adopt_certificate_inner(&aak_pub, epoch, &cert).is_err());
    }

    #[test]
    fn a_device_without_the_account_key_cannot_authorize_others() {
        let d2 = Conversation::new_inner("d2").unwrap(); // holds no account key
        assert!(d2.authorize_device_inner(&"aa".repeat(32), 0, &"00".repeat(32), &"00".repeat(32)).is_err());
    }

    /// The full QR pairing crypto: the seed-holder authorizes the SCANNED device key (no SAS), seals the
    /// Grant to the new device's OPTICALLY-transmitted ephemeral key, and only that device can open and
    /// adopt it and then join. This is the crypto behind add-a-device-by-QR.
    #[test]
    fn qr_scan_authorize_seal_open_adopt_and_join() {
        let mut d1 = Conversation::new_authorized_inner("d1", &[10u8; 32]).unwrap();
        let mut d2 = Conversation::new_inner("d2").unwrap(); // pending: no account key

        // D2 makes an ephemeral keypair and (conceptually) shows its device key + ephemeral pub in a QR.
        let kp = crate::provision::ephemeral_keypair().unwrap();
        let (e2_secret, e2_public) = (&kp[0..32], &kp[32..64]);
        let d2_key = hex_to_bytes(&d2.signature_public_key_hex()).unwrap();

        // D1 scans it: authorizes the scanned key (no SAS) and seals the Grant to the ephemeral pub.
        let grant = d1.authorize_scanned_device_inner(&d2_key, 0).unwrap();
        assert_eq!(grant.len(), 32 + 8 + 64);
        let sealed = crate::provision::seal_to_pub(e2_public, &grant).unwrap();

        // A gateway that never saw the ephemeral pub cannot open (or forge) the box.
        let attacker_kp = crate::provision::ephemeral_keypair().unwrap();
        assert!(crate::provision::open_to_priv(&attacker_kp[0..32], &sealed).is_err());

        // D2 opens the box with its ephemeral secret, parses the Grant, and adopts the certificate.
        let opened = crate::provision::open_to_priv(e2_secret, &sealed).unwrap();
        let aak_pub = hex(&opened[0..32]);
        let epoch = u64::from_be_bytes(opened[32..40].try_into().unwrap());
        let cert = hex(&opened[40..104]);
        d2.adopt_certificate_inner(&aak_pub, epoch, &cert).unwrap();
        assert!(d2.account_key_hex().is_empty()); // holds a cert, not the account key

        // The now-authorized device joins the account group and exchanges a message.
        let (welcome, _gid) = d1.create_group_inner(&[d2.key_package().unwrap()]).unwrap();
        let g1 = sole_gid(&d1);
        d2.join_from_welcome_inner(&welcome).unwrap();
        let g2 = sole_gid(&d2);
        let ct = d1.encrypt_inner(&g1, b"paired by QR").unwrap();
        assert_eq!(d2.decrypt_inner(&g2, &ct).unwrap(), b"paired by QR");
    }

    #[test]
    fn a_device_without_the_account_key_cannot_qr_authorize_others() {
        let d2 = Conversation::new_inner("d2").unwrap();
        assert!(d2.authorize_scanned_device_inner(&[9u8; 32], 0).is_err());
    }

    #[test]
    fn a_revoked_seed_holder_cannot_recertify_its_way_back_in() {
        // THE ATTACK UNDER TEST. Revocation is a SERVER-SIDE act: it burns a directory row, kills the
        // sessions and deletes the key packages. It cannot reach the revoked device's own disk, where its
        // copy of the ACCOUNT seed still sits (aak_seed in the sealed container). The floor is only a
        // LOWER BOUND, and recredential_at_epoch_inner signs whatever epoch it is handed with no ceiling
        // (reauthorize_at_epoch exposes it to JS unbounded). So the revoked device should be able to
        // re-certify ITSELF at an absurd epoch, sail over any floor, and be re-admitted by an honest
        // device that has correctly raised its own floor. If it can, exclusion by epoch does not work.
        let seed = [42u8; 32]; // ONE account: both devices derive the SAME account key from it
        let honest = Conversation::new_authorized_inner("honest", &seed).unwrap();
        let evil = Conversation::new_authorized_inner("evil", &seed).unwrap();
        let evil_sig = evil.signature_public_key_hex();

        // They share a conversation, so `honest` trusts the account and knows the roster.
        let mut honest = honest;
        let (welcome, _g) = honest.create_group_inner(&[evil.key_package().unwrap()]).unwrap();
        let mut evil = evil;
        evil.join_from_welcome_inner(&welcome).unwrap();
        let g = sole_gid(&honest);
        assert_eq!(honest.roster_hex_inner(&g).unwrap().len(), 2, "both devices are in the group");

        // The user revokes `evil`. The honest device removes it from the group, ISSUES A SIGNED
        // REVOCATION RECORD naming evil's key (ADR-022 P7), and re-certifies itself at the account's new
        // epoch. All three are what the app does on a revoke; the record is the part that carries the
        // authorization decision, the other two are hygiene.
        let commit = honest.remove_member_inner(&g, &evil_sig).unwrap();
        evil.receive_inner(&commit).unwrap(); // evil observes its own eviction
        honest.revoke_device_inner(&evil_sig, 1).unwrap();
        honest.recredential_at_epoch_inner(1).unwrap(); // the post-revoke floor raise
        assert_eq!(honest.roster_hex_inner(&g).unwrap().len(), 1, "evil is out of the group");

        // THE ATTACK: evil still holds the account seed on its own disk. It re-certifies itself at an
        // epoch far above anything the honest device will ever reach, and offers a fresh key package.
        evil.recredential_at_epoch_inner(u64::from(u32::MAX)).unwrap();
        let evil_kp = evil.key_package().unwrap();

        // Can the honest device be made to admit it again?
        let readmitted = honest.add_member_inner(&g, &evil_kp).is_ok();
        assert!(
            !readmitted,
            "SECURITY: a revoked device re-certified itself at a higher epoch and was re-admitted. \
             An epoch floor is a lower bound, so it cannot exclude a party that holds the account key \
             and can mint at an arbitrary epoch. Exclusion needs IDENTITY (a signed revocation record \
             checked at the gate), not ordering.",
        );
    }

    #[test]
    fn the_denylist_speaks_only_for_our_own_account_never_for_a_peers() {
        // Scope check. Our account key signs records about OUR devices; it has no authority over a
        // peer's, and a record naming a key we happen to also see on a peer leaf must not gate that
        // leaf. Getting this wrong would let one account silently evict another's devices from a shared
        // conversation, which is a worse failure than the hole this whole mechanism closes.
        let (mut a, b, _, _) = authorized_pair();
        let ga = sole_gid(&a);

        // A revokes some key of its own, and (adversarially) the SAME bytes as B's live device key.
        let b_sig = b.signature_public_key_hex();
        a.revoke_device_inner(&b_sig, 1).unwrap();
        assert!(a.is_revoked(&hex_to_bytes(&b_sig).unwrap()), "the record is held and verifies");

        // B is still a member and still passes A's gate: the record is scoped to A's account key, and
        // B's leaf carries B's.
        let trusted = a.groups.get(&hex_to_bytes(&ga).unwrap()).unwrap().trusted_aaks.clone();
        let identity = a
            .groups
            .get(&hex_to_bytes(&ga).unwrap())
            .unwrap()
            .group
            .members()
            .find(|m| hex(&m.signature_key) == b_sig)
            .map(|m| BasicCredential::try_from(m.credential.clone()).unwrap().identity().to_vec())
            .unwrap();
        assert!(
            a.check_added_leaf(&trusted, &hex_to_bytes(&b_sig).unwrap(), &identity).is_ok(),
            "a peer's device must never be gated by OUR account's denylist",
        );
    }

    #[test]
    fn every_mirror_of_the_gate_refuses_a_revoked_device_not_just_check_added_leaf() {
        // The gate is written in three places: check_added_leaf (the real one), the self-group BIRTH
        // gate, and the key-package pre-filter. Drift between them has been a live bug class here
        // before, and the self-group is the worst place to drift: it carries the whole contact graph,
        // so admitting a revoked device there hands over the buddy list.
        //
        // The revoked device here is a SEED-HOLDER that has re-certified itself at u32::MAX, which is
        // the whole point: at that epoch the floor check passes trivially, so if a mirror refuses the
        // device it can only be because the denylist did it. A test where the floor could also catch it
        // proves nothing about these sites (an earlier draft of this test had exactly that flaw).
        let seed = [21u8; 32];
        let mut evil = Conversation::new_authorized_inner("evil", &seed).unwrap();
        let evil_sig = evil.signature_public_key_hex();
        evil.recredential_at_epoch_inner(u64::from(u32::MAX)).unwrap();
        let evil_kp = evil.key_package().unwrap();

        // Before the record exists, both mirrors admit it: its cert verifies and sails over the floor.
        let mut before = Conversation::new_authorized_inner("before", &seed).unwrap();
        assert!(before.key_package_self_eligible_inner(&evil_kp), "eligible before the revoke");
        assert!(before.create_self_group_inner(&[evil_kp.clone()]).is_ok(), "birth gate admits it before");

        // Now the user revokes it, and the record reaches another device the way the control plane
        // delivers one.
        let record = crate::revoke::sign_revocation(
            &authz::aak_from_seed(&seed).unwrap(),
            &hex_to_bytes(&evil_sig).unwrap(),
            1,
        )
        .unwrap();
        let mut after = Conversation::new_authorized_inner("after", &seed).unwrap();
        after.ingest_revocation_inner(&record).unwrap();

        assert!(
            !after.key_package_self_eligible_inner(&evil_kp),
            "the pre-filter must refuse a revoked device even at an epoch far above the floor",
        );
        let err = after.create_self_group_inner(&[evil_kp]).unwrap_err();
        assert!(err.contains("revoked"), "the self-group birth gate must refuse it, got: {err}");
    }

    #[test]
    fn a_revoked_CERT_ONLY_device_cannot_recertify_at_all_bounding_the_attack() {
        // Bounds the hole above. The re-certify attack needs the ACCOUNT KEY, which only a seed-holder
        // has: a device paired by QR or six words adopts a CERTIFICATE and never learns the seed. So the
        // blast radius is "devices provisioned with the recovery secret, plus the registering device",
        // NOT every device. This test pins that boundary so a future change cannot widen it unnoticed.
        let seed = [43u8; 32];
        let holder = Conversation::new_authorized_inner("holder", &seed).unwrap();
        let mut certonly = Conversation::new_inner("certonly").unwrap();
        let aak_pub = holder.account_key_hex();
        let target = certonly.signature_public_key_hex();

        // Certify it the way pairing does: it receives a cert, never the seed.
        let grant = holder
            .authorize_scanned_device_inner(&hex_to_bytes(&target).unwrap(), 0)
            .unwrap();
        let cert = hex(&grant[40..104]);
        certonly.adopt_certificate_inner(&aak_pub, 0, &cert).unwrap();
        assert!(certonly.account_key_hex().is_empty(), "a paired device holds no account key");

        // It cannot mint itself a new certificate at any epoch: no account key to sign with.
        let err = certonly.recredential_at_epoch_inner(u64::from(u32::MAX)).unwrap_err();
        assert!(
            err.contains("no account key"),
            "a cert-only device must not be able to re-certify itself, got: {err}",
        );
    }

    #[test]
    fn certifying_below_our_own_floor_raises_to_the_floor_instead_of_minting_a_dead_certificate() {
        // The caller hard-coded epoch 0 for a long time. On an account that had ever revoked a device
        // the floor is above 0, so every certificate minted was one our OWN gate refuses the moment the
        // new device is staged into a group: pairing looked successful, the directory row was created,
        // and the device could never be added — and the app's advice (revoke and pair again) raised the
        // floor, making it permanent.
        //
        // The fix is to certify AT the floor, not to error. Erroring makes the disagreement the user's
        // problem: the epoch is supplied by the control plane's counter and the floor is device-local,
        // so any drift between them blocks pairing with nothing to be done about it. Raising is always
        // safe (the epoch is a lower bound), and P7 moved exclusion onto the signed denylist, so a high
        // epoch buys an attacker nothing.
        let mut d1 = Conversation::new_authorized_inner("d1", &[10u8; 32]).unwrap();
        d1.recredential_at_epoch_inner(7).unwrap(); // the account has advanced to epoch 7
        let target = [9u8; 32];

        // Asked for 0, signed at 7: the epoch is carried in the Grant at bytes 32..40, so the new device
        // adopts the number we actually used.
        let grant = d1.authorize_scanned_device_inner(&target, 0).unwrap();
        let minted = u64::from_be_bytes(grant[32..40].try_into().unwrap());
        assert_eq!(minted, 7, "a below-floor request must be raised to the floor, not signed as asked");
        assert!(
            verify_device_cert(&hex_to_bytes(&d1.account_key_hex()).unwrap(), 7, &target, &grant[40..104]),
            "the certificate must actually verify at the epoch it claims",
        );

        // At or above the floor the requested epoch is honored unchanged.
        for asked in [7u64, 8, 99] {
            let g = d1.authorize_scanned_device_inner(&target, asked).unwrap();
            assert_eq!(u64::from_be_bytes(g[32..40].try_into().unwrap()), asked);
        }
    }

    #[test]
    fn a_revoked_key_is_never_re_certified_by_either_pairing_path() {
        // The mint side of the denylist. Once a device is revoked, our own gate denies its key, so
        // handing it a fresh certificate would only produce a device that believes it is authorized and
        // can never join anything. Both pairing paths must refuse, and must say why in a way that points
        // at the actual remedy (pair as a NEW device, i.e. with a new key).
        let mut d1 = Conversation::new_authorized_inner("d1", &[11u8; 32]).unwrap();
        let target = [3u8; 32];
        assert!(d1.authorize_scanned_device_inner(&target, 0).is_ok(), "not revoked yet");

        d1.revoke_device_inner(&hex(&target), 1).unwrap();

        let err = d1.authorize_scanned_device_inner(&target, 0).unwrap_err();
        assert!(err.contains("revoked"), "got: {err}");
        assert!(err.contains("new device"), "the message must name the remedy, got: {err}");

        // And the six-word path, which reaches the same check before the SAS compare.
        let nonce = [1u8; 16];
        let sas = authz::sas_digest(&nonce, &hex_to_bytes(&d1.account_key_hex()).unwrap(), &target, 0);
        let err = d1
            .authorize_device_inner(&hex(&target), 0, &hex(&nonce), &hex(&sas))
            .unwrap_err();
        assert!(err.contains("revoked"), "got: {err}");

        // A DIFFERENT key on the same (physical) device pairs normally: revocation names a key, so
        // coming back means coming back as a new device, exactly as re-pairing already produces.
        assert!(d1.authorize_scanned_device_inner(&[4u8; 32], 0).is_ok());
    }

    #[test]
    fn revocation_records_survive_a_reload_and_a_forged_one_is_refused() {
        // The denylist is only as good as its persistence: if a reload dropped it, the hole re-opened
        // until the next successful fetch from a control plane that is free to stall forever.
        let seed = [12u8; 32];
        let mut d1 = Conversation::new_authorized_inner("d1", &seed).unwrap();
        let target = [5u8; 32];
        let record = d1.revoke_device_inner(&hex(&target), 1).unwrap();
        assert_eq!(d1.revoked_device_keys().len(), 1);
        assert!(d1.is_revoked(&target));

        let msk = [7u8; 32];
        let sealed = d1.export_sealed_inner(&msk).unwrap();
        let reloaded = Conversation::from_sealed_inner(&msk, &sealed).unwrap();
        assert!(reloaded.is_revoked(&target), "the denylist must survive a reload");
        assert_eq!(reloaded.revoked_device_keys().len(), 1);
        // Accepting records also derives the floor: |S| == 1, so nothing certifies below 1 any more.
        assert_eq!(reloaded.effective_floor(&reloaded.our_account_pub().unwrap(), 0), 1);

        // A record signed by SOMEONE ELSE's account key is refused outright, so a hostile control plane
        // cannot revoke our devices by serving us fabricated records.
        let mut d2 = Conversation::new_authorized_inner("d2", &[13u8; 32]).unwrap();
        let foreign = d2.revoke_device_inner(&hex(&[6u8; 32]), 1).unwrap();
        let mut victim = Conversation::new_authorized_inner("victim", &seed).unwrap();
        assert!(victim.ingest_revocation_inner(&hex_to_bytes(&foreign).unwrap()).is_err());
        assert!(!victim.is_revoked(&[6u8; 32]));

        // The genuine record ingests once and is idempotent (the app re-fetches the whole set on every
        // sync, so a second copy must not inflate the derived floor).
        let blob = hex_to_bytes(&record).unwrap();
        assert!(victim.ingest_revocation_inner(&blob).unwrap(), "new");
        assert!(!victim.ingest_revocation_inner(&blob).unwrap(), "already held");
        assert_eq!(victim.revoked_device_keys().len(), 1);
    }

    #[test]
    fn a_transfer_authorized_device_is_accepted_by_the_gate_at_the_peer() {
        let (mut a, mut b, _, _) = authorized_pair();
        // A authorizes its second device A2 by certificate transfer (no seed on A2).
        let mut a2 = Conversation::new_inner("a-phone").unwrap();
        transfer_authorize(&a, &mut a2, 0).unwrap();

        // A adds A2 to the existing A+B group; the PEER B accepts it because A2's certificate verifies
        // under A's account key, which is trusted in this conversation.
        let ga = sole_gid(&a);
        let gb = sole_gid(&b);
        let (commit, _welcome) = a.add_member_inner(&ga, &a2.key_package().unwrap()).unwrap();
        match b.receive_inner(&commit).unwrap().1 {
            Received::MembershipChanged { .. } => {}
            other => panic!("expected the transfer-authorized device to be accepted, got {other:?}"),
        }
        assert_eq!(b.roster_hex_inner(&gb).unwrap().len(), 3);
    }

    // ---- Multiple concurrent conversations on one device (the multi-group refactor) ----

    /// One device A holding TWO conversations: g1 with B, g2 with C (different accounts). B and C each
    /// join their own group. Returns (a, b, c, g1_hex, g2_hex).
    fn two_conversations() -> (Conversation, Conversation, Conversation, String, String) {
        let b = member("b");
        let c = member("c");
        let mut a = member("a");
        let (w1, g1) = a.create_group_inner(&[b.key_package().unwrap()]).unwrap();
        let (w2, g2) = a.create_group_inner(&[c.key_package().unwrap()]).unwrap();
        let mut b = b;
        let mut c = c;
        b.join_from_welcome_inner(&w1).unwrap();
        c.join_from_welcome_inner(&w2).unwrap();
        (a, b, c, hex(&g1), hex(&g2))
    }

    #[test]
    fn one_device_holds_two_independent_conversations() {
        let (mut a, mut b, mut c, g1, g2) = two_conversations();
        assert_eq!(a.list_conversations_inner().len(), 2, "A holds both conversations");
        assert_ne!(g1, g2, "the two conversations have distinct ids");
        // A message in g1 reaches B and NOT C; a message in g2 reaches C and NOT B.
        let m1 = a.encrypt_inner(&g1, b"only for B").unwrap();
        assert_eq!(b.decrypt_inner(&sole_gid(&b), &m1).unwrap(), b"only for B");
        assert!(c.decrypt_inner(&sole_gid(&c), &m1).is_err(), "C is not in g1");
        let m2 = a.encrypt_inner(&g2, b"only for C").unwrap();
        assert_eq!(c.decrypt_inner(&sole_gid(&c), &m2).unwrap(), b"only for C");
        // Rosters are independent (each is a 2-member group, different peers).
        assert_eq!(a.roster_hex_inner(&g1).unwrap().len(), 2);
        assert_eq!(a.roster_hex_inner(&g2).unwrap().len(), 2);
        assert_ne!(a.group_mailbox_inner(&g1).unwrap(), a.group_mailbox_inner(&g2).unwrap());
    }

    #[test]
    fn receive_routes_each_message_to_its_own_conversation() {
        let (mut a, mut b, mut c, g1, g2) = two_conversations();
        // B sends in g1, C sends in g2. A's receive must route each to the correct conversation by id.
        let from_b = b.encrypt_inner(&sole_gid(&b), b"hi from B").unwrap();
        let from_c = c.encrypt_inner(&sole_gid(&c), b"hi from C").unwrap();
        let (rb, recv_b) = a.receive_inner(&from_b).unwrap();
        assert_eq!(hex(&rb), g1);
        assert!(matches!(recv_b, Received::Application { ref plaintext, .. } if plaintext == b"hi from B"));
        let (rc, recv_c) = a.receive_inner(&from_c).unwrap();
        assert_eq!(hex(&rc), g2);
        assert!(matches!(recv_c, Received::Application { ref plaintext, .. } if plaintext == b"hi from C"));
    }

    #[test]
    fn a_message_for_an_unheld_conversation_is_ignored_not_an_error() {
        // A holds g1 and g2; a stray message belonging to a group A does NOT hold must be ignored
        // (benign Proposal), never crash or mis-route, and must not disturb A's real conversations.
        let (mut a, mut b, _c, g1, _g2) = two_conversations();
        // Build an entirely separate group between two strangers; its message names a group id A lacks.
        let mut x = member("x");
        let y = member("y");
        let (wy, _gx) = x.create_group_inner(&[y.key_package().unwrap()]).unwrap();
        let mut y = y;
        y.join_from_welcome_inner(&wy).unwrap();
        let stray = x.encrypt_inner(&sole_gid(&x), b"not for A").unwrap();
        // A does not hold that group: receive returns the (unheld) id and a benign Proposal, no error.
        let (_gid, received) = a.receive_inner(&stray).unwrap();
        assert!(matches!(received, Received::Proposal), "an unheld group's message is ignored");
        // A's real conversation with B is untouched.
        let m = a.encrypt_inner(&g1, b"still works").unwrap();
        assert_eq!(b.decrypt_inner(&sole_gid(&b), &m).unwrap(), b"still works");
    }

    #[test]
    fn a_welcome_to_a_second_group_does_not_clobber_the_first() {
        // A is in g1 with B. A then joins g2 (welcomed by C). g1 must still work afterward.
        let b = member("b");
        let mut a = member("a");
        let (w1, g1) = a.create_group_inner(&[b.key_package().unwrap()]).unwrap();
        let g1 = hex(&g1);
        let mut b = b;
        b.join_from_welcome_inner(&w1).unwrap();

        let mut c = member("c");
        let (w_for_a, _g2c) = c.create_group_inner(&[a.key_package().unwrap()]).unwrap();
        let g2 = a.join_from_welcome_inner(&w_for_a).unwrap();
        let g2 = hex(&g2);
        assert_ne!(g1, g2);
        assert_eq!(a.list_conversations_inner().len(), 2);
        // g1 still delivers after A joined g2.
        let m = a.encrypt_inner(&g1, b"g1 survives").unwrap();
        assert_eq!(b.decrypt_inner(&sole_gid(&b), &m).unwrap(), b"g1 survives");
        // And g2 works too.
        let m2 = c.encrypt_inner(&sole_gid(&c), b"g2 hello").unwrap();
        assert_eq!(a.decrypt_inner(&g2, &m2).unwrap(), b"g2 hello");
    }

    #[test]
    fn seal_restore_preserves_all_conversations() {
        let (a, b, c, g1, g2) = two_conversations();
        let msk = [21u8; 32];
        let sealed = a.export_sealed_inner(&msk).unwrap();
        let mut reloaded = Conversation::from_sealed_inner(&msk, &sealed).unwrap();
        // Both conversations survive the reload with their distinct rosters and mailboxes.
        assert_eq!(reloaded.list_conversations_inner().len(), 2);
        assert_eq!(reloaded.roster_hex_inner(&g1).unwrap().len(), 2);
        assert_eq!(reloaded.roster_hex_inner(&g2).unwrap().len(), 2);
        // The reloaded device can still send in BOTH, and the right peer decrypts each.
        let mut b = b;
        let mut c = c;
        let m1 = reloaded.encrypt_inner(&g1, b"after reload g1").unwrap();
        assert_eq!(b.decrypt_inner(&sole_gid(&b), &m1).unwrap(), b"after reload g1");
        let m2 = reloaded.encrypt_inner(&g2, b"after reload g2").unwrap();
        assert_eq!(c.decrypt_inner(&sole_gid(&c), &m2).unwrap(), b"after reload g2");
    }

    // ── Batch B: the staged-commit crash window ────────────────────────────────────────────────────
    // A committer that crashes between stage and confirm used to lose its Pending (memory-only): if a
    // peer had already merged its commit, the reload re-staged a DISTINCT commit and the backstop merged
    // it, permanently forking the committer. The sealed container now persists the outgoing commit
    // bytes, and from_sealed reconstructs the pending, so the reload resumes the SAME commit.

    // The exact crash-window scenario: stage, SEAL (crash), the peer merges the commit meanwhile, RELOAD,
    // then the gateway redelivers our own commit: the reloaded committer recognizes its echo and confirms
    // onto the same epoch as the peer. No fork.
    #[test]
    fn a_staged_add_survives_seal_and_reload_then_confirms_on_its_echo() {
        let (mut a, mut b, a_seed, _) = authorized_pair();
        let ga = sole_gid(&a);
        let gb = sole_gid(&b);
        let a2 = Conversation::new_authorized_inner("a-phone", &a_seed).unwrap();
        let a2_sig = a2.signature_public_key_hex();
        let (commit, welcome) = a.stage_add_inner(&ga, &a2.key_package().unwrap()).unwrap();
        // Persist-before-publish: the client seals BEFORE the commit hits the wire. Then "crash".
        let msk = [77u8; 32];
        let sealed = a.export_sealed_inner(&msk).unwrap();
        drop(a);
        // The publish landed: the peer merges the commit while the committer is down.
        b.receive_inner(&commit).unwrap();
        // Reload: the pending survives with the exact wire bytes and target.
        let mut a = Conversation::from_sealed_inner(&msk, &sealed).unwrap();
        assert_eq!(a.pending_kind_inner(&ga).unwrap(), 1, "the staged Add must survive the reload");
        assert_eq!(a.pending_target_inner(&ga).unwrap(), a2_sig);
        assert_eq!(a.pending_commit_inner(&ga).unwrap(), commit, "the outgoing wire bytes must survive");
        // The gateway redelivers the un-acked commit on the epoch-N mailbox: the reloaded committer
        // recognizes its OWN echo and confirms (merges), landing on the peer's exact epoch.
        match a.receive_inner(&commit).unwrap().1 {
            Received::MembershipChanged { added, removed } => {
                assert!(removed.is_empty());
                assert_eq!(added.iter().map(|k| hex(k)).collect::<Vec<_>>(), vec![a2_sig]);
            }
            other => panic!("the reloaded committer must confirm its own echo, got {other:?}"),
        }
        let mut a2 = a2;
        a2.join_from_welcome_inner(&welcome).unwrap();
        // Converged: everyone decrypts on the same epoch. No fork.
        let ct = b.encrypt_inner(&gb, b"post-crash convergence").unwrap();
        let g2 = sole_gid(&a2);
        assert_eq!(a.decrypt_inner(&ga, &ct).unwrap(), b"post-crash convergence");
        assert_eq!(a2.decrypt_inner(&g2, &ct).unwrap(), b"post-crash convergence");
        assert_eq!(a.roster_hex_inner(&ga).unwrap().len(), 3);
    }

    // Backstop path: no echo ever arrives after the reload; the client's re-armed timeout confirms the
    // restored pending explicitly, still landing on the peer's epoch.
    #[test]
    fn a_reloaded_staged_add_confirms_via_the_backstop_when_no_echo() {
        let (mut a, mut b, a_seed, _) = authorized_pair();
        let ga = sole_gid(&a);
        let gb = sole_gid(&b);
        let a2 = Conversation::new_authorized_inner("a-phone", &a_seed).unwrap();
        let (commit, welcome) = a.stage_add_inner(&ga, &a2.key_package().unwrap()).unwrap();
        let msk = [78u8; 32];
        let sealed = a.export_sealed_inner(&msk).unwrap();
        drop(a);
        b.receive_inner(&commit).unwrap();
        let mut a = Conversation::from_sealed_inner(&msk, &sealed).unwrap();
        a.confirm_add_inner(&ga).unwrap(); // the re-armed backstop fires (no echo)
        a.confirm_add_inner(&ga).unwrap(); // idempotent
        let mut a2 = a2;
        a2.join_from_welcome_inner(&welcome).unwrap();
        let ct = a.encrypt_inner(&ga, b"backstop after reload").unwrap();
        let g2 = sole_gid(&a2);
        assert_eq!(b.decrypt_inner(&gb, &ct).unwrap(), b"backstop after reload");
        assert_eq!(a2.decrypt_inner(&g2, &ct).unwrap(), b"backstop after reload");
    }

    // Race safety after a reload: a COMPETING commit that won the epoch still aborts the restored pending
    // (exactly like the steady-state race), and the reloaded committer adopts the winner. No fork.
    #[test]
    fn a_reloaded_staged_add_aborts_on_a_competing_commit_no_fork() {
        let (mut a, mut b, mut c) = established_group_3();
        let ga = sole_gid(&a);
        let gb = sole_gid(&b);
        let gc = sole_gid(&c);
        let d = member("d");
        let e = member("e");
        let e_sig = e.signature_public_key_hex();
        let (commit_a, _welcome_d) = a.stage_add_inner(&ga, &d.key_package().unwrap()).unwrap();
        let msk = [79u8; 32];
        let sealed = a.export_sealed_inner(&msk).unwrap();
        drop(a);
        // B's competing add wins the gateway order while A is down.
        let (commit_b, welcome_e) = b.stage_add_inner(&gb, &e.key_package().unwrap()).unwrap();
        b.receive_inner(&commit_b).unwrap(); // B's own echo confirms it
        c.receive_inner(&commit_b).unwrap();
        // Reload A (pending restored), then the winner's commit arrives first: abort + adopt.
        let mut a = Conversation::from_sealed_inner(&msk, &sealed).unwrap();
        assert_eq!(a.pending_kind_inner(&ga).unwrap(), 1);
        match a.receive_inner(&commit_b).unwrap().1 {
            Received::MembershipChanged { added, .. } => {
                assert_eq!(added.iter().map(|k| hex(k)).collect::<Vec<_>>(), vec![e_sig]);
            }
            other => panic!("the reloaded loser must abort and adopt the winner, got {other:?}"),
        }
        assert_eq!(a.pending_kind_inner(&ga).unwrap(), 0, "the aborted pending must clear");
        let mut e = e;
        e.join_from_welcome_inner(&welcome_e).unwrap();
        // Converged on the winner's epoch; the stale commit_a is never adopted by anyone.
        let ct = c.encrypt_inner(&gc, b"winner converged").unwrap();
        let ge = sole_gid(&e);
        assert_eq!(a.decrypt_inner(&ga, &ct).unwrap(), b"winner converged");
        assert_eq!(b.decrypt_inner(&gb, &ct).unwrap(), b"winner converged");
        assert_eq!(e.decrypt_inner(&ge, &ct).unwrap(), b"winner converged");
        let _ = commit_a;
    }

    // The Remove twin of the crash window (a revocation in flight when the device dies).
    #[test]
    fn a_staged_remove_survives_seal_and_reload_then_confirms_on_its_echo() {
        let (mut a, mut b, a_seed, _) = authorized_pair();
        let ga = sole_gid(&a);
        let gb = sole_gid(&b);
        let a2 = Conversation::new_authorized_inner("a-phone", &a_seed).unwrap();
        let a2_sig = a2.signature_public_key_hex();
        // Admit a2 first so there is a sibling to remove.
        let (add_commit, _welcome) = a.stage_add_inner(&ga, &a2.key_package().unwrap()).unwrap();
        a.receive_inner(&add_commit).unwrap();
        b.receive_inner(&add_commit).unwrap();
        // Stage its removal, seal (crash), the peer merges the removal meanwhile.
        let rm_commit = a.stage_remove_inner(&ga, &a2_sig).unwrap();
        let msk = [80u8; 32];
        let sealed = a.export_sealed_inner(&msk).unwrap();
        drop(a);
        b.receive_inner(&rm_commit).unwrap();
        // Reload: the staged Remove survives and its echo confirms onto the peer's epoch.
        let mut a = Conversation::from_sealed_inner(&msk, &sealed).unwrap();
        assert_eq!(a.pending_kind_inner(&ga).unwrap(), 2, "the staged Remove must survive the reload");
        assert_eq!(a.pending_target_inner(&ga).unwrap(), a2_sig);
        match a.receive_inner(&rm_commit).unwrap().1 {
            Received::MembershipChanged { added, removed } => {
                assert!(added.is_empty());
                assert_eq!(removed.iter().map(|k| hex(k)).collect::<Vec<_>>(), vec![a2_sig]);
            }
            other => panic!("the reloaded committer must confirm its own removal echo, got {other:?}"),
        }
        let ct = b.encrypt_inner(&gb, b"after the removal").unwrap();
        assert_eq!(a.decrypt_inner(&ga, &ct).unwrap(), b"after the removal");
        assert_eq!(a.roster_hex_inner(&ga).unwrap().len(), 2, "a2 is rotated out on both sides");
    }

    // Must-fix 1 (Batch B review): re-delivering a Welcome to a device that ALREADY holds that group (the
    // restore re-arm re-publishes an Add's Welcome) must never clobber the live group's stored MLS state.
    // Two lines of defense, both exercised here:
    //  - at the ADDER, OpenMLS refuses to re-add a signature key already present (DuplicateSignatureKey),
    //    so an HONEST member cannot even mint a rival Welcome for a held group id;
    //  - at the JOINER, the same-bytes replay is a clean rejection (single-use key package), and the
    //    join_from_welcome_inner gid guard rejects any (e.g. maliciously crafted) Welcome naming a held
    //    group id BEFORE into_staged_welcome's PublicGroup::from_external can overwrite stored state.
    #[test]
    fn a_welcome_for_an_already_held_group_never_clobbers_it() {
        let (mut a, mut b, a_seed, _) = authorized_pair();
        let ga = sole_gid(&a);
        let gb = sole_gid(&b);
        let a2 = Conversation::new_authorized_inner("a-phone", &a_seed).unwrap();
        let (commit, welcome) = a.stage_add_inner(&ga, &a2.key_package().unwrap()).unwrap();
        a.receive_inner(&commit).unwrap();
        b.receive_inner(&commit).unwrap();
        let mut a2 = a2;
        a2.join_from_welcome_inner(&welcome).unwrap();
        let g2 = sole_gid(&a2);
        // Adder side: re-adding a2 (a member) is refused, so no honest rival Welcome for ga can exist.
        assert!(
            a.add_member_inner(&ga, &a2.key_package().unwrap()).is_err(),
            "OpenMLS must refuse to re-add an existing member (DuplicateSignatureKey)",
        );
        // Joiner side: replaying the original Welcome is a clean rejection, not a second join or a clobber.
        assert!(a2.join_from_welcome_inner(&welcome).is_err(), "a replayed Welcome must not join twice");
        // The live group is intact after both rejected paths: a2 still decrypts on its real epoch.
        let ct = b.encrypt_inner(&gb, b"unclobbered").unwrap();
        assert_eq!(a2.decrypt_inner(&g2, &ct).unwrap(), b"unclobbered");
    }

    // Should-fix 1 (Batch B review): a MALFORMED / truncated pendings section must NOT fail the decode
    // (which would silently replace the vault via the loadSelf fresh-identity fallback). It degrades to
    // "no pending". Emulate corruption by appending a bogus oversized pending count to a real blob.
    #[test]
    fn a_corrupt_pendings_section_degrades_to_no_pending_not_a_brick() {
        let (mut a, mut b, a_seed, _) = authorized_pair();
        let ga = sole_gid(&a);
        let gb = sole_gid(&b);
        let a2 = Conversation::new_authorized_inner("a-phone", &a_seed).unwrap();
        // Stage a real add so there IS a pendings section, then corrupt it.
        a.stage_add_inner(&ga, &a2.key_package().unwrap()).unwrap();
        let msk = [82u8; 32];
        let sealed = a.export_sealed_inner(&msk).unwrap();
        let container = crate::atrest::open(&msk, &sealed).unwrap();
        // Truncate INTO the trailing pendings section (chop the last bytes of the staged entry) so a
        // length-prefixed read runs past the end. Every earlier section is complete, so only the lenient
        // pendings parse sees the damage.
        let corrupt = &container[..container.len() - 12];
        let resealed = crate::atrest::seal(&msk, corrupt).unwrap();
        // It must still load (identity + groups intact) and simply carry no pending, not error out.
        let mut reloaded = Conversation::from_sealed_inner(&msk, &resealed).unwrap();
        let ct = b.encrypt_inner(&gb, b"survived corruption").unwrap();
        assert_eq!(reloaded.decrypt_inner(&ga, &ct).unwrap(), b"survived corruption");
    }

    // BH-S2: the mailbox delivery-cursor tag is stable across a seal/reload, differs per subject
    // (unlinkable in a registry snapshot), differs per device, and never equals the public bootstrap key.
    #[test]
    fn mailbox_tag_is_stable_per_subject_and_unlinkable_across_subjects() {
        let a = Conversation::new_authorized_inner("a", &[60u8; 32]).unwrap();
        let ta = a.mailbox_tag("gmbox-A");
        let tb = a.mailbox_tag("gmbox-B");
        assert_ne!(ta, tb, "different subjects must yield unrelated tags (unlinkable snapshot)");
        assert_eq!(ta, a.mailbox_tag("gmbox-A"), "the tag must be deterministic for a subject");
        assert_ne!(ta, a.signature_public_key_hex(), "the tag must not be the public bootstrap key");
        assert_eq!(ta.len(), 32, "16-byte hex tag");
        // Survives a seal + reload (the signer is restored identically), so the returning device
        // presents the SAME cursor and finds its held blobs.
        let msk = [61u8; 32];
        let sealed = a.export_sealed_inner(&msk).unwrap();
        let reloaded = Conversation::from_sealed_inner(&msk, &sealed).unwrap();
        assert_eq!(reloaded.mailbox_tag("gmbox-A"), ta, "the tag must survive a reload");
        // A different device (different signer) yields a different tag for the same subject.
        let b = Conversation::new_authorized_inner("b", &[62u8; 32]).unwrap();
        assert_ne!(b.mailbox_tag("gmbox-A"), ta, "different devices must yield different tags");
    }

    // BH-S3: a permanently unprocessable frame (malformed, or a gate-rejected commit) returns an error
    // marked with DROP_PREFIX so the client acks + drops it; a transient error is NOT so marked.
    #[test]
    fn permanent_receive_errors_are_marked_for_drop() {
        let (mut a, _b, _seed, _) = authorized_pair();
        // Malformed bytes: a parse failure, marked permanent.
        let err = a.receive_inner(&[0xff, 0x00, 0x13, 0x37]).unwrap_err();
        assert!(err.starts_with(DROP_PREFIX), "a malformed frame must be marked droppable, got: {err}");

        // A gate-rejected commit (an unknown-account add) is marked permanent too. Build a real one:
        // an attacker account commits an add of itself into a group it is (wrongly) in via a fork.
        let a_seed = [63u8; 32];
        let mut a2 = Conversation::new_authorized_inner("a", &a_seed).unwrap();
        let b2 = Conversation::new_authorized_inner("b", &[64u8; 32]).unwrap();
        let (w1, g1) = a2.create_group_inner(&[b2.key_package().unwrap()]).unwrap();
        let g1 = hex(&g1);
        let mut b2 = b2;
        b2.join_from_welcome_inner(&w1).unwrap();
        let attacker = Conversation::new_authorized_inner("attacker", &[99u8; 32]).unwrap();
        ungate(&mut a2, &g1);
        let (commit, _welcome) = a2.add_member_inner(&g1, &attacker.key_package().unwrap()).unwrap();
        let err = b2.receive_inner(&commit).unwrap_err();
        assert!(err.contains("unknown account key"), "sanity: gate rejection, got: {err}");
        assert!(err.starts_with(DROP_PREFIX), "a gate-rejected commit must be marked droppable, got: {err}");
    }

    // Back-compat: a blob sealed by a PRE-FIX build ends before the pendings section. Emulate one by
    // stripping the trailing empty-pendings count from a fresh export; it must still load cleanly (with
    // no pending), so the format change cannot brick an existing vault.
    #[test]
    fn a_pre_fix_blob_without_a_pendings_section_still_loads() {
        let (a, mut b, _, _) = authorized_pair();
        let ga = sole_gid(&a);
        let msk = [81u8; 32];
        let sealed = a.export_sealed_inner(&msk).unwrap();
        let container = crate::atrest::open(&msk, &sealed).unwrap();
        // Nothing is staged, so the new writer appended exactly a zero u32 pendings count; stripping it
        // yields the byte-exact pre-fix layout (the section absent, not empty).
        let truncated = &container[..container.len() - 4];
        let resealed = crate::atrest::seal(&msk, truncated).unwrap();
        let mut reloaded = Conversation::from_sealed_inner(&msk, &resealed).unwrap();
        assert_eq!(reloaded.pending_kind_inner(&ga).unwrap(), 0);
        let ct = reloaded.encrypt_inner(&ga, b"old blob still works").unwrap();
        assert_eq!(b.decrypt_inner(&sole_gid(&b), &ct).unwrap(), b"old blob still works");
    }

    #[test]
    fn a_staged_add_in_one_conversation_does_not_block_another() {
        // Per-group pending_add: A can have an add in flight in g1 AND stage one in g2 at the same time.
        let (mut a, _b, _c, g1, g2) = two_conversations();
        let d = member("d");
        let e = member("e");
        let (_c1, _w1) = a.stage_add_inner(&g1, &d.key_package().unwrap()).unwrap();
        // A second stage in g1 is refused (one in flight per group)...
        let f = member("f");
        assert!(a.stage_add_inner(&g1, &f.key_package().unwrap()).is_err());
        // ...but a stage in g2 is allowed (independent pending state).
        assert!(a.stage_add_inner(&g2, &e.key_package().unwrap()).is_ok());
    }

    #[test]
    fn the_authorization_gate_is_per_conversation() {
        // A is authorized and in two conversations, each with a different authorized peer. An add under
        // an unknown account is rejected in the conversation it targets; the other conversation is fine.
        let a_seed = [40u8; 32];
        let mut a = Conversation::new_authorized_inner("a", &a_seed).unwrap();
        let b = Conversation::new_authorized_inner("b", &[41u8; 32]).unwrap();
        let c = Conversation::new_authorized_inner("c", &[42u8; 32]).unwrap();
        let (w1, g1) = a.create_group_inner(&[b.key_package().unwrap()]).unwrap();
        let (_w2, g2) = a.create_group_inner(&[c.key_package().unwrap()]).unwrap();
        let g1 = hex(&g1);
        let g2 = hex(&g2);
        let mut b = b;
        b.join_from_welcome_inner(&w1).unwrap();
        // A (acting compromised) tries to add an UNKNOWN account into g1; the honest peer B rejects it.
        let attacker = Conversation::new_authorized_inner("attacker", &[99u8; 32]).unwrap();
        ungate(&mut a, &g1);
        let (commit, _welcome) = a.add_member_inner(&g1, &attacker.key_package().unwrap()).unwrap();
        let err = b.receive_inner(&commit).unwrap_err();
        assert!(err.contains("unknown account key"), "got: {err}");
        // g2's trusted set (A + C) is independent and intact: A's own account is still trusted there.
        let slot2_trusted_len = a.groups.get(&hex_to_bytes(&g2).unwrap()).unwrap().trusted_aaks.len();
        assert_eq!(slot2_trusted_len, 2, "g2 trusts A and C, unaffected by the g1 attack attempt");
    }

    // Own-identity sync (buddy icon across devices): a received application message reports whether its
    // AUTHENTICATED sender is one of OUR OWN account's devices, so a sibling's identity update is adopted
    // while a peer's is not. A peer cannot forge being our account (its credential carries its account
    // key, vetted by the gate).
    #[test]
    fn from_own_account_distinguishes_a_sibling_from_a_peer() {
        let a_seed = [50u8; 32];
        let mut a = Conversation::new_authorized_inner("a", &a_seed).unwrap();
        let b = Conversation::new_authorized_inner("b", &[51u8; 32]).unwrap();
        let a2 = Conversation::new_authorized_inner("a2", &a_seed).unwrap(); // A's sibling (same account)
        let (welcome, _gid) = a
            .create_group_inner(&[b.key_package().unwrap(), a2.key_package().unwrap()])
            .unwrap();
        let mut b = b;
        let mut a2 = a2;
        b.join_from_welcome_inner(&welcome).unwrap();
        a2.join_from_welcome_inner(&welcome).unwrap();
        // A message from our SIBLING A2 is flagged from_own_account = true.
        let from_sib = a2.encrypt_inner(&sole_gid(&a2), b"new icon").unwrap();
        match a.receive_inner(&from_sib).unwrap().1 {
            Received::Application { plaintext, from_own_account } => {
                assert_eq!(plaintext, b"new icon");
                assert!(from_own_account, "a sibling's message is from our own account");
            }
            other => panic!("expected an application message, got {other:?}"),
        }
        // A message from the PEER B is flagged from_own_account = false.
        let from_peer = b.encrypt_inner(&sole_gid(&b), b"hello").unwrap();
        match a.receive_inner(&from_peer).unwrap().1 {
            Received::Application { from_own_account, .. } => {
                assert!(!from_own_account, "a peer's message is NOT from our own account");
            }
            other => panic!("expected an application message, got {other:?}"),
        }
    }

    // The hidden self-group (a group of ONLY our own devices) is identified cryptographically: every
    // member carries our account key. A group that holds even one peer is NOT a self-group, so our buddy
    // list never rides a roster a peer can read.
    #[test]
    fn is_self_conversation_is_true_only_when_every_member_shares_our_account() {
        let a_seed = [60u8; 32];
        let mut a = Conversation::new_authorized_inner("a", &a_seed).unwrap();
        let a2 = Conversation::new_authorized_inner("a2", &a_seed).unwrap(); // sibling (same account)
        let a3 = Conversation::new_authorized_inner("a3", &a_seed).unwrap(); // sibling (same account)
        let b = Conversation::new_authorized_inner("b", &[61u8; 32]).unwrap(); // a peer (different account)

        // A group of ONLY our own devices is a self-group on every member.
        let (welcome, self_gid) = a
            .create_group_inner(&[a2.key_package().unwrap(), a3.key_package().unwrap()])
            .unwrap();
        let mut a2 = a2;
        let mut a3 = a3;
        a2.join_from_welcome_inner(&welcome).unwrap();
        a3.join_from_welcome_inner(&welcome).unwrap();
        assert!(a.is_self_conversation_inner(&hex(&self_gid)).unwrap(), "creator sees its own-devices group as a self-group");
        assert!(a2.is_self_conversation_inner(&sole_gid(&a2)).unwrap(), "a joined sibling sees it as a self-group");

        // A group that includes a PEER is NOT a self-group, even though our own devices are in it.
        let (welcome2, mixed_gid) = a
            .create_group_inner(&[b.key_package().unwrap(), a2.key_package().unwrap()])
            .unwrap();
        let mut b = b;
        b.join_from_welcome_inner(&welcome2).unwrap();
        assert!(!a.is_self_conversation_inner(&hex(&mixed_gid)).unwrap(), "a group with a peer is not a self-group");
        assert!(!b.is_self_conversation_inner(&sole_gid(&b)).unwrap(), "the peer does not see it as ITS self-group either");

        // The read-only diagnostic AGREES with the boolean and NAMES the cause. "self" exactly when the
        // predicate is true; a concrete, non-sensitive reason exactly when it is false. This is what lets
        // a stuck pairing be diagnosed by reading the reason instead of guessing at the roster.
        assert_eq!(a.self_classification_reason(&hex(&self_gid)), "self");
        assert_eq!(a2.self_classification_reason(&sole_gid(&a2)), "self");
        let mixed_reason = a.self_classification_reason(&hex(&mixed_gid));
        assert!(
            mixed_reason.contains("different account") || mixed_reason.contains("foreign account"),
            "a peer group must be named as such, got: {mixed_reason}",
        );
        // Reason and boolean can never disagree: whenever the reason is exactly "self", the predicate is
        // true, and whenever it is anything else, the predicate is false. Assert the invariant directly.
        for (conv, gid) in [(&a, hex(&self_gid)), (&a, hex(&mixed_gid))] {
            let is_self = conv.is_self_conversation_inner(&gid).unwrap();
            let reason_self = conv.self_classification_reason(&gid) == "self";
            assert_eq!(is_self, reason_self, "reason and boolean must agree for {gid}");
        }
        // A device with no account anchor at all names that, rather than silently returning "not self".
        let legacy = Conversation::new_inner("legacy").unwrap();
        let solo = {
            let mut l = legacy;
            let g = l.create_self_inner().unwrap();
            (l, hex(&g))
        };
        assert!(solo.0.self_classification_reason(&solo.1).contains("no account anchor"));
    }

    // BH-S3 refinement: our OWN echoed application frame is permanently undecryptable (the fan-out bus
    // echoes every publish back to the sender's own cursor) and must be marked droppable so the mailbox
    // drains instead of pinning + replaying an error on every reconnect. The slot must survive untouched.
    #[test]
    fn own_application_echo_is_droppable_and_group_survives() {
        let mut a = Conversation::new_authorized_inner("a", &[70u8; 32]).unwrap();
        let b = Conversation::new_authorized_inner("b", &[71u8; 32]).unwrap();
        let (welcome, gid) = a.create_group_inner(&[b.key_package().unwrap()]).unwrap();
        let gid = hex(&gid);
        let mut b = b;
        b.join_from_welcome_inner(&welcome).unwrap();
        let ct = a.encrypt_inner(&gid, b"hello").unwrap();
        let err = a.receive_inner(&ct).unwrap_err();
        assert!(err.starts_with(DROP_PREFIX), "an own echo must be droppable, got: {err}");
        assert!(err.contains("RatchetTypeError"), "must be the own-leaf decrypt failure, got: {err}");
        // The slot survived the error: the frame still decrypts on the peer and traffic keeps flowing.
        match b.receive_inner(&ct).unwrap().1 {
            Received::Application { plaintext, .. } => assert_eq!(plaintext, b"hello"),
            other => panic!("expected an application message, got {other:?}"),
        }
        let reply = b.encrypt_inner(&sole_gid(&b), b"yo").unwrap();
        match a.receive_inner(&reply).unwrap().1 {
            Received::Application { plaintext, .. } => assert_eq!(plaintext, b"yo"),
            other => panic!("expected an application message, got {other:?}"),
        }
    }

    // The ghost-channel repair: a device whose OWN leaf was minted pre-authorization (certless, frozen in
    // the roster forever) must still classify its own-devices group as self once its cert lands. The
    // sibling keeps classifying false (the certless leaf is not ITS own leaf): a documented residual its
    // recorded-set hiding covers.
    #[test]
    fn joiner_with_precert_leaf_reclassifies_after_adoption() {
        let mut a = Conversation::new_authorized_inner("a", &[80u8; 32]).unwrap();
        let mut d = Conversation::new_inner("d").unwrap(); // pending: certless key package
        let d_kp = d.key_package().unwrap();
        let (welcome, gid) = a.create_group_inner(&[d_kp]).unwrap();
        d.join_from_welcome_inner(&welcome).unwrap();
        let gid = hex(&gid);
        // Pre-adoption: no account anchor at all, so the group cannot classify self.
        assert!(!d.is_self_conversation_inner(&sole_gid(&d)).unwrap(), "no cert yet: not classifiable");
        transfer_authorize(&a, &mut d, 0).unwrap();
        assert!(d.our_account_pub().is_some(), "the adopted cert anchors the account key");
        // Post-adoption: the own-leaf exemption lets d recognize its self-group despite its frozen
        // certless leaf (false before this fix), while the strict predicate still reports the degraded
        // shape so canonical selection never prefers this copy.
        assert!(d.is_self_conversation_inner(&sole_gid(&d)).unwrap(), "own certless leaf is exempt");
        assert!(!d.is_self_conversation_strict_inner(&sole_gid(&d)).unwrap(), "strict sees the certless leaf");
        // Sibling residual: on a, d's leaf is NOT a's own leaf, so classification stays false.
        assert!(!a.is_self_conversation_inner(&gid).unwrap(), "the sibling still rejects the frozen leaf");
        // The cert adoption BACKFILLED the trusted set from the roster (a's leaf verifies), so the
        // trusted conjunct holds non-vacuously on the cert-only joiner too.
        let our = d.our_account_pub().unwrap();
        let trusted = &d.groups.values().next().unwrap().trusted_aaks;
        assert!(!trusted.is_empty(), "the backfill captured the roster's accounts");
        assert!(trusted.iter().all(|(k, _)| k == &our));
    }

    // PREVENTION (R9): the ADDER now mirrors the receive gate, so a certless (pre-authorization) or
    // forged key package can never be staged into an authorized conversation in the first place. The
    // error is PLAIN (skip-and-retry drains the consumed package), never DROP-prefixed.
    #[test]
    fn adder_rejects_a_certless_package_in_an_authorized_conversation() {
        let seed = [90u8; 32];
        let mut a = Conversation::new_authorized_inner("a", &seed).unwrap();
        let a2 = Conversation::new_authorized_inner("a2", &seed).unwrap();
        let (_welcome, gid) = a.create_group_inner(&[a2.key_package().unwrap()]).unwrap();
        let gid = hex(&gid);
        let pending = Conversation::new_inner("pend").unwrap(); // certless: never authorized
        let err = a.stage_add_inner(&gid, &pending.key_package().unwrap()).unwrap_err();
        assert!(err.contains("missing certificate"), "got: {err}");
        assert!(!err.starts_with(DROP_PREFIX), "adder-side rejections are plain skip-and-retry errors");
        let err2 = a.add_member_inner(&gid, &pending.key_package().unwrap()).unwrap_err();
        assert!(err2.contains("missing certificate"), "got: {err2}");
        // The group is untouched: a certified sibling package still stages fine afterwards.
        let a3 = Conversation::new_authorized_inner("a3", &seed).unwrap();
        a.stage_add_inner(&gid, &a3.key_package().unwrap()).unwrap();
    }

    // The adder gate also rejects a FORGED credential (claims a trusted account over an attacker key)
    // and an UNKNOWN account, exactly like the receive side. Legacy (empty trusted set) stays ungated.
    #[test]
    fn adder_gate_matches_the_receive_gate_semantics() {
        let (mut a, _b, _sa, _sb) = authorized_pair();
        let g = sole_gid(&a);
        // Forged: claims a's account key over a fresh attacker key with a junk cert.
        let a_aak = hex_to_bytes(&a.account_key_hex()).unwrap();
        let forged = forged_authorized_kp(&a.provider, &a_aak);
        let err = a.stage_add_inner(&g, &forged).unwrap_err();
        assert!(err.contains("did not verify"), "got: {err}");
        // Unknown account: a fully certified device of an account this conversation never trusted.
        let stranger = Conversation::new_authorized_inner("s", &[91u8; 32]).unwrap();
        let err2 = a.stage_add_inner(&g, &stranger.key_package().unwrap()).unwrap_err();
        assert!(err2.contains("unknown account key"), "got: {err2}");
        // Legacy contrast: a label-only device (empty trusted set everywhere) still stages ungated.
        let mut legacy = Conversation::new_inner("l1").unwrap();
        let legacy2 = Conversation::new_inner("l2").unwrap();
        let (_w, lg) = legacy.create_group_inner(&[legacy2.key_package().unwrap()]).unwrap();
        let legacy3 = Conversation::new_inner("l3").unwrap();
        legacy.stage_add_inner(&hex(&lg), &legacy3.key_package().unwrap()).unwrap();
    }

    // PREVENTION (R9): the self-group is gated at BIRTH: every founding member must chain to OUR
    // account. A stale pre-authorization package can never mint a poisoned self-group again.
    #[test]
    fn create_self_group_rejects_a_certless_or_foreign_package() {
        let seed = [92u8; 32];
        let mut a = Conversation::new_authorized_inner("a", &seed).unwrap();
        let pending = Conversation::new_inner("pend").unwrap();
        let err = a.create_self_group_inner(&[pending.key_package().unwrap()]).unwrap_err();
        assert!(err.contains("without a certificate"), "got: {err}");
        let peer = Conversation::new_authorized_inner("b", &[93u8; 32]).unwrap();
        let err2 = a.create_self_group_inner(&[peer.key_package().unwrap()]).unwrap_err();
        assert!(err2.contains("another account"), "got: {err2}");
        assert!(a.groups.is_empty(), "no group was minted by the rejected attempts");
        // A certified sibling founds it fine, and it is a STRICT self-group from birth.
        let a2 = Conversation::new_authorized_inner("a2", &seed).unwrap();
        let (_welcome, gid) = a.create_self_group_inner(&[a2.key_package().unwrap()]).unwrap();
        assert!(a.is_self_conversation_strict_inner(&hex(&gid)).unwrap());
    }

    // The birth gate carries the FLOOR half too: a revoked device's leftover pre-revoke package still
    // verifies, and only the device-local anti-rollback floor rejects it when a lying directory serves
    // it. The eligibility predicate (the client-side pre-filter) must agree with the gate.
    #[test]
    fn create_self_group_rejects_a_below_floor_package() {
        let seed = [94u8; 32];
        let mut a = Conversation::new_authorized_inner("a", &seed).unwrap();
        let stale = Conversation::new_authorized_inner("stale", &seed).unwrap(); // certified at epoch 0
        let stale_kp = stale.key_package().unwrap();
        assert!(a.key_package_self_eligible_inner(&stale_kp), "at the floor: eligible before the bump");
        // A revoke bumped the account epoch; the creator re-certified at 1, raising its floor.
        a.recredential_at_epoch_inner(1).unwrap();
        let err = a.create_self_group_inner(&[stale_kp.clone()]).unwrap_err();
        assert!(err.contains("below floor"), "got: {err}");
        assert!(!a.key_package_self_eligible_inner(&stale_kp), "the pre-filter agrees with the gate");
        assert!(a.groups.is_empty(), "nothing was minted");
        // A sibling re-certified at the current epoch founds it fine.
        let mut fresh = Conversation::new_authorized_inner("fresh", &seed).unwrap();
        fresh.recredential_at_epoch_inner(1).unwrap();
        a.create_self_group_inner(&[fresh.key_package().unwrap()]).unwrap();
    }

    // R10: closing a conversation drops the group AND its MLS state, so the sealed export no longer
    // carries it and a reload cannot revive it. Idempotent for an unknown id; refuses the self-group.
    #[test]
    fn close_conversation_drops_the_group_durably_and_refuses_the_self_group() {
        let (mut a, _b, _sa, _sb) = authorized_pair();
        let g = sole_gid(&a);
        a.close_conversation_inner(&g).unwrap();
        assert!(a.list_conversations_inner().is_empty(), "the group is gone");
        a.close_conversation_inner(&g).unwrap(); // idempotent: closing again is a no-op
        // Durable: a seal/restore round-trip does not resurrect it.
        let msk = [44u8; 32];
        let sealed = a.export_sealed_inner(&msk).unwrap();
        let reloaded = Conversation::from_sealed_inner(&msk, &sealed).unwrap();
        assert!(reloaded.list_conversations_inner().is_empty(), "the restore does not revive it");
        // The own-devices self-group refuses to close.
        let seed = [95u8; 32];
        let mut s = Conversation::new_authorized_inner("s", &seed).unwrap();
        let s2 = Conversation::new_authorized_inner("s2", &seed).unwrap();
        let (_w, self_gid) = s.create_self_group_inner(&[s2.key_package().unwrap()]).unwrap();
        let err = s.close_conversation_inner(&hex(&self_gid)).unwrap_err();
        assert!(err.contains("own-devices"), "got: {err}");
        assert_eq!(s.list_conversations_inner().len(), 1, "the self-group survives");
    }

    // The close guards must hold in the GHOST states where the lenient classifier fails: a self-group
    // carrying a frozen certless leaf, and a pre-cert device that cannot classify anything yet.
    #[test]
    fn close_refuses_a_ghost_classified_self_group_in_every_window() {
        let seed = [99u8; 32];
        let mut a = Conversation::new_authorized_inner("a", &seed).unwrap();
        let mut d = Conversation::new_inner("d").unwrap(); // joins pre-cert: its leaf is frozen certless
        let d_kp = d.key_package().unwrap();
        let (welcome, gid) = a.create_group_inner(&[d_kp]).unwrap();
        d.join_from_welcome_inner(&welcome).unwrap();
        let gid_hex = hex(&gid);
        // Seed-holder view: classify is FALSE (d's certless leaf), yet the formation trust is all-ours.
        assert!(!a.is_self_conversation_inner(&gid_hex).unwrap(), "sanity: the ghost state");
        let err = a.close_conversation_inner(&gid_hex).unwrap_err();
        assert!(err.contains("own-devices"), "the trusted-set guard holds: {err}");
        // Pre-cert joiner view: no account anchor, but a CERTIFIED member exists (could be a sibling).
        let err2 = d.close_conversation_inner(&sole_gid(&d)).unwrap_err();
        assert!(err2.contains("unsettled"), "the indeterminate guard holds: {err2}");
        // Post-cert joiner view: the backfilled trusted set is all-ours; still refused.
        transfer_authorize(&a, &mut d, 0).unwrap();
        let err3 = d.close_conversation_inner(&sole_gid(&d)).unwrap_err();
        assert!(err3.contains("own-devices"), "the trusted-set guard holds post-cert: {err3}");
        // A legacy label-only conversation (no certified member anywhere) still closes.
        let mut l1 = Conversation::new_inner("l1").unwrap();
        let l2 = Conversation::new_inner("l2").unwrap();
        let (_w, lg) = l1.create_group_inner(&[l2.key_package().unwrap()]).unwrap();
        l1.close_conversation_inner(&hex(&lg)).unwrap();
        assert!(l1.list_conversations_inner().is_empty(), "legacy accounts are not blocked from closing");
    }

    // R10: the unlinked advisory fires ONLY for a roster with a certless non-own leaf and no verified
    // foreign device. A real peer (even one that never comes online) keeps the channel linked.
    #[test]
    fn channel_unlinked_flags_certless_rosters_and_never_real_peers() {
        // A certified PEER conversation: linked, regardless of liveness.
        let (a, _b, _sa, _sb) = authorized_pair();
        assert!(!a.channel_unlinked_inner(&sole_gid(&a)).unwrap(), "a verified peer keeps it linked");
        // A group whose only other member is a certless (pre-authorization) leaf: unlinked.
        let mut c = Conversation::new_authorized_inner("c", &[96u8; 32]).unwrap();
        let orphan = Conversation::new_inner("orphan").unwrap();
        let (_w, gid) = c.create_group_inner(&[orphan.key_package().unwrap()]).unwrap();
        assert!(c.channel_unlinked_inner(&hex(&gid)).unwrap(), "a certless-only roster is unlinked");
        // A mixed roster (certless leaf + a verified peer): still linked (the peer is reachable).
        let peer = Conversation::new_authorized_inner("p", &[97u8; 32]).unwrap();
        let orphan2 = Conversation::new_inner("orphan2").unwrap();
        let (_w2, gid2) = c
            .create_group_inner(&[orphan2.key_package().unwrap(), peer.key_package().unwrap()])
            .unwrap();
        assert!(!c.channel_unlinked_inner(&hex(&gid2)).unwrap(), "a verified peer outranks the orphan");
        // An own-devices self-group: never flagged (all members are our certed siblings).
        let seed = [98u8; 32];
        let mut s = Conversation::new_authorized_inner("s", &seed).unwrap();
        let s2 = Conversation::new_authorized_inner("s2", &seed).unwrap();
        let (_w3, self_gid) = s.create_self_group_inner(&[s2.key_package().unwrap()]).unwrap();
        assert!(!s.channel_unlinked_inner(&hex(&self_gid)).unwrap());
        // The partially-formed GHOST self-group {us, verified sibling, certless orphan}: the verified
        // sibling IS a reachable recipient, so the row must NOT read as unreachable (an advisory there
        // would invite removing the real self-group).
        let s3 = Conversation::new_authorized_inner("s3", &seed).unwrap();
        let orphan3 = Conversation::new_inner("orphan3").unwrap();
        let (_w4, mixed_self) = s
            .create_group_inner(&[s3.key_package().unwrap(), orphan3.key_package().unwrap()])
            .unwrap();
        assert!(!s.channel_unlinked_inner(&hex(&mixed_self)).unwrap(), "a verified own sibling keeps it linked");
    }

    // SG2 SELF-HEAL: a poisoned self-group (a frozen certless leaf, unrepairable in place) must be
    // abandonable so the account can reform a clean one — WITHOUT opening a way to delete a healthy
    // own-devices group. The refusals are the load-bearing half of this test.
    #[test]
    fn a_dead_self_group_can_be_abandoned_but_a_live_one_and_a_peer_conversation_never_are() {
        let seed = [120u8; 32];

        // A HEALTHY self-group (us + a certified sibling) must be REFUSED: it still works.
        let mut s = Conversation::new_authorized_inner("s", &seed).unwrap();
        let s2 = Conversation::new_authorized_inner("s2", &seed).unwrap();
        let (_w, healthy) = s.create_self_group_inner(&[s2.key_package().unwrap()]).unwrap();
        let err = s.abandon_dead_self_group_inner(&hex(&healthy), true).unwrap_err();
        assert!(err.contains("still reachable"), "a live self-group must never be abandoned, got: {err}");
        assert!(s.list_conversations_inner().contains(&hex(&healthy)), "and it is still held");

        // A PEER conversation must be REFUSED even when unlinked: that is close_conversation's job, and
        // this path must never become a way to silently drop someone else's chat.
        let mut c = Conversation::new_authorized_inner("c", &[121u8; 32]).unwrap();
        let orphan = Conversation::new_inner("orphan").unwrap();
        let (_w2, peerish) = c.create_group_inner(&[orphan.key_package().unwrap()]).unwrap();
        assert!(c.channel_unlinked_inner(&hex(&peerish)).unwrap(), "fixture really is unlinked");
        // The caller has NOT recorded it as a self-group, which is the only signal that separates it from
        // a poisoned self-group here. This is the case that protects a real pending peer chat.
        let err2 = c.abandon_dead_self_group_inner(&hex(&peerish), false).unwrap_err();
        assert!(err2.contains("not a recorded own-devices group"), "a peer conversation is refused, got: {err2}");
        assert!(c.list_conversations_inner().contains(&hex(&peerish)), "and it survives");

        // THE REAL CASE: a self-group whose only other member is a frozen CERTLESS leaf. It can never be
        // repaired (MLS never rewrites a leaf credential) and never syncs — the live "ghost Note to Self".
        // create_self_group_inner refuses to MINT one, so build the poisoned state the way it actually
        // arises (an ungated create) and mark it own-account, exactly as the formation-time trusted set does.
        let mut p = Conversation::new_authorized_inner("p", &seed).unwrap();
        let certless = Conversation::new_inner("certless").unwrap();
        let (_w3, dead) = p.create_group_inner(&[certless.key_package().unwrap()]).unwrap();
        let our = p.our_account_pub().unwrap();
        if let Some(slot) = p.groups.get_mut(&dead) {
            slot.trusted_aaks = vec![(our, 0)]; // formed trusting ONLY our account: this is OUR group
        }
        assert!(p.channel_unlinked_inner(&hex(&dead)).unwrap(), "the poisoned group is unreachable");
        assert!(p.abandon_dead_self_group_inner(&hex(&dead), true).unwrap(), "it is abandoned");
        assert!(!p.list_conversations_inner().contains(&hex(&dead)), "and the MLS state is gone");
        // Idempotent: abandoning again is a no-op, not an error (the heal may run on every reconnect).
        assert!(!p.abandon_dead_self_group_inner(&hex(&dead), true).unwrap());
    }

    // MIGRATION: a sealed blob written by an OLD build on a cert-only device carries the adopted
    // credential alongside EMPTY trusted sets. The restore must repopulate them, or the trusted
    // conjunct stays vacuous on the already-deployed population forever.
    #[test]
    fn restore_backfills_an_empty_trusted_set_when_the_account_is_anchored() {
        let mut a = Conversation::new_authorized_inner("a", &[88u8; 32]).unwrap();
        let mut d = Conversation::new_inner("d").unwrap();
        let d_kp = d.key_package().unwrap();
        let (welcome, _gid) = a.create_group_inner(&[d_kp]).unwrap();
        d.join_from_welcome_inner(&welcome).unwrap();
        transfer_authorize(&a, &mut d, 0).unwrap();
        // Model the old-build blob: the cert is adopted but the trusted set was never captured.
        for slot in d.groups.values_mut() {
            slot.trusted_aaks.clear();
        }
        let msk = [43u8; 32];
        let sealed = d.export_sealed_inner(&msk).unwrap();
        let reloaded = Conversation::from_sealed_inner(&msk, &sealed).unwrap();
        let our = reloaded.our_account_pub().unwrap();
        let trusted = &reloaded.groups.values().next().unwrap().trusted_aaks;
        assert!(!trusted.is_empty(), "the restore backfilled the trusted set");
        assert!(trusted.iter().all(|(k, _)| k == &our));
    }

    // The certified-replacement mint gate: a certified credential reports true, a legacy label-only
    // one false (its mint would be lenient-only too, so the client must not replace with it).
    #[test]
    fn credential_certified_tracks_the_adopted_or_minted_cert() {
        let a = Conversation::new_authorized_inner("a", &[89u8; 32]).unwrap();
        assert!(a.credential_certified_inner(), "a seed-holder's self-signed cert verifies");
        let mut d = Conversation::new_inner("d").unwrap();
        assert!(!d.credential_certified_inner(), "a pending label-only credential does not");
        transfer_authorize(&a, &mut d, 0).unwrap();
        assert!(d.credential_certified_inner(), "the adopted cert verifies");
    }

    // The trusted conjunct must hold on CERT-ONLY devices too: a peer conversation whose peer left
    // must never classify self there. Regression coverage for the backfill (the set used to stay empty
    // on cert-only devices, making the conjunct vacuous exactly where the own-leaf exemption is live).
    #[test]
    fn cert_only_device_keeps_a_peer_left_conversation_non_self() {
        let mut a = Conversation::new_authorized_inner("a", &[86u8; 32]).unwrap(); // seed-holder
        let b = Conversation::new_authorized_inner("b", &[87u8; 32]).unwrap(); // a peer
        let mut d = Conversation::new_inner("d").unwrap(); // joins pre-cert, authorized cert-only later
        let d_kp = d.key_package().unwrap();
        let (welcome, gid) = a.create_group_inner(&[b.key_package().unwrap(), d_kp]).unwrap();
        d.join_from_welcome_inner(&welcome).unwrap();
        transfer_authorize(&a, &mut d, 0).unwrap(); // the cert lands AFTER the Welcome: backfill runs
        let commit = a.remove_member_inner(&hex(&gid), &b.signature_public_key_hex()).unwrap();
        d.receive_inner(&commit).unwrap();
        // Only our own account's devices remain in the roster, yet the formation-time trust remembers
        // the peer, so the conversation stays a peer conversation (its row must never be hidden).
        assert!(!d.is_self_conversation_inner(&sole_gid(&d)).unwrap(), "the departed peer's account keeps it non-self");
        let our = d.our_account_pub().unwrap();
        assert!(d.groups.values().next().unwrap().trusted_aaks.iter().any(|(k, _)| k != &our), "the peer's account is in the trusted set");
    }

    // The own-leaf exemption must NEVER admit a peer: with our certless own leaf AND a peer in the same
    // roster, the peer's foreign leaf still fails the member check.
    #[test]
    fn own_leaf_exemption_never_admits_a_peer() {
        let mut a = Conversation::new_authorized_inner("a", &[82u8; 32]).unwrap();
        let b = Conversation::new_authorized_inner("b", &[83u8; 32]).unwrap(); // a peer
        let mut d = Conversation::new_inner("d").unwrap(); // pending: certless key package
        let d_kp = d.key_package().unwrap();
        let (welcome, _gid) = a.create_group_inner(&[b.key_package().unwrap(), d_kp]).unwrap();
        d.join_from_welcome_inner(&welcome).unwrap();
        transfer_authorize(&a, &mut d, 0).unwrap();
        assert!(!d.is_self_conversation_inner(&sole_gid(&d)).unwrap(), "the peer's leaf fails the check");
    }

    // A peer conversation whose peer devices all LEFT keeps its formation-time trusted set, so the
    // roster-only shape (all remaining members our own) must not classify self: hiding it would delete
    // a real conversation's summary. This is the trusted_aaks conjunct.
    #[test]
    fn peer_left_conversation_stays_non_self() {
        let (mut a, b, _a_seed, _b_seed) = authorized_pair();
        let g = sole_gid(&a);
        let commit = a.remove_member_inner(&g, &b.signature_public_key_hex()).unwrap();
        drop(commit); // b is gone from a's roster; only our own device remains
        let only_own = a
            .groups
            .values()
            .next()
            .unwrap()
            .group
            .members()
            .count();
        assert_eq!(only_own, 1, "the roster is all-own after the peer left");
        assert!(!a.is_self_conversation_inner(&g).unwrap(), "the formation-time peer trust keeps it a peer conversation");
        assert_eq!(a.groups.values().next().unwrap().trusted_aaks.len(), 2, "the trusted set still holds the peer's account");
    }

    // The strict predicate is TRUE for a fully certified self-group (both classifications agree there).
    #[test]
    fn strict_predicate_accepts_a_fully_certified_self_group() {
        let seed = [84u8; 32];
        let mut a = Conversation::new_authorized_inner("a", &seed).unwrap();
        let a2 = Conversation::new_authorized_inner("a2", &seed).unwrap();
        let (welcome, self_gid) = a.create_group_inner(&[a2.key_package().unwrap()]).unwrap();
        let mut a2 = a2;
        a2.join_from_welcome_inner(&welcome).unwrap();
        assert!(a.is_self_conversation_strict_inner(&hex(&self_gid)).unwrap());
        assert!(a2.is_self_conversation_strict_inner(&sole_gid(&a2)).unwrap());
    }

    // create_self opens the own-devices self-group on a SINGLE device (no sibling to admit yet), so a
    // one-device account still has a Note-to-Self / buddy-sync channel. It must be a self-conversation
    // immediately, and it must grow into the multi-device self-group when a sibling folds in later.
    #[test]
    fn create_self_opens_a_solo_self_group_that_grows_with_a_sibling() {
        let seed = [72u8; 32];
        let mut a = Conversation::new_authorized_inner("a", &seed).unwrap();
        let gid = a.create_self_inner().unwrap();
        assert_eq!(a.roster_hex_inner(&hex(&gid)).unwrap().len(), 1, "a solo self-group holds only this device");
        assert!(a.is_self_conversation_inner(&hex(&gid)).unwrap(), "a solo own-device group is a self-group");
        // A sibling (same account seed) joins later through the normal add path; it stays a self-group.
        let a2 = Conversation::new_authorized_inner("a2", &seed).unwrap();
        let (_commit, welcome) = a.add_member_inner(&hex(&gid), &a2.key_package().unwrap()).unwrap();
        let mut a2 = a2;
        a2.join_from_welcome_inner(&welcome).unwrap();
        assert_eq!(a.roster_hex_inner(&hex(&gid)).unwrap().len(), 2, "the sibling folded in");
        assert!(a.is_self_conversation_inner(&hex(&gid)).unwrap(), "still a self-group after a sibling joins");
        assert!(a2.is_self_conversation_inner(&sole_gid(&a2)).unwrap(), "the joined sibling sees it as a self-group too");
    }

    // A device that never adopted an account key (legacy/unauthorized) has no self-group: is_self_conversation
    // needs the account key to verify member certificates, so its solo group is NOT a self-conversation.
    #[test]
    fn an_unauthorized_device_has_no_self_group() {
        let mut d = Conversation::new_inner("d").unwrap();
        let gid = d.create_self_inner().unwrap();
        assert!(!d.is_self_conversation_inner(&hex(&gid)).unwrap());
    }

    // A CERT-ONLY device (provisioned by QR/six words: it adopted a certificate but never the account
    // key) anchors is_self_conversation on the account key inside its OWN verified credential, so it
    // still recognizes the own-devices self-group. Without this it would surface the self-group as a
    // normal peer conversation, whose Add control could then inject a real peer into it.
    #[test]
    fn a_cert_only_device_recognizes_the_self_group() {
        let mut d1 = Conversation::new_authorized_inner("d1", &[73u8; 32]).unwrap();
        let mut d2 = Conversation::new_inner("d2").unwrap();
        transfer_authorize(&d1, &mut d2, 0).unwrap();
        assert!(d2.account_key_hex().is_empty()); // holds a cert, not the account key

        let (welcome, gid) = d1.create_group_inner(&[d2.key_package().unwrap()]).unwrap();
        d2.join_from_welcome_inner(&welcome).unwrap();
        assert!(d1.is_self_conversation_inner(&hex(&gid)).unwrap(), "the seed holder sees the self-group");
        assert!(d2.is_self_conversation_inner(&sole_gid(&d2)).unwrap(), "the cert-only sibling recognizes it too");

        // And a sibling's app message reads as from OUR OWN account on the cert-only device, so
        // control-frame syncs (buddy list, identity) converge there as well.
        let ct = d1.encrypt_inner(&hex(&gid), b"note").unwrap();
        match d2.receive_inner(&ct).unwrap().1 {
            Received::Application { from_own_account, .. } => {
                assert!(from_own_account, "a sibling's message is from our own account on a cert-only device");
            }
            other => panic!("expected an application message, got {other:?}"),
        }
    }

    // THE SELF-GROUP SPLIT REGRESSION (2026-08-01). A KeyPackage's private half lives only in the
    // provider's storage map until a reseal writes it down, and the sealed blob IS that map. Minting
    // AFTER the last seal therefore publishes a public package whose private half dies on the next
    // reload — the directory still advertises it, a sibling claims it, and the Welcome sealed to it is
    // mathematically un-openable. These two tests pin both directions of the ordering contract that
    // the client's `freshKeyPackages` now enforces (mint, then seal, THEN publish).
    #[test]
    fn a_key_package_sealed_after_minting_survives_a_reload() {
        let msk = [7u8; 32];
        let mut d1 = Conversation::new_authorized_inner("d1", &[76u8; 32]).unwrap();
        let mut d2 = Conversation::new_inner("d2").unwrap();
        transfer_authorize(&d1, &mut d2, 0).unwrap();

        let kp = d2.key_package().unwrap(); // published to the directory
        let sealed = d2.export_sealed_inner(&msk).unwrap(); // Fix A: seal AFTER minting
        let mut d2 = Conversation::from_sealed_inner(&msk, &sealed).unwrap(); // reload (iOS tab recycle)

        let (welcome, _gid) = d1.create_group_inner(&[kp]).unwrap();
        assert!(
            d2.join_from_welcome_inner(&welcome).is_ok(),
            "a key package sealed after minting must still open its Welcome after a reload"
        );
    }

    #[test]
    fn a_key_package_minted_after_the_last_seal_is_lost_on_reload() {
        let msk = [8u8; 32];
        let mut d1 = Conversation::new_authorized_inner("d1", &[77u8; 32]).unwrap();
        let mut d2 = Conversation::new_inner("d2").unwrap();
        transfer_authorize(&d1, &mut d2, 0).unwrap();

        let sealed = d2.export_sealed_inner(&msk).unwrap(); // the OLD order: seal, then mint
        let kp = d2.key_package().unwrap(); // private half never reaches the blob
        let mut d2 = Conversation::from_sealed_inner(&msk, &sealed).unwrap();

        let (welcome, _gid) = d1.create_group_inner(&[kp]).unwrap();
        let err = d2.join_from_welcome_inner(&welcome).unwrap_err();
        assert!(
            err.contains("NoMatchingKeyPackage"),
            "an orphaned key package must fail loudly as NoMatchingKeyPackage, got: {err}"
        );
    }

    // The directory keeps ONE permanently re-claimable last-resort row (UserStore: no consumed_at
    // filter), so its private bundle must survive a join. OpenMLS only skips the delete when the
    // LastResort extension is present — without it the SECOND claim of that same row yields an
    // un-openable Welcome, with no crash and no race required.
    #[test]
    fn the_last_resort_key_package_is_reusable_across_joins() {
        let mut d1 = Conversation::new_authorized_inner("d1", &[78u8; 32]).unwrap();
        let mut d2 = Conversation::new_inner("d2").unwrap();
        transfer_authorize(&d1, &mut d2, 0).unwrap();

        let lr = d2.key_package_last_resort().unwrap();
        let (w1, _) = d1.create_group_inner(&[lr.clone()]).unwrap();
        d2.join_from_welcome_inner(&w1).expect("first join with the last-resort package");

        let (w2, _) = d1.create_group_inner(&[lr]).unwrap();
        assert!(
            d2.join_from_welcome_inner(&w2).is_ok(),
            "the last-resort package is re-served forever, so its bundle must survive the first join"
        );
    }

    // The counterpart boundary: ONE-TIME packages must still be consumed by their first join, or a
    // stale directory row would let a package be claimed twice and silently fork forward secrecy.
    #[test]
    fn a_one_time_key_package_is_consumed_by_its_first_join() {
        let mut d1 = Conversation::new_authorized_inner("d1", &[79u8; 32]).unwrap();
        let mut d2 = Conversation::new_inner("d2").unwrap();
        transfer_authorize(&d1, &mut d2, 0).unwrap();

        let kp = d2.key_package().unwrap();
        let (w1, _) = d1.create_group_inner(&[kp.clone()]).unwrap();
        d2.join_from_welcome_inner(&w1).expect("first join with a one-time package");

        let (w2, _) = d1.create_group_inner(&[kp]).unwrap();
        assert!(
            d2.join_from_welcome_inner(&w2).is_err(),
            "a one-time key package must not open a second Welcome"
        );
    }

    // The cert-only fallback must NOT weaken the peer boundary: a group holding a PEER is still not a
    // self-group on the cert-only device (the peer's cert cannot verify under our account key).
    #[test]
    fn a_cert_only_device_still_rejects_a_group_with_a_peer() {
        let mut d1 = Conversation::new_authorized_inner("d1", &[74u8; 32]).unwrap();
        let mut d2 = Conversation::new_inner("d2").unwrap();
        transfer_authorize(&d1, &mut d2, 0).unwrap();
        let b = Conversation::new_authorized_inner("b", &[75u8; 32]).unwrap(); // a peer account

        let (welcome, _gid) = d1
            .create_group_inner(&[d2.key_package().unwrap(), b.key_package().unwrap()])
            .unwrap();
        let joined = d2.join_from_welcome_inner(&welcome).unwrap();
        assert!(!d2.is_self_conversation_inner(&hex(&joined)).unwrap(), "a peer in the roster breaks self on a cert-only device");
    }

    // A member that merely CLAIMS our account key (our aak in free-form credential bytes) with a bogus
    // certificate must NOT make a group a self-group. The creator add path does not run the roster gate,
    // so the forged member is genuinely in the group; is_self_conversation still returns false because it
    // verifies each member's certificate. Without that cert check it returns true and the buddy list (the
    // contact graph) would publish into a group an attacker can decrypt. This is the P0 leak guard.
    #[test]
    fn is_self_conversation_rejects_a_member_that_forges_our_account_key() {
        let a_seed = [62u8; 32];
        let mut a = Conversation::new_authorized_inner("a", &a_seed).unwrap();
        let a_aak_pub = authz::aak_public(&authz::aak_from_seed(&a_seed).unwrap());
        // An attacker mints a key package claiming OUR account key with a junk certificate (it lacks our
        // account secret, so the cert cannot verify). The creator add path does not gate, so it joins.
        let forged_kp = forged_authorized_kp(&OpenMlsRustCrypto::default(), &a_aak_pub);
        let (_welcome, gid) = a.create_group_inner(&[forged_kp]).unwrap();
        assert!(
            !a.is_self_conversation_inner(&hex(&gid)).unwrap(),
            "a forged, unverifiable certificate must not make this a self-group (else the contact graph leaks)"
        );
    }

    // An UNauthorized (legacy, label-only) identity has no account key, so from_own_account is always
    // false (the legacy 2-member path never adopts a sibling identity).
    #[test]
    fn from_own_account_is_false_without_an_account_key() {
        let (mut accepter, mut offerer) = established_pair(); // both unauthorized (new_inner)
        let g = sole_gid(&accepter);
        let ct = offerer.encrypt_inner(&sole_gid(&offerer), b"hi").unwrap();
        match accepter.receive_inner(&ct).unwrap().1 {
            Received::Application { from_own_account, .. } => assert!(!from_own_account),
            other => panic!("expected an application message, got {other:?}"),
        }
        let _ = g;
    }
}
