# DEAD DROP — Threat Model

> Source of truth: the build brief §A and §5. This document engineers the property
> set against the stated adversary. Where this document and the brief's §A conflict,
> §A wins. Where a claim is best-effort rather than guaranteed, it is labeled as such.
> We do not use the phrase "perfect secrecy."

## 0. Who this protects and why it matters

Primary users are dissidents and reporters operating inside hostile states. For this
population, loss of content confidentiality, of metadata, or of deniability can lead to
imprisonment, torture, or death. Safety is the top design constraint and overrides
performance, scale, simplicity, and aesthetic fidelity wherever they conflict.

False confidence is the failure mode that gets people hurt. Every property below is
stated with its honest limit. See [honest-limits.md](honest-limits.md) for the
bright-line limits as they must appear to users.

## 1. Property set (what we commit to and test against)

We do **not** claim information-theoretic / one-time-pad secrecy. A one-time-pad content
mode protects only content confidentiality, only with truly random single-use keys as
long as the message, and would still leave metadata and endpoints exposed. It buys little
here over modern authenticated encryption with forward secrecy, at large operational cost.
Instead we commit to, and test against, this set:

| ID | Property | Mechanism (target) | Honest limit |
|----|----------|--------------------|--------------|
| P1 | Content security: confidentiality + integrity, forward secrecy, post-compromise security | MLS / TreeKEM (RFC 9420) for both 1:1 and groups; classical X25519 ciphersuite (PQ-hybrid pending, see P-note) | Cannot protect content on an implanted or compelled-unlocked endpoint; **no PQ yet** so wire captures are not harvest-now-decrypt-later safe |
| P2 | Metadata resistance: who-talks-to-whom, when, how much is hidden from server and in-country network | Sealed sender, fixed-size padding, no stored graph, traffic shaping | SNI exposes destination domain; single origin enumerates the user set |
| P3 | Endpoint risk minimization (web-only) | No plaintext at rest (IndexedDB crypto-erase), no plaintext in browser caches, excluded from browser sync | A seized-unlocked or implanted device is not protected, only bounded; the browser/OS are the trusted base |
| P4 | Coercion resistance | Duress passphrase, decoy mode, panic wipe | **No deniable authentication** (accepted, ADR-006): MLS signs messages with the sender's key, which can serve as transferable proof of authorship. Plus: a user can still be physically coerced |
| P5 | Unobservability / censorship resistance | Innocuous rotating domain, decoy site, common-stack TLS fingerprint, traffic shaping | "Hard to detect" is not "undetectable"; destination domain is visible |
| P6 | Untrusted server | Ciphertext only, sealed sender, no PII, no persistence, no logs | A powered-on seized server may yield in-flight ciphertext from RAM (still opaque) |
| P7 | Forensic unrecoverability | Permanent ciphertext opacity (incl. PQ), crypto-erase (destroy keys, not bytes) | Does not cover implanted / unlocked-seized / screenshotted / photographed endpoints |

## 2. Adversary model (assume all of this)

A hostile state that:

- Controls or compels the in-country network (ISPs, telecoms, IXPs): full passive
  capture, active interference, TLS/IP metadata, timing and volume analysis, long-term
  retention with retrospective correlation, and the ability to block or throttle.
- Can compel any company or infrastructure in its jurisdiction, and can obtain or coerce
  a trusted CA for active man-in-the-middle.
- Seizes devices at checkpoints, borders, and on arrest, and compels unlock by law or force.
- Deploys targeted endpoint malware (zero-click implants of the Pegasus / Predator class)
  against high-value targets.
- Coerces users and their contacts directly.
- Correlates across SIM registration, purchase records, CCTV / face recognition, app-store records.
- Retains captured ciphertext indefinitely for later decryption, including with a future
  quantum computer (harvest-now-decrypt-later). Treat today's wire captures as readable years out.
- Is patient and well resourced.

## 3. How each property is engineered (§5)

### P1 Content security (§5.1)
- Both 1:1 and groups: MLS / TreeKEM (RFC 9420) via OpenMLS-WASM. A 1:1 is a 2-member group.
  Forward secrecy + post-compromise security; rekey on membership change.
- **No deniable authentication** (ADR-006, accepted): MLS signs application messages with the
  sender's signature key. This is recorded under P4 as an accepted weakening. Do not claim it.
- PQ-hybrid (P-note): the target is the MLS X-Wing ciphersuite (ML-KEM-768 + X25519). It is
  DEFINED in OpenMLS 0.6 but the RustCrypto provider does not implement the X-Wing KEM, so it is
  **not running yet** (verified; ADR-007). M1 ships classical X25519. Until a provider supports
  X-Wing, captured ciphertext is NOT protected against future quantum decryption. Do not claim PQ.
- Primitives via audited libraries only (OpenMLS, libsodium). No hand-rolled ratchets.
- **Decided: Gate 4 (MLS everywhere), Gate 14 (PQ-hybrid). Built at M1 (see ADR-006/007).**

### P2 Metadata resistance (§5.2)
- Server layer: sealed sender, no stored contact graph, no routing pairs in logs,
  fixed-size padding, per-message TTL with delete-on-delivery.
- Network layer: plausibility + reachability, not destination hiding (no ECH). See P5.
- Residual: SNI shows the destination domain; the single origin enumerates the user set.

### P3 Endpoint risk minimization (§5.4) — web-only reframe
This build targets a browser PWA only (no phone client). The phone-platform mechanisms in the
brief (secure element / Keystore / Keychain, locked-screen notification suppression, OS backup
exclusion) do not apply; their web equivalents do:
- No plaintext at rest: local store in IndexedDB, encrypted under an Argon2id-derived key,
  unlocked into memory only.
- Keys held as WebCrypto non-extractable keys, wrapped by a WebAuthn-PRF or Argon2id key (ADR-008).
  There is no general-purpose hardware secure element available to a web page; this is weaker
  than a phone secure element, and that gap is stated in honest-limits.
- Keep plaintext out of browser caches and `localStorage`; clear clipboard use; exclude app data
  from browser sync/profile sync where the platform allows.
- **Built at M4.** The phone-specific items are out of scope per the web-only directive.

### P4 Coercion resistance (§5.5)
- **No deniable authentication** (ADR-006, accepted). DEAD DROP does not provide the
  "cannot be cryptographically proven to have authored this" property. Coercion resistance
  rests on the controls below, not on deniability.
- Duress passphrase opening a decoy account or triggering silent wipe.
- Decoy / hidden mode; panic wipe. **Built at M4.**

### P5 Unobservability / reachability (§5.3)
- Self-hosted innocuous domain that rotates on a non-predictable schedule.
- Probe-resistant decoy site (= the cover production's promo site, §A.7).
- Common-stack TLS + server fingerprint (uTLS-style client JA3/JA4).
- Disposable rotating front, never the operator's origin IP.
- Rotation-distribution channel the adversary cannot subscribe to or predict (the crux).
- Traffic shaping (fixed buckets, smoothed timing). **Built at M3. Decision: Gate 5 (owner-set), Gate 13.**

### P6 Untrusted server (§5.9)
- Ciphertext only, sealed sender, no PII, no graph, no persistence beyond in-memory TTL, no logs.
- No long-term server secret that retroactively decrypts traffic.
- Seizure test is an acceptance criterion.

### P7 Forensic unrecoverability (§5.12)
- In transit: captured ciphertext stays permanently opaque (P1 + PQ-hybrid).
- On server: in-memory only, delete-on-delivery, mlock, no swap, no core dumps, zeroize buffers.
- At rest on endpoints: **crypto-erase, never overwrite-delete** (NIST SP 800-88: flash
  controllers may not erase physical cells). Per-message keys destroyed on expiry; master
  store key destroyed by panic wipe.
- Residue and metadata: kept out of OS caches; contact list and conversation index live
  only inside the crypto-erasable store.

## 4. Architecture invariant that makes P1/P6 true by construction

**Payloads are end-to-end ciphertext. The gateway, the in-process bus, and every server
tier only ever carry opaque blobs and never hold decryption keys.** The server cannot read
messages because it never has the keys, regardless of configuration or who operates it.
mTLS between any internal hops is defense in depth; the real guarantee is payload encryption.

See [architecture.md](architecture.md) for the reduced single-vhost topology and
[decisions.md](decisions.md) for the gate decisions that shaped it.
