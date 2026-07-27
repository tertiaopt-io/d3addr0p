# Decision Log (ADRs)

Records the Decision Gates from brief §9 as they are decided. Each gate stays here with its
decision, the date, and the reasoning. Deferred gates are listed so the owner knows what is
still owed and at which milestone.

Format: gate, status, decision, why, residual / honest limit.

---

## ADR-022 — Multi-device identities + device management (single-active routing)
- **Status:** Decided and implemented (2026-06-27). Server: PHPStan-max clean, PHPUnit 11 tests / 80
  assertions (device registry, two-factor enroll, idempotency, foreign-key rejection, revoke +
  session-cut + directory fallback, active-device routing, burned-key, legacy migration). Client:
  auth.ts 19 tests, app.flow 10 tests (enroll-on-login, multi-device notice, Settings list + revoke).
  Owner chose **C now, then B** at the routing decision gate. Informed by a 5-agent design analysis
  (crypto feasibility / server / UX / adversarial security / synthesis).
- **Context / the fork:** the owner asked for identities that work across devices plus a settings
  screen to list and revoke devices. A 4-analyst review found the obvious implementation is a trap.
  The verified crypto core is pervasively pairwise (`peer_signature_key()` errs unless exactly one
  peer; the sealed-sender mailbox derives from a single key; `decrypt()` ingests only application
  messages, not membership commits; the §5.7 cross-check and the key-change alert at handshake.ts:72
  assume one key). Three routing models were weighed: (A) per-device fan-out, (B) full multi-device
  MLS group, (C) single active device.
- **Decision:** ship **model C** as the MVP and build **B** as a later, separately-audited milestone.
  - Common groundwork (built now): the server gains a `devices` table (per-device public key, opaque
    device id, added/last-seen, revoked tombstone; a globally-unique device key that stays burned on
    revoke) and three authenticated endpoints — `add-device` (two-factor: session token AND the
    re-presented auth secret, so a stolen token alone cannot enroll), `list-devices`, `revoke-device`
    (burns the key and deletes that device''s sessions). `register` now creates the account and its
    first device atomically; `lookup` returns the active device set plus an `activeDeviceKey`. The
    client mints a per-device identity (its existing durable MLS signer), enrolls it on login
    (idempotent), and adds a Settings -> Devices screen (list, mark this device, inline-confirm
    revoke). A migration backfills the old single `identity_key` into a first device and upgrades the
    `sessions` table in place.
  - Routing (C): `lookup` returns `activeDeviceKey` = the most-recently-seen active device, and the
    client routes there over the UNCHANGED pairwise path. The crypto core, the TOFU pin, the
    one-peer cross-check, and the key-change alert all keep working verbatim. A login makes this
    device the active receiver and others go dark; the client surfaces this loudly (a channels-screen
    note when the account has more than one device).
- **Why C over A and B:** A is rejected for this threat model — adding a device key triggers no
  key-change alert (handshake.ts:72 only fires on mutation of an already-pinned key), so a coerced or
  leaked passphrase, or a compelled server, becomes a SILENT EXTRA READER for every correspondent;
  its app-layer revoke is not forward-secure. B is the right long-term model (an MLS Remove rotates
  group secrets, the only cryptographically real revoke) but is XL: it rewrites the security-critical
  mailbox derivation and key-substitution cross-check for N members (mandatory re-audit), collides
  with the ADR-015 in-memory anti-replay residual under membership churn, and needs a signed
  device-authorization root + roster-acknowledgement UX to be safe. C delivers the literal ask (list +
  revoke) with zero crypto-core change and every MITM defense intact, and keeps every routing option
  open (the only per-model server difference is the optional `activeDeviceKey` field).
- **Residual / honest limit:** the directory now reveals each account''s active device count and keys
  to an authorized looker-up. **Anyone with the passphrase can add a device** (no signed device-auth
  yet — a prerequisite for B). **Revoke is a directory + auth control, not a cryptographic exclusion**
  in C: it stops new messages and new sign-ins and cuts sessions, but does not rotate any conversation
  secret or wipe an already-delivered message. **C is single-receiver:** only the most-recently-active
  device receives, so a device that has gone quiet may look reachable; this is surfaced in the UI.
  Two cross-cutting fixes (signed device authorization; genuine out-of-band fingerprint verification)
  are prerequisites for B and improve the single-device posture too. All documented in honest-limits.

## ADR-021 — Server account registry + username->identity directory
- **Status:** Decided and implemented (2026-06-27). Control-plane is PHPStan-max clean, PHPUnit (5
  tests) green, and HTTP-smoke verified (register/login/lookup 8/8). Client is unit-tested (auth.ts
  14 tests) and DOM-flow-tested (app.flow 7 tests: register, duplicate rejection + rollback, login
  gate, directory lookup). Owner-approved via the three-way decision gate (server-side accounts /
  salted Argon2id verifier / message-by-username).
- **Decision:** add a minimal **control-plane** (PHP 8, SQLite, `DeadDrop\ControlPlane\`) that owns
  three endpoints behind the Apache `/api` proxy, separate from the keyless message gateway:
  `POST /api/register {usernameHash, authSecret, identityKey}` (201 + session token, or **409 when
  the username is already taken**), `POST /api/login {usernameHash, authSecret}` (200 + token / 401),
  and `POST /api/lookup {token, usernameHash}` (200 `{identityKey}` / 404), the username->identity
  directory used to open a channel by handle. Uniqueness is enforced atomically by the username-hash
  primary key (`INSERT OR IGNORE` + `rowCount`), so a duplicate is denied with no read-then-write
  race. **The server never sees a plaintext username or passphrase:** the client pre-hashes both with
  domain-tagged SHA-256 (`usernameHash`, `authSecret`) and the server stores only
  `password_hash(authSecret, ARGON2ID)` plus the public identity key. The directory entry is the
  account's MLS Ed25519 signature key (64 hex). Registration creates the local vault + durable
  identity first, then registers; a 409 rolls the local vault back (`discardAccount`) so a seized
  device keeps no orphaned account. Same-origin `/api` only (token in the JSON body, never a cookie,
  so there is no ambient authority for CSRF to ride); `§5.10` logs-nothing still holds (no access log).
- **Why:** the owner asked for a real registration/authentication workflow that denies a username
  already taken, which is impossible to guarantee with purely local accounts (two devices cannot see
  each other's choices). A small server-side registry is the least-server way to get global
  uniqueness and lookup-by-handle, while keeping every secret client-side and the gateway keyless.
- **Residual / honest limit:** the server now learns the **set of account username hashes, their
  Argon2id verifiers, and their identity keys** (it still never learns the plaintext handle, the
  passphrase, or any message). A hostile or compromised server can (a) enumerate or block accounts and
  (b) **return the wrong identity key for a looked-up username (a MITM substitution)** — so the
  out-of-band fingerprint check at channel setup remains the trust anchor (TOFU, ADR-009). Accounts
  are **unrecoverable** (no reset, no escrow) and **effectively single-device** (the identity lives
  only on the registering device; logging in elsewhere authenticates but mints a new device identity
  that does not match the directory). These are documented in honest-limits and the runbook.

## ADR-017 — M4: live gateway transport wiring (controller ↔ gateway)
- **Status:** Decided and implemented (2026-06-27). Verified in a real browser against the running
  Go gateway over real WebSockets (full wasm handshake + protobuf + relay, both sides reach secure,
  message decrypts correctly).
- **Decision:** The owning Web Worker hosts the live transport: it holds the single WebSocket
  `Transport`, the per-conversation `Session` plus its wasm `Conversation`, and turns inbound gateway
  frames into push events to the main thread. The orchestration lives in a gate-clean, unit-tested
  module (`client/src/live.ts`, `LiveChannel`); its browser-only dependencies (the WebSocket
  `connect`, the wasm `Conversation` factory, the `pushEvent` sink) are injected by the worker, so
  no wasm or socket code leaks into the gated controller.
- **Bootstrap routing (sealed sender + TOFU):** before a group exists there is no epoch mailbox, so
  each device subscribes to a stable bootstrap routing key equal to its signature public key, and
  advertises it in a copy-pasteable contact string `deaddrop:1:<routingKeyHex>:<sigKeyHex>`. The
  initiator addresses its offer to the peer's bootstrap key; the accepter addresses its accept back
  to the offerer's signature key carried in the offer; on establishment both sides re-subscribe to
  the epoch-rotating `selfMailbox()`. The accepter's key is pinned (TOFU) against the contact used.
- **Wire codec packaging:** the generated protobuf wire types depend on `@bufbuild/protobuf`, and
  the app is served as raw ES modules with no bundler. Only the gate-excluded adapter glue
  (`wsadapter.ts` + generated wire + the protobuf runtime) is bundled into one self-contained ESM
  file (`esbuild`, `dist/wsadapter.bundle.js`) that the worker imports; the app modules stay raw.
- **Why:** keeps the sole-writer / sole-key-holder property (live crypto runs in the worker), keeps
  the controller gate-clean, and confines the one non-strict dependency (codegen + protobuf runtime)
  to a single bundled artifact at the existing gate boundary.
- **Residual / honest limit (sealed sender, bootstrap phase):** because the bootstrap routing key IS
  the signature identity key, during the handshake the gateway can see that a party subscribed to a
  given identity key received an offer addressed to it. Sealed-sender unlinkability is therefore
  weaker for the initial contact than in steady state, where routing keys are epoch-derived and
  opaque. Stated, and a candidate for a blinded bootstrap mailbox in a later milestone. This rides
  on top of the ADR-009 trust-on-first-use residual (no out-of-band verification).
- **Residual (persistence):** resolved by ADR-018 (live messages are now persisted to the
  crypto-erasable keyvault). Live messaging still requires the owning worker; the main-thread
  fallback controller rejects the live ops with a clear message.

## ADR-018 — Live-message persistence + hold-until-seen
- **Status:** Decided and implemented (2026-06-27). Verified in a real browser: a received message
  persists to the keyvault, survives a reload, and starts its countdown only when the conversation
  is opened.
- **Decision (two parts):**
  1. **Persistence.** Sent and received live messages are sealed into the crypto-erasable keyvault
     (per-message key wrapped under the MSK, ADR-015), keyed by conversation, ordered by a stored
     timestamp. A conversation view is always rebuilt from the keyvault (openChannel), so a reload
     re-renders history and revoke/expiry still apply. The owning worker provides the lifetime
     manager's timer hooks (setTimeout) and forwards erasures to the UI as an `erased` event.
  2. **Hold-until-seen.** A received message does not start its destruction countdown until the
     recipient views it. Inbound duration messages are stored UNARMED (`expiresAtMs` null, the
     duration retained in `durationSeconds`); opening the conversation arms them from that moment
     (armOnView). Outbound messages arm on send (we authored them). At the network layer the
     recipient now connects and subscribes on UNLOCK (logging in), and an inbound delivery is acked
     to the gateway only after it is durably stored, so the gateway keeps holding it (within its
     TTL) until the recipient is logged in and has saved it.
- **Why:** fulfils the owner's request that a message persist and not vanish before the recipient
  has actually seen it, while keeping the destroy-the-key crypto-erase invariant for expiry/revoke.
- **Residual / honest limit (durable cross-login offline delivery is NOT yet delivered):** the
  "drop someone your contact, they retrieve it days later from a fresh session" promise needs three
  things this build does not have: (a) a STABLE identity, but each connect mints a fresh wasm
  signature key, so a device's contact/mailbox changes every login; (b) persisted MLS group state to
  reconstruct the epoch mailbox and decrypt after a reload (ADR-016 deferred this; OpenMLS does not
  persist the SignatureKeyPair); (c) a durable gateway, but the gateway is RAM-only by design
  (§5.10), so a held message is lost if the gateway restarts and is bounded by its TTL (1 to 7 days).
  So today hold-until-seen works within a live session and the gateway's hold window, not across a
  fresh-session re-login days later. Closing that is a separate gate: persistent MLS identity + an
  encrypting StorageProvider in the Rust core (a crypto-core change), plus a decision on gateway
  durability that conflicts with the no-disk design.

## ADR-020 — Username + passphrase login (per-account vaults)
- **Status:** Decided and implemented (2026-06-27); deployed and browser-verified.
- **Decision:** Login takes a **username and a passphrase**. The normalized (trim + lowercase)
  username is SHA-256 hashed to an account id that keys a per-account MSK vault record
  (`msk:<accountId>`) and the per-account identity record (`self:<accountId>`), and it is also bound
  into the Argon2id input (`username passphrase`) so the derived key depends on both. A new
  username+passphrase creates an account on first login; the same pair restores it. Several accounts
  coexist on one device, fully isolated: a record that fails to decrypt under the current account's
  MSK is skipped (listChannels / openChannel), and panic-wipe clears every account's MSK wrap.
- **Why:** the standard login model real users expect, it lets multiple people share a browser with
  isolated data, and binding the username into the KDF raises the at-rest brute-force floor above
  passphrase-only (ADR-015 residual) by the username's entropy.
- **Residual / honest limit:** because the account record is keyed by the username hash, the username
  functions as part of the secret (it must be typed exactly, case aside) rather than a displayed
  handle; and a guessable username adds little entropy, so the passphrase remains the real floor.

## ADR-019 — Persistent MLS identity (stable contact) + the session-resume gate
- **Status:** Decided and implemented (2026-06-27) for the IDENTITY layer; verified in a real
  browser (three fresh controllers over the same store + passphrase derive the same contact). The
  full session-resume layer is gated below.
- **Empirical findings (4 new crypto probe tests, all passing).** The crypto core already shipped
  `exportSealed`/`fromSealed` (M2 Layer 1, ADR-015): full MLS state sealed under the MSK. Probing it:
  1. A reloaded session KEEPS RECEIVING new messages from the peer.
  2. A reloaded session computes the SAME opaque mailbox (so a reloaded device could retrieve
     messages held for it).
  3. Identity (the signer) is preserved across reload, so it can still sign and send.
  4. Replay protection is LOST across reload: a message decrypted before the snapshot decrypts
     again afterward. This is exactly the ADR-015 accepted forward-secrecy residual (the anti-replay
     guard is in memory, not in the storage map). It is now pinned by a regression test that flips
     to celebrate the day an upstream OpenMLS fix lands.
- **Decision (Layer 1, done): persist only the identity.** On login the owning worker restores our
  long-lived signer-bearing Conversation from an MSK-sealed `self` record (or creates and persists
  one on first run), so a device's contact string and bootstrap mailbox are STABLE across logins.
  The worker keeps the raw MSK (it is the sole holder) to drive the wasm seal/restore. Crucially,
  Layer 1 persists the signer BEFORE any group forms, so NO group/ratchet keys are stored and the
  forward-secrecy residual above does NOT apply.
- **Why stop at identity:** persisting GROUP state (to resume a conversation and reconstruct its
  epoch mailbox after a reload) (a) activates the ADR-015 forward-secrecy residual on this device,
  and (b) in the current one-Conversation-per-identity model would conflate the identity with a
  single group: a restored conversation-bearing Conversation cannot also host a NEW conversation
  (a 1:1 MLS group cannot take a second peer, and a fresh group needs a fresh signer = a new
  identity). So useful multi-conversation resume needs the Rust core to separate the long-lived
  signer from per-conversation groups (a stable identity that spawns several resumable groups).
- **Gate (Layer 2, deferred for owner sign-off):** separate signer from group in the crypto core,
  add a `Session.resume` path (the handshake state machine already supports a direct
  established-state entry), re-persist group state after establishment and each message, and restore
  + resume conversations on login. This delivers durable cross-login message retrieval but turns on
  the ADR-015 forward-secrecy residual; that is the owner's call to make explicitly.

## ADR-015 — Gate 15: at-rest destruction mechanism (crypto-erase) + M2 custody
- **Status:** Decided (2026-06-26), grounded in a design+adversarial-review workflow.
- **Decision:** Crypto-erase under one destroyable Master Store Key (MSK). Two at-rest layers:
  Layer 1 = MLS session state via a custom AEAD-encrypting OpenMLS StorageProvider; Layer 2 =
  per-message readable history, each message sealed under its own random per-message key (PMK)
  wrapped by the MSK. Deletion = destroy a key (delete the wrapped PMK / the MSK wrap), never
  byte-overwrite (flash caveat, NIST SP 800-88). At-rest AEAD (AES-256-GCM / XChaCha20) is
  INDEPENDENT of the MLS ciphersuite.
- **Owner choices:**
  - **Custody = hybrid:** persisted-wrapped MSK as the default (durable recognition + panic
    lever), plus an opt-in per-session ephemeral/burner mode (memory-only MSK, persists nothing).
  - **Derivation = passphrase-only Argon2id** (no WebAuthn-PRF). **Accepted residual:** a
    powered-off disk image permits an offline Argon2id-bounded brute-force of the MSK wrap, so
    passphrase strength is the at-rest security floor. Stated to users (honest-limits).
  - **FS residual = accepted, not rotation-fixed.** No mandatory epoch rotation on suspend.
    **Accepted residual:** OpenMLS 0.6 never persists the advanced receive ratchet, and the
    anti-replay guard is itself a disk record, so an adversary who images a powered-off disk,
    rolls the guard back, and replays retained wire ciphertext can re-decrypt already-read
    messages. Bounded by the per-message PMK layer for displayed history; tracked against an
    upstream OpenMLS receive-ratchet persistence API. Stated to users.
- **Engineering resolutions (not gated):** OpenMLS + IndexedDB run in a single owning Web
  Worker (resolves the sync StorageProvider trait vs async IndexedDB mismatch AND multi-tab
  races: one sole writer). PMK is `getRandomValues` only, enforced by a test (never derived
  from MSK/messageId/MLS secrets), so per-message erase cannot be silently downgraded. Burn-on-
  read destroys the wrapped PMK in the same IndexedDB txn before display (fail-closed).
- **Honest limits (in copy):** crypto-erase is key-destruction not byte-overwrite; burn/expiry
  cover only the cooperating uncompromised device (not screenshots/photos/OS-GPU-accessibility
  copies); the browser/OS are the trusted base; heap zeroize is best-effort, the real defense is
  encrypt-under-destroyable-key.
- **Build order:** Layer 2 (keyvault + lifetime + burn) first (the user-facing §3.2 feature,
  fully testable with WebCrypto), then Layer 1 (Rust encrypting StorageProvider + Worker +
  IndexedDB + Argon2id wiring), then revoke. Panic-wipe UX, duress/decoy, and the ephemeral-mode
  toggle complete at M4 (Gate 15's stated milestone).
- **Adversarial review hardening applied (both reviewers: sound):** Argon2id uses explicit
  pinned params (64 MiB, 3 passes, not library defaults), with a param-drift test, since this is
  the sole passphrase-only at-rest barrier; the at-rest AEAD binds a format-version byte as AAD
  (versioning hook); the sealed-container parser uses checked arithmetic and bounded allocation
  (wasm32 overflow safety); `wipe()` now reaches and drops the signing key (best-effort, foreign
  type not byte-scrubbable); `importMsk` zeroizes the raw key bytes after import. Open follow-ups
  for Layer 1's browser wiring: persist Argon2 {params, salt} beside the sealed blob for
  upgradability, and bind the salt as AAD.

## ADR-016 — wasm conversation Session API: in-memory only; persistence deferred to M2
- **Status:** Decided (2026-06-26), driven by an adversarial design review (2 critical findings each from a security and a correctness reviewer).
- **Decision:** The wasm `Conversation` (crypto/src/conversation.rs) and the TS `Session`
  (client/src/session.ts) are **in-memory only** in M1. NO `snapshot` / `from_snapshot` /
  IndexedDB persistence ships now. The live API is: new identity, mint KeyPackage, create+add
  (accepter), join-from-Welcome (offerer), encrypt, decrypt, peer-key cross-check, wipe.
- **Why (review findings, all verified against the OpenMLS 0.6 source):**
  1. `process_message` advances the receive ratchet **in memory only** and never writes it
     back to storage, so a storage snapshot would be stale, and a reload could re-derive keys
     for already-read messages (forward-secrecy break, P1/P7).
  2. OpenMLS never stores the `SignatureKeyPair`, so a reloaded session could not sign.
  3. A serialized snapshot is **plaintext private keys**; persisting it in M1 (before the M2
     encrypting StorageProvider exists) bakes plaintext keys at rest (P3/P7 violation).
  Deferring persistence to M2 fixes all three at once: an AEAD-encrypting StorageProvider
  under a destroyable master key (Argon2id / WebAuthn-PRF) gives crypto-erase, authenticity
  against tampered snapshots, and a correct place to flush the receive ratchet.
- **Other review fixes applied now:** (a) the TS `receiveMessage` cross-checks the peer key and
  **drops/zeroizes the plaintext rather than surfacing it** if the key changed (bounds MITM
  leakage to one un-returned decrypt); (b) `zeroize` added and `wipe()` scrubs the in-memory
  storage values. **Honest limits recorded:** the foreign `SignatureKeyPair` exposes no
  zeroizing API (dropped, not scrubbed), WASM heap zeroize is best-effort, and a consistent
  server-from-the-start MITM is not caught by the cross-check (ADR-009, no OOB).
- **Private-key custody:** all `Conversation` struct fields are private, so wasm-bindgen emits
  no getters; no private key material crosses the wasm boundary. Verified in the review.
- **Group roles:** the ACCEPTER creates the MLS group and emits the Welcome; the OFFERER joins.

## ADR-001 — Gate 3: realtime gateway + language tier
- **Status:** Decided (2026-06-26)
- **Decision:** PHP-FPM control plane (typed, PHPStan/Psalm max) + a single static Go
  gateway binary (`CGO_ENABLED=0`), run as a systemd service on the host, fronted by Apache
  `mod_proxy_wstunnel`.
- **Why:** Constraint is "entire stack runs on the operator's Virtualmin host," owner has
  root. OpenSwoole is out under a managed-host model (PECL root install, fights FPM). A
  static Go binary drops in as one daemon with no shared-lib deps. The earlier
  "Rust pairs with MLS libs" argument was discarded: MLS/Signal run entirely client-side
  (§4.5/§5.1), so the gateway language is independent of the crypto stack.
- **Residual:** Go gateway has a lower raw-throughput ceiling than Rust. Acceptable: scope
  is single-node (ADR-005), so HFT-grade tail latency is not a goal.

## ADR-002 — Gate 2: message bus
- **Status:** Decided (2026-06-26)
- **Decision:** In-process fan-out inside the Go gateway, exposed behind a NATS-style
  subject interface (`Bus`), so it can be externalized to a real NATS server later without
  touching call sites. No separate broker daemon now.
- **Why:** Single node, single gateway process (ADR-005). Nothing to cluster. A separate
  broker daemon would only add a second long-lived process to keep alive for no benefit.
  The NATS subject model is kept as the seam so the lift to a real cluster is mechanical.
- **Residual:** When the system outgrows one node, a real NATS/JetStream cluster (memory
  storage, per-message TTL) is the intended replacement. The `Bus` interface is the seam.

## ADR-003 — Wire schema format (§6)
- **Status:** Decided (2026-06-26)
- **Decision:** Protocol Buffers. One `.proto` is the single source of truth; codegen to
  Go (gateway), PHP (control plane), and TypeScript (client).
- **Why:** Compact binary helps fixed-bucket padding / traffic shaping at M3; mature codegen
  across all three tiers; strict typed bindings on every side.
- **Residual:** None material. The vhost constraint does not touch build-time codegen.

## ADR-004 — Gate 1: client distribution / form  (REVISED 2026-06-26)
- **Status:** Decided, revised (2026-06-26)
- **Decision:** A single web codebase delivered as a **hardened installable PWA for all
  users**, including the at-risk population. No phone apps; no separate packaged client.
- **Why:** Owner constraint is "web client, runs inside the Virtualmin vhost, no phone apps."
  At-risk users install the PWA: a signed service worker pins a reproducibly-built bundle,
  Subresource Integrity on assets, updates only on verified signature, and the bundle hash is
  verifiable out-of-band. This collapses most of the "server ships fresh code every load"
  risk without a native app.
- **Residual (must be in honest-limits copy):** This is below the §5.8 packaged-client ideal.
  First load is trust-on-first-use; the browser and OS are the trusted base; a browser can
  update a service worker; a compelled server is still the bundle's origin. The crypto
  choices (ADR-006/007/008) cannot fix a delivery-model compromise. State this plainly.
- **Supersedes:** the earlier "packaged client + lower-assurance web client" split.

## ADR-006 — Gate 4 + Gate 9: protocol + crypto core  (REVISED 2026-06-26)
- **Status:** Decided (2026-06-26). Residual 1 (deniability) explicitly ACCEPTED by owner.
- **Decision:** **OpenMLS (RFC 9420) compiled Rust→WASM** as the single client crypto core,
  used for **both 1:1 and groups**. A 1:1 conversation is a 2-member MLS group. This also
  decides **Gate 9: groups are in scope** (MLS-everywhere only makes sense if they are).
  Rejects the self-compiled-libsignal and vodozemac options.
- **Residual 1 disposition:** owner accepts the reduced deniability. P4 is therefore
  downgraded: DEAD DROP does **not** provide deniable authentication for 1:1 or groups. This
  is recorded as an accepted weakening in the threat model and stated in the honest-limits
  copy. It must not be described as a property the system provides.
- **Why:** One audited Rust→WASM library for every conversation size; TreeKEM gives FS + PCS;
  native path to groups (M7) without a second protocol; emerging PQ MLS ciphersuites.
- **Residual 1 (SAFETY — needs owner sign-off):** base MLS authenticates application messages
  with the sender's signature key, which is closer to a *transferable proof of authorship*
  than Signal's deniable MACs. This **weakens deniable authentication (P4 / §5.1)**, a property
  the brief made mandatory for coerced users. §A.4 says the safety-maximizing option wins, so
  this tradeoff must be explicitly accepted, or 1:1 uses Signal while MLS covers groups.
- **Residual 2 (PQ maturity):** PQ MLS ciphersuites are still emerging and less mature than
  libsignal's PQXDH, so ADR-007's "PQ from the start" is harder to hit cleanly on this core.
- **Build cost:** we own a non-official OpenMLS→WASM (wasm-pack) pipeline; consistent with the
  §5.8 reproducible-build commitment.

## ADR-006 (superseded note)
- The prior ADR-006 ("Full Signal 1:1") and the "M1 implementation blocker" below are
  superseded by the revised ADR-006 above, pending the Residual-1 confirmation.

## ADR-007 — Gate 14: post-quantum handshake
- **Status:** Decided; partially blocked at the provider layer (verified 2026-06-26).
- **Decision:** Hybrid classical + ML-KEM, via the MLS X-Wing ciphersuite
  (`MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519`, X-Wing = ML-KEM-768 + X25519). Never
  weaker than classical X25519; resists harvest-now-decrypt-later (§A.2).
- **Verified reality:** OpenMLS 0.6 DEFINES the X-Wing ciphersuite, but `openmls_rust_crypto`
  0.3 does NOT implement the X-Wing KEM at runtime (panics "XWingKemDraft1 is not supported by
  the RustCrypto provider"). So PQ-hybrid is **not yet runnable** with the default provider.
- **Disposition:** M1 ships the classical ciphersuite
  (`MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`). The crypto core is a one-line ciphersuite
  swap away from PQ once a provider implements X-Wing (newer `openmls_rust_crypto`, or a custom
  HPKE provider). Until then, the §A.2 harvest-now-decrypt-later protection is **not in place**;
  this is an open item, not a shipped property. State it honestly; do not claim PQ yet.
- **Note:** this is more concrete than the brief's "PQ MLS is emerging" — the ciphersuite
  exists in the spec layer; the gap is purely the RustCrypto provider's KEM implementation.

## ADR-008 — Gate 6: identity model + persistence
- **Status:** Decided (2026-06-26)
- **Decision:** Opaque public-key identity, generated client-side, no phone/email. **Persistent
  but crypto-erasable.** In-browser: a WebCrypto non-extractable identity key in IndexedDB,
  wrapped by a key derived from WebAuthn PRF (hardware-bound where available) with an
  Argon2id(WASM) passphrase fallback. Panic wipe clears IndexedDB and destroys the wrap.
- **Why:** Persistence enables durable recognition (a stated goal); crypto-erasability keeps
  panic-wipe and duress effective.
- **Residual:** Browser storage is weaker than a phone secure element (on-disk IndexedDB,
  browser caches, no general-purpose hardware decryption key). Below the §5.4 ideal; stated.

## ADR-009 — Gate 7: discovery / conversation setup  (REVISED 2026-06-26)
- **Status:** Decided, revised (2026-06-26). Web-only, no out-of-band verification "for now"
  (owner directive). The dropped property is recorded as an accepted residual below.
- **Decision:** Mandatory mutual key-exchange-and-accept before any message, performed
  **in-app only** (the keys are relayed through the service). No out-of-band verification, no
  QR, no phone, no in-person safety-number step in this build. Still no server-side address
  book; PSI contact discovery remains the discovery path.
- **Residual 1 (SAFETY, owner-accepted "for now"):** with accept no longer bound to an
  out-of-band channel, the handshake is **trust-on-first-use**. A hostile or compelled server
  (the threat model assumes both, plus a compellable CA) can MITM by giving each side its own
  keys, and the "accept" step then rubber-stamps the attacker's keys. The brief calls this
  "theater" (§5.6/§5.7). This weakens content security (P1) and authenticity against an active
  server adversary. Key-change alerts (M1) catch only changes *after* the first exchange.
  **Must be re-added before real at-risk users rely on the system**, and stated in honest-limits.
- **Residual 2:** PSI discovery is added metadata surface (§5.6), reviewed before real users.
- **Supersedes:** the earlier OOB-bound version of ADR-009.

## ADR-005 — Scope vs §8 scale-out
- **Status:** Decided (2026-06-26)
- **Decision:** A single node (the Virtualmin host) is the whole system. §8's 3-node
  vSphere cluster, Docker/k8s/Nomad orchestration, and the clustered bus are **out of scope**.
- **Why:** Owner: "vhost IS the whole system." M6 scale-out reduces to vertical scaling plus
  the rotating-front hop (§A.5).
- **Residual:** Horizontal scale-out is deferred, not designed-out: ADR-002's `Bus` seam and
  ADR-001's stateless-gateway shape keep the door open.

---

## Deferred gates (owed to owner, with target milestone)

| Gate | Topic | Target milestone | Recommendation to bring back |
|------|-------|------------------|------------------------------|
| 5 | Network reachability (owner-set) | M3 | Self-hosted rotating innocuous domain; sub-questions: rotation criteria + distribution channel. |
| 13 | Rotation-distribution channel + independent audit | M3 / M8 | Peer-propagation over verified channels; external crypto review before any real user. |
| 11 | Default appearance (owner-set: Assassins skin) | M5 | Skin is default; sub-question: discreet launcher icon/name. |
| 10 | Aesthetic effects layer | M5 | Subtle CRT/typewriter, off under reduced motion. |
| 12 | Hosting topology / operator linkage | M3 | Disposable rotating fronts; never terminate at-risk traffic on operator's residential IP. |
| 8 | Performance targets | M6 | Get concrete numbers (concurrent users, msgs/sec, fan-out, p99). |
| 9 | Groups in scope? | before M7 | Decide whether MLS group messaging is in this build. |

## M1 implementation blocker — browser crypto library (raised 2026-06-26)

ADR-006/007 commit to Full Signal + PQXDH **in a browser PWA**, but there is no official,
audited, browser-WASM Signal package on npm (libsignal officially targets iOS/Android/Node;
Signal Desktop runs the Node bindings inside Electron, not a browser). §5.1 forbids
hand-rolling and requires audited libraries. Concrete options for the browser:
- **Self-compile libsignal (Rust) to WASM** (wasm-pack). Gives Signal + PQXDH from the
  audited reference core in one dependency. Cost: we own a non-official build pipeline
  (reproducibility, upstream sync). Consistent with the §5.8 reproducible-build commitment.
  **Recommended.**
- **vodozemac (Matrix, Rust→WASM, audited).** Easy WASM, proven in browsers, Double Ratchet.
  But no post-quantum, so it fails ADR-007 (Gate 14) on its own.
- **OpenMLS→WASM.** Unifies 1:1 + groups with an emerging PQ-ciphersuite path, but MLS-for-1:1
  trades away some Signal deniability ergonomics and reopens Gate 4.
Decision needed before M1 crypto code.
