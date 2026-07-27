/**
 * At-rest per-message crypto-erase (M2 Layer 2, ADR-015).
 *
 * Each stored readable message is sealed under its OWN random per-message key (PMK); the PMK
 * is wrapped under the Master Store Key (MSK). Deletion means destroying the wrapped PMK, never
 * overwriting bytes (flash caveat, NIST SP 800-88): once the wrapped PMK is gone, the stored
 * ciphertext decrypts to nothing even though the MSK and the MLS session still exist. That is
 * what makes an expired or burned message forensically unrecoverable on a cooperating,
 * uncompromised device (threat-model P7).
 *
 * KEY INVARIANT (enforced by a test): the PMK is fresh `getRandomValues` ONLY. It is never
 * derived from the MSK, the messageId, or any MLS secret. If it were, deleting the wrapped PMK
 * would not actually erase the message (the MSK could re-derive it). Do not change this.
 *
 * The at-rest AEAD (AES-256-GCM) is INDEPENDENT of the MLS ciphersuite (ADR-007), so MLS can
 * migrate to a post-quantum suite without touching stored history.
 *
 * HONEST LIMITS: this protects the STORED copy on a cooperating device. It cannot reach a
 * screenshot, a photo, or a copy the OS/GPU/accessibility layer made while a message was on
 * screen, and heap zeroize of plaintext is best-effort. The real defense is destroy-the-key.
 */

import type { Lifetime } from './index.js';

/** Persisted record for one message. `ciphertext` is inert once `wrappedPmk` is destroyed. */
export interface VaultRecord {
  readonly messageId: string;
  readonly conversationId: string;
  readonly direction: 'in' | 'out';
  readonly lifetimeKind: Lifetime['kind'];
  /** Absolute expiry in epoch-ms for an ARMED `duration` message; null when not armed (the timer
   * has not started, e.g. an inbound message the recipient has not viewed yet) or for the
   * burn-on-read / until-revoked kinds. */
  readonly expiresAtMs: number | null;
  /** The duration in seconds for a `duration` message, retained so its timer can be started on
   * first view (hold-until-seen). null for the other kinds. */
  readonly durationSeconds: number | null;
  /** Epoch-ms the record was stored, for chronological ordering of a conversation's history. */
  readonly storedAtMs: number;
  /** True once a burn-on-read message has been opened (the read latch). */
  readonly read: boolean;
  /** True when OUR OWN account authored this message: every outbound record, plus an inbound copy
   * synced from a sibling device (the MLS layer authenticated its sender as one of our devices; a
   * peer cannot forge that). Grants the revoke control on every device of the authoring account.
   * Absent on records stored before this field existed (fail-closed: treated as not own-authored). */
  readonly ownAuthored?: boolean;
  readonly nonce: Uint8Array;
  readonly ciphertext: Uint8Array;
  /** AES-256-GCM(MSK, pmkBytes). The ONLY persisted copy of the PMK. Delete to crypto-erase. */
  readonly wrappedPmk: Uint8Array;
  readonly wrapNonce: Uint8Array;
}

/** Async store the records live in. IndexedDB in production (inside the owning Worker); an
 * in-memory fake in tests. The store never holds plaintext or unwrapped keys. */
export interface KeyvaultStore {
  get(messageId: string): Promise<VaultRecord | undefined>;
  put(record: VaultRecord): Promise<void>;
  delete(messageId: string): Promise<void>;
  list(): Promise<readonly VaultRecord[]>;
}

const AEAD = 'AES-GCM';

function randomBytes(n: number): Uint8Array {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}

/** Bind a record to its identity so a sealed payload cannot be transplanted to another record. */
function aad(messageId: string, conversationId: string, lifetimeKind: string): Uint8Array {
  return new TextEncoder().encode(`${messageId}|${conversationId}|${lifetimeKind}|${AEAD}`);
}

function expiryMs(lifetime: Lifetime, nowMs: number): number | null {
  return lifetime.kind === 'duration' ? nowMs + lifetime.seconds * 1000 : null;
}

/**
 * Seal a framed plaintext into a VaultRecord under a fresh PMK wrapped by the MSK.
 * `msk` is a non-extractable AES-GCM CryptoKey (derived elsewhere, ADR-015). The live PMK bytes
 * are zeroized before returning; only `wrappedPmk` persists.
 */
export async function seal(
  msk: CryptoKey,
  meta: {
    messageId: string;
    conversationId: string;
    direction: 'in' | 'out';
    lifetime: Lifetime;
    /** An INBOUND record whose MLS-authenticated sender is one of our own devices (a sibling's copy
     * of a message we authored). Outbound records are own-authored regardless of this flag. */
    ownAuthored?: boolean;
  },
  framedPlaintext: Uint8Array,
  nowMs: number,
  /** When false, a duration message is stored UNARMED (expiresAtMs null): its countdown has not
   * started, so it persists until armed on first view (hold-until-seen). Defaults to armed. */
  arm = true,
): Promise<VaultRecord> {
  const pmkBytes = randomBytes(32); // PMK is random ONLY (invariant).
  const pmk = await crypto.subtle.importKey('raw', new Uint8Array(pmkBytes), AEAD, true, [
    'encrypt',
  ]);
  const nonce = randomBytes(12);
  const additional = aad(meta.messageId, meta.conversationId, meta.lifetime.kind);
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: AEAD, iv: new Uint8Array(nonce), additionalData: new Uint8Array(additional) },
      pmk,
      new Uint8Array(framedPlaintext),
    ),
  );

  const wrapNonce = randomBytes(12);
  const wrappedPmk = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: AEAD, iv: new Uint8Array(wrapNonce), additionalData: new Uint8Array(additional) },
      msk,
      new Uint8Array(pmkBytes),
    ),
  );
  pmkBytes.fill(0); // best-effort zeroize the live PMK; wrappedPmk is now the sole copy.

  return {
    messageId: meta.messageId,
    conversationId: meta.conversationId,
    direction: meta.direction,
    lifetimeKind: meta.lifetime.kind,
    expiresAtMs: arm ? expiryMs(meta.lifetime, nowMs) : null,
    durationSeconds: meta.lifetime.kind === 'duration' ? meta.lifetime.seconds : null,
    storedAtMs: nowMs,
    read: false,
    ownAuthored: meta.direction === 'out' || meta.ownAuthored === true,
    nonce,
    ciphertext,
    wrappedPmk,
    wrapNonce,
  };
}

/** Start an unarmed duration message's countdown from `nowMs` (hold-until-seen first view). Returns
 * the record unchanged if it is already armed or is not a duration message. */
export function armRecord(record: VaultRecord, nowMs: number): VaultRecord {
  if (record.lifetimeKind !== 'duration' || record.expiresAtMs !== null || record.durationSeconds === null) {
    return record;
  }
  return { ...record, expiresAtMs: nowMs + record.durationSeconds * 1000 };
}

/** Open a record to its framed plaintext. Throws if the wrapped PMK is gone (crypto-erased). */
export async function open(msk: CryptoKey, record: VaultRecord): Promise<Uint8Array> {
  const additional = aad(record.messageId, record.conversationId, record.lifetimeKind);
  const pmkBytes = new Uint8Array(
    await crypto.subtle.decrypt(
      { name: AEAD, iv: new Uint8Array(record.wrapNonce), additionalData: new Uint8Array(additional) },
      msk,
      new Uint8Array(record.wrappedPmk),
    ),
  );
  const pmk = await crypto.subtle.importKey('raw', new Uint8Array(pmkBytes), AEAD, false, [
    'decrypt',
  ]);
  pmkBytes.fill(0);
  const framed = new Uint8Array(
    await crypto.subtle.decrypt(
      { name: AEAD, iv: new Uint8Array(record.nonce), additionalData: new Uint8Array(additional) },
      pmk,
      new Uint8Array(record.ciphertext),
    ),
  );
  return framed;
}

/** Crypto-erase one message: destroy the wrapped PMK (by deleting the record). Idempotent. */
export async function cryptoErase(store: KeyvaultStore, messageId: string): Promise<void> {
  await store.delete(messageId);
}

/** Seal arbitrary bytes under the MSK with a string AAD. Output is `nonce || ciphertext`. Used
 * for at-rest metadata (channel summaries, contact graph) that must not be plaintext on disk. */
export async function sealUnder(msk: CryptoKey, plaintext: Uint8Array, aad: string): Promise<Uint8Array> {
  const nonce = randomBytes(12);
  const additional = new TextEncoder().encode(aad);
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: AEAD, iv: new Uint8Array(nonce), additionalData: new Uint8Array(additional) },
      msk,
      new Uint8Array(plaintext),
    ),
  );
  const out = new Uint8Array(nonce.length + ciphertext.length);
  out.set(nonce);
  out.set(ciphertext, nonce.length);
  return out;
}

/** Open a `nonce || ciphertext` blob sealed by `sealUnder`. Throws on the wrong key, tampering,
 * or a mismatched AAD. */
export async function openUnder(msk: CryptoKey, sealed: Uint8Array, aad: string): Promise<Uint8Array> {
  if (sealed.length < 12) {
    throw new Error('sealed blob too short');
  }
  const nonce = sealed.slice(0, 12);
  const ciphertext = sealed.slice(12);
  const additional = new TextEncoder().encode(aad);
  return new Uint8Array(
    await crypto.subtle.decrypt(
      { name: AEAD, iv: new Uint8Array(nonce), additionalData: new Uint8Array(additional) },
      msk,
      new Uint8Array(ciphertext),
    ),
  );
}

/**
 * Import raw MSK bytes (an Argon2id output from the wasm core) as a non-extractable AES-256-GCM
 * key, then best-effort zeroize the source bytes. Honest limit (ADR-015): the key still lives in
 * the non-extractable CryptoKey and possibly in copies the runtime made; there is no hardware
 * enclave in a browser, so this is best-effort, and the real defense is destroying the key.
 */
export async function importMsk(rawKey: Uint8Array): Promise<CryptoKey> {
  const key = await crypto.subtle.importKey('raw', new Uint8Array(rawKey), AEAD, false, [
    'encrypt',
    'decrypt',
  ]);
  rawKey.fill(0);
  return key;
}
