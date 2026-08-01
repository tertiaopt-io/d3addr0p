/**
 * IndexedDB persistence for the at-rest stores (M2, ADR-015).
 *
 * Three object stores in the `deaddrop` database, all holding ONLY ciphertext at rest:
 *   - `vault`     : the MSK-wrap record (the single panic lever).
 *   - `mls_state` : sealed MLS session state (Conversation.exportSealed bytes), per conversation.
 *   - `messages`  : per-message keyvault records (vault.ts VaultRecord), the readable history.
 *
 * Custody (Gate 15, ADR-015): a RANDOM Master Store Key (MSK) is wrapped under a passphrase-
 * derived KEK (Argon2id, from the wasm core) and stored in `vault`. Changing the passphrase
 * re-wraps the same MSK without re-encrypting data; a duress passphrase can wrap a decoy MSK
 * (M4). Panic wipe destroys the wrap first, so every other store is inert ciphertext under a
 * key that no longer exists.
 *
 * In production these run inside a single owning Web Worker (the sole writer, avoiding multi-tab
 * races and keeping the MSK and the wasm Conversation off the main thread). The adapters here are
 * plain and are tested against fake-indexeddb.
 */

import type { KeyvaultStore, VaultRecord } from './vault.js';

const DB_NAME = 'deaddrop';
const DB_VERSION = 4;
const STORE_VAULT = 'vault';
const STORE_MLS = 'mls_state';
const STORE_MESSAGES = 'messages';
const STORE_CHANNELS = 'channels';
const STORE_DEVICE_SETTINGS = 'device_settings';
const IDX_MESSAGES_BY_CONV = 'conversationId';

const WRAP_AEAD = 'AES-GCM';

export function openDeadDropDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE_VAULT)) {
        db.createObjectStore(STORE_VAULT, { keyPath: 'id' });
      }
      if (!db.objectStoreNames.contains(STORE_MLS)) {
        db.createObjectStore(STORE_MLS, { keyPath: 'conversationId' });
      }
      if (!db.objectStoreNames.contains(STORE_MESSAGES)) {
        db.createObjectStore(STORE_MESSAGES, { keyPath: 'messageId' });
      }
      if (!db.objectStoreNames.contains(STORE_CHANNELS)) {
        db.createObjectStore(STORE_CHANNELS, { keyPath: 'id' });
      }
      if (!db.objectStoreNames.contains(STORE_DEVICE_SETTINGS)) {
        db.createObjectStore(STORE_DEVICE_SETTINGS, { keyPath: 'id' });
      }
      // v4: an index over the (plaintext, non-sensitive) conversationId field so opening a chat reads
      // only ITS records instead of getAll-ing every message in every conversation. The upgrade
      // transaction is the only place an index can be added to an existing store.
      const messages = req.transaction?.objectStore(STORE_MESSAGES);
      if (messages !== undefined && !messages.indexNames.contains(IDX_MESSAGES_BY_CONV)) {
        messages.createIndex(IDX_MESSAGES_BY_CONV, 'conversationId', { unique: false });
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error('indexeddb open failed'));
  });
}

function reqDone<T>(req: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error('indexeddb request failed'));
  });
}

function randomBytes(n: number): Uint8Array {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}

/** How many memory-held records one conversation may accumulate in history-off mode before the oldest
 * are dropped. Inline images ride inside a record (32 KiB bucket budget), so this is a memory ceiling,
 * not a policy: the chat simply renders fewer entries once it is hit. */
const EPHEMERAL_PER_CONV_MAX = 500;

/** KeyvaultStore (vault.ts) backed by the `messages` object store, with an optional HISTORY-OFF mode.
 *
 * History-off does not SKIP writes, it REDIRECTS them to memory. Skipping would render an empty chat,
 * because every repaint re-reads this store (there is no in-memory view log), and it would strand the
 * lifetime, burn-on-read and revoke machinery that all operate through these same methods. Redirecting
 * keeps every one of those working while nothing new touches disk.
 *
 * The routing rule that matters: a `put` goes to memory only when the record is NOT already on disk.
 * A tombstone written by the burn latch, or a record armed on first view, MUST land back on disk when
 * that is where it came from; otherwise the latch is lost on reload and a burned message becomes
 * readable again. Every put in the codebase is preceded by a get, so the extra lookup is cheap and
 * only happens in this mode. */
export class IndexedDbKeyvaultStore implements KeyvaultStore {
  private ephemeral = false;
  private readonly mem = new Map<string, VaultRecord>();

  constructor(private readonly db: IDBDatabase) {}

  /** Turn history-off on or off for this device. Leaving the mode drops whatever memory held. */
  setEphemeral(on: boolean): void {
    this.ephemeral = on;
    if (!on) {
      this.mem.clear();
    }
  }

  isEphemeral(): boolean {
    return this.ephemeral;
  }

  async get(messageId: string): Promise<VaultRecord | undefined> {
    const held = this.mem.get(messageId);
    if (held !== undefined) {
      return held;
    }
    const store = this.db.transaction(STORE_MESSAGES, 'readonly').objectStore(STORE_MESSAGES);
    return reqDone(store.get(messageId) as IDBRequest<VaultRecord | undefined>);
  }

  async put(record: VaultRecord): Promise<void> {
    if (this.mem.has(record.messageId)) {
      this.mem.set(record.messageId, record); // already memory-held: keep it there
      return;
    }
    if (this.ephemeral) {
      const store = this.db.transaction(STORE_MESSAGES, 'readonly').objectStore(STORE_MESSAGES);
      const onDisk = await reqDone(store.get(record.messageId) as IDBRequest<VaultRecord | undefined>);
      if (onDisk === undefined) {
        this.mem.set(record.messageId, record);
        this.evictOldest(record.conversationId);
        return;
      }
      // It IS on disk (written before the mode was turned on): its update belongs on disk too.
    }
    const rw = this.db.transaction(STORE_MESSAGES, 'readwrite').objectStore(STORE_MESSAGES);
    await reqDone(rw.put(record));
  }

  /** Keep the newest EPHEMERAL_PER_CONV_MAX memory records for one conversation. */
  private evictOldest(conversationId: string): void {
    const mine = [...this.mem.values()].filter((v) => v.conversationId === conversationId);
    if (mine.length <= EPHEMERAL_PER_CONV_MAX) {
      return;
    }
    mine
      .sort((a, b) => a.storedAtMs - b.storedAtMs)
      .slice(0, mine.length - EPHEMERAL_PER_CONV_MAX)
      .forEach((v) => this.mem.delete(v.messageId));
  }

  async delete(messageId: string): Promise<void> {
    this.mem.delete(messageId);
    const store = this.db.transaction(STORE_MESSAGES, 'readwrite').objectStore(STORE_MESSAGES);
    await reqDone(store.delete(messageId));
  }

  async list(): Promise<readonly VaultRecord[]> {
    const store = this.db.transaction(STORE_MESSAGES, 'readonly').objectStore(STORE_MESSAGES);
    const disk = await reqDone(store.getAll() as IDBRequest<VaultRecord[]>);
    return this.mem.size === 0 ? disk : [...disk, ...this.mem.values()];
  }

  /** Only ONE conversation's records, via the v4 conversationId index: opening a chat must not pay a
   * full-store scan of every message in every conversation (openChannel runs on every send/receive).
   * Falls back to a filtered full scan if the index is missing (a DB opened before the v4 upgrade). */
  async listByConversation(conversationId: string): Promise<readonly VaultRecord[]> {
    const store = this.db.transaction(STORE_MESSAGES, 'readonly').objectStore(STORE_MESSAGES);
    const disk = store.indexNames.contains(IDX_MESSAGES_BY_CONV)
      ? await reqDone(store.index(IDX_MESSAGES_BY_CONV).getAll(IDBKeyRange.only(conversationId)) as IDBRequest<VaultRecord[]>)
      : (await reqDone(store.getAll() as IDBRequest<VaultRecord[]>)).filter((v) => v.conversationId === conversationId);
    if (this.mem.size === 0) {
      return disk;
    }
    // Union: openChannel sorts by storedAtMs, and memory records carry the same field from seal().
    return [...disk, ...[...this.mem.values()].filter((v) => v.conversationId === conversationId)];
  }

  /** Destroy every message record on DISK for this device (crypto-erase: the wrapped per-message keys
   * go with them). Used when history-off is switched on, so turning it on does not leave the past
   * sitting there. Memory-held records are untouched, so the open conversation survives the switch. */
  async purgeDurable(): Promise<void> {
    const store = this.db.transaction(STORE_MESSAGES, 'readwrite').objectStore(STORE_MESSAGES);
    await reqDone(store.clear());
  }
}

export interface SealedSession {
  readonly conversationId: string;
  readonly sealed: Uint8Array; // Conversation.exportSealed bytes, opaque without the MSK; the
  // MLS group id is inside the sealed blob (fromSealed self-describes), so it is not stored here.
}

/** Durable, MSK-sealed MLS session state, keyed by conversation. */
export class SealedSessionStore {
  constructor(private readonly db: IDBDatabase) {}

  async save(session: SealedSession): Promise<void> {
    const store = this.db.transaction(STORE_MLS, 'readwrite').objectStore(STORE_MLS);
    await reqDone(store.put(session));
  }

  load(conversationId: string): Promise<SealedSession | undefined> {
    const store = this.db.transaction(STORE_MLS, 'readonly').objectStore(STORE_MLS);
    return reqDone(store.get(conversationId) as IDBRequest<SealedSession | undefined>);
  }

  async delete(conversationId: string): Promise<void> {
    const store = this.db.transaction(STORE_MLS, 'readwrite').objectStore(STORE_MLS);
    await reqDone(store.delete(conversationId));
  }
}

/** KDF descriptor persisted beside the wrap so the work factor is explicit, auditable, and
 * upgradable (review follow-up). Mirrors the pinned Argon2id params in the wasm core. */
export interface KdfDescriptor {
  readonly algo: 'argon2id';
  readonly v: number;
  readonly m: number; // memory KiB
  readonly t: number; // passes
  readonly p: number; // parallelism
}

export const KDF_DESCRIPTOR: KdfDescriptor = { algo: 'argon2id', v: 1, m: 65536, t: 3, p: 1 };

/** A sealed channel-summary record (the contact graph), keyed by channel id. The blob is
 * AEAD-sealed under the MSK (vault.sealUnder), so the contact graph is never plaintext at rest. */
export interface ChannelRecord {
  readonly id: string;
  readonly blob: Uint8Array;
}

export class ChannelStore {
  private ephemeral = false;
  private readonly mem = new Map<string, ChannelRecord>();

  constructor(private readonly db: IDBDatabase) {}

  /** History-off mode. The summary carries no message text (only the peer short-name and a constant
   * preview), but it is still evidence a conversation happened, and dropping it entirely would make
   * openChannel report the conversation as insecure and render the compose box read-only. */
  setEphemeral(on: boolean): void {
    this.ephemeral = on;
    if (!on) {
      this.mem.clear();
    }
  }

  async put(record: ChannelRecord): Promise<void> {
    if (this.ephemeral || this.mem.has(record.id)) {
      this.mem.set(record.id, record);
      return;
    }
    const store = this.db.transaction(STORE_CHANNELS, 'readwrite').objectStore(STORE_CHANNELS);
    await reqDone(store.put(record));
  }
  async get(id: string): Promise<ChannelRecord | undefined> {
    const held = this.mem.get(id);
    if (held !== undefined) {
      return held;
    }
    const store = this.db.transaction(STORE_CHANNELS, 'readonly').objectStore(STORE_CHANNELS);
    return reqDone(store.get(id) as IDBRequest<ChannelRecord | undefined>);
  }
  async list(): Promise<readonly ChannelRecord[]> {
    const store = this.db.transaction(STORE_CHANNELS, 'readonly').objectStore(STORE_CHANNELS);
    const disk = await reqDone(store.getAll() as IDBRequest<ChannelRecord[]>);
    if (this.mem.size === 0) {
      return disk;
    }
    const byId = new Map(disk.map((r) => [r.id, r]));
    for (const [id, r] of this.mem) {
      byId.set(id, r);
    }
    return [...byId.values()];
  }
  async delete(id: string): Promise<void> {
    this.mem.delete(id);
    const store = this.db.transaction(STORE_CHANNELS, 'readwrite').objectStore(STORE_CHANNELS);
    await reqDone(store.delete(id));
  }
  /** Drop every conversation row on disk (used when history-off is switched on). */
  async purgeDurable(): Promise<void> {
    const store = this.db.transaction(STORE_CHANNELS, 'readwrite').objectStore(STORE_CHANNELS);
    await reqDone(store.clear());
  }
}

/** A sealed device-settings record: the local user's own identity bits (buddy icon, profile, away
 * config, and the per-sender away-reply dedupe state) plus the cached identity of peers we share a
 * conversation with, keyed by a setting id. The blob is AEAD-sealed under the MSK (vault.sealUnder),
 * so none of it sits in plaintext at rest, and none of it reaches the server. */
export interface DeviceSettingRecord {
  readonly id: string;
  readonly blob: Uint8Array;
}

export class DeviceSettingsStore {
  constructor(private readonly db: IDBDatabase) {}

  async put(record: DeviceSettingRecord): Promise<void> {
    const store = this.db.transaction(STORE_DEVICE_SETTINGS, 'readwrite').objectStore(STORE_DEVICE_SETTINGS);
    await reqDone(store.put(record));
  }
  get(id: string): Promise<DeviceSettingRecord | undefined> {
    const store = this.db.transaction(STORE_DEVICE_SETTINGS, 'readonly').objectStore(STORE_DEVICE_SETTINGS);
    return reqDone(store.get(id) as IDBRequest<DeviceSettingRecord | undefined>);
  }
  list(): Promise<readonly DeviceSettingRecord[]> {
    const store = this.db.transaction(STORE_DEVICE_SETTINGS, 'readonly').objectStore(STORE_DEVICE_SETTINGS);
    return reqDone(store.getAll() as IDBRequest<DeviceSettingRecord[]>);
  }
  async delete(id: string): Promise<void> {
    const store = this.db.transaction(STORE_DEVICE_SETTINGS, 'readwrite').objectStore(STORE_DEVICE_SETTINGS);
    await reqDone(store.delete(id));
  }
}

interface MskRecord {
  readonly id: string;
  readonly wrappedMsk: Uint8Array;
  readonly salt: Uint8Array;
  readonly wrapNonce: Uint8Array;
  readonly kdf: KdfDescriptor;
}

/** Derive a key-encryption-key from a credential string + salt. Production injects the wasm
 * Argon2id `deriveMasterKey`; tests inject a deterministic fake. The credential is the account's
 * combined login secret (username plus passphrase), so the KEK is bound to both. */
export type DeriveKek = (credential: string, salt: Uint8Array) => Promise<Uint8Array>;

const MSK_PREFIX = 'msk:';
const SALT_LEN = 16;
const MSK_LEN = 32;

/**
 * The MSK vault: a random MSK wrapped under a credential-derived KEK, one record per account so
 * several accounts (each a username) can coexist on one device, fully isolated. `unlock` returns
 * the raw MSK bytes the caller uses for the wasm Conversation seal and the WebCrypto keyvault, then
 * zeroizes when locking. A wrong credential (username and/or passphrase) yields null (AEAD unwrap
 * fails). The account id keys the record; the credential derives the KEK.
 */
export class MskVault {
  constructor(
    private readonly db: IDBDatabase,
    private readonly deriveKek: DeriveKek,
  ) {}

  exists(account: string): Promise<boolean> {
    return this.get(account).then((r) => r !== undefined);
  }

  /** Destroy an account's MSK wrap. Used to roll back a local vault whose server registration was
   * rejected (the username was taken), so a seized device keeps no orphaned account. With the wrap
   * gone, anything else sealed under that MSK is inert ciphertext (crypto-erase, ADR-015). */
  async delete(account: string): Promise<void> {
    const store = this.db.transaction(STORE_VAULT, 'readwrite').objectStore(STORE_VAULT);
    await reqDone(store.delete(MSK_PREFIX + account));
  }

  /** Create a fresh vault for a new account. Returns the raw MSK. */
  async create(account: string, credential: string): Promise<Uint8Array> {
    const salt = randomBytes(SALT_LEN);
    const msk = randomBytes(MSK_LEN);
    const wrapNonce = randomBytes(12);
    const kek = await this.importKek(credential, salt, 'encrypt');
    const wrappedMsk = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: WRAP_AEAD, iv: new Uint8Array(wrapNonce), additionalData: new Uint8Array(salt) },
        kek,
        new Uint8Array(msk),
      ),
    );
    await this.putRecord({ id: MSK_PREFIX + account, wrappedMsk, salt, wrapNonce, kdf: KDF_DESCRIPTOR });
    return msk;
  }

  /** Unlock an account with its credential. Returns the raw MSK, or null if there is no vault for
   * that account or the credential is wrong (the AEAD authentication fails). The salt is bound as
   * associated data, so a swapped salt also fails authentication. */
  async unlock(account: string, credential: string): Promise<Uint8Array | null> {
    const rec = await this.get(account);
    if (rec === undefined) {
      return null;
    }
    const kek = await this.importKek(credential, rec.salt, 'decrypt');
    try {
      const msk = await crypto.subtle.decrypt(
        { name: WRAP_AEAD, iv: new Uint8Array(rec.wrapNonce), additionalData: new Uint8Array(rec.salt) },
        kek,
        new Uint8Array(rec.wrappedMsk),
      );
      return new Uint8Array(msk);
    } catch {
      return null;
    }
  }

  private async importKek(credential: string, salt: Uint8Array, usage: 'encrypt' | 'decrypt'): Promise<CryptoKey> {
    const kekBytes = await this.deriveKek(credential, salt);
    const kek = await crypto.subtle.importKey('raw', new Uint8Array(kekBytes), WRAP_AEAD, false, [usage]);
    kekBytes.fill(0); // best-effort scrub the derived KEK bytes
    return kek;
  }

  private get(account: string): Promise<MskRecord | undefined> {
    const store = this.db.transaction(STORE_VAULT, 'readonly').objectStore(STORE_VAULT);
    return reqDone(store.get(MSK_PREFIX + account) as IDBRequest<MskRecord | undefined>);
  }

  private async putRecord(rec: MskRecord): Promise<void> {
    const store = this.db.transaction(STORE_VAULT, 'readwrite').objectStore(STORE_VAULT);
    await reqDone(store.put(rec));
  }
}

/**
 * Panic crypto-erase: destroy the MSK wrap FIRST so every other store becomes inert ciphertext
 * under a key that no longer exists, even if the rest is interrupted, then best-effort clear all
 * stores. Honest limit (ADR-015): a deleted IndexedDB record is not byte-overwritten on flash;
 * the protection is that what remains is ciphertext under a destroyed key (crypto-erase, not
 * overwrite, NIST SP 800-88).
 */
export async function panicWipe(db: IDBDatabase): Promise<void> {
  // Destroy every account's MSK wrap FIRST so all other stores become inert ciphertext under keys
  // that no longer exist, then best-effort clear the rest.
  await reqDone(db.transaction(STORE_VAULT, 'readwrite').objectStore(STORE_VAULT).clear());
  for (const name of [STORE_MESSAGES, STORE_MLS, STORE_CHANNELS, STORE_DEVICE_SETTINGS]) {
    await reqDone(db.transaction(name, 'readwrite').objectStore(name).clear());
  }
}
