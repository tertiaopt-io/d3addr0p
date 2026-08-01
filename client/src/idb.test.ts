import 'fake-indexeddb/auto';
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import {
  openDeadDropDb,
  IndexedDbKeyvaultStore,
  SealedSessionStore,
  DeviceSettingsStore,
  MskVault,
  panicWipe,
  type DeriveKek,
} from './idb.js';
import { seal, importMsk } from './vault.js';

const enc = new TextEncoder();

// Deterministic test KEK derivation (production injects the wasm Argon2id deriveMasterKey).
const deriveKek: DeriveKek = async (passphrase, salt) => {
  const material = enc.encode(passphrase);
  const joined = new Uint8Array(material.length + salt.length);
  joined.set(material);
  joined.set(salt, material.length);
  const digest = await crypto.subtle.digest('SHA-256', joined);
  return new Uint8Array(digest);
};

function clearStore(db: IDBDatabase, name: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const req = db.transaction(name, 'readwrite').objectStore(name).clear();
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error ?? new Error('clear failed'));
  });
}

let db: IDBDatabase;
beforeEach(async () => {
  db = await openDeadDropDb();
  // Isolate tests by clearing the stores rather than deleting the database (which blocks while
  // a connection is open).
  for (const name of ['vault', 'mls_state', 'messages', 'device_settings']) {
    await clearStore(db, name);
  }
});

afterEach(() => {
  db.close();
});

describe('IndexedDbKeyvaultStore', () => {
  it('persists, reads, lists, and crypto-erases a record', async () => {
    const store = new IndexedDbKeyvaultStore(db);
    const msk = await importMsk(new Uint8Array(32));
    const rec = await seal(
      msk,
      { messageId: 'm1', conversationId: 'c', direction: 'in', lifetime: { kind: 'duration', seconds: 30 } },
      enc.encode('hi'),
      0,
    );

    await store.put(rec);
    expect((await store.get('m1'))?.messageId).toBe('m1');
    expect(await store.list()).toHaveLength(1);

    await store.delete('m1'); // crypto-erase: the wrapped PMK is gone with the record
    expect(await store.get('m1')).toBeUndefined();
    expect(await store.list()).toHaveLength(0);
  });

  describe('history-off (ephemeral) mode', () => {
    const msk = () => importMsk(new Uint8Array(32));
    const rec = async (id: string, conv = 'c') =>
      seal(
        await msk(),
        { messageId: id, conversationId: conv, direction: 'in', lifetime: { kind: 'duration', seconds: 30 } },
        enc.encode(id),
        0,
      );

    it('keeps new messages out of storage while still serving them to the open conversation', async () => {
      const store = new IndexedDbKeyvaultStore(db);
      store.setEphemeral(true);
      await store.put(await rec('e1'));
      // Readable through every path the UI uses, so the chat still renders.
      expect((await store.get('e1'))?.messageId).toBe('e1');
      expect(await store.listByConversation('c')).toHaveLength(1);
      // But a fresh store over the SAME database sees nothing: nothing was written.
      const fresh = new IndexedDbKeyvaultStore(db);
      expect(await fresh.get('e1')).toBeUndefined();
      expect(await fresh.list()).toHaveLength(0);
    });

    it('sends an update to a DISK-backed record back to disk, so a burn latch is never lost', async () => {
      // The dangerous case: a record stored before the mode was turned on, then burned. If the
      // tombstone went to memory, a reload would restore the readable original.
      const store = new IndexedDbKeyvaultStore(db);
      const original = await rec('d1');
      await store.put(original); // durable, mode off
      store.setEphemeral(true);
      await store.put({ ...original, read: true }); // the burn latch writing its tombstone
      const fresh = new IndexedDbKeyvaultStore(db);
      expect((await fresh.get('d1'))?.read).toBe(true); // the latch survived, on disk
    });

    it('unions memory and disk, and leaving the mode drops what memory held', async () => {
      const store = new IndexedDbKeyvaultStore(db);
      await store.put(await rec('k1'));
      store.setEphemeral(true);
      await store.put(await rec('k2'));
      expect(await store.listByConversation('c')).toHaveLength(2); // one of each
      store.setEphemeral(false);
      expect(await store.listByConversation('c')).toHaveLength(1); // the memory-held one is gone
    });

    it('purgeDurable crypto-erases what is already stored, which is what the toggle promises', async () => {
      const store = new IndexedDbKeyvaultStore(db);
      await store.put(await rec('p1'));
      await store.purgeDurable();
      expect(await new IndexedDbKeyvaultStore(db).list()).toHaveLength(0);
    });
  });
});

describe('SealedSessionStore', () => {
  it('saves and loads sealed MLS state per conversation', async () => {
    const store = new SealedSessionStore(db);
    await store.save({ conversationId: 'c1', sealed: new Uint8Array([1, 2, 3]) });
    const loaded = await store.load('c1');
    expect(loaded?.sealed).toEqual(new Uint8Array([1, 2, 3]));
    await store.delete('c1');
    expect(await store.load('c1')).toBeUndefined();
  });
});

describe('DeviceSettingsStore', () => {
  it('persists, reads, lists, and deletes a sealed device-settings record', async () => {
    const store = new DeviceSettingsStore(db);
    await store.put({ id: 'self:identity', blob: new Uint8Array([7, 8, 9]) });
    expect((await store.get('self:identity'))?.blob).toEqual(new Uint8Array([7, 8, 9]));
    expect(await store.list()).toHaveLength(1);
    await store.delete('self:identity');
    expect(await store.get('self:identity')).toBeUndefined();
    expect(await store.list()).toHaveLength(0);
  });
});

describe('MskVault', () => {
  it('creates a vault and unlocks with the correct credential', async () => {
    const vault = new MskVault(db, deriveKek);
    expect(await vault.exists('alice')).toBe(false);
    const msk = await vault.create('alice', 'correct horse battery staple');
    expect(msk).toHaveLength(32);
    expect(await vault.exists('alice')).toBe(true);

    const unlocked = await vault.unlock('alice', 'correct horse battery staple');
    expect(unlocked).toEqual(msk);
  });

  it('returns null for the wrong credential (AEAD unwrap fails)', async () => {
    const vault = new MskVault(db, deriveKek);
    await vault.create('alice', 'the real passphrase');
    expect(await vault.unlock('alice', 'a guess')).toBeNull();
  });

  it('returns null when no vault exists for that account', async () => {
    const vault = new MskVault(db, deriveKek);
    expect(await vault.unlock('nobody', 'anything')).toBeNull();
  });

  it('keeps separate accounts isolated on one device', async () => {
    const vault = new MskVault(db, deriveKek);
    const aMsk = await vault.create('alice', 'pass-a');
    const bMsk = await vault.create('bob', 'pass-b');
    expect(aMsk).not.toEqual(bMsk); // distinct MSKs per account
    expect(await vault.unlock('alice', 'pass-a')).toEqual(aMsk);
    expect(await vault.unlock('bob', 'pass-b')).toEqual(bMsk);
    expect(await vault.unlock('alice', 'pass-b')).toBeNull(); // alice's account, bob's passphrase
  });

  it('persists the KDF descriptor beside the wrap (auditable work factor)', async () => {
    const vault = new MskVault(db, deriveKek);
    await vault.create('alice', 'pass');
    const rec = await new Promise<{ kdf: { algo: string; m: number; t: number; p: number } }>((resolve, reject) => {
      const req = db.transaction('vault', 'readonly').objectStore('vault').get('msk:alice');
      req.onsuccess = () => resolve(req.result as { kdf: { algo: string; m: number; t: number; p: number } });
      req.onerror = () => reject(req.error ?? new Error('read failed'));
    });
    expect(rec.kdf).toEqual({ algo: 'argon2id', v: 1, m: 65536, t: 3, p: 1 });
  });
});

describe('panicWipe', () => {
  it('destroys every account MSK wrap and clears all stores', async () => {
    const vault = new MskVault(db, deriveKek);
    await vault.create('alice', 'pass');
    await vault.create('bob', 'pass2');
    const messages = new IndexedDbKeyvaultStore(db);
    const sessions = new SealedSessionStore(db);
    const msk = await importMsk(new Uint8Array(32));
    const rec = await seal(
      msk,
      { messageId: 'm1', conversationId: 'c', direction: 'in', lifetime: { kind: 'burn-on-read' } },
      enc.encode('secret'),
      0,
    );
    await messages.put(rec);
    await sessions.save({ conversationId: 'c', sealed: new Uint8Array([1]) });
    const settings = new DeviceSettingsStore(db);
    await settings.put({ id: 'self:identity', blob: new Uint8Array([1, 2, 3]) });

    await panicWipe(db);

    expect(await vault.exists('alice')).toBe(false); // every panic lever is gone
    expect(await vault.exists('bob')).toBe(false);
    expect(await messages.list()).toHaveLength(0);
    expect(await sessions.load('c')).toBeUndefined();
    expect(await settings.list()).toHaveLength(0); // the sealed identity store is wiped too
    expect(await vault.unlock('alice', 'pass')).toBeNull(); // nothing left to unlock
  });
});
