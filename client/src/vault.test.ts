import { describe, it, expect } from 'vitest';
import {
  seal,
  open,
  cryptoErase,
  importMsk,
  type KeyvaultStore,
  type VaultRecord,
} from './vault.js';

const enc = new TextEncoder();
const dec = new TextDecoder();

class MemStore implements KeyvaultStore {
  private m = new Map<string, VaultRecord>();
  get(id: string): Promise<VaultRecord | undefined> {
    return Promise.resolve(this.m.get(id));
  }
  put(r: VaultRecord): Promise<void> {
    this.m.set(r.messageId, r);
    return Promise.resolve();
  }
  delete(id: string): Promise<void> {
    this.m.delete(id);
    return Promise.resolve();
  }
  list(): Promise<readonly VaultRecord[]> {
    return Promise.resolve([...this.m.values()]);
  }
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) {
      return false;
    }
  }
  return true;
}

async function freshMsk(): Promise<CryptoKey> {
  const raw = new Uint8Array(32);
  crypto.getRandomValues(raw);
  return importMsk(raw);
}

const META = {
  messageId: 'm1',
  conversationId: 'conv-1',
  direction: 'in' as const,
  lifetime: { kind: 'duration', seconds: 30 } as const,
};

describe('vault crypto-erase (M2 Layer 2, ADR-015)', () => {
  it('seals and opens back to the framed plaintext', async () => {
    const msk = await freshMsk();
    const rec = await seal(msk, META, enc.encode('framed-payload'), 1000);
    expect(dec.decode(await open(msk, rec))).toBe('framed-payload');
    expect(rec.expiresAtMs).toBe(1000 + 30_000);
  });

  it('uses a fresh random PMK each time (ciphertext and wrapped key differ)', async () => {
    const msk = await freshMsk();
    const a = await seal(msk, META, enc.encode('same'), 0);
    const b = await seal(msk, { ...META, messageId: 'm2' }, enc.encode('same'), 0);
    expect(bytesEqual(a.ciphertext, b.ciphertext)).toBe(false);
    expect(bytesEqual(a.wrappedPmk, b.wrappedPmk)).toBe(false);
  });

  it('destroying the wrapped PMK makes the message unrecoverable even with the MSK alive', async () => {
    const msk = await freshMsk();
    const store = new MemStore();
    const rec = await seal(msk, META, enc.encode('secret'), 0);
    await store.put(rec);

    await cryptoErase(store, 'm1');
    expect(await store.get('m1')).toBeUndefined();

    // The PMK is NOT derivable from the MSK + messageId, so a record whose wrappedPmk is gone
    // (here: replaced) cannot be opened. This is the per-message-erase invariant.
    const tampered: VaultRecord = { ...rec, wrappedPmk: new Uint8Array(rec.wrappedPmk.length) };
    await expect(open(msk, tampered)).rejects.toThrow();
  });

  it('binds the record identity so a sealed payload cannot be transplanted (AAD)', async () => {
    const msk = await freshMsk();
    const rec = await seal(msk, META, enc.encode('payload'), 0);
    const moved: VaultRecord = { ...rec, messageId: 'someone-elses-id' };
    await expect(open(msk, moved)).rejects.toThrow();
  });

  it('sets no absolute expiry for burn-on-read and until-revoked', async () => {
    const msk = await freshMsk();
    const burn = await seal(msk, { ...META, lifetime: { kind: 'burn-on-read' } }, enc.encode('x'), 5);
    const revocable = await seal(msk, { ...META, lifetime: { kind: 'until-revoked' } }, enc.encode('x'), 5);
    expect(burn.expiresAtMs).toBeNull();
    expect(revocable.expiresAtMs).toBeNull();
  });

  it('records own-account authorship: always on outbound, only as flagged on inbound (default off)', async () => {
    const msk = await freshMsk();
    // Outbound is own-authored by definition; the flag need not be passed.
    expect((await seal(msk, { ...META, direction: 'out' }, enc.encode('x'), 0)).ownAuthored).toBe(true);
    // Inbound defaults to NOT own-authored (fail-closed): a peer's message never gains the revoke control.
    expect((await seal(msk, META, enc.encode('x'), 0)).ownAuthored).toBe(false);
    // Inbound flagged by the receive path as MLS-authenticated own-account (a sibling's copy) keeps it.
    expect((await seal(msk, { ...META, ownAuthored: true }, enc.encode('x'), 0)).ownAuthored).toBe(true);
  });
});
