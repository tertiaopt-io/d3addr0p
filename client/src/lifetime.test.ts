import { describe, it, expect, beforeEach } from 'vitest';
import { LifetimeManager, type LifetimeHooks, type ErasureReason } from './lifetime.js';
import { seal, importMsk, type KeyvaultStore, type VaultRecord } from './vault.js';

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

/** Controllable clock + scheduler so tests drive time deterministically. */
class FakeHooks implements LifetimeHooks {
  current = 0;
  erased: { id: string; reason: ErasureReason }[] = [];
  private pending = new Map<number, () => void>();
  private seq = 0;
  now(): number {
    return this.current;
  }
  schedule(_delayMs: number, cb: () => void): unknown {
    const h = this.seq++;
    this.pending.set(h, cb);
    return h;
  }
  cancel(handle: unknown): void {
    this.pending.delete(handle as number);
  }
  onErased(messageId: string, reason: ErasureReason): void {
    this.erased.push({ id: messageId, reason });
  }
  fireAll(): void {
    const cbs = [...this.pending.values()];
    this.pending.clear();
    for (const cb of cbs) {
      cb();
    }
  }
}

async function freshMsk(): Promise<CryptoKey> {
  const raw = new Uint8Array(32);
  crypto.getRandomValues(raw);
  return importMsk(raw);
}

let store: MemStore;
let hooks: FakeHooks;
let mgr: LifetimeManager;

beforeEach(() => {
  store = new MemStore();
  hooks = new FakeHooks();
  mgr = new LifetimeManager(store, hooks);
});

describe('LifetimeManager (M2)', () => {
  it('erases a duration message when its timer fires', async () => {
    const msk = await freshMsk();
    const rec = await seal(
      msk,
      { messageId: 'm1', conversationId: 'c', direction: 'in', lifetime: { kind: 'duration', seconds: 30 } },
      enc.encode('hi'),
      hooks.now(),
    );
    await store.put(rec);
    await mgr.arm(rec);
    expect(await store.get('m1')).toBeDefined();

    await Promise.resolve(hooks.fireAll());
    await new Promise((r) => setTimeout(r, 0)); // let the async expire settle
    expect(await store.get('m1')).toBeUndefined();
    expect(hooks.erased).toEqual([{ id: 'm1', reason: 'duration' }]);
  });

  it('sweeps already-overdue messages on resume', async () => {
    const msk = await freshMsk();
    const rec = await seal(
      msk,
      { messageId: 'm2', conversationId: 'c', direction: 'in', lifetime: { kind: 'duration', seconds: 10 } },
      enc.encode('hi'),
      0,
    );
    await store.put(rec);
    hooks.current = 999_999; // well past expiry
    await mgr.sweepExpired();
    expect(await store.get('m2')).toBeUndefined();
    expect(hooks.erased).toEqual([{ id: 'm2', reason: 'duration' }]);
  });

  it('re-arms a still-pending duration timer on resume so it is destroyed at its deadline (AIM25)', async () => {
    const msk = await freshMsk();
    // Armed BEFORE the "reload": expiresAtMs = 0 + 100_000. A reload loses the in-memory timer.
    const rec = await seal(
      msk,
      { messageId: 'm7', conversationId: 'c', direction: 'in', lifetime: { kind: 'duration', seconds: 100 } },
      enc.encode('secret'),
      0,
      true, // arm now
    );
    await store.put(rec);
    hooks.current = 50_000; // resume BEFORE the deadline: not overdue, so it must be re-armed, not swept
    await mgr.sweepExpired();
    expect(await store.get('m7')).toBeDefined(); // not erased yet (still pending)
    expect(hooks.erased).toEqual([]);
    // When the re-armed timer fires it erases the message — no lingering readable plaintext past expiry.
    hooks.fireAll();
    await new Promise((r) => setTimeout(r, 0)); // let the async expire() drain fully
    expect(hooks.erased).toEqual([{ id: 'm7', reason: 'duration' }]);
    expect(await store.get('m7')).toBeUndefined();
  });

  it('burns on read exactly once and is idempotent thereafter', async () => {
    const msk = await freshMsk();
    const rec = await seal(
      msk,
      { messageId: 'm3', conversationId: 'c', direction: 'in', lifetime: { kind: 'burn-on-read' } },
      enc.encode('for your eyes only'),
      0,
    );
    await store.put(rec);

    const first = await mgr.openBurnOnRead(msk, 'm3');
    expect(first).not.toBeNull();
    expect(dec.decode(first as Uint8Array)).toBe('for your eyes only');
    // Second open returns null; the durable key is gone (tombstone with read latch).
    expect(await mgr.openBurnOnRead(msk, 'm3')).toBeNull();
    expect(hooks.erased).toEqual([{ id: 'm3', reason: 'burn' }]);
  });

  it('storeIncoming never overwrites: a redelivery cannot resurrect a burn tombstone', async () => {
    const msk = await freshMsk();
    const meta = { messageId: 'mre', conversationId: 'c', direction: 'in' as const, lifetime: { kind: 'burn-on-read' as const } };
    await mgr.storeIncoming(msk, meta, enc.encode('secret'), false);
    expect(dec.decode((await mgr.openBurnOnRead(msk, 'mre')) as Uint8Array)).toBe('secret');
    // The gateway redelivers the same envelope (its ack was lost): the read latch must survive.
    await mgr.storeIncoming(msk, meta, enc.encode('secret'), false);
    expect((await store.get('mre'))?.read).toBe(true);
    expect((await store.get('mre'))?.wrappedPmk.length).toBe(0);
    expect(await mgr.openBurnOnRead(msk, 'mre')).toBeNull();
  });

  it('revoke destroys the stored copy idempotently', async () => {
    const msk = await freshMsk();
    const rec = await seal(
      msk,
      { messageId: 'm4', conversationId: 'c', direction: 'in', lifetime: { kind: 'until-revoked' } },
      enc.encode('recall me'),
      0,
    );
    await store.put(rec);
    await mgr.revoke('m4');
    expect(await store.get('m4')).toBeUndefined();
    await mgr.revoke('m4'); // idempotent, no throw
    expect(hooks.erased).toEqual([{ id: 'm4', reason: 'revoke' }]);
  });

  it('storeIncoming seals, persists, and arms a duration message in one step', async () => {
    const msk = await freshMsk();
    await mgr.storeIncoming(
      msk,
      { messageId: 'm6', conversationId: 'c', direction: 'in', lifetime: { kind: 'duration', seconds: 30 } },
      enc.encode('stored'),
    );
    expect(await store.get('m6')).toBeDefined();
    // The timer is armed; firing it crypto-erases the record.
    hooks.fireAll();
    await new Promise((r) => setTimeout(r, 0));
    expect(await store.get('m6')).toBeUndefined();
    expect(hooks.erased).toEqual([{ id: 'm6', reason: 'duration' }]);
  });

  it('expires immediately if armed after the deadline already passed', async () => {
    const msk = await freshMsk();
    const rec = await seal(
      msk,
      { messageId: 'm5', conversationId: 'c', direction: 'in', lifetime: { kind: 'duration', seconds: 1 } },
      enc.encode('hi'),
      0,
    );
    await store.put(rec);
    hooks.current = 10_000; // past expiresAtMs (1000)
    await mgr.arm(rec);
    expect(await store.get('m5')).toBeUndefined();
  });

  // Hold-until-seen: an inbound message stored unarmed must persist (no countdown, survives a
  // reload sweep) until the recipient views it, at which point armOnView starts the clock.
  it('stores an inbound message unarmed and only starts its countdown on first view', async () => {
    const msk = await freshMsk();
    await mgr.storeIncoming(
      msk,
      { messageId: 'mhold', conversationId: 'c', direction: 'in', lifetime: { kind: 'duration', seconds: 30 } },
      enc.encode('hold me'),
      false, // armNow = false (inbound)
    );
    const stored = await store.get('mhold');
    expect(stored?.expiresAtMs).toBeNull(); // not counting down
    expect(stored?.durationSeconds).toBe(30); // duration retained for later arming

    // A reload (sweepExpired) must NOT erase an unseen message even long after it "would" expire.
    hooks.current = 1_000_000;
    await mgr.sweepExpired();
    expect(await store.get('mhold')).toBeDefined();

    // The recipient opens the conversation: the timer starts from now.
    await mgr.armOnView('mhold');
    expect((await store.get('mhold'))?.expiresAtMs).toBe(1_000_000 + 30_000);

    // Now it expires on the timer.
    hooks.fireAll();
    await new Promise((r) => setTimeout(r, 0));
    expect(await store.get('mhold')).toBeUndefined();
    expect(hooks.erased).toEqual([{ id: 'mhold', reason: 'duration' }]);
  });

  it('armOnView is a no-op for an already-armed message (idempotent re-view)', async () => {
    const msk = await freshMsk();
    await mgr.storeIncoming(
      msk,
      { messageId: 'marm', conversationId: 'c', direction: 'out', lifetime: { kind: 'duration', seconds: 30 } },
      enc.encode('sent'),
      true, // outbound: armed immediately at store time (now=0 -> expires at 30000)
    );
    expect((await store.get('marm'))?.expiresAtMs).toBe(30_000);
    hooks.current = 5_000;
    await mgr.armOnView('marm'); // must not push the deadline out
    expect((await store.get('marm'))?.expiresAtMs).toBe(30_000);
  });
});
