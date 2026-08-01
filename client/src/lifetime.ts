/**
 * Per-message lifetime enforcement (M2 Layer 2, ADR-015 / brief §3.2).
 *
 * Every expiry path reduces to the same primitive: destroy the message's key (crypto-erase),
 * never overwrite bytes. Duration messages erase on a timer; burn-on-read messages erase the
 * durable key in the same step they are first opened (fail-closed: the key is gone before the
 * plaintext is returned to the UI); revoke erases on a cooperating recipient's command.
 *
 * Clock, scheduler, and store are injected so this is fully testable. Production wires the
 * scheduler to setTimeout and the store to the IndexedDB keyvault inside the owning Worker.
 *
 * HONEST LIMIT (ADR-015): this erases the STORED copy and signals the UI to drop the rendered
 * copy. It cannot remove a screenshot, a photo, or a copy the OS/GPU/accessibility layer made
 * while the message was on screen.
 */

import { armRecord, cryptoErase, open, seal, type KeyvaultStore, type VaultRecord } from './vault.js';
import type { Lifetime } from './index.js';

export type ErasureReason = 'duration' | 'burn' | 'revoke';

/** Run `fn` holding an EXCLUSIVE cross-tab Web Lock when the platform provides one. Two tabs are two
 * independent workers over the one shared database (each worker's op queue cannot see the other tab),
 * and the burn read latch is a get -> decrypt -> put sequence with awaits between the steps, so
 * without this a second tab could open the same burn message inside the first tab's window and render
 * the plaintext twice. Node test hosts have no lock manager; there a direct call is correct (a single
 * process over a single store). */
async function exclusive<T>(name: string, fn: () => Promise<T>): Promise<T> {
  const locks = (globalThis as { navigator?: { locks?: LockManager } }).navigator?.locks;
  if (locks === undefined) {
    return fn();
  }
  return locks.request(name, fn) as Promise<T>;
}

export interface LifetimeHooks {
  /** Epoch milliseconds. Used only to compare against stored absolute expiry. */
  now(): number;
  /** Schedule `cb` after `delayMs`. Returns an opaque handle. */
  schedule(delayMs: number, cb: () => void): unknown;
  cancel(handle: unknown): void;
  /** The stored copy was erased; the UI must drop any rendered copy of THAT conversation and show a
   * tombstone. `conversationId` scopes the signal: without it the UI could only rebuild whatever
   * conversation happens to be open, and an unrelated expiry would consume a burn message's one
   * permitted view mid-read. */
  onErased(messageId: string, reason: ErasureReason, conversationId: string): void;
}

export class LifetimeManager {
  private readonly timers = new Map<string, unknown>();

  constructor(
    private readonly store: KeyvaultStore,
    private readonly hooks: LifetimeHooks,
  ) {}

  /**
   * Store an incoming (or outgoing) message into the crypto-erasable keyvault and arm its
   * lifetime. Seals the plaintext under a fresh per-message key, persists the record, and starts
   * the expiry timer for duration messages. This is the bridge from Session.receiveMessage to
   * the at-rest history.
   */
  async storeIncoming(
    msk: CryptoKey,
    meta: {
      messageId: string;
      conversationId: string;
      direction: 'in' | 'out';
      lifetime: Lifetime;
      /** An inbound copy of a message OUR OWN account authored on a sibling device (see vault.ts). */
      ownAuthored?: boolean;
    },
    plaintext: Uint8Array,
    /** When false, a duration message is stored UNARMED: its countdown starts on first view via
     * armOnView (hold-until-seen). Inbound messages pass false; outbound pass true. */
    armNow = true,
  ): Promise<VaultRecord> {
    // Create-if-absent: a redelivered envelope (a lost ack makes the gateway resend) must never
    // overwrite what this id already became. Overwriting would resurrect a burn read-latch tombstone
    // as a fresh readable copy, or restart a countdown.
    const existing = await this.store.get(meta.messageId);
    if (existing !== undefined) {
      return existing;
    }
    const record = await seal(msk, meta, plaintext, this.hooks.now(), armNow);
    await this.store.put(record);
    if (armNow) {
      await this.arm(record);
    }
    return record;
  }

  /**
   * Start the countdown for an unarmed duration message the recipient has now viewed (hold-until-
   * seen). Idempotent: a no-op if the message is missing, already armed, read, or not a duration.
   *
   * Pass `known` when the caller already holds the record. openChannel does, for every message in the
   * conversation, and it runs on every send and every inbound message, so re-fetching each one cost a
   * fresh IndexedDB transaction per message for a value already in memory (measured at 1000 messages:
   * 86ms of 196ms, 44% of the call). The copy is used for the CHECK only. That is safe in the one
   * direction that matters: arming is one-way, so a copy that reads armed cannot be a stale "unarmed",
   * and anything that actually needs a write re-reads the authoritative record below first.
   */
  async armOnView(messageId: string, known?: VaultRecord): Promise<void> {
    if (known !== undefined && (known.expiresAtMs !== null || known.lifetimeKind !== 'duration')) {
      return;
    }
    const record = await this.store.get(messageId);
    if (record === undefined || record.expiresAtMs !== null || record.lifetimeKind !== 'duration') {
      return;
    }
    const armed = armRecord(record, this.hooks.now());
    await this.store.put(armed);
    await this.arm(armed);
  }

  /** Arm a duration message's expiry timer. No-op for burn-on-read / until-revoked. */
  async arm(record: VaultRecord): Promise<void> {
    if (record.lifetimeKind !== 'duration' || record.expiresAtMs === null) {
      return;
    }
    const delay = record.expiresAtMs - this.hooks.now();
    if (delay <= 0) {
      await this.expire(record.messageId, 'duration');
      return;
    }
    const handle = this.hooks.schedule(delay, () => {
      void this.expire(record.messageId, 'duration');
    });
    this.timers.set(record.messageId, handle);
  }

  /** On resume (a reload loses every in-memory timer): erase everything already overdue AND re-arm the
   * still-pending duration timers so a message keeps being destroyed at its expiry even if the tab never
   * receives another message. Without the re-arm, a duration message armed before the reload but expiring
   * after it would linger readable past its deadline (its countdown reaches 0 with the plaintext intact)
   * until the NEXT resume swept it — a real ephemeral-message leak the live burn ticker made visible. */
  async sweepExpired(): Promise<void> {
    const now = this.hooks.now();
    for (const r of await this.store.list()) {
      if (r.expiresAtMs === null || r.lifetimeKind !== 'duration') {
        continue;
      }
      if (r.expiresAtMs <= now) {
        await this.expire(r.messageId, 'duration');
      } else if (!this.timers.has(r.messageId)) {
        await this.arm(r); // re-schedule the expiry timer this session lost on reload
      }
    }
  }

  /**
   * Open a burn-on-read message exactly once. Returns the framed plaintext, or null if it is
   * missing or already burned (idempotent, no view-again). The durable key is destroyed before
   * the plaintext is returned, so a crash mid-flow loses the message rather than showing it twice.
   * The whole read-latch sequence runs under a cross-tab exclusive lock: a second tab (its own
   * worker over the same database) re-reads the latch inside the lock and gets null.
   */
  openBurnOnRead(msk: CryptoKey, messageId: string): Promise<Uint8Array | null> {
    return exclusive(`dd-burn:${messageId}`, async () => {
      const record = await this.store.get(messageId);
      if (record === undefined || record.read || record.lifetimeKind !== 'burn-on-read') {
        return null;
      }
      const framed = await open(msk, record); // needs the wrapped PMK, still present here
      await this.store.put(tombstone(record)); // destroy the durable key before returning
      this.hooks.onErased(messageId, 'burn', record.conversationId);
      return framed;
    });
  }

  /** Cooperative revoke: destroy the target message's stored copy. Idempotent. */
  async revoke(messageId: string): Promise<void> {
    await this.expire(messageId, 'revoke');
  }

  private async expire(messageId: string, reason: ErasureReason): Promise<void> {
    const handle = this.timers.get(messageId);
    if (handle !== undefined) {
      this.hooks.cancel(handle);
      this.timers.delete(messageId);
    }
    // Idempotent: if the record is already gone, do not erase or signal again.
    const record = await this.store.get(messageId);
    if (record === undefined) {
      return;
    }
    await cryptoErase(this.store, messageId);
    this.hooks.onErased(messageId, reason, record.conversationId);
  }
}

/** A read burn message keeps a tombstone (read latch) with its key and ciphertext destroyed. */
function tombstone(r: VaultRecord): VaultRecord {
  return {
    ...r,
    read: true,
    nonce: new Uint8Array(0),
    ciphertext: new Uint8Array(0),
    wrappedPmk: new Uint8Array(0),
    wrapNonce: new Uint8Array(0),
  };
}
