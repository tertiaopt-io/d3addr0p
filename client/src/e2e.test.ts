import 'fake-indexeddb/auto';
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { Session, type ConversationLike, type Identity } from './session.js';
import { LifetimeManager, type LifetimeHooks, type ErasureReason } from './lifetime.js';
import { AppControllerImpl, accountIdFor, credentialFor } from './controller.js';
import { openDeadDropDb, MskVault, ChannelStore, IndexedDbKeyvaultStore, type DeriveKek } from './idb.js';
import { importMsk } from './vault.js';
import type { GroupDeps } from './groupchannel.js';

/*
 * End-to-end client integration: two Sessions (Alice, Bob) complete the gated mutual-accept
 * handshake, exchange messages, and Bob persists received messages into his encrypted keyvault and
 * re-opens the conversation through the REAL controller. The MLS crypto is proven natively in Rust
 * (crypto/src/conversation.rs); here the Conversation is faked so the full client orchestration
 * (handshake -> transport shapes -> at-rest persistence -> read-back) is exercised in Node.
 */

const enc = new TextEncoder();
const ALICE_HEX = 'a'.repeat(64);
const BOB_HEX = 'b'.repeat(64);

function hex(b: Uint8Array): string {
  return [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
}

class FakeConversation implements ConversationLike {
  constructor(
    private readonly selfHex: string,
    private readonly peerHex: string,
  ) {}
  signaturePublicKeyHex(): string {
    return this.selfHex;
  }
  keyPackage(): Uint8Array {
    return enc.encode(`${this.selfHex}-kp`);
  }
  createAndAdd(_peerKeyPackage: Uint8Array): Uint8Array {
    return enc.encode('welcome');
  }
  joinFromWelcome(_welcome: Uint8Array): void {}
  encrypt(plaintext: Uint8Array): Uint8Array {
    return plaintext;
  }
  decrypt(ciphertext: Uint8Array): Uint8Array {
    return ciphertext;
  }
  peerSignatureKeyHex(): string {
    return this.peerHex;
  }
  selfMailbox(): string {
    return `${this.selfHex}-mbox`;
  }
  peerMailbox(): string {
    return `${this.peerHex}-mbox`;
  }
  mailboxTag(subject: string): string {
    return 'ctag-' + subject;
  }
  wipe(): void {}
}

function identity(hexKey: string, label: string): Identity {
  return { signatureKeyHex: hexKey, keyPackage: enc.encode(`${label}-kp`), label };
}

/** Run the full gated handshake between two devices (Bob offers, Alice accepts). */
function establishedPair(): { alice: Session; bob: Session } {
  const aliceConv = new FakeConversation(ALICE_HEX, BOB_HEX);
  const bobConv = new FakeConversation(BOB_HEX, ALICE_HEX);
  const bob = new Session(identity(BOB_HEX, 'bob'), 'conv-1', () => bobConv);
  const alice = new Session(identity(ALICE_HEX, 'alice'), 'conv-1', () => aliceConv);

  const offer = bob.makeOffer('mailbox-alice');
  alice.onOfferReceived(offer);
  const accept = alice.acceptOffer('mailbox-bob');
  bob.onAcceptReceived(accept);
  return { alice, bob };
}

const deriveKek: DeriveKek = async (passphrase, salt) => {
  const joined = new Uint8Array(enc.encode(passphrase).length + salt.length);
  joined.set(enc.encode(passphrase));
  joined.set(salt, enc.encode(passphrase).length);
  return new Uint8Array(await crypto.subtle.digest('SHA-256', joined));
};

function clearStore(db: IDBDatabase, name: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const req = db.transaction(name, 'readwrite').objectStore(name).clear();
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error ?? new Error('clear failed'));
  });
}

// A simple controllable lifetime clock/scheduler so duration expiry is deterministic.
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

let db: IDBDatabase;
let bobMsk: CryptoKey;
let keyvault: IndexedDbKeyvaultStore;
let hooks: FakeHooks;
let lifetime: LifetimeManager;
let controller: AppControllerImpl;

beforeEach(async () => {
  db = await openDeadDropDb();
  for (const name of ['vault', 'mls_state', 'messages', 'channels']) {
    await clearStore(db, name);
  }
  const vault = new MskVault(db, deriveKek);
  const rawMsk = await vault.create(await accountIdFor('bob'), credentialFor('bob', 'bob-pass')); // establish Bob's MSK
  bobMsk = await importMsk(rawMsk.slice());
  keyvault = new IndexedDbKeyvaultStore(db);
  hooks = new FakeHooks();
  lifetime = new LifetimeManager(keyvault, hooks);
  // Minimal live deps (sharing the deterministic scheduler) so the controller builds its own
  // LifetimeManager and openChannel enforces lifetimes exactly as the production worker does.
  const live: GroupDeps = {
    connect: () => {
      throw new Error('live transport not used in this test');
    },
    makeConversation: () => {
      throw new Error('wasm not used in this test');
    },
    pushEvent: () => {},
    schedule: (ms, cb) => hooks.schedule(ms, cb),
    cancel: (h) => hooks.cancel(h),
    sealConversation: () => new Uint8Array(0),
    restoreConversation: () => {
      throw new Error('wasm not used in this test');
    },
    sasDigestHex: () => '00'.repeat(32),
  };
  controller = new AppControllerImpl(vault, new ChannelStore(db), keyvault, () => hooks.now(), undefined, live);
  await controller.unlock('bob', 'bob-pass'); // controller shares Bob's MSK
});

afterEach(() => {
  db.close();
});

describe('end-to-end: two clients', () => {
  it('establish via the handshake, exchange a message, persist it, and re-open the conversation', async () => {
    const { alice, bob } = establishedPair();
    expect(alice.canSend()).toBe(true);
    expect(bob.canSend()).toBe(true);

    // Alice sends; the envelope is addressed to Bob's derived mailbox (sealed sender).
    const env = alice.sendMessage(enc.encode('meet at dawn'), { kind: 'duration', seconds: 3600 });
    expect(env.routingKey).toBe(bob.inboundMailbox());

    // Bob receives, decodes, and persists into his encrypted keyvault under the channel 'alice'.
    const got = bob.receiveMessage(env);
    expect(got.type).toBe('message');
    if (got.type !== 'message') {
      throw new Error('expected a message');
    }
    await lifetime.storeIncoming(
      bobMsk,
      { messageId: hex(env.messageId), conversationId: 'alice', direction: 'in', lifetime: got.lifetime },
      got.plaintext,
    );

    // Bob saves the channel and re-opens it through the real controller; the message is there.
    await controller.saveChannel({ id: 'alice', peer: 'ALICE', fingerprint: '5F·A2', status: 'secure', preview: 'meet at dawn', unread: 1 });
    const model = await controller.openChannel('alice');
    expect(model.peer).toBe('ALICE');
    expect(model.secure).toBe(true);
    expect(model.log.some((e) => e.kind === 'message' && e.text === 'meet at dawn')).toBe(true);
  });

  it('a revoke from Alice erases the message Bob stored', async () => {
    const { alice, bob } = establishedPair();
    const env = alice.sendMessage(enc.encode('burn this'), { kind: 'until-revoked' });
    const got = bob.receiveMessage(env);
    if (got.type !== 'message') {
      throw new Error('expected a message');
    }
    const messageId = hex(env.messageId);
    await lifetime.storeIncoming(
      bobMsk,
      { messageId, conversationId: 'alice', direction: 'in', lifetime: got.lifetime },
      got.plaintext,
    );
    expect(await keyvault.get(messageId)).toBeDefined();

    // Alice revokes; the command rides the channel; Bob applies it.
    const revokeEnv = alice.sendRevoke(messageId);
    const revoke = bob.receiveMessage(revokeEnv);
    expect(revoke.type).toBe('revoke');
    if (revoke.type !== 'revoke') {
      throw new Error('expected a revoke');
    }
    await lifetime.revoke(revoke.targetMessageId);
    expect(await keyvault.get(messageId)).toBeUndefined(); // crypto-erased
  });

  it('a burn-on-read message from Alice renders once through the real controller, then only its tombstone', async () => {
    const { alice, bob } = establishedPair();
    const env = alice.sendMessage(enc.encode('one look only'), { kind: 'burn-on-read' });
    const got = bob.receiveMessage(env);
    if (got.type !== 'message') {
      throw new Error('expected a message');
    }
    expect(got.lifetime).toEqual({ kind: 'burn-on-read' }); // the kind rode inside the ciphertext
    const messageId = hex(env.messageId);
    await lifetime.storeIncoming(
      bobMsk,
      { messageId, conversationId: 'alice', direction: 'in', lifetime: got.lifetime },
      got.plaintext,
      false, // inbound: held unread until Bob views the conversation
    );
    await controller.saveChannel({ id: 'alice', peer: 'ALICE', fingerprint: '5F·A2', status: 'secure', preview: '', unread: 1 });

    // The first view renders it, and the durable key dies in the same step (read latch).
    const first = await controller.openChannel('alice');
    expect(first.log.some((e) => e.kind === 'message' && e.text === 'one look only')).toBe(true);
    const latched = await keyvault.get(messageId);
    expect(latched?.read).toBe(true);
    expect(latched?.wrappedPmk.length).toBe(0); // crypto-erased: only the read-latch tombstone remains

    // Every later view shows the tombstone, never the text: this is the regression the 2026-07-06
    // review flagged (a burn message used to re-render forever).
    const second = await controller.openChannel('alice');
    expect(second.log.some((e) => e.kind === 'message' && e.text === 'one look only')).toBe(false);
    expect(second.log.some((e) => e.kind === 'destroyed')).toBe(true);
  });

  it('a duration message Bob stored expires and is erased on the timer', async () => {
    const { alice, bob } = establishedPair();
    const env = alice.sendMessage(enc.encode('see you soon'), { kind: 'duration', seconds: 30 });
    const got = bob.receiveMessage(env);
    if (got.type !== 'message') {
      throw new Error('expected a message');
    }
    const messageId = hex(env.messageId);
    await lifetime.storeIncoming(
      bobMsk,
      { messageId, conversationId: 'alice', direction: 'in', lifetime: got.lifetime },
      got.plaintext,
    );
    expect(await keyvault.get(messageId)).toBeDefined();

    hooks.fireAll();
    await new Promise((r) => setTimeout(r, 0));
    expect(await keyvault.get(messageId)).toBeUndefined();
    expect(hooks.erased).toEqual([{ id: messageId, reason: 'duration' }]);
  });
});
