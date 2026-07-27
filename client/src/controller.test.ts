import 'fake-indexeddb/auto';
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { AppControllerImpl, accountIdFor, credentialFor, normalizeBuddyMap, normalizeGroupMap } from './controller.js';
import { DEFAULT_IDENTITY, PROFILE_MAX_CHARS, ICON_VALUE_MAX } from './app.js';
import { openDeadDropDb, MskVault, ChannelStore, IndexedDbKeyvaultStore, SealedSessionStore, type DeriveKek } from './idb.js';
import { importMsk, sealUnder, seal } from './vault.js';
import { encodeList } from './group.js';
import { CONTROL_BUDDY_ICON, CONTROL_PROFILE, CONTROL_AWAY, type EnvelopeMsg } from './session.js';
import type { GroupDeps } from './groupchannel.js';
import type { GroupConversationLike } from './group.js';
import type { Transport, TransportHandlers } from './transport.js';

// A minimal GroupConversationLike with a fixed identity, enough for connectGateway. It never drives
// real group traffic here, so the multi-group methods return trivial-but-valid shapes: createGroup
// returns an empty [welcome, groupId] list, joinFromWelcome returns no group id, receive returns a
// [groupId, proposal] list, and there are no open conversations.
function fakeConv(sig = '0'.repeat(64)): GroupConversationLike {
  return {
    signaturePublicKeyHex: () => sig,
    accountKeyHex: () => '',
    keyPackage: () => new Uint8Array([1]),
    createGroup: () => encodeList([new Uint8Array(), new Uint8Array()]),
    createSelf: () => new Uint8Array(),
    listConversations: () => [],
    addMember: (_id, _kp) => new Uint8Array(),
    stageAdd: (_id, _kp) => new Uint8Array(),
    confirmAdd: (_id) => {},
    abortAdd: (_id) => {},
    removeMember: (_id, _sig) => new Uint8Array(),
    stageRemove: (_id, _sig) => new Uint8Array(),
    confirmRemove: (_id) => {},
    abortRemove: (_id) => {},
    pendingKind: (_id) => 0,
    pendingTarget: (_id) => '',
    pendingCommit: (_id) => new Uint8Array(),
    pendingWelcome: (_id) => new Uint8Array(),
    mailboxTag: (subject) => 'ctag-' + subject,
    joinFromWelcome: () => '',
    encrypt: (_id, p) => p,
    receive: () => encodeList([new Uint8Array(), new Uint8Array([3])]),
    roster: (_id) => [sig],
    isSelfConversation: (_id) => false,
    groupMailbox: (_id) => '',
    authorizeDevice: () => '',
    authorizeScannedDevice: () => new Uint8Array(104),
    adoptCertificate: () => {},
    recoverWithSeed: () => {},
    reauthorizeAtEpoch: () => {},
    certEpoch: () => 0,
    wipe: () => {},
  };
}

const noopTransport = {
  setConsumerIdResolver: () => {},
  subscribe: () => {},
  publish: () => {},
  ack: () => {},
  sendOffer: () => {},
  sendAccept: () => {},
  close: () => {},
} as unknown as Transport;

// Live deps whose seal/restore round-trip an identity (so a restored Conversation keeps its
// signature), and whose factory mints a UNIQUE identity each call (so a failure to restore is
// visible as a changed contact). Used to exercise per-account identity persistence.
let convCounter = 0;
function roundTripLiveDeps(): GroupDeps {
  return {
    connect: () => noopTransport,
    makeConversation: () => fakeConv(`sig${++convCounter}`),
    pushEvent: () => {},
    schedule: () => 0,
    cancel: () => {},
    sealConversation: (conv) => new TextEncoder().encode(conv.signaturePublicKeyHex()),
    restoreConversation: (_msk, sealed) => fakeConv(new TextDecoder().decode(sealed)),
    sasDigestHex: () => '00'.repeat(32),
  };
}

// Minimal live deps so the controller builds its LifetimeManager. The live transport is not
// exercised here; schedule never fires, so an armed timer does not erase mid-test.
const stubLiveDeps: GroupDeps = {
  connect: () => {
    throw new Error('live transport not used in this test');
  },
  makeConversation: () => {
    throw new Error('wasm not used in this test');
  },
  pushEvent: () => {},
  schedule: () => 0,
  cancel: () => {},
  sealConversation: () => new Uint8Array(0),
  restoreConversation: () => {
    throw new Error('wasm not used in this test');
  },
  sasDigestHex: () => '00'.repeat(32),
};

const enc = new TextEncoder();
const dec = new TextDecoder();

const deriveKek: DeriveKek = async (passphrase, salt) => {
  const material = enc.encode(passphrase);
  const joined = new Uint8Array(material.length + salt.length);
  joined.set(material);
  joined.set(salt, material.length);
  return new Uint8Array(await crypto.subtle.digest('SHA-256', joined));
};

function clearStore(db: IDBDatabase, name: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const req = db.transaction(name, 'readwrite').objectStore(name).clear();
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error ?? new Error('clear failed'));
  });
}

let db: IDBDatabase;
let vault: MskVault;
let channels: ChannelStore;
let keyvault: IndexedDbKeyvaultStore;
let ctrl: AppControllerImpl;

beforeEach(async () => {
  db = await openDeadDropDb();
  for (const name of ['vault', 'mls_state', 'messages', 'channels']) {
    await clearStore(db, name);
  }
  vault = new MskVault(db, deriveKek);
  channels = new ChannelStore(db);
  keyvault = new IndexedDbKeyvaultStore(db);
  ctrl = new AppControllerImpl(vault, channels, keyvault, () => 0);
});

afterEach(() => {
  db.close();
});

describe('AppControllerImpl (real storage-backed controller)', () => {
  it('creates the account on first login and rejects a wrong passphrase afterward', async () => {
    expect((await ctrl.unlock('alice', 'correct horse')).ok).toBe(true);
    const ctrl2 = new AppControllerImpl(vault, channels, keyvault, () => 0);
    expect((await ctrl2.unlock('alice', 'correct horse')).ok).toBe(true);
    expect((await ctrl2.unlock('alice', 'wrong')).ok).toBe(false);
  });

  it('rejects an empty username or passphrase', async () => {
    expect((await ctrl.unlock('alice', '')).ok).toBe(false);
    expect((await ctrl.unlock('', 'pass')).ok).toBe(false);
  });

  it('peerFor resolves one channel name in a single-row lookup (the notification label)', async () => {
    await ctrl.unlock('alice', 'pass');
    await ctrl.saveChannel({ id: 'raven', peer: 'RAVEN', fingerprint: '5F', status: 'secure', preview: '', unread: 0 });
    expect(await ctrl.peerFor('raven')).toBe('RAVEN');
    expect(await ctrl.peerFor('nope')).toBe(''); // unknown id: unnamed, never a throw
  });

  it('seals channel summaries at rest (no plaintext) and lists them back', async () => {
    await ctrl.unlock('alice', 'pass');
    await ctrl.saveChannel({ id: 'raven', peer: 'RAVEN', fingerprint: '5F·A2', status: 'secure', preview: 'hi', unread: 2 });

    const rec = await channels.get('raven');
    if (rec === undefined) {
      throw new Error('channel not stored');
    }
    expect(dec.decode(rec.blob)).not.toContain('RAVEN'); // the contact graph is sealed

    const list = await ctrl.listChannels();
    expect(list).toHaveLength(1);
    expect(list[0]?.peer).toBe('RAVEN');
    expect(list[0]?.unread).toBe(2);
  });

  it('isolates accounts on one device (one user does not see another user channels)', async () => {
    await ctrl.unlock('alice', 'pass-a');
    await ctrl.saveChannel({ id: 'raven', peer: 'RAVEN', fingerprint: '5F', status: 'secure', preview: '', unread: 0 });
    expect((await ctrl.listChannels()).length).toBe(1);

    // A different account on the SAME device and stores must not see alice's channel: it cannot be
    // decrypted under bob's MSK, so it is skipped.
    const bob = new AppControllerImpl(vault, channels, keyvault, () => 0);
    await bob.unlock('bob', 'pass-b');
    expect((await bob.listChannels()).length).toBe(0);
  });

  it('the connect-time sweep deletes a dead channel summary but keeps held and foreign rows', async () => {
    const conv: GroupConversationLike = { ...fakeConv(), listConversations: () => ['abcd'], groupMailbox: () => 'gmbox' };
    const tx = {
      setConsumerIdResolver: () => {},
      subscribe: () => {},
      publish: () => {},
      ack: () => {},
      sendOffer: () => {},
      sendAccept: () => {},
      close: () => {},
    } as unknown as Transport;
    const deps: GroupDeps = {
      connect: () => tx,
      makeConversation: () => conv,
      pushEvent: () => {},
      schedule: () => 0,
      cancel: () => {},
      sealConversation: () => new Uint8Array(),
      restoreConversation: () => conv,
      sasDigestHex: () => '00'.repeat(32),
    };
    const live = new AppControllerImpl(vault, channels, keyvault, () => 0, undefined, deps, new SealedSessionStore(db));
    await live.unlock('alice', 'pass');
    // A held conversation's summary, a DEAD one (evicted long ago; the wasm no longer holds it), and a
    // foreign account's row that must never be touched.
    await live.saveChannel({ id: 'c-abcd', peer: 'PEER', fingerprint: '', status: 'secure', preview: '', unread: 0 });
    await live.saveChannel({ id: 'c-dead', peer: 'GHOST', fingerprint: '', status: 'secure', preview: '', unread: 0 });
    const bob = new AppControllerImpl(vault, channels, keyvault, () => 0);
    await bob.unlock('bob', 'pass-b');
    await bob.saveChannel({ id: 'bobs', peer: 'BOB-PEER', fingerprint: '', status: 'secure', preview: '', unread: 0 });
    // Connect: the restore holds only c-abcd, so the sweep removes c-dead, keeps c-abcd, ignores bobs.
    await live.connectGateway('ws://x/ws');
    expect((await live.listChannels()).map((c) => c.id)).toEqual(['c-abcd']);
    expect(await channels.get('c-dead')).toBeUndefined(); // the ghost row is gone for good
    expect(await channels.get('bobs')).toBeDefined(); // the other account's row is untouched
  });

  it('removeConversation closes for good: summary gone, wasm forgotten, and a reconnect cannot resurrect it', async () => {
    const heldRef = { v: ['abcd'] };
    const conv: GroupConversationLike = {
      ...fakeConv(),
      listConversations: () => heldRef.v.slice(),
      groupMailbox: () => 'gmbox',
      closeConversation: (gid: string): void => {
        heldRef.v = heldRef.v.filter((g) => g !== gid);
      },
    };
    const tx = {
      setConsumerIdResolver: () => {},
      subscribe: () => {},
      publish: () => {},
      ack: () => {},
      sendOffer: () => {},
      sendAccept: () => {},
      close: () => {},
      takePending: () => [], // the second connect (the resurrection check) drains the paced queue
    } as unknown as Transport;
    const deps: GroupDeps = {
      connect: () => tx,
      makeConversation: () => conv,
      pushEvent: () => {},
      schedule: () => 0,
      cancel: () => {},
      sealConversation: () => new Uint8Array(),
      restoreConversation: () => conv,
      sasDigestHex: () => '00'.repeat(32),
    };
    const live = new AppControllerImpl(vault, channels, keyvault, () => 0, undefined, deps, new SealedSessionStore(db));
    await live.unlock('alice', 'pass');
    await live.connectGateway('ws://x/ws');
    await live.saveChannel({ id: 'c-abcd', peer: 'DEAD', fingerprint: '', status: 'secure', preview: '', unread: 0 });
    await live.removeConversation('c-abcd');
    expect(await channels.get('c-abcd')).toBeUndefined(); // the row is gone
    expect(heldRef.v).toEqual([]); // and the wasm dropped the group
    // Resurrection check: even when the group somehow survives in the sealed state (an old-wasm close,
    // or a parallel tab's reseal), the restore skips it via the durable closed set and re-closes it.
    heldRef.v = ['abcd'];
    await live.connectGateway('ws://x/ws');
    expect((await live.listChannels()).map((c) => c.id)).toEqual([]);
    expect(heldRef.v).toEqual([]); // the restore re-closed the resurrected copy
  });

  it('a wasm-refused close falls back to hide-and-record: the group is never destroyed', async () => {
    const heldRef = { v: ['abcd'] };
    const conv: GroupConversationLike = {
      ...fakeConv(),
      listConversations: () => heldRef.v.slice(),
      groupMailbox: () => 'gmbox',
      closeConversation: (): void => {
        throw new Error('refusing to close the own-devices group'); // the ghost-classified self-group
      },
    };
    const tx = {
      setConsumerIdResolver: () => {},
      subscribe: () => {},
      publish: () => {},
      ack: () => {},
      sendOffer: () => {},
      sendAccept: () => {},
      close: () => {},
      takePending: () => [],
    } as unknown as Transport;
    const deps: GroupDeps = {
      connect: () => tx,
      makeConversation: () => conv,
      pushEvent: () => {},
      schedule: () => 0,
      cancel: () => {},
      sealConversation: () => new Uint8Array(),
      restoreConversation: () => conv,
      sasDigestHex: () => '00'.repeat(32),
    };
    const live = new AppControllerImpl(vault, channels, keyvault, () => 0, undefined, deps, new SealedSessionStore(db));
    await live.unlock('alice', 'pass');
    await live.connectGateway('ws://x/ws');
    await live.saveChannel({ id: 'c-abcd', peer: 'GHOST', fingerprint: '', status: 'secure', preview: '', unread: 0 });
    await live.removeConversation('c-abcd'); // the wasm guard refuses: fall back, never throw to the UI
    expect(await channels.get('c-abcd')).toBeUndefined(); // the row is hidden
    expect(heldRef.v).toEqual(['abcd']); // and the group SURVIVES (recorded self, not closed)
    // The next connect restores it normally: the id landed in the SELF set, never the closed set.
    await live.connectGateway('ws://x/ws');
    expect(heldRef.v).toEqual(['abcd']);
    expect((await live.listChannels()).map((c) => c.id)).toEqual([]); // stays hidden via the self set
  });

  it('the connect-time reclassify pass hides a self-group summary with no channels render at all', async () => {
    const conv: GroupConversationLike = {
      ...fakeConv(),
      listConversations: () => ['abcd', '1234'], // both held: the self-group AND a real peer conversation
      groupMailbox: () => 'gmbox',
      isSelfConversation: (id?: string) => id === 'abcd', // the cert settled: only the self-group classifies
    };
    const tx = {
      setConsumerIdResolver: () => {},
      subscribe: () => {},
      publish: () => {},
      ack: () => {},
      sendOffer: () => {},
      sendAccept: () => {},
      close: () => {},
    } as unknown as Transport;
    const deps: GroupDeps = {
      connect: () => tx,
      makeConversation: () => conv,
      pushEvent: () => {},
      schedule: () => 0,
      cancel: () => {},
      sealConversation: () => new Uint8Array(),
      restoreConversation: () => conv,
      sasDigestHex: () => '00'.repeat(32),
    };
    const live = new AppControllerImpl(vault, channels, keyvault, () => 0, undefined, deps, new SealedSessionStore(db));
    await live.unlock('alice', 'pass');
    // The ghost row exists BEFORE this session connects (minted at join time on this device).
    await live.saveChannel({ id: 'c-abcd', peer: 'GHOST', fingerprint: '', status: 'secure', preview: '', unread: 0 });
    await live.saveChannel({ id: 'c-1234', peer: 'RAVEN', fingerprint: '5F', status: 'secure', preview: '', unread: 0 });
    await live.connectGateway('ws://x/ws');
    // Healed at connect, deterministically: no listChannels render was needed.
    expect(await channels.get('c-abcd')).toBeUndefined();
    expect(await channels.get('c-1234')).toBeDefined(); // the peer row is untouched
    expect((await live.listChannels()).map((c) => c.id)).toEqual(['c-1234']);
  });

  it('blockConversation on a self-classified id hides and records it instead of blocking our own devices', async () => {
    const conv: GroupConversationLike = {
      ...fakeConv(),
      listConversations: () => ['abcd'],
      groupMailbox: () => 'gmbox',
      isSelfConversation: () => true,
    };
    const tx = {
      setConsumerIdResolver: () => {},
      subscribe: () => {},
      publish: () => {},
      ack: () => {},
      sendOffer: () => {},
      sendAccept: () => {},
      close: () => {},
    } as unknown as Transport;
    const deps: GroupDeps = {
      connect: () => tx,
      makeConversation: () => conv,
      pushEvent: () => {},
      schedule: () => 0,
      cancel: () => {},
      sealConversation: () => new Uint8Array(),
      restoreConversation: () => conv,
      sasDigestHex: () => '00'.repeat(32),
    };
    const live = new AppControllerImpl(vault, channels, keyvault, () => 0, undefined, deps, new SealedSessionStore(db));
    await live.unlock('alice', 'pass');
    await live.connectGateway('ws://x/ws');
    await live.saveChannel({ id: 'c-abcd', peer: 'GHOST', fingerprint: '', status: 'secure', preview: '', unread: 0 });
    await live.blockConversation('c-abcd');
    // Blocking our own sibling devices would silently drop future self-group Welcomes; instead the row
    // is hidden and recorded, the block list stays empty, and the live session survives.
    expect(await live.listBlocked()).toEqual([]);
    expect(await channels.get('c-abcd')).toBeUndefined();
    expect((await live.listChannels()).map((c) => c.id)).toEqual([]);
  });

  it('Note to Self renders the union of self-copy histories, with revoke controls only on the open id', async () => {
    const conv: GroupConversationLike = {
      ...fakeConv(),
      listConversations: () => ['aaaa', 'bbbb'], // the canonical group and a superseded self-copy
      groupMailbox: () => 'gmbox',
      isSelfConversation: () => true,
    };
    const tx = {
      setConsumerIdResolver: () => {},
      subscribe: () => {},
      publish: () => {},
      ack: () => {},
      sendOffer: () => {},
      sendAccept: () => {},
      close: () => {},
    } as unknown as Transport;
    const deps: GroupDeps = {
      connect: () => tx,
      makeConversation: () => conv,
      pushEvent: () => {},
      schedule: () => 0,
      cancel: () => {},
      sealConversation: () => new Uint8Array(),
      restoreConversation: () => conv,
      sasDigestHex: () => '00'.repeat(32),
    };
    const mskKey = await importMsk((await vault.create(await accountIdFor('alice'), credentialFor('alice', 'pass'))).slice());
    await keyvault.put(
      await seal(mskKey, { messageId: 'newer', conversationId: 'c-aaaa', direction: 'out', lifetime: { kind: 'until-revoked' } }, enc.encode('new note'), 1),
    );
    await keyvault.put(
      await seal(mskKey, { messageId: 'older', conversationId: 'c-bbbb', direction: 'out', lifetime: { kind: 'until-revoked' } }, enc.encode('old note'), 0),
    );
    const live = new AppControllerImpl(vault, channels, keyvault, () => 0, undefined, deps, new SealedSessionStore(db));
    await live.unlock('alice', 'pass');
    await live.connectGateway('ws://x/ws');
    const t = await live.openChannel('c-aaaa');
    expect(t.selfNote).toBe(true);
    const msgs = t.log.filter((e) => e.kind === 'message');
    // BOTH histories render (the superseded copy's notes stay readable), oldest first.
    expect(msgs.map((m) => (m.kind === 'message' ? m.text : ''))).toEqual(['old note', 'new note']);
    // The revoke control only appears on the OPEN conversation's own message: the UI revokes against
    // the open id, so a control on the superseded copy's note would silently no-op (a dead button).
    const byText = (txt: string) => msgs.find((m) => m.kind === 'message' && m.text === txt);
    expect(byText('new note')?.kind === 'message' && byText('new note')?.canRevoke).toBe(true);
    expect(byText('old note')?.kind === 'message' ? byText('old note')?.canRevoke : undefined).toBeUndefined();
  });

  it('hides an orphaned self-group channel row, cleans it up, and keeps it hidden after the predicate goes null (Bug 2)', async () => {
    const published: EnvelopeMsg[] = [];
    let selfFlag = true; // the live isSelfConversation predicate; flip it to null-out the live filter later
    const conv: GroupConversationLike = {
      ...fakeConv(),
      listConversations: () => ['abcd'], // restores a session under conversationId c-abcd
      groupMailbox: () => 'gmbox',
      isSelfConversation: () => selfFlag,
    };
    const tx = {
      setConsumerIdResolver: () => {},
      subscribe: () => {},
      publish: (e: EnvelopeMsg) => published.push(e),
      ack: () => {},
      sendOffer: () => {},
      sendAccept: () => {},
      close: () => {},
    } as unknown as Transport;
    const deps: GroupDeps = {
      connect: () => tx,
      makeConversation: () => conv,
      pushEvent: () => {},
      schedule: () => 0,
      cancel: () => {},
      sealConversation: () => new Uint8Array(),
      restoreConversation: () => conv,
      sasDigestHex: () => '00'.repeat(32),
    };
    const live = new AppControllerImpl(vault, channels, keyvault, () => 0, undefined, deps, new SealedSessionStore(db));
    await live.unlock('alice', 'pass');
    await live.connectGateway('ws://x/ws');
    // A stale self-group summary (an older-build artifact, or one minted before a fresh device's cert
    // settled), plus a real peer channel.
    await live.saveChannel({ id: 'c-abcd', peer: 'alice-phone', fingerprint: '', status: 'secure', preview: '', unread: 0 });
    await live.saveChannel({ id: 'raven', peer: 'RAVEN', fingerprint: '5F', status: 'secure', preview: '', unread: 0 });
    // listChannels hides the self-group and lists only the real peer, and proactively deletes the orphan.
    expect((await live.listChannels()).map((c) => c.id)).toEqual(['raven']);
    expect(await channels.get('c-abcd')).toBeUndefined();
    // Durable: even after the live predicate goes null (cert unsettled) and the summary is re-minted, the
    // recorded self-group id keeps it out of the list.
    selfFlag = false;
    await live.saveChannel({ id: 'c-abcd', peer: 'alice-phone', fingerprint: '', status: 'secure', preview: '', unread: 0 });
    expect((await live.listChannels()).map((c) => c.id)).toEqual(['raven']);
    expect(published.length).toBeGreaterThanOrEqual(0); // (the transport is only here to build the live channel)
  });

  it('opens a channel and reconstructs its message history from the keyvault under the MSK', async () => {
    // Seed: derive the same MSK the controller will unlock, then seal a message + channel under it.
    const mskRaw = await vault.create(await accountIdFor('alice'), credentialFor('alice', 'pass'));
    const mskKey = await importMsk(mskRaw.slice());
    const summary = { id: 'raven', peer: 'RAVEN', fingerprint: '5F', status: 'secure' as const, preview: '', unread: 0 };
    await channels.put({ id: 'raven', blob: await sealUnder(mskKey, enc.encode(JSON.stringify(summary)), 'channel:raven') });
    const rec = await seal(
      mskKey,
      { messageId: 'm1', conversationId: 'raven', direction: 'in', lifetime: { kind: 'duration', seconds: 60 } },
      enc.encode('drop confirmed at the usual place'),
      0,
    );
    await keyvault.put(rec);

    expect((await ctrl.unlock('alice', 'pass')).ok).toBe(true);
    const t = await ctrl.openChannel('raven');
    expect(t.peer).toBe('RAVEN');
    expect(t.secure).toBe(true);

    const msg = t.log.find((e) => e.kind === 'message');
    expect(msg?.kind).toBe('message');
    if (msg?.kind === 'message') {
      expect(msg.text).toBe('drop confirmed at the usual place');
      expect(msg.sender).toBe('RAVEN');
    }
  });

  it('holds an inbound message unarmed and starts its countdown when the conversation is opened', async () => {
    const live = new AppControllerImpl(vault, channels, keyvault, () => 0, undefined, stubLiveDeps);

    // Seed an INBOUND duration message stored UNARMED, exactly as the live receive path stores it.
    const mskKey = await importMsk((await vault.create(await accountIdFor('alice'), credentialFor('alice', 'pass'))).slice());
    const summary = { id: 'c1', peer: 'B7', fingerprint: 'AA', status: 'secure' as const, preview: '', unread: 0 };
    await channels.put({ id: 'c1', blob: await sealUnder(mskKey, enc.encode(JSON.stringify(summary)), 'channel:c1') });
    await keyvault.put(
      await seal(
        mskKey,
        { messageId: 'in1', conversationId: 'c1', direction: 'in', lifetime: { kind: 'duration', seconds: 60 } },
        enc.encode('held until you look'),
        0,
        false, // unarmed
      ),
    );
    expect((await keyvault.get('in1'))?.expiresAtMs).toBeNull();

    // Logging in must NOT erase the unseen message (sweepExpired skips unarmed records).
    await live.unlock('alice', 'pass');
    expect(await keyvault.get('in1')).toBeDefined();

    // Opening the conversation is the view: the timer starts and the message renders.
    const t = await live.openChannel('c1');
    expect((await keyvault.get('in1'))?.expiresAtMs).toBe(60_000); // now(0) + 60s
    const msg = t.log.find((e) => e.kind === 'message');
    expect(msg?.kind).toBe('message');
    if (msg?.kind === 'message') {
      expect(msg.text).toBe('held until you look');
      expect(msg.sender).toBe('B7');
    }
  });

  it('renders a burn-on-read message exactly once on view, then only its destroyed tombstone', async () => {
    const live = new AppControllerImpl(vault, channels, keyvault, () => 0, undefined, stubLiveDeps);

    // Seed an inbound burn message (stored as the live receive path stores it) AND our own outbound
    // one (stored as the send path stores it): both go through the same read latch on first view.
    const mskKey = await importMsk((await vault.create(await accountIdFor('alice'), credentialFor('alice', 'pass'))).slice());
    const summary = { id: 'c1', peer: 'B7', fingerprint: 'AA', status: 'secure' as const, preview: '', unread: 0 };
    await channels.put({ id: 'c1', blob: await sealUnder(mskKey, enc.encode(JSON.stringify(summary)), 'channel:c1') });
    await keyvault.put(
      await seal(
        mskKey,
        { messageId: 'bin', conversationId: 'c1', direction: 'in', lifetime: { kind: 'burn-on-read' } },
        enc.encode('for your eyes only'),
        0,
        false,
      ),
    );
    await keyvault.put(
      await seal(
        mskKey,
        { messageId: 'bout', conversationId: 'c1', direction: 'out', lifetime: { kind: 'burn-on-read' } },
        enc.encode('sent secret'),
        0,
      ),
    );
    await live.unlock('alice', 'pass');

    // Neither login nor the expiry sweep touches an unread burn message (no timer to fire).
    expect(await keyvault.get('bin')).toBeDefined();

    // First view renders both, and the stored keys are ALREADY destroyed (read latch: the key dies
    // before the plaintext is returned).
    const first = await live.openChannel('c1');
    expect(first.log.some((e) => e.kind === 'message' && e.text === 'for your eyes only' && e.sender === 'B7')).toBe(true);
    expect(first.log.some((e) => e.kind === 'message' && e.text === 'sent secret' && e.sender === 'YOU')).toBe(true);
    for (const id of ['bin', 'bout']) {
      const latched = await keyvault.get(id);
      expect(latched?.read).toBe(true);
      expect(latched?.wrappedPmk.length).toBe(0); // crypto-erased: only the read-latch tombstone remains
      expect(latched?.ciphertext.length).toBe(0);
    }

    // Every later view shows the tombstones, never the text.
    const second = await live.openChannel('c1');
    expect(second.log.some((e) => e.kind === 'message' && (e.text === 'for your eyes only' || e.text === 'sent secret'))).toBe(false);
    expect(second.log.filter((e) => e.kind === 'destroyed')).toHaveLength(2);
  });

  it('holds a burn message unopened while the view is not secure, then spends the read on a secure view', async () => {
    const live = new AppControllerImpl(vault, channels, keyvault, () => 0, undefined, stubLiveDeps);
    const mskKey = await importMsk((await vault.create(await accountIdFor('alice'), credentialFor('alice', 'pass'))).slice());
    // NO channel summary yet: openChannel renders a DEAD view (secure=false), e.g. mid-restore.
    await keyvault.put(
      await seal(
        mskKey,
        { messageId: 'bheld', conversationId: 'c1', direction: 'in', lifetime: { kind: 'burn-on-read' } },
        enc.encode('wait for me'),
        0,
        false,
      ),
    );
    await live.unlock('alice', 'pass');
    const dead = await live.openChannel('c1');
    expect(dead.secure).toBe(false);
    expect(dead.log.some((e) => e.kind === 'message' && e.text === 'wait for me')).toBe(false);
    expect(dead.log.some((e) => e.kind === 'destroyed')).toBe(false); // held, never falsely labeled destroyed
    expect((await keyvault.get('bheld'))?.read).toBe(false); // the one read is still unspent

    // The summary lands (the channel heals): the next view spends the read and renders it once.
    const summary = { id: 'c1', peer: 'B7', fingerprint: 'AA', status: 'secure' as const, preview: '', unread: 0 };
    await channels.put({ id: 'c1', blob: await sealUnder(mskKey, enc.encode(JSON.stringify(summary)), 'channel:c1') });
    const healed = await live.openChannel('c1');
    expect(healed.log.some((e) => e.kind === 'message' && e.text === 'wait for me')).toBe(true);
    expect((await keyvault.get('bheld'))?.read).toBe(true);
  });

  it('marks our account\'s until-revoked messages revocable and applies an inbound revoke only within its contract', async () => {
    const live = new AppControllerImpl(vault, channels, keyvault, () => 0, undefined, stubLiveDeps);
    const mskKey = await importMsk((await vault.create(await accountIdFor('alice'), credentialFor('alice', 'pass'))).slice());
    const summary = { id: 'c1', peer: 'B7', fingerprint: 'AA', status: 'secure' as const, preview: '', unread: 0 };
    await channels.put({ id: 'c1', blob: await sealUnder(mskKey, enc.encode(JSON.stringify(summary)), 'channel:c1') });
    const put = async (messageId: string, direction: 'in' | 'out', kind: 'until-revoked' | 'duration', ownAuthored = false): Promise<void> => {
      await keyvault.put(
        await seal(
          mskKey,
          {
            messageId,
            conversationId: 'c1',
            direction,
            lifetime: kind === 'duration' ? { kind: 'duration', seconds: 60 } : { kind: 'until-revoked' },
            ownAuthored,
          },
          enc.encode(messageId),
          0,
          direction === 'out',
        ),
      );
    };
    await put('keep-in', 'in', 'until-revoked');
    await put('keep-in-own', 'in', 'until-revoked', true); // synced from a sibling device of OUR account
    await put('keep-out', 'out', 'until-revoked');
    await put('dur-in', 'in', 'duration');
    await live.unlock('alice', 'pass');

    // The view flags OUR ACCOUNT's until-revoked messages as revocable: the one authored on this
    // device (out) AND the one synced from a sibling device (in + ownAuthored). Never a peer's.
    const t = await live.openChannel('c1');
    const mine = t.log.find((e) => e.kind === 'message' && e.text === 'keep-out');
    expect(mine?.kind === 'message' && mine.canRevoke === true && mine.messageId === 'keep-out').toBe(true);
    const sibling = t.log.find((e) => e.kind === 'message' && e.text === 'keep-in-own');
    expect(sibling?.kind === 'message' && sibling.canRevoke === true && sibling.messageId === 'keep-in-own').toBe(true);
    const theirs = t.log.find((e) => e.kind === 'message' && e.text === 'keep-in');
    expect(theirs?.kind === 'message' && theirs.canRevoke === undefined).toBe(true);

    // An inbound revoke is applied ONLY to an until-revoked record of the same conversation, and a
    // PEER's frame (fromOwnAccount false) never touches our own outbound copy.
    await live.applyInboundRevoke('other-conversation', 'keep-in', false);
    expect(await keyvault.get('keep-in')).toBeDefined();
    await live.applyInboundRevoke('other-conversation', 'keep-out', true); // wrong conversation refused even from a sibling
    expect(await keyvault.get('keep-out')).toBeDefined();
    await live.applyInboundRevoke('c1', 'keep-out', false);
    expect(await keyvault.get('keep-out')).toBeDefined();
    await live.applyInboundRevoke('c1', 'dur-in', false);
    expect(await keyvault.get('dur-in')).toBeDefined();
    await live.applyInboundRevoke('c1', 'keep-in', false);
    expect(await keyvault.get('keep-in')).toBeUndefined(); // crypto-erased
    await live.applyInboundRevoke('c1', 'keep-in', false); // idempotent, no throw
    // A sibling's revoke (MLS-authenticated as our own account) DOES erase the authoring device's
    // outbound copy: the account revoked its message, whichever device issued it.
    await live.applyInboundRevoke('c1', 'keep-out', true);
    expect(await keyvault.get('keep-out')).toBeUndefined();
    // And the sibling-synced inbound copy participates like any inbound until-revoked record.
    await live.applyInboundRevoke('c1', 'keep-in-own', true);
    expect(await keyvault.get('keep-in-own')).toBeUndefined();
  });

  it('Note to Self renders the union of self-copy histories, with revoke controls only on the open id', async () => {
    const live = new AppControllerImpl(vault, channels, keyvault, () => 0, undefined, stubLiveDeps, new SealedSessionStore(db));
    const mskKey = await importMsk((await vault.create(await accountIdFor('alice'), credentialFor('alice', 'pass'))).slice());
    const put = async (messageId: string, conversationId: string): Promise<void> => {
      await keyvault.put(
        await seal(mskKey, { messageId, conversationId, direction: 'out', lifetime: { kind: 'until-revoked' } }, enc.encode(messageId), 0, true),
      );
    };
    await put('note-old', 'c-old');
    await put('note-new', 'c-canon');
    await live.unlock('alice', 'pass');
    await live.openChannel('c-old', { forceSelf: true }); // the superseded copy gets recorded as self
    const t = await live.openChannel('c-canon', { forceSelf: true });
    const texts = t.log.filter((e) => e.kind === 'message').map((e) => (e.kind === 'message' ? e.text : ''));
    expect(texts).toContain('note-new');
    expect(texts).toContain('note-old'); // the superseded copy's notes stay readable after the heal
    // The revoke control only rides the OPEN conversation's records: the UI revokes against the open
    // id, and a mismatched record would silently no-op (a dead control).
    const oldNote = t.log.find((e) => e.kind === 'message' && e.text === 'note-old');
    expect(oldNote?.kind === 'message' && oldNote.canRevoke === undefined).toBe(true);
    const newNote = t.log.find((e) => e.kind === 'message' && e.text === 'note-new');
    expect(newNote?.kind === 'message' && newNote.canRevoke === true).toBe(true);
  });

  // Live deps for the sender-side revoke tests: one restored conversation ('abcd' => 'c-abcd'), a
  // transport that records publishes and exposes the handlers (to echo the gateway receipt back), and
  // a schedule that captures timers (to fire the receipt-timeout backstop by hand).
  function receiptHarness(): {
    deps: GroupDeps;
    published: EnvelopeMsg[];
    scheduled: Array<() => void>;
    handlers: () => TransportHandlers;
  } {
    const published: EnvelopeMsg[] = [];
    const scheduled: Array<() => void> = [];
    let h: TransportHandlers | undefined;
    const tx = {
      setConsumerIdResolver: () => {},
  subscribe: () => {},
      publish: (e: EnvelopeMsg) => published.push(e),
      ack: () => {},
      sendOffer: () => {},
      sendAccept: () => {},
      close: () => {},
    } as unknown as Transport;
    const conv: GroupConversationLike = { ...fakeConv(), listConversations: () => ['abcd'], groupMailbox: () => 'gmbox' };
    const deps: GroupDeps = {
      connect: (_url, hh) => {
        h = hh;
        return tx;
      },
      makeConversation: () => conv,
      pushEvent: () => {},
      schedule: (_ms, cb) => {
        scheduled.push(cb);
        return scheduled.length;
      },
      cancel: () => {},
      sealConversation: () => new Uint8Array(),
      restoreConversation: () => conv,
      sasDigestHex: () => '00'.repeat(32),
    };
    return {
      deps,
      published,
      scheduled,
      handlers: () => {
        if (h === undefined) {
          throw new Error('connectGateway first');
        }
        return h;
      },
    };
  }

  it('revokeMessage crypto-erases the local copy only after the gateway receipt confirms the revoke frame', async () => {
    const harness = receiptHarness();
    const live = new AppControllerImpl(vault, channels, keyvault, () => 0, undefined, harness.deps);
    const mskKey = await importMsk((await vault.create(await accountIdFor('alice'), credentialFor('alice', 'pass'))).slice());
    await keyvault.put(
      await seal(
        mskKey,
        { messageId: 'm1', conversationId: 'c-abcd', direction: 'out', lifetime: { kind: 'until-revoked' } },
        enc.encode('recall me'),
        0,
        true,
      ),
    );
    await live.unlock('alice', 'pass');
    await live.connectGateway('ws://x/ws');

    const pending = live.revokeMessage('c-abcd', 'm1');
    // The revoke frame was handed off, but no receipt came back yet: the local copy MUST be intact.
    while (harness.published.length === 0) {
      await new Promise((r) => setTimeout(r, 0));
    }
    expect(await keyvault.get('m1')).toBeDefined();
    harness.handlers().onReceipt(harness.published[0]!.messageId); // the gateway confirms the revoke frame
    await pending;
    expect(await keyvault.get('m1')).toBeUndefined(); // crypto-erased only after the receipt
  });

  it('revokeMessage keeps the local copy when the gateway receipt times out (the command may be lost)', async () => {
    const harness = receiptHarness();
    const live = new AppControllerImpl(vault, channels, keyvault, () => 0, undefined, harness.deps);
    const mskKey = await importMsk((await vault.create(await accountIdFor('alice'), credentialFor('alice', 'pass'))).slice());
    await keyvault.put(
      await seal(
        mskKey,
        { messageId: 'm1', conversationId: 'c-abcd', direction: 'out', lifetime: { kind: 'until-revoked' } },
        enc.encode('recall me'),
        0,
        true,
      ),
    );
    await live.unlock('alice', 'pass');
    await live.connectGateway('ws://x/ws');

    const before = harness.scheduled.length;
    const pending = live.revokeMessage('c-abcd', 'm1');
    const rejection = expect(pending).rejects.toThrow(/did not confirm/);
    while (harness.published.length === 0) {
      await new Promise((r) => setTimeout(r, 0));
    }
    harness.scheduled[before]!(); // the receipt-timeout backstop fires: no receipt ever arrived
    await rejection;
    expect(await keyvault.get('m1')).toBeDefined(); // the copy survives, so the control is still offered
  });

  it('restores a per-account identity across logins so the contact is stable', async () => {
    const sessions = new SealedSessionStore(db);
    const first = new AppControllerImpl(vault, channels, keyvault, () => 0, undefined, roundTripLiveDeps(), sessions);
    await first.unlock('alice', 'pass');
    const c1 = await first.connectGateway('ws://x/ws'); // mints + persists alice's identity

    // A fresh controller (simulating a reload) over the SAME stores and username must restore it.
    const second = new AppControllerImpl(vault, channels, keyvault, () => 0, undefined, roundTripLiveDeps(), sessions);
    await second.unlock('alice', 'pass');
    const c2 = await second.connectGateway('ws://x/ws');
    expect(c2.selfContact).toBe(c1.selfContact);

    // A different username on the same device gets a DIFFERENT identity.
    const other = new AppControllerImpl(vault, channels, keyvault, () => 0, undefined, roundTripLiveDeps(), sessions);
    await other.unlock('bob', 'pass');
    const c3 = await other.connectGateway('ws://x/ws');
    expect(c3.selfContact).not.toBe(c1.selfContact);
  });

  it('gives an away auto-reply when away is on, then holds off within the cooldown', async () => {
    const sessions = new SealedSessionStore(db);
    let clock = 1000;
    const ctrl2 = new AppControllerImpl(vault, channels, keyvault, () => clock, undefined, undefined, sessions);
    await ctrl2.unlock('alice', 'pass');
    expect(await ctrl2.awayReplyText('c1', 'RAVEN')).toBeNull(); // away is off by default
    await ctrl2.setIdentity({ icon: null, bio: '', away: { enabled: true, message: 'brb', serverSide: false } });
    expect(await ctrl2.awayReplyText('c1', 'RAVEN')).toBe('brb'); // first inbound message gets a reply
    expect(await ctrl2.awayReplyText('c1', 'RAVEN')).toBeNull(); // a second within the cooldown does not
    clock += 11 * 60 * 1000; // past the 10-minute cooldown
    expect(await ctrl2.awayReplyText('c1', 'RAVEN')).toBe('brb');
  });

  it('substitutes the AIM-style specials (%n = buddy, %d = date, %t = time) in the away reply', async () => {
    const sessions = new SealedSessionStore(db);
    // A fixed clock: 2026-06-30 15:45 local. new Date(ms) below is compared against the same components.
    const at = new Date(2026, 5, 30, 15, 45).getTime();
    const ctrl2 = new AppControllerImpl(vault, channels, keyvault, () => at, undefined, undefined, sessions);
    await ctrl2.unlock('alice', 'pass');
    await ctrl2.setIdentity({ icon: null, bio: '', away: { enabled: true, message: 'hi %n, back after %t on %d', serverSide: false } });
    expect(await ctrl2.awayReplyText('c1', 'RAVEN')).toBe('hi RAVEN, back after 3:45 PM on 6/30/2026');
  });

  it('seals and restores the buddy list, normalized and deduped, across logins', async () => {
    const sessions = new SealedSessionStore(db);
    const ctrl = new AppControllerImpl(vault, channels, keyvault, () => 0, undefined, undefined, sessions);
    await ctrl.unlock('alice', 'pass');
    expect(await ctrl.listBuddies()).toEqual([]);
    await ctrl.addBuddy('  RAVEN  '); // normalized to 'raven'
    await ctrl.addBuddy('raven'); // deduped
    const list = await ctrl.addBuddy('falcon');
    expect(list.map((b) => b.username)).toEqual(['raven', 'falcon']);
    // Survives a reload (a fresh controller over the same stores + account).
    const ctrl2 = new AppControllerImpl(vault, channels, keyvault, () => 0, undefined, undefined, sessions);
    await ctrl2.unlock('alice', 'pass');
    expect((await ctrl2.listBuddies()).map((b) => b.username)).toEqual(['raven', 'falcon']);
    expect((await ctrl2.removeBuddy('RAVEN')).map((b) => b.username)).toEqual(['falcon']);
  });

  it('normalizeBuddyMap loads a legacy Buddy[] blob and the current map shape', () => {
    // Legacy format (before cross-device sync): a plain array. Each entry becomes version 0 so a genuine
    // sibling change always wins.
    const legacy = normalizeBuddyMap([
      { username: 'raven', addedAt: 5 },
      { username: 'falcon', addedAt: 7 },
    ]);
    expect(legacy.raven).toEqual({ addedAt: 5, v: 0, removed: false, group: 'Buddies' });
    expect(legacy.falcon).toEqual({ addedAt: 7, v: 0, removed: false, group: 'Buddies' });
    // Current map shape (with versions, groups, and tombstones) round-trips, and a tombstone stays a tombstone.
    const current = normalizeBuddyMap({ raven: { addedAt: 5, v: 30, removed: false, group: 'Family' }, owl: { addedAt: 9, v: 40, removed: true, group: 'Buddies' } });
    expect(current.raven).toEqual({ addedAt: 5, v: 30, removed: false, group: 'Family' });
    expect(current.owl?.removed).toBe(true);
    // Garbage yields an empty map (a corrupt or foreign blob never throws).
    expect(normalizeBuddyMap('nonsense')).toEqual({});
    expect(normalizeBuddyMap(null)).toEqual({});
  });

  it('adopts a sibling buddy-list frame per-buddy last-writer-wins (newer add and remove win, stale ignored)', async () => {
    const sessions = new SealedSessionStore(db);
    let clock = 0;
    const ctrl = new AppControllerImpl(vault, channels, keyvault, () => clock, undefined, undefined, sessions);
    await ctrl.unlock('alice', 'pass');
    clock = 10;
    await ctrl.addBuddy('raven'); // local raven at version 10
    const frame = (buddies: Record<string, { addedAt: number; v: number; removed: boolean }>): Uint8Array =>
      enc.encode(JSON.stringify({ buddies }));
    // A sibling's add of 'falcon' (version 20) is adopted alongside our 'raven' (no concurrent-add loss).
    await ctrl.adoptBuddies(frame({ falcon: { addedAt: 2, v: 20, removed: false } }));
    expect((await ctrl.listBuddies()).map((b) => b.username).sort()).toEqual(['falcon', 'raven']);
    // A STALE remove of 'raven' (version 5, older than our add at 10) is ignored: raven stays.
    await ctrl.adoptBuddies(frame({ raven: { addedAt: 1, v: 5, removed: true } }));
    expect((await ctrl.listBuddies()).map((b) => b.username)).toContain('raven');
    // A NEWER remove of 'raven' (version 15) is adopted as a tombstone: raven disappears everywhere.
    await ctrl.adoptBuddies(frame({ raven: { addedAt: 1, v: 15, removed: true } }));
    expect((await ctrl.listBuddies()).map((b) => b.username)).toEqual(['falcon']);
    // The tombstone persists across a reload, so a stale add cannot resurrect raven.
    const ctrl2 = new AppControllerImpl(vault, channels, keyvault, () => clock, undefined, undefined, sessions);
    await ctrl2.unlock('alice', 'pass');
    await ctrl2.adoptBuddies(frame({ raven: { addedAt: 1, v: 12, removed: false } })); // older than the v=15 tombstone
    expect((await ctrl2.listBuddies()).map((b) => b.username)).toEqual(['falcon']);
  });

  it('resolves a same-version add-vs-remove tie deterministically (removal wins), so presence converges', async () => {
    const sessions = new SealedSessionStore(db);
    let clock = 0;
    const ctrl = new AppControllerImpl(vault, channels, keyvault, () => clock, undefined, undefined, sessions);
    await ctrl.unlock('alice', 'pass');
    clock = 100;
    await ctrl.addBuddy('raven'); // local: raven present at version 100
    // A sibling's REMOVE of raven at the SAME version 100 must win the tie (deterministic), so raven goes.
    await ctrl.adoptBuddies(enc.encode(JSON.stringify({ buddies: { raven: { addedAt: 1, v: 100, removed: true } } })));
    expect((await ctrl.listBuddies()).map((b) => b.username)).toEqual([]);
    // The reverse order converges identically: a same-version ADD does NOT revive a tombstone.
    await ctrl.adoptBuddies(enc.encode(JSON.stringify({ buddies: { raven: { addedAt: 1, v: 100, removed: false } } })));
    expect((await ctrl.listBuddies()).map((b) => b.username)).toEqual([]);
  });

  it('normalizeGroupMap coerces a stored map and rejects garbage', () => {
    const map = normalizeGroupMap({ Family: { v: 30, removed: false, order: 2 }, Old: { v: 40, removed: true, order: 1 } });
    expect(map.Family).toEqual({ v: 30, removed: false, order: 2 });
    expect(map.Old?.removed).toBe(true);
    // Missing fields default (v/order 0, removed false); non-objects and arrays yield an empty map.
    expect(normalizeGroupMap({ Bare: {} }).Bare).toEqual({ v: 0, removed: false, order: 0 });
    expect(normalizeGroupMap('nonsense')).toEqual({});
    expect(normalizeGroupMap([{ name: 'Family' }])).toEqual({});
    expect(normalizeGroupMap(null)).toEqual({});
  });

  it('normalizeGroupMap holds map KEYS to the local naming rules (a hostile sibling frame cannot smuggle names)', () => {
    const ent = { v: 1, removed: false, order: 0 };
    // A key with an embedded control character, an over-length key, or a whitespace doppelganger of a
    // real group (undeletable: delete lookups trim) is one this code could never have written: dropped.
    expect(normalizeGroupMap({ 'Ev\u0001il': ent })).toEqual({});
    expect(normalizeGroupMap({ ['A'.repeat(100)]: ent })).toEqual({});
    expect(normalizeGroupMap({ ' Family': ent })).toEqual({});
    expect(normalizeGroupMap({ 'Family ': ent })).toEqual({});
    // The two exact reserved alias keys pass; an alias is only honored ON them, and gets sanitized.
    const res = normalizeGroupMap({ '\u0000d': { ...ent, n: '  Pals\u0002  ' }, Family: { ...ent, n: 'sneaky' } });
    expect(res['\u0000d']).toEqual({ v: 1, removed: false, order: 0, n: 'Pals' });
    expect(res.Family).toEqual({ v: 1, removed: false, order: 0 }); // no alias on a normal group
    // A reserved-LOOKING key that is not exactly reserved is dropped (it would hide but persist forever).
    expect(normalizeGroupMap({ '\u0000x': ent })).toEqual({});
    // Non-finite versions coerce to 0 instead of poisoning LWW.
    expect(normalizeGroupMap({ Family: { v: Infinity, removed: false, order: 0 } }).Family?.v).toBe(0);
    // The entry count is capped so a runaway sibling cannot grow the sealed blob without bound.
    const big: Record<string, typeof ent> = {};
    for (let i = 0; i < 600; i++) {
      big[`G${i}`] = ent;
    }
    expect(Object.keys(normalizeGroupMap(big)).length).toBe(512);
  });

  it('adoptGroups refuses far-future versions, so one bad clock cannot pin a key against every honest write', async () => {
    const sessions = new SealedSessionStore(db);
    let clock = 1000;
    const ctrl = new AppControllerImpl(vault, channels, keyvault, () => clock, undefined, undefined, sessions);
    await ctrl.unlock('alice', 'pass');
    const frame = (groups: Record<string, { v: number; removed: boolean; order: number; n?: string }>): Uint8Array =>
      enc.encode(JSON.stringify({ groups }));
    // A poisoned far-future rename of the default group is refused outright...
    await ctrl.adoptGroups(frame({ '\u0000d': { v: 9e15, removed: false, order: 0, n: 'PWNED' } }));
    expect((await ctrl.listGroups()).find((g) => g.role === 'default')?.name).toBe('Buddies');
    // ...so a later honest rename works and sticks.
    clock = 2000;
    await ctrl.renameGroup('default', 'Pals');
    expect((await ctrl.listGroups()).find((g) => g.role === 'default')?.name).toBe('Pals');
    // A version within the one-day skew allowance still adopts (an honest, slightly-fast sibling).
    await ctrl.adoptGroups(frame({ Family: { v: clock + 60_000, removed: false, order: 1 } }));
    expect((await ctrl.listGroups()).some((g) => g.name === 'Family')).toBe(true);
  });

  it('seals, lists, and deletes buddy groups (deletion moves the members back to Buddies)', async () => {
    const sessions = new SealedSessionStore(db);
    let clock = 0;
    const ctrl = new AppControllerImpl(vault, channels, keyvault, () => clock, undefined, undefined, sessions);
    await ctrl.unlock('alice', 'pass');
    // Every user has the two built-ins from the start: the default group first, the Blocked drop last.
    const customs = (gs: readonly { name: string; role?: string }[]): string[] => gs.filter((g) => g.role === undefined).map((g) => g.name);
    expect(customs(await ctrl.listGroups())).toEqual([]); // no custom groups until you add one
    expect((await ctrl.listGroups()).map((g) => g.role)).toEqual(['default', 'blocked']);
    clock = 10;
    await ctrl.addGroup('Family');
    clock = 20;
    await ctrl.addGroup('Co-Workers');
    await ctrl.addGroup('Family'); // dedupe: no second Family
    await ctrl.addGroup('Buddies'); // the default is always implicit, never stored
    expect(customs(await ctrl.listGroups())).toEqual(['Family', 'Co-Workers']);
    // A fresh controller over the same sealed store restores the groups.
    const ctrl2 = new AppControllerImpl(vault, channels, keyvault, () => clock, undefined, undefined, sessions);
    await ctrl2.unlock('alice', 'pass');
    expect(customs(await ctrl2.listGroups())).toEqual(['Family', 'Co-Workers']);
    // File a buddy under Family, then delete Family: the buddy moves back to the default group.
    clock = 30;
    await ctrl2.addBuddy('stan', 'Family');
    clock = 40;
    await ctrl2.deleteGroup('Family');
    expect(customs(await ctrl2.listGroups())).toEqual(['Co-Workers']);
    expect((await ctrl2.listBuddies()).find((b) => b.username === 'stan')?.group).toBe('Buddies');
    // The default group cannot be deleted.
    clock = 50;
    await ctrl2.deleteGroup('Buddies');
    expect(customs(await ctrl2.listGroups())).toEqual(['Co-Workers']);
  });

  it('renames the built-in groups label-only (functionality survives) and blocks colliding names', async () => {
    const sessions = new SealedSessionStore(db);
    let clock = 0;
    const ctrl = new AppControllerImpl(vault, channels, keyvault, () => clock, undefined, undefined, sessions);
    await ctrl.unlock('alice', 'pass');
    clock = 10;
    await ctrl.renameGroup('default', 'Pals');
    clock = 20;
    await ctrl.renameGroup('blocked', 'Enemies');
    let groups = await ctrl.listGroups();
    expect(groups.find((g) => g.role === 'default')?.name).toBe('Pals');
    expect(groups.find((g) => g.role === 'blocked')?.name).toBe('Enemies');
    // Functionality survives the rename: a new buddy still files under the INTERNAL default key.
    clock = 30;
    await ctrl.addBuddy('stan');
    expect((await ctrl.listBuddies()).find((b) => b.username === 'stan')?.group).toBe('Buddies');
    // The labels persist across a reload of the sealed store.
    const ctrl2 = new AppControllerImpl(vault, channels, keyvault, () => clock, undefined, undefined, sessions);
    await ctrl2.unlock('alice', 'pass');
    groups = await ctrl2.listGroups();
    expect(groups.find((g) => g.role === 'default')?.name).toBe('Pals');
    expect(groups.find((g) => g.role === 'blocked')?.name).toBe('Enemies');
    // Collisions are refused: a rename to the other built-in's name or an existing group's name is a
    // no-op, and a control character in the name is stripped (it could forge the reserved keys).
    clock = 40;
    await ctrl2.addGroup('Family');
    await ctrl2.renameGroup('default', 'Enemies');
    await ctrl2.renameGroup('default', 'Family');
    expect((await ctrl2.listGroups()).find((g) => g.role === 'default')?.name).toBe('Pals');
    await ctrl2.renameGroup('blocked', '\u0000d');
    expect((await ctrl2.listGroups()).find((g) => g.role === 'blocked')?.name).toBe('d');
    // A group answering to a built-in's current label cannot be created (two folders, one name).
    await ctrl2.addGroup('Pals');
    expect((await ctrl2.listGroups()).filter((g) => g.name === 'Pals')).toHaveLength(1);
  });

  it('adopts a sibling group-list frame per-group last-writer-wins (newer add/delete wins, tie deletes)', async () => {
    const sessions = new SealedSessionStore(db);
    let clock = 0;
    const ctrl = new AppControllerImpl(vault, channels, keyvault, () => clock, undefined, undefined, sessions);
    await ctrl.unlock('alice', 'pass');
    clock = 10;
    await ctrl.addGroup('Family'); // local Family at version 10
    const customs = async (): Promise<string[]> => (await ctrl.listGroups()).filter((g) => g.role === undefined).map((g) => g.name);
    const frame = (groups: Record<string, { v: number; removed: boolean; order: number; n?: string }>): Uint8Array =>
      enc.encode(JSON.stringify({ groups }));
    // A sibling's add of 'Co-Workers' (version 20) joins ours (no concurrent-add loss).
    await ctrl.adoptGroups(frame({ 'Co-Workers': { v: 20, removed: false, order: 5 } }));
    expect((await customs()).sort()).toEqual(['Co-Workers', 'Family']);
    // A STALE delete of Family (version 5) is ignored.
    await ctrl.adoptGroups(frame({ Family: { v: 5, removed: true, order: 1 } }));
    expect(await customs()).toContain('Family');
    // A NEWER delete of Family (version 15) tombstones it everywhere.
    await ctrl.adoptGroups(frame({ Family: { v: 15, removed: true, order: 1 } }));
    expect(await customs()).toEqual(['Co-Workers']);
    // A same-version add-vs-delete tie converges to deleted, and cannot resurrect a tombstone.
    await ctrl.adoptGroups(frame({ Family: { v: 15, removed: false, order: 1 } }));
    expect(await customs()).toEqual(['Co-Workers']);
    // A sibling's built-in rename rides the same frame (the reserved alias entry) and adopts LWW.
    await ctrl.adoptGroups(frame({ '\u0000d': { v: 30, removed: false, order: 0, n: 'Pals' } }));
    expect((await ctrl.listGroups()).find((g) => g.role === 'default')?.name).toBe('Pals');
    // A STALE alias write does not roll the label back.
    await ctrl.adoptGroups(frame({ '\u0000d': { v: 25, removed: false, order: 0, n: 'Old' } }));
    expect((await ctrl.listGroups()).find((g) => g.role === 'default')?.name).toBe('Pals');
  });

  it('tags a conversation with a buddy handle (device-local) and returns empty buddy info until a profile arrives', async () => {
    const sessions = new SealedSessionStore(db);
    const ctrl = new AppControllerImpl(vault, channels, keyvault, () => 0, undefined, undefined, sessions);
    await ctrl.unlock('alice', 'pass');
    // No conversation with anyone yet: buddy info is empty (profiles are E2E, never on the server).
    expect(await ctrl.getBuddyInfo('raven')).toEqual([]);
    // Tag a conversation for raven; the tag round-trips across a reload (sealed, device-local).
    await ctrl.tagConversationHandle('c-abc', 'RAVEN'); // handle is normalized
    const reopened = new AppControllerImpl(vault, channels, keyvault, () => 0, undefined, undefined, sessions);
    await reopened.unlock('alice', 'pass');
    // The tag persists (no throw) and, with no peer profile delivered into that conversation yet, buddy
    // info is still the honest empty result; an unknown handle is likewise empty.
    expect(await reopened.getBuddyInfo('raven')).toEqual([]);
    expect(await reopened.getBuddyInfo('nobody')).toEqual([]);
  });

  it('persists the presence opt-in (off by default) under the MSK', async () => {
    const sessions = new SealedSessionStore(db);
    const ctrl = new AppControllerImpl(vault, channels, keyvault, () => 0, undefined, undefined, sessions);
    await ctrl.unlock('alice', 'pass');
    expect(await ctrl.getPresenceEnabled()).toBe(false);
    await ctrl.setPresenceEnabled(true);
    const ctrl2 = new AppControllerImpl(vault, channels, keyvault, () => 0, undefined, undefined, sessions);
    await ctrl2.unlock('alice', 'pass');
    expect(await ctrl2.getPresenceEnabled()).toBe(true);
    await ctrl2.setPresenceEnabled(false);
    expect(await ctrl2.getPresenceEnabled()).toBe(false);
  });

  it('persists in-app notifications (on by default) under the MSK', async () => {
    const sessions = new SealedSessionStore(db);
    const ctrl = new AppControllerImpl(vault, channels, keyvault, () => 0, undefined, undefined, sessions);
    await ctrl.unlock('alice', 'pass');
    expect(await ctrl.getNotifyEnabled()).toBe(true); // default on
    await ctrl.setNotifyEnabled(false);
    const ctrl2 = new AppControllerImpl(vault, channels, keyvault, () => 0, undefined, undefined, sessions);
    await ctrl2.unlock('alice', 'pass');
    expect(await ctrl2.getNotifyEnabled()).toBe(false);
  });

  it('seals and restores the identity card per account under the MSK', async () => {
    const sessions = new SealedSessionStore(db);
    const ctrlA = new AppControllerImpl(vault, channels, keyvault, () => 0, undefined, undefined, sessions);
    await ctrlA.unlock('alice', 'pass');
    expect(await ctrlA.getIdentity()).toEqual(DEFAULT_IDENTITY); // default before anything is set
    const profile = { icon: { kind: 'emoji' as const, value: 'X', bg: '#111' }, bio: 'meet at the drop', away: { enabled: false, message: '', serverSide: false } };
    await ctrlA.setIdentity(profile);
    // setIdentity stamps a change version (here 0, from the test's () => 0 clock) only on the fields that
    // actually CHANGED. Icon and bio changed, so both get version 0. The away config equals the default
    // (off), so it is NOT stamped and keeps the -1 "never set" sentinel, so an unset away never overrides
    // a sibling's real away config.
    expect(await ctrlA.getIdentity()).toEqual({ ...profile, iconVersion: 0, bioVersion: 0, awayVersion: -1 });
    // A different account on the same device cannot read it (sealed under a different MSK).
    const ctrlB = new AppControllerImpl(vault, channels, keyvault, () => 0, undefined, undefined, sessions);
    await ctrlB.unlock('bob', 'pass2');
    expect(await ctrlB.getIdentity()).toEqual(DEFAULT_IDENTITY);
  });

  it('adopts a NEWER sibling buddy-icon change and ignores an older one (last-writer-wins)', async () => {
    const sessions = new SealedSessionStore(db);
    let clock = 0;
    const ctrl = new AppControllerImpl(vault, channels, keyvault, () => clock, undefined, undefined, sessions);
    await ctrl.unlock('alice', 'pass');
    // This device sets an icon at version 10.
    clock = 10;
    await ctrl.setIdentity({ icon: { kind: 'emoji', value: 'A', bg: '#1' }, bio: '', away: { enabled: false, message: '', serverSide: false } });
    expect((await ctrl.getIdentity()).iconVersion).toBe(10);
    // A sibling's icon change at a NEWER version (20) is adopted.
    await ctrl.adoptSiblingIdentity(CONTROL_BUDDY_ICON, enc.encode(JSON.stringify({ icon: { kind: 'emoji', value: 'B', bg: '#2' }, v: 20 })));
    let id = await ctrl.getIdentity();
    expect(id.icon).toEqual({ kind: 'emoji', value: 'B', bg: '#2' });
    expect(id.iconVersion).toBe(20);
    // An OLDER sibling change (version 15) is ignored: the most recent change (20) stays.
    await ctrl.adoptSiblingIdentity(CONTROL_BUDDY_ICON, enc.encode(JSON.stringify({ icon: { kind: 'emoji', value: 'C', bg: '#3' }, v: 15 })));
    id = await ctrl.getIdentity();
    expect(id.icon).toEqual({ kind: 'emoji', value: 'B', bg: '#2' });
    expect(id.iconVersion).toBe(20);
  });

  it('a fresh device adopts a v=0 sibling identity (baseline is -1 "never set", not 0)', async () => {
    const sessions = new SealedSessionStore(db);
    const ctrl = new AppControllerImpl(vault, channels, keyvault, () => 0, undefined, undefined, sessions);
    await ctrl.unlock('newdev', 'pw-fresh');
    // A brand-new device has never set an identity, so its baseline versions are the -1 "never set"
    // sentinel. A sibling that set its icon/profile before versioning advertises v=0; a 0 baseline lost
    // the strict adopt compare (0 <= 0) and the account icon/profile never synced to the new device.
    expect((await ctrl.getIdentity()).iconVersion).toBe(-1);
    await ctrl.adoptSiblingIdentity(CONTROL_BUDDY_ICON, enc.encode(JSON.stringify({ icon: { kind: 'emoji', value: 'S', bg: '#9' }, v: 0 })));
    await ctrl.adoptSiblingIdentity(CONTROL_PROFILE, enc.encode(JSON.stringify({ bio: 'from the seed-holder', v: 0 })));
    const adopted = await ctrl.getIdentity();
    expect(adopted.icon).toEqual({ kind: 'emoji', value: 'S', bg: '#9' }); // v=0 icon adopted, not dropped
    expect(adopted.iconVersion).toBe(0);
    expect(adopted.bio).toBe('from the seed-holder'); // v=0 profile adopted
    expect(adopted.bioVersion).toBe(0);
    // A duplicate v=0 echo is now dropped (0 <= 0): the adopt self-terminates, no re-broadcast loop.
    await ctrl.adoptSiblingIdentity(CONTROL_BUDDY_ICON, enc.encode(JSON.stringify({ icon: { kind: 'emoji', value: 'X', bg: '#0' }, v: 0 })));
    expect((await ctrl.getIdentity()).icon).toEqual({ kind: 'emoji', value: 'S', bg: '#9' });
  });

  it('serializes CONCURRENT sibling-identity adopts so icon, bio, and away all survive (no lost update)', async () => {
    const sessions = new SealedSessionStore(db);
    const ctrl = new AppControllerImpl(vault, channels, keyvault, () => 0, undefined, undefined, sessions);
    await ctrl.unlock('racer', 'pw');
    // The three identity frames are flushed back-to-back on a join. Each adopt is a read-modify-write of the
    // one shared card; adopted WITHOUT awaiting between them, an unserialized RMW would have all three read
    // the same base card and last-writer-wins would null the other two fields (the icon was the casualty).
    await Promise.all([
      ctrl.adoptSiblingIdentity(CONTROL_BUDDY_ICON, enc.encode(JSON.stringify({ icon: { kind: 'emoji', value: 'K', bg: '#7' }, v: 5 }))),
      ctrl.adoptSiblingIdentity(CONTROL_PROFILE, enc.encode(JSON.stringify({ bio: 'synced bio', v: 5 }))),
      ctrl.adoptSiblingIdentity(CONTROL_AWAY, enc.encode(JSON.stringify({ away: { enabled: true, message: 'brb', serverSide: false }, v: 5 }))),
    ]);
    const id = await ctrl.getIdentity();
    expect(id.icon).toEqual({ kind: 'emoji', value: 'K', bg: '#7' }); // icon survived the concurrent writes
    expect(id.bio).toBe('synced bio');
    expect(id.away).toEqual({ enabled: true, message: 'brb', serverSide: false });
  });

  it('adopts a NEWER sibling profile (bio) change and ignores an older one (last-writer-wins)', async () => {
    const sessions = new SealedSessionStore(db);
    let clock = 0;
    const ctrl = new AppControllerImpl(vault, channels, keyvault, () => clock, undefined, undefined, sessions);
    await ctrl.unlock('alice', 'pass');
    clock = 10;
    await ctrl.setIdentity({ icon: null, bio: 'first bio', away: { enabled: false, message: '', serverSide: false } });
    expect((await ctrl.getIdentity()).bioVersion).toBe(10);
    // A sibling's NEWER profile change (v=20) is adopted.
    await ctrl.adoptSiblingIdentity(CONTROL_PROFILE, enc.encode(JSON.stringify({ bio: 'updated from my phone', v: 20 })));
    let id = await ctrl.getIdentity();
    expect(id.bio).toBe('updated from my phone');
    expect(id.bioVersion).toBe(20);
    // An OLDER profile change (v=15) is ignored: the most recent (20) stays.
    await ctrl.adoptSiblingIdentity(CONTROL_PROFILE, enc.encode(JSON.stringify({ bio: 'stale', v: 15 })));
    id = await ctrl.getIdentity();
    expect(id.bio).toBe('updated from my phone');
    expect(id.bioVersion).toBe(20);
  });

  it('HARD-CLAMPS an oversized sibling bio and drops a malformed/oversized icon on adoption', async () => {
    const sessions = new SealedSessionStore(db);
    let clock = 0;
    const ctrl = new AppControllerImpl(vault, channels, keyvault, () => clock, undefined, undefined, sessions);
    await ctrl.unlock('alice', 'pass');
    clock = 10;
    await ctrl.setIdentity({ icon: { kind: 'emoji', value: 'A', bg: '#1' }, bio: 'x', away: { enabled: false, message: '', serverSide: false } });
    // A hostile sibling frame with a huge bio is clamped to the AIM-parity cap, not stored whole.
    await ctrl.adoptSiblingIdentity(CONTROL_PROFILE, enc.encode(JSON.stringify({ bio: 'Z'.repeat(PROFILE_MAX_CHARS * 4), v: 20 })));
    expect((await ctrl.getIdentity()).bio.length).toBe(PROFILE_MAX_CHARS);
    // An oversized image-icon value is dropped (kept null), not stored.
    await ctrl.adoptSiblingIdentity(CONTROL_BUDDY_ICON, enc.encode(JSON.stringify({ icon: { kind: 'image', value: 'd'.repeat(ICON_VALUE_MAX + 1), bg: '#1' }, v: 30 })));
    expect((await ctrl.getIdentity()).icon).toBeNull();
    // A malformed icon (wrong kind, missing value) is also dropped rather than crashing adoption.
    await ctrl.adoptSiblingIdentity(CONTROL_BUDDY_ICON, enc.encode(JSON.stringify({ icon: { kind: 'evil', bg: 42 }, v: 40 })));
    expect((await ctrl.getIdentity()).icon).toBeNull();
  });

  it('adopts a NEWER sibling away-config change and ignores an older one (last-writer-wins)', async () => {
    const sessions = new SealedSessionStore(db);
    let clock = 0;
    const ctrl = new AppControllerImpl(vault, channels, keyvault, () => clock, undefined, undefined, sessions);
    await ctrl.unlock('alice', 'pass');
    clock = 10;
    await ctrl.setIdentity({ icon: null, bio: '', away: { enabled: true, message: 'biking', serverSide: false } });
    expect((await ctrl.getIdentity()).awayVersion).toBe(10);
    // A sibling's NEWER away change (v=20) is adopted (message + on/off + server-side opt-in).
    await ctrl.adoptSiblingIdentity(CONTROL_AWAY, enc.encode(JSON.stringify({ away: { enabled: true, message: 'at lunch', serverSide: true }, v: 20 })));
    let id = await ctrl.getIdentity();
    expect(id.away).toEqual({ enabled: true, message: 'at lunch', serverSide: true });
    expect(id.awayVersion).toBe(20);
    // An OLDER away change (v=15) is ignored.
    await ctrl.adoptSiblingIdentity(CONTROL_AWAY, enc.encode(JSON.stringify({ away: { enabled: false, message: 'old', serverSide: false }, v: 15 })));
    id = await ctrl.getIdentity();
    expect(id.away.message).toBe('at lunch');
    expect(id.awayVersion).toBe(20);
  });

  it('does not overwrite an existing identity when restore fails (no silent identity loss)', async () => {
    const sessions = new SealedSessionStore(db);
    const selfKey = `self:${await accountIdFor('alice')}`;
    // Pre-seed this account's identity record, as a prior login would have left.
    await sessions.save({ conversationId: selfKey, sealed: new Uint8Array([1, 2, 3, 4]) });

    const live: GroupDeps = {
      connect: () => noopTransport,
      makeConversation: () => fakeConv(),
      pushEvent: () => {},
      schedule: () => 0,
      cancel: () => {},
      sealConversation: () => new Uint8Array([9, 9, 9]),
      restoreConversation: () => {
        throw new Error('corrupt or wrong-key blob');
      },
      sasDigestHex: () => '00'.repeat(32),
    };
    const live2 = new AppControllerImpl(vault, channels, keyvault, () => 0, undefined, live, sessions);
    await live2.unlock('alice', 'pass');
    await live2.connectGateway('ws://x/ws'); // restore throws -> fresh in-memory identity...

    // ...but the durable record must be UNCHANGED (create-if-absent), not clobbered.
    const after = await sessions.load(selfKey);
    expect([...(after?.sealed ?? [])]).toEqual([1, 2, 3, 4]);
  });

  it('throws when used before unlock', async () => {
    await expect(ctrl.listChannels()).rejects.toThrow('locked');
  });

  it('surfaces the identity fingerprint from the injected provider when starting key exchange', async () => {
    const withId = new AppControllerImpl(vault, channels, keyvault, () => 0, () => Promise.resolve('AA·BB·CC'));
    await withId.unlock('alice', 'pass');
    const state = await withId.startKeyExchange();
    expect(state.mode).toBe('start');
    expect(state.selfFingerprint).toBe('AA·BB·CC');
  });

  it('unlock reports created on a fresh device and not on a later login', async () => {
    const first = await ctrl.unlock('alice', 'pass');
    expect(first.ok).toBe(true);
    expect(first.created).toBe(true);
    const ctrl2 = new AppControllerImpl(vault, channels, keyvault, () => 0);
    const second = await ctrl2.unlock('alice', 'pass');
    expect(second.ok).toBe(true);
    expect(second.created).toBeFalsy();
  });

  it('deviceAuthState reports unauthorized for a login-created vault (credentials alone never authorize)', async () => {
    const sessions = new SealedSessionStore(db);
    const c = new AppControllerImpl(vault, channels, keyvault, () => 0, undefined, undefined, sessions);
    await c.unlock('alice', 'pass');
    expect(await c.deviceAuthState()).toEqual({ authorized: false, seedHolder: false });
  });

  it('deviceAuthState is authorized once the provisioned-device marker is written', async () => {
    const sessions = new SealedSessionStore(db);
    const c = new AppControllerImpl(vault, channels, keyvault, () => 0, undefined, undefined, sessions);
    await c.unlock('alice', 'pass');
    const account = await accountIdFor('alice');
    await sessions.save({ conversationId: `authorized:${account}`, sealed: new Uint8Array([1]) });
    expect(await c.deviceAuthState()).toEqual({ authorized: true, seedHolder: false });
  });

  it('deviceAuthState is the seed-holder after the recovery seed is created (registration)', async () => {
    const sessions = new SealedSessionStore(db);
    const c = new AppControllerImpl(vault, channels, keyvault, () => 0, undefined, undefined, sessions);
    await c.unlock('alice', 'pass');
    await c.ensureAccountSeed(); // registration makes this device the seed-holder
    expect(await c.deviceAuthState()).toEqual({ authorized: true, seedHolder: true });
  });

  it('discardAccount clears the vault, the recovery seed, and the authorized marker', async () => {
    const sessions = new SealedSessionStore(db);
    const c = new AppControllerImpl(vault, channels, keyvault, () => 0, undefined, undefined, sessions);
    await c.unlock('alice', 'pass');
    await c.ensureAccountSeed();
    const account = await accountIdFor('alice');
    await sessions.save({ conversationId: `authorized:${account}`, sealed: new Uint8Array([1]) });

    await c.discardAccount('alice');
    expect(await vault.exists(account)).toBe(false);
    expect(await sessions.load(`aak:${account}`)).toBeUndefined();
    expect(await sessions.load(`authorized:${account}`)).toBeUndefined();

    // A later login re-creates a fresh, unauthorized vault (no orphaned authorization survives).
    const c2 = new AppControllerImpl(vault, channels, keyvault, () => 0, undefined, undefined, sessions);
    const res = await c2.unlock('alice', 'pass');
    expect(res.created).toBe(true);
    expect((await c2.deviceAuthState()).authorized).toBe(false);
  });
});
