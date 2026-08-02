import { describe, it, expect, beforeEach } from 'vitest';
import {
  GroupChannel,
  formatContact,
  type GroupDeps,
  type GroupPersistence,
  type DeviceTarget,
  type PendingWelcome,
} from './groupchannel.js';
import { encodeList, type GroupConversationLike } from './group.js';
import {
  frameMessage,
  frameControl,
  frameRevoke,
  parseFrame,
  padToBucket,
  unpadFromBucket,
  CONTROL_BUDDY_ICON,
  CONTROL_AWAY,
  CONTROL_BUDDIES,
  CONTROL_GROUPS,
  CONTROL_FILE,
  CONTROL_CALL,
  type EnvelopeMsg,
} from './session.js';
import type { Transport, TransportHandlers } from './transport.js';
import type { ChannelSummary } from './app.js';
import type { Lifetime } from './index.js';

const LIFE: Lifetime = { kind: 'duration', seconds: 86400 };
const APP = 0xaa;
const COMMIT_ADD = 0xc0;
const COMMIT_REMOVE = 0xc2; // a staged-remove commit; carries the removed sig after the tag (like COMMIT_ADD)
// The single conversation's group id for these tests (one device, one open conversation). Every crypto
// byte the fake produces carries it so receive self-routes by it, exactly as the real wasm does.
const GID = 'abcd';
// The conversationId the channel derives from GID (`c-${groupId}`), the key the public methods take.
const CID = `c-${GID}`;

function hx(s: string): string {
  return s.repeat(16);
}
function bytesToHex(b: Uint8Array): string {
  return [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
}
function hexToBytesTop(s: string): Uint8Array {
  const b = new Uint8Array(s.length / 2);
  for (let i = 0; i < b.length; i++) {
    b[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  }
  return b;
}
function gidBytes(): Uint8Array {
  return new Uint8Array([0xab, 0xcd]); // hexToBytes(GID)
}

class FakeConv implements GroupConversationLike {
  hasGroup = false;
  epoch = 0;
  members: string[]; // the group roster; grows when a staged add confirms (self-heal tests)
  pending: string | null = null; // a staged add awaiting its echo
  pendingRemove: string | null = null; // a staged remove awaiting its echo
  fromOwnAccount = false; // whether the NEXT received app frame is flagged as from our own account
  ratchetFlushes = 0; // how many times the receive-ratchet flush was invoked (item 10 coverage)
  constructor(private readonly sig: string, extra: string[] = [hx('bb')]) {
    this.members = [this.sig, ...extra];
  }
  flushReceiveRatchet(_conversationId: string): boolean {
    this.ratchetFlushes += 1;
    return true;
  }
  signaturePublicKeyHex(): string {
    return this.sig;
  }
  accountKey = 'acct'; // our account key hex; empty models a cert-only device (no account key)
  accountKeyHex(): string {
    return this.accountKey;
  }
  keyPackage(): Uint8Array {
    return new Uint8Array([1]);
  }
  createGroup(): Uint8Array {
    this.hasGroup = true;
    this.epoch = 0;
    // The welcome (opaque 0x57) and this conversation's group id, length-prefixed.
    return encodeList([new Uint8Array([0x57]), gidBytes()]);
  }
  createSelfCalls = 0; // how many times a solo self-group mint ran (strict-replacement tests)
  createSelf(): Uint8Array {
    // A SOLO group whose only member is this device; no one is admitted, so there is no welcome.
    this.createSelfCalls++;
    this.hasGroup = true;
    this.epoch = 0;
    return gidBytes(); // just the group id
  }
  listConversations(): string[] {
    return this.hasGroup ? [GID] : [];
  }
  addMember(_id: string): Uint8Array {
    this.epoch += 1;
    return encodeList([new Uint8Array([COMMIT_ADD]), new Uint8Array([9])]);
  }
  // The staged commit's wire bytes, exposed via pendingCommit()/pendingWelcome() so the post-await
  // byte-equality guard (Batch B should-fix 2) and the restore re-arm can read the in-flight commit. Set
  // when a commit is staged, cleared on confirm/abort. A reload-with-pending test can set these directly.
  stagedCommitBytes: Uint8Array = new Uint8Array();
  stagedWelcomeBytes: Uint8Array = new Uint8Array();
  // Staged add: build the commit WITHOUT advancing (no member, no epoch bump). The commit carries the
  // added sig so the echo can be recognized in receive (confirm) vs a competing commit (abort).
  stageAddThrow: string | null = null; // the adder-side gate rejection (R9), or the in-flight error
  stageAdd(_id: string, kp: Uint8Array): Uint8Array {
    if (this.stageAddThrow !== null) {
      throw new Error(this.stageAddThrow);
    }
    this.pending = bytesToHex(kp);
    this.stagedCommitBytes = new Uint8Array([COMMIT_ADD, ...kp]);
    this.stagedWelcomeBytes = new Uint8Array([9]);
    return encodeList([this.stagedCommitBytes, this.stagedWelcomeBytes]);
  }
  confirmAdd(_id: string): void {
    if (this.pending !== null) {
      if (!this.members.includes(this.pending)) {
        this.members.push(this.pending);
      }
      this.epoch += 1;
      this.pending = null;
      this.stagedCommitBytes = new Uint8Array();
    }
  }
  abortAdd(_id: string): void {
    this.pending = null;
    this.stagedCommitBytes = new Uint8Array();
  }
  removeMember(_id: string): Uint8Array {
    this.epoch += 1;
    return new Uint8Array([0xc1]);
  }
  // Staged remove: build the commit WITHOUT advancing; the commit carries the removed sig so its echo can
  // be recognized in receive (confirm) vs a competing commit (abort). Mirror of stageAdd.
  stageRemove(_id: string, sigKeyHex: string): Uint8Array {
    this.pendingRemove = sigKeyHex;
    this.stagedCommitBytes = new Uint8Array([COMMIT_REMOVE, ...hexToBytesTop(sigKeyHex)]);
    return this.stagedCommitBytes;
  }
  confirmRemove(_id: string): void {
    if (this.pendingRemove !== null) {
      this.members = this.members.filter((m) => m !== this.pendingRemove);
      this.epoch += 1;
      this.pendingRemove = null;
      this.stagedCommitBytes = new Uint8Array();
    }
  }
  abortRemove(_id: string): void {
    this.pendingRemove = null;
    this.stagedCommitBytes = new Uint8Array();
  }
  // The pending getters derive from the LIVE staged state: pendingKind is 0/1/2, pendingTarget is the
  // added/removed sig, pendingCommit/pendingWelcome are the staged wire bytes (Batch B).
  pendingKind(_id: string): number {
    if (this.pending !== null) return 1;
    if (this.pendingRemove !== null) return 2;
    return 0;
  }
  pendingTarget(_id: string): string {
    return this.pending ?? this.pendingRemove ?? '';
  }
  pendingCommit(_id: string): Uint8Array {
    return this.stagedCommitBytes;
  }
  pendingWelcome(_id: string): Uint8Array {
    return this.stagedWelcomeBytes;
  }
  mailboxTag(subject: string): string {
    return 'ctag-' + subject; // a deterministic per-subject tag (the real wasm derives a secret-keyed hash)
  }
  // Takes the Welcome bytes (like the real wasm) even though this base fake ignores them; PairedConv
  // below overrides it to derive the group id from those bytes, which is what makes a two-device
  // convergence assertion meaningful.
  joinFromWelcome(_welcome: Uint8Array): string {
    this.hasGroup = true;
    this.epoch = 0;
    return GID;
  }
  encrypt(_id: string, pt: Uint8Array): Uint8Array {
    return new Uint8Array([APP, ...pt]);
  }
  receiveThrow: string | null = null; // when set, receive throws this message (BH-S3 poison/transient test)
  receive(ct: Uint8Array): Uint8Array {
    if (this.receiveThrow !== null) {
      throw new Error(this.receiveThrow);
    }
    return encodeList([gidBytes(), this.receiveBlob(ct)]);
  }
  // The tagged received blob for this message; receive wraps it with the group id (self-routing).
  protected receiveBlob(ct: Uint8Array): Uint8Array {
    if (ct[0] === APP) {
      // tag 0 (application), then the from-own-account flag byte, then the plaintext.
      return new Uint8Array([0, this.fromOwnAccount ? 1 : 0, ...ct.slice(1)]);
    }
    if (ct[0] === COMMIT_ADD) {
      // A staged-add commit carries the added sig after the tag; a bare commit (legacy addMember or a
      // peer's opaque add) does not.
      if (ct.length > 1) {
        const addedBytes = ct.slice(1);
        const sig = bytesToHex(addedBytes);
        if (this.pending === sig) {
          this.confirmAdd(GID); // our own commit echoed back: confirm it
        } else {
          if (this.pending !== null) {
            this.abortAdd(GID); // a competing commit won: drop ours and adopt theirs
          }
          this.epoch += 1;
          if (!this.members.includes(sig)) {
            this.members.push(sig);
          }
        }
        return new Uint8Array([1, ...encodeList([addedBytes]), ...encodeList([])]);
      }
      this.epoch += 1;
      return new Uint8Array([1, ...encodeList([new Uint8Array([0xbb])]), ...encodeList([])]);
    }
    if (ct[0] === COMMIT_REMOVE) {
      const removedBytes = ct.slice(1);
      const sig = bytesToHex(removedBytes);
      if (this.pendingRemove === sig) {
        this.confirmRemove(GID); // our own remove echoed back: confirm it
      } else {
        if (this.pendingRemove !== null) {
          this.abortRemove(GID); // a competing commit won: drop ours and adopt theirs
        }
        this.epoch += 1;
        this.members = this.members.filter((m) => m !== sig);
      }
      return new Uint8Array([1, ...encodeList([]), ...encodeList([removedBytes])]);
    }
    return new Uint8Array([3]);
  }
  roster(_id?: string): string[] {
    return [...this.members];
  }
  selfConversation = false; // whether this conversation is the hidden self-group (all our own devices)
  isSelfConversation(_id?: string): boolean {
    return this.selfConversation;
  }
  // null mirrors selfConversation (a healthy self-group is strict); set false to model the degraded
  // lenient-only state (our own leaf frozen certless in the roster).
  strictSelf: boolean | null = null;
  isSelfConversationStrict(_id?: string): boolean {
    return this.strictSelf ?? this.selfConversation;
  }
  // Whether a fresh mint would be strict; false models a legacy label-only credential.
  credentialCertifiedFlag = true;
  credentialCertified(): boolean {
    return this.credentialCertifiedFlag;
  }
  groupMailbox(_id: string): string {
    if (!this.hasGroup) {
      throw new Error('no group yet');
    }
    return `gmbox-${this.epoch}`;
  }
  authorizeDevice(): string {
    return '';
  }
  authorizeScannedDevice(): Uint8Array {
    return new Uint8Array(104);
  }
  adoptCertificate(): void {
    /* no-op */
  }
  recoverWithSeed(): void {
    /* no-op */
  }
  reauthorized = 0; // how many times a re-certify ran (mint-guard tests)
  reauthorizeAtEpoch(): void {
    this.reauthorized++;
  }
  certEpoch(): number {
    return 0;
  }
  // ADR-022 P7 denylist. `revoked` is the accepted set; ingest models the wasm's fail-closed check by
  // throwing on anything that is not one of `acceptable`.
  revoked = new Set<string>();
  acceptable: Set<string> | null = null; // null = accept everything
  minted: Array<{ key: string; seq: number }> = [];
  revokeDevice(deviceSigKeyHex: string, issuedSeq: number): string {
    this.minted.push({ key: deviceSigKeyHex, seq: issuedSeq });
    const record = `rec-${deviceSigKeyHex}`;
    this.revoked.add(record);
    return record;
  }
  ingestRevocation(recordHex: string): boolean {
    if (this.acceptable !== null && !this.acceptable.has(recordHex)) {
      throw new Error('revocation record did not verify under this account key');
    }
    if (this.revoked.has(recordHex)) {
      return false;
    }
    this.revoked.add(recordHex);
    return true;
  }
  revokedCount(): number {
    return this.revoked.size;
  }
  // SG2 self-heal. `unlinkedGroups` marks a group as provably dead; abandonDeadSelfGroup mirrors the
  // wasm guards (recorded-self AND dead), so a test can prove a LIVE self-group is never abandoned.
  unlinkedGroups = new Set<string>();
  abandoned: string[] = [];
  channelUnlinked(conversationId: string): boolean {
    return this.unlinkedGroups.has(conversationId);
  }
  abandonDeadSelfGroup(conversationId: string, recordedSelf: boolean): boolean {
    if (!recordedSelf) {
      throw new Error('not a recorded own-devices group');
    }
    if (!this.unlinkedGroups.has(conversationId)) {
      throw new Error('this own-devices group is still reachable');
    }
    this.abandoned.push(conversationId);
    return true;
  }
  accountFloor(): number {
    return this.revoked.size;
  }
  // The birth-gated self-group create; null models an older wasm (the wrapper falls back to createGroup).
  createSelfGroupThrow: string | null = null;
  createSelfGroup(_blob: Uint8Array): Uint8Array {
    if (this.createSelfGroupThrow !== null) {
      throw new Error(this.createSelfGroupThrow);
    }
    return this.createGroup();
  }
  // The birth pre-filter; null models an older wasm (the client then treats every package as eligible).
  selfEligible: ((kp: Uint8Array) => boolean) | null = null;
  keyPackageSelfEligible(kp: Uint8Array): boolean {
    return this.selfEligible === null ? true : this.selfEligible(kp);
  }
  wipe(): void {
    /* no-op */
  }
}

// A SECOND conversation joined from a Welcome, so a test can drive two live groups at once. The crypto
// layer holds every group in one object and self-routes by the group id inside the ciphertext, so the
// fake routes by a distinct app tag rather than by mailbox (both groups share `gmbox-${epoch}` here).
const GID_B = 'ef01';
const APP_B = 0xab; // an application frame the fake routes to the SECOND group

class TwoGroupConv extends FakeConv {
  flushed: string[] = []; // the group id of every flushReceiveRatchet call, in order
  private joinedB = false;
  override joinFromWelcome(): string {
    this.joinedB = true;
    return GID_B;
  }
  override listConversations(): string[] {
    const open = super.listConversations();
    return this.joinedB ? [...open, GID_B] : open;
  }
  override flushReceiveRatchet(conversationId: string): boolean {
    this.flushed.push(conversationId);
    return true;
  }
  override receive(ct: Uint8Array): Uint8Array {
    if (ct[0] === APP_B) {
      // tag 0 (application) + the from-own-account flag, routed to the second group
      return encodeList([new Uint8Array([0xef, 0x01]), new Uint8Array([0, 0, ...ct.slice(1)])]);
    }
    return super.receive(ct);
  }
}

class FakeTransport {
  subscribed: string[] = [];
  published: EnvelopeMsg[] = [];
  acked: string[] = [];
  closed = false; // models wsadapter's BrowserSocket: send on a CLOSED socket throws
  consumerId = ''; // the delivery-cursor id resolved for the LAST subscribe (Batch BR/BH)
  setConsumerIdResolver(fn: (subject: string) => string): void {
    this.resolver = fn;
  }
  resolver: (subject: string) => string = () => '';
  subscribe(k: string): void {
    this.subscribed.push(k);
    this.consumerId = this.resolver(k); // record the resolved delivery-cursor id for this subscribe
  }
  publish(e: EnvelopeMsg): void {
    if (this.closed) {
      throw new Error('connection closed');
    }
    this.published.push(e);
  }
  ack(id: Uint8Array): void {
    this.acked.push(bytesToHex(id));
  }
  sendOffer(): void {}
  sendAccept(): void {}
  takePending(): EnvelopeMsg[] {
    return []; // the fake publishes immediately, so nothing is ever queued behind the pacer
  }
  close(): void {}
}

const SELF = hx('aa');

describe('GroupChannel', () => {
  let conv: FakeConv;
  let tx: FakeTransport;
  let handlers: TransportHandlers;
  let events: Array<{ kind: string; payload: unknown }>;
  let channels: ChannelSummary[];
  let messages: Array<{ direction: 'in' | 'out'; text: string; ownAuthored: boolean | undefined }>;
  let ch: GroupChannel;
  let identityFramesCalls: number;
  let peerIdentitySaves: Array<{ conv: string; key: string; controlType: number }>;
  let siblingIdentities: Array<{ controlType: number; payload: Uint8Array }>;
  let scheduled: Array<() => void>;
  let awayText: string | null;
  let blockedPeers: Set<string>;
  let fileSignals: Uint8Array[];
  let callSignals: Uint8Array[];
  let buddiesAdopted: Uint8Array[];
  let buddiesFrame: Uint8Array | null;
  let groupsAdopted: Uint8Array[];
  let groupsFrame: Uint8Array | null;
  let revokesApplied: Array<{ conv: string; target: string; own: boolean }>;

  beforeEach(() => {
    conv = new FakeConv(SELF);
    tx = new FakeTransport();
    events = [];
    channels = [];
    messages = [];
    identityFramesCalls = 0;
    peerIdentitySaves = [];
    siblingIdentities = [];
    scheduled = [];
    awayText = null;
    blockedPeers = new Set();
    fileSignals = [];
    callSignals = [];
    buddiesAdopted = [];
    buddiesFrame = null;
    groupsAdopted = [];
    groupsFrame = null;
    revokesApplied = [];
    const deps: GroupDeps = {
      connect: (_url, h) => {
        handlers = h;
        return tx as unknown as Transport;
      },
      makeConversation: () => conv,
      pushEvent: (kind, payload) => events.push({ kind, payload }),
      schedule: (_ms, cb) => {
        scheduled.push(cb);
        return scheduled.length;
      },
      cancel: () => {},
      sealConversation: () => new Uint8Array(),
      restoreConversation: () => conv,
      sasDigestHex: () => '00'.repeat(32),
    };
    ch = new GroupChannel(
      deps,
      (s) => {
        channels.push(s);
        return Promise.resolve();
      },
      (meta, plaintext) => {
        messages.push({ direction: meta.direction, text: new TextDecoder().decode(plaintext), ownAuthored: meta.ownAuthored });
        return Promise.resolve();
      },
      undefined,
      () => {
        identityFramesCalls++;
        return Promise.resolve([
          { controlType: CONTROL_BUDDY_ICON, payload: new TextEncoder().encode(JSON.stringify({ k: SELF, icon: null })) },
        ]);
      },
      (c, k, t, _p) => {
        peerIdentitySaves.push({ conv: c, key: k, controlType: t });
        return Promise.resolve();
      },
      (t, p) => {
        siblingIdentities.push({ controlType: t, payload: p });
      },
      (_c) => Promise.resolve(awayText),
      (peers) => Promise.resolve(peers.length > 0 && peers.every((k) => blockedPeers.has(k))),
      (_conversationId, payload) => {
        fileSignals.push(payload);
      },
      (_conversationId, payload) => {
        callSignals.push(payload);
      },
      (payload) => {
        buddiesAdopted.push(payload);
      },
      () => Promise.resolve(buddiesFrame),
      (payload) => {
        groupsAdopted.push(payload);
      },
      () => Promise.resolve(groupsFrame),
      (conversationId, targetMessageId, fromOwnAccount) => {
        revokesApplied.push({ conv: conversationId, target: targetMessageId, own: fromOwnAccount });
        return Promise.resolve();
      },
    );
  });

  function deliver(routingKey: string, payload: Uint8Array): void {
    handlers.onDeliver({ messageId: new Uint8Array([1, 2, 3]), routingKey, payload, ttlSeconds: 60 });
  }

  it('publishIdentityFor publishes on the CURRENT transport after a mid-flight reconnect (icon-sync fix)', async () => {
    // The identity frames load async (an IDB decrypt). A self-group heal at device join runs amid
    // reconnect churn, so the transport can be REPLACED during that gap. publishIdentityFor must publish
    // on the live transport (like publishBuddiesFor), not a socket captured before the await; publishing
    // on the dead socket silently dropped the icon/profile, so a new device never got them until an edit.
    const localConv = new FakeConv(SELF);
    localConv.selfConversation = true;
    const tx1 = new FakeTransport();
    const tx2 = new FakeTransport();
    const conns = [tx1, tx2];
    let resolveFrames!: (f: { controlType: number; payload: Uint8Array }[]) => void;
    const framesPending = new Promise<{ controlType: number; payload: Uint8Array }[]>((r) => {
      resolveFrames = r;
    });
    let framesLoads = 0;
    const localDeps: GroupDeps = {
      connect: (_url, _h) => (conns.shift() ?? tx2) as unknown as Transport,
      makeConversation: () => localConv,
      pushEvent: () => {},
      schedule: () => 0,
      cancel: () => {},
      sealConversation: () => new Uint8Array(),
      restoreConversation: () => localConv,
      sasDigestHex: () => '00'.repeat(32),
    };
    const local = new GroupChannel(
      localDeps,
      () => Promise.resolve(),
      () => Promise.resolve(),
      undefined,
      () => {
        framesLoads++;
        return framesPending; // stays pending so a reconnect can land in the async gap
      },
      undefined, undefined, undefined, undefined, undefined, undefined,
      undefined, undefined, undefined, undefined, undefined,
    );
    await local.connectGateway('ws://x/ws'); // transport = tx1
    // startConversation publishes our identity to the new group (publishIdentityFor); the frames load stays
    // pending, so the publish is still in its async gap when the reconnect below swaps the transport.
    await local.startConversation([{ deviceKey: hx('bb'), keyPackage: new Uint8Array([7]) }]);
    expect(framesLoads).toBeGreaterThan(0);
    const tx1CountBeforeReconnect = tx1.published.length;
    await local.connectGateway('ws://x/ws'); // RECONNECT: transport = tx2 (tx1 is now closed)
    resolveFrames([{ controlType: CONTROL_BUDDY_ICON, payload: new TextEncoder().encode(JSON.stringify({ k: SELF, icon: null })) }]);
    await new Promise((r) => setTimeout(r, 0));
    // The icon control frame (APP-tagged, non-trivial payload) must ride the LIVE transport tx2, and tx1
    // must have received nothing NEW after the reconnect (it is the dead socket).
    const iconOnTx2 = tx2.published.some((p) => p.payload[0] === APP && p.payload.length > 2);
    expect(iconOnTx2).toBe(true);
    expect(tx1.published.length).toBe(tx1CountBeforeReconnect);
  });

  it('acks a permanently unprocessable (poison) frame so the bus drops it, but not a transient one (BH-S3)', async () => {
    await ch.connectGateway('ws://x/ws');
    await ch.startConversation([{ deviceKey: hx('bb'), keyPackage: new Uint8Array([7]) }]);
    // A poison frame: the crypto layer marks the error 'drop:'. It must be ACKED so the hold-until-ack
    // bus drops it instead of redelivering it forever (a member cannot pin the mailbox with poison).
    tx.acked.length = 0;
    conv.receiveThrow = 'drop: parse message: garbage bytes';
    deliver('gmbox-0', new Uint8Array([0x99]));
    expect(tx.acked.length).toBe(1);
    // The gate rejection still surfaces its error event (diagnosable), unlike an own echo below.
    expect(events.some((e) => e.kind === 'error')).toBe(true);
    // A transient error (e.g. a future-epoch frame): NOT acked, so it can redeliver (bounded by TTL).
    tx.acked.length = 0;
    conv.receiveThrow = 'process message: cannot decrypt at this epoch yet';
    deliver('gmbox-0', new Uint8Array([0x99]));
    expect(tx.acked.length).toBe(0);
    conv.receiveThrow = null;
  });

  it('acks an own-frame echo silently: no error event, so a re-flushed backlog cannot spam the app', async () => {
    await ch.connectGateway('ws://x/ws');
    await ch.startConversation([{ deviceKey: hx('bb'), keyPackage: new Uint8Array([7]) }]);
    tx.acked.length = 0;
    events.length = 0;
    // The bus echoes our own publish back; the crypto marks it droppable with the own-frame marker.
    conv.receiveThrow = 'drop:own frame: process message: ValidationError(UnableToDecrypt(SecretTreeError(RatchetTypeError)))';
    deliver('gmbox-0', new Uint8Array([0x99]));
    expect(tx.acked.length).toBe(1); // acked away so the cursor stops pinning
    expect(events.some((e) => e.kind === 'error')).toBe(false); // and no event: routine, not an error
    conv.receiveThrow = null;
  });

  it('connects and subscribes to our bootstrap mailbox', async () => {
    const res = await ch.connectGateway('ws://x/ws');
    expect(res.ok).toBe(true);
    expect(res.selfContact).toBe(formatContact(SELF));
    expect(tx.subscribed).toContain(SELF);
    expect(events.some((e) => e.kind === 'connection')).toBe(true);
  });

  it('starts a conversation: creates the group, subscribes to the group mailbox, and welcomes each device', async () => {
    await ch.connectGateway('ws://x/ws');
    const targets: DeviceTarget[] = [
      { deviceKey: hx('bb'), keyPackage: new Uint8Array([7]) },
      { deviceKey: hx('cc'), keyPackage: new Uint8Array([8]) },
    ];
    const model = await ch.startConversation(targets);
    expect(model.secure).toBe(true);
    expect(tx.subscribed).toContain('gmbox-0'); // subscribed to the group mailbox
    // The single Welcome is delivered to BOTH devices' bootstrap mailboxes.
    const welcomeTargets = tx.published.map((p) => p.routingKey);
    expect(welcomeTargets).toContain(hx('bb'));
    expect(welcomeTargets).toContain(hx('cc'));
    expect(channels.length).toBe(1); // channel summary persisted
  });

  it('joins from a Welcome delivered to the bootstrap mailbox and subscribes to the group mailbox', async () => {
    await ch.connectGateway('ws://x/ws');
    deliver(SELF, new Uint8Array([0x57])); // a Welcome arrives on our bootstrap mailbox
    await Promise.resolve();
    await Promise.resolve(); // the block check on Welcome is async
    expect(tx.subscribed).toContain('gmbox-0');
    expect(events.some((e) => e.kind === 'established')).toBe(true);
    expect(tx.acked.length).toBeGreaterThan(0);
  });

  it('delivers an inbound group message: persists it, acks, and signals the UI', async () => {
    await ch.connectGateway('ws://x/ws');
    await ch.startConversation([{ deviceKey: hx('bb'), keyPackage: new Uint8Array([7]) }]);
    const payload = new Uint8Array([APP, ...padToBucket(frameMessage(new TextEncoder().encode('hello team'), LIFE))]);
    deliver('gmbox-0', payload);
    await new Promise((r) => setTimeout(r, 0)); // let the FIFO-chained persist + ack settle
    expect(messages).toContainEqual({ direction: 'in', text: 'hello team', ownAuthored: false });
    expect(events.some((e) => e.kind === 'inbound-message')).toBe(true);
    // honest-limits item 10: once the plaintext is stored under its own key, the MLS ratchet that
    // produced it must be pushed forward and re-sealed, or a seized powered-off device re-derives it.
    // The flush is debounced, so it runs when the timer fires, not inline.
    expect(conv.ratchetFlushes).toBe(0);
    scheduled.forEach((cb) => cb());
    expect(conv.ratchetFlushes).toBe(1);
  });

  it('coalesces a burst of arrivals into ONE ratchet flush (each flush costs a send generation)', async () => {
    await ch.connectGateway('ws://x/ws');
    await ch.startConversation([{ deviceKey: hx('bb'), keyPackage: new Uint8Array([7]) }]);
    for (const text of ['one', 'two', 'three', 'four']) {
      deliver('gmbox-0', new Uint8Array([APP, ...padToBucket(frameMessage(new TextEncoder().encode(text), LIFE))]));
    }
    await new Promise((r) => setTimeout(r, 0));
    scheduled.forEach((cb) => cb());
    expect(conv.ratchetFlushes).toBe(1);
  });

  it('coalesces the flush ACROSS conversations: two busy conversations still cost ONE container re-seal', async () => {
    // The flush is per group (each has its own ratchet) but the re-seal is NOT: resealSelf serializes and
    // seals EVERY conversation into one blob. An earlier cut debounced per conversation and re-sealed
    // inside each timer, so an account with N busy conversations paid N full seals (measured at ~46ms and
    // 450KB for fifty). Both conversations must flush; only one seal may follow.
    const two = new TwoGroupConv(SELF);
    const localScheduled: Array<() => void> = [];
    let reseals = 0;
    let localHandlers: TransportHandlers;
    const localTx = new FakeTransport();
    const localDeps: GroupDeps = {
      connect: (_url, h) => {
        localHandlers = h;
        return localTx as unknown as Transport;
      },
      makeConversation: () => two,
      pushEvent: () => {},
      schedule: (_ms, cb) => {
        localScheduled.push(cb);
        return localScheduled.length;
      },
      cancel: () => {},
      sealConversation: () => new Uint8Array(),
      restoreConversation: () => two,
      sasDigestHex: () => '00'.repeat(32),
    };
    const persistence: GroupPersistence = {
      loadSelf: () => Promise.resolve(null),
      saveSelf: () => Promise.resolve(),
      resealSelf: () => {
        reseals += 1;
        return Promise.resolve(true);
      },
      recoverySeedHex: () => Promise.resolve(''),
    };
    const c = new GroupChannel(localDeps, () => Promise.resolve(), () => Promise.resolve(), persistence);
    await c.connectGateway('ws://x/ws');
    await c.startConversation([{ deviceKey: hx('bb'), keyPackage: new Uint8Array([7]) }]); // conversation A
    localHandlers!.onDeliver({ messageId: new Uint8Array([1]), routingKey: SELF, payload: new Uint8Array([0x57]), ttlSeconds: 60 });
    await new Promise((r) => setTimeout(r, 0)); // conversation B joins from the Welcome
    localScheduled.length = 0;
    reseals = 0;
    const body = (tag: number, text: string): Uint8Array =>
      new Uint8Array([tag, ...padToBucket(frameMessage(new TextEncoder().encode(text), LIFE))]);
    localHandlers!.onDeliver({ messageId: new Uint8Array([2]), routingKey: 'gmbox-0', payload: body(APP, 'to A'), ttlSeconds: 60 });
    localHandlers!.onDeliver({ messageId: new Uint8Array([3]), routingKey: 'gmbox-0', payload: body(APP_B, 'to B'), ttlSeconds: 60 });
    await new Promise((r) => setTimeout(r, 0));
    expect(localScheduled).toHaveLength(1); // ONE timer covers both conversations
    localScheduled.forEach((cb) => cb());
    await new Promise((r) => setTimeout(r, 0));
    expect(two.flushed).toEqual([GID, GID_B]); // yet BOTH ratchets advanced
    expect(reseals).toBe(1); // and the whole container was sealed exactly once
  });

  it('ADR-022 P7: mints a revocation record, and a record that does not verify never enters the denylist', async () => {
    // The denylist is the only thing that excludes a revoked device that still holds the account seed
    // (it re-certifies itself above any epoch floor). So two properties matter here: a revoke must
    // actually produce a record, and a record from anywhere else must survive exactly one check.
    const two = new FakeConv(SELF);
    let reseals = 0;
    const localDeps: GroupDeps = {
      connect: (_url, h) => {
        void h;
        return new FakeTransport() as unknown as Transport;
      },
      makeConversation: () => two,
      pushEvent: () => {},
      schedule: (_ms, cb) => {
        void cb;
        return 1;
      },
      cancel: () => {},
      sealConversation: () => new Uint8Array(),
      restoreConversation: () => two,
      sasDigestHex: () => '00'.repeat(32),
    };
    const persistence: GroupPersistence = {
      loadSelf: () => Promise.resolve(null),
      saveSelf: () => Promise.resolve(),
      resealSelf: () => {
        reseals += 1;
        return Promise.resolve(true);
      },
      recoverySeedHex: () => Promise.resolve(''),
    };
    const c = new GroupChannel(localDeps, () => Promise.resolve(), () => Promise.resolve(), persistence);
    await c.connectGateway('ws://x/ws');
    await c.startConversation([{ deviceKey: hx('bb'), keyPackage: new Uint8Array([7]) }]);
    reseals = 0;

    // Revoking mints a record naming the target key and seals it, so the exclusion survives a reload
    // even if publishing the record to the control plane then fails.
    const record = await c.revokeDeviceKey(SIBLING, 4);
    expect(record).toBe(`rec-${SIBLING}`);
    expect(two.minted).toEqual([{ key: SIBLING, seq: 4 }]);
    expect(reseals).toBe(1);

    // Now only the genuine record verifies. Everything else is DISCARDED, not stored: a hostile control
    // plane must not be able to grow this list, and one bad entry must not poison the batch.
    two.acceptable = new Set(['rec-good']);
    reseals = 0;
    const added = await c.ingestRevocations(['rec-forged', 'rec-good', 'rec-junk']);
    expect(added).toBe(1);
    expect(two.revoked.has('rec-good')).toBe(true);
    expect(two.revoked.has('rec-forged')).toBe(false);
    expect(reseals).toBe(1);

    // Re-ingesting the same set is a no-op and does NOT re-seal: this runs on every sync, and a
    // duplicate would also inflate the derived epoch (which is the record COUNT).
    reseals = 0;
    expect(await c.ingestRevocations(['rec-good'])).toBe(0);
    expect(reseals).toBe(0);
    expect(c.revocationState()).toEqual({ revoked: 2, floor: 2 });
  });

  it('persists a sibling device\'s message flagged ownAuthored, so this device keeps the revoke control', async () => {
    await ch.connectGateway('ws://x/ws');
    await ch.startConversation([{ deviceKey: hx('bb'), keyPackage: new Uint8Array([7]) }]);
    conv.fromOwnAccount = true; // the frame's MLS-authenticated sender is one of OUR OWN devices
    deliver('gmbox-0', new Uint8Array([APP, ...padToBucket(frameMessage(new TextEncoder().encode('from my laptop'), LIFE))]));
    await new Promise((r) => setTimeout(r, 0));
    expect(messages).toContainEqual({ direction: 'in', text: 'from my laptop', ownAuthored: true });
  });

  it('applies an inbound revoke frame through the revoke hook and acks after the erase', async () => {
    await ch.connectGateway('ws://x/ws');
    await ch.startConversation([{ deviceKey: hx('bb'), keyPackage: new Uint8Array([7]) }]);
    deliver('gmbox-0', new Uint8Array([APP, ...padToBucket(frameRevoke('deadbeef'))]));
    await new Promise((r) => setTimeout(r, 0)); // let the FIFO-chained apply + ack settle
    expect(revokesApplied).toEqual([{ conv: CID, target: 'deadbeef', own: false }]);
    expect(tx.acked.length).toBeGreaterThan(0); // acked only after the apply resolved
    // A revoke is a command, not content: nothing is persisted and no inbound-message signal fires.
    expect(messages).toHaveLength(0);
    expect(events.some((e) => e.kind === 'inbound-message')).toBe(false);
  });

  it('passes a sibling revoke to the hook as own-account, so it may erase our outbound copy too', async () => {
    await ch.connectGateway('ws://x/ws');
    await ch.startConversation([{ deviceKey: hx('bb'), keyPackage: new Uint8Array([7]) }]);
    conv.fromOwnAccount = true; // the REVOKE frame's MLS-authenticated sender is one of OUR OWN devices
    deliver('gmbox-0', new Uint8Array([APP, ...padToBucket(frameRevoke('deadbeef'))]));
    await new Promise((r) => setTimeout(r, 0));
    expect(revokesApplied).toEqual([{ conv: CID, target: 'deadbeef', own: true }]);
  });

  it('applies a revoke AFTER the message it chases has persisted (per-conversation apply order)', async () => {
    const order: string[] = [];
    const localConv = new FakeConv(SELF);
    const localTx = new FakeTransport();
    let h!: TransportHandlers;
    const localDeps: GroupDeps = {
      connect: (_url, hh) => {
        h = hh;
        return localTx as unknown as Transport;
      },
      makeConversation: () => localConv,
      pushEvent: () => {},
      schedule: () => 0,
      cancel: () => {},
      sealConversation: () => new Uint8Array(),
      restoreConversation: () => localConv,
      sasDigestHex: () => '00'.repeat(32),
    };
    const slow = new GroupChannel(
      localDeps,
      () => Promise.resolve(),
      async () => {
        // The message's seal + put takes real async time; the revoke chasing it must still wait.
        await new Promise((r) => setTimeout(r, 10));
        order.push('persist');
      },
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      (_conversationId, _target) => {
        order.push('revoke');
        return Promise.resolve();
      },
    );
    await slow.connectGateway('ws://x/ws');
    await slow.startConversation([{ deviceKey: hx('bb'), keyPackage: new Uint8Array([7]) }]);
    h.onDeliver({
      messageId: new Uint8Array([1]),
      routingKey: 'gmbox-0',
      payload: new Uint8Array([APP, ...padToBucket(frameMessage(new TextEncoder().encode('target'), LIFE))]),
      ttlSeconds: 60,
    });
    h.onDeliver({
      messageId: new Uint8Array([2]),
      routingKey: 'gmbox-0',
      payload: new Uint8Array([APP, ...padToBucket(frameRevoke('0102'))]),
      ttlSeconds: 60,
    });
    await new Promise((r) => setTimeout(r, 40));
    expect(order).toEqual(['persist', 'revoke']);
  });

  it('revokeMessage publishes an encrypted revoke frame and resolves only on ITS gateway receipt', async () => {
    await ch.connectGateway('ws://x/ws');
    const model = await ch.startConversation([{ deviceKey: hx('bb'), keyPackage: new Uint8Array([7]) }]);
    const before = tx.published.length;
    let settled = false;
    const pending = ch.revokeMessage(model.conversationId ?? '', 'deadbeef').then(() => {
      settled = true;
    });
    expect(tx.published.length).toBe(before + 1);
    const env = tx.published[tx.published.length - 1]!;
    expect(env.routingKey).toBe('gmbox-0');
    // The fake's encrypt prefixes APP; inside rides the padded revoke frame with the target id.
    expect(env.payload[0]).toBe(APP);
    expect(parseFrame(unpadFromBucket(env.payload.slice(1)))).toEqual({ type: 'revoke', targetMessageId: 'deadbeef' });
    // Hand-off is not delivery: a receipt for a DIFFERENT publish leaves the revoke unconfirmed.
    handlers.onReceipt(new Uint8Array([9, 9, 9]));
    await Promise.resolve();
    await Promise.resolve();
    expect(settled).toBe(false);
    // The receipt carrying the revoke frame's own message id resolves it.
    handlers.onReceipt(env.messageId);
    await pending;
    expect(settled).toBe(true);
    // Revoking on a conversation that is not open rejects instead of silently doing nothing.
    await expect(ch.revokeMessage('c-nope', 'deadbeef')).rejects.toThrow();
  });

  it('revokeMessage REJECTS on receipt timeout, so the caller keeps its local copy', async () => {
    await ch.connectGateway('ws://x/ws');
    const model = await ch.startConversation([{ deviceKey: hx('bb'), keyPackage: new Uint8Array([7]) }]);
    const before = scheduled.length;
    const pending = ch.revokeMessage(model.conversationId ?? '', 'deadbeef');
    const rejection = expect(pending).rejects.toThrow(/did not confirm/);
    expect(scheduled.length).toBe(before + 1); // the receipt-timeout backstop armed with the publish
    scheduled[before]!(); // the backstop fires: the receipt never arrived
    await rejection;
    // A receipt that straggles in after the timeout has no waiter left and is dropped harmlessly.
    const env = tx.published[tx.published.length - 1]!;
    handlers.onReceipt(env.messageId);
  });

  it('revokeMessage REJECTS when the connection closes before the receipt (the dead-link instant)', async () => {
    await ch.connectGateway('ws://x/ws');
    const model = await ch.startConversation([{ deviceKey: hx('bb'), keyPackage: new Uint8Array([7]) }]);
    const pending = ch.revokeMessage(model.conversationId ?? '', 'deadbeef');
    const rejection = expect(pending).rejects.toThrow(/connection closed/);
    handlers.onClose?.(); // the link died after the hand-off but before the gateway confirmed
    await rejection;
  });

  it('revokeMessage REJECTS when the socket is already dead at publish', async () => {
    await ch.connectGateway('ws://x/ws');
    const model = await ch.startConversation([{ deviceKey: hx('bb'), keyPackage: new Uint8Array([7]) }]);
    tx.closed = true;
    await expect(ch.revokeMessage(model.conversationId ?? '', 'deadbeef')).rejects.toThrow('connection closed');
  });

  it('re-subscribes to the rotated mailbox on a membership change', async () => {
    await ch.connectGateway('ws://x/ws');
    await ch.startConversation([{ deviceKey: hx('bb'), keyPackage: new Uint8Array([7]) }]);
    deliver('gmbox-0', new Uint8Array([COMMIT_ADD])); // an add commit advances the epoch
    expect(tx.subscribed).toContain('gmbox-1'); // re-subscribed to the new epoch's mailbox
    expect(events.some((e) => e.kind === 'roster-changed')).toBe(true);
  });

  it('sends a message to the group mailbox and persists our copy', async () => {
    await ch.connectGateway('ws://x/ws');
    const model = await ch.startConversation([{ deviceKey: hx('bb'), keyPackage: new Uint8Array([7]) }]);
    await ch.sendMessage(model.conversationId ?? '', 'on my way');
    const sent = tx.published.find((p) => p.routingKey === 'gmbox-0');
    expect(sent).toBeTruthy();
    expect(messages).toContainEqual({ direction: 'out', text: 'on my way' });
  });

  it('publishes our identity to the group on create (E2E control frame)', async () => {
    await ch.connectGateway('ws://x/ws');
    await ch.startConversation([{ deviceKey: hx('bb'), keyPackage: new Uint8Array([7]) }]);
    await Promise.resolve();
    await Promise.resolve(); // let the async identity publish run
    expect(identityFramesCalls).toBeGreaterThan(0);
    expect(tx.published.some((p) => p.routingKey === 'gmbox-0')).toBe(true); // a control frame rode the group mailbox
  });

  it('stores a peer identity frame from a current member, and drops a self-echo or a non-member', async () => {
    await ch.connectGateway('ws://x/ws');
    await ch.startConversation([{ deviceKey: hx('bb'), keyPackage: new Uint8Array([7]) }]);
    peerIdentitySaves = [];
    const ctrl = (k: string): Uint8Array =>
      new Uint8Array([APP, ...padToBucket(frameControl(CONTROL_BUDDY_ICON, 1, new TextEncoder().encode(JSON.stringify({ k, icon: { kind: 'emoji', value: 'X', bg: '#111' } }))))]);
    deliver('gmbox-0', ctrl(hx('bb'))); // from a current member -> stored
    expect(peerIdentitySaves.map((s) => s.key)).toContain(hx('bb'));
    const after = peerIdentitySaves.length;
    deliver('gmbox-0', ctrl(SELF)); // our own key echoed back -> dropped
    deliver('gmbox-0', ctrl(hx('dd'))); // not a roster member -> dropped
    expect(peerIdentitySaves.length).toBe(after);
  });

  it('routes an identity frame from our OWN account to the sibling-identity handler, not the peer store', async () => {
    await ch.connectGateway('ws://x/ws');
    await ch.startConversation([{ deviceKey: hx('bb'), keyPackage: new Uint8Array([7]) }]);
    peerIdentitySaves = [];
    siblingIdentities = [];
    conv.fromOwnAccount = true; // the next received app frame is crypto-flagged as from one of our devices
    const ownIcon = new Uint8Array([
      APP,
      ...padToBucket(
        frameControl(
          CONTROL_BUDDY_ICON,
          1,
          new TextEncoder().encode(JSON.stringify({ k: hx('bb'), icon: { kind: 'emoji', value: 'Z', bg: '#222' }, v: 5 })),
        ),
      ),
    ]);
    deliver('gmbox-0', ownIcon);
    expect(siblingIdentities).toHaveLength(1); // adopted as an OWN-identity update (sibling sync)
    expect(siblingIdentities[0]?.controlType).toBe(CONTROL_BUDDY_ICON);
    expect(peerIdentitySaves).toHaveLength(0); // NOT stored as a peer identity
  });

  it('adopts an away frame from our OWN account, and STORES a peer away frame as their peer identity (the buddy-list subtitle)', async () => {
    await ch.connectGateway('ws://x/ws');
    await ch.startConversation([{ deviceKey: hx('bb'), keyPackage: new Uint8Array([7]) }]);
    const awayFrame = (): Uint8Array =>
      new Uint8Array([
        APP,
        ...padToBucket(
          frameControl(
            CONTROL_AWAY,
            1,
            new TextEncoder().encode(JSON.stringify({ k: hx('bb'), away: { enabled: true, message: 'biking', serverSide: false }, v: 7 })),
          ),
        ),
      ]);
    // From one of our own devices: adopted (sibling sync), never stored as a peer.
    peerIdentitySaves = [];
    siblingIdentities = [];
    conv.fromOwnAccount = true;
    deliver('gmbox-0', awayFrame());
    expect(siblingIdentities).toHaveLength(1);
    expect(siblingIdentities[0]?.controlType).toBe(CONTROL_AWAY);
    expect(peerIdentitySaves).toHaveLength(0);
    // From a peer (a different account): NOT adopted into our own card, but STORED as the peer's identity
    // so their away message can show as the dim buddy-list subtitle while they are away.
    peerIdentitySaves = [];
    siblingIdentities = [];
    conv.fromOwnAccount = false;
    deliver('gmbox-0', awayFrame());
    expect(siblingIdentities).toHaveLength(0);
    expect(peerIdentitySaves).toHaveLength(1);
    expect(peerIdentitySaves[0]?.controlType).toBe(CONTROL_AWAY);
  });

  it('creates the hidden self-group: subscribes, welcomes siblings, publishes the buddy list, and stays out of the channel list', async () => {
    await ch.connectGateway('ws://x/ws');
    conv.selfConversation = true; // the group we are about to create is all our own devices
    buddiesFrame = new TextEncoder().encode(JSON.stringify({ buddies: { raven: { addedAt: 1, v: 9, removed: false } } }));
    channels.length = 0;
    await ch.createSelfGroup([{ deviceKey: hx('bb'), keyPackage: new Uint8Array([7]) }]);
    await Promise.resolve();
    await Promise.resolve(); // let the async buddy/identity publishes run
    expect(ch.hasSelfGroup()).toBe(true);
    expect(tx.subscribed).toContain('gmbox-0'); // subscribed to the self-group mailbox
    expect(tx.published.some((p) => p.routingKey === hx('bb'))).toBe(true); // the Welcome reached the sibling
    expect(channels.length).toBe(0); // NO channel summary: it never appears as a conversation
    expect(events.some((e) => e.kind === 'established')).toBe(false); // and never opens a conversation view
    // Both our identity (1 frame) AND the buddy list (1 frame) rode the self-group mailbox, so the buddy
    // list reaches the joining sibling. The fake identity source yields exactly one frame.
    expect(tx.published.filter((p) => p.routingKey === 'gmbox-0').length).toBeGreaterThanOrEqual(2);
  });

  // ── TWO-DEVICE CONVERGENCE GATE ─────────────────────────────────────────────────────────────────
  // The self-group split (2026-08-01) shipped because NOTHING at any layer asserted that two devices
  // end up on the SAME self-group. The shared FakeConv returns the constant GID from BOTH createGroup
  // and joinFromWelcome, and FakeTransport.publish only appends to an array, so the assertion in the
  // formation test above ("the Welcome reached the sibling") holds even when the sibling joins nothing.
  // These tests wire two real GroupChannels over one bus, give each mint a DISTINCT group id, and make
  // the joiner derive its id from the Welcome BYTES — the property real MLS has — so a device that
  // fails to join now fails the test.
  class PairedConv extends FakeConv {
    joinThrow: string | null = null; // models a wasm join rejection (e.g. NoMatchingKeyPackage)
    mintedGid: string | null = null;
    joinedGid: string | null = null;
    constructor(sig: string, private readonly ownGid: string) {
      super(sig, []);
      this.selfConversation = true;
    }
    override createSelfGroup(): Uint8Array {
      this.hasGroup = true;
      this.mintedGid = this.ownGid;
      this.members = [this.signaturePublicKeyHex(), 'sibling']; // founding roster: us + the welcomed device
      const gid = hexToBytesTop(this.ownGid);
      return encodeList([new Uint8Array([0x57, ...gid]), gid]); // the Welcome CARRIES the group id
    }
    override joinFromWelcome(welcome: Uint8Array): string {
      if (this.joinThrow !== null) {
        throw new Error(this.joinThrow);
      }
      this.hasGroup = true;
      this.members = [this.signaturePublicKeyHex(), 'minter']; // we joined a group that already had the minter
      this.joinedGid = bytesToHex(welcome.slice(1));
      return this.joinedGid;
    }
    override listConversations(): string[] {
      return [this.mintedGid, this.joinedGid].filter((g): g is string => g !== null);
    }
    override groupMailbox(id: string): string {
      return `gmbox-${id}`;
    }
    // Route a received frame to whichever group THIS device actually holds, instead of the file-wide
    // constant GID — otherwise a two-device exchange "receives" into a conversation neither device has.
    override receive(ct: Uint8Array): Uint8Array {
      const gid = this.joinedGid ?? this.mintedGid;
      if (gid === null) {
        throw new Error('no group');
      }
      return encodeList([hexToBytesTop(gid), this.receiveBlob(ct)]);
    }
  }

  interface Dev {
    conv: PairedConv;
    ch: GroupChannel;
    handlers: TransportHandlers;
    subscribed: Set<string>;
    outbox: PendingWelcome[];
  }

  // A hold-until-ack bus shared by both devices, mirroring gateway/internal/bus: a blob is delivered to
  // every subscriber of its routing key and stays queued until it is ACKED (so an unacked Welcome is
  // redelivered on the next flush, exactly as a re-subscribe would).
  function makeBus(): { devs: Dev[]; queue: EnvelopeMsg[]; acked: Set<string>; flush: () => void } {
    const devs: Dev[] = [];
    const queue: EnvelopeMsg[] = [];
    const acked = new Set<string>();
    const flush = (): void => {
      for (const env of [...queue]) {
        for (const d of devs) {
          if (d.subscribed.has(env.routingKey)) {
            d.handlers.onDeliver(env);
          }
        }
      }
      for (let i = queue.length - 1; i >= 0; i--) {
        const q = queue[i];
        if (q !== undefined && acked.has(bytesToHex(q.messageId))) {
          queue.splice(i, 1);
        }
      }
    };
    return { devs, queue, acked, flush };
  }

  function addDevice(bus: ReturnType<typeof makeBus>, sig: string, gid: string): Dev {
    const pconv = new PairedConv(sig, gid);
    const subscribed = new Set<string>();
    let captured: TransportHandlers;
    const transport = {
      setConsumerIdResolver: () => {},
      subscribe: (k: string) => subscribed.add(k),
      publish: (e: EnvelopeMsg) => queuePush(e),
      ack: (id: Uint8Array) => bus.acked.add(bytesToHex(id)),
      sendOffer: () => {},
      sendAccept: () => {},
      takePending: () => [],
      close: () => {},
    };
    const queuePush = (e: EnvelopeMsg): void => {
      bus.queue.push(e);
    };
    const deps: GroupDeps = {
      connect: (_url, h) => {
        captured = h;
        return transport as unknown as Transport;
      },
      makeConversation: () => pconv,
      pushEvent: () => {},
      schedule: () => 1,
      cancel: () => {},
      sealConversation: () => new Uint8Array(),
      restoreConversation: () => pconv,
      sasDigestHex: () => '00'.repeat(32),
    };
    // A durable, device-local outbox store (the real one seals under the MSK in IndexedDB).
    let outbox: PendingWelcome[] = [];
    const persistence: GroupPersistence = {
      loadSelf: () => Promise.resolve(null),
      saveSelf: () => Promise.resolve(),
      resealSelf: () => Promise.resolve(true),
      recoverySeedHex: () => Promise.resolve(''),
      loadWelcomeOutbox: () => Promise.resolve([...outbox]),
      saveWelcomeOutbox: (e) => {
        outbox = [...e];
        return Promise.resolve();
      },
    };
    const channel = new GroupChannel(deps, () => Promise.resolve(), () => Promise.resolve(), persistence);
    const dev: Dev = {
      conv: pconv,
      ch: channel,
      get handlers(): TransportHandlers {
        return captured;
      },
      subscribed,
      get outbox(): PendingWelcome[] {
        return outbox;
      },
    } as Dev;
    bus.devs.push(dev);
    return dev;
  }

  it('TWO DEVICES CONVERGE: the sibling joins the minter self-group and both report the SAME id', async () => {
    const bus = makeBus();
    const phone = addDevice(bus, hx('d7'), '9a86'); // the designated minter (lowest device key)
    const laptop = addDevice(bus, hx('fc'), '2e44'); // defers, joins via the Welcome
    await phone.ch.connectGateway('ws://x/ws');
    await laptop.ch.connectGateway('ws://x/ws');

    await phone.ch.createSelfGroup([{ deviceKey: hx('fc'), keyPackage: new Uint8Array([7]) }]);
    bus.flush();
    await new Promise((r) => setTimeout(r, 0));

    // THE assertion the old suite never made. Without it, a laptop sitting on its own self-group and a
    // phone sitting on another both look "healthy" to every other test in this file.
    expect(laptop.ch.selfConversationId()).toBe(phone.ch.selfConversationId());
    expect(laptop.ch.selfConversationId()).toBe('c-9a86'); // and it is the MINTER's group, not a second one
    expect(laptop.conv.mintedGid).toBeNull(); // the joiner never minted a competing group
  });

  it('a self-group Welcome whose join FAILS is not acked away, and converges once the join can succeed', async () => {
    // Fix C. The bare `catch { ack(); return; }` acked a failed join, and an ack destroys the only copy
    // on a hold-until-ack bus — one transient failure split the account permanently and silently.
    // The example here must be a genuinely RETRYABLE error: a Welcome that cannot open because its key
    // package is gone is permanent and is acked on purpose (see the publish-loop test below). A storage
    // hiccup is the real case this protects — it succeeds on the very next delivery.
    const bus = makeBus();
    const phone = addDevice(bus, hx('d7'), '9a86');
    const laptop = addDevice(bus, hx('fc'), '2e44');
    await phone.ch.connectGateway('ws://x/ws');
    await laptop.ch.connectGateway('ws://x/ws');
    laptop.conv.joinThrow = 'process welcome: storage write failed';

    await phone.ch.createSelfGroup([{ deviceKey: hx('fc'), keyPackage: new Uint8Array([7]) }]);
    bus.flush();
    await new Promise((r) => setTimeout(r, 0));

    expect(laptop.ch.selfConversationId()).toBeNull(); // the join failed
    expect(bus.acked.size).toBe(0); // ...and the Welcome was NOT destroyed
    expect(bus.queue.length).toBe(1); // it is still queued for redelivery

    laptop.conv.joinThrow = null; // the sender re-sealed a fresh package / the vault unlocked
    bus.flush();
    await new Promise((r) => setTimeout(r, 0));
    expect(laptop.ch.selfConversationId()).toBe(phone.ch.selfConversationId()); // self-healed
  });

  it('the on-screen diagnostic distinguishes a converged pair from a device whose join was REJECTED', async () => {
    // The phone has no usable console and device-local MLS state is invisible to the keyless gateway,
    // so this line IS the instrument. Roster size answers what the group id alone cannot — which device
    // minted — and W<seen>/<joined> says what an arriving Welcome actually did.
    const ok = makeBus();
    const phoneOk = addDevice(ok, hx('d7'), '9a86');
    const laptopOk = addDevice(ok, hx('fc'), '2e44');
    await phoneOk.ch.connectGateway('ws://x/ws');
    await laptopOk.ch.connectGateway('ws://x/ws');
    await phoneOk.ch.createSelfGroup([{ deviceKey: hx('fc'), keyPackage: new Uint8Array([7]) }]);
    ok.flush();
    await new Promise((r) => setTimeout(r, 0));
    // A healthy pair: BOTH sides report a populated group, and the joiner logs a Welcome it consumed.
    expect(phoneOk.ch.selfGroupDiagnostic()).toBe('2 devices · W0/0'); // the minter saw no Welcome
    expect(laptopOk.ch.selfGroupDiagnostic()).toBe('2 devices · W1/1'); // the joiner saw one and used it

    const bad = makeBus();
    const phoneBad = addDevice(bad, hx('d7'), '9a86');
    const laptopBad = addDevice(bad, hx('fc'), '2e44');
    await phoneBad.ch.connectGateway('ws://x/ws');
    await laptopBad.ch.connectGateway('ws://x/ws');
    laptopBad.conv.joinThrow = 'process welcome: WelcomeError(NoMatchingKeyPackage)';
    await phoneBad.ch.createSelfGroup([{ deviceKey: hx('fc'), keyPackage: new Uint8Array([7]) }]);
    bad.flush();
    await new Promise((r) => setTimeout(r, 0));
    // The split, legible on the device: a Welcome arrived, produced nothing, and named its own cause.
    expect(laptopBad.ch.selfGroupDiagnostic()).toBe('W1/0 · NoMatchingKeyPackage');
  });

  it('a founding Welcome DESTROYED by a gateway restart is re-published from the durable outbox', async () => {
    // The durability requirement. gateway/internal/bus holds undelivered blobs in a plain in-process
    // map and clamps the TTL to 24h, and the unit has no queue hand-off, so any restart silently
    // vaporises a Welcome in flight. The gateway is deliberately amnesiac (nothing at rest, threat
    // model unchanged), so the SENDER has to be the durable party.
    const bus = makeBus();
    const phone = addDevice(bus, hx('d7'), '9a86');
    const laptop = addDevice(bus, hx('fc'), '2e44');
    await phone.ch.connectGateway('ws://x/ws');
    await laptop.ch.connectGateway('ws://x/ws');

    await phone.ch.createSelfGroup([{ deviceKey: hx('fc'), keyPackage: new Uint8Array([7]) }]);
    expect(phone.outbox).toHaveLength(1); // the sender kept its own copy

    bus.queue.length = 0; // ── the gateway restarts: every held blob is gone, nobody is told ──
    bus.flush();
    await new Promise((r) => setTimeout(r, 0));
    expect(laptop.ch.selfConversationId()).toBeNull(); // the Welcome really was lost

    await phone.ch.connectGateway('ws://x/ws'); // the phone reconnects to the fresh gateway
    bus.flush();
    await new Promise((r) => setTimeout(r, 0));
    expect(laptop.ch.selfConversationId()).toBe(phone.ch.selfConversationId()); // recovered

    // And the entry retires on PROOF the sibling is live (a frame we did not author), not on roster
    // membership — the roster is asserted unilaterally by the adder and is what made the split invisible.
    const cid = laptop.ch.selfConversationId();
    await laptop.ch.sendMessage(cid as string, 'hello from the sibling');
    bus.flush();
    await new Promise((r) => setTimeout(r, 0));
    expect(phone.outbox).toHaveLength(0);
  });

  it('an UNOPENABLE Welcome is acked once and the outbox stops replaying it (no publish loop)', async () => {
    // Observed live: a mobile client reported W1707/0 — 1707 Welcomes seen, none joined. Two of my own
    // changes multiplied together. NoMatchingKeyPackage was not on the permanent list, so a Welcome
    // sealed to a key package whose private half is gone was never acked and redelivered on every
    // re-subscribe; and the outbox re-published a NEW envelope (new messageId) on every reconnect, so
    // copies accumulated up to the bus cap and EACH of them redelivered. A dead Welcome must die once.
    const bus = makeBus();
    const phone = addDevice(bus, hx('d7'), '9a86');
    const laptop = addDevice(bus, hx('fc'), '2e44');
    await phone.ch.connectGateway('ws://x/ws');
    await laptop.ch.connectGateway('ws://x/ws');
    laptop.conv.joinThrow = 'process welcome: WelcomeError(NoMatchingKeyPackage)';

    await phone.ch.createSelfGroup([{ deviceKey: hx('fc'), keyPackage: new Uint8Array([7]) }]);
    bus.flush();
    await new Promise((r) => setTimeout(r, 0));

    // The recipient can never open it, so it is acked and DROPPED rather than held for redelivery.
    expect(laptop.ch.selfConversationId()).toBeNull();
    expect(bus.acked.size).toBe(1);
    expect(bus.queue.length).toBe(0);

    // And the sender gives up rather than re-publishing forever: many reconnects must not grow the
    // recipient's mailbox without bound.
    for (let i = 0; i < 20; i++) {
      await phone.ch.connectGateway('ws://x/ws');
      bus.flush();
      await new Promise((r) => setTimeout(r, 0));
    }
    expect(phone.outbox).toHaveLength(0); // retired after the attempt cap
    expect(bus.queue.length).toBe(0); // nothing left pinned in the mailbox
  });

  it('syncBuddies publishes the buddy list ONLY to the self-group, never to a peer conversation', async () => {
    await ch.connectGateway('ws://x/ws');
    // A normal (peer) conversation: not a self-group.
    conv.selfConversation = false;
    await ch.startConversation([{ deviceKey: hx('bb'), keyPackage: new Uint8Array([7]) }]);
    await Promise.resolve();
    await Promise.resolve(); // let startConversation's async identity publish land before we clear
    buddiesFrame = new TextEncoder().encode(JSON.stringify({ buddies: {} }));
    tx.published = [];
    expect(ch.hasSelfGroup()).toBe(false);
    ch.syncBuddies(); // no self-group open: must publish nothing (the contact graph never rides a peer roster)
    await Promise.resolve();
    await Promise.resolve();
    expect(tx.published).toHaveLength(0);
  });

  it('a reconnect RE-PUBLISHES the contact graph into the self-group, so a sibling that missed a one-time frame converges', async () => {
    // SG2 convergence. When the laptop first added the phone, the phone's certificate had not settled,
    // so the phone RECEIVED the buddy frame, saw it as not-from-our-account, dropped it, and acked it off
    // the bus. The frame is gone. Without a re-publish the phone waits for a buddy-list EDIT that may
    // never happen. On every reconnect we re-publish into the canonical self-group (idempotent CRDT), so
    // any device that missed an earlier one-time publish converges on the next reconnect of ANY member.
    await ch.connectGateway('ws://x/ws');
    conv.selfConversation = true;
    await ch.openSelfConversation(); // a self-group now exists and is restored on reconnect
    buddiesFrame = new TextEncoder().encode(JSON.stringify({ buddies: { raven: { addedAt: 1, v: 9, removed: false } } }));
    tx.published = [];
    await ch.connectGateway('ws://x/ws'); // reconnect
    await Promise.resolve();
    await Promise.resolve(); // let the async resync publishes land
    // Identity AND buddy list AND group list rode the self-group mailbox on reconnect.
    expect(tx.published.filter((p) => p.routingKey === 'gmbox-0').length).toBeGreaterThanOrEqual(2);
  });

  it('the reconnect resync NEVER publishes the contact graph when the only conversation is a peer roster', async () => {
    // The load-bearing privacy guard: the resync is self-group-gated. A device whose only conversation is
    // with a PEER must publish NOTHING on reconnect, or its buddy list would ride a roster the peer reads.
    await ch.connectGateway('ws://x/ws');
    conv.selfConversation = false; // a peer conversation, never a self-group
    await ch.startConversation([{ deviceKey: hx('bb'), keyPackage: new Uint8Array([7]) }]);
    await Promise.resolve();
    await Promise.resolve();
    buddiesFrame = new TextEncoder().encode(JSON.stringify({ buddies: { raven: { addedAt: 1, v: 9, removed: false } } }));
    tx.published = [];
    await ch.connectGateway('ws://x/ws'); // reconnect
    await Promise.resolve();
    await Promise.resolve();
    // No buddy/group/identity frame on the peer's group mailbox: the resync found no self-group and did nothing.
    expect(tx.published.some((p) => p.routingKey === 'gmbox-0')).toBe(false);
  });

  it('a POPULATED self-group outranks a certified SOLO one, so a replacement mint cannot strand a device', async () => {
    // Notes stopped crossing devices: each device had minted a certified SOLO replacement self-group and
    // canonical selection preferred it (strict ranked ahead of population), orphaning the real shared
    // group. A solo self-group has nobody to deliver to, so it must never outrank a populated one, and
    // a populated group must SUFFICE (never trigger the replacement mint that creates the orphan).
    await ch.connectGateway('ws://x/ws');
    conv.selfConversation = true;
    conv.strictSelf = false; // the shared group classifies lenient-only (our frozen certless own leaf)
    conv.members = [SELF, SIBLING]; // ...but it HAS a sibling: it actually syncs
    await ch.startConversation([{ deviceKey: hx('bb'), keyPackage: new Uint8Array([7]) }]);
    await Promise.resolve();
    // THE ISLAND INVARIANT, stated precisely: openSelfConversation must hand back the EXISTING populated
    // group and must never mint a SOLO replacement over it. That is what stranded devices before.
    const opened = await ch.openSelfConversation();
    expect(opened).toBe(CID);
    expect(conv.createSelfCalls).toBe(0);
  });

  it('a populated self-group whose OWN leaf is certless asks for a CERTIFIED replacement (deadlock fix)', async () => {
    // The state that deadlocked a live account. lenient && !strict means OUR OWN leaf is the failing one
    // (lenient differs from strict solely by the own-leaf exemption), so the group looks healthy HERE and
    // is a ghost on every sibling. Nothing can rewrite a leaf credential, so hasSelfGroup must report
    // false and let the app mint a POPULATED certified replacement. Before this, hasSelfGroup returned
    // true forever and the device sat on an unusable group no reload could shift.
    await ch.connectGateway('ws://x/ws');
    conv.selfConversation = true;
    conv.strictSelf = false;
    conv.members = [SELF, SIBLING];
    await ch.startConversation([{ deviceKey: hx('bb'), keyPackage: new Uint8Array([7]) }]);
    await Promise.resolve();
    expect(ch.hasSelfGroup()).toBe(false); // the app will now mint a certified replacement

    // ANTI-LOOP: a device whose OWN credential is still label-only would mint an equally poisoned
    // group on every trigger, forever. It must park instead.
    conv.credentialCertifiedFlag = false;
    expect(ch.hasSelfGroup()).toBe(true);
    conv.credentialCertifiedFlag = true;

    // A CERT-ONLY device anchors nothing and must never drive a replacement: it waits for a Welcome.
    conv.accountKey = '';
    expect(ch.hasSelfGroup()).toBe(true);
    conv.accountKey = 'acct';

    // And once the group classifies strict, the replacement is no longer wanted.
    conv.strictSelf = null; // strict mirrors selfConversation === true
    expect(ch.hasSelfGroup()).toBe(true);
  });

  it('SG2 self-heal: a DEAD self-group is abandoned and unsubscribed, a LIVE one is never touched', async () => {
    // A self-group poisoned by a frozen certless leaf can never be repaired in place and never syncs. It
    // used to sit forever while the user closed it by hand on every device. The heal abandons it so a
    // clean one can form — but it must NEVER touch a working self-group, which is the property that
    // makes this safe to run automatically.
    await ch.connectGateway('ws://x/ws');
    conv.selfConversation = true;
    const id = await ch.openSelfConversation();

    // LIVE self-group: the crypto layer refuses, and the session stays put.
    expect(await ch.abandonDeadSelfGroup(id, true)).toBe(false);
    expect(conv.abandoned).toHaveLength(0);
    expect(ch.selfConversationId()).toBe(id); // still ours, still open

    // Not recorded as self: refused too (this is what protects a pending peer chat).
    conv.unlinkedGroups.add(GID);
    expect(await ch.abandonDeadSelfGroup(id, false)).toBe(false);
    expect(conv.abandoned).toHaveLength(0);

    // DEAD and recorded: abandoned, and the local session + subscription go with it.
    expect(await ch.abandonDeadSelfGroup(id, true)).toBe(true);
    expect(conv.abandoned).toEqual([GID]);
    expect(ch.selfConversationId()).toBeNull(); // no self-group held any more: a clean one can form
  });

  it('joins a self-group Welcome SILENTLY: subscribes and syncs buddies but never surfaces a conversation', async () => {
    await ch.connectGateway('ws://x/ws');
    conv.selfConversation = true; // the incoming Welcome is for a group of our own devices
    buddiesFrame = new TextEncoder().encode(JSON.stringify({ buddies: {} }));
    channels.length = 0;
    deliver(SELF, new Uint8Array([0x57])); // a Welcome arrives on our bootstrap mailbox
    await Promise.resolve();
    await Promise.resolve();
    expect(tx.subscribed).toContain('gmbox-0'); // we joined and subscribed
    expect(events.some((e) => e.kind === 'established')).toBe(false); // but it is NOT surfaced as a conversation
    expect(channels.length).toBe(0); // and no channel summary is written
    // Establishing the own-devices E2E context DOES flip the connection to secure (so the buddy list reads
    // SECURE LINK, not a perpetual SECURING), even though the self-group never appears as a conversation.
    expect(events.some((e) => e.kind === 'connection' && (e.payload as { state: string }).state === 'secure')).toBe(true);
  });

  it('openSelfConversation opens a SOLO self-group when none exists (Note to Self on a single device)', async () => {
    await ch.connectGateway('ws://x/ws');
    conv.selfConversation = true; // the group we create holds only this device, so it is a self-group
    channels.length = 0;
    const id = await ch.openSelfConversation();
    expect(id).toBe(`c-${GID}`);
    expect(ch.selfConversationId()).toBe(id); // it is now the open self-group
    expect(ch.hasSelfGroup()).toBe(true);
    expect(tx.subscribed).toContain('gmbox-0'); // subscribed to the solo group mailbox to receive syncs
    expect(channels.length).toBe(0); // NO channel summary: it is surfaced only as the Note-to-Self view
    expect(events.some((e) => e.kind === 'established')).toBe(false); // and never opens a normal conversation
    // Creating the self-group establishes this device's E2E context → the link reports secure.
    expect(events.some((e) => e.kind === 'connection' && (e.payload as { state: string }).state === 'secure')).toBe(true);
  });

  it('reconnect with a restored self-group reports SECURE immediately (not the transitional SECURING)', async () => {
    // First connect + create the self-group (persisted so listConversations restores it).
    await ch.connectGateway('ws://x/ws');
    conv.selfConversation = true;
    await ch.openSelfConversation();
    events.length = 0;
    // A reconnect restores the self-group session from listConversations; the connection event must be
    // 'secure' (an E2E session is live) rather than the bare 'live' transport-up state.
    await ch.connectGateway('ws://x/ws');
    const connEvents = events.filter((e) => e.kind === 'connection').map((e) => (e.payload as { state: string }).state);
    expect(connEvents).toContain('secure');
    expect(connEvents).not.toContain('live'); // never the perpetual-SECURING state when a session exists
  });

  it('a staged add that survived a reload is re-published and re-armed, and its backstop abandons it', async () => {
    // Simulate a reload with a commit in flight: the restored conversation reports a persisted pending
    // Add (Batch B). connectGateway must re-publish the EXACT wire bytes (commit to the group mailbox,
    // Welcome to the added device), mark pendingOps (so reconcile cannot re-stage a forking duplicate),
    // and re-arm the confirm backstop.
    const target = hx('cc');
    conv.hasGroup = true; // the group itself was restored from storage
    conv.pending = target; // the crypto layer's restored staged add (confirmAdd consumes it; drives the getters)
    conv.stagedCommitBytes = new Uint8Array([COMMIT_ADD, ...hexToBytesTop(target)]);
    conv.stagedWelcomeBytes = new Uint8Array([0x57]);
    scheduled.length = 0;
    await ch.connectGateway('ws://x/ws');
    // The original commit bytes went back out on the epoch-N group mailbox, and the Welcome to the target.
    expect(tx.published.some((p) => p.routingKey === 'gmbox-0' && p.payload[0] === COMMIT_ADD)).toBe(true);
    expect(tx.published.some((p) => p.routingKey === target && p.payload[0] === 0x57)).toBe(true);
    // Re-staging is blocked while the restored add is in flight (the double guard).
    const before = tx.published.length;
    await ch.reconcileSiblings([SELF, target], [{ deviceKey: target, keyPackage: hexToBytesTop(target) }]);
    expect(tx.published.length).toBe(before); // pendingOps bail: no second, forking commit
    // No echo arrives. The re-armed backstop is still only a wall clock, so it abandons the staged
    // commit rather than merging it: the device stays on the epoch its peers are on, and the stalled
    // membership change is reported instead of being silently claimed as done.
    expect(scheduled.length).toBeGreaterThan(0);
    scheduled.forEach((cb) => cb());
    expect(conv.roster()).not.toContain(target);
    expect(events.some((e) => e.kind === 'roster-changed')).toBe(false);
    expect(events.some((e) => e.kind === 'membership-stalled')).toBe(true);
  });

  it('openSelfConversation refuses on a cert-only device (no account key) instead of minting an unrecognized group', async () => {
    await ch.connectGateway('ws://x/ws');
    conv.accountKey = ''; // a device provisioned by QR/six words holds a cert but not the account key
    channels.length = 0;
    await expect(ch.openSelfConversation()).rejects.toThrow();
    expect(ch.selfConversationId()).toBeNull(); // nothing was created
  });

  it('createSelfGroup is a no-op when a self-group already exists (the Note-to-Self TOCTOU race)', async () => {
    // The app checks hasSelfGroup(), then fetches sibling key packages over the network, THEN calls
    // createSelfGroup. Note to Self can mint a solo self-group inside that window; createSelfGroup must
    // re-check or two self-groups would exist and the devices would sync over different ones.
    await ch.connectGateway('ws://x/ws');
    conv.selfConversation = true;
    await ch.openSelfConversation(); // the solo self-group appears mid-window
    const first = ch.selfConversationId();
    tx.published = [];
    await ch.createSelfGroup([{ deviceKey: hx('bb'), keyPackage: new Uint8Array([7]) }]);
    expect(ch.selfConversationId()).toBe(first); // still the SAME single self-group
    expect(tx.published).toHaveLength(0); // and no second-group Welcome went out
  });

  it('a seed-holder whose best self-group is lenient-only mints a certified replacement', async () => {
    await ch.connectGateway('ws://x/ws');
    conv.selfConversation = true;
    // openSelfConversation mints a SOLO group; model that roster explicitly. The certified-replacement
    // mint is only for a solo/degraded copy: a POPULATED lenient self-group suffices and must never be
    // replaced (replacing it strands this device alone and notes stop crossing devices).
    conv.members = [SELF];
    await ch.openSelfConversation(); // the only self-group held (strict by default: healthy)
    expect(conv.createSelfCalls).toBe(1);
    expect(ch.hasSelfGroup()).toBe(true); // a certified best suffices
    // The degraded state: the group classifies self only via the own-leaf exemption.
    conv.strictSelf = false;
    expect(ch.hasSelfGroup()).toBe(false); // the app's mint gates see "needs a certified replacement"
    await ch.openSelfConversation(); // does NOT reuse the degraded copy: mints the replacement
    expect(conv.createSelfCalls).toBe(2);
    conv.strictSelf = null; // the replacement is certified
    await ch.openSelfConversation(); // and from then on it is reused
    expect(conv.createSelfCalls).toBe(2);
  });

  it('the self-group birth gate: a rejected founding package aborts the mint with no session added', async () => {
    await ch.connectGateway('ws://x/ws');
    conv.createSelfGroupThrow = 'self-group member without a certificate';
    await expect(ch.createSelfGroup([{ deviceKey: hx('bb'), keyPackage: new Uint8Array([7]) }])).rejects.toThrow('without a certificate');
    expect(ch.hasSelfGroup()).toBe(false); // nothing was minted; the caller retries with the next package
    conv.createSelfGroupThrow = null;
  });

  it('the birth pre-filter mints with the certified survivors and welcomes ONLY them', async () => {
    await ch.connectGateway('ws://x/ws');
    // All-stale first: nothing to found with; defer (the caller warn-and-retries on the next trigger).
    conv.selfEligible = () => false;
    await expect(ch.createSelfGroup([{ deviceKey: hx('ee'), keyPackage: new Uint8Array([0x77]) }])).rejects.toThrow('no certified sibling');
    expect(ch.hasSelfGroup()).toBe(false);
    // One stale package (ineligible) beside one certified sibling: the mint proceeds with the
    // survivor instead of aborting the whole batch (a reusable stale last-resort would never drain).
    conv.selfEligible = (kp): boolean => kp[0] !== 0x77; // 0x77 marks the stale package
    conv.selfConversation = true; // the minted own-devices group classifies self
    tx.published = [];
    await ch.createSelfGroup([
      { deviceKey: hx('dd'), keyPackage: new Uint8Array([0x77]) }, // stale: filtered out
      { deviceKey: hx('bb'), keyPackage: new Uint8Array([7]) }, // certified: founds the group
    ]);
    expect(ch.hasSelfGroup()).toBe(true);
    expect(tx.published.some((p) => p.routingKey === hx('bb'))).toBe(true); // the survivor got the Welcome
    expect(tx.published.some((p) => p.routingKey === hx('dd'))).toBe(false); // the dropped device did NOT
    conv.selfEligible = null;
  });

  it('the mint guard re-certifies an uncertified seed-holder before minting key packages', async () => {
    await ch.connectGateway('ws://x/ws');
    conv.credentialCertifiedFlag = false; // legacy label-only credential on a seed-holder
    await ch.freshKeyPackages(3);
    expect(conv.reauthorized).toBe(1); // re-certified once, BEFORE the packages were minted
    conv.credentialCertifiedFlag = true;
    await ch.freshKeyPackages(3);
    expect(conv.reauthorized).toBe(1); // a certified credential mints without touching the cert
  });

  it('a legacy label-only seed-holder never re-mints: its replacement would be lenient-only too', async () => {
    await ch.connectGateway('ws://x/ws');
    conv.selfConversation = true;
    conv.strictSelf = false; // every group this credential mints classifies lenient-only
    conv.credentialCertifiedFlag = false; // the legacy pre-cert sealed-blob state
    await ch.openSelfConversation(); // the first open mints the one self-group this device gets
    expect(conv.createSelfCalls).toBe(1);
    expect(ch.hasSelfGroup()).toBe(true); // the degraded best SUFFICES here: minting again cannot improve it
    await ch.openSelfConversation(); // stable: reused, not re-minted (was: one more group per open, forever)
    expect(conv.createSelfCalls).toBe(1);
  });

  it('a legacy label-only credential never triggers the replacement mint (no unbounded re-mint)', async () => {
    await ch.connectGateway('ws://x/ws');
    conv.selfConversation = true;
    await ch.openSelfConversation();
    expect(conv.createSelfCalls).toBe(1);
    // Degraded best AND a label-only credential: a replacement would come out lenient-only too, so
    // the existing group must suffice; otherwise every trigger would mint another group forever.
    conv.strictSelf = false;
    conv.credentialCertifiedFlag = false;
    expect(ch.hasSelfGroup()).toBe(true); // stable: the mint gates stay closed
    await ch.openSelfConversation(); // reused, not replaced
    expect(conv.createSelfCalls).toBe(1);
  });

  it('openSelfConversation REUSES an existing self-group rather than creating a second one', async () => {
    await ch.connectGateway('ws://x/ws');
    conv.selfConversation = true;
    await ch.createSelfGroup([{ deviceKey: hx('bb'), keyPackage: new Uint8Array([7]) }]);
    const first = ch.selfConversationId();
    const subsBefore = tx.subscribed.length;
    const id = await ch.openSelfConversation();
    expect(id).toBe(first); // same conversation, no new group minted
    expect(tx.subscribed.length).toBe(subsBefore); // and no fresh subscription
  });

  it('adopts a CONTROL_BUDDIES frame from our OWN account and DROPS one from a peer', async () => {
    await ch.connectGateway('ws://x/ws');
    conv.selfConversation = true;
    await ch.createSelfGroup([{ deviceKey: hx('bb'), keyPackage: new Uint8Array([7]) }]);
    const buddiesCtrl = (): Uint8Array =>
      new Uint8Array([APP, ...padToBucket(frameControl(CONTROL_BUDDIES, 1, new TextEncoder().encode(JSON.stringify({ buddies: { owl: { addedAt: 1, v: 3, removed: false } } }))))]);
    // From one of our own devices (fromOwnAccount): adopted (the buddy list converges).
    buddiesAdopted = [];
    conv.fromOwnAccount = true;
    deliver('gmbox-0', buddiesCtrl());
    expect(buddiesAdopted).toHaveLength(1);
    // From a peer (fromOwnAccount false): dropped (the contact graph is never adopted from a peer).
    buddiesAdopted = [];
    conv.fromOwnAccount = false;
    deliver('gmbox-0', buddiesCtrl());
    expect(buddiesAdopted).toHaveLength(0);
  });

  it('syncGroups publishes the group list ONLY to the self-group, never to a peer conversation', async () => {
    await ch.connectGateway('ws://x/ws');
    conv.selfConversation = false; // a normal (peer) conversation
    await ch.startConversation([{ deviceKey: hx('bb'), keyPackage: new Uint8Array([7]) }]);
    await Promise.resolve();
    await Promise.resolve();
    groupsFrame = new TextEncoder().encode(JSON.stringify({ groups: {} }));
    tx.published = [];
    expect(ch.hasSelfGroup()).toBe(false);
    ch.syncGroups(); // no self-group open: publish nothing (group names are contact-graph data)
    await Promise.resolve();
    await Promise.resolve();
    expect(tx.published).toHaveLength(0);
  });

  it('adopts a CONTROL_GROUPS frame from our OWN account and DROPS one from a peer', async () => {
    await ch.connectGateway('ws://x/ws');
    conv.selfConversation = true;
    await ch.createSelfGroup([{ deviceKey: hx('bb'), keyPackage: new Uint8Array([7]) }]);
    const groupsCtrl = (): Uint8Array =>
      new Uint8Array([APP, ...padToBucket(frameControl(CONTROL_GROUPS, 1, new TextEncoder().encode(JSON.stringify({ groups: { Family: { v: 3, removed: false, order: 1 } } }))))]);
    // From one of our own devices: adopted.
    groupsAdopted = [];
    conv.fromOwnAccount = true;
    deliver('gmbox-0', groupsCtrl());
    expect(groupsAdopted).toHaveLength(1);
    // From a peer: dropped (group names are never adopted from a peer).
    groupsAdopted = [];
    conv.fromOwnAccount = false;
    deliver('gmbox-0', groupsCtrl());
    expect(groupsAdopted).toHaveLength(0);
  });

  it('auto-replies with the away message on an inbound message, jittered through the scheduler', async () => {
    awayText = 'away from keyboard, back later';
    await ch.connectGateway('ws://x/ws');
    await ch.startConversation([{ deviceKey: hx('bb'), keyPackage: new Uint8Array([7]) }]);
    scheduled = [];
    const payload = new Uint8Array([APP, ...padToBucket(frameMessage(new TextEncoder().encode('you there?'), LIFE))]);
    deliver('gmbox-0', payload);
    await Promise.resolve();
    await Promise.resolve(); // let the away-reply lookup resolve and schedule the jittered send
    expect(scheduled.length).toBeGreaterThan(0); // the reply is delayed, never sent on the dot
    scheduled.forEach((cb) => cb());
    expect(messages).toContainEqual({ direction: 'out', text: 'away from keyboard, back later' });
    // It must show on OUR side too: the reply is stored as our own outgoing message, and the event
    // repaints the open conversation. Without it the away user only saw their auto reply by
    // reopening the chat, so it looked like it went only to the other person.
    await Promise.resolve();
    await Promise.resolve();
    expect(events.some((e) => e.kind === 'outbound-appended')).toBe(true);
    // And it is OUR message: never the inbound event, which would notify us about ourselves.
    // Exactly ONE inbound-message: the peer's trigger message. Our own auto-reply must never add a
    // second one, which would notify us about our own away reply.
    expect(events.filter((e) => e.kind === 'inbound-message').length).toBe(1);
  });

  it('does not auto-reply when away is off', async () => {
    await ch.connectGateway('ws://x/ws'); // awayText stays null
    await ch.startConversation([{ deviceKey: hx('bb'), keyPackage: new Uint8Array([7]) }]);
    scheduled = [];
    deliver('gmbox-0', new Uint8Array([APP, ...padToBucket(frameMessage(new TextEncoder().encode('ping'), LIFE))]));
    await Promise.resolve();
    await Promise.resolve();
    expect(scheduled.length).toBe(0);
  });

  it('drops a Welcome whose entire roster is blocked, so a blocked party cannot pull you in', async () => {
    await ch.connectGateway('ws://x/ws');
    blockedPeers.add(hx('bb')); // the only other member of the joined group
    deliver(SELF, new Uint8Array([0x57]));
    await Promise.resolve();
    await Promise.resolve();
    expect(events.some((e) => e.kind === 'established')).toBe(false); // silently dropped, not surfaced
    expect(ch.roster(CID)).toEqual([]); // we did not adopt the group
  });

  it('routes a CONTROL_FILE frame to the file-signal handler, not the identity store', async () => {
    await ch.connectGateway('ws://x/ws');
    await ch.startConversation([{ deviceKey: hx('bb'), keyPackage: new Uint8Array([7]) }]);
    peerIdentitySaves = [];
    fileSignals = [];
    const payload = new TextEncoder().encode(JSON.stringify({ kind: 'offer', id: 't1' }));
    const ct = new Uint8Array([APP, ...padToBucket(frameControl(CONTROL_FILE, 1, payload))]);
    deliver('gmbox-0', ct);
    expect(fileSignals).toHaveLength(1); // file signaling is routed to the transfer module
    expect(peerIdentitySaves).toHaveLength(0); // and never mistaken for a peer identity
  });

  it('publishes a file signal as a control frame on the group mailbox (bytes never go here)', async () => {
    await ch.connectGateway('ws://x/ws');
    await ch.startConversation([{ deviceKey: hx('bb'), keyPackage: new Uint8Array([7]) }]);
    const before = tx.published.filter((p) => p.routingKey === 'gmbox-0').length;
    ch.sendFileSignal(CID, new TextEncoder().encode('{"kind":"offer","id":"t1"}'));
    expect(tx.published.filter((p) => p.routingKey === 'gmbox-0').length).toBe(before + 1);
  });

  it('routes a CONTROL_CALL frame to the call-signal handler, not the file or identity handlers', async () => {
    await ch.connectGateway('ws://x/ws');
    await ch.startConversation([{ deviceKey: hx('bb'), keyPackage: new Uint8Array([7]) }]);
    peerIdentitySaves = [];
    fileSignals = [];
    callSignals = [];
    const payload = new TextEncoder().encode(JSON.stringify({ kind: 'call-offer', id: 'k1', video: true }));
    const ct = new Uint8Array([APP, ...padToBucket(frameControl(CONTROL_CALL, 1, payload))]);
    deliver('gmbox-0', ct);
    expect(callSignals).toHaveLength(1); // call signaling is routed to the call module
    expect(fileSignals).toHaveLength(0); // and not confused with a file signal
    expect(peerIdentitySaves).toHaveLength(0); // nor a peer identity
  });

  it('publishes a call signal as a control frame on the group mailbox (media never goes here)', async () => {
    await ch.connectGateway('ws://x/ws');
    await ch.startConversation([{ deviceKey: hx('bb'), keyPackage: new Uint8Array([7]) }]);
    const before = tx.published.filter((p) => p.routingKey === 'gmbox-0').length;
    ch.sendCallSignal(CID, new TextEncoder().encode('{"kind":"call-offer","id":"k1","video":false}'));
    expect(tx.published.filter((p) => p.routingKey === 'gmbox-0').length).toBe(before + 1);
  });

  // ---- Self-heal: admit late siblings into the open conversation (H1, ADR-022) ----

  function hexToBytes(s: string): Uint8Array {
    const b = new Uint8Array(s.length / 2);
    for (let i = 0; i < b.length; i++) {
      b[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
    }
    return b;
  }
  const SIBLING = hx('cc');
  // Candidate DeviceTargets: a key package encoding the sibling's own signature key (so the fake's
  // stageAdd derives the right pending sig). The app claims these and passes them as data.
  const candidates: DeviceTarget[] = [{ deviceKey: SIBLING, keyPackage: hexToBytes(SIBLING) }];

  it('self-heal: the designated adder stages a missing sibling and confirms on its own echo', async () => {
    await ch.connectGateway('ws://x/ws');
    await ch.startConversation([{ deviceKey: hx('bb'), keyPackage: new Uint8Array([7]) }]);
    expect(conv.roster()).not.toContain(SIBLING);
    expect(ch.hasMissingSiblings([SELF, SIBLING])).toBe(true); // the cheap pre-check agrees
    await ch.reconcileSiblings([SELF, SIBLING], candidates);
    // It staged the add: a commit to the group mailbox plus a Welcome to the sibling's bootstrap mailbox.
    const commitPub = tx.published.find((p) => p.routingKey === 'gmbox-0' && p.payload[0] === COMMIT_ADD);
    expect(commitPub).toBeDefined();
    expect(tx.published.some((p) => p.routingKey === SIBLING)).toBe(true);
    // Staged, not merged: the sibling is not a member until the commit is confirmed.
    expect(conv.roster()).not.toContain(SIBLING);
    // The gateway echoes our own commit back on the group mailbox: receive confirms it (merges).
    deliver('gmbox-0', commitPub!.payload);
    expect(conv.roster()).toContain(SIBLING);
    expect(events.some((e) => e.kind === 'roster-changed')).toBe(true);
  });

  it('an adder-gate rejection surfaces a sibling-add-rejected event; the in-flight error stays silent', async () => {
    await ch.connectGateway('ws://x/ws');
    await ch.startConversation([{ deviceKey: hx('bb'), keyPackage: new Uint8Array([7]) }]);
    // The gate rejected the package (e.g. certless or below the floor): the heal must learn about it
    // so it stops claiming a fresh package per tick for a deterministically-rejected device.
    conv.stageAddThrow = 'unauthorized device: missing certificate';
    events.length = 0;
    await ch.reconcileSiblings([SELF, SIBLING], candidates);
    const rejected = events.find((e) => e.kind === 'sibling-add-rejected');
    expect(rejected).toBeDefined();
    expect((rejected?.payload as { deviceKey?: string }).deviceKey).toBe(SIBLING);
    // The pre-existing in-flight error keeps its silent skip (the add completes on its own).
    conv.stageAddThrow = 'an add is already in flight';
    events.length = 0;
    await ch.reconcileSiblings([SELF, SIBLING], candidates);
    expect(events.some((e) => e.kind === 'sibling-add-rejected')).toBe(false);
    conv.stageAddThrow = null;
  });

  it('the backstop ABANDONS an unechoed add rather than merging it onto a private key period', async () => {
    await ch.connectGateway('ws://x/ws');
    await ch.startConversation([{ deviceKey: hx('bb'), keyPackage: new Uint8Array([7]) }]);
    await ch.reconcileSiblings([SELF, SIBLING], candidates);
    expect(conv.roster()).not.toContain(SIBLING); // staged, awaiting confirmation
    // No echo arrives, so nothing proves any other member received this commit. Merging here used to
    // advance this device alone onto a key period nobody else was on, which is unrecoverable and
    // silent. The timer now abandons the staged commit and says so.
    expect(scheduled.length).toBeGreaterThan(0);
    scheduled.forEach((cb) => cb());
    expect(conv.roster()).not.toContain(SIBLING); // still on the epoch everyone else is on
    expect(events.some((e) => e.kind === 'roster-changed')).toBe(false); // no false membership claim
    expect(events.some((e) => e.kind === 'membership-stalled')).toBe(true);
  });

  it('connectGateway resolves a secret-keyed per-mailbox delivery-cursor tag for each subscribe', async () => {
    await ch.connectGateway('ws://x/ws');
    const last = tx.subscribed[tx.subscribed.length - 1]!;
    expect(tx.consumerId).toBe(conv.mailboxTag(last)); // the resolver returns the crypto per-mailbox tag
    expect(tx.consumerId).not.toBe(SELF); // NOT the raw bootstrap key (unlinkable across mailboxes)
  });

  it('a reconnect while an add is in flight neutralizes the stale backstop (Batch B must-fix 2)', async () => {
    await ch.connectGateway('ws://x/ws');
    await ch.startConversation([{ deviceKey: hx('bb'), keyPackage: new Uint8Array([7]) }]);
    await ch.reconcileSiblings([SELF, SIBLING], candidates);
    expect(conv.roster()).not.toContain(SIBLING); // staged, awaiting confirmation
    const staleBackstop = scheduled[scheduled.length - 1]!; // the add's confirm backstop on THIS connection
    // A reconnect (the auto-reconnect backoff can fire inside the 8s confirm window) must neutralize the
    // prior backstop. Left live, when it fires it would delete the freshly re-armed pendingOps entry,
    // zombie-confirm a discarded commit, and emit a false roster-changed on the new connection.
    scheduled.length = 0;
    events.length = 0;
    await ch.connectGateway('ws://x/ws');
    // The stale backstop is stamped with the OLD connection generation, so firing it now is a no-op: it
    // does not confirm, does not advance the roster, and emits no roster-changed. The fresh restore
    // backstop scheduled on the new connection is what legitimately converges the add.
    staleBackstop();
    expect(events.filter((e) => e.kind === 'roster-changed').length).toBe(0);
  });

  it('self-heal: a device already in the roster is never re-added (idempotent)', async () => {
    await ch.connectGateway('ws://x/ws');
    await ch.startConversation([{ deviceKey: hx('bb'), keyPackage: new Uint8Array([7]) }]);
    expect(ch.hasMissingSiblings([SELF])).toBe(false); // nothing missing
    const before = tx.published.length;
    // Every own device given is already a member (SELF), so there is nothing to add.
    await ch.reconcileSiblings([SELF], candidates);
    expect(tx.published.length).toBe(before); // no commit, no welcome
  });

  it('self-heal: a non-designated device defers to the lowest-keyed sibling instead of adding', async () => {
    // Rebuild the conv with a LOWER own device (01) already in the group, so SELF (aa) is not lowest.
    conv = new FakeConv(SELF, [hx('bb'), hx('01')]);
    await ch.connectGateway('ws://x/ws');
    await ch.startConversation([{ deviceKey: hx('bb'), keyPackage: new Uint8Array([7]) }]);
    expect(ch.hasMissingSiblings([SELF, hx('01'), SIBLING])).toBe(false); // not the designated adder
    const before = tx.published.length;
    scheduled.length = 0;
    await ch.reconcileSiblings([SELF, hx('01'), SIBLING], candidates);
    expect(tx.published.length).toBe(before); // we did NOT add: the lower-keyed device 01 is designated
    expect(scheduled.length).toBeGreaterThan(0); // a failover was scheduled in case 01 is offline
  });

  it('reconcileSelf: a non-lowest seed-holder heals the self-group via the failover, without stacking (S1)', async () => {
    // 01 is lower than SELF (aa), so SELF is NOT the designated adder for the self-group.
    conv = new FakeConv(SELF, [hx('bb'), hx('01')]);
    conv.selfConversation = true; // the group is the hidden own-devices self-group
    await ch.connectGateway('ws://x/ws');
    await ch.startConversation([{ deviceKey: hx('bb'), keyPackage: new Uint8Array([7]) }]);
    scheduled.length = 0;
    const before = tx.published.length;
    // The seed-holder's post-add poll reaches reconcileSelf even though SELF is not the adder: it DEFERS
    // (race-free) to the lower-keyed 01 and arms a single failover instead of staging now.
    await ch.reconcileSelf([SELF, hx('01'), SIBLING], candidates);
    expect(tx.published.length).toBe(before); // did not stage: 01 is designated
    expect(scheduled.length).toBe(1); // one failover armed
    expect(ch.selfSiblingState(SIBLING)).toBe('pending'); // the armed failover reads as an add under way
    // A repeated poll tick must NOT stack a second failover (poll-safe).
    await ch.reconcileSelf([SELF, hx('01'), SIBLING], candidates);
    expect(scheduled.length).toBe(1);
    // 01 is offline, so the failover fires and SELF takes over: it stages the add (commit + Welcome).
    scheduled[0]!();
    await new Promise((r) => setTimeout(r, 0)); // the stage persists BEFORE publishing (async), let it flush
    expect(tx.published.some((p) => p.routingKey === 'gmbox-0' && p.payload[0] === COMMIT_ADD)).toBe(true);
    expect(tx.published.some((p) => p.routingKey === SIBLING)).toBe(true);
  });

  it('selfSiblingState reports none / absent / pending / member across the self-group add lifecycle', async () => {
    conv.selfConversation = true;
    await ch.connectGateway('ws://x/ws');
    expect(ch.selfSiblingState(SIBLING)).toBe('none'); // no self-group open yet
    await ch.startConversation([{ deviceKey: hx('bb'), keyPackage: new Uint8Array([7]) }]);
    expect(ch.selfSiblingState(SIBLING)).toBe('absent'); // self-group exists, SIBLING not in it, no add
    // SELF (aa) is the lowest here, so reconcileSelf stages immediately: pendingOps busy -> 'pending'.
    await ch.reconcileSelf([SELF, SIBLING], candidates);
    expect(ch.selfSiblingState(SIBLING)).toBe('pending');
    const commitPub = tx.published.find((p) => p.routingKey === 'gmbox-0' && p.payload[0] === COMMIT_ADD);
    deliver('gmbox-0', commitPub!.payload); // our own commit echoes back: the add confirms
    expect(ch.selfSiblingState(SIBLING)).toBe('member'); // now in the self-group roster
  });

  it('self-heal: defers (no partial add) when the missing device has no candidate package', async () => {
    await ch.connectGateway('ws://x/ws');
    await ch.startConversation([{ deviceKey: hx('bb'), keyPackage: new Uint8Array([7]) }]);
    const before = tx.published.length;
    await ch.reconcileSiblings([SELF, SIBLING], []); // no candidate for the missing sibling
    expect(tx.published.length).toBe(before); // nothing claimable: defer, never add partially
  });

  it('self-heal: no-op (and the pre-check is false) when there is no open conversation', async () => {
    await ch.connectGateway('ws://x/ws');
    expect(ch.hasMissingSiblings([SELF, SIBLING])).toBe(false);
    const before = tx.published.length;
    await ch.reconcileSiblings([SELF, SIBLING], candidates);
    expect(tx.published.length).toBe(before);
  });

  it('durable exclusion: the designated device stages a Remove for a revoked member and confirms on echo', async () => {
    await ch.connectGateway('ws://x/ws');
    await ch.startConversation([{ deviceKey: hx('bb'), keyPackage: new Uint8Array([7]) }]);
    expect(conv.roster()).toContain(hx('bb'));
    await ch.reconcileRemovals([SELF], [hx('bb')]); // bb is revoked
    const commitPub = tx.published.find((p) => p.routingKey === 'gmbox-0' && p.payload[0] === COMMIT_REMOVE);
    expect(commitPub).toBeDefined();
    expect(conv.roster()).toContain(hx('bb')); // staged, not merged, until the echo confirms
    deliver('gmbox-0', commitPub!.payload); // the gateway echoes our own remove back: confirm (merge)
    expect(conv.roster()).not.toContain(hx('bb'));
    expect(events.some((e) => e.kind === 'roster-changed')).toBe(true);
  });

  it('durable exclusion: no-op when no revoked device is present in the roster', async () => {
    await ch.connectGateway('ws://x/ws');
    await ch.startConversation([{ deviceKey: hx('bb'), keyPackage: new Uint8Array([7]) }]);
    const before = tx.published.length;
    await ch.reconcileRemovals([SELF], [hx('dd')]); // dd is revoked but is not a member of this group
    expect(tx.published.length).toBe(before);
  });

  it('durable exclusion: never removes our OWN device even if its key is on the revoked list', async () => {
    await ch.connectGateway('ws://x/ws');
    await ch.startConversation([{ deviceKey: hx('bb'), keyPackage: new Uint8Array([7]) }]);
    const before = tx.published.length;
    await ch.reconcileRemovals([SELF], [SELF]); // our own key must never be targeted
    expect(tx.published.length).toBe(before);
    expect(conv.roster()).toContain(SELF);
  });

  it('durable exclusion: bails while an add is already in flight for the conversation', async () => {
    await ch.connectGateway('ws://x/ws');
    await ch.startConversation([{ deviceKey: hx('bb'), keyPackage: new Uint8Array([7]) }]);
    await ch.reconcileSiblings([SELF, SIBLING], candidates); // stages an add: pendingOps is busy
    const before = tx.published.length;
    await ch.reconcileRemovals([SELF], [hx('bb')]);
    expect(tx.published.length).toBe(before); // no remove published while a commit is in flight
  });

  it('durable exclusion: a non-designated device defers the removal to the lowest-keyed sibling', async () => {
    conv = new FakeConv(SELF, [hx('bb'), hx('01')]); // a LOWER own device (01) is in the group
    await ch.connectGateway('ws://x/ws');
    await ch.startConversation([{ deviceKey: hx('bb'), keyPackage: new Uint8Array([7]) }]);
    scheduled.length = 0;
    const before = tx.published.length;
    await ch.reconcileRemovals([SELF, hx('01'), SIBLING], [hx('bb')]);
    expect(tx.published.length).toBe(before); // did NOT publish: device 01 is the designated adder
    expect(scheduled.length).toBeGreaterThan(0); // scheduled a failover in case 01 is offline
  });
});
