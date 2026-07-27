import { describe, it, expect } from 'vitest';
import { GroupSession, receiveGroup, encodeList, decodeList, decodeReceived, type GroupConversationLike, type GroupReceived } from './group.js';
import { padToBucket, CONTROL_PROFILE } from './session.js';
import type { Lifetime } from './index.js';

const LIFE: Lifetime = { kind: 'duration', seconds: 60 };

function hexToBytes(h: string): Uint8Array {
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}
function bytesToHex(b: Uint8Array): string {
  return [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
}
function txt(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}
function str(b: Uint8Array): string {
  return new TextDecoder().decode(b);
}

// A shared in-memory MLS stand-in for MANY conversations at once. Fakes that share one World deliver
// to each other; every message carries its group id (as the real wasm does), so receive self-routes by
// it. It mirrors the Rust wire format (tagged receive blobs, length-prefixed lists) so the codecs under
// test are real. The actual MLS crypto + the authorization gate are proven in crypto/src/{conversation,
// authz}.rs. Per-conversation crypto bytes are tagged then carry [groupIdBytes, body] as a list, so a
// receiver decodes the group id out of the message exactly the way the real receive routes.
const APP = 0xaa;
const COMMIT = 0xcc;
const ADD = 1;
const REMOVE = 2;

interface GroupState {
  members: string[];
  epoch: number;
}

// The shared world: every open conversation keyed by its group id. createGroup mints a new entry; the
// joiner reads the same one (it is already a member after createGroup, as the old shared world modeled).
class World {
  readonly groups = new Map<string, GroupState>();
  private counter = 0;
  /** Mint a fresh, unique group id (hex). */
  newGroupId(): string {
    this.counter += 1;
    return `9900${this.counter.toString(16).padStart(4, '0')}`;
  }
}

class FakeGroupConv implements GroupConversationLike {
  // A staged add awaiting confirm, per conversation (groupId -> added sig).
  private readonly pending = new Map<string, string>();
  private readonly pendingRemove = new Map<string, string>();
  constructor(
    private readonly sig: string,
    private readonly acct: string,
    private readonly world: World,
  ) {}
  signaturePublicKeyHex(): string {
    return this.sig;
  }
  accountKeyHex(): string {
    return this.acct;
  }
  keyPackage(): Uint8Array {
    return hexToBytes(this.sig); // a fake key package is just its owner's signature key
  }
  private group(groupId: string): GroupState {
    const g = this.world.groups.get(groupId);
    if (g === undefined) {
      throw new Error(`no such group ${groupId}`);
    }
    return g;
  }
  createGroup(blob: Uint8Array): Uint8Array {
    const groupId = this.world.newGroupId();
    this.world.groups.set(groupId, { members: [this.sig, ...decodeList(blob).map(bytesToHex)], epoch: 0 });
    // The welcome carries the group id back, so joinFromWelcome recovers the SAME id both sides agree on.
    const welcome = hexToBytes(groupId);
    return encodeList([welcome, hexToBytes(groupId)]); // [welcome, groupId]
  }
  createSelf(): Uint8Array {
    // A SOLO group whose only member is this device; no one is admitted, so there is no welcome.
    const groupId = this.world.newGroupId();
    this.world.groups.set(groupId, { members: [this.sig], epoch: 0 });
    return hexToBytes(groupId); // just the groupId
  }
  listConversations(): string[] {
    return [...this.world.groups.keys()];
  }
  addMember(conversationId: string, kp: Uint8Array): Uint8Array {
    const g = this.group(conversationId);
    const sig = bytesToHex(kp);
    g.members.push(sig);
    g.epoch += 1;
    const commit = taggedControl(conversationId, COMMIT, ADD, hexToBytes(sig));
    return encodeList([commit, new Uint8Array([9])]); // [commit, welcome]
  }
  stageAdd(conversationId: string, kp: Uint8Array): Uint8Array {
    // Build the commit WITHOUT mutating the group (no member push, no epoch bump): staged, not merged.
    this.pending.set(conversationId, bytesToHex(kp));
    const commit = taggedControl(conversationId, COMMIT, ADD, kp);
    return encodeList([commit, new Uint8Array([9])]);
  }
  confirmAdd(conversationId: string): void {
    const p = this.pending.get(conversationId);
    if (p !== undefined) {
      const g = this.group(conversationId);
      g.members.push(p);
      g.epoch += 1;
      this.pending.delete(conversationId);
    }
  }
  abortAdd(conversationId: string): void {
    this.pending.delete(conversationId);
  }
  removeMember(conversationId: string, sigKeyHex: string): Uint8Array {
    const g = this.group(conversationId);
    g.members = g.members.filter((m) => m !== sigKeyHex);
    g.epoch += 1;
    return taggedControl(conversationId, COMMIT, REMOVE, hexToBytes(sigKeyHex));
  }
  stageRemove(conversationId: string, sigKeyHex: string): Uint8Array {
    // Build the Remove commit WITHOUT mutating the group: staged, not merged.
    this.pendingRemove.set(conversationId, sigKeyHex);
    return taggedControl(conversationId, COMMIT, REMOVE, hexToBytes(sigKeyHex));
  }
  confirmRemove(conversationId: string): void {
    const s = this.pendingRemove.get(conversationId);
    if (s !== undefined) {
      const g = this.group(conversationId);
      g.members = g.members.filter((m) => m !== s);
      g.epoch += 1;
      this.pendingRemove.delete(conversationId);
    }
  }
  abortRemove(conversationId: string): void {
    this.pendingRemove.delete(conversationId);
  }
  pendingKind(_conversationId: string): number {
    return 0; // the fake never persists a staged commit across a reload
  }
  pendingTarget(_conversationId: string): string {
    return '';
  }
  pendingCommit(_conversationId: string): Uint8Array {
    return new Uint8Array();
  }
  pendingWelcome(_conversationId: string): Uint8Array {
    return new Uint8Array();
  }
  mailboxTag(subject: string): string {
    return 'ctag-' + subject;
  }
  joinFromWelcome(welcome: Uint8Array): string {
    // The welcome IS the group id bytes; the shared world already holds the group from createGroup.
    return bytesToHex(welcome);
  }
  encrypt(conversationId: string, plaintext: Uint8Array): Uint8Array {
    return taggedBody(conversationId, APP, plaintext);
  }
  receive(ct: Uint8Array): Uint8Array {
    const tag = ct[0];
    const { groupId, body } = untag(ct);
    if (tag === APP) {
      // tag 0 (application), then the from-own-account flag byte (0 here: these fakes are cross-account),
      // then the plaintext.
      return encodeList([hexToBytes(groupId), new Uint8Array([0, 0, ...body])]); // tag 0 = application
    }
    if (tag === COMMIT) {
      const sub = body[0];
      const sig = bytesToHex(body.slice(1));
      let blob: Uint8Array;
      if (sub === REMOVE && sig === this.sig) {
        blob = new Uint8Array([2]); // we were removed
      } else {
        const added = sub === ADD ? [hexToBytes(sig)] : [];
        const removed = sub === REMOVE ? [hexToBytes(sig)] : [];
        blob = new Uint8Array([1, ...encodeList(added), ...encodeList(removed)]);
      }
      return encodeList([hexToBytes(groupId), blob]);
    }
    return encodeList([hexToBytes(groupId), new Uint8Array([3])]);
  }
  roster(conversationId: string): string[] {
    return [...this.group(conversationId).members].sort();
  }
  // These fakes model cross-account conversations, so none is a self-group (the GroupSession-level
  // self-group behavior is covered in groupchannel.test.ts where a self-group can be simulated).
  isSelfConversation(): boolean {
    return false;
  }
  groupMailbox(conversationId: string): string {
    return `mbox-${conversationId}-${this.group(conversationId).epoch}`;
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
  reauthorizeAtEpoch(): void {
    /* no-op */
  }
  certEpoch(): number {
    return 0;
  }
  wipe(): void {
    /* no-op */
  }
}

// Carry the group id inside an application ciphertext: [tag, ...encodeList([groupIdBytes, body])].
function taggedBody(groupId: string, tag: number, body: Uint8Array): Uint8Array {
  return new Uint8Array([tag, ...encodeList([hexToBytes(groupId), body])]);
}

// Carry the group id inside a control commit: body is [sub, ...payload].
function taggedControl(groupId: string, tag: number, sub: number, payload: Uint8Array): Uint8Array {
  return taggedBody(groupId, tag, new Uint8Array([sub, ...payload]));
}

// Split a tagged ciphertext back into its group id and body.
function untag(ct: Uint8Array): { groupId: string; body: Uint8Array } {
  const parts = decodeList(ct.slice(1));
  return { groupId: bytesToHex(parts[0]!), body: parts[1]! };
}

// One device's conversation handle. The fake conv is per-device; create/join mint the shared group.
function makeConv(world: World, sig: string, acct: string): FakeGroupConv {
  return new FakeGroupConv(sig, acct, world);
}

// Receive on a device's conv and return just the decoded result (the tests assert on the result; the
// group id is checked by routing). Mirrors the old `session.receive` ergonomics over the new free fn.
function recv(conv: FakeGroupConv, payload: Uint8Array): GroupReceived {
  return receiveGroup(conv, payload).received;
}

describe('group codecs (must match the Rust wire format)', () => {
  it('round-trips a length-prefixed list', () => {
    const items = [new Uint8Array([1, 2, 3]), new Uint8Array([]), new Uint8Array([9, 9])];
    const back = decodeList(encodeList(items));
    expect(back.map(bytesToHex)).toEqual(items.map(bytesToHex));
  });

  it('decodes each receive tag', () => {
    // tag 0 (application) is followed by the from-own-account flag byte, then the plaintext.
    expect(decodeReceived(new Uint8Array([0, 1, 65, 66]))).toEqual({ kind: 'application', plaintext: new Uint8Array([65, 66]), fromOwnAccount: true });
    expect(decodeReceived(new Uint8Array([0, 0, 67]))).toEqual({ kind: 'application', plaintext: new Uint8Array([67]), fromOwnAccount: false });
    const membership = new Uint8Array([1, ...encodeList([hexToBytes('aabb')]), ...encodeList([])]);
    expect(decodeReceived(membership)).toEqual({ kind: 'membership', added: ['aabb'], removed: [] });
    expect(decodeReceived(new Uint8Array([2]))).toEqual({ kind: 'evicted' });
    expect(decodeReceived(new Uint8Array([3]))).toEqual({ kind: 'proposal' });
  });
});

describe('GroupSession orchestration', () => {
  it('bootstraps a group and delivers a message to another member', () => {
    const world = new World();
    const convA = makeConv(world, 'aa'.repeat(16), 'a-acct');
    const convB = makeConv(world, 'bb'.repeat(16), 'b-acct');

    const { welcome, session: a } = GroupSession.create(convA, [convB.keyPackage()]);
    const b = GroupSession.join(convB, welcome);
    expect(a.groupId).toBe(b.groupId); // both sides agree on the conversation's group id
    expect(a.roster()).toEqual(['aa'.repeat(16), 'bb'.repeat(16)].sort());

    const env = a.send(txt('meet at the drop'), LIFE);
    expect(env.routingKey).toBe(a.mailbox()); // addressed to the shared group mailbox
    const got = recv(convB, env.payload);
    expect(got.type).toBe('message');
    if (got.type === 'message' && got.frame.type === 'message') {
      expect(str(got.frame.plaintext)).toBe('meet at the drop');
      expect(got.frame.lifetime).toEqual(LIFE);
    }
  });

  it('rotates the group mailbox when membership changes', () => {
    const world = new World();
    const convA = makeConv(world, 'aa'.repeat(16), 'a-acct');
    const { session: a } = GroupSession.create(convA, [hexToBytes('bb'.repeat(16))]);
    const before = a.mailbox();
    a.addDevice(hexToBytes('cc'.repeat(16)));
    expect(a.mailbox()).not.toBe(before);
  });

  it('reports an added device as a membership change to other members', () => {
    const world = new World();
    const convA = makeConv(world, 'aa'.repeat(16), 'a-acct');
    const convB = makeConv(world, 'bb'.repeat(16), 'b-acct');
    const { welcome: w0, session: a } = GroupSession.create(convA, [hexToBytes('bb'.repeat(16))]);
    GroupSession.join(convB, w0);

    const { commit, welcome } = a.addDevice(hexToBytes('cc'.repeat(16)));
    expect(welcome.length).toBeGreaterThan(0);
    const got = recv(convB, commit);
    expect(got).toEqual({ type: 'membership', added: ['cc'.repeat(16)], removed: [] });
  });

  it('staged add: stage does not change membership until confirmed, then it does', () => {
    const world = new World();
    const convA = makeConv(world, 'aa'.repeat(16), 'a-acct');
    const { session: a } = GroupSession.create(convA, [hexToBytes('bb'.repeat(16))]);
    const before = a.roster().length;
    const { commit, welcome } = a.stageAddDevice(hexToBytes('cc'.repeat(16)));
    expect(commit.length).toBeGreaterThan(0);
    expect(welcome.length).toBeGreaterThan(0);
    expect(a.roster().length).toBe(before); // staged, not merged: no member yet
    a.confirmAdd();
    expect(a.roster()).toContain('cc'.repeat(16)); // confirmed: now a member
  });

  it('staged add: abort leaves membership unchanged', () => {
    const world = new World();
    const convA = makeConv(world, 'aa'.repeat(16), 'a-acct');
    const { session: a } = GroupSession.create(convA, [hexToBytes('bb'.repeat(16))]);
    const before = a.roster().length;
    a.stageAddDevice(hexToBytes('cc'.repeat(16)));
    a.abortAdd();
    expect(a.roster().length).toBe(before); // aborted: never added
    a.confirmAdd(); // idempotent after abort: still no change
    expect(a.roster().length).toBe(before);
  });

  it('reports a removal to remaining members and evicts the removed device', () => {
    const world = new World();
    const convA = makeConv(world, 'aa'.repeat(16), 'a-acct');
    const convB = makeConv(world, 'bb'.repeat(16), 'b-acct');
    const convC = makeConv(world, 'cc'.repeat(16), 'a-acct'); // a's second device
    const { welcome, session: a } = GroupSession.create(convA, [hexToBytes('bb'.repeat(16)), hexToBytes('cc'.repeat(16))]);
    GroupSession.join(convB, welcome);
    GroupSession.join(convC, welcome);

    const commit = a.removeDevice('cc'.repeat(16));
    expect(recv(convB, commit)).toEqual({ type: 'membership', added: [], removed: ['cc'.repeat(16)] });
    expect(recv(convC, commit)).toEqual({ type: 'evicted' });
  });

  it('distributes a control frame (buddy icon / profile) to other members', () => {
    const world = new World();
    const convA = makeConv(world, 'aa'.repeat(16), 'a-acct');
    const convB = makeConv(world, 'bb'.repeat(16), 'b-acct');
    const { welcome, session: a } = GroupSession.create(convA, [hexToBytes('bb'.repeat(16))]);
    GroupSession.join(convB, welcome);

    const env = a.sendControl(CONTROL_PROFILE, 1, txt('{"bio":"meet me at the drop"}'));
    expect(env.routingKey).toBe(a.mailbox()); // rides the shared group mailbox like any message
    const got = recv(convB, env.payload);
    expect(got.type).toBe('control');
    if (got.type === 'control') {
      expect(got.controlType).toBe(CONTROL_PROFILE);
      expect(got.version).toBe(1);
      expect(str(got.payload)).toBe('{"bio":"meet me at the drop"}');
    }
  });

  it('drops an unknown application frame type instead of wedging the receive loop', () => {
    const world = new World();
    const convA = makeConv(world, 'aa'.repeat(16), 'a-acct');
    const convB = makeConv(world, 'bb'.repeat(16), 'b-acct');
    const { welcome, session: a } = GroupSession.create(convA, [hexToBytes('bb'.repeat(16))]);
    GroupSession.join(convB, welcome);
    // A future/unknown application frame from a newer peer: an APP ciphertext carrying a's group id and a
    // padded frame whose first byte is an unknown frame type. The receiver drops it (ignored), not throws.
    const ciphertext = taggedBody(a.groupId, APP, padToBucket(new Uint8Array([0xfe, 1, 2, 3])));
    expect(recv(convB, ciphertext)).toEqual({ type: 'ignored' });
  });

  it('one device holds two independent conversations and receive self-routes each by group id', () => {
    const world = new World();
    const a = makeConv(world, 'aa'.repeat(16), 'a-acct');
    const b = makeConv(world, 'bb'.repeat(16), 'b-acct');
    const c = makeConv(world, 'cc'.repeat(16), 'c-acct');
    // A opens TWO conversations on one device: g1 with B, g2 with C.
    const r1 = GroupSession.create(a, [b.keyPackage()]);
    const r2 = GroupSession.create(a, [c.keyPackage()]);
    const bSession = GroupSession.join(b, r1.welcome);
    const cSession = GroupSession.join(c, r2.welcome);
    expect(r1.session.groupId).not.toBe(r2.session.groupId); // distinct conversations
    expect(a.listConversations()).toHaveLength(2);
    // Independent rosters and mailboxes.
    expect(a.roster(r1.session.groupId)).not.toEqual(a.roster(r2.session.groupId));
    expect(a.groupMailbox(r1.session.groupId)).not.toBe(a.groupMailbox(r2.session.groupId));
    // B sends in g1 and C sends in g2; A's receive self-routes EACH to the correct conversation.
    const fromB = bSession.send(txt('hi from B'), LIFE);
    const routedB = receiveGroup(a, fromB.payload);
    expect(routedB.groupId).toBe(r1.session.groupId);
    const fromC = cSession.send(txt('hi from C'), LIFE);
    const routedC = receiveGroup(a, fromC.payload);
    expect(routedC.groupId).toBe(r2.session.groupId);
    expect(routedC.groupId).not.toBe(routedB.groupId);
    // ...and each carries the right plaintext, never crossed.
    if (routedB.received.type === 'message' && routedB.received.frame.type === 'message') {
      expect(str(routedB.received.frame.plaintext)).toBe('hi from B');
    } else {
      throw new Error('expected a message in g1');
    }
    if (routedC.received.type === 'message' && routedC.received.frame.type === 'message') {
      expect(str(routedC.received.frame.plaintext)).toBe('hi from C');
    } else {
      throw new Error('expected a message in g2');
    }
  });
});
