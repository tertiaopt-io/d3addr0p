/**
 * Multi-device group conversation orchestration (ADR-022 model B, P4).
 *
 * A conversation is an N-member MLS group whose leaves are all of each participant's devices. This
 * module is the bundler- and wasm-agnostic glue that drives one such group through an injected
 * `GroupConversationLike` (the real wasm `Conversation` in production, a fake in tests): it bootstraps
 * a group from the participants' key packages, sends application messages to the single per-epoch
 * group mailbox, and dispatches inbound payloads into application messages, membership changes (which
 * rotate the mailbox), or our own eviction. The real MLS crypto and the authorization gate are
 * verified by the Rust tests in crypto/src/{conversation,authz}.rs; this layer is the orchestration.
 *
 * The byte codecs below MUST match the Rust wire format (crypto/src/conversation.rs encode_list /
 * encode_received): a length-prefixed list is u32-BE count then each u32-BE length + bytes, and a
 * received blob is a one-byte tag (0 application, 1 membership, 2 evicted, 3 proposal).
 */

import {
  frameMessage,
  frameControl,
  frameRevoke,
  parseFrame,
  padToBucket,
  unpadFromBucket,
  deriveTtlSeconds,
  SEVEN_DAYS_SECONDS,
  type EnvelopeMsg,
  type IncomingFrame,
  type ParsedFrame,
} from './session.js';
import type { Lifetime } from './index.js';

/**
 * The injected wasm `Conversation` surface for the N-member group path. The real implementation is
 * the wasm-bindgen class from crypto/pkg; nothing here returns private key material.
 */
export interface GroupConversationLike {
  signaturePublicKeyHex(): string;
  accountKeyHex(): string; // the account authorization key (empty for a legacy/unauthorized identity)
  keyPackage(): Uint8Array;
  // This conversation's MLS epoch, or -1 when not held. Diagnostic only. Two devices can both classify
  // a group as their self-group and still be unable to read each other if their epochs have diverged,
  // which no certificate check can surface. Optional so older wasm builds still load.
  groupEpoch?(conversationId: string): number;
  // The LAST-RESORT package: carries the MLS LastResort extension so OpenMLS keeps its private
  // bundle after a join. The directory re-serves that row forever, so an unmarked package there is
  // un-openable from the second claim on. Optional so older wasm builds still load.
  keyPackageLastResort?(): Uint8Array;
  // MULTI-GROUP (one device, many conversations): every per-conversation method takes the conversation's
  // groupId (hex of the MLS group id). createGroup returns a length-prefixed [welcome, groupId] for the
  // NEW conversation; joinFromWelcome returns the joined conversation's groupId (hex). receive ROUTES by
  // the group id inside the message and returns [groupId, taggedReceivedBlob]. listConversations lists
  // every open conversation's groupId so the channel can restore them all on reconnect.
  createGroup(keyPackagesBlob: Uint8Array): Uint8Array; // returns [welcome, groupId]
  // Self-group BIRTH-gated variant: every added package must chain to OUR account. Optional (older
  // wasm); the caller falls back to the ungated create when absent.
  createSelfGroup?(keyPackagesBlob: Uint8Array): Uint8Array; // returns [welcome, groupId]
  // Whether one package would pass the birth gate; the client pre-filters founding targets with it so
  // one stale package cannot abort the whole mint. Optional (older wasm).
  keyPackageSelfEligible?(keyPackage: Uint8Array): boolean;
  // Close (locally drop) one conversation: the wasm removes the group and deletes its MLS state.
  // Refuses the own-devices self-group; idempotent for an unknown id. Optional (older wasm).
  closeConversation?(conversationId: string): void;
  // Whether a held conversation provably has no reachable recipient (certless non-own leaf, no
  // verified foreign device). Advisory only. Optional (older wasm).
  channelUnlinked?(conversationId: string): boolean;
  // The distinct FOREIGN account authority keys (hex, sorted) among members whose device certs verify.
  // The anchor contact verification pins. Optional (older wasm).
  peerAccountKeys?(conversationId: string): string[];
  // Persist the ADVANCED receive ratchet (the library only writes it on send), so a seized powered-off
  // device cannot re-derive messages it already processed. False = this epoch's budget is spent.
  // Optional (older wasm).
  flushReceiveRatchet?(conversationId: string): boolean;
  createSelf(): Uint8Array; // SOLO own-devices group (no member admitted, so no welcome): returns groupId
  listConversations(): string[]; // groupId hex of every open conversation
  addMember(conversationId: string, keyPackage: Uint8Array): Uint8Array; // returns [commit, welcome]
  // Staged add (ADR-022 concurrency, the fork-free add path) in one conversation. stageAdd builds the
  // Add commit WITHOUT merging; the committer stays on that group's epoch N until confirmed (its own echo
  // seen in receive, or confirmAdd on a timeout) or aborted (a competing commit won). Idempotent.
  stageAdd(conversationId: string, keyPackage: Uint8Array): Uint8Array; // returns [commit, welcome]
  confirmAdd(conversationId: string): void;
  abortAdd(conversationId: string): void;
  removeMember(conversationId: string, sigKeyHex: string): Uint8Array; // returns the Remove commit
  // Staged remove (the fork-free removal path, mirror of stageAdd): stageRemove builds the Remove commit
  // but does NOT merge until confirmed (confirmRemove on the echo/timeout) or aborted (abortRemove on a
  // competing win). Used by the peer-revoke self-heal. Idempotent.
  stageRemove(conversationId: string, sigKeyHex: string): Uint8Array; // returns the Remove commit (no welcome)
  confirmRemove(conversationId: string): void;
  abortRemove(conversationId: string): void;
  // A staged commit that survived a reload (the sealed blob persists its wire bytes), for the restore
  // re-arm: kind 0 = none, 1 = Add, 2 = Remove; target = the device signature key hex ('' when none);
  // commit = the outgoing wire bytes to re-publish (empty when none).
  pendingKind(conversationId: string): number;
  pendingTarget(conversationId: string): string;
  pendingCommit(conversationId: string): Uint8Array;
  pendingWelcome(conversationId: string): Uint8Array; // the staged Add's Welcome (empty for none/Remove)
  // A stable, opaque, SECRET-KEYED per-mailbox delivery-cursor tag for the gateway's hold-until-ack bus
  // (unlinkable across mailboxes; survives reload). Passed as the subscribe consumer id. Subject-keyed,
  // so it is independent of any conversation id.
  mailboxTag(subject: string): string;
  joinFromWelcome(welcome: Uint8Array): string; // returns the joined conversation's groupId (hex)
  encrypt(conversationId: string, plaintext: Uint8Array): Uint8Array;
  receive(ciphertext: Uint8Array): Uint8Array; // returns [groupId, taggedReceivedBlob] (self-routed)
  roster(conversationId: string): string[]; // sorted member signature-key hex strings
  // True iff every member of this conversation is one of OUR OWN account's devices (the hidden self-group
  // that syncs our buddy list across our devices). Cryptographically grounded (each member's certificate
  // account key is compared to ours), so it never depends on a client-side device-list cache.
  isSelfConversation(conversationId: string): boolean;
  // STRICT variant: our own leaf must also carry a verifying certificate (no own-leaf exemption). Used
  // only to PREFER a fully certified self-group during canonical-group selection.
  isSelfConversationStrict?(conversationId: string): boolean;
  // READ-ONLY diagnostic: WHY a conversation is or is not a self-group ("self" when it is). Makes no
  // decision and grants no access; surfaced so a stuck self-classification is diagnosed by reading the
  // cause instead of guessing at MLS rosters the keyless gateway cannot show.
  selfClassificationReason?(conversationId: string): string;
  // SG2 self-heal: abandon an own-devices group that is provably DEAD (a frozen certless leaf makes it
  // unrepairable in place and it can never sync). `recordedSelf` is the CALLER's durable record that
  // this id is one of our self-groups: the crypto layer cannot derive it (a peer chat whose peer was
  // still certless looks identical), so it refuses without it. Also refuses a group that still has any
  // verified sibling. Returns true when it abandoned one.
  abandonDeadSelfGroup?(conversationId: string, recordedSelf: boolean): boolean;
  // Whether our CURRENT credential carries a verifying certificate (a fresh mint would be strict).
  // Bounds the certified-replacement mint: a legacy label-only credential must not replace, ever.
  credentialCertified?(): boolean;
  groupMailbox(conversationId: string): string; // that conversation's per-epoch mailbox
  // Device provisioning (ADR-022 model b). A seed-holder signs a certificate for a new device; the
  // new device adopts a certificate signed by the account key, becoming authorized without the seed.
  authorizeDevice(deviceKeyHex: string, certEpoch: number, nonceHex: string, confirmedSasHex: string): string;
  adoptCertificate(accountPubHex: string, certEpoch: number, certHex: string): void;
  // QR pairing: certify a device key obtained by SCANNING its QR (no SAS; the optical scan is the auth).
  // Returns the grant bytes `aak_pub(32) || epoch(8, BE) || cert(64)`.
  authorizeScannedDevice(deviceSigKey: Uint8Array, certEpoch: number): Uint8Array;
  // Recovery + the P6 epoch bump. recoverWithSeed adopts the account key from the recovery secret and
  // self-certifies (keeping the device key); reauthorizeAtEpoch re-certifies at a bumped epoch; certEpoch
  // is this device's own certificate epoch (0 if unauthorized).
  recoverWithSeed(recoverySeedHex: string, certEpoch: number): void;
  reauthorizeAtEpoch(certEpoch: number): void;
  certEpoch(): number;
  // ADR-022 P7 signed revocation records: the account's DENYLIST, and the thing that actually excludes a
  // revoked device. The epoch above is only a lower bound, and a revoked device that still holds the
  // account seed re-certifies itself above any bound, so exclusion has to name the device's key.
  // revokeDevice mints a record (seed-holder only) and returns it as hex to publish; ingestRevocation
  // accepts one fetched from the control plane, erroring on anything that does not verify under our own
  // account key; revokedCount is the DERIVED epoch (|records|), which every device computes identically
  // offline; accountFloor is the lowest epoch this device will now certify at.
  revokeDevice?(deviceSigKeyHex: string, issuedSeq: number): string;
  ingestRevocation?(recordHex: string): boolean;
  revokedCount?(): number;
  isDeviceRevoked?(deviceSigKeyHex: string): boolean;
  accountFloor?(): number;
  wipe(): void;
}

/** What receiving one inbound group payload yields. `fromOwnAccount` (on application-derived results) is
 * true when the message's authenticated MLS sender is a device of OUR OWN account, so an identity update
 * from a sibling can be adopted (vs. a peer's, which is stored separately). */
export type GroupReceived =
  | { readonly type: 'message'; readonly frame: IncomingFrame; readonly fromOwnAccount: boolean }
  | { readonly type: 'membership'; readonly added: readonly string[]; readonly removed: readonly string[] }
  | { readonly type: 'evicted' }
  | { readonly type: 'proposal' }
  | { readonly type: 'control'; readonly controlType: number; readonly version: number; readonly payload: Uint8Array; readonly fromOwnAccount: boolean }
  | { readonly type: 'ignored' };

/** The result of adding a device: the commit to publish to the group, and the Welcome for the device. */
export interface AddOutput {
  readonly commit: Uint8Array;
  readonly welcome: Uint8Array;
}

/**
 * One open conversation's send/roster/membership view over the shared multi-group `conv`. It holds the
 * conversation's `groupId` (the MLS group id, hex) and forwards every crypto op with it, so a device can
 * hold many GroupSessions at once. Inbound routing is NOT per-session: `receiveGroup` (below) self-routes
 * by the group id inside the message, so the GroupChannel maps the returned id back to its channel.
 */
export class GroupSession {
  constructor(
    private readonly conv: GroupConversationLike,
    /** The MLS group id (hex). Stable across epochs; the per-conversation key at the crypto boundary. */
    readonly groupId: string,
  ) {}

  /** Creator path: create a NEW conversation adding every other device (peer devices + our own siblings)
   * from their key packages in one commit. Returns the Welcome each device joins from and the session. */
  static create(conv: GroupConversationLike, keyPackages: readonly Uint8Array[]): { welcome: Uint8Array; session: GroupSession } {
    const parts = decodeList(conv.createGroup(encodeList(keyPackages)));
    if (parts.length !== 2 || parts[0] === undefined || parts[1] === undefined) {
      throw new Error('createGroup did not return a welcome and a group id');
    }
    return { welcome: parts[0], session: new GroupSession(conv, bytesToHex(parts[1])) };
  }

  /** Creator path for the SOLO own-devices self-group: a group whose only member is this device. There
   * is no Welcome (no one else is admitted). Used so a single-device account still has a self-group for
   * Note to Self and buddy-list sync; siblings fold in later via the normal staged-add path. */
  static createSelf(conv: GroupConversationLike): GroupSession {
    return new GroupSession(conv, bytesToHex(conv.createSelf()));
  }

  /** Creator path for the MULTI-DEVICE self-group, BIRTH-gated in the wasm: every founding package must
   * chain to our account, so a stale pre-authorization package can never mint a poisoned self-group.
   * Falls back to the ungated create on an older wasm. */
  static createSelfGroup(conv: GroupConversationLike, keyPackages: readonly Uint8Array[]): { welcome: Uint8Array; session: GroupSession } {
    const make = conv.createSelfGroup?.bind(conv) ?? conv.createGroup.bind(conv);
    const parts = decodeList(make(encodeList(keyPackages)));
    if (parts.length !== 2 || parts[0] === undefined || parts[1] === undefined) {
      throw new Error('createSelfGroup did not return a welcome and a group id');
    }
    return { welcome: parts[0], session: new GroupSession(conv, bytesToHex(parts[1])) };
  }

  /** Joiner path: join a conversation from the Welcome delivered to our bootstrap mailbox. */
  static join(conv: GroupConversationLike, welcome: Uint8Array): GroupSession {
    return new GroupSession(conv, conv.joinFromWelcome(welcome));
  }

  /** This conversation's per-epoch group mailbox: subscribe to it to receive, publish to it to send. It
   * rotates whenever the membership changes, so re-read it after a membership event. */
  mailbox(): string {
    return this.conv.groupMailbox(this.groupId);
  }

  /** This conversation's roster as member signature-key hex strings (for the device/roster view). */
  roster(): readonly string[] {
    return this.conv.roster(this.groupId);
  }

  /** True iff every member of this conversation is one of OUR OWN account's devices (the hidden
   * self-group that syncs our buddy list). Used to keep it out of the conversation list and to target
   * buddy-list syncs. Cryptographically grounded, so it does not rely on any device-list cache. */
  isSelfConversation(): boolean {
    return this.conv.isSelfConversation(this.groupId);
  }

  /** STRICT self classification: no own-leaf exemption. False when our own leaf was minted pre-cert.
   * Canonical-group selection prefers strict groups; absent on an older wasm, treated as false. */
  isSelfConversationStrict(): boolean {
    return this.conv.isSelfConversationStrict?.(this.groupId) ?? false;
  }

  /** READ-ONLY diagnostic: the classifier's reason this conversation is or is not a self-group ("self"
   * when it is). '' on an older wasm without the accessor. Never changes behavior; surfaced so a stuck
   * self-classification is diagnosed by reading the cause. */
  selfClassificationReason(): string {
    return this.conv.selfClassificationReason?.(this.groupId) ?? '';
  }

  /** Whether this conversation provably has no reachable recipient. Advisory only; false on an older
   * wasm or any classification error (fail-safe: no advisory beats a wrong one). */
  unlinked(): boolean {
    try {
      return this.conv.channelUnlinked?.(this.groupId) ?? false;
    } catch {
      return false;
    }
  }

  /** The distinct foreign account keys (hex) of this conversation's cert-verified members. Empty on an
   * older wasm or any error (fail-safe: showing nothing to verify beats pinning a wrong key). */
  peerAccountKeys(): string[] {
    try {
      return this.conv.peerAccountKeys?.(this.groupId) ?? [];
    } catch {
      return [];
    }
  }

  /** Persist the advanced receive ratchet for this conversation. Returns false when the wasm is older,
   * the budget for this epoch is spent, or anything throws, so the caller can skip a pointless re-seal. */
  flushReceiveRatchet(): boolean {
    try {
      return this.conv.flushReceiveRatchet?.(this.groupId) ?? false;
    } catch {
      return false;
    }
  }

  /** This account's authorization-key public value (its stable identity), verified out of band. */
  accountKey(): string {
    return this.conv.accountKeyHex();
  }

  /** Send a user message to this whole conversation. The effective lifetime rides inside the ciphertext;
   * the payload is padded to a fixed bucket before encryption so on-wire length leaks nothing (§5.2). */
  send(plaintext: Uint8Array, lifetime: Lifetime, ttlSeconds?: number): EnvelopeMsg {
    const framed = frameMessage(plaintext, lifetime);
    return {
      messageId: randomBytes(16),
      routingKey: this.conv.groupMailbox(this.groupId),
      payload: this.conv.encrypt(this.groupId, padToBucket(framed)),
      ttlSeconds: ttlSeconds ?? deriveTtlSeconds(lifetime),
    };
  }

  /** Send a cooperative revoke command for one of OUR OWN messages to this whole conversation. It
   * rides the same padded, encrypted stream as a message, so the server never learns which message is
   * revoked (P2/P6). Every well-behaved member device crypto-erases its stored copy. HONEST LIMIT: it
   * cannot recall a copy a recipient already screenshotted or exported. */
  sendRevoke(targetMessageId: string, ttlSeconds: number = SEVEN_DAYS_SECONDS): EnvelopeMsg {
    return {
      messageId: randomBytes(16),
      routingKey: this.conv.groupMailbox(this.groupId),
      payload: this.conv.encrypt(this.groupId, padToBucket(frameRevoke(targetMessageId))),
      ttlSeconds,
    };
  }

  /** Send a versioned application control frame (buddy icon, profile) to this whole conversation. It
   * rides the same padded, encrypted stream as a message, so the server sees only an opaque blob. */
  sendControl(
    controlType: number,
    version: number,
    payload: Uint8Array,
    ttlSeconds: number = SEVEN_DAYS_SECONDS,
  ): EnvelopeMsg {
    return {
      messageId: randomBytes(16),
      routingKey: this.conv.groupMailbox(this.groupId),
      payload: this.conv.encrypt(this.groupId, padToBucket(frameControl(controlType, version, payload))),
      ttlSeconds,
    };
  }

  /** Add a device to this conversation (an online sibling admitting a newly enrolled device, P5). */
  addDevice(keyPackage: Uint8Array): AddOutput {
    const parts = decodeList(this.conv.addMember(this.groupId, keyPackage));
    if (parts.length !== 2 || parts[0] === undefined || parts[1] === undefined) {
      throw new Error('addMember did not return a commit and a welcome');
    }
    return { commit: parts[0], welcome: parts[1] };
  }

  /** STAGE a device add without merging (ADR-022 concurrency, the fork-free path) in this conversation.
   * Returns the commit to publish and the Welcome for the new device. This conversation stays on its
   * epoch N until confirmAdd (its own echo seen in receive, or a timeout) or abortAdd (a competing commit
   * won the epoch). The caller must NOT rotate this conversation's mailbox until the add is confirmed. */
  stageAddDevice(keyPackage: Uint8Array): AddOutput {
    const parts = decodeList(this.conv.stageAdd(this.groupId, keyPackage));
    if (parts.length !== 2 || parts[0] === undefined || parts[1] === undefined) {
      throw new Error('stageAdd did not return a commit and a welcome');
    }
    return { commit: parts[0], welcome: parts[1] };
  }

  /** Confirm a staged add in this conversation (merge its pending commit). Idempotent. */
  confirmAdd(): void {
    this.conv.confirmAdd(this.groupId);
  }

  /** Abort a staged add in this conversation (clear its pending commit). Idempotent. */
  abortAdd(): void {
    this.conv.abortAdd(this.groupId);
  }

  /** Remove a device from this conversation, rotating its group secrets (forward-secure exclusion, P6).
   * Returns the Remove commit to publish. */
  removeDevice(sigKeyHex: string): Uint8Array {
    return this.conv.removeMember(this.groupId, sigKeyHex);
  }

  /** STAGE a device removal (fork-free): build the Remove commit but stay on epoch N until confirmRemove
   * (its own echo seen in receive, or a timeout) or abortRemove (a competing commit won). Returns the
   * Remove commit to publish (no welcome). Used by the peer-revoke self-heal. */
  stageRemoveDevice(sigKeyHex: string): Uint8Array {
    return this.conv.stageRemove(this.groupId, sigKeyHex);
  }

  /** CONFIRM a staged removal in this conversation (merge the pending Remove commit). Idempotent. */
  confirmRemove(): void {
    this.conv.confirmRemove(this.groupId);
  }

  /** ABORT a staged removal in this conversation (clear the pending Remove commit), staying on epoch N. */
  abortRemove(): void {
    this.conv.abortRemove(this.groupId);
  }

  /** A staged commit that survived a reload, for the restore re-arm: 'add', 'remove', or null. */
  pendingKind(): 'add' | 'remove' | null {
    const k = this.conv.pendingKind(this.groupId);
    return k === 1 ? 'add' : k === 2 ? 'remove' : null;
  }

  /** The surviving staged commit's target device signature key hex ('' when nothing is staged). */
  pendingTarget(): string {
    return this.conv.pendingTarget(this.groupId);
  }

  /** The surviving staged commit's outgoing wire bytes to re-publish (empty when nothing is staged). */
  pendingCommit(): Uint8Array {
    return this.conv.pendingCommit(this.groupId);
  }

  /** The surviving staged Add's Welcome bytes to re-deliver to the added device (empty for none/Remove). */
  pendingWelcome(): Uint8Array {
    return this.conv.pendingWelcome(this.groupId);
  }
}

/** Receive one inbound group payload at the device level: the crypto layer ROUTES it to the right
 * conversation by the group id inside the message. Returns that conversation's groupId (hex) and the
 * decoded result, so the GroupChannel maps the id to its channel and dispatches. A membership change
 * advances that conversation's epoch, so the caller must re-read its mailbox after a 'membership'. */
export function receiveGroup(conv: GroupConversationLike, payload: Uint8Array): { groupId: string; received: GroupReceived } {
  const outer = decodeList(conv.receive(payload));
  if (outer.length !== 2 || outer[0] === undefined || outer[1] === undefined) {
    throw new Error('receive did not return a group id and a result');
  }
  return { groupId: bytesToHex(outer[0]), received: decodeGroupReceived(outer[1]) };
}

/** Decode the tagged receive blob (the inner half of receive's [groupId, blob]) into a GroupReceived. */
function decodeGroupReceived(blob: Uint8Array): GroupReceived {
  const decoded = decodeReceived(blob);
  if (decoded.kind === 'application') {
    const fromOwnAccount = decoded.fromOwnAccount;
    let parsed: ParsedFrame;
    try {
      parsed = parseFrame(unpadFromBucket(decoded.plaintext));
    } catch {
      return { type: 'ignored' }; // malformed padding/body: drop, never wedge the receive loop
    }
    if (parsed.type === 'control') {
      return { type: 'control', controlType: parsed.controlType, version: parsed.version, payload: parsed.payload, fromOwnAccount };
    }
    if (parsed.type === 'ignored') {
      return { type: 'ignored' };
    }
    return { type: 'message', frame: parsed, fromOwnAccount };
  }
  if (decoded.kind === 'membership') {
    return { type: 'membership', added: decoded.added, removed: decoded.removed };
  }
  if (decoded.kind === 'evicted') {
    return { type: 'evicted' };
  }
  return { type: 'proposal' };
}

// --- byte codecs (must match crypto/src/conversation.rs) ---

/** A length-prefixed list: u32-BE count, then each item as u32-BE length + bytes. */
export function encodeList(items: readonly Uint8Array[]): Uint8Array {
  let total = 4;
  for (const it of items) {
    total += 4 + it.length;
  }
  const out = new Uint8Array(total);
  const dv = new DataView(out.buffer);
  dv.setUint32(0, items.length, false);
  let pos = 4;
  for (const it of items) {
    dv.setUint32(pos, it.length, false);
    pos += 4;
    out.set(it, pos);
    pos += it.length;
  }
  return out;
}

function decodeListAt(b: Uint8Array, ref: { pos: number }): Uint8Array[] {
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const n = dv.getUint32(ref.pos, false);
  ref.pos += 4;
  const items: Uint8Array[] = [];
  for (let i = 0; i < n; i++) {
    const len = dv.getUint32(ref.pos, false);
    ref.pos += 4;
    items.push(b.slice(ref.pos, ref.pos + len));
    ref.pos += len;
  }
  return items;
}

export function decodeList(b: Uint8Array): Uint8Array[] {
  return decodeListAt(b, { pos: 0 });
}

type Decoded =
  | { kind: 'application'; plaintext: Uint8Array; fromOwnAccount: boolean }
  | { kind: 'membership'; added: string[]; removed: string[] }
  | { kind: 'evicted' }
  | { kind: 'proposal' };

/** Decode a tagged receive blob from the wasm `receive`. Tag 0 (application) is followed by a flag byte
 * (1 = the authenticated sender is one of our own account's devices) then the plaintext. */
export function decodeReceived(b: Uint8Array): Decoded {
  const tag = b[0];
  if (tag === 0) {
    return { kind: 'application', plaintext: b.slice(2), fromOwnAccount: b[1] === 1 };
  }
  if (tag === 1) {
    const ref = { pos: 1 };
    const added = decodeListAt(b, ref).map(bytesToHex);
    const removed = decodeListAt(b, ref).map(bytesToHex);
    return { kind: 'membership', added, removed };
  }
  if (tag === 2) {
    return { kind: 'evicted' };
  }
  return { kind: 'proposal' };
}

function bytesToHex(b: Uint8Array): string {
  return [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
}

function randomBytes(n: number): Uint8Array {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}
