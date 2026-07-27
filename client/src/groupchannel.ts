/**
 * Multi-device group transport channel (ADR-022 model B, P4). This REPLACES the pairwise LiveChannel
 * (offer/accept) with a single group code path: a conversation is one MLS group whose leaves are all
 * of each participant's devices.
 *
 * Flow:
 *   - connectGateway restores (or creates) the device's durable AUTHORIZED identity and subscribes to
 *     its bootstrap mailbox (its signature key), where Welcomes arrive. If a group already exists, it
 *     also re-subscribes to that group's per-epoch mailbox.
 *   - startConversation creates the group adding all of the peer's devices AND our own siblings in one
 *     commit, subscribes to the group mailbox, and publishes the single Welcome to each device's
 *     bootstrap mailbox. Every device joins from it and subscribes to the group mailbox, so all
 *     receive and any can reply (the bus fans a publish out to every subscriber).
 *   - onDeliver routes by the envelope's routing key: our bootstrap mailbox => a Welcome to join; the
 *     group mailbox => an application message, a membership change (re-subscribe to the rotated
 *     mailbox), or our own eviction.
 *
 * Like LiveChannel, browser-only dependencies are injected so this module stays gate-clean and is
 * unit-tested with fakes. The authorization gate and the MLS crypto are in crypto/src/*.rs.
 */

import { GroupSession, receiveGroup, type GroupConversationLike } from './group.js';
import { CONTROL_FILE, CONTROL_CALL, CONTROL_BUDDY_ICON, CONTROL_PROFILE, CONTROL_AWAY, CONTROL_BUDDIES, CONTROL_GROUPS } from './session.js';
import { Provisioning, deriveProvMailbox, type ProvisioningDeps } from './provisioning.js';
import { renderSasHex } from './sas.js';
import type { Transport, TransportHandlers } from './transport.js';
import type { EnvelopeMsg } from './session.js';
import type { LogEntry, TransmitModel, ChannelSummary } from './app.js';
import type { Lifetime } from './index.js';

const enc = new TextEncoder();
const CONTACT_TAG = 'deaddrop';
const CONTACT_VERSION = '1';

/** A short, human-readable fingerprint of a key for recognition (first 4 bytes). */
export function fingerprintOf(sigHex: string): string {
  return [0, 2, 4, 6].map((i) => sigHex.slice(i, i + 2).toUpperCase()).join('·');
}

function shortName(sigHex: string): string {
  return sigHex.slice(0, 6).toUpperCase();
}

/** Our copy-pasteable contact string (kept for compatibility; messaging is by username directory). */
export function formatContact(sigHex: string): string {
  return `${CONTACT_TAG}:${CONTACT_VERSION}:${sigHex}:${sigHex}`;
}

function bytesToHex(b: Uint8Array): string {
  return [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
}

function errMsg(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

function systemEntry(text: string): LogEntry {
  return { kind: 'system', text: `» ${text}` };
}

function randomBytes(n: number): Uint8Array {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}

/** Byte-exact equality, used to confirm a staged commit is STILL the one we staged after an async gap. */
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

/** One device of a participant, as returned by the key-package directory (take-keys). */
export interface DeviceTarget {
  readonly deviceKey: string; // the device's signature key = its bootstrap mailbox
  readonly keyPackage: Uint8Array; // the device's claimed one-time key package
}

/** Browser-only dependencies injected by the worker host. */
export interface GroupDeps {
  connect(url: string, handlers: TransportHandlers): Transport;
  /** Make our durable AUTHORIZED identity Conversation from the account's recovery seed (the worker
   * builds it via wasm `newAuthorized`). */
  makeConversation(label: string, recoverySeedHex: string): GroupConversationLike;
  pushEvent(kind: string, payload: unknown): void;
  schedule(delayMs: number, cb: () => void): unknown;
  cancel(handle: unknown): void;
  sealConversation(conv: GroupConversationLike, msk: Uint8Array): Uint8Array;
  restoreConversation(msk: Uint8Array, sealed: Uint8Array): GroupConversationLike;
  /** The 66-bit device-provisioning SAS digest (wasm free function), bound to the transcript. */
  sasDigestHex(nonceHex: string, accountPubHex: string, deviceKeyHex: string, certEpoch: number): string;
  /** QR-pairing box primitives (wasm free functions); optional so hosts without them still run the
   * 6-word flow. Fresh ephemeral X25519 keypair (secret||public), seal a grant to a public key, open a
   * sealed grant with a secret. */
  provisionEphemeralKeypair?: (() => Uint8Array) | undefined;
  provisionSeal?: ((recipPub: Uint8Array, plaintext: Uint8Array) => Uint8Array) | undefined;
  provisionOpen?: ((recipSecret: Uint8Array, sealedBox: Uint8Array) => Uint8Array) | undefined;
  /** Conversation ids the user CLOSED (durable). The restore skips (and re-closes) them so a parallel
   * tab's reseal can never resurrect a closed conversation. Optional: hosts without it restore all. */
  loadClosedIds?: (() => Promise<ReadonlySet<string>>) | undefined;
}

export type PersistMessage = (
  /** `ownAuthored` marks an inbound copy of a message OUR OWN account authored on a sibling device
   * (MLS-authenticated as fromOwnAccount), so that device keeps the revoke control too. */
  meta: { messageId: string; conversationId: string; direction: 'in' | 'out'; lifetime: Lifetime; ownAuthored?: boolean },
  plaintext: Uint8Array,
) => Promise<void>;

/** Durable identity persistence (wired to the controller, which holds the MSK). loadSelf restores our
 * long-lived authorized identity (and any group it is in); saveSelf persists it on first creation. */
export interface GroupPersistence {
  loadSelf(): Promise<GroupConversationLike | null>;
  saveSelf(conv: GroupConversationLike): Promise<void>;
  /** Re-seal our durable identity, OVERWRITING the stored one. Used after a provisioned device adopts
   * its certificate, so the now-authorized identity survives a reload (saveSelf is create-if-absent
   * and must not clobber a stable identity, so adoption needs this explicit re-seal). */
  resealSelf(conv: GroupConversationLike): Promise<void>;
  /** The account's recovery-secret seed (hex) if this device holds it (the registering/seed-holder
   * device), else '' for a device that joins by provisioning and never learns the seed (model b). */
  recoverySeedHex(): Promise<string>;
}

/** One open conversation's live state. The MLS group id lives in `session.groupId`; the conversationId
 * (the channel key the app + persistence use) is derived from it as `c-${groupId}`, so it is stable
 * across reload and dedupes a resent Welcome. */
interface SessionEntry {
  readonly session: GroupSession;
  groupMailbox: string; // this conversation's current per-epoch mailbox (rotates on membership change)
}

export class GroupChannel {
  private transport: Transport | null = null;
  private connectGen = 0; // bumped per connectGateway; a superseded socket's events are ignored
  private conv: GroupConversationLike | null = null;
  private bootstrapKey = ''; // our signature key = our bootstrap mailbox
  // Every open conversation, keyed by conversationId (= `c-${groupId}`). One device holds MANY at once;
  // inbound messages self-route by group id (receiveGroup) and we map the group id back to its entry.
  private readonly sessions = new Map<string, SessionEntry>();
  private provisioning: Provisioning | null = null; // the device-provisioning state machine, when active
  // A sibling add in flight per conversation (ADR-022 self-heal): we staged its commit and are waiting
  // for our own echo to confirm it. `handle` is the confirm-backstop timer. Cleared when that
  // conversation's membership event lands (our echo confirmed it, or a competing commit won and the wasm
  // aborted ours). Per conversation, so an add in one conversation never blocks another.
  // One in-flight staged commit per conversation (an Add or a Remove). Mirrors the single OpenMLS pending
  // slot, so a reconcile of either kind bails while the other is in flight (structural single-writer).
  private readonly pendingOps = new Map<string, { kind: 'add' | 'remove'; target?: DeviceTarget; handle: unknown }>();
  // Conversations with an add failover already armed (a non-designated device waiting to take over). Guards
  // against stacking duplicate failovers when reconcile is retriggered repeatedly (e.g. the seed-holder's
  // post-add poll fires every few seconds); one armed failover per conversation is enough.
  private readonly failoverScheduled = new Set<string>();
  // Our own account's device keys, cached from the last reconcile. Lets onMembershipAdvanced tell a
  // genuine new PEER (who needs our identity) from one of our OWN siblings the heal cascade just added
  // (who already gets our identity over the self-group), so we do not re-broadcast identity to every
  // peer roster on a device add (that fan-out is what floods the gateway publish limit).
  private knownOwnKeys: ReadonlySet<string> = new Set();
  // Per-conversation FIFO of inbound APPLY effects (message persistence, revoke application). The
  // receive handler is synchronous but the effects are async; without ordering, a revoke arriving
  // right behind its target message would run its keyvault lookup before the target's put commits,
  // find nothing, and be acked away forever. Chaining preserves arrival order per conversation.
  private readonly applyChains = new Map<string, Promise<void>>();
  // Publishes awaiting the gateway's per-message receipt, keyed by the envelope's message-id hex.
  // Today only the revoke frame registers here (its sender crypto-erases its local copy only once the
  // gateway durably holds the frame); a receipt with no waiter is an ordinary publish ack and is
  // dropped as before. confirm/fail settle the waiter exactly once and remove it.
  private readonly pendingReceipts = new Map<string, { confirm: () => void; fail: (e: Error) => void }>();

  constructor(
    private readonly deps: GroupDeps,
    private readonly persistChannel: (summary: ChannelSummary) => Promise<void>,
    private readonly persistMessage: PersistMessage,
    private readonly persistence?: GroupPersistence,
    /** Build this device's identity control frames (buddy icon, profile) to publish to the group, so
     * members see them E2E. Absent on a controller with no identity source. */
    private readonly loadIdentityFrames?: () => Promise<readonly { controlType: number; payload: Uint8Array }[]>,
    /** Persist a peer's received identity control frame, already validated as a current non-self group
     * member. Cosmetic and authenticated only by membership (see onControlFrame). */
    private readonly persistPeerIdentity?: (
      conversationId: string,
      peerKey: string,
      controlType: number,
      payload: Uint8Array,
    ) => Promise<void>,
    /** Adopt an identity control frame (buddy icon / profile) that came from one of THIS account's own
     * devices (a sibling), so the buddy icon stays consistent across all your devices, last-change-wins.
     * Crypto-authenticated as own-account (fromOwnAccount), so a peer cannot push you a fake own icon. */
    private readonly onSiblingIdentity?: (controlType: number, payload: Uint8Array) => void,
    /** Return the away text to auto-reply with for this conversation, or null when away is off or the
     * per-conversation cooldown has not elapsed. The cooldown + dedupe live in the controller. */
    private readonly awayReply?: (conversationId: string, peerName: string) => Promise<string | null>,
    /** Return true when EVERY non-self member of a group is blocked, so an inbound Welcome to it is
     * dropped silently and a blocked party cannot pull you into a conversation. Best-effort: a blocked
     * party can make a new key (honest-limits). */
    private readonly isBlockedRoster?: (peerKeys: readonly string[]) => Promise<boolean>,
    /** Hand an inbound file-transfer signal (a CONTROL_FILE payload) to the file-transfer module, tagged
     * with the conversation it arrived in so the app routes it to the right transfer. The file bytes
     * never reach this layer; only the E2E SDP/ICE handshake does. */
    private readonly onFileSignal?: (conversationId: string, payload: Uint8Array) => void,
    /** Hand an inbound call signal (a CONTROL_CALL payload) to the call module, tagged with its
     * conversation. The audio/video media never reaches this layer; only the E2E SDP/ICE handshake. */
    private readonly onCallSignal?: (conversationId: string, payload: Uint8Array) => void,
    /** Hand an inbound buddy-list frame (CONTROL_BUDDIES) to the controller to merge per-buddy
     * last-writer-wins. Only ever called for a frame whose authenticated sender is one of our own devices. */
    private readonly onBuddies?: (payload: Uint8Array) => void,
    /** Load our current buddy-list control frame to publish to the self-group when it forms or a sibling
     * joins. Returns null before login or when the sealed store is unavailable. */
    private readonly loadBuddiesFrame?: () => Promise<Uint8Array | null>,
    /** Hand an inbound buddy-GROUP-list frame (CONTROL_GROUPS) to the controller to merge per-group
     * last-writer-wins. Only ever called for a frame whose authenticated sender is one of our own devices. */
    private readonly onGroups?: (payload: Uint8Array) => void,
    /** Load our current group-list control frame to publish to the self-group when it forms or a sibling
     * joins. Returns null before login or when the sealed store is unavailable. */
    private readonly loadGroupsFrame?: () => Promise<Uint8Array | null>,
    /** Apply an inbound cooperative revoke: crypto-erase the targeted stored message. The controller
     * validates the target (it must be an until-revoked record of THIS conversation, and a PEER's
     * revoke can never touch our own OUTBOUND copy) so a member can only destroy what the
     * revocable-message contract covers. `fromOwnAccount` is the frame's MLS-authenticated
     * own-account flag: a sibling device's revoke may also erase the authoring device's 'out' copy. */
    private readonly onRevoke?: (conversationId: string, targetMessageId: string, fromOwnAccount: boolean) => Promise<void>,
    /** Delete a conversation's persisted channel summary (the mirror of persistChannel). Called when we
     * are EVICTED from a conversation: without it the summary outlives the session forever, and the dead
     * row (which can never receive again, and no longer classifies as anything) haunts the Channels list. */
    private readonly deleteChannel?: (conversationId: string) => Promise<void>,
  ) {}

  selfContact(): string | undefined {
    return this.conv !== null ? formatContact(this.bootstrapKey) : undefined;
  }

  selfFingerprint(): string {
    return this.conv !== null ? fingerprintOf(this.bootstrapKey) : 'pending';
  }

  /** This device's signature key hex (its identity in the group roster), or '' before connect. */
  selfDeviceKeyHex(): string {
    return this.bootstrapKey;
  }

  /** The account authorization key (AAK) public hex: the STABLE account identity, the same across all of
   * this user's devices. Empty for a legacy/unauthorized identity. Backs the shareable contact QR. */
  accountKeyHex(): string {
    return this.conv !== null ? this.conv.accountKeyHex() : '';
  }

  /** Re-publish this device's identity (buddy icon, profile) to the open group. Called after the user
   * edits their identity, and internally whenever a group forms or its membership changes so a new
   * member receives it. No-op when no group is open or no identity source is wired. */
  publishIdentityNow(): void {
    this.publishIdentity();
  }

  /** The conversationId (channel key) for a group id: derived deterministically so it is stable across
   * reload and a resent Welcome maps to the same conversation (dedupe). */
  private convId(groupId: string): string {
    return `c-${groupId}`;
  }

  /** Run `apply` after every earlier apply of the same conversation has settled (arrival-order FIFO).
   * Returns apply's own outcome; the stored chain tail never rejects, so one failed apply cannot
   * poison the conversation's later ones. */
  private enqueueApply(conversationId: string, apply: () => Promise<void>): Promise<void> {
    const prev = this.applyChains.get(conversationId) ?? Promise.resolve();
    const run = prev.then(apply);
    this.applyChains.set(
      conversationId,
      run.then(
        () => undefined,
        () => undefined,
      ),
    );
    return run;
  }

  /** Re-share this device's identity (buddy icon, profile) to EVERY open conversation. */
  private publishIdentity(): void {
    for (const entry of this.sessions.values()) {
      this.publishIdentityFor(entry.session);
    }
  }

  /** Share this device's identity to ONE conversation (on join, or when its membership changes so a new
   * member receives it). Best-effort; a locked vault or absent identity must not break the channel. */
  private publishIdentityFor(session: GroupSession): void {
    if (this.transport === null || this.loadIdentityFrames === undefined) {
      return;
    }
    void this.loadIdentityFrames()
      .then((frames) => {
        // Re-read the CURRENT transport inside the async gap (like publishBuddiesFor). loadIdentityFrames
        // does an IDB decrypt, and a self-group heal at join runs amid reconnect churn (AIM21), so a
        // transport captured before the await can be a CLOSED socket by the time the frames load. Publishing
        // the icon/profile/away frames on that dead socket silently dropped them, so a new device synced the
        // buddy list (published on the live transport) but not the icon/profile until a later edit re-sent
        // them on a stable socket.
        const t = this.transport;
        if (t === null) {
          return;
        }
        for (const f of frames) {
          t.publish(session.sendControl(f.controlType, 1, f.payload));
        }
      })
      .catch(() => {
        /* best-effort */
      });
  }

  /** The open conversation that is the hidden self-group (every member is one of our own devices), or
   * null. Cryptographically determined per session (isSelfConversation), so it never depends on a
   * device-list cache. There is at most one self-group by construction, but a state written by an older
   * build can hold two (a solo one raced the sibling orchestration before createSelfGroup re-checked);
   * selection is therefore DETERMINISTIC: the largest roster wins, then the smallest group id, so every
   * device and every reload targets the SAME group for notes and buddy sync instead of following map
   * iteration order. The loser just sits unused. */
  private selfSessionBest(): { session: GroupSession; strict: boolean } | null {
    let best: GroupSession | null = null;
    let bestStrict = false;
    for (const entry of this.sessions.values()) {
      if (!entry.session.isSelfConversation()) {
        continue;
      }
      // STRICT (fully certified) groups outrank exemption-classified ones, THEN largest roster, THEN
      // smallest gid. Without the strict key, a roster tie could let a copy holding our frozen certless
      // leaf win the gid tie-break here while a sibling picks the certified group, and our buddy
      // publishes would be dropped at its gate.
      const strict = entry.session.isSelfConversationStrict();
      if (
        best === null ||
        (strict && !bestStrict) ||
        (strict === bestStrict &&
          (entry.session.roster().length > best.roster().length ||
            (entry.session.roster().length === best.roster().length && entry.session.groupId < best.groupId)))
      ) {
        best = entry.session;
        bestStrict = strict;
      }
    }
    return best === null ? null : { session: best, strict: bestStrict };
  }

  private selfSession(): GroupSession | null {
    return this.selfSessionBest()?.session ?? null;
  }

  /** Whether this device may abort minting because the best self-group already SUFFICES: either it is
   * fully certified (strict), or this device cannot mint anyway (cert-only, no account key). A
   * seed-holder whose best self-group classifies self only via the own-leaf exemption (its own leaf
   * frozen certless in that roster) must NOT abort: it mints a certified replacement, the
   * strict-preference sort migrates every device onto it, and the degraded copy stays hidden. */
  private selfGroupSuffices(): boolean {
    const best = this.selfSessionBest();
    if (best === null) {
      return false;
    }
    if (best.strict || this.conv === null || this.conv.accountKeyHex().length === 0) {
      return true;
    }
    // A replacement mint is worthwhile ONLY when it would come out strict: a legacy label-only
    // credential (pre-cert sealed blobs restore this way) would mint another lenient-only group, and
    // the gate would see "still insufficient" forever, minting one more group per trigger. For that
    // device the degraded best is as good as it gets, so it suffices.
    return !(this.conv.credentialCertified?.() ?? false);
  }

  /** Whether the hidden self-group is open (and does not need a certified replacement). The app uses
   * this so only the designated device creates or replaces it. */
  hasSelfGroup(): boolean {
    return this.selfGroupSuffices();
  }

  /** The conversationId of the open hidden self-group (Note to Self rides it), or null when none is
   * open. Cryptographically grounded via isSelfConversation, so it never trusts a device-list cache. */
  selfConversationId(): string | null {
    const s = this.selfSession();
    return s === null ? null : this.convId(s.groupId);
  }

  /** Whether a SPECIFIC conversation id is one of our hidden own-devices self-groups. Unlike
   * selfConversationId (which returns only the single BEST self-group), this recognizes ANY loaded
   * self-group session, so a stale second self-group's id is still classified as self and kept out of
   * the channel list even when a different one is the primary. Cryptographic (isSelfConversation), so
   * it never trusts a device-list cache. */
  isSelfConversationId(conversationId: string): boolean {
    const entry = this.sessions.get(conversationId);
    return entry !== undefined && entry.session.isSelfConversation();
  }

  /** Whether a held conversation provably has NO reachable recipient (a certless non-own leaf and no
   * verified foreign device). Advisory only; a real peer conversation, even one whose peer never comes
   * online, is never flagged. False when the wasm lacks the accessor or the session is not held. */
  isUnlinkedConversationId(conversationId: string): boolean {
    const entry = this.sessions.get(conversationId);
    return entry !== undefined && entry.session.unlinked();
  }

  /** CLOSE one conversation for good, locally: drop the live session (cancelling any in-flight staged
   * commit), remove the group's MLS state from the wasm (an older wasm degrades to the plain leave),
   * and re-seal so the reconnect restore cannot rebuild it. The group is never notified; a frame that
   * still lands on a subscribed mailbox this session falls to the benign not-held drop in receive.
   * Strictly user-initiated (the caller owns the self-group guard and summary deletion). */
  async closeConversation(conversationId: string): Promise<void> {
    const gid = conversationId.startsWith('c-') ? conversationId.slice(2) : conversationId;
    // The wasm close runs FIRST and its refusal PROPAGATES: the guards (own-devices group, unsettled
    // pre-cert classification) must abort the whole close, with the caller falling back to
    // hide-and-record. The wasm is idempotent for unknown ids, so no catch is needed here.
    this.conv?.closeConversation?.(gid);
    this.leaveConversation(conversationId);
    await this.resealSelf();
  }

  /** Every conversation id the WASM currently holds (the ground truth for liveness, straight from the
   * sealed MLS state rather than the JS session map). Used by the connect-time dead-summary sweep: a
   * persisted channel summary whose id is not held here (and is not a recorded self-group) belongs to a
   * conversation this device was evicted from or lost, which can never deliver again. */
  heldConversationIds(): string[] {
    if (this.conv === null) {
      return [];
    }
    return this.conv.listConversations().map((gid) => this.convId(gid));
  }

  /** Ensure the hidden own-devices self-group is open and return its conversationId, so the app can
   * surface it as "Note to Self". Reuses an existing self-group (created by the designated device, or
   * joined from a sibling). Otherwise creates a SOLO one (just this device) so Note to Self works on a
   * single-device account; a sibling folds in later through the normal staged-add path, from which
   * point notes sync. Like createSelfGroup it is never given a channel summary or an 'established'
   * event, so the group stays out of the conversation list except as the Note-to-Self view. */
  async openSelfConversation(): Promise<string> {
    // Reuse the best self-group only when it suffices (strict, or this device cannot mint). A
    // seed-holder whose best copy is lenient-only mints a certified solo replacement instead; the
    // strict-preference sort then makes the new group canonical and the degraded copy stays hidden.
    if (this.selfGroupSuffices()) {
      const existing = this.selfConversationId();
      if (existing !== null) {
        return existing;
      }
    }
    const conv = this.requireConv();
    // Only a device holding the account key can anchor the own-devices self-group: isSelfConversation
    // verifies each member's certificate against our account key, so a cert-only device (one provisioned
    // by QR or six words, which holds a cert but not the account key) could neither recognize a self-group
    // nor have the solo one it creates recognized as such. Refuse rather than mint an unrecognized group
    // that openChannel would then mislabel as an UNKNOWN peer (and wrongly show the Add control on).
    if (conv.accountKeyHex().length === 0) {
      throw new Error('note to self is available on your account-key device');
    }
    const t = this.requireTransport();
    const session = GroupSession.createSelf(conv);
    const conversationId = this.convId(session.groupId);
    this.sessions.set(conversationId, { session, groupMailbox: session.mailbox() });
    t.subscribe(session.mailbox());
    await this.resealSelf(); // the self-group must survive reload (restored via listConversations; no summary)
    // The own-devices self-group is now a live E2E session: report the link secure (no channel summary /
    // 'established' event, so it stays hidden as a conversation).
    this.deps.pushEvent('connection', { state: 'secure' });
    return conversationId;
  }

  /** Publish our buddy list to the hidden self-group so our other devices converge (per-buddy
   * last-writer-wins). No-op when the self-group is not open yet: the change is saved locally and syncs
   * once the self-group forms. The buddy list NEVER rides any other conversation. */
  syncBuddies(): void {
    const session = this.selfSession();
    if (session !== null) {
      this.publishBuddiesFor(session);
    }
  }

  /** Publish our buddy list to ONE session, but ONLY if it is the self-group. The guard is the privacy
   * backstop: the contact graph must never be published to a roster a peer can read. Best-effort. */
  private publishBuddiesFor(session: GroupSession): void {
    const t = this.transport;
    if (t === null || this.loadBuddiesFrame === undefined || !session.isSelfConversation()) {
      return;
    }
    void this.loadBuddiesFrame()
      .then((frame) => {
        if (frame !== null && this.transport !== null) {
          this.transport.publish(session.sendControl(CONTROL_BUDDIES, 1, frame));
        }
      })
      .catch(() => {
        /* best-effort; a locked vault must not break the channel */
      });
  }

  /** Publish our buddy-GROUP list to our own devices over the hidden self-group (last-writer-wins). No-op
   * when the self-group is not open yet: the change is saved locally and syncs once it forms. Like the
   * buddy list, the group list NEVER rides any other conversation. */
  syncGroups(): void {
    const session = this.selfSession();
    if (session !== null) {
      this.publishGroupsFor(session);
    }
  }

  /** Publish our group list to ONE session, but ONLY if it is the self-group. Same privacy backstop as
   * publishBuddiesFor: your group names are part of the contact graph and must never reach a peer roster. */
  private publishGroupsFor(session: GroupSession): void {
    const t = this.transport;
    if (t === null || this.loadGroupsFrame === undefined || !session.isSelfConversation()) {
      return;
    }
    void this.loadGroupsFrame()
      .then((frame) => {
        if (frame !== null && this.transport !== null) {
          this.transport.publish(session.sendControl(CONTROL_GROUPS, 1, frame));
        }
      })
      .catch(() => {
        /* best-effort; a locked vault must not break the channel */
      });
  }

  /** Create the hidden self-group: an MLS group of ONLY our own devices, the private channel that syncs
   * our buddy list across them. Built like startConversation but never surfaced (no channel summary, no
   * 'established' event), so it stays out of the conversation list. The caller (the designated device)
   * invokes this only when no self-group exists. No-op with no targets. */
  async createSelfGroup(targets: readonly DeviceTarget[]): Promise<void> {
    const conv = this.requireConv();
    const t = this.requireTransport();
    if (targets.length === 0) {
      return; // a self-group needs at least one sibling
    }
    // There is AT MOST ONE SUFFICIENT self-group. The app's hasSelfGroup() pre-check happens BEFORE it
    // fetches the sibling key packages (a network round-trip), and Note to Self can open a solo
    // self-group inside that window; without this re-check we would mint a second self-group and the
    // two devices would sync over different groups (silently splitting the buddy list and notes). The
    // sibling folds into the existing group through the normal reconcile path instead. A lenient-only
    // best on a seed-holder does NOT abort: the certified replacement is exactly what this mint is for.
    if (this.selfGroupSuffices()) {
      return;
    }
    // BIRTH-gated in the wasm: every founding package must chain to OUR account, so a stale
    // pre-authorization package can never mint a poisoned self-group. PRE-FILTER the targets so one
    // bad package does not abort the whole multi-device mint (a reusable last-resort package is never
    // consumed, so an abort loop would never drain it): healthy siblings found now, the dropped
    // device folds in later via the per-device staged-add heal once its directory rows are replaced.
    // The wasm gate stays as the fail-closed backstop; peer conversations keep the ungated TOFU create.
    const eligible = targets.filter((d) => conv.keyPackageSelfEligible?.(d.keyPackage) ?? true);
    if (eligible.length === 0) {
      throw new Error('no certified sibling package is available yet');
    }
    const { welcome, session } = GroupSession.createSelfGroup(conv, eligible.map((d) => d.keyPackage));
    const conversationId = this.convId(session.groupId);
    if (this.sessions.has(conversationId)) {
      return; // already holding this group
    }
    this.sessions.set(conversationId, { session, groupMailbox: session.mailbox() });
    t.subscribe(session.mailbox());
    for (const d of eligible) {
      // Only the FOUNDING members get the Welcome: a filtered-out device is not in it and could not
      // decrypt it (an undecodable frame would just sit poisoning its bootstrap mailbox).
      t.publish({ messageId: randomBytes(16), routingKey: d.deviceKey, payload: welcome, ttlSeconds: SEVEN_DAYS });
    }
    await this.resealSelf(); // the self-group must survive reload (restored via listConversations; no summary)
    this.publishIdentityFor(session); // sync our icon/profile/away privately too (own devices; harmless)
    this.publishBuddiesFor(session);
    this.publishGroupsFor(session);
    // The own-devices self-group is now a live E2E session on THIS (creating) device too: report the link
    // secure, matching openSelfConversation. Without this the designated creator stayed on SECURING until a
    // later reconnect saw the restored session, while the joining sibling flipped secure via its Welcome.
    this.deps.pushEvent('connection', { state: 'secure' });
  }

  /** Publish a file-transfer signal (SDP/ICE) to the group as a CONTROL_FILE frame. The signal is E2E;
   * the file bytes go peer-to-peer and never touch the server. No-op when no group is open. */
  sendFileSignal(conversationId: string, payload: Uint8Array): void {
    const entry = this.sessions.get(conversationId);
    const t = this.transport;
    if (entry === undefined || t === null) {
      return;
    }
    t.publish(entry.session.sendControl(CONTROL_FILE, 1, payload));
  }

  /** Publish a call signal (SDP/ICE) to one conversation as a CONTROL_CALL frame. The signal is E2E; the
   * audio/video media goes peer-to-peer and never touches the server. No-op when that conversation is
   * not open. */
  sendCallSignal(conversationId: string, payload: Uint8Array): void {
    const entry = this.sessions.get(conversationId);
    const t = this.transport;
    if (entry === undefined || t === null) {
      return;
    }
    t.publish(entry.session.sendControl(CONTROL_CALL, 1, payload));
  }

  /** Route an inbound identity control frame. Identity is COSMETIC and authenticated only by group
   * membership: accept it solely from a current group member that is not this device, and never as
   * proof of who the peer is (the Get-Info panel shows the fingerprint warning). A member could still
   * claim another member's key, so this is best-effort attribution, disclosed in honest-limits. */
  private onControlFrame(conversationId: string, controlType: number, payload: Uint8Array, fromOwnAccount: boolean): void {
    const entry = this.sessions.get(conversationId);
    if (entry === undefined) {
      return;
    }
    if (controlType === CONTROL_FILE) {
      // A file-transfer signal (SDP/ICE): hand it to the file-transfer module, tagged with the
      // conversation it arrived in. The file bytes go peer-to-peer and never reach this layer.
      this.onFileSignal?.(conversationId, payload);
      return;
    }
    if (controlType === CONTROL_CALL) {
      // A call signal (SDP/ICE): hand it to the call module, tagged with its conversation. The
      // audio/video media goes peer-to-peer and never reaches this layer.
      this.onCallSignal?.(conversationId, payload);
      return;
    }
    if (controlType === CONTROL_BUDDIES) {
      // The buddy list (our contact graph). It rides ONLY the hidden self-group, so adopt it solely when
      // its authenticated sender is one of our OWN devices (a peer cannot forge fromOwnAccount). Anything
      // else is dropped: the contact graph is never stored as a peer's data.
      if (fromOwnAccount) {
        this.onBuddies?.(payload);
      }
      return;
    }
    if (controlType === CONTROL_GROUPS) {
      // The buddy-group list is part of the same contact graph and carries the identical own-devices-only
      // guarantee: adopt solely from our OWN devices, drop everything else.
      if (fromOwnAccount) {
        this.onGroups?.(payload);
      }
      return;
    }
    // An identity control frame (buddy icon / profile / away). If its authenticated sender is one of OUR
    // OWN devices (a sibling), adopt it as an own-identity update so the icon, profile, and away config
    // stay consistent across all our devices (last-change-wins). A peer cannot forge this (fromOwnAccount
    // is crypto-authenticated).
    if (fromOwnAccount) {
      this.onSiblingIdentity?.(controlType, payload);
      return;
    }
    // From a peer: store their buddy icon, profile, or AWAY message as their peer identity (the away text
    // becomes the dim buddy-list subtitle while they are away). Only their OWN away CONFIG (enabled/saved
    // library) is adopted by their own devices; here we keep just the message text a peer chose to share.
    // Any other control sub-type from a peer is dropped.
    if (controlType !== CONTROL_BUDDY_ICON && controlType !== CONTROL_PROFILE && controlType !== CONTROL_AWAY) {
      return;
    }
    if (this.persistPeerIdentity === undefined) {
      return;
    }
    let key: string;
    try {
      const obj = JSON.parse(new TextDecoder().decode(payload)) as { k?: unknown };
      key = typeof obj.k === 'string' ? obj.k : '';
    } catch {
      return; // malformed control payload: drop
    }
    if (key === '' || key === this.bootstrapKey || !entry.session.roster().includes(key)) {
      return;
    }
    void this.persistPeerIdentity(conversationId, key, controlType, payload).catch(() => {
      /* best-effort; a locked vault must not break the receive loop */
    });
  }

  /** If the user is away, auto-reply to an inbound message with their away text as an ordinary E2E
   * message. The reply is jittered so a network observer cannot read precise processing time from it,
   * and rate-limited per conversation by the controller's cooldown. HONEST LIMIT: sending any reply at
   * all reveals to a network observer that a device was online to handle the message (honest-limits). */
  private maybeAwayReply(conversationId: string): void {
    const replyEntry = this.sessions.get(conversationId);
    if (this.awayReply === undefined || replyEntry === undefined) {
      return;
    }
    void this.awayReply(conversationId, this.peerLabel(replyEntry.session)) // %n = the buddy we reply to
      .then((text) => {
        if (text === null || !this.sessions.has(conversationId) || this.transport === null) {
          return;
        }
        const delay = 500 + Math.floor(Math.random() * 4500); // 0.5s to 5s jitter
        this.deps.schedule(delay, () => {
          const entry = this.sessions.get(conversationId);
          const t = this.transport;
          if (entry === undefined || t === null) {
            return;
          }
          const lifetime: Lifetime = { kind: 'duration', seconds: 86400 };
          const env = entry.session.send(enc.encode(text), lifetime);
          t.publish(env);
          void this.persistMessage(
            { messageId: bytesToHex(env.messageId), conversationId, direction: 'out', lifetime },
            enc.encode(text),
          )
            .then(() => {
              // Show it on OUR side too. The reply is stored as our own outgoing message, but without
              // this the open conversation never repaints, so the away user only ever saw their auto
              // reply by reopening the chat: it looked like it went only to the other person. A
              // distinct event (not 'inbound-message') because our own reply must never notify us.
              this.deps.pushEvent('outbound-appended', { conversationId });
            })
            .catch(() => {
              /* best-effort persistence of our own auto-reply */
            });
        });
      })
      .catch(() => {
        /* best-effort; a locked vault must not break the receive loop */
      });
  }

  /** Open the gateway, restore/create our authorized identity, and subscribe to our bootstrap mailbox
   * (and the group mailbox if a group already exists from a previous session). */
  async connectGateway(url: string): Promise<{ ok: boolean; selfContact: string }> {
    const restored = this.persistence !== undefined ? await this.persistence.loadSelf() : null;
    // The seed is present only on the registering/seed-holder device. A device that joins by
    // provisioning gets '' here, so makeConversation builds an UNAUTHORIZED identity that later adopts
    // a certificate from the seed-holder (model b); it never holds the account seed.
    const seedHex = this.persistence !== undefined ? await this.persistence.recoverySeedHex() : '';
    const conv = restored ?? this.deps.makeConversation('me', seedHex);
    this.conv = conv;
    this.bootstrapKey = conv.signaturePublicKeyHex();
    if (restored === null && this.persistence !== undefined) {
      await this.persistence.saveSelf(conv);
    }
    // Supersede any previous transport (AIM21 auto-reconnect dials repeatedly mid-session): close it,
    // fail its in-flight receipt waiters (a replaced socket can never confirm them), and drop the cached
    // provisioning machine (it closes over the old socket's publish/subscribe; a new pairing rebuilds
    // against the live one). The generation stamp makes every superseded socket's events dead on arrival —
    // without it a stale onClose would flip a healthy session to OFFLINE, and a leaked still-subscribed
    // socket would double-deliver every envelope into this channel.
    const gen = ++this.connectGen;
    for (const waiter of [...this.pendingReceipts.values()]) {
      waiter.fail(new Error('connection replaced before the gateway confirmed the publish'));
    }
    // Tear down staged-op backstops armed on the PRIOR connection before the restore loop re-arms below.
    // Left in place, a stale ADD_CONFIRM_MS timer (its 8s window easily straddles the 3s auto-reconnect
    // backoff) would fire on this fresh connection, delete the freshly re-armed pendingOps entry, merge
    // (zombie-confirm) a discarded commit, emit a false roster-changed, and disarm the 24s restore
    // backstop, defeating exactly the crash-recovery guarantee Batch B adds. Cancel every handle and clear
    // the election guard; the restore re-arm re-populates whatever is genuinely still pending.
    for (const op of this.pendingOps.values()) {
      this.deps.cancel(op.handle);
    }
    this.pendingOps.clear();
    this.failoverScheduled.clear();
    // Lift any paced-but-unsent publishes off the old transport BEFORE closing it, so a sibling Welcome (or
    // any frame) that was still queued when the socket dropped is re-issued on the fresh socket below,
    // instead of being lost (which would leave the new device stranded on SECURING).
    const pendingPublishes = this.transport?.takePending() ?? [];
    try {
      this.transport?.close();
    } catch {
      /* already dead */
    }
    // A shown-QR add-a-device machine (Fix 3) is PRESERVED across the reconnect: its deps resolve the
    // transport at call time, so it rebinds to the new socket and its one-shot ephemeral survives, letting
    // a grant that lands after the reconnect still adopt. Every other role is dropped and rebuilt.
    if (this.provisioning === null || !this.provisioning.qrShowLive()) {
      this.provisioning = null;
    }
    // Load the closed set BEFORE creating the socket: it needs neither the transport nor the wasm, and
    // awaiting it here keeps the span from transport creation through the restore loop, subscribes,
    // and pending re-publishes fully synchronous (the R8 sweep-race analysis relies on no macrotask
    // boundary in that span; the old socket is already generation-dead during this await).
    const closed = (await this.deps.loadClosedIds?.()) ?? new Set<string>();
    this.transport = this.deps.connect(url, this.handlers(gen));
    // Every subscribe on this connection carries a SECRET-KEYED per-mailbox delivery-cursor tag, so the
    // bus holds each blob until THIS device acks it and redelivers un-acked blobs on re-subscribe (the
    // contested-crash fix). The tag is derived per subject from a device secret (crypto mailboxTag), so
    // the gateway cannot link this device's mailboxes from its registry. `conv` (above) is the live session.
    this.transport.setConsumerIdResolver((subject) => conv.mailboxTag(subject));
    this.transport.subscribe(this.bootstrapKey);
    this.provisioning?.resubscribeLive(); // re-subscribe a preserved QR machine's reply mailbox on the new transport
    // Restore EVERY conversation from a previous session so all are live for receive + self-heal. Clear
    // the map first: a reconnect must not carry stale entries for groups the (possibly fresh) restored
    // wasm no longer holds — a lingering entry would both shield a dead summary from the connect-time
    // sweep and make isSelfConversationId throw against a missing wasm slot. Add each fresh entry BEFORE
    // subscribing to its mailbox, so an inbound message never finds an empty map.
    this.sessions.clear();
    // A conversation the user CLOSED must never come back: a parallel tab's reseal (or an old-wasm
    // close that could not drop the group) can leave the group in the restored state, so re-close it
    // here instead of rebuilding a session. A closed id that NOW classifies self restores normally
    // (the closed set never outranks live self classification; a pre-cert mistaken close recovers).
    let reclosed = false;
    for (const groupId of conv.listConversations()) {
      if (closed.has(this.convId(groupId)) && conv.isSelfConversation(groupId) !== true) {
        try {
          conv.closeConversation?.(groupId);
          reclosed = true;
        } catch {
          /* the wasm refused (e.g. it now classifies protective); the session is not rebuilt either way */
        }
        continue;
      }
      const session = new GroupSession(conv, groupId);
      const groupMailbox = session.mailbox();
      this.sessions.set(this.convId(groupId), { session, groupMailbox });
      this.transport.subscribe(groupMailbox);
    }
    if (reclosed) {
      // Converge the durable blob to the closed state now (a crash between close and reseal, or a
      // parallel tab's reseal, left it carrying the closed group's secrets). Fire-and-forget: no new
      // await may widen the pre-subscribe frame-buffering window.
      void this.resealSelf().catch(() => {
        /* best-effort; the next reseal point retries */
      });
    }
    // Re-issue any publishes stranded in the old transport's paced queue when it dropped (see takePending),
    // now that the fresh socket and all mailbox subscriptions are live.
    for (const env of pendingPublishes) {
      this.transport.publish(env);
    }
    // Re-arm any staged commit that survived the reload (the sealed blob persists its wire bytes): a
    // committer that crashed between stage and confirm used to lose its pending, and once a peer had
    // merged the published commit, self-heal re-staged a DISTINCT commit whose backstop then FORKED this
    // device onto a private epoch. Instead: re-publish the exact original commit (and, for an Add, the
    // added device's Welcome) on the epoch-N mailbox, and mark pendingOps + re-arm the confirm backstop.
    // pendingOps set here makes reconcile bail and the crypto layer reject a second stage (double guard),
    // and the normal arbitration still applies: our own echo confirms; a rival commit that won aborts and
    // adopts inside receive. The post-restore backstop is LONGER than the steady-state one to give a rival
    // commit that is STILL held for us time to redeliver and abort our restored pending first. The bus
    // holds every blob until THIS device acks it (we ack only after durable processing) and re-flushes the
    // un-acked backlog on this very re-subscribe, so a rival that won pre-crash IS redelivered here and the
    // contested crash no longer forks - bounded by the bus retention (24h TTL / 1024 blobs per mailbox).
    for (const [conversationId, entry] of this.sessions) {
      const kind = entry.session.pendingKind();
      if (kind === null) {
        continue;
      }
      const target = entry.session.pendingTarget();
      const commit = entry.session.pendingCommit();
      if (commit.length > 0) {
        this.transport.publish({ messageId: randomBytes(16), routingKey: entry.groupMailbox, payload: commit, ttlSeconds: SEVEN_DAYS });
      }
      if (kind === 'add' && target !== '') {
        const welcome = entry.session.pendingWelcome();
        if (welcome.length > 0) {
          // Re-deliver the added device's Welcome too: a crash BEFORE the original publish would otherwise
          // confirm the roster while the added device never receives its (unreproducible) invitation. The
          // receive side dedups a resent Welcome, so a duplicate is harmless.
          this.transport.publish({ messageId: randomBytes(16), routingKey: target, payload: welcome, ttlSeconds: SEVEN_DAYS });
        }
      }
      const handle = this.deps.schedule(RESTORE_CONFIRM_MS, () => {
        if (gen !== this.connectGen || !this.pendingOps.has(conversationId)) {
          return; // a newer connection superseded this backstop, or it was already resolved
        }
        this.pendingOps.delete(conversationId);
        if (entry.session.pendingKind() === null) {
          return; // an echo or a competing commit already resolved the staged op: nothing to confirm
        }
        try {
          if (kind === 'add') {
            entry.session.confirmAdd();
          } else {
            entry.session.confirmRemove();
          }
        } catch {
          return;
        }
        void this.onMembershipAdvanced(conversationId, kind === 'add' ? [target] : [], kind === 'remove' ? [target] : []);
      });
      this.pendingOps.set(conversationId, { kind, handle });
    }
    // 'secure' once ANY end-to-end session is restored (the hidden own-devices self-group counts): the
    // account's E2E context is live, so the buddy list reads SECURE LINK rather than sitting forever on
    // the transitional SECURING. Only a brand-new device with no session yet reports the bare transport up.
    this.deps.pushEvent('connection', { state: this.sessions.size > 0 ? 'secure' : 'live' });
    return { ok: true, selfContact: formatContact(this.bootstrapKey) };
  }

  /** Start a conversation: create the group adding all the given devices (the peer's plus our own
   * siblings), subscribe to the group mailbox, and deliver the Welcome to each device's bootstrap
   * mailbox. Returns the opened conversation view. */
  async startConversation(targets: readonly DeviceTarget[]): Promise<TransmitModel> {
    const conv = this.requireConv();
    const t = this.requireTransport();
    if (targets.length === 0) {
      throw new Error('a conversation needs at least one other device');
    }
    const { welcome, session } = GroupSession.create(conv, targets.map((d) => d.keyPackage));
    const conversationId = this.convId(session.groupId);
    const groupMailbox = session.mailbox();
    this.sessions.set(conversationId, { session, groupMailbox });
    t.subscribe(groupMailbox);
    // Deliver the single Welcome to every added device's bootstrap mailbox.
    for (const d of targets) {
      t.publish({ messageId: randomBytes(16), routingKey: d.deviceKey, payload: welcome, ttlSeconds: SEVEN_DAYS });
    }
    await this.persist(conversationId, session);
    await this.resealSelf(); // the new conversation must survive reload (the durable blob holds all groups)
    this.publishIdentityFor(session); // share our buddy icon + profile with the group we just created
    this.deps.pushEvent('connection', { state: 'secure' });
    return {
      secure: true,
      peer: this.peerLabel(session),
      fingerprint: fingerprintOf(this.bootstrapKey),
      log: [systemEntry('group conversation open · all your devices receive')],
      compose: '',
      conversationId,
    };
  }

  /** Send a plaintext message to one conversation and persist our copy (armed immediately). The
   * lifetime rides INSIDE the encrypted payload (recipient-enforced); when the caller picks none we
   * keep the long-standing 24h default. */
  async sendMessage(conversationId: string, text: string, lifetime: Lifetime = { kind: 'duration', seconds: 86400 }): Promise<void> {
    const entry = this.sessions.get(conversationId);
    if (entry === undefined) {
      throw new Error('this conversation is not open yet');
    }
    const env = entry.session.send(enc.encode(text), lifetime);
    this.requireTransport().publish(env);
    await this.persistMessage(
      { messageId: bytesToHex(env.messageId), conversationId, direction: 'out', lifetime },
      enc.encode(text),
    );
  }

  /** Publish a cooperative revoke for one of OUR OWN messages to one conversation. Every well-behaved
   * member device (peers and our own siblings alike) crypto-erases its stored copy of the target. The
   * caller (controller) has already validated the target is our own until-revoked record. Resolves
   * only when the gateway's publish RECEIPT for the revoke frame arrives — hand-off to the socket is
   * not delivery, so the caller gates its own local erase on this promise. Rejects, with the frame
   * possibly never sent, when the socket is already dead, the connection closes before the receipt,
   * or the receipt does not arrive within REVOKE_RECEIPT_MS; the caller then keeps its copy. */
  async revokeMessage(conversationId: string, targetMessageId: string): Promise<void> {
    const entry = this.sessions.get(conversationId);
    if (entry === undefined) {
      throw new Error('this conversation is not open yet');
    }
    const t = this.requireTransport();
    const env = entry.session.sendRevoke(targetMessageId);
    const idHex = bytesToHex(env.messageId);
    await new Promise<void>((resolve, reject) => {
      const handle = this.deps.schedule(REVOKE_RECEIPT_MS, () => {
        this.pendingReceipts.get(idHex)?.fail(new Error('the gateway did not confirm the revoke'));
      });
      this.pendingReceipts.set(idHex, {
        confirm: () => {
          this.deps.cancel(handle);
          this.pendingReceipts.delete(idHex);
          resolve();
        },
        fail: (e) => {
          this.deps.cancel(handle);
          this.pendingReceipts.delete(idHex);
          reject(e);
        },
      });
      try {
        t.publish(env);
      } catch (e) {
        this.pendingReceipts.get(idHex)?.fail(e instanceof Error ? e : new Error(errMsg(e)));
      }
    });
  }

  /** SEED-HOLDER: open a short add-a-device window for this account, publishing a Challenge to the
   * account rendezvous mailbox. The user then compares six words out of band and calls confirm. */
  async openProvisioningWindow(usernameHash: string): Promise<void> {
    const provMailbox = await deriveProvMailbox(usernameHash);
    this.ensureProvisioning().openWindow(provMailbox);
  }

  /** NEW DEVICE: begin being added to this account; wait for the seed-holder's Challenge and show the
   * six words for the user to compare. This device must be UNAUTHORIZED (no account seed) so it adopts
   * the certificate the seed-holder grants (model b). */
  async joinDevice(usernameHash: string): Promise<void> {
    const provMailbox = await deriveProvMailbox(usernameHash);
    this.ensureProvisioning().startJoin(provMailbox);
  }

  /** SEED-HOLDER: the user confirmed the six words match; authorize the pending device and grant it. */
  confirmProvisioning(): void {
    this.provisioning?.confirm();
  }

  /** SEED-HOLDER: dismiss the add-a-device window without authorizing. Also cancels a shown-QR (Fix 3):
   * prov-cancel is the only showqr exit and signOutNewDevice does not reload the page. */
  closeProvisioning(): void {
    this.provisioning?.closeWindow();
    this.provisioning?.cancelQrShow();
  }

  /** NEW DEVICE (QR): generate an ephemeral key, listen on the derived reply mailbox, and return the QR
   * payload to display. The existing device scans it and seals a certificate to the ephemeral key. */
  startQrPairing(): Promise<string> {
    return this.ensureProvisioning().startQrShow();
  }

  /** SEED-HOLDER (scan): authorize the scanned device and seal the grant to its ephemeral key. */
  grantScannedDevice(qrPayload: string): Promise<void> {
    return this.ensureProvisioning().grantScanned(qrPayload);
  }

  /** P5: add one already-enrolled device to one conversation (an online sibling admits it). The commit
   * goes to the members still on the current mailbox; the Welcome goes to the device's bootstrap mailbox.
   * That conversation's epoch rotated on commit, so re-subscribe to its new mailbox and re-seal. */
  addDevice(conversationId: string, target: DeviceTarget): Promise<void> {
    const entry = this.sessions.get(conversationId);
    if (entry === undefined) {
      return Promise.reject(new Error('no such conversation'));
    }
    const t = this.requireTransport();
    const oldMailbox = entry.groupMailbox;
    const { commit, welcome } = entry.session.addDevice(target.keyPackage);
    t.publish({ messageId: randomBytes(16), routingKey: oldMailbox, payload: commit, ttlSeconds: SEVEN_DAYS });
    t.publish({ messageId: randomBytes(16), routingKey: target.deviceKey, payload: welcome, ttlSeconds: SEVEN_DAYS });
    entry.groupMailbox = entry.session.mailbox();
    t.subscribe(entry.groupMailbox);
    void this.resealSelf();
    this.deps.pushEvent('roster-changed', { conversationId, added: [target.deviceKey], removed: [] });
    return Promise.resolve();
  }

  /** Self-heal (ADR-022, the H1 fix): admit any of THIS account's devices that are authorized but not
   * yet in the open conversation, so every signed-in device receives going forward. Idempotent and
   * concurrency-safe:
   *   - Roster gate: a device already in the group (or this device) is skipped, never re-added.
   *   - Designated adder: only the lowest-keyed of our devices currently in the group issues the add;
   *     the others fail over after a position-ranked delay if the designate is offline. The staged add
   *     (stageAddDevice) resolves any residual race with no fork (the loser aborts and retries).
   *   - Claim-or-defer: a key package is claimed only for a genuinely missing device; if none is
   *     claimable we defer to the next trigger rather than add partially.
   * Forward secrecy holds: a self-healed device reads from when it joins onward, never the history. The
   * authorization gate at every honest member still vets the add (a forged/unknown/revoked device is
   * rejected); self-heal is orchestration only and grants no new trust. No-op with no open conversation.
   * `candidates` are this account's devices with a claimed single-use key package (the app supplies them
   * as data; a device without a claimable package is simply absent, so it defers, never adds partially).
   * Stages ONE add per call; the roster-changed it fires drives the app to re-run for the next one. */
  reconcileSiblings(
    ownDeviceKeys: readonly string[],
    candidates: readonly DeviceTarget[],
  ): Promise<void> {
    // Heal EVERY open conversation independently (each can stage its own add concurrently).
    for (const conversationId of [...this.sessions.keys()]) {
      this.reconcileOne(conversationId, ownDeviceKeys, candidates, false);
    }
    return Promise.resolve();
  }

  /** Heal a just-authorized new device into the hidden own-devices self-group. Reachable from the
   * seed-holder's post-add poll even when this device is NOT the designated adder: the normal reconcile
   * pre-check (hasMissingSiblings) is adder-scoped and would gate it off, so a lower-keyed device that
   * never receives the device-added event would leave the new (cert-only) device stuck on SECURING. This
   * keeps the RACE-FREE election: if the lowest-keyed device is online and triggered it stages immediately
   * and we defer; otherwise our position-ranked failover takes over. Touches ONLY self-conversations (peer
   * conversations heal via the roster-changed cascade once the device is in the self-group). */
  reconcileSelf(ownDeviceKeys: readonly string[], candidates: readonly DeviceTarget[]): Promise<void> {
    for (const [conversationId, entry] of this.sessions) {
      if (entry.session.isSelfConversation()) {
        this.reconcileOne(conversationId, ownDeviceKeys, candidates, false);
      }
    }
    return Promise.resolve();
  }

  /** Where a device stands relative to the hidden self-group: 'member' (already in it), 'pending' (an add
   * or remove is in flight OR a failover is armed for that group), 'absent' (a self-group exists but the
   * device is not in it and no add is under way), or 'none' (no self-group yet). Lets the seed-holder's
   * post-add poll settle precisely on membership and skip claiming key packages while an add is already
   * under way. Non-adder-scoped by design. */
  selfSiblingState(deviceKey: string): 'member' | 'pending' | 'absent' | 'none' {
    let sawSelf = false;
    let pending = false;
    for (const [conversationId, entry] of this.sessions) {
      if (!entry.session.isSelfConversation()) {
        continue;
      }
      sawSelf = true;
      if (new Set(entry.session.roster()).has(deviceKey)) {
        return 'member';
      }
      if (this.pendingOps.has(conversationId) || this.failoverScheduled.has(conversationId)) {
        pending = true; // a staged add or an armed failover is already working this group: do not re-claim
      }
    }
    if (!sawSelf) {
      return 'none';
    }
    return pending ? 'pending' : 'absent';
  }

  /** P6 durable forward-secure exclusion: remove any REVOKED device that is still a member of one of our
   * open conversations, so a device revoked while we were offline is re-keyed out on our next sync. The
   * mirror of reconcileSiblings for removals. `revokedKeys` are the account's revoked device keys (the
   * app supplies them from listDevices); the removal targets ONLY a key that is BOTH a current roster
   * member AND on that revoked list, so it can never touch a re-added device (fresh key, not on the list)
   * or a peer. Stages ONE removal per conversation; the roster-changed it fires re-runs for the next. */
  reconcileRemovals(ownDeviceKeys: readonly string[], revokedKeys: readonly string[]): Promise<void> {
    for (const conversationId of [...this.sessions.keys()]) {
      this.reconcileRemovalOne(conversationId, ownDeviceKeys, revokedKeys, false);
    }
    return Promise.resolve();
  }

  private reconcileRemovalOne(
    conversationId: string,
    ownDeviceKeys: readonly string[],
    revokedKeys: readonly string[],
    forced: boolean,
  ): void {
    const entry = this.sessions.get(conversationId);
    const t = this.transport;
    if (entry === undefined || t === null || this.pendingOps.has(conversationId)) {
      return; // gone, or a commit (add or remove) is already in flight in this conversation
    }
    const roster = new Set(entry.session.roster());
    const revokedSet = new Set(revokedKeys);
    // Target ONLY a current roster member whose key is EXACTLY on the account's revoked list, never our
    // own key. This exact-match is the sole guard against removing a re-added device or being weaponized.
    const targets = [...roster].filter((k) => revokedSet.has(k) && k !== this.bootstrapKey);
    if (targets.length === 0) {
      return; // idempotent no-op: nothing revoked is still present
    }
    if (!forced && !this.isDesignatedAdder(ownDeviceKeys, roster)) {
      // Defer to the lowest-keyed of our devices in this group; fail over after a position-ranked delay if
      // it is offline. The staged remove resolves any residual race with no fork.
      const ourInGroup = this.ourDevicesInGroup(ownDeviceKeys, roster);
      const rank = Math.max(1, ourInGroup.indexOf(this.bootstrapKey));
      const delay = ADD_FAILOVER_MS * rank + Math.floor(Math.random() * RECONCILE_JITTER_MS);
      this.deps.schedule(delay, () => {
        this.reconcileRemovalOne(conversationId, ownDeviceKeys, revokedKeys, true);
      });
      return;
    }
    void this.stageRemoveSibling(conversationId, entry, t, targets[0]!);
  }

  /** Stage one revoked-device removal: build the Remove commit without merging, PERSIST it, then publish
   * it to the group and arm a confirm backstop. Confirmation normally arrives as our own commit echoed
   * back (receive confirms and advances the epoch); a competing commit that wins auto-aborts it inside
   * receive. Persist-BEFORE-publish: a crash on either side of the publish then reloads with the staged
   * commit intact (re-published by the restore re-arm), instead of losing it and re-staging a distinct
   * commit that forks this device once a peer merged the first one. */
  private async stageRemoveSibling(conversationId: string, entry: SessionEntry, t: Transport, target: string): Promise<void> {
    const oldMailbox = entry.groupMailbox;
    const armedGen = this.connectGen;
    let commit: Uint8Array;
    try {
      commit = entry.session.stageRemoveDevice(target);
    } catch {
      return; // the crypto layer already has a commit in flight for this conversation: let it complete
    }
    await this.resealSelf(); // durable BEFORE the wire sees it (best-effort: a locked vault degrades, not blocks)
    // The await opened a window (see stageAddSibling): bail unless our exact staged Remove is still in
    // flight and this connection is still current, so we never publish a dead commit or arm a phantom backstop.
    if (this.connectGen !== armedGen || !bytesEqual(entry.session.pendingCommit(), commit)) {
      return;
    }
    t.publish({ messageId: randomBytes(16), routingKey: oldMailbox, payload: commit, ttlSeconds: SEVEN_DAYS });
    const handle = this.deps.schedule(ADD_CONFIRM_MS, () => {
      if (this.connectGen !== armedGen || !this.pendingOps.has(conversationId)) {
        return; // a reconnect superseded this backstop, or it was already resolved
      }
      this.pendingOps.delete(conversationId);
      if (entry.session.pendingKind() === null) {
        return; // an echo or a competing commit already resolved the remove: nothing to confirm or announce
      }
      try {
        entry.session.confirmRemove();
      } catch {
        return;
      }
      void this.onMembershipAdvanced(conversationId, [], [target]);
    });
    this.pendingOps.set(conversationId, { kind: 'remove', handle });
  }

  private reconcileOne(
    conversationId: string,
    ownDeviceKeys: readonly string[],
    candidates: readonly DeviceTarget[],
    forced: boolean,
  ): void {
    this.knownOwnKeys = new Set(ownDeviceKeys); // remember our own devices for the identity re-publish gate
    const entry = this.sessions.get(conversationId);
    const t = this.transport;
    if (entry === undefined || t === null || this.pendingOps.has(conversationId)) {
      return; // gone, or an add is already in flight in this conversation (it re-runs on resolve)
    }
    const roster = new Set(entry.session.roster());
    const ownSet = new Set(ownDeviceKeys);
    // A candidate is added only if it is one of OUR currently-authorized (non-revoked) devices that is
    // not already in this group. Intersecting with ownDeviceKeys guards a stray or stale candidate.
    const missing = candidates.filter(
      (c) => ownSet.has(c.deviceKey) && !roster.has(c.deviceKey) && c.deviceKey !== this.bootstrapKey,
    );
    if (missing.length === 0) {
      return;
    }
    if (!forced && !this.isDesignatedAdder(ownDeviceKeys, roster)) {
      // Defer to the lowest-keyed of our devices in this group; fail over to us after a position-ranked
      // delay if it is offline. The staged add resolves any residual race with no fork. One armed failover
      // per conversation: a repeated trigger (the seed-holder's post-add poll) must not stack duplicates.
      if (this.failoverScheduled.has(conversationId)) {
        return;
      }
      const ourInGroup = this.ourDevicesInGroup(ownDeviceKeys, roster);
      const rank = Math.max(1, ourInGroup.indexOf(this.bootstrapKey));
      const delay = ADD_FAILOVER_MS * rank + Math.floor(Math.random() * RECONCILE_JITTER_MS);
      this.failoverScheduled.add(conversationId);
      this.deps.schedule(delay, () => {
        this.failoverScheduled.delete(conversationId);
        this.reconcileOne(conversationId, ownDeviceKeys, candidates, true);
      });
      return;
    }
    void this.stageAddSibling(conversationId, entry, t, missing[0]!);
  }

  /** Cheap pre-check (no key-package claim): is there a sibling this device should add to ANY open
   * conversation right now? Lets the app skip claiming key packages on a peer-only roster change. True
   * only where we are the designated adder AND one of our authorized devices is missing from that group. */
  hasMissingSiblings(ownDeviceKeys: readonly string[]): boolean {
    for (const entry of this.sessions.values()) {
      const roster = new Set(entry.session.roster());
      if (
        this.isDesignatedAdder(ownDeviceKeys, roster) &&
        ownDeviceKeys.some((k) => !roster.has(k) && k !== this.bootstrapKey)
      ) {
        return true;
      }
    }
    return false;
  }

  /** Our devices currently in the group, lowest signature key first (includes this device). */
  private ourDevicesInGroup(ownDeviceKeys: readonly string[], roster: ReadonlySet<string>): string[] {
    return [...new Set([this.bootstrapKey, ...ownDeviceKeys.filter((k) => roster.has(k))])].sort();
  }

  /** True when this device is the lowest-keyed of our devices in the group (the one that issues adds). */
  private isDesignatedAdder(ownDeviceKeys: readonly string[], roster: ReadonlySet<string>): boolean {
    return this.ourDevicesInGroup(ownDeviceKeys, roster)[0] === this.bootstrapKey;
  }

  /** Stage one sibling add: build the commit without merging, publish it to the group and the Welcome to
   * the new device, and arm a confirm backstop. Confirmation normally arrives as our own commit echoed
   * back (onGroupMessage -> receive confirms and advances the epoch). */
  private async stageAddSibling(conversationId: string, entry: SessionEntry, t: Transport, target: DeviceTarget): Promise<void> {
    const oldMailbox = entry.groupMailbox;
    const armedGen = this.connectGen;
    let staged;
    try {
      staged = entry.session.stageAddDevice(target.keyPackage);
    } catch (e) {
      const msg = errMsg(e);
      if (msg === 'an add is already in flight') {
        return; // the crypto layer already has an add in flight for this conversation: let it complete
      }
      // The adder-side gate rejected the package (certless, forged, unknown account, or below the
      // epoch floor). Deterministic for THIS package: surface it so the heal can stop claiming a
      // fresh package per tick for a device whose directory can only serve rejected ones.
      console.warn('sibling add rejected:', msg);
      this.deps.pushEvent('sibling-add-rejected', { deviceKey: target.deviceKey, detail: msg });
      return;
    }
    // Persist-BEFORE-publish (see stageRemoveSibling): the sealed blob now carries the staged commit, so a
    // crash between here and confirmation resumes the SAME commit on reload instead of forking.
    await this.resealSelf();
    // The await opened a window: a rival commit could have arrived and ABORTED this staged add (receive's
    // competing-commit path), after which reconcile may have re-staged a DIFFERENT one. Publishing now
    // would push a dead commit + a doomed Welcome and arm a phantom backstop. Bail unless our exact staged
    // commit is still the one in flight, and unless this connection is still current.
    if (this.connectGen !== armedGen || !bytesEqual(entry.session.pendingCommit(), staged.commit)) {
      return;
    }
    t.publish({ messageId: randomBytes(16), routingKey: oldMailbox, payload: staged.commit, ttlSeconds: SEVEN_DAYS });
    t.publish({ messageId: randomBytes(16), routingKey: target.deviceKey, payload: staged.welcome, ttlSeconds: SEVEN_DAYS });
    // Backstop: if no echo and no competing commit arrive, confirm the still-pending add (idempotent)
    // and advance. A competing commit that wins is auto-aborted inside receive and clears this
    // conversation's pendingAdd via onGroupMessage before this fires, so this only runs for an
    // uncontested add whose echo was lost.
    const handle = this.deps.schedule(ADD_CONFIRM_MS, () => {
      if (this.connectGen !== armedGen || !this.pendingOps.has(conversationId)) {
        return; // a reconnect superseded this backstop, or it was already resolved
      }
      this.pendingOps.delete(conversationId);
      if (entry.session.pendingKind() === null) {
        return; // an echo or a competing commit already resolved the add: nothing to confirm or announce
      }
      try {
        entry.session.confirmAdd();
      } catch {
        return;
      }
      void this.onMembershipAdvanced(conversationId, [target.deviceKey], []);
    });
    this.pendingOps.set(conversationId, { kind: 'add', target, handle });
  }

  /** Shared post-commit handling for ONE conversation: rotate to its new epoch mailbox, re-seal (so the
   * membership change survives reload), surface the roster change (which re-runs reconcile for any
   * sibling still missing), and re-share our identity so a new member sees it. */
  private onMembershipAdvanced(conversationId: string, added: readonly string[], removed: readonly string[]): Promise<void> {
    const entry = this.sessions.get(conversationId);
    const t = this.transport;
    if (entry === undefined || t === null) {
      return Promise.resolve();
    }
    const next = entry.session.mailbox();
    if (next !== entry.groupMailbox) {
      entry.groupMailbox = next;
      t.subscribe(next);
    }
    // Return the reseal promise so a caller that acks an inbound commit can wait for the new epoch to be
    // DURABLE first (see the membership branch of onGroupMessage): the bus never redelivers a blob this
    // device has ACKED (per-consumer hold-until-ack covers only the un-acked), so acking before the reseal
    // risks a crash stranding us on the pre-merge epoch with no redelivery to recover from.
    const sealed = this.resealSelf();
    this.deps.pushEvent('roster-changed', { conversationId, added, removed });
    // Re-share our identity only where it is actually needed: the self-group (our own new device converges
    // its account identity) or a conversation a GENUINE new peer joined (they need our icon). Skip it when
    // a PEER conversation gained only our OWN siblings during the heal cascade: the peer already holds our
    // identity, our sibling gets it over the self-group, and re-broadcasting to every peer roster on a
    // device add is exactly the fan-out that floods the gateway publish limit.
    const addedAllOwn = added.length > 0 && added.every((k) => this.knownOwnKeys.has(k));
    if (entry.session.isSelfConversation() || !addedAllOwn) {
      this.publishIdentityFor(entry.session);
    }
    // When a sibling joins the self-group, re-publish our buddy list and group list so the newcomer
    // converges. Both are guarded to the self-group inside their publish helpers, so a peer roster change
    // never publishes the contact graph.
    this.publishBuddiesFor(entry.session);
    this.publishGroupsFor(entry.session);
    return sealed;
  }

  /** P6: remove a device from the group, rotating the group secrets so it cannot read future messages
   * (forward-secure exclusion). The Remove commit goes to the members still on the current mailbox; the
   * removed device receives it as an eviction. Server-side key burn is done by the controller. */
  removeDevice(conversationId: string, sigKeyHex: string): Promise<void> {
    const entry = this.sessions.get(conversationId);
    if (entry === undefined) {
      return Promise.reject(new Error('no such conversation'));
    }
    const t = this.requireTransport();
    const oldMailbox = entry.groupMailbox;
    const commit = entry.session.removeDevice(sigKeyHex);
    t.publish({ messageId: randomBytes(16), routingKey: oldMailbox, payload: commit, ttlSeconds: SEVEN_DAYS });
    entry.groupMailbox = entry.session.mailbox();
    t.subscribe(entry.groupMailbox);
    void this.resealSelf();
    this.deps.pushEvent('roster-changed', { conversationId, added: [], removed: [sigKeyHex] });
    return Promise.resolve();
  }

  /** P6 revoke: remove a device from EVERY conversation it is a member of, rotating each group's secrets
   * so the revoked device cannot read future messages in any conversation (forward-secure exclusion).
   * RETAINED ONLY for the immediate SELF-exit (revokeself): this merges eagerly and can fork on a dead
   * socket, but the self device crypto-erases its vault right after, so its stranded epoch is inert. PEER
   * revokes use the fork-free reconcileRemovals path instead. */
  async excludeEverywhere(sigKeyHex: string): Promise<void> {
    for (const conversationId of [...this.sessions.keys()]) {
      const entry = this.sessions.get(conversationId);
      if (entry !== undefined && entry.session.roster().includes(sigKeyHex)) {
        await this.removeDevice(conversationId, sigKeyHex).catch(() => {
          /* not a member or a transient failure: the server key burn still locks it out of the account */
        });
      }
    }
  }

  /** One conversation's roster as member signature-key hex strings, or empty when it is not open. */
  roster(conversationId: string): readonly string[] {
    const entry = this.sessions.get(conversationId);
    return entry !== undefined ? entry.session.roster() : [];
  }

  /** One conversation's roster minus this device's own key (the other members). Used by block. */
  peerRoster(conversationId: string): readonly string[] {
    const entry = this.sessions.get(conversationId);
    return entry !== undefined ? entry.session.roster().filter((k) => k !== this.bootstrapKey) : [];
  }

  /** Locally leave one conversation: forget its session so we stop surfacing or replying to it (and
   * cancel any in-flight add for it). The transport has no unsubscribe, but onGroupMessage drops
   * anything for a conversation we no longer hold, so this is a silent local leave; the group is not
   * notified. Other open conversations are untouched. Used by block. */
  leaveConversation(conversationId: string): void {
    const pa = this.pendingOps.get(conversationId);
    if (pa !== undefined) {
      this.deps.cancel(pa.handle);
      this.pendingOps.delete(conversationId);
    }
    this.sessions.delete(conversationId);
    this.applyChains.delete(conversationId);
  }

  /** Recovery: make THIS device an authorized seed-holder by supplying the account recovery secret,
   * certifying at the account's current epoch. The device key is unchanged, so its directory entry and
   * bootstrap mailbox stay stable. Re-seals the now-authorized identity. */
  async recoverWithSeed(recoverySeedHex: string, certEpoch: number): Promise<void> {
    const conv = this.requireConv();
    conv.recoverWithSeed(recoverySeedHex, certEpoch);
    await this.resealSelf();
  }

  /** P6 epoch sync: bring this device up to the account's current cert epoch. A seed-holder behind the
   * epoch re-certifies and re-seals (returns ready); a seedless device that cannot self-certify and is
   * behind is stale (returns not-ready, so the app declines to publish its key packages and prompts a
   * reconnect). A device already at or above the epoch is ready. */
  async syncEpoch(certEpoch: number): Promise<{ ready: boolean; stale: boolean }> {
    const conv = this.conv;
    if (conv === null) {
      return { ready: false, stale: false };
    }
    // Blind spot at 0: a legacy label-only SEED-HOLDER reports certEpoch 0, and an epoch-0 account
    // requires 0, so the epoch compare alone passed an UNCERTIFIED credential as ready and it kept
    // publishing packages that mint certless roster leaves (the ghost-channel origin). A seed-holder
    // whose credential carries no verifying cert falls through to re-certify; seedless devices and
    // legacy accounts without the account key are unchanged.
    const needsRecert = conv.accountKeyHex() !== '' && !(conv.credentialCertified?.() ?? true);
    if (!needsRecert && conv.certEpoch() >= certEpoch) {
      return { ready: true, stale: false };
    }
    if (conv.accountKeyHex() === '') {
      return { ready: false, stale: true }; // seedless and behind: cannot self-upgrade
    }
    conv.reauthorizeAtEpoch(certEpoch);
    await this.resealSelf();
    return { ready: true, stale: false };
  }

  /** This device's own certificate epoch (0 if unauthorized), or null before an identity exists. */
  certEpoch(): number | null {
    return this.conv !== null ? this.conv.certEpoch() : null;
  }

  /** Mint `n` fresh one-time key packages to publish to the directory, so peers (and our own future
   * devices) can add this device to a group. Each carries the CURRENT credential, so after a provisioned
   * device adopts its certificate these packages are authorized and pass the gate at peers. */
  freshKeyPackages(n: number): Uint8Array[] {
    const conv = this.requireConv();
    // Mint-time guard: a SEED-HOLDER must never mint label-only packages (they become certless roster
    // leaves nothing can ever repair, the ghost-channel origin). Self-heal by re-certifying at the
    // current epoch before minting; the reseal is fire-and-forget (the credential change is in-memory
    // for these packages either way, and the next reseal point persists it).
    if (conv.accountKeyHex() !== '' && !(conv.credentialCertified?.() ?? true)) {
      conv.reauthorizeAtEpoch(conv.certEpoch());
      void this.resealSelf().catch(() => {
        /* best-effort persistence; re-runs on the next mint or epoch sync */
      });
    }
    const out: Uint8Array[] = [];
    for (let i = 0; i < n; i++) {
      out.push(conv.keyPackage());
    }
    return out;
  }

  /** Build the provisioning state machine on demand, wiring the transport to our gateway connection and
   * the crypto to our durable identity Conversation (the seed-holder's account key signs certs; a new
   * device adopts one). Created once we have a connected transport and an identity. */
  private ensureProvisioning(): Provisioning {
    if (this.provisioning !== null) {
      return this.provisioning;
    }
    this.requireConv(); // fail-fast construction contract: a provisioning machine needs a live conv + transport
    this.requireTransport();
    // Capture the optional QR box primitives locally so we can arrow-wrap them (avoids unbound-method
    // scoping) while preserving undefined when the host did not wire them.
    const pek = this.deps.provisionEphemeralKeypair;
    const psl = this.deps.provisionSeal;
    const pop = this.deps.provisionOpen;
    const deps: ProvisioningDeps = {
      // Resolve conv/transport at CALL time (not construction time): a QR machine preserved across a
      // gateway reconnect (Fix 3) then binds to the NEW transport and the live conv, never a dead socket.
      publish: (key, payload) => this.requireTransport().publish({ messageId: randomBytes(16), routingKey: key, payload, ttlSeconds: PROV_TTL }),
      subscribe: (key) => this.requireTransport().subscribe(key),
      ack: (id) => this.requireTransport().ack(id),
      accountKeyHex: () => this.requireConv().accountKeyHex(),
      deviceKeyHex: () => this.requireConv().signaturePublicKeyHex(),
      sasDigestHex: (n, a, d, e) => this.deps.sasDigestHex(n, a, d, e),
      authorizeDevice: (d, e, n, c) => this.requireConv().authorizeDevice(d, e, n, c),
      adoptCertificate: (a, e, c) => this.requireConv().adoptCertificate(a, e, c),
      renderSas: (digestHex) => renderSasHex(digestHex),
      pushEvent: (kind, payload) => this.onProvisioningEvent(kind, payload),
      random: (n) => randomBytes(n),
      schedule: (ms, cb) => this.deps.schedule(ms, cb),
      cancel: (h) => this.deps.cancel(h),
      // QR pairing box (present only when the wasm host wired them); the seed-holder certifies a scanned
      // key with no SAS and seals the grant to the new device's ephemeral key. Wrap in arrows (and keep
      // undefined when absent) so the startQrShow/grantScanned guards still fall back on legacy hosts.
      provisionEphemeralKeypair: pek ? () => pek() : undefined,
      provisionSeal: psl ? (r, p) => psl(r, p) : undefined,
      provisionOpen: pop ? (s, b) => pop(s, b) : undefined,
      authorizeScannedDevice: (k, e) => this.requireConv().authorizeScannedDevice(k, e),
    };
    this.provisioning = new Provisioning(deps);
    return this.provisioning;
  }

  private onProvisioningEvent(kind: string, payload: unknown): void {
    if (kind === 'provisioning-authorized') {
      // This device just adopted the account certificate. Its credential now carries the account key.
      // Re-seal the durable identity (and write the group-ready marker) BEFORE the main thread learns
      // of the authorization, so the publishOwnKeys/isGroupReady check that follows observes the
      // durable marker. Posting the event first would race the persistence and silently skip the
      // key-package publish. The signature key is unchanged, so our bootstrap subscription stays valid.
      void this.resealSelf().finally(() => this.deps.pushEvent(kind, payload));
      return;
    }
    this.deps.pushEvent(kind, payload);
  }

  private async resealSelf(): Promise<void> {
    if (this.conv !== null && this.persistence !== undefined) {
      await this.persistence.resealSelf(this.conv).catch(() => {
        /* best-effort; a locked vault must not break an in-progress join */
      });
    }
  }

  /** Handlers stamped with the connect generation that created them: once a newer connectGateway has
   * run, every event from the superseded socket is ignored (its late close must not report the CURRENT
   * link offline, and its deliveries must not duplicate the live socket's). */
  private handlers(gen: number): TransportHandlers {
    const current = (): boolean => gen === this.connectGen;
    return {
      onOffer: () => {
        /* the group model does not use the pairwise offer/accept handshake */
      },
      onAccept: () => {
        /* unused in the group model */
      },
      onDeliver: (env) => {
        if (current()) {
          this.onDeliver(env);
        }
      },
      onReceipt: (messageId) => {
        // The gateway confirms each publish with a receipt carrying its message id. Route it to the
        // waiter gating on it (today: a revoke frame, whose sender erases its local copy only now);
        // a receipt for an ordinary publish has no waiter and is dropped, as before.
        if (current()) {
          this.pendingReceipts.get(bytesToHex(messageId))?.confirm();
        }
      },
      onError: (code, detail) => {
        if (current()) {
          // A gateway rejection during a LIVE pairing ceremony needs a user-visible retry signal (the
          // generic error event is console-only): a rejected ceremony subscribe would otherwise leave
          // the wizard waiting forever. Publish-pacing rate limits are excluded (the transport
          // retransmits those itself).
          const publishPacing = code === 3 && (detail.startsWith('sending too fast') || detail.startsWith('recipient is receiving'));
          if (this.provisioning?.active() === true && !publishPacing) {
            this.deps.pushEvent('provisioning-error', { detail: 'connection problem during pairing, please try again' });
          }
          this.deps.pushEvent('error', { code, detail });
        }
      },
      onClose: () => {
        if (!current()) {
          return; // a superseded socket closing (including the close we issued) is not news
        }
        // A closed socket can never deliver a pending receipt (a WebSocket never reopens), so fail
        // every waiter now instead of leaving each to its timeout backstop.
        for (const waiter of [...this.pendingReceipts.values()]) {
          waiter.fail(new Error('connection closed before the gateway confirmed the publish'));
        }
        this.deps.pushEvent('connection', { state: 'offline' });
      },
    };
  }

  private onDeliver(env: EnvelopeMsg): void {
    // A provisioning frame (Challenge/Request/Grant) rides a rendezvous or reply mailbox; route it to
    // the provisioning state machine and never let it reach the group path (an own-Challenge echo or a
    // stale post-window frame would otherwise fail to decrypt as MLS and surface a spurious error).
    if (this.provisioning !== null && this.provisioning.owns(env.routingKey)) {
      this.provisioning.handle(env);
      return;
    }
    // A delivery on our bootstrap mailbox is a Welcome to join; on the group mailbox it is group
    // traffic. Routing by the envelope's own routing key keeps the two paths distinct.
    if (env.routingKey === this.bootstrapKey) {
      this.onWelcome(env);
      return;
    }
    this.onGroupMessage(env);
  }

  private onWelcome(env: EnvelopeMsg): void {
    const conv = this.conv;
    const t = this.transport;
    if (conv === null || t === null) {
      return;
    }
    let session: GroupSession;
    try {
      // Join creates the group slot in the wasm and yields its (stable) group id. A duplicate/resent
      // Welcome for a conversation we already hold makes the wasm reject the join (group-id collision);
      // we ack and drop it, never clobbering the existing conversation (Welcome-storm safe).
      session = GroupSession.join(conv, env.payload);
    } catch {
      t.ack(env.messageId);
      return;
    }
    const conversationId = this.convId(session.groupId);
    if (this.sessions.has(conversationId)) {
      t.ack(env.messageId); // already joined (belt-and-suspenders alongside the wasm collision guard)
      return;
    }
    const peers = session.roster().filter((k) => k !== this.bootstrapKey);
    const adopt = (): void => {
      const groupMailbox = session.mailbox();
      this.sessions.set(conversationId, { session, groupMailbox });
      t.subscribe(groupMailbox);
      t.ack(env.messageId);
      void this.persist(conversationId, session);
      void this.resealSelf(); // the joined conversation must survive reload
      this.publishIdentityFor(session); // share our buddy icon + profile with the group we just joined
      this.deps.pushEvent('connection', { state: 'secure' });
      this.deps.pushEvent('established', { conversationId });
    };
    // The hidden self-group (every member is one of our own devices): join it SILENTLY. No channel summary
    // and no 'established' event, so it never appears as a conversation; subscribe and sync our buddy list
    // over it. Determined cryptographically (isSelfConversation), so it does not depend on a device cache.
    if (session.isSelfConversation()) {
      const groupMailbox = session.mailbox();
      this.sessions.set(conversationId, { session, groupMailbox });
      t.subscribe(groupMailbox);
      t.ack(env.messageId);
      void this.resealSelf(); // restored on reload via listConversations; no summary keeps it hidden
      this.publishIdentityFor(session);
      this.publishBuddiesFor(session); // hand the joining device our current buddy list
      this.publishGroupsFor(session); // and our current group list
      // Joining the own-devices self-group establishes this device's E2E context: report secure (still
      // no 'established' event, so it never surfaces as a conversation).
      this.deps.pushEvent('connection', { state: 'secure' });
      return;
    }
    // If every other member of this group is blocked, drop the Welcome silently and stay out (the wasm
    // slot lingers harmlessly; we never subscribe, so no traffic reaches it). Block guard preserved.
    if (this.isBlockedRoster === undefined || peers.length === 0) {
      adopt();
      return;
    }
    void this.isBlockedRoster(peers)
      .then((blocked) => {
        if (blocked) {
          t.ack(env.messageId);
          return;
        }
        adopt();
      })
      .catch(() => adopt());
  }

  private onGroupMessage(env: EnvelopeMsg): void {
    const conv = this.conv;
    const t = this.transport;
    if (conv === null || t === null) {
      return;
    }
    let routed;
    try {
      // The crypto layer self-routes by the group id inside the message and returns that conversation's
      // group id, so we never trust the mailbox to identify the conversation.
      routed = receiveGroup(conv, env.payload);
    } catch (e) {
      const detail = errMsg(e);
      if (detail.startsWith(POISON_DROP_PREFIX)) {
        // The crypto layer marked this frame PERMANENTLY unprocessable (malformed, or a gate-rejected
        // commit that no honest member will ever merge). Ack it so the hold-until-ack bus DROPS it instead
        // of redelivering it forever - a member cannot pin a mailbox with poison. It never advanced our
        // state, so there is nothing to persist. A transient error (e.g. a future-epoch frame we may yet
        // process) is NOT acked, so it can redeliver, bounded by the bus TTL.
        t.ack(env.messageId);
        if (detail.startsWith(OWN_ECHO_DROP_PREFIX)) {
          // Our own frame echoed back by the fan-out bus: permanent, routine, already acked away. A
          // reconnect can re-flush an hours-deep echo backlog, so an event per frame would be a burst
          // of raw MLS noise; the console stays quiet too.
          return;
        }
      }
      this.deps.pushEvent('error', { code: -1, detail });
      return;
    }
    const conversationId = this.convId(routed.groupId);
    if (!this.sessions.has(conversationId)) {
      t.ack(env.messageId); // a message for a conversation we do not (locally) hold: drop it
      return;
    }
    const received = routed.received;
    if (received.type === 'membership') {
      // A staged add we were waiting on in THIS conversation just resolved: either our own commit was
      // echoed back (the wasm confirmed it internally and this is the new member), or a competing commit
      // won the epoch (the wasm aborted ours and this is the winner). Either way clear this
      // conversation's in-flight tracker so the roster-changed below re-runs reconcile (forward heal).
      const pa = this.pendingOps.get(conversationId);
      if (pa !== undefined) {
        this.deps.cancel(pa.handle);
        this.pendingOps.delete(conversationId);
      }
      // Ack only AFTER the merged epoch is durable (mirror of the app-message ack-after-durable rule).
      // The wasm merged this commit in memory inside receiveGroup, but the bus never redelivers a blob
      // this device has ACKED (only the un-acked backlog re-flushes on re-subscribe), so acking before
      // the reseal would let a crash strand us on the pre-merge epoch. A reseal failure (locked vault)
      // still acks: a redelivery could not re-apply an already-merged commit anyway, and the next reseal
      // persists the advanced state.
      void this.onMembershipAdvanced(conversationId, received.added, received.removed).then(
        () => t.ack(env.messageId),
        () => t.ack(env.messageId),
      );
      return;
    }
    if (received.type === 'evicted') {
      // We were removed from THIS conversation: drop it locally and re-seal (the wasm deleted its group).
      // Ack only after the removal is durable, for the same reason as the membership branch above.
      this.leaveConversation(conversationId);
      // Also drop the persisted channel summary: the session is gone, the group can never deliver here
      // again, and an undeleted summary lists forever as a dead "ghost" row (it cannot re-classify).
      void this.deleteChannel?.(conversationId).catch(() => {
        /* best-effort; the connect-time dead-summary sweep heals a miss */
      });
      void this.resealSelf().then(
        () => t.ack(env.messageId),
        () => t.ack(env.messageId),
      );
      this.deps.pushEvent('roster-changed', { conversationId, added: [], removed: [this.bootstrapKey] });
      return;
    }
    if (received.type === 'proposal') {
      t.ack(env.messageId);
      return;
    }
    if (received.type === 'ignored') {
      t.ack(env.messageId); // an unrecognized / forward-version frame: drop it
      return;
    }
    if (received.type === 'control') {
      // A peer identity control frame (buddy icon, profile): validate membership and store it sealed.
      this.onControlFrame(conversationId, received.controlType, received.payload, received.fromOwnAccount);
      t.ack(env.messageId);
      return;
    }
    if (received.frame.type === 'revoke') {
      // A cooperative revoke: erase the targeted stored copy (the controller validates the target
      // belongs to this conversation and is a revocable inbound record). Ack only AFTER the erase
      // completes, so an apply interrupted by a crash is redelivered rather than lost. The apply is
      // FIFO-ordered behind any message persist that arrived earlier in this conversation, so a
      // recall sent right after its message finds the target already durable.
      const targetMessageId = received.frame.targetMessageId;
      const fromOwnAccount = received.fromOwnAccount;
      const onRevoke = this.onRevoke;
      if (onRevoke === undefined) {
        t.ack(env.messageId);
        return;
      }
      void this.enqueueApply(conversationId, () => onRevoke(conversationId, targetMessageId, fromOwnAccount))
        .then(() => {
          t.ack(env.messageId);
        })
        .catch((e: unknown) => {
          this.deps.pushEvent('error', { code: -1, detail: errMsg(e) });
        });
      return;
    }
    const messageId = bytesToHex(env.messageId);
    const frame = received.frame;
    // Ack only AFTER the message is durably stored (hold-until-seen at the network layer). FIFO per
    // conversation, so a revoke chasing this message applies after the store commit.
    void this.enqueueApply(conversationId, () =>
      // ownAuthored: a sibling device's copy of a message our own account sent keeps its revoke
      // control here too (the flag is MLS-authenticated; a peer cannot claim it).
      this.persistMessage(
        { messageId, conversationId, direction: 'in', lifetime: frame.lifetime, ownAuthored: received.fromOwnAccount },
        frame.plaintext,
      ),
    )
      .then(() => {
        t.ack(env.messageId);
        this.deps.pushEvent('inbound-message', { conversationId });
      })
      .catch((e) => {
        this.deps.pushEvent('error', { code: -1, detail: errMsg(e) });
      });
    // If the user is away, auto-reply once per cooldown. A message held while every device was offline
    // replays through this same path on reconnect, so this covers the deferred case too.
    this.maybeAwayReply(conversationId);
  }

  private peerLabel(session: GroupSession): string {
    // Show the first member that is not us (best-effort label for the conversation header).
    const others = session.roster().filter((k) => k !== this.bootstrapKey);
    return others.length > 0 ? shortName(others[0] ?? '') : 'GROUP';
  }

  private persist(conversationId: string, session: GroupSession): Promise<void> {
    const summary: ChannelSummary = {
      id: conversationId,
      peer: this.peerLabel(session),
      fingerprint: fingerprintOf(this.bootstrapKey),
      status: 'secure',
      preview: 'group conversation open',
      unread: 0,
    };
    return this.persistChannel(summary).catch(() => {
      /* best-effort; a locked vault must not break the live channel */
    });
  }

  private requireConv(): GroupConversationLike {
    if (this.conv === null) {
      throw new Error('connect to the gateway first');
    }
    return this.conv;
  }

  private requireTransport(): Transport {
    if (this.transport === null) {
      throw new Error('connect to the gateway first');
    }
    return this.transport;
  }
}

const SEVEN_DAYS = 604800;
const PROV_TTL = 600; // provisioning frames are control-plane and short-lived (10 min backstop)
// How long a revoke waits for its gateway receipt before rejecting (the sender keeps its copy and can
// retry). One gateway round trip in practice; generous for real-network latency, like the backstops below.
const REVOKE_RECEIPT_MS = 10000;
// Self-heal timing (ADR-022). The confirm path is normally the echo (sub-second on the in-process bus,
// one round trip on the live gateway); these are backstops, generous to avoid a premature confirm or a
// double-add under real-network latency.
// Prefix the crypto `receive` puts on an error for a PERMANENTLY unprocessable frame; the client acks
// such a frame so the bus drops it (see onGroupMessage). Mirrors DROP_PREFIX in crypto/conversation.rs.
const POISON_DROP_PREFIX = 'drop:';
// The crypto marks a bus echo of OUR OWN publish with this sub-prefix (see conversation.rs
// process_in_slot): acked and silenced, never surfaced as an error event.
const OWN_ECHO_DROP_PREFIX = POISON_DROP_PREFIX + 'own frame';
const ADD_CONFIRM_MS = 8000; // confirm an uncontested staged add if its echo never arrives
// The post-restore confirm backstop is deliberately LONGER: right after a reload the gateway may still be
// re-delivering a rival commit that won the epoch while we were down; give it time to arrive (and abort
// our restored pending) before we would force-merge our own commit onto a possibly-stale epoch.
const RESTORE_CONFIRM_MS = 24000;
const ADD_FAILOVER_MS = 6000; // per rank: how long a non-designated device waits before taking over
const RECONCILE_JITTER_MS = 2000; // random spread so failovers do not fire in lockstep
