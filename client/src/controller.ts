/**
 * The real AppController (M5): wires the screens to the encrypted IndexedDB stores.
 *
 * - unlock derives the Master Store Key via the MskVault (passphrase -> Argon2id KEK -> wrapped
 *   random MSK), creating the vault on first run.
 * - listChannels / openChannel decrypt the contact graph and per-message history UNDER the MSK,
 *   so nothing is plaintext at rest (P2/P7). History is read from the Layer-2 keyvault, never by
 *   re-running MLS (ADR-015), so this read path needs no wasm.
 * - The MLS handshake/send path needs the wasm Session and the owning worker; startKeyExchange and
 *   acceptKeyExchange therefore reject with a clear message until that integration lands. The
 *   preview uses DemoController; this is the storage-backed controller, unit-tested with
 *   fake-indexeddb + WebCrypto.
 */

import {
  MskVault,
  ChannelStore,
  IndexedDbKeyvaultStore,
  SealedSessionStore,
  type ChannelRecord,
} from './idb.js';
import { importMsk, sealUnder, openUnder, open as openVaultRecord } from './vault.js';
import {
  GroupChannel,
  fingerprintOf,
  type GroupDeps,
  type GroupPersistence,
  type DeviceTarget,
  type PendingWelcome,
} from './groupchannel.js';
import { CONTROL_BUDDY_ICON, CONTROL_PROFILE, CONTROL_AWAY } from './session.js';
import { substituteSpecials } from './specials.js';
import { LifetimeManager } from './lifetime.js';
import type { GroupConversationLike } from './group.js';
import { DEFAULT_IDENTITY, PROFILE_MAX_CHARS, ICON_VALUE_MAX, AWAY_MAX_CHARS } from './app.js';

/** Validate and bound a PEER- or sibling-authored buddy icon before storing it: anything malformed
 * (wrong shape, non-string fields) or oversized becomes null. Frames are attacker-influenced JSON, so
 * every field is checked rather than trusted to match the BuddyIcon type. */
function sanitizeIcon(raw: unknown): BuddyIcon | null {
  if (raw === null || raw === undefined || typeof raw !== 'object') {
    return null;
  }
  const { kind, value, bg } = raw as { kind?: unknown; value?: unknown; bg?: unknown };
  if (kind !== 'emoji' && kind !== 'initials' && kind !== 'image') {
    return null;
  }
  if (typeof value !== 'string' || typeof bg !== 'string' || value.length > ICON_VALUE_MAX || bg.length > 32) {
    return null;
  }
  return { kind, value, bg };
}
import type { AppController, ChannelSummary, KeyExchangeState, TransmitModel, LogEntry, IdentityProfile, BuddyIcon, AwayConfig, PeerIdentity, Buddy, BuddyVerifyInfo, BuddyVerifyBadge, GroupSummary } from './app.js';
import type { Lifetime } from './index.js';

function toHexStr(b: Uint8Array): string {
  return [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
}
function fromHexStr(h: string): Uint8Array {
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}
function randomBytes(n: number): Uint8Array {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}

const enc = new TextEncoder();
const dec = new TextDecoder();
const AWAY_COOLDOWN_MS = 600000; // 10 minutes between away auto-replies per conversation

function channelAad(id: string): string {
  return `channel:${id}`;
}

function lifetimeOf(kind: Lifetime['kind'], remainingSeconds: number | null): Lifetime {
  if (kind === 'duration') {
    return { kind: 'duration', seconds: remainingSeconds ?? 0 };
  }
  return { kind };
}

/** Normalize a username for account lookup: trim + lowercase, so it is a forgiving identifier. */
function normalizeUsername(username: string): string {
  return username.trim().toLowerCase();
}

/** One buddy's stored state: when first added, the change version (a wall-clock ms timestamp used for
 * per-buddy last-writer-wins across devices), and whether it is a tombstone (removed). */
interface BuddyEntry {
  addedAt: number;
  v: number;
  removed: boolean;
  group: string; // the group (category) the buddy is filed under; part of the synced per-buddy state
  /** The account authority key (64 hex chars) this user MARKED VERIFIED for the buddy, after comparing
   * the six-word phrase out of band. Absent until they verify. Synced with the record, so verifying on
   * one device verifies on all of them; a later change of the buddy's actual key is a loud mismatch. */
  vk?: string;
}
const DEFAULT_GROUP = 'Buddies';
/** The buddy list keyed by normalized username, including tombstones. */
type BuddyMap = Record<string, BuddyEntry>;

/** Coerce a stored or received buddy blob into a BuddyMap. Accepts the current map shape and, for
 * backward compatibility, a legacy `Buddy[]` array (each entry gets version 0 so a genuine sibling change
 * always wins). Unknown shapes yield an empty map. Exported for direct testing. */
export function normalizeBuddyMap(raw: unknown): BuddyMap {
  const out: BuddyMap = {};
  if (Array.isArray(raw)) {
    for (const b of raw) {
      const e = b as { username?: unknown; addedAt?: unknown };
      if (typeof e.username === 'string' && e.username.length > 0) {
        out[e.username] = { addedAt: typeof e.addedAt === 'number' ? e.addedAt : 0, v: 0, removed: false, group: DEFAULT_GROUP };
      }
    }
    return out;
  }
  if (raw !== null && typeof raw === 'object') {
    for (const [u, e] of Object.entries(raw as Record<string, unknown>)) {
      if (u.length === 0 || e === null || typeof e !== 'object') {
        continue;
      }
      const ent = e as { addedAt?: unknown; v?: unknown; removed?: unknown; group?: unknown; vk?: unknown };
      const vk = typeof ent.vk === 'string' && /^[0-9a-f]{64}$/.test(ent.vk) ? ent.vk : '';
      out[u] = {
        addedAt: typeof ent.addedAt === 'number' ? ent.addedAt : 0,
        v: typeof ent.v === 'number' ? ent.v : 0,
        removed: ent.removed === true,
        group: typeof ent.group === 'string' && ent.group.trim().length > 0 ? ent.group : DEFAULT_GROUP,
        ...(vk.length > 0 ? { vk } : {}),
      };
    }
  }
  return out;
}

/** One buddy-group's stored state: a change version (a wall-clock ms timestamp for per-group
 * last-writer-wins across devices), a tombstone flag (a deleted group is kept as a tombstone so the
 * deletion propagates and a stale add cannot resurrect it), and a sort order (append position). */
interface GroupEntry {
  v: number;
  removed: boolean;
  order: number;
  /** Display name carried ONLY by the two reserved alias entries (see RK_DEFAULT / RK_BLOCKED). */
  n?: string;
}
/** The buddy-group list keyed by group name, including tombstones. This is what lets an EMPTY group
 * exist and sync (the buddy map alone can only imply groups that have at least one member). */
type GroupMap = Record<string, GroupEntry>;

/** Reserved map keys carrying the DISPLAY NAMES of the two built-in groups (the default "Buddies" group
 * and the "Blocked" drop). They start with a control character, which group names can never contain
 * (sanitizeGroupName strips them), so a user-made group can never collide with or forge one. Renaming a
 * built-in only changes its label here: buddies stay filed under the internal 'Buddies' key and blocks
 * stay in the block list, so both keep working under the new name and the rename syncs LWW like any
 * other group entry. */
const RK_DEFAULT = '\u0000d';
const RK_BLOCKED = '\u0000b';
const BLOCKED_LABEL_FALLBACK = 'Blocked';
const GROUP_NAME_MAX = 32;

/** Group names and built-in labels: trimmed, control characters stripped (they would collide with the
 * reserved alias keys), and length-capped. */
export function sanitizeGroupName(raw: string): string {
  // eslint-disable-next-line no-control-regex
  return raw.replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0, GROUP_NAME_MAX).trim();
}

/** Bounds on a synced group map: entries beyond the cap are dropped (a runaway or buggy sibling cannot
 * grow the sealed blob and every re-broadcast without bound), and a version further than one day ahead
 * of the local clock is rejected on adopt (a far-future version would win LWW forever, permanently
 * pinning that key against every honest device's now()-stamped writes). */
const GROUP_MAP_MAX_ENTRIES = 512;
const CRDT_MAX_FUTURE_MS = 24 * 60 * 60 * 1000;

/** Coerce a stored or received group blob into a GroupMap. Defensive per-field coercion (a malformed or
 * forward-version blob degrades to an empty map rather than throwing in the receive loop). Exported for
 * direct testing. */
export function normalizeGroupMap(raw: unknown): GroupMap {
  const out: GroupMap = {};
  let kept = 0;
  if (raw !== null && typeof raw === 'object' && !Array.isArray(raw)) {
    for (const [name, e] of Object.entries(raw as Record<string, unknown>)) {
      if (name.length === 0 || e === null || typeof e !== 'object' || kept >= GROUP_MAP_MAX_ENTRIES) {
        continue;
      }
      // KEYS are held to the same rules as locally created names: a key that changes under sanitization
      // (control characters, over-length, edge whitespace) is one this code could never have written, so
      // it is dropped entirely. Adopting it under a rewritten spelling would break LWW convergence, and
      // keeping it verbatim would let a buggy sibling smuggle unbounded labels or a whitespace
      // doppelganger of a real group that deleteGroup's trimming lookup could never remove. The two
      // exact reserved alias keys pass as themselves.
      const reserved = name === RK_DEFAULT || name === RK_BLOCKED;
      if (!reserved && sanitizeGroupName(name) !== name) {
        continue;
      }
      const ent = e as { v?: unknown; removed?: unknown; order?: unknown; n?: unknown };
      // The alias display name (reserved entries only): sanitized like any group name so a synced blob
      // cannot smuggle control characters or an unbounded label into the UI.
      const alias = reserved && typeof ent.n === 'string' ? sanitizeGroupName(ent.n) : '';
      out[name] = {
        v: typeof ent.v === 'number' && Number.isFinite(ent.v) ? ent.v : 0,
        removed: ent.removed === true,
        order: typeof ent.order === 'number' && Number.isFinite(ent.order) ? ent.order : 0,
        ...(alias.length > 0 ? { n: alias } : {}),
      };
      kept++;
    }
  }
  return out;
}

/** The account id keying a user's vault and per-account state: a SHA-256 hash of the normalized
 * username, so a seized device stores a hash rather than the handle. */
export async function accountIdFor(username: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', enc.encode(normalizeUsername(username)));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** The combined login secret fed to Argon2id: the normalized username bound to the passphrase, so
 * the derived key depends on BOTH and the username adds entropy to the at-rest floor (ADR-015). */
export function credentialFor(username: string, passphrase: string): string {
  return `${normalizeUsername(username)}\u001f${passphrase}`;
}

export class AppControllerImpl implements AppController {
  private mskKey: CryptoKey | null = null;
  private mskRaw: Uint8Array | null = null; // raw MSK, kept for the wasm at-rest seal/restore
  private account: string | null = null; // the unlocked account id (namespaces per-account state)
  private readonly groupChannel: GroupChannel | null;
  private readonly lifetime: LifetimeManager | null;
  private aakSeedHex: string | null = null; // the account's recovery seed, cached after unseal
  private freshRecoverySecret: string | null = null; // shown once at registration, then cleared

  /** Key for this account's long-lived identity Conversation in the sealed-session store. Scoped by
   * account so several users on one device do not collide on a single 'self' record. */
  private selfKey(): string {
    if (this.account === null) {
      throw new Error('locked');
    }
    return `self:${this.account}`;
  }

  constructor(
    private readonly vault: MskVault,
    private readonly channels: ChannelStore,
    private readonly keyvault: IndexedDbKeyvaultStore,
    private readonly now: () => number = () => Date.now(),
    /** Returns our identity key fingerprint (wasm-backed in the app); enables startKeyExchange. */
    private readonly identity?: () => Promise<string>,
    /** Browser-only group-transport dependencies (worker host only); absent on the main thread. */
    private readonly live?: GroupDeps,
    /** Durable MSK-sealed MLS state store (worker host only); enables a stable identity across logins. */
    private readonly sessions?: SealedSessionStore,
  ) {
    if (live !== undefined) {
      // Live messages are persisted into the crypto-erasable keyvault and their lifetimes enforced
      // here, so a reload re-renders them and revoke/expiry still apply. The timer hooks come from
      // the worker (setTimeout); erasure notifies the UI to drop the rendered copy.
      this.lifetime = new LifetimeManager(this.keyvault, {
        now: this.now,
        schedule: (delayMs, cb) => live.schedule(delayMs, cb),
        cancel: (handle) => live.cancel(handle),
        onErased: (messageId, reason, conversationId) => {
          // Flag erasures inside ANY self-classified copy: an open Note to Self renders the UNION of
          // those histories, so the UI must drop the rendered copy even though the ids differ.
          const selfCopy =
            this.selfGroupIdsCache?.has(conversationId) === true || this.groupChannel?.isSelfConversationId(conversationId) === true;
          live.pushEvent('erased', { messageId, reason, conversationId, selfCopy });
        },
      });
      // Identity persistence: restore our long-lived AUTHORIZED signer so the contact/mailbox is
      // stable across logins, and supply the account recovery seed. Only when the sealed-session
      // store is wired (the owning worker).
      const persistence: GroupPersistence | undefined =
        sessions !== undefined
          ? {
              loadSelf: () => this.loadSelf(),
              saveSelf: (conv) => this.saveSelf(conv),
              resealSelf: (conv) => this.resealSelf(conv),
              recoverySeedHex: () => this.loadAccountSeed(),
              loadWelcomeOutbox: () => this.loadWelcomeOutbox(),
              saveWelcomeOutbox: (entries) => this.saveWelcomeOutbox(entries),
            }
          : undefined;
      this.groupChannel = new GroupChannel(
        // The closed-set loader rides the deps so the reconnect restore can skip (and re-close)
        // conversations the user closed for good, without the GroupChannel knowing about storage.
        { ...live, loadClosedIds: () => this.loadClosedChannelIds() },
        (s) => this.saveChannel(s),
        (meta, plaintext) => this.persistLiveMessage(meta, plaintext),
        persistence,
        () => this.buildIdentityFrames(),
        (c, k, t, p) => this.savePeerIdentity(c, k, t, p),
        (t, p) => void this.adoptSiblingIdentity(t, p),
        (c, peerName) => this.awayReplyText(c, peerName),
        (peers) => this.isBlockedRoster(peers),
        (conversationId, payload) => this.relayFileSignal(conversationId, payload),
        (conversationId, payload) => this.relayCallSignal(conversationId, payload),
        (payload) => void this.adoptBuddies(payload),
        () => this.buddiesFrame(),
        (payload) => void this.adoptGroups(payload),
        () => this.groupsFrame(),
        (conversationId, targetMessageId, fromOwnAccount) => this.applyInboundRevoke(conversationId, targetMessageId, fromOwnAccount),
        (conversationId) => this.channels.delete(conversationId),
      );
    } else {
      this.lifetime = null;
      this.groupChannel = null;
      this.selfConvId = null; // a new session (or another account) must re-derive its own self-group
      this.selfGroupIdsCache = null; // and must not inherit the previous account's recorded self ids
    }
  }

  private aakKey(): string {
    return `aak:${this.account}`;
  }

  /** Key for this account's sealed identity card (buddy icon, profile, away config) in the sealed store,
   * scoped by account so several users on one device do not collide. */
  private idKey(): string {
    return `identity:${this.account}`;
  }

  /** This device's identity card, sealed under the MSK per account. Returns the default card before
   * anything is set, when locked, or if the sealed-session store is unavailable. */
  async getIdentity(): Promise<IdentityProfile> {
    if (this.sessions === undefined || this.account === null) {
      return DEFAULT_IDENTITY;
    }
    const key = this.requireKey();
    const rec = await this.sessions.load(this.idKey());
    if (rec === undefined) {
      return DEFAULT_IDENTITY;
    }
    try {
      return JSON.parse(dec.decode(await openUnder(key, rec.sealed, this.idKey()))) as IdentityProfile;
    } catch {
      return DEFAULT_IDENTITY; // another account's record (or a corrupt blob): fall back to the default
    }
  }

  /** Seal the identity card under the MSK as-is (no version bump, no publish). The low-level write used
   * by both a user edit (setIdentity) and a sibling adoption (adoptSiblingIdentity). */
  private async saveIdentityCard(profile: IdentityProfile): Promise<void> {
    if (this.sessions === undefined || this.account === null) {
      return;
    }
    const key = this.requireKey();
    const sealed = await sealUnder(key, enc.encode(JSON.stringify(profile)), this.idKey());
    await this.sessions.save({ conversationId: this.idKey(), sealed });
  }

  /** Persist the identity card and publish the icon + profile to every open conversation (E2E) so peers
   * AND this account's other devices see the update. A changed icon or profile gets a fresh version
   * (timestamp) so the most recent change wins on every device (last-writer-wins). The publish is
   * best-effort and a no-op when no conversation is open. */
  // The identity card is ONE sealed record holding icon + profile + away, but a sibling change to each
  // arrives as a SEPARATE control frame. Each adopt is a read-modify-write (load the card, replace one
  // field, save it), and the gateway flushes the three frames back-to-back on a join, so without a lock
  // three concurrent read-modify-writes all read the same base card and last-writer-wins nulls the other
  // two fields (the buddy icon was the visible casualty). Serialize every write to the card through this
  // FIFO chain so each sees the previous one's committed result.
  private identityWrite: Promise<unknown> = Promise.resolve();
  private runIdentityWrite<T>(op: () => Promise<T>): Promise<T> {
    const run = this.identityWrite.then(op, op); // run after the prior write settles, success OR failure
    this.identityWrite = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }

  async setIdentity(profile: IdentityProfile): Promise<void> {
    if (this.sessions === undefined || this.account === null) {
      return;
    }
    await this.runIdentityWrite(async () => {
      const current = await this.getIdentity();
      const now = this.now();
      const iconChanged = JSON.stringify(profile.icon ?? null) !== JSON.stringify(current.icon ?? null);
      const bioChanged = profile.bio !== current.bio;
      const awayChanged = JSON.stringify(profile.away) !== JSON.stringify(current.away);
      const versioned: IdentityProfile = {
        ...profile,
        iconVersion: iconChanged ? now : current.iconVersion ?? 0,
        bioVersion: bioChanged ? now : current.bioVersion ?? 0,
        awayVersion: awayChanged ? now : current.awayVersion ?? 0,
      };
      await this.saveIdentityCard(versioned);
    });
    this.groupChannel?.publishIdentityNow();
  }

  /** Adopt an identity control frame (buddy icon or profile) that arrived from one of THIS account's own
   * devices (a sibling, crypto-authenticated upstream). Last-writer-wins by version: apply only a STRICTLY
   * newer change, then re-broadcast (so it reaches our other devices and peers) and signal the UI. An
   * older-or-equal version is ignored, which also terminates the re-broadcast loop. */
  async adoptSiblingIdentity(controlType: number, payload: Uint8Array): Promise<void> {
    if (this.sessions === undefined || this.account === null) {
      return;
    }
    let parsed: { icon?: BuddyIcon | null; bio?: string; away?: AwayConfig; v?: number };
    try {
      parsed = JSON.parse(dec.decode(payload)) as { icon?: BuddyIcon | null; bio?: string; away?: AwayConfig; v?: number };
    } catch {
      return;
    }
    const incoming = typeof parsed.v === 'number' ? parsed.v : 0;
    // Serialize the whole read-modify-write so three sibling frames flushed back-to-back on a join cannot
    // each read the same base card and clobber one another (which nulled the icon). A version-gate return
    // inside just resolves this op without saving.
    await this.runIdentityWrite(async () => {
      const current = await this.getIdentity();
      let updated: IdentityProfile;
      if (controlType === CONTROL_BUDDY_ICON) {
        if (incoming <= (current.iconVersion ?? -1)) {
          return;
        }
        // HARD LIMIT on adoption: a malformed or oversized icon (only a data-URL image can be large) is
        // dropped rather than stored, so a modified sibling cannot bloat this device's sealed card.
        updated = { ...current, icon: sanitizeIcon(parsed.icon), iconVersion: incoming };
      } else if (controlType === CONTROL_PROFILE) {
        if (incoming <= (current.bioVersion ?? -1)) {
          return;
        }
        // HARD LIMIT on adoption: clamp to the same cap the editor enforces (AIM-parity 1024).
        updated = { ...current, bio: typeof parsed.bio === 'string' ? parsed.bio.slice(0, PROFILE_MAX_CHARS) : '', bioVersion: incoming };
      } else if (controlType === CONTROL_AWAY) {
        if (incoming <= (current.awayVersion ?? -1) || parsed.away === undefined) {
          return;
        }
        // Adopt the away config a sibling changed (message + on/off + server-side opt-in). The per-device
        // idle/offline trigger still gates the actual auto-reply, so adopting "enabled" here is safe.
        updated = { ...current, away: parsed.away, awayVersion: incoming };
      } else {
        return;
      }
      await this.saveIdentityCard(updated);
      this.groupChannel?.publishIdentityNow(); // re-broadcast at the same version: siblings/peers converge, no loop
      // Carry the adopted card. Without it the only possible reaction is a full re-read, which the app
      // can do only when the buddy list is the FOCUSED window; with it, a parked or backgrounded buddy
      // list can be patched in place, so a sibling's away change is never left silently stale.
      this.live?.pushEvent('identity-updated', { profile: updated });
    });
  }

  /** Build this device's identity control frames (buddy icon, profile) for the group to receive E2E.
   * Each payload declares this device's key (for peer attribution) and the change version (for the
   * own-device sync to pick the most recent). */
  private async buildIdentityFrames(): Promise<{ controlType: number; payload: Uint8Array }[]> {
    const k = this.groupChannel?.selfDeviceKeyHex() ?? '';
    if (k === '') {
      return [];
    }
    const id = await this.getIdentity();
    return [
      { controlType: CONTROL_BUDDY_ICON, payload: enc.encode(JSON.stringify({ k, icon: id.icon, v: id.iconVersion ?? 0 })) },
      { controlType: CONTROL_PROFILE, payload: enc.encode(JSON.stringify({ k, bio: id.bio, v: id.bioVersion ?? 0 })) },
      // Away config: only YOUR OWN devices adopt it (from_own_account); a peer drops it. It rides the
      // conversation, so a peer's client receives the bytes (the away text is content meant for peers
      // anyway); disclosed in honest-limits.
      { controlType: CONTROL_AWAY, payload: enc.encode(JSON.stringify({ k, away: id.away, v: id.awayVersion ?? 0 })) },
    ];
  }

  private peerMapAad(conversationId: string): string {
    return `peerids:${conversationId}`;
  }

  private async loadPeerMap(key: CryptoKey, aad: string): Promise<Record<string, { icon: BuddyIcon | null; bio: string; away?: string }>> {
    const rec = await this.sessions?.load(aad);
    if (rec === undefined) {
      return {};
    }
    try {
      return JSON.parse(dec.decode(await openUnder(key, rec.sealed, aad))) as Record<string, { icon: BuddyIcon | null; bio: string; away?: string }>;
    } catch {
      return {}; // another account's record on this device, or a corrupt blob
    }
  }

  /** Persist one peer's received identity control frame into the per-conversation sealed map. The
   * groupchannel has already validated the sender is a current non-self group member. */
  private async savePeerIdentity(conversationId: string, peerKey: string, controlType: number, payload: Uint8Array): Promise<void> {
    if (this.sessions === undefined || this.historyOff) {
      // History-off: this record is durable proof of WHO you talked to, so it is not written at all.
      // The cost is that Get Info shows no cached profile for a conversation held in this mode.
      return;
    }
    const key = this.requireKey();
    const aad = this.peerMapAad(conversationId);
    let parsed: { icon?: BuddyIcon | null; bio?: string; away?: AwayConfig };
    try {
      parsed = JSON.parse(dec.decode(payload)) as { icon?: BuddyIcon | null; bio?: string; away?: AwayConfig };
    } catch {
      return;
    }
    const map = await this.loadPeerMap(key, aad);
    const cur = map[peerKey] ?? { icon: null, bio: '' };
    // HARD LIMITS on what a PEER can make this device store: the bio + away text clamp to the same caps our
    // own editors enforce (AIM-parity 1024 / 560) and a malformed or oversized icon is dropped, so a hostile
    // client cannot bloat the sealed peer cache or the Get-Info / buddy-list render. The away text is the
    // buddy's away message (empty when their away is off), shown as a dim buddy-list subtitle while away.
    map[peerKey] =
      controlType === CONTROL_BUDDY_ICON
        ? { ...cur, icon: sanitizeIcon(parsed.icon) }
        : controlType === CONTROL_AWAY
          ? { ...cur, away: parsed.away?.enabled === true && typeof parsed.away.message === 'string' ? parsed.away.message.slice(0, AWAY_MAX_CHARS) : '' }
          : { ...cur, bio: typeof parsed.bio === 'string' ? parsed.bio.slice(0, PROFILE_MAX_CHARS) : '' };
    const sealed = await sealUnder(key, enc.encode(JSON.stringify(map)), aad);
    await this.sessions.save({ conversationId: aad, sealed });
  }

  /** The cached buddy icon + profile for each peer device in a conversation, for the Get-Info panel. */
  async getPeerIdentities(conversationId: string): Promise<readonly PeerIdentity[]> {
    if (this.sessions === undefined || this.account === null) {
      return [];
    }
    const key = this.requireKey();
    const map = await this.loadPeerMap(key, this.peerMapAad(conversationId));
    return Object.entries(map).map(([k, v]) => ({ key: k, fingerprint: fingerprintOf(k), icon: v.icon, bio: v.bio, away: v.away ?? '' }));
  }

  // A device-local map from a buddy handle to the conversation it was opened with, so Buddy Info can find
  // that conversation's cached peer profile by username. It is sealed under the MSK like the block list and
  // never leaves this device (it is NOT part of any E2E payload and is NOT synced to siblings).
  private convHandlesKey(): string {
    return `convhandles:${this.account}`;
  }

  private async loadConvHandles(): Promise<Record<string, string>> {
    if (this.sessions === undefined || this.account === null) {
      return {};
    }
    const key = this.requireKey();
    const rec = await this.sessions.load(this.convHandlesKey());
    if (rec === undefined) {
      return {};
    }
    try {
      const parsed = JSON.parse(dec.decode(await openUnder(key, rec.sealed, this.convHandlesKey()))) as unknown;
      if (parsed === null || typeof parsed !== 'object') {
        return {};
      }
      const out: Record<string, string> = {};
      for (const [u, c] of Object.entries(parsed as Record<string, unknown>)) {
        if (typeof c === 'string') {
          out[u] = c;
        }
      }
      return out;
    } catch {
      return {};
    }
  }

  /** Tag a conversation with the buddy handle it was opened with (most recent wins). */
  async tagConversationHandle(conversationId: string, username: string): Promise<void> {
    if (this.sessions === undefined || this.account === null) {
      return;
    }
    const u = username.trim().toLowerCase();
    if (u.length === 0 || conversationId.length === 0) {
      return;
    }
    const map = await this.loadConvHandles();
    // A 1:1 tag is what contact verification resolves a buddy's account key through, so a GROUP chat
    // must never displace one. Starting a group with a verified buddy used to repoint their handle at
    // the multi-account conversation, which made their key unreadable and silently killed every
    // verification surface, including the original 1:1 window. Prefer the more specific binding.
    const prev = map[u];
    if (prev !== undefined && prev !== conversationId) {
      const prevIsOneToOne = (this.groupChannel?.peerAccountKeysFor(prev) ?? []).length === 1;
      const nextIsOneToOne = (this.groupChannel?.peerAccountKeysFor(conversationId) ?? []).length === 1;
      if (prevIsOneToOne && !nextIsOneToOne) {
        return; // keep the 1:1 binding
      }
    }
    map[u] = conversationId;
    const key = this.requireKey();
    const sealed = await sealUnder(key, enc.encode(JSON.stringify(map)), this.convHandlesKey());
    await this.sessions.save({ conversationId: this.convHandlesKey(), sealed });
  }

  /** The cached peer profile(s) for a buddy by username, via the conversation tagged for that handle.
   * Empty when we have no conversation with them on this device (profiles never live on the server). */
  async getBuddyInfo(username: string): Promise<readonly PeerIdentity[]> {
    const u = username.trim().toLowerCase();
    const conversationId = (await this.loadConvHandles())[u];
    if (conversationId === undefined) {
      return [];
    }
    return this.getPeerIdentities(conversationId);
  }

  /** The cached buddy icons for a set of usernames in ONE call (the buddy list shows an icon per row).
   * Loads the handle->conversation map once, then picks each buddy's first cached device icon. A buddy
   * with no tagged conversation, or whose peers never shared an icon, is simply absent from the result
   * (the list renders a placeholder). Icons come from the E2E identity cache; nothing touches the server. */
  async buddyIcons(usernames: readonly string[]): Promise<Record<string, BuddyIcon>> {
    const handles = await this.loadConvHandles();
    const out: Record<string, BuddyIcon> = {};
    for (const name of usernames) {
      const conversationId = handles[name.trim().toLowerCase()];
      if (conversationId === undefined) {
        continue;
      }
      const icon = (await this.getPeerIdentities(conversationId)).find((p) => p.icon !== null)?.icon;
      if (icon !== undefined && icon !== null) {
        out[name] = icon;
      }
    }
    return out;
  }

  /** The cached away MESSAGE (E2E, from CONTROL_AWAY) for a set of usernames in ONE call, for the dim
   * buddy-list subtitle shown while a buddy is away. Mirrors buddyIcons: handle->conversation, then the
   * first peer device that has a non-empty away message. Absent (or empty) when the buddy's away is off,
   * they never shared one, or you have no conversation with them. Nothing touches the server. */
  async buddyAwayText(usernames: readonly string[]): Promise<Record<string, string>> {
    const handles = await this.loadConvHandles();
    const out: Record<string, string> = {};
    for (const name of usernames) {
      const conversationId = handles[name.trim().toLowerCase()];
      if (conversationId === undefined) {
        continue;
      }
      const away = (await this.getPeerIdentities(conversationId)).find((p) => p.away.length > 0)?.away;
      if (away !== undefined && away.length > 0) {
        out[name] = away;
      }
    }
    return out;
  }

  /** Resolve the buddy's CURRENT account key through the conversation tagged for that handle: exactly
   * one cert-verified foreign account = an unambiguous anchor; anything else = '' (a group chat with
   * several accounts, no live session yet, or nothing verifies — never guess). */
  private buddyPeerKey(handles: Record<string, string>, username: string): string {
    const conversationId = handles[username.trim().toLowerCase()];
    if (conversationId === undefined) {
      return '';
    }
    const keys = this.groupChannel?.peerAccountKeysFor(conversationId) ?? [];
    return keys.length === 1 ? (keys[0] ?? '') : '';
  }

  /** Everything the Verify Buddy panel needs, in one call. `state` is precomputed here so every device
   * and every surface (panel, list badge, channel line) agrees on what it means. */
  async buddyVerifyInfo(username: string): Promise<BuddyVerifyInfo> {
    const u = username.trim().toLowerCase();
    const handles = await this.loadConvHandles();
    const peerKey = this.buddyPeerKey(handles, u);
    const verifiedKey = (await this.loadBuddyMap())[u]?.vk ?? '';
    const ourKey = this.groupChannel?.accountKeyHex() ?? '';
    const ourWords = this.groupChannel?.contactPhraseFor(ourKey) ?? '';
    const theirWords = peerKey.length > 0 ? (this.groupChannel?.contactPhraseFor(peerKey) ?? '') : '';
    // Comparable only when BOTH halves actually rendered. A device that cannot derive its own phrase
    // (an older wasm, or no account key yet) must not present a half-empty panel as if it worked.
    const comparable = ourWords.length > 0 && theirWords.length > 0;
    let state: BuddyVerifyInfo['state'];
    if (verifiedKey.length > 0) {
      if (peerKey.length === 0) {
        // Pinned, but the current key is unreadable right now (no live session, or the tagged
        // conversation has several accounts in it). Say so. Claiming 'verified' here was the defect
        // that let one group chat silently disable the alarm for a verified buddy.
        state = 'stale';
      } else {
        state = peerKey !== verifiedKey ? 'changed' : 'verified';
      }
    } else {
      state = comparable ? 'none' : 'unavailable';
    }
    return {
      peerKey,
      peerFingerprint: peerKey.length > 0 ? fingerprintOf(peerKey) : '',
      ourFingerprint: await this.accountFingerprint(),
      ourWords,
      theirWords,
      verifiedKey,
      state,
    };
  }

  /** The verification badge per buddy for the list, in ONE call. Only buddies with a stored key appear.
   * Three outcomes, and the third matters: 'verified' (checked and matching), 'changed' (positive
   * mismatch), 'stale' (pinned but not checkable right now). A stale pin must never render as a green
   * check, or a user reads reassurance the app cannot actually back. */
  async buddyVerifyStates(usernames: readonly string[]): Promise<Record<string, BuddyVerifyBadge>> {
    const map = await this.loadBuddyMap();
    const handles = await this.loadConvHandles();
    const out: Record<string, BuddyVerifyBadge> = {};
    for (const name of usernames) {
      const u = name.trim().toLowerCase();
      const vk = map[u]?.vk ?? '';
      if (vk.length === 0 || map[u]?.removed === true) {
        continue;
      }
      const peerKey = this.buddyPeerKey(handles, u);
      out[name] = peerKey.length === 0 ? 'stale' : peerKey !== vk ? 'changed' : 'verified';
    }
    return out;
  }

  /** Record that the user compared the words and confirmed them: pin `peerKey` for this buddy and sync
   * it to our other devices. Refuses a key that does not MATCH what the conversation currently shows,
   * so a stale panel can never pin an attacker's key that arrived after it was rendered. */
  async markBuddyVerified(username: string, peerKey: string, expectedPrev = ''): Promise<boolean> {
    const u = username.trim().toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(peerKey)) {
      return false;
    }
    const handles = await this.loadConvHandles();
    if (this.buddyPeerKey(handles, u) !== peerKey) {
      return false; // the key on screen is no longer the key in the group: re-open and re-compare
    }
    const map = await this.loadBuddyMap();
    const existing = map[u];
    if (existing === undefined || existing.removed) {
      return false;
    }
    // The panel was rendered against a specific PRIOR pin (empty for a first verification). If a
    // sibling device changed it since, this tap was aimed at a screen that no longer describes the
    // world, so it must not commit. Cheap, and it closes the stale-panel re-trust race.
    if ((existing.vk ?? '') !== expectedPrev) {
      return false;
    }
    map[u] = { ...existing, vk: peerKey, v: this.now() };
    await this.saveBuddyMap(map);
    this.groupChannel?.syncBuddies();
    return true;
  }

  /** Drop the stored verification for a buddy (kept as a plain field clear; the record itself stays). */
  async clearBuddyVerified(username: string): Promise<void> {
    const u = username.trim().toLowerCase();
    const map = await this.loadBuddyMap();
    const existing = map[u];
    if (existing === undefined || existing.vk === undefined) {
      return;
    }
    const { vk: _vk, ...rest } = existing;
    map[u] = { ...rest, v: this.now() };
    await this.saveBuddyMap(map);
    this.groupChannel?.syncBuddies();
  }

  private historyKey(): string {
    return `history:${this.account}`;
  }

  /** Read the stored history-off flag into the cached field. Called once, inside unlock. */
  private async hydrateHistoryMode(): Promise<void> {
    this.historyOff = false;
    if (this.sessions === undefined) {
      return;
    }
    try {
      const rec = await this.sessions.load(this.historyKey());
      if (rec !== undefined) {
        const key = this.requireKey();
        const raw = await openUnder(key, rec.sealed, this.historyKey());
        this.historyOff = JSON.parse(dec.decode(raw)) === true;
      }
    } catch {
      this.historyOff = false; // an unreadable setting means the normal, durable mode
    }
    this.applyHistoryMode();
  }

  /** Push the resolved mode into the two stores that hold message content and conversation rows. */
  private applyHistoryMode(): void {
    this.keyvault.setEphemeral(this.historyOff);
    this.channels.setEphemeral(this.historyOff);
  }

  /** Whether this device is holding messages in memory only. */
  historyOffEnabled(): Promise<boolean> {
    return Promise.resolve(this.historyOff);
  }

  /** Turn history-off on or off for this device.
   *
   * Turning it ON also DESTROYS the message history already on this device, because leaving it there
   * would make the setting a promise the device does not keep. That is a crypto-erase (the wrapped
   * per-message keys go with the records), and it cannot be undone. Turning it OFF simply resumes
   * writing new messages to disk; whatever was held in memory stays in memory until the session ends. */
  async setHistoryOff(on: boolean, purgeExisting = true): Promise<void> {
    if (this.sessions === undefined) {
      return;
    }
    const key = this.requireKey();
    const sealed = await sealUnder(key, enc.encode(JSON.stringify(on)), this.historyKey());
    await this.sessions.save({ conversationId: this.historyKey(), sealed });
    this.historyOff = on;
    this.applyHistoryMode();
    if (on && purgeExisting) {
      await this.keyvault.purgeDurable();
      await this.channels.purgeDurable();
    }
  }

  private buddiesKey(): string {
    return `buddies:${this.account}`;
  }

  private selfGroupsKey(): string {
    return `selfgroups:${this.account}`;
  }

  private closedChannelsKey(): string {
    return `closedchannels:${this.account}`;
  }

  /** Conversation ids the user CLOSED for good on this device (MSK-sealed, per account). The reconnect
   * restore skips them so a parallel tab's reseal cannot resurrect a closed conversation. DELIBERATELY
   * uncached (unlike the hot-path selfgroups set): the set is read only at connect and close time, and
   * a fresh read is what lets a running tab learn of a sibling tab's close at its next reconnect. */
  private async loadClosedChannelIds(): Promise<Set<string>> {
    if (this.sessions === undefined || this.account === null) {
      return new Set();
    }
    const rec = await this.sessions.load(this.closedChannelsKey());
    if (rec === undefined) {
      return new Set();
    }
    try {
      const ids: unknown = JSON.parse(dec.decode(await openUnder(this.requireKey(), rec.sealed, this.closedChannelsKey())));
      return new Set(Array.isArray(ids) ? ids.filter((x): x is string => typeof x === 'string') : []);
    } catch {
      return new Set(); // another account's record on this device, or a corrupt blob
    }
  }

  /** Add ONE id to the closed set with a cross-tab-safe read-modify-write: two tabs closing different
   * conversations concurrently must both stick (a blind RMW over a stale snapshot loses one). */
  private async recordClosedChannelId(conversationId: string): Promise<void> {
    if (this.sessions === undefined || this.account === null) {
      return;
    }
    const doRecord = async (): Promise<void> => {
      const fresh = await this.loadClosedChannelIds();
      fresh.add(conversationId);
      const sealed = await sealUnder(this.requireKey(), enc.encode(JSON.stringify([...fresh])), this.closedChannelsKey());
      await this.sessions?.save({ conversationId: this.closedChannelsKey(), sealed });
    };
    if (typeof navigator !== 'undefined' && navigator.locks !== undefined) {
      await navigator.locks.request(this.closedChannelsKey(), doRecord);
    } else {
      await doRecord(); // no Web Locks (a bare test runtime): single-writer is a safe assumption there
    }
  }

  /** The set of conversation ids that have EVER been recognized as one of our hidden own-devices
   * self-groups, sealed under the MSK. It exists because the live isSelfConversation predicate is null
   * during the brief window before a freshly-provisioned device's certificate settles, and a channel
   * summary minted in that window (an older-build artifact, or a self-group whose Welcome was processed
   * pre-cert) would then slip past the single-id self-filter and render as an orphaned "Note to Self"
   * row. Recording every id that ever classified self and excluding all of them keeps such a row hidden
   * regardless of the live predicate's timing. An id enters only when isSelfConversation is true, so a
   * peer conversation can never be in the set. */
  // In-memory copy of the recorded set, loaded once per unlock. listChannels sits on the inbound-message
  // and navigation hot paths, so it must not pay an IDB read + XChaCha decrypt per call; the worker is
  // the sole writer of this account's store, so the cache cannot go stale under another writer. Null =
  // not loaded yet (or account switched); reset wherever selfConvId resets.
  private selfGroupIdsCache: Set<string> | null = null;
  /** History-off (ephemeral) mode for THIS device, resolved once at unlock. See setHistoryOff. */
  private historyOff = false;
  /** Away-reply cooldowns held in memory while history-off, so the cooldown still works without
   * leaving a durable per-conversation timestamp (which is proof a conversation happened at time T). */
  private readonly awayDedupeMem = new Map<string, number>();

  private async loadSelfGroupIds(): Promise<Set<string>> {
    if (this.selfGroupIdsCache !== null) {
      return this.selfGroupIdsCache;
    }
    if (this.sessions === undefined || this.account === null) {
      return new Set();
    }
    const rec = await this.sessions.load(this.selfGroupsKey());
    if (rec === undefined) {
      this.selfGroupIdsCache = new Set();
      return this.selfGroupIdsCache;
    }
    try {
      const ids: unknown = JSON.parse(dec.decode(await openUnder(this.requireKey(), rec.sealed, this.selfGroupsKey())));
      this.selfGroupIdsCache = new Set(Array.isArray(ids) ? ids.filter((x): x is string => typeof x === 'string') : []);
    } catch {
      this.selfGroupIdsCache = new Set(); // another account's record on this device, or a corrupt blob
    }
    return this.selfGroupIdsCache;
  }

  private async recordSelfGroupIds(ids: ReadonlySet<string>): Promise<void> {
    if (this.sessions === undefined || this.account === null) {
      return;
    }
    this.selfGroupIdsCache = new Set(ids); // keep the hot-path cache current with the durable copy
    const sealed = await sealUnder(this.requireKey(), enc.encode(JSON.stringify([...ids])), this.selfGroupsKey());
    await this.sessions.save({ conversationId: this.selfGroupsKey(), sealed });
  }

  private welcomeOutboxKey(): string {
    return `welcome-outbox:${this.account ?? ''}`;
  }

  /** The pending-Welcome outbox, sealed under the MSK per account. A founding Welcome is published
   * exactly once into a bus that holds it only in memory (and clamps its TTL to a day), so a gateway
   * restart, a crash, or a sibling that stays offline long enough loses it with nobody informed. The
   * SENDER keeps its own durable copy and re-publishes on reconnect; the gateway stays amnesiac, so
   * nothing about the at-rest threat model changes (this blob is sealed device-local, like the buddy
   * list). See [self-group split, 2026-08-01]. */
  private async loadWelcomeOutbox(): Promise<PendingWelcome[]> {
    if (this.sessions === undefined || this.account === null) {
      return [];
    }
    const rec = await this.sessions.load(this.welcomeOutboxKey());
    if (rec === undefined) {
      return [];
    }
    try {
      const raw: unknown = JSON.parse(dec.decode(await openUnder(this.requireKey(), rec.sealed, this.welcomeOutboxKey())));
      if (!Array.isArray(raw)) {
        return [];
      }
      return raw.filter((e): e is PendingWelcome => {
        const c = e as Partial<PendingWelcome> | null;
        return (
          c !== null &&
          typeof c.conversationId === 'string' &&
          typeof c.deviceKey === 'string' &&
          typeof c.welcomeHex === 'string' &&
          typeof c.createdAt === 'number'
        );
      });
    } catch {
      return []; // another account's record on this device, or a corrupt blob
    }
  }

  private async saveWelcomeOutbox(entries: readonly PendingWelcome[]): Promise<void> {
    if (this.sessions === undefined || this.account === null) {
      return;
    }
    const sealed = await sealUnder(this.requireKey(), enc.encode(JSON.stringify(entries)), this.welcomeOutboxKey());
    await this.sessions.save({ conversationId: this.welcomeOutboxKey(), sealed });
  }

  /** The buddy list, sealed under the MSK per account. Stored as a per-username map with a change version
   * and a tombstone flag (removed buddies are kept as tombstones, never deleted) so that a removal
   * propagates to our other devices instead of looking like an absence an older add could resurrect. A
   * legacy `Buddy[]` blob from before the sync feature still loads (each entry gets version 0). */
  private async loadBuddyMap(): Promise<BuddyMap> {
    if (this.sessions === undefined || this.account === null) {
      return {};
    }
    const key = this.requireKey();
    const rec = await this.sessions.load(this.buddiesKey());
    if (rec === undefined) {
      return {};
    }
    try {
      return normalizeBuddyMap(JSON.parse(dec.decode(await openUnder(key, rec.sealed, this.buddiesKey()))));
    } catch {
      return {}; // another account's record on this device, or a corrupt blob
    }
  }

  private async saveBuddyMap(map: BuddyMap): Promise<void> {
    if (this.sessions === undefined || this.account === null) {
      return;
    }
    const key = this.requireKey();
    const sealed = await sealUnder(key, enc.encode(JSON.stringify(map)), this.buddiesKey());
    await this.sessions.save({ conversationId: this.buddiesKey(), sealed });
  }

  /** The present (non-tombstoned) buddies, in the order they were first added. */
  async listBuddies(): Promise<readonly Buddy[]> {
    const map = await this.loadBuddyMap();
    return Object.entries(map)
      .filter(([, e]) => !e.removed)
      .map(([username, e]) => ({ username, addedAt: e.addedAt, group: e.group }));
  }

  /** Add a normalized username to the buddy list (deduped) under `group` (default 'Buddies') and sync it
   * to our other devices. Returns the updated present list. */
  async addBuddy(username: string, group?: string): Promise<readonly Buddy[]> {
    const u = username.trim().toLowerCase();
    if (u.length === 0) {
      return this.listBuddies();
    }
    // The group goes through the SAME sanitizer as addGroup, so a buddy can never be filed under a
    // spelling of a group that the group store itself would have truncated or trimmed differently (the
    // two diverging forks the tree into a phantom folder).
    const gClean = group !== undefined ? sanitizeGroupName(group) : '';
    const g = gClean.length > 0 ? gClean : DEFAULT_GROUP;
    const map = await this.loadBuddyMap();
    if (map[u] !== undefined && !map[u].removed) {
      return this.listBuddies(); // already a buddy: no change, no version bump
    }
    map[u] = { addedAt: Math.floor(this.now() / 1000), v: this.now(), removed: false, group: g };
    await this.saveBuddyMap(map);
    this.groupChannel?.syncBuddies(); // push to our own devices over the hidden self-group
    return this.listBuddies();
  }

  /** Move a buddy to a different group (last-writer-wins across devices). Returns the updated list. */
  async setBuddyGroup(username: string, group: string): Promise<readonly Buddy[]> {
    const u = username.trim().toLowerCase();
    // Same sanitizer as addGroup, so a move can never fork the tree under a differently-spelled name.
    const gClean = sanitizeGroupName(group);
    const g = gClean.length > 0 ? gClean : DEFAULT_GROUP;
    const map = await this.loadBuddyMap();
    const existing = map[u];
    if (existing === undefined || existing.removed || existing.group === g) {
      return this.listBuddies();
    }
    map[u] = { ...existing, group: g, v: this.now() };
    await this.saveBuddyMap(map);
    this.groupChannel?.syncBuddies();
    return this.listBuddies();
  }

  /** Remove a username from the buddy list (as a tombstone, so the removal propagates) and sync it.
   * Returns the updated present list. */
  async removeBuddy(username: string): Promise<readonly Buddy[]> {
    const u = username.trim().toLowerCase();
    const map = await this.loadBuddyMap();
    const existing = map[u];
    if (existing === undefined || existing.removed) {
      return this.listBuddies(); // not currently a buddy
    }
    map[u] = { ...existing, v: this.now(), removed: true };
    await this.saveBuddyMap(map);
    this.groupChannel?.syncBuddies();
    return this.listBuddies();
  }

  /** The buddy-list control frame for the hidden self-group: the full per-username map (present buddies
   * AND tombstones, each with its change version). The groupchannel publishes this when the self-group
   * forms or a sibling joins. Returns null before login or when the sealed store is unavailable. */
  async buddiesFrame(): Promise<Uint8Array | null> {
    if (this.sessions === undefined || this.account === null) {
      return null;
    }
    return enc.encode(JSON.stringify({ buddies: await this.loadBuddyMap() }));
  }

  /** Adopt a buddy-list frame from one of THIS account's own devices (a sibling, crypto-authenticated by
   * from_own_account). Per-buddy last-writer-wins: for each username, adopt the incoming entry only if its
   * version is strictly newer than ours (so adds and removes both converge, and a stale frame cannot undo
   * a newer change). On any change, re-seal, re-broadcast (terminating since an equal version is ignored),
   * and signal the UI to re-render. */
  async adoptBuddies(payload: Uint8Array): Promise<void> {
    if (this.sessions === undefined || this.account === null) {
      return;
    }
    let incoming: BuddyMap;
    try {
      const parsed = JSON.parse(dec.decode(payload)) as { buddies?: unknown };
      incoming = normalizeBuddyMap(parsed.buddies);
    } catch {
      return;
    }
    const local = await this.loadBuddyMap();
    let changed = false;
    // Same future-clamp as adoptGroups: a version running ahead of the local clock beyond the skew
    // allowance would win LWW forever, so it is refused rather than adopted.
    const maxV = this.now() + CRDT_MAX_FUTURE_MS;
    for (const [u, inEnt] of Object.entries(incoming)) {
      if (inEnt.v > maxV) {
        continue;
      }
      const cur = local[u];
      // Per-buddy last-writer-wins by version, with a deterministic tiebreak: on the same version a
      // removal beats an add, so a same-millisecond add-vs-remove of one buddy on two devices converges to
      // removed on both rather than each keeping its own. (Two adds at one version agree on presence, so a
      // cosmetic addedAt difference is harmless.)
      let newer = cur === undefined || inEnt.v > cur.v || (inEnt.v === cur.v && inEnt.removed && !cur.removed);
      // Same-version, same-liveness tiebreak for the verified key (mirrors the group-alias tiebreak):
      // when two devices stamp the same millisecond, the lexically larger vk wins on BOTH, so they
      // converge on one answer instead of each keeping its own. An absent vk never beats a present one
      // here; a genuine unverify carries a newer version and wins the plain LWW race above.
      if (!newer && cur !== undefined && inEnt.v === cur.v && inEnt.removed === cur.removed) {
        newer = (inEnt.vk ?? '') > (cur.vk ?? '');
      }
      if (newer) {
        local[u] = inEnt;
        changed = true;
      }
    }
    if (!changed) {
      return;
    }
    await this.saveBuddyMap(local);
    this.groupChannel?.syncBuddies(); // converge the rest of our devices; an equal version is a no-op, so it terminates
    this.live?.pushEvent('buddies-updated', {});
  }

  // --- buddy GROUP list (the named folders buddies are filed under) ---------------------------------
  // Stored and synced exactly like the buddy list: an MSK-sealed per-name map with a change version and a
  // tombstone flag, published ONLY to the hidden self-group so an empty group you create (or a group you
  // delete) converges across your own devices. The buddy map alone cannot represent an empty group, so
  // this list is what backs "Add Group" / "Delete Group" in Buddy List Setup.

  private groupsKey(): string {
    return `groups:${this.account}`;
  }

  private async loadGroupMap(): Promise<GroupMap> {
    if (this.sessions === undefined || this.account === null) {
      return {};
    }
    const key = this.requireKey();
    const rec = await this.sessions.load(this.groupsKey());
    if (rec === undefined) {
      return {};
    }
    try {
      return normalizeGroupMap(JSON.parse(dec.decode(await openUnder(key, rec.sealed, this.groupsKey()))));
    } catch {
      return {}; // another account's record on this device, or a corrupt blob
    }
  }

  private async saveGroupMap(map: GroupMap): Promise<void> {
    if (this.sessions === undefined || this.account === null) {
      return;
    }
    const key = this.requireKey();
    const sealed = await sealUnder(key, enc.encode(JSON.stringify(map)), this.groupsKey());
    await this.sessions.save({ conversationId: this.groupsKey(), sealed });
  }

  /** The two built-in display labels: what the default "Buddies" group and the "Blocked" drop are
   * currently called (their internal keys never change, only these labels). */
  private groupLabels(map: GroupMap): { def: string; blocked: string } {
    const d = map[RK_DEFAULT]?.n;
    const b = map[RK_BLOCKED]?.n;
    return {
      def: d !== undefined && d.length > 0 ? d : DEFAULT_GROUP,
      blocked: b !== undefined && b.length > 0 ? b : BLOCKED_LABEL_FALLBACK,
    };
  }

  /** The present (non-tombstoned) groups, in their sort order then by name, BRACKETED by the two
   * built-ins: the default group first (role 'default') and the Blocked drop last (role 'blocked'),
   * each under its current display label. The built-ins are always present so every user has them; the
   * reserved alias entries that carry their labels never surface as groups themselves. */
  async listGroups(): Promise<readonly GroupSummary[]> {
    const map = await this.loadGroupMap();
    const labels = this.groupLabels(map);
    const customs = Object.entries(map)
      .filter(([name, e]) => !e.removed && !name.includes('\u0000'))
      .sort(([an, a], [zn, z]) => a.order - z.order || an.localeCompare(zn))
      .map(([name]) => ({ name }));
    return [{ name: labels.def, role: 'default' as const }, ...customs, { name: labels.blocked, role: 'blocked' as const }];
  }

  /** Create a named group (deduped) and sync it to our other devices. The built-in groups are always
   * present, so a name matching either of their current labels (or the internal default key) is a no-op:
   * two folders answering to one name would be indistinguishable. Returns the updated present list. */
  async addGroup(name: string): Promise<readonly GroupSummary[]> {
    const g = sanitizeGroupName(name);
    const labels = this.groupLabels(await this.loadGroupMap());
    if (g.length === 0 || g === DEFAULT_GROUP || g === labels.def || g === labels.blocked) {
      return this.listGroups();
    }
    const map = await this.loadGroupMap();
    if (map[g] !== undefined && !map[g].removed) {
      return this.listGroups(); // already a group: no change, no version bump
    }
    const maxOrder = Object.values(map).reduce((m, e) => Math.max(m, e.order), 0);
    map[g] = { v: this.now(), removed: false, order: maxOrder + 1 };
    await this.saveGroupMap(map);
    this.groupChannel?.syncGroups();
    return this.listGroups();
  }

  /** Rename a built-in group: set the display label the default group or the Blocked drop goes by.
   * Label-only, so both keep working (buddies stay filed under the internal default key; blocks stay in
   * the block list) and the rename syncs to our other devices like any group change. A name colliding
   * with an existing group or the other built-in is refused (two folders, one name). */
  async renameGroup(role: 'default' | 'blocked', name: string): Promise<readonly GroupSummary[]> {
    const g = sanitizeGroupName(name);
    if (g.length === 0) {
      return this.listGroups();
    }
    const map = await this.loadGroupMap();
    const labels = this.groupLabels(map);
    const other = role === 'default' ? labels.blocked : labels.def;
    const collides =
      g === other ||
      (role !== 'default' && g === DEFAULT_GROUP) ||
      Object.entries(map).some(([n, e]) => !e.removed && !n.includes('\u0000') && n === g);
    if (collides) {
      return this.listGroups();
    }
    const key = role === 'default' ? RK_DEFAULT : RK_BLOCKED;
    map[key] = { v: this.now(), removed: false, order: 0, n: g };
    await this.saveGroupMap(map);
    this.groupChannel?.syncGroups();
    return this.listGroups();
  }

  /** Delete a group (as a tombstone, so the deletion propagates) and move any buddies filed under it back
   * to the default group. The built-in groups cannot be deleted. Returns the updated present list. */
  async deleteGroup(name: string): Promise<readonly GroupSummary[]> {
    const g = name.trim();
    if (g.length === 0 || g === DEFAULT_GROUP || g.includes('\u0000')) {
      return this.listGroups();
    }
    const map = await this.loadGroupMap();
    const existing = map[g];
    if (existing === undefined || existing.removed) {
      return this.listGroups(); // not currently a group
    }
    map[g] = { ...existing, v: this.now(), removed: true };
    await this.saveGroupMap(map);
    // Reassign buddies out of the deleted group so none render under a phantom header. Each move bumps its
    // own version and re-syncs the buddy list, so the reassignment converges on our other devices too.
    const buddies = await this.loadBuddyMap();
    let movedAny = false;
    for (const [u, ent] of Object.entries(buddies)) {
      if (!ent.removed && ent.group === g) {
        buddies[u] = { ...ent, group: DEFAULT_GROUP, v: this.now() };
        movedAny = true;
      }
    }
    if (movedAny) {
      await this.saveBuddyMap(buddies);
      this.groupChannel?.syncBuddies();
    }
    this.groupChannel?.syncGroups();
    return this.listGroups();
  }

  /** The group-list control frame for the hidden self-group: the full per-name map (present groups AND
   * tombstones). Returns null before login or when the sealed store is unavailable. */
  async groupsFrame(): Promise<Uint8Array | null> {
    if (this.sessions === undefined || this.account === null) {
      return null;
    }
    return enc.encode(JSON.stringify({ groups: await this.loadGroupMap() }));
  }

  /** Adopt a group-list frame from one of THIS account's own devices (crypto-authenticated by
   * from_own_account). Per-group last-writer-wins, mirroring adoptBuddies: adopt an incoming entry only if
   * its version is strictly newer, with the same tiebreak (on an equal version a deletion beats an add so
   * two devices converge to deleted). On any change, re-seal, re-broadcast (equal versions terminate it),
   * and signal the UI. */
  async adoptGroups(payload: Uint8Array): Promise<void> {
    if (this.sessions === undefined || this.account === null) {
      return;
    }
    let incoming: GroupMap;
    try {
      const parsed = JSON.parse(dec.decode(payload)) as { groups?: unknown };
      incoming = normalizeGroupMap(parsed.groups);
    } catch {
      return;
    }
    const local = await this.loadGroupMap();
    let changed = false;
    // No incoming version may run ahead of the local clock by more than the skew allowance: honest
    // devices stamp v = now(), so a far-future v (a badly wrong sibling clock, or a hostile frame) would
    // otherwise win LWW forever and permanently pin that key against every later honest write.
    const maxV = this.now() + CRDT_MAX_FUTURE_MS;
    for (const [name, inEnt] of Object.entries(incoming)) {
      if (inEnt.v > maxV) {
        continue;
      }
      const cur = local[name];
      const newer =
        cur === undefined ||
        inEnt.v > cur.v ||
        (inEnt.v === cur.v && inEnt.removed && !cur.removed) ||
        // Same-version alias writes tiebreak lexically (larger label wins) so two devices that renamed a
        // built-in in the same millisecond still converge on ONE label instead of each keeping its own.
        (inEnt.v === cur.v && inEnt.removed === cur.removed && inEnt.n !== undefined && cur.n !== undefined && inEnt.n > cur.n);
      if (newer) {
        local[name] = inEnt;
        changed = true;
      }
    }
    if (!changed) {
      return;
    }
    await this.saveGroupMap(local);
    this.groupChannel?.syncGroups();
    this.live?.pushEvent('groups-updated', {});
  }

  private blockedKey(): string {
    return `blocked:${this.account}`;
  }

  /** The sealed block list. Stored as entries {k: key, u?: username} so the buddy surfaces can show WHO
   * is blocked, not just a key fingerprint; a legacy plain-string entry (pre-username builds) still
   * loads as a key-only block. The username is display metadata only: every block DECISION (gating,
   * roster checks) keys on the device key, which a peer cannot swap. */
  private async loadBlockedEntries(): Promise<ReadonlyArray<{ k: string; u?: string }>> {
    if (this.sessions === undefined || this.account === null) {
      return [];
    }
    const key = this.requireKey();
    const rec = await this.sessions.load(this.blockedKey());
    if (rec === undefined) {
      return [];
    }
    try {
      const parsed = JSON.parse(dec.decode(await openUnder(key, rec.sealed, this.blockedKey()))) as unknown;
      if (!Array.isArray(parsed)) {
        return [];
      }
      const out: Array<{ k: string; u?: string }> = [];
      for (const e of parsed) {
        if (typeof e === 'string') {
          out.push({ k: e }); // legacy key-only entry
        } else if (typeof e === 'object' && e !== null && typeof (e as { k?: unknown }).k === 'string') {
          const u = (e as { u?: unknown }).u;
          out.push(typeof u === 'string' ? { k: (e as { k: string }).k, u } : { k: (e as { k: string }).k });
        }
      }
      return out;
    } catch {
      return [];
    }
  }

  private async listBlockedKeys(): Promise<readonly string[]> {
    return (await this.loadBlockedEntries()).map((e) => e.k);
  }

  private async saveBlocked(list: ReadonlyArray<{ k: string; u?: string }>): Promise<void> {
    if (this.sessions === undefined || this.account === null) {
      return;
    }
    const key = this.requireKey();
    const sealed = await sealUnder(key, enc.encode(JSON.stringify(list)), this.blockedKey());
    await this.sessions.save({ conversationId: this.blockedKey(), sealed });
  }

  private async blockKeys(keys: readonly string[], username?: string): Promise<void> {
    const entries = [...(await this.loadBlockedEntries())];
    for (const k of keys) {
      const existing = entries.find((e) => e.k === k);
      if (existing === undefined) {
        entries.push(username !== undefined ? { k, u: username } : { k });
      } else if (existing.u === undefined && username !== undefined) {
        entries[entries.indexOf(existing)] = { k, u: username }; // backfill the name on a legacy entry
      }
    }
    await this.saveBlocked(entries);
  }

  /** True when there are blocked peers and EVERY one of them is blocked (used to drop blocked Welcomes). */
  private async isBlockedRoster(peers: readonly string[]): Promise<boolean> {
    if (peers.length === 0) {
      return false;
    }
    const set = new Set(await this.listBlockedKeys());
    return peers.every((k) => set.has(k));
  }

  /** The blocked contacts, each with a short fingerprint and, when the block came from a conversation
   * tagged with a buddy handle, the username, so the buddy list can show WHO is blocked. */
  async listBlocked(): Promise<readonly { key: string; fingerprint: string; username?: string }[]> {
    return (await this.loadBlockedEntries()).map((e) => ({
      key: e.k,
      fingerprint: fingerprintOf(e.k),
      ...(e.u !== undefined ? { username: e.u } : {}),
    }));
  }

  /** The username a conversation was opened with (its tagged handle), or null. The tag map is
   * username -> conversation, so this is the reverse lookup; ambiguity (a multi-buddy group tagged
   * with several handles) resolves to null rather than guessing. */
  private async handleForConversation(conversationId: string): Promise<string | null> {
    const handles = await this.loadConvHandles();
    const matches = Object.keys(handles).filter((u) => handles[u] === conversationId);
    return matches.length === 1 ? (matches[0] ?? null) : null;
  }

  /** Block everyone in the open conversation and leave it: their keys go on the block list (with the
   * buddy handle this conversation was tagged with, when unambiguous, so the block list reads as a
   * name), we forget the session, and the channel is removed. Best-effort: a blocked party can make a
   * new key. */
  async blockConversation(conversationId: string): Promise<void> {
    if (this.groupChannel === null) {
      return;
    }
    // A self-group must never be blocked: its "peer roster" is our OWN sibling devices, and blocking
    // them silently drops future self-group Welcomes, durably stranding every later device join. A
    // ghost row that classifies self (e.g. one recognized only after the cert settled) gets the
    // hide-and-record treatment instead. Residual: in the pre-cert window the union can miss and a
    // block goes through; unblock recovers.
    const recorded = await this.loadSelfGroupIds();
    if (
      recorded.has(conversationId) ||
      this.groupChannel.selfConversationId() === conversationId ||
      this.groupChannel.isSelfConversationId(conversationId)
    ) {
      recorded.add(conversationId);
      await this.recordSelfGroupIds(recorded);
      await this.channels.delete(conversationId).catch(() => {
        /* best-effort cleanup of the self-group's stale summary */
      });
      return;
    }
    const username = await this.handleForConversation(conversationId);
    await this.blockKeys(this.groupChannel.peerRoster(conversationId), username ?? undefined);
    // The REAL close (R10): drop the group's MLS state and only THEN record the id durably. The old
    // bare leave only removed the JS session (the reconnect restore rebuilt it every time, so a
    // blocked conversation quietly lived on). NOTE this makes Block PERMANENT for the conversation:
    // unblock restores contact from a fresh Welcome, and never this closed copy.
    try {
      await this.groupChannel.closeConversation(conversationId);
      await this.recordClosedChannelId(conversationId);
    } catch {
      // The wasm refused (an own-devices or unsettled-classification group): never destroy it. Hide
      // and record it as self instead, exactly like the guard branch above.
      const rec = await this.loadSelfGroupIds();
      rec.add(conversationId);
      await this.recordSelfGroupIds(rec);
    }
    await this.channels.delete(conversationId).catch(() => {
      /* best-effort channel cleanup */
    });
  }

  /** REMOVE one channel from this device for good, WITHOUT blocking anyone: the way to retire a dead
   * or abandoned conversation (its roster can include our own sibling keys, which must never land on
   * the block list). Self-classified ids get the hide-and-record treatment instead. Local only; the
   * group is never notified, and stored messages stay until their lifetimes end. */
  async removeConversation(conversationId: string): Promise<void> {
    if (this.groupChannel === null) {
      return;
    }
    const recorded = await this.loadSelfGroupIds();
    if (
      recorded.has(conversationId) ||
      this.groupChannel.selfConversationId() === conversationId ||
      this.groupChannel.isSelfConversationId(conversationId)
    ) {
      recorded.add(conversationId);
      await this.recordSelfGroupIds(recorded);
      await this.channels.delete(conversationId).catch(() => {
        /* best-effort cleanup of the self-group's stale summary */
      });
      return;
    }
    try {
      await this.groupChannel.closeConversation(conversationId);
      await this.recordClosedChannelId(conversationId);
    } catch {
      // The wasm refused (an own-devices or unsettled-classification group): never destroy it. Hide
      // and record it as self instead, exactly like the guard branch above.
      const rec = await this.loadSelfGroupIds();
      rec.add(conversationId);
      await this.recordSelfGroupIds(rec);
    }
    await this.channels.delete(conversationId).catch(() => {
      /* best-effort channel cleanup */
    });
  }

  /** Remove a key from the block list; returns the updated list. */
  async unblock(key: string): Promise<readonly { key: string; fingerprint: string; username?: string }[]> {
    await this.saveBlocked((await this.loadBlockedEntries()).filter((e) => e.k !== key));
    return this.listBlocked();
  }

  private presenceOnKey(): string {
    return `presence-on:${this.account}`;
  }

  /** Whether this account shares opt-in presence (online/away/idle) with buddies. Off by default. */
  async getPresenceEnabled(): Promise<boolean> {
    if (this.sessions === undefined || this.account === null) {
      return false;
    }
    const key = this.requireKey();
    const rec = await this.sessions.load(this.presenceOnKey());
    if (rec === undefined) {
      return false;
    }
    try {
      return JSON.parse(dec.decode(await openUnder(key, rec.sealed, this.presenceOnKey()))) === true;
    } catch {
      return false;
    }
  }

  /** Turn presence sharing on or off (sealed, so it survives a reload). */
  async setPresenceEnabled(on: boolean): Promise<void> {
    if (this.sessions === undefined || this.account === null) {
      return;
    }
    const key = this.requireKey();
    const sealed = await sealUnder(key, enc.encode(JSON.stringify(on)), this.presenceOnKey());
    await this.sessions.save({ conversationId: this.presenceOnKey(), sealed });
  }

  private notifyOnKey(): string {
    return `notify-on:${this.account}`;
  }

  /** Whether in-app notifications (toasts, sounds, buddy sign-on) are on. Defaults ON. */
  async getNotifyEnabled(): Promise<boolean> {
    if (this.sessions === undefined || this.account === null) {
      return true;
    }
    const key = this.requireKey();
    const rec = await this.sessions.load(this.notifyOnKey());
    if (rec === undefined) {
      return true; // default on
    }
    try {
      return JSON.parse(dec.decode(await openUnder(key, rec.sealed, this.notifyOnKey()))) !== false;
    } catch {
      return true;
    }
  }

  /** Turn in-app notifications on or off (sealed). */
  async setNotifyEnabled(on: boolean): Promise<void> {
    if (this.sessions === undefined || this.account === null) {
      return;
    }
    const key = this.requireKey();
    const sealed = await sealUnder(key, enc.encode(JSON.stringify(on)), this.notifyOnKey());
    await this.sessions.save({ conversationId: this.notifyOnKey(), sealed });
  }

  private appearanceKey(): string {
    return `theme:${this.account}`;
  }

  /** The device-local appearance (chosen theme + validated per-user token tweaks). Returns the raw parsed
   * value (or null when unset); the caller sanitizes it. Appearance is DEVICE-LOCAL and never synced. */
  async getAppearance(): Promise<unknown> {
    if (this.sessions === undefined || this.account === null) {
      return null;
    }
    const key = this.requireKey();
    const rec = await this.sessions.load(this.appearanceKey());
    if (rec === undefined) {
      return null;
    }
    try {
      return JSON.parse(dec.decode(await openUnder(key, rec.sealed, this.appearanceKey()))) as unknown;
    } catch {
      return null;
    }
  }

  /** Persist the appearance (sealed under the MSK, so it survives a reload). Device-local. */
  async setAppearance(value: unknown): Promise<void> {
    if (this.sessions === undefined || this.account === null) {
      return;
    }
    const key = this.requireKey();
    const sealed = await sealUnder(key, enc.encode(JSON.stringify(value)), this.appearanceKey());
    await this.sessions.save({ conversationId: this.appearanceKey(), sealed });
  }

  /** The away text to auto-reply with for `conversationId`, or null when away is off, the message is
   * empty, or the per-conversation cooldown has not elapsed. Records the reply time on a hit so the
   * cooldown applies. The away text lives only on the device; the dedupe state is sealed under the MSK. */
  async awayReplyText(conversationId: string, peerName: string): Promise<string | null> {
    const id = await this.getIdentity();
    if (!id.away.enabled || id.away.message.trim().length === 0) {
      return null;
    }
    const now = this.now();
    const last = await this.awayDedupeAt(conversationId);
    if (last !== null && now - last < AWAY_COOLDOWN_MS) {
      return null;
    }
    await this.setAwayDedupe(conversationId, now);
    // Substitute the AIM-style tokens now, on this device: %n = the buddy we are replying to, %d/%t = now.
    return substituteSpecials(id.away.message, { name: peerName, at: now });
  }

  private awayDedupeAad(conversationId: string): string {
    return `awaydedupe:${conversationId}`;
  }

  private async awayDedupeAt(conversationId: string): Promise<number | null> {
    if (this.historyOff) {
      return this.awayDedupeMem.get(conversationId) ?? null; // cooldown without a durable timestamp
    }
    if (this.sessions === undefined) {
      return null;
    }
    const key = this.requireKey();
    const aad = this.awayDedupeAad(conversationId);
    const rec = await this.sessions.load(aad);
    if (rec === undefined) {
      return null;
    }
    try {
      const o = JSON.parse(dec.decode(await openUnder(key, rec.sealed, aad))) as { at?: number };
      return typeof o.at === 'number' ? o.at : null;
    } catch {
      return null;
    }
  }

  private async setAwayDedupe(conversationId: string, at: number): Promise<void> {
    if (this.historyOff) {
      // A durable per-conversation timestamp is proof a conversation happened at time T, so in
      // history-off mode the cooldown lives in memory for the session instead.
      this.awayDedupeMem.set(conversationId, at);
      return;
    }
    if (this.sessions === undefined) {
      return;
    }
    const key = this.requireKey();
    const aad = this.awayDedupeAad(conversationId);
    const sealed = await sealUnder(key, enc.encode(JSON.stringify({ at })), aad);
    await this.sessions.save({ conversationId: aad, sealed });
  }

  /** This device's copy of the account recovery seed (hex), or '' if it does not hold one. ONLY the
   * registering/seed-holder device holds the seed; a device that joins by provisioning never learns it
   * (model b) and gets '', which makes its identity UNAUTHORIZED until it adopts a certificate. This is
   * read-only: it never creates a seed (creation is the explicit ensureAccountSeed at registration). */
  private async loadAccountSeed(): Promise<string> {
    if (this.aakSeedHex !== null) {
      return this.aakSeedHex;
    }
    const key = this.requireKey();
    const rec = await this.sessions?.load(this.aakKey());
    if (rec === undefined) {
      return ''; // a provisioned device, or before registration created the seed
    }
    const seed = await openUnder(key, rec.sealed, this.aakKey());
    this.aakSeedHex = toHexStr(seed);
    return this.aakSeedHex;
  }

  /** Create the account recovery seed if absent: generate 32 random bytes, MSK-seal them, and stash the
   * value for a ONE-TIME display to the user. Called at registration, BEFORE connecting the gateway, so
   * the first device becomes the AAK-rooted seed-holder. A no-op if a seed already exists. The seed is
   * never sent to the server; it is the root of device authorization. */
  async ensureAccountSeed(): Promise<void> {
    const key = this.requireKey();
    if ((await this.sessions?.load(this.aakKey())) !== undefined) {
      return; // already provisioned this device as the seed-holder
    }
    const seed = randomBytes(32);
    const sealed = await sealUnder(key, seed, this.aakKey());
    await this.sessions?.save({ conversationId: this.aakKey(), sealed });
    this.aakSeedHex = toHexStr(seed);
    this.freshRecoverySecret = this.aakSeedHex; // show it once at registration
  }

  /** The recovery secret to display ONCE, right after it was first created this session, else null. */
  recoverySecret(): Promise<string | null> {
    const s = this.freshRecoverySecret;
    this.freshRecoverySecret = null;
    return Promise.resolve(s);
  }

  /** SEED-HOLDER: open a short add-a-device window for this account (model b provisioning). */
  async openProvisioningWindow(): Promise<void> {
    await this.requireGroup().openProvisioningWindow(this.requireAccount());
  }

  /** NEW DEVICE: begin being added to this account; waits for the seed-holder and shows six words. */
  async joinDevice(): Promise<void> {
    await this.requireGroup().joinDevice(this.requireAccount());
  }

  /** SEED-HOLDER: confirm the six words matched and grant the pending device. */
  confirmProvisioning(): Promise<void> {
    this.requireGroup().confirmProvisioning();
    return Promise.resolve();
  }

  /** SEED-HOLDER: dismiss the add-a-device window without authorizing. */
  closeProvisioning(): Promise<void> {
    this.requireGroup().closeProvisioning();
    return Promise.resolve();
  }

  /** NEW DEVICE (QR): start listening and return the pairing QR payload for the user to display. */
  startQrPairing(): Promise<string> {
    return this.requireGroup().startQrPairing();
  }

  /** SEED-HOLDER (scan): certify the scanned device and seal the grant to its ephemeral key. */
  grantScannedDevice(qrPayload: string): Promise<void> {
    return this.requireGroup().grantScannedDevice(qrPayload);
  }

  /** Mint `n` fresh key packages (hex) for this device to publish to the directory, so peers can add
   * it to groups. After a provisioned device adopts its certificate, these carry the authorized
   * credential. The app publishes them via the account client (the last one is the last-resort). */
  async keyPackages(n: number): Promise<string[]> {
    return (await this.requireGroup().freshKeyPackages(n)).map((kp) => toHexStr(kp));
  }

  /** Recovery: make THIS device an authorized seed-holder by entering the account recovery secret.
   * Validates the secret, self-certifies at the account's current epoch (keeping the device key), and
   * seals the seed so the device stays a seed-holder across logins. The secret is never sent anywhere. */
  async recoverWithSeed(recoverySeedHex: string, epoch: number): Promise<{ ok: boolean; error?: string }> {
    const seedHex = recoverySeedHex.trim().toLowerCase().replace(/\s+/g, '');
    if (!/^[0-9a-f]{64}$/.test(seedHex)) {
      return { ok: false, error: 'that does not look like a recovery secret' };
    }
    try {
      await this.requireGroup().recoverWithSeed(seedHex, epoch);
    } catch {
      return { ok: false, error: 'could not recover with that secret' };
    }
    // Seal the seed so this device is a seed-holder (and group-ready) on later logins. The authorized
    // marker and the identity re-seal are handled by the channel's resealSelf during recovery.
    const key = this.requireKey();
    const sealed = await sealUnder(key, fromHexStr(seedHex), this.aakKey());
    await this.sessions?.save({ conversationId: this.aakKey(), sealed });
    this.aakSeedHex = seedHex;
    return { ok: true };
  }

  /** P6: bring this device up to the account's current certificate epoch (after a revoke bumped it).
   * A seed-holder behind the epoch re-certifies and re-publishes; a seedless device that cannot
   * self-certify is reported stale so the app prompts a reconnect. */
  syncEpoch(epoch: number): Promise<{ ready: boolean; stale: boolean }> {
    if (this.groupChannel === null) {
      return Promise.resolve({ ready: false, stale: false });
    }
    return this.groupChannel.syncEpoch(epoch);
  }

  /** This device's own certificate epoch (0 if unauthorized or before an identity exists). */
  certEpoch(): Promise<number> {
    return Promise.resolve(this.groupChannel?.certEpoch() ?? 0);
  }

  /** ADR-022 P7: mint a signed revocation record naming a device's signature key, so every device of
   * this account refuses it at the gate no matter what epoch it certifies itself at. Returns the record
   * as hex to publish, or null when this device holds no account key (only a seed-holder can sign one).
   * Never throws: a failure here must not block the server-side revoke, which is what cuts the sessions.
   */
  async revokeDeviceKey(deviceSigKeyHex: string, issuedSeq: number): Promise<string | null> {
    if (this.groupChannel === null) {
      return null;
    }
    try {
      return await this.groupChannel.revokeDeviceKey(deviceSigKeyHex, issuedSeq);
    } catch {
      return null;
    }
  }

  /** ADR-022 P7: accept revocation records fetched from the control plane. Each is verified against our
   * own account key inside the crypto layer; anything that does not check out is discarded. Returns how
   * many were new to this device. */
  async ingestRevocations(records: readonly string[]): Promise<number> {
    if (this.groupChannel === null) {
      return 0;
    }
    try {
      return await this.groupChannel.ingestRevocations(records);
    } catch {
      return 0;
    }
  }

  /** The revocation-record count (the derived epoch) and this device's certification floor. Diagnostic:
   * a pairing that fails at the gate is explained by these two numbers plus the leaf's own epoch. */
  revocationState(): Promise<{ revoked: number; floor: number }> {
    return Promise.resolve(this.groupChannel?.revocationState() ?? { revoked: 0, floor: 0 });
  }

  /** Whether we hold a verifying revocation record for this device key. */
  isDeviceRevoked(deviceSigKeyHex: string): Promise<boolean> {
    return Promise.resolve(this.groupChannel?.isDeviceRevoked(deviceSigKeyHex) ?? false);
  }

  /** A short fingerprint of this account's authorization key (AAK) — the stable account identity shared
   * across the user's devices. Backs the "verify me" fingerprint in the shareable contact QR. Empty for a
   * legacy/unauthorized identity or before the group is connected. */
  accountFingerprint(): Promise<string> {
    const aak = this.groupChannel?.accountKeyHex() ?? '';
    return Promise.resolve(aak.length > 0 ? fingerprintOf(aak) : '');
  }

  /** P5: add an already-enrolled device (a peer's or our own) to one conversation. */
  async addDevice(conversationId: string, target: DeviceTarget): Promise<void> {
    await this.requireGroup().addDevice(conversationId, target);
  }

  /** Cheap pre-check (no key-package claim): does this device have a sibling it should add right now?
   * Lets the app avoid claiming key packages on a peer-only roster change. */
  hasMissingSiblings(ownDeviceKeys: readonly string[]): Promise<boolean> {
    return Promise.resolve(this.groupChannel?.hasMissingSiblings(ownDeviceKeys) ?? false);
  }

  /** Heal a just-authorized device into the hidden self-group from the seed-holder's post-add poll (the
   * adder-scoped reconcileSiblings pre-check would otherwise gate it off on a non-lowest-keyed device).
   * Keeps the race-free election + failover; touches only self-conversations. A no-op with no GroupChannel. */
  reconcileSelf(ownDeviceKeys: readonly string[], candidates: readonly DeviceTarget[]): Promise<void> {
    return this.groupChannel?.reconcileSelf(ownDeviceKeys, candidates) ?? Promise.resolve();
  }

  /** Where a device stands relative to the hidden self-group: 'member' / 'pending' / 'absent' / 'none'.
   * Lets the seed-holder's post-add poll settle on membership and avoid burning key packages while pending. */
  selfSiblingState(deviceKey: string): Promise<'member' | 'pending' | 'absent' | 'none'> {
    return Promise.resolve(this.groupChannel?.selfSiblingState(deviceKey) ?? 'none');
  }

  /** Self-heal (ADR-022, H1): admit any of this account's authorized devices not yet in the open
   * conversation, so every signed-in device receives going forward. Idempotent, concurrency-safe (the
   * GroupChannel runs the designated-adder + staged add), and a no-op with no open conversation.
   * `candidates` are this account's devices with a claimed single-use key package (supplied as data so
   * this is structured-clone-safe across the worker boundary). */
  async reconcileSiblings(ownDeviceKeys: readonly string[], candidates: readonly DeviceTarget[]): Promise<void> {
    if (this.groupChannel === null) {
      return;
    }
    await this.groupChannel.reconcileSiblings(ownDeviceKeys, candidates);
  }

  /** P6 durable forward-secure exclusion: remove any revoked device still present in an open conversation
   * (the designated-adder + staged remove run in the GroupChannel). `revokedKeys` are the account's
   * revoked device keys, supplied as plain string arrays (structured-clone-safe across the worker
   * boundary; a removal needs no key package). Idempotent; a no-op with no open conversation. */
  async reconcileRemovals(ownDeviceKeys: readonly string[], revokedKeys: readonly string[]): Promise<void> {
    if (this.groupChannel === null) {
      return;
    }
    await this.groupChannel.reconcileRemovals(ownDeviceKeys, revokedKeys);
  }

  /** Whether the hidden self-group (a group of only our own devices, the private buddy-list sync channel)
   * is open. The app uses this so only the designated device creates it, and only once. Async to match the
   * worker-proxy boundary (the app awaits it). */
  hasSelfGroup(): Promise<boolean> {
    return Promise.resolve(this.groupChannel?.hasSelfGroup() ?? false);
  }

  /** Create the hidden self-group adding the given sibling devices. The app calls this on the designated
   * device when 2+ devices exist and no self-group is open yet. No-op without a live channel or targets. */
  async ensureSelfGroup(targets: readonly DeviceTarget[]): Promise<void> {
    if (this.groupChannel === null) {
      return;
    }
    await this.groupChannel.createSelfGroup(targets);
  }

  /** Open (creating if needed) the private "Note to Self" conversation: the hidden own-devices
   * self-group, surfaced to the user. On a single-device account this is a solo group; when a second
   * device folds in it starts syncing notes. Needs a live channel (the self-group rides the gateway). */
  /** The conversationId known to be the hidden self-group this session (set the moment Note to Self is
   * opened or recognized). openChannel consults it so re-opens (every send rebuilds the view) can never
   * mislabel the self chat, even when the cryptographic re-derivation misses. */
  private selfConvId: string | null = null;

  async openNoteToSelf(): Promise<TransmitModel> {
    if (this.groupChannel === null) {
      throw new Error('note to self needs a live session');
    }
    const id = await this.groupChannel.openSelfConversation();
    // openSelfConversation returns the hidden own-devices self-group by construction (an existing one or a
    // freshly minted solo one), so this view IS Note to Self regardless of how the cryptographic
    // self-classification races. Remember it and force it, so the window is always secure and typeable:
    // relying on selfConversationId() re-derivation is what left a just-created solo self-group briefly
    // unrecognized, opening a dead "UNKNOWN / OFFLINE" window the user could not type into. The cache
    // also covers every LATER re-open of the same conversation (each send re-opens the channel to
    // rebuild the view, and a missed re-derivation there killed the compose after the first message).
    this.selfConvId = id;
    return this.openChannel(id, { forceSelf: true });
  }

  /** P6: exclude a device from the open group, rotating its secrets (forward-secure exclusion). The
   * permanent server-side key burn is issued separately by the app via the account client; this is the
   * MLS half. Tolerant when the device is not a current member (nothing to rotate). */
  async excludeDevice(sigKeyHex: string): Promise<void> {
    if (this.groupChannel === null) {
      return;
    }
    // A revoked device is removed from EVERY conversation it is in (it belongs to all of this account's
    // conversations), so it cannot read future messages in any of them.
    await this.groupChannel.excludeEverywhere(sigKeyHex).catch(() => {
      /* the server burn alone still locks it out of the account */
    });
  }

  private requireAccount(): string {
    if (this.account === null) {
      throw new Error('locked');
    }
    return this.account;
  }

  /** Publish a file-transfer signal (the WebRTC handshake) to the group over the E2E channel. The file
   * bytes go peer-to-peer; the WebRTC connection itself lives in the app (main thread, where the API
   * exists), so this only relays the small JSON signals through the group. */
  sendFileSignal(conversationId: string, json: string): void {
    this.groupChannel?.sendFileSignal(conversationId, enc.encode(json));
  }

  /** Relay an inbound file-transfer signal to the app, tagged with the conversation it arrived in so the
   * app routes it to the right transfer (the app holds the WebRTC connection). */
  private relayFileSignal(conversationId: string, payload: Uint8Array): void {
    this.live?.pushEvent('file-signal', { conversationId, json: dec.decode(payload) });
  }

  /** Publish a call signal (the WebRTC handshake) to the group over the E2E channel. The audio/video
   * media goes peer-to-peer; the WebRTC connection lives in the app (main thread), so this only relays
   * the small JSON signals through the group. */
  sendCallSignal(conversationId: string, json: string): void {
    this.groupChannel?.sendCallSignal(conversationId, enc.encode(json));
  }

  /** Relay an inbound call signal to the app, tagged with the conversation it arrived in so the app
   * routes it to the right call (the app holds the WebRTC media connection). */
  private relayCallSignal(conversationId: string, payload: Uint8Array): void {
    this.live?.pushEvent('call-signal', { conversationId, json: dec.decode(payload) });
  }

  /** Restore our long-lived identity Conversation from the MSK-sealed store, or null on first run. */
  private async loadSelf(): Promise<GroupConversationLike | null> {
    if (this.live === undefined || this.sessions === undefined || this.mskRaw === null) {
      return null;
    }
    const rec = await this.sessions.load(this.selfKey());
    if (rec === undefined) {
      return null;
    }
    try {
      return this.live.restoreConversation(this.mskRaw, rec.sealed);
    } catch {
      // A corrupt or wrong-key blob must not wedge login; fall back to a fresh identity.
      return null;
    }
  }

  /** Persist our identity Conversation (signer) under the MSK on first creation. Create-if-absent:
   * never overwrite an existing identity, so a transient restore failure (which falls back to a
   * fresh in-memory identity) cannot permanently replace the stable durable one. */
  private async saveSelf(conv: GroupConversationLike): Promise<void> {
    if (this.live === undefined || this.sessions === undefined || this.mskRaw === null) {
      return;
    }
    if ((await this.sessions.load(this.selfKey())) !== undefined) {
      return;
    }
    const sealed = this.live.sealConversation(conv, this.mskRaw);
    await this.sessions.save({ conversationId: this.selfKey(), sealed });
  }

  /** Re-seal our durable identity, OVERWRITING the stored one. Used after a provisioned device adopts
   * its certificate (saveSelf is create-if-absent, so adoption needs an explicit overwrite to persist
   * the now-authorized identity). The signature key is unchanged, so the contact stays stable. Also
   * marks this device group-ready so it may now publish key packages to the directory. */
  private async resealSelf(conv: GroupConversationLike): Promise<boolean> {
    // A locked vault (mskRaw null) cannot seal. Report that honestly instead of no-opping: a caller
    // about to publish something derived from in-memory key material must not proceed.
    if (this.live === undefined || this.sessions === undefined || this.mskRaw === null) {
      return false;
    }
    const sealed = this.live.sealConversation(conv, this.mskRaw);
    await this.sessions.save({ conversationId: this.selfKey(), sealed });
    await this.sessions.save({ conversationId: `authorized:${this.account}`, sealed: new Uint8Array([1]) });
    return true;
  }

  /** True when this device can be added to a group: it is the seed-holder (holds the account seed) or
   * it adopted a certificate by provisioning. ONLY then should it publish key packages, so a peer never
   * claims an unauthorized package and fails the whole group's authorization gate. */
  async isGroupReady(): Promise<boolean> {
    if (this.account === null || this.sessions === undefined) {
      return false;
    }
    if ((await this.sessions.load(this.aakKey())) !== undefined) {
      return true; // seed-holder
    }
    return (await this.sessions.load(`authorized:${this.account}`)) !== undefined;
  }

  /** Whether THIS device is authorized to read the account's conversations, and whether it holds the
   * account recovery seed. A device whose vault was just created by login (enrolled on the server but
   * holding no certificate and no seed) is UNAUTHORIZED: username and passphrase enroll a device, they
   * never authorize it. The login flow uses this to route an unauthorized device into the add-device
   * wizard instead of an empty channels view. When there is no sealed-session store (the degraded
   * main-thread fallback, which also cannot provision) we cannot determine state, so we report
   * authorized to avoid trapping the user. */
  async deviceAuthState(): Promise<{ authorized: boolean; seedHolder: boolean }> {
    if (this.sessions === undefined || this.account === null) {
      return { authorized: true, seedHolder: false };
    }
    const seedHolder = (await this.sessions.load(this.aakKey())) !== undefined;
    const authorized = await this.isGroupReady();
    return { authorized, seedHolder };
  }

  /** Persist a sent or received live message into the crypto-erasable keyvault. Outbound messages
   * arm their lifetime immediately (we authored them); inbound messages are stored UNARMED so they
   * persist until the recipient opens the conversation and views them (hold-until-seen). */
  private async persistLiveMessage(
    meta: { messageId: string; conversationId: string; direction: 'in' | 'out'; lifetime: Lifetime; ownAuthored?: boolean },
    plaintext: Uint8Array,
  ): Promise<void> {
    if (this.lifetime === null) {
      return;
    }
    const key = this.requireKey();
    await this.lifetime.storeIncoming(key, meta, plaintext, meta.direction === 'out');
  }

  /** Apply a member's cooperative revoke that arrived over the encrypted channel. Fail-closed
   * validation before anything is erased: the target must exist, belong to the conversation the
   * revoke arrived in, and have been SENT as until-revoked (only a message whose author declared it
   * revocable participates in cooperative recall). A PEER's frame can never erase this device's own
   * OUTBOUND record; only a revoke whose MLS-authenticated sender is one of OUR OWN devices
   * (`fromOwnAccount`, unforgeable by a peer) reaches an 'out' copy — the authoring device honoring
   * the same revoke a sibling device issued for our account's message. HONEST LIMIT: the MLS layer
   * authenticates that the revoker is a current member, but stored records carry no per-message
   * author key, so in a conversation with several peers any member can revoke any until-revoked
   * message we received. A revoke only ever DESTROYS a message its author marked recallable; it can
   * never read or alter one. */
  async applyInboundRevoke(conversationId: string, targetMessageId: string, fromOwnAccount: boolean): Promise<void> {
    if (this.lifetime === null) {
      return;
    }
    const rec = await this.keyvault.get(targetMessageId);
    if (
      rec === undefined ||
      rec.conversationId !== conversationId ||
      rec.lifetimeKind !== 'until-revoked'
    ) {
      return;
    }
    if (rec.direction === 'out' && !fromOwnAccount) {
      return; // a peer's revoke never touches our own outbound copy
    }
    await this.lifetime.revoke(targetMessageId);
  }

  /** Revoke one of OUR OWN until-revoked messages: publish the revoke command to the conversation
   * (every member device erases its stored copy) and crypto-erase our local copy. Validated to an
   * until-revoked record of this conversation that our account authored — either this device's
   * outbound original, or a sibling-synced inbound copy (`ownAuthored`, set only from the
   * MLS-authenticated own-account flag) — so a stray UI action can never broadcast a revoke for a
   * peer's message. The local erase is gated on the GATEWAY RECEIPT for the revoke frame (from that
   * point the gateway durably holds it, even for offline recipients), not on the socket hand-off: a
   * dead socket, a link that dies before the receipt, or a receipt timeout rejects here (see
   * GroupChannel.revokeMessage) with our copy intact and the control still offered, so the command
   * can never be lost while our copy is already gone. */
  async revokeMessage(conversationId: string, messageId: string): Promise<TransmitModel> {
    const rec = await this.keyvault.get(messageId);
    if (
      rec !== undefined &&
      rec.conversationId === conversationId &&
      (rec.direction === 'out' || rec.ownAuthored === true) &&
      rec.lifetimeKind === 'until-revoked'
    ) {
      await this.requireGroup().revokeMessage(conversationId, messageId);
      await this.lifetime?.revoke(messageId);
    }
    return this.openChannel(conversationId);
  }

  private requireGroup(): GroupChannel {
    if (this.groupChannel === null) {
      throw new Error('group channel needs the gateway and the owning worker');
    }
    return this.groupChannel;
  }

  /** Open the live gateway WebSocket and subscribe to our bootstrap mailbox (restoring our durable
   * authorized identity so the contact and mailbox are stable across logins). */
  async connectGateway(wsUrl: string): Promise<{ ok: boolean; selfContact: string; error?: string }> {
    const res = await this.requireGroup().connectGateway(wsUrl);
    if (res.ok) {
      // Reclassify held self-groups FIRST (deterministic, render-free): a group that only became
      // recognizable as self after this device's certificate settled gets recorded and its ghost row
      // deleted at every connect, not merely on the next channel-list render. Runs before the sweep so
      // the sweep's recorded-self exemption sees the ids this same pass records.
      await this.reconcileSelfGroupRecords().catch(() => {
        /* best-effort; the next connect or channels render retries */
      });
      // Heal already-orphaned ghost rows: a summary whose conversation the restored WASM does not hold
      // (and that is not a recorded self-group) belongs to a conversation this device was evicted from
      // or lost; it can never deliver again and would list forever. Gate on at least one restored
      // conversation, so a fresh identity or a failed restore never sweeps a healthy account's rows;
      // and only summaries that decrypt under THIS account's MSK are considered (a shared device holds
      // other accounts' sealed rows, which trivially have no session here and must not be touched).
      // Even a wrongly-swept live row self-heals: a fresh Welcome recreates the session AND the summary.
      await this.sweepDeadChannels().catch(() => {
        /* best-effort cleanup; the next connect retries */
      });
    }
    return res;
  }

  /** Start a conversation: create the MLS group adding all the given devices (the peer's plus our own
   * siblings) and show it. The app resolves the devices via the username directory (take-keys). */
  startConversation(targets: readonly DeviceTarget[]): Promise<TransmitModel> {
    return this.requireGroup().startConversation(targets);
  }

  /** Send a plaintext message to the group, persist it, and re-render from the keyvault so the sent
   * message shows with its (armed) countdown. */
  async sendMessage(conversationId: string, text: string, lifetime?: Lifetime): Promise<TransmitModel> {
    await this.requireGroup().sendMessage(conversationId, text, lifetime);
    return this.openChannel(conversationId);
  }

  async unlock(username: string, passphrase: string): Promise<{ ok: boolean; created?: boolean; error?: string }> {
    if (username.trim().length === 0) {
      return { ok: false, error: 'enter a username' };
    }
    if (passphrase.length === 0) {
      return { ok: false, error: 'enter a passphrase' };
    }
    const account = await accountIdFor(username);
    const credential = credentialFor(username, passphrase);
    let raw = await this.vault.unlock(account, credential);
    // `created` is true only when this login MADE a brand-new local vault on this device. It is a cheap
    // signal that this device has no prior local state; the authoritative "is this device authorized for
    // the account" check is deviceAuthState() (a created vault is enrolled but not yet authorized).
    let created = false;
    if (raw === null) {
      if (await this.vault.exists(account)) {
        return { ok: false, error: 'wrong username or passphrase' };
      }
      raw = await this.vault.create(account, credential); // first login for this username
      created = true;
    }
    this.account = account;
    this.mskKey = await importMsk(raw.slice());
    // The owning worker keeps the raw MSK to seal/restore wasm MLS state (it is the sole holder).
    if (this.live !== undefined) {
      this.mskRaw = raw.slice();
    }
    raw.fill(0);
    // Resolve history-off BEFORE connecting, so the very first message of the session is routed by a
    // settled flag rather than racing the read. Cached in a field: this must not decrypt per message.
    await this.hydrateHistoryMode();
    // A reload lost the in-memory expiry timers; erase anything already overdue before showing it.
    await this.lifetime?.sweepExpired();
    return { ok: true, created };
  }

  /** Roll back the local state a just-created account left behind when the server rejected its
   * registration (the username was already taken). Destroys the MSK wrap and the persisted identity
   * for that account and locks this controller, so retrying with a different username starts clean
   * and a seized device keeps no orphaned vault. */
  /** Verify a typed passphrase against the account's vault WITHOUT changing any state. Used to gate the
   * Self Destruct confirmation (the user types it twice). Returns false for a wrong passphrase or an
   * unknown account; never throws. The derived MSK is read and immediately zeroized, never retained. */
  async verifyPassphrase(username: string, passphrase: string): Promise<boolean> {
    if (username.trim().length === 0 || passphrase.length === 0) {
      return false;
    }
    const account = await accountIdFor(username);
    const raw = await this.vault.unlock(account, credentialFor(username, passphrase));
    if (raw === null) {
      return false;
    }
    raw.fill(0);
    return true;
  }

  async discardAccount(username: string): Promise<void> {
    const account = await accountIdFor(username);
    await this.sessions?.delete(`self:${account}`);
    // Also clear authorization state, so an abandoned add-device wizard leaves no orphaned seed or
    // "authorized" marker on a seized device, and a later retry starts from a clean unauthorized state.
    await this.sessions?.delete(`authorized:${account}`);
    await this.sessions?.delete(`aak:${account}`);
    await this.vault.delete(account);
    this.mskKey = null;
    this.mskRaw = null;
    this.account = null;
  }

  /** Persist a channel summary sealed under the MSK (called after a channel is established). */
  async saveChannel(summary: ChannelSummary): Promise<void> {
    const key = this.requireKey();
    const blob = await sealUnder(key, enc.encode(JSON.stringify(summary)), channelAad(summary.id));
    await this.channels.put({ id: summary.id, blob });
  }

  async listChannels(): Promise<readonly ChannelSummary[]> {
    const key = this.requireKey();
    const out: ChannelSummary[] = [];
    for (const rec of await this.channels.list()) {
      try {
        out.push(await this.decodeChannel(key, rec));
      } catch {
        // Belongs to another account on this device: it fails to decrypt under our MSK, so skip it.
      }
    }
    const hidden = await this.reconcileSelfGroupRecords(out);
    // Advisory only, display-time only (never persisted): a row whose roster provably has no
    // reachable recipient says so instead of posing as a normal channel. A real peer conversation,
    // even one whose peer never comes online, is never flagged (liveness is not the signal).
    return out
      .filter((c) => !hidden.has(c.id))
      .map((c) => {
        // A row shown as a channel that the self-classifier REFUSES for a reason that is NOT "this is a
        // genuine peer" (a member of a different account) is a probable mis-classified own-devices group
        // — the ghost that will not sync. Surface the classifier's reason as the row subtitle so a stuck
        // sync can be diagnosed ON SCREEN (Chrome on iOS has no usable console). A genuine peer chat
        // ("belongs to a different account") is left looking normal. Display-time only, never persisted.
        const reason = this.groupChannel?.selfClassificationReason?.(c.id);
        if (
          reason !== undefined &&
          reason !== '' &&
          reason !== 'self' &&
          reason !== 'no such conversation' &&
          reason.indexOf('different account') === -1
        ) {
          // Include the group id: two poisoned groups minted by the SAME sibling render with identical
          // labels and identical reasons, so without the id they are indistinguishable on screen and
          // there is no way to tell one ghost row from the other.
          return { ...c, preview: `self-group ${c.id.replace(/^c-/, '').slice(0, 8)} not recognized: ${reason}` };
        }
        if (this.groupChannel?.heldConversationIds().includes(c.id) !== true) {
          return { ...c, preview: 'no live crypto session (dead ghost)' };
        }
        if (this.groupChannel?.isUnlinkedConversationId(c.id) === true) {
          return { ...c, preview: 'no verified device can receive here' };
        }
        return c;
      });
  }

  /** The hidden self-group never lists as a channel (it is reached as Note to Self). A summary for it
   * can exist from an older build, or from a self-group whose Welcome was processed before a fresh
   * device's certificate settled, and the live self predicate is null in exactly that window. So we
   * exclude the UNION of: every id ever recorded as self (durable), the live best self-group, and any
   * currently-loaded self-group session. Any row that classifies self now but is not yet recorded is
   * recorded AND its stale summary deleted, so an already-minted orphan is cleaned up permanently once
   * the cert settles. Runs from every listChannels AND once per connect (deterministic, render-free).
   * Returns the full hidden-id set. Deletes summaries ONLY; never wasm groups, never stored messages. */
  private async reconcileSelfGroupRecords(summaries?: readonly ChannelSummary[]): Promise<Set<string>> {
    let rows = summaries;
    if (rows === undefined) {
      const key = this.requireKey();
      const built: ChannelSummary[] = [];
      for (const rec of await this.channels.list()) {
        const summary = await this.tryDecodeChannel(key, rec);
        if (summary !== null) {
          built.push(summary); // another account's row stays untouched (fails our MSK)
        }
      }
      rows = built;
    }
    const recorded = await this.loadSelfGroupIds();
    const hidden = new Set(recorded);
    const liveSelf = this.groupChannel?.selfConversationId();
    if (liveSelf !== undefined && liveSelf !== null) {
      hidden.add(liveSelf);
    }
    let changed = false;
    for (const c of rows) {
      const isSelf = hidden.has(c.id) || this.groupChannel?.isSelfConversationId(c.id) === true;
      if (!isSelf) {
        // A held conversation shown as a channel that the classifier REFUSES as self. When it should
        // have been self (a raced/mis-timed self-group mint), it lingers as a ghost and buddy sync is
        // withheld. Log the classifier's own reason so a stuck sync is diagnosed by READING the cause
        // (member with no cert, foreign account, cert not settled) instead of guessing at the roster.
        // Read-only; never changes behavior. Only for conversations this device actually holds.
        const reason = this.groupChannel?.selfClassificationReason?.(c.id);
        if (reason !== undefined && reason !== '' && reason !== 'no such conversation') {
          console.warn(`self-classification: conversation ${c.id.slice(0, 8)} is not a self-group: ${reason}`);
        } else if (this.groupChannel?.heldConversationIds().includes(c.id) !== true) {
          // A channel row shown to the user for which we hold NO live crypto session: a stale summary
          // left by a join that never completed (or whose wasm state did not persist). It can never sync
          // or decrypt, so it lingers as a dead ghost. Name it so a stuck sync is not a silent console.
          // (sweepDeadChannels deletes these on connect; logging here catches one that slipped through.)
          console.warn(`self-classification: conversation ${c.id.slice(0, 8)} has a summary but no live crypto session (dead ghost)`);
        }
        continue;
      }
      hidden.add(c.id);
      if (!recorded.has(c.id)) {
        // First time this id is recognized as self: record it durably (so it stays hidden even after the
        // live predicate goes null) and delete its stale summary (clean up an already-minted orphan).
        changed = true;
        await this.channels.delete(c.id).catch(() => {
          /* best-effort cleanup of the orphaned self-group summary */
        });
      }
    }
    if (changed) {
      await this.recordSelfGroupIds(hidden);
    }
    await this.healDeadSelfGroups(hidden);
    return hidden;
  }

  /** SG2 SELF-HEAL + artifact cleanup. A self-group poisoned by a frozen certless leaf can never be
   * repaired in place (MLS never rewrites a leaf credential): it never syncs, and it used to sit there
   * forever while the user closed it by hand on every device (or, worse, never realized). Sweep the
   * RECORDED self-groups, abandon any the crypto layer agrees is provably dead, and clean up what it
   * leaves behind (its channel summary and its recorded id), so the normal formation path mints a clean
   * replacement on the next trigger.
   *
   * Safety rests in the crypto layer, which refuses unless the group is recorded-self AND trusts only
   * our account AND has NO verified sibling — so a healthy self-group, and any peer conversation, are
   * never touched. Best-effort throughout: a failure here must never break a login. */
  private async healDeadSelfGroups(recordedSelfIds: ReadonlySet<string>): Promise<void> {
    const ch = this.groupChannel;
    if (ch === null || ch === undefined || recordedSelfIds.size === 0) {
      return;
    }
    const held = new Set(ch.heldConversationIds());
    let healed = false;
    for (const id of recordedSelfIds) {
      if (!held.has(id) || ch.isUnlinkedConversationId(id) !== true) {
        continue; // not held here, or still reachable: leave it alone
      }
      let abandoned = false;
      try {
        abandoned = await ch.abandonDeadSelfGroup(id, true); // recorded-self: this id is in our own set
      } catch {
        continue; // refused: the safe outcome
      }
      if (!abandoned) {
        continue;
      }
      healed = true;
      console.warn(`self-heal: abandoned a dead own-devices group (${id.slice(0, 8)}); a clean one will form`);
      // Clean the artifacts it leaves behind: its channel summary (so no ghost row survives) and its
      // recorded id (so a NEW self-group is not mistaken for this dead one).
      await this.channels.delete(id).catch(() => {
        /* best-effort */
      });
    }
    if (healed) {
      const remaining = new Set([...recordedSelfIds].filter((id) => ch.heldConversationIds().includes(id)));
      await this.recordSelfGroupIds(remaining).catch(() => {
        /* best-effort; recomputed on the next sweep */
      });
    }
  }

  /** Delete every channel summary whose conversation the restored WASM no longer holds (see the caller
   * in connectGateway for the safety argument). Skips recorded self-group ids (already hidden and
   * cleaned elsewhere) and rows that do not decrypt under this account's MSK. */
  private async sweepDeadChannels(): Promise<void> {
    const held = new Set(this.groupChannel?.heldConversationIds() ?? []);
    if (held.size === 0) {
      return; // fresh identity or failed restore: nothing provably dead, never sweep
    }
    const key = this.requireKey();
    const recorded = await this.loadSelfGroupIds();
    for (const rec of await this.channels.list()) {
      const summary = await this.tryDecodeChannel(key, rec);
      if (summary === null) {
        continue; // another account's row on this device: not ours to touch
      }
      if (!held.has(summary.id) && !recorded.has(summary.id)) {
        await this.channels.delete(summary.id).catch(() => {
          /* best-effort; retried on the next connect */
        });
      }
    }
  }

  /** Just one channel's display name, for naming a notification: a single-row fetch + decrypt instead
   * of the full listChannels sweep (which decrypts every channel and consults the self-group filter).
   * Runs on every inbound background message, so it must stay O(1). '' when unknown. */
  async peerFor(id: string): Promise<string> {
    const key = this.requireKey();
    const rec = await this.channels.get(id);
    if (rec === undefined) {
      return '';
    }
    const summary = await this.tryDecodeChannel(key, rec);
    return summary?.peer ?? '';
  }

  async openChannel(id: string, opts: { forceSelf?: boolean } = {}): Promise<TransmitModel> {
    const key = this.requireKey();
    const rec = await this.channels.get(id);
    const summary = rec !== undefined ? await this.tryDecodeChannel(key, rec) : null;
    // The hidden own-devices self-group is surfaced as "Note to Self": it is always secure (an MLS
    // group of only our own devices) and carries no peer fingerprint. Recognize it by the SAME union
    // listChannels uses: forceSelf/cached id, the live best self-group, ANY loaded self-group session,
    // and the durable recorded set. The last two matter on a freshly-provisioned device, where the
    // live "best" predicate can be momentarily null while the certificate settles; without them this
    // returned selfNote:false in that window, and the established handler's selfNote skip then let the
    // self-group AUTO-OPEN as the active conversation instead of landing on the buddy list.
    const recordedSelf = await this.loadSelfGroupIds();
    const isSelf =
      opts.forceSelf === true ||
      id === this.selfConvId ||
      this.groupChannel?.selfConversationId() === id ||
      this.groupChannel?.isSelfConversationId(id) === true ||
      recordedSelf.has(id);
    if (isSelf) {
      this.selfConvId = id;
      if (!recordedSelf.has(id)) {
        // Newly recognized here (e.g. forceSelf from openNoteToSelf): record it durably so listChannels
        // and every later open agree, even if the live predicate is null at that moment.
        await this.recordSelfGroupIds(new Set(recordedSelf).add(id));
      }
    }
    if (isSelf && rec !== undefined) {
      // A summary for the self-group only exists when an older build adopted it visibly (a cert-only
      // device before the credential fallback). Erase it so the self chat stops posing as a channel.
      await this.channels.delete(id).catch(() => {
        /* best-effort cleanup */
      });
    }
    const peer = isSelf ? 'Note to Self' : (summary?.peer ?? 'UNKNOWN');
    const secure = isSelf || summary?.status === 'secure';

    const log: LogEntry[] = [{ kind: 'system', text: '» channel open · forward secrecy active' }];
    if (!isSelf && this.groupChannel?.isUnlinkedConversationId(id) === true) {
      // Honest advisory: sends into this group are stored and published, and no reachable device can
      // ever read them (the roster's identities are provably dead). Words only; nothing is deleted.
      log.push({ kind: 'system', text: '» no verified device on this channel · sent messages may be unreachable' });
    }
    // Contact verification state for THIS conversation, computed once and used three ways: the system
    // line below, the honest header label, and the send gate. Missing data never warns (an offline
    // session is not an attack); only a positive mismatch does.
    let verifyState: TransmitModel['verifyState'];
    if (!isSelf) {
      const handle = await this.handleForConversation(id);
      const vk = handle !== null ? ((await this.loadBuddyMap())[handle]?.vk ?? '') : '';
      const keys = this.groupChannel?.peerAccountKeysFor(id) ?? [];
      if (vk.length > 0) {
        verifyState = keys.length !== 1 ? 'stale' : keys[0] !== vk ? 'changed' : 'verified';
      } else {
        verifyState = keys.length === 1 ? 'none' : 'unavailable';
      }
      if (verifyState === 'changed') {
        log.push({ kind: 'system', text: '» identity changed · this is not the key you verified for this buddy · confirm with them before trusting this channel' });
      }
    }
    // ONE read of this conversation's stored messages, shared by the arm loop and the log build:
    // openChannel is the hottest path in the app (every send, every inbound message in the open
    // conversation, every heal), and it used to getAll the ENTIRE keyvault twice per call.
    let convRecords = await this.keyvault.listByConversation(id);
    if (isSelf) {
      // Note to Self renders the UNION of every self-classified history: notes written into a
      // superseded (now hidden) self-group copy stay readable after canonical selection moves to a
      // certified replacement. Membership is cryptographically grounded (recorded set + per-session
      // classification), so no peer conversation's messages can leak in. Writes still target only
      // the canonical group.
      const selfIds = new Set<string>(recordedSelf);
      for (const cid of this.groupChannel?.heldConversationIds() ?? []) {
        if (this.groupChannel?.isSelfConversationId(cid) === true) {
          selfIds.add(cid);
        }
      }
      selfIds.delete(id);
      for (const cid of selfIds) {
        convRecords = convRecords.concat(await this.keyvault.listByConversation(cid));
      }
    }
    // Opening the conversation IS the recipient viewing it: start the countdown on any inbound
    // message that was held unarmed (hold-until-seen). Outbound messages were armed when sent.
    for (const v of convRecords) {
      if (v.direction === 'in') {
        // Hand over the record we just listed: armOnView re-reads only when it actually has to write.
        await this.lifetime?.armOnView(v.messageId, v);
      }
    }
    const records = [...convRecords].sort((a, b) => a.storedAtMs - b.storedAtMs);
    for (const v of records) {
      // In a self-chat every message is ours, whether typed here or synced from another of our
      // devices, so both directions read as 'YOU'; a normal conversation labels inbound with the peer.
      const sender = v.direction === 'in' && !isSelf ? peer : 'YOU';
      if (v.lifetimeKind === 'burn-on-read') {
        // Burn-on-read: building a SECURE view IS the read, the same trigger that arms a duration
        // countdown (hold-until-seen). The read latch destroys the durable key BEFORE the plaintext
        // is returned, so this render is the only one; every later rebuild finds the latched
        // tombstone and shows the destroyed marker. The SENDER's stored copy goes through the same
        // latch: it renders once in the view rebuilt right after sending, then only the tombstone
        // remains, so neither end keeps a readable at-rest copy past its first view.
        if (!v.read) {
          // The one read must not be spent where it cannot be usefully seen: a transient DEAD view
          // (secure=false, e.g. mid-restore before the summary or self-group is recognized) gets
          // replaced automatically when the connection heals, and the degraded main-thread
          // controller has no LifetimeManager at all. In both cases hold the message unopened and
          // render nothing for it; a later secure view spends the read.
          if (!secure || this.lifetime === null) {
            continue;
          }
          let framed: Uint8Array | null;
          try {
            framed = await this.lifetime.openBurnOnRead(key, v.messageId);
          } catch {
            continue; // another account's message; not ours to show (or to burn)
          }
          if (framed !== null) {
            log.push({
              kind: 'message',
              sender,
              text: dec.decode(framed),
              lifetime: { kind: 'burn-on-read' },
              remainingSeconds: null,
            });
            continue;
          }
          // null here: the latch won a race with another view of this record; fall through.
        }
        log.push({ kind: 'destroyed' });
        continue;
      }
      let text: string;
      try {
        text = dec.decode(await openVaultRecord(key, v));
      } catch {
        continue; // another account's message (or an erased record); not ours to show
      }
      // An armed duration shows its live remaining; an unarmed one shows its full duration (the
      // countdown has not started). Other kinds have no countdown.
      const remainingSeconds =
        v.expiresAtMs !== null
          ? Math.max(0, Math.round((v.expiresAtMs - this.now()) / 1000))
          : v.durationSeconds;
      log.push({
        kind: 'message',
        sender,
        text,
        lifetime: lifetimeOf(v.lifetimeKind, remainingSeconds),
        remainingSeconds,
        // The absolute expiry (armed duration only) so the UI can tick the countdown live per second.
        expiresAtMs: v.expiresAtMs,
        // Our own account's until-revoked message keeps its revoke control — whether authored on
        // THIS device (out) or synced from a sibling device (in + ownAuthored): the id lets the UI
        // target it. A peer's message never gets one. A note union-rendered from a SUPERSEDED
        // self-copy gets none either: the UI revokes against the OPEN conversation id, and the
        // per-record guard would silently no-op on the mismatched id (a dead control).
        ...(v.lifetimeKind === 'until-revoked' && (v.direction === 'out' || v.ownAuthored === true) && v.conversationId === id
          ? { messageId: v.messageId, canRevoke: true }
          : {}),
      });
    }
    // The buddy handle this conversation was tagged with (when unambiguous) and whether that handle is
    // already on the buddy list: the conversation toolbar shows Add Buddy only for a known non-buddy.
    const peerHandle = isSelf ? null : await this.handleForConversation(id);
    const peerIsBuddy = peerHandle !== null && (await this.loadBuddyMap())[peerHandle]?.removed === false;
    return {
      secure,
      peer,
      fingerprint: isSelf ? null : (summary?.fingerprint ?? null),
      selfNote: isSelf,
      // Only the self-group view carries the split diagnostic (roster size + Welcome counters).
      ...(isSelf ? { selfDiag: this.groupChannel?.selfGroupDiagnostic() ?? '' } : {}),
      peerHandle,
      peerIsBuddy,
      ...(verifyState !== undefined ? { verifyState } : {}),
      log,
      compose: '',
      conversationId: id,
    };
  }

  async channelKeyExchange(id: string): Promise<KeyExchangeState> {
    const key = this.requireKey();
    const rec = await this.channels.get(id);
    const summary = rec !== undefined ? await this.tryDecodeChannel(key, rec) : null;
    return {
      mode: 'incoming',
      conversationId: id,
      selfFingerprint: 'pending',
      peer: summary?.peer ?? 'NEW CONTACT',
      peerFingerprint: summary?.fingerprint ?? '',
    };
  }

  async startKeyExchange(): Promise<KeyExchangeState> {
    // Our identity and contact come from the connected gateway session; fall back to the wasm
    // identity provider for the fingerprint only.
    const selfContact = this.groupChannel?.selfContact();
    const selfFingerprint = this.groupChannel?.selfFingerprint() ?? (this.identity !== undefined ? await this.identity() : 'pending');
    const base: KeyExchangeState = {
      mode: 'start',
      conversationId: `c-${crypto.randomUUID()}`,
      selfFingerprint,
    };
    return selfContact !== undefined ? { ...base, selfContact } : base;
  }

  /** In the group model a conversation auto-establishes from the Welcome (no manual accept); just
   * open it, rendering any messages the gateway held for us. */
  async acceptKeyExchange(conversationId: string): Promise<TransmitModel> {
    return this.openChannel(conversationId);
  }

  private async decodeChannel(key: CryptoKey, rec: ChannelRecord): Promise<ChannelSummary> {
    const json = dec.decode(await openUnder(key, rec.blob, channelAad(rec.id)));
    return JSON.parse(json) as ChannelSummary;
  }

  /** decodeChannel, but returns null instead of throwing when the record belongs to another account
   * on this device (it cannot be decrypted under our MSK). */
  private async tryDecodeChannel(key: CryptoKey, rec: ChannelRecord): Promise<ChannelSummary | null> {
    try {
      return await this.decodeChannel(key, rec);
    } catch {
      return null;
    }
  }

  private requireKey(): CryptoKey {
    if (this.mskKey === null) {
      throw new Error('locked');
    }
    return this.mskKey;
  }
}
