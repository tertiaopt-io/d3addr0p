// @vitest-environment happy-dom
//
// DOM-level tests for the mountApp registration/authentication orchestration: the server-gated
// login, the create-account flow, the duplicate-username rejection that rolls back local state, and
// the by-username directory lookup that opens a channel. Drives the real form against a fake
// controller and the real AccountClient over a scriptable transport.

import { describe, it, expect, beforeAll, beforeEach, vi } from 'vitest';
import { webcrypto } from 'node:crypto';
import {
  mountApp,
  DEFAULT_IDENTITY,
  type AppController,
  type ChannelSummary,
  type KeyExchangeState,
  type TransmitModel,
  type Buddy,
  type GroupSummary,
  type BlockedContact,
  type IdentityProfile,
  type LogEntry,
} from './app.js';
import type { Lifetime } from './index.js';
import { AccountClient, contactFromIdentityKey, type AccountTransport } from './auth.js';
import type { DeviceTarget } from './groupchannel.js';

function clickMenu(root: HTMLElement, label: string): void {
  root.querySelectorAll('.dd-menu-item').forEach((el) => {
    if (el.textContent === label && el instanceof HTMLElement) {
      el.click();
    }
  });
}

function device(over: Record<string, unknown>): Record<string, unknown> {
  return { deviceId: 'd', deviceKey: 'b'.repeat(64), addedAt: 1, lastSeenAt: 1, revoked: false, current: false, authorized: true, ...over };
}

// happy-dom does not provide WebCrypto; the account derivations need SHA-256.
beforeAll(() => {
  if (!(globalThis.crypto && 'subtle' in globalThis.crypto)) {
    Object.defineProperty(globalThis, 'crypto', { value: webcrypto, configurable: true });
  }
});

const SIG = 'a'.repeat(64);
const SELF_CONTACT = contactFromIdentityKey(SIG);
const PEER_KEY = 'd'.repeat(64);

function transmit(peer: string): TransmitModel {
  return { secure: true, peer, fingerprint: null, log: [], compose: '', conversationId: 'c1' };
}

/** Records the controller calls the flow makes so the test can assert on them. */
class FakeController implements AppController {
  unlockOk = true;
  discarded: string[] = [];
  identity: IdentityProfile = DEFAULT_IDENTITY; // the sealed identity card (icon + bio + away)
  getIdentity(): Promise<IdentityProfile> {
    return Promise.resolve(this.identity);
  }
  setIdentity(profile: IdentityProfile): Promise<void> {
    this.identity = profile;
    return Promise.resolve();
  }
  unlocks: Array<{ u: string; p: string }> = [];
  lastTargets: readonly DeviceTarget[] | null = null;
  // Provisioning + device spies.
  secret: string | null = null;
  groupReady = true;
  unlockCreated = false;
  authorizedState: { authorized: boolean; seedHolder: boolean } = { authorized: true, seedHolder: false };
  seededAccount = false;
  windowOpened = 0;
  joined = 0;
  confirmed = 0;
  excluded: string[] = [];
  private handler: ((ev: { event: string; payload: unknown }) => void) | null = null;
  emit(event: string, payload: unknown = {}): void {
    this.handler?.({ event, payload });
  }
  onEvent(h: (ev: { event: string; payload: unknown }) => void): void {
    this.handler = h;
  }
  recoverySecret(): Promise<string | null> {
    const s = this.secret;
    this.secret = null;
    return Promise.resolve(s);
  }
  ensureAccountSeed(): Promise<void> {
    this.seededAccount = true;
    return Promise.resolve();
  }
  isGroupReady(): Promise<boolean> {
    return Promise.resolve(this.groupReady);
  }
  deviceAuthState(): Promise<{ authorized: boolean; seedHolder: boolean }> {
    return Promise.resolve(this.authorizedState);
  }
  keyPackages(n: number): Promise<string[]> {
    return Promise.resolve(Array.from({ length: n }, () => 'ab'.repeat(4)));
  }
  openProvisioningWindow(): Promise<void> {
    this.windowOpened++;
    return Promise.resolve();
  }
  joinDevice(): Promise<void> {
    this.joined++;
    return Promise.resolve();
  }
  confirmProvisioning(): Promise<void> {
    this.confirmed++;
    return Promise.resolve();
  }
  closeProvisioning(): Promise<void> {
    return Promise.resolve();
  }
  excludeDevice(sigKeyHex: string): Promise<void> {
    this.excluded.push(sigKeyHex);
    return Promise.resolve();
  }
  reconciledRemovals: string[][] = []; // the revokedKeys passed to each reconcileRemovals call
  reconcileRemovals(_ownDeviceKeys: readonly string[], revokedKeys: readonly string[]): Promise<void> {
    this.reconciledRemovals.push([...revokedKeys]);
    return Promise.resolve();
  }
  recovered: string | null = null;
  recoverOk = true;
  recoverWithSeed(secret: string): Promise<{ ok: boolean; error?: string }> {
    this.recovered = secret;
    return Promise.resolve(this.recoverOk ? { ok: true } : { ok: false, error: 'that does not look like a recovery secret' });
  }
  syncEpoch(): Promise<{ ready: boolean; stale: boolean }> {
    return Promise.resolve({ ready: true, stale: false });
  }
  certEpoch(): Promise<number> {
    return Promise.resolve(0);
  }
  // ADR-022 P7 denylist.
  mintedRevocations: Array<{ key: string; seq: number }> = [];
  ingested: string[] = [];
  revokeMintFails = false;
  revokeDeviceKey(deviceSigKeyHex: string, issuedSeq: number): Promise<string | null> {
    if (this.revokeMintFails) {
      return Promise.reject(new Error('no account key'));
    }
    this.mintedRevocations.push({ key: deviceSigKeyHex, seq: issuedSeq });
    return Promise.resolve(`rec-${deviceSigKeyHex}`);
  }
  ingestRevocations(records: readonly string[]): Promise<number> {
    this.ingested.push(...records);
    return Promise.resolve(records.length);
  }
  revocationState(): Promise<{ revoked: number; floor: number }> {
    return Promise.resolve({ revoked: this.mintedRevocations.length, floor: this.mintedRevocations.length });
  }
  // Overridden per-test to model the crypto layer's own dedupe (a key already covered is not re-minted).
  isDeviceRevoked: (deviceSigKeyHex: string) => Promise<boolean> = () => Promise.resolve(false);

  unlock(u: string, p: string): Promise<{ ok: boolean; created?: boolean; error?: string }> {
    this.unlocks.push({ u, p });
    return Promise.resolve(
      this.unlockOk ? { ok: true, created: this.unlockCreated } : { ok: false, error: 'wrong username or passphrase' },
    );
  }
  discardAccount(u: string): Promise<void> {
    this.discarded.push(u);
    return Promise.resolve();
  }
  verifyPassphraseOk = true;
  verifiedPass: string[] = [];
  verifyPassphrase(_u: string, p: string): Promise<boolean> {
    this.verifiedPass.push(p);
    return Promise.resolve(this.verifyPassphraseOk);
  }
  channelsList: ChannelSummary[] = [];
  listChannels(): Promise<readonly ChannelSummary[]> {
    return Promise.resolve(this.channelsList);
  }
  selfNoteId: string | null = null; // openChannel(id) returns the Note-to-Self model for this id
  deadIds = new Set<string>(); // openChannel(id) returns a DEAD model (secure=false) while present
  conversationLog: LogEntry[] = []; // extra log entries every conversation model carries
  openChannelCount = 0; // how many times a flow re-fetched a conversation view
  openChannel(id?: string): Promise<TransmitModel> {
    this.openChannelCount++;
    if (id !== undefined && id === this.selfNoteId) {
      return Promise.resolve({ ...transmit('Note to Self'), selfNote: true, conversationId: id, log: this.conversationLog });
    }
    if (id !== undefined && this.deadIds.has(id)) {
      return Promise.resolve({ ...transmit('UNKNOWN'), secure: false, conversationId: id });
    }
    // Return the conversation that was ASKED FOR. Returning a fixed 'c1' for every id made every window
    // key identical, so any test about opening the wrong window — duplicates, focus theft, raise-vs-pop —
    // could not fail no matter how broken the app was.
    return Promise.resolve({ ...transmit('PEER'), conversationId: id ?? 'c1', log: this.conversationLog });
  }
  openNoteToSelf(): Promise<TransmitModel> {
    return Promise.resolve({ ...transmit('Note to Self'), selfNote: true, log: this.conversationLog });
  }
  removed: string[] = []; // conversation ids retired via removeConversation (the two-tap Remove)
  removeConversation(conversationId: string): Promise<void> {
    this.removed.push(conversationId);
    return Promise.resolve();
  }
  blockedConvs: string[] = []; // conversation ids blocked+closed via blockConversation (two-tap too)
  blockConversation(conversationId: string): Promise<void> {
    this.blockedConvs.push(conversationId);
    return Promise.resolve();
  }
  revoked: Array<{ conversationId: string; messageId: string }> = [];
  revokeOk = true;
  revokeMessage(conversationId: string, messageId: string): Promise<TransmitModel> {
    this.revoked.push({ conversationId, messageId });
    if (!this.revokeOk) {
      return Promise.reject(new Error('connection closed'));
    }
    // The real controller erases the copy and returns the refreshed view (no revocable entry left).
    return Promise.resolve(transmit('PEER'));
  }
  startKeyExchange(): Promise<KeyExchangeState> {
    return Promise.resolve({ mode: 'start', conversationId: 'c1', selfFingerprint: 'fp', selfContact: SELF_CONTACT });
  }
  channelKeyExchange(): Promise<KeyExchangeState> {
    return Promise.resolve({ mode: 'incoming', conversationId: 'c1', selfFingerprint: 'fp' });
  }
  acceptKeyExchange(): Promise<TransmitModel> {
    return Promise.resolve(transmit('PEER'));
  }
  connects = 0; // how many times the app dialed the gateway (login + every reconnect)
  connectGateway(): Promise<{ ok: boolean; selfContact: string }> {
    this.connects++;
    return Promise.resolve({ ok: true, selfContact: SELF_CONTACT });
  }
  // Hidden self-group formation (SG1). selfGroupExists models whether a self-group is present; mints
  // records every ensureSelfGroup call so a test can assert WHO minted and how often.
  selfGroupExists = false;
  mints: Array<readonly DeviceTarget[]> = [];
  hasSelfGroup(): Promise<boolean> {
    return Promise.resolve(this.selfGroupExists);
  }
  ensureSelfGroup(targets: readonly DeviceTarget[]): Promise<void> {
    this.mints.push(targets);
    this.selfGroupExists = true;
    return Promise.resolve();
  }
  startConversation(targets: readonly DeviceTarget[]): Promise<TransmitModel> {
    this.lastTargets = targets;
    return Promise.resolve(transmit('PEER'));
  }
  lastSendLifetime: Lifetime | undefined; // what the compose's ⏳ pick threaded through send
  sendLog: LogEntry[] = []; // what the refreshed view after a send shows in the log
  sendMessage(_conversationId?: string, _text?: string, lifetime?: Lifetime): Promise<TransmitModel> {
    this.lastSendLifetime = lifetime;
    return Promise.resolve({ ...transmit('PEER'), log: this.sendLog });
  }
  // Buddy List + Setup surface (in-memory), so a DOM flow can exercise add/delete of buddies and groups.
  buddies: Buddy[] = [];
  groups: GroupSummary[] = [];
  blocked: BlockedContact[] = [];
  listBuddies(): Promise<readonly Buddy[]> {
    return Promise.resolve(this.buddies);
  }
  addBuddy(username: string, group?: string): Promise<readonly Buddy[]> {
    const u = username.trim().toLowerCase();
    if (u.length > 0 && !this.buddies.some((b) => b.username === u)) {
      this.buddies = [...this.buddies, { username: u, addedAt: 0, group: group ?? 'Buddies' }];
    }
    return Promise.resolve(this.buddies);
  }
  removeBuddy(username: string): Promise<readonly Buddy[]> {
    this.buddies = this.buddies.filter((b) => b.username !== username);
    return Promise.resolve(this.buddies);
  }
  setBuddyGroup(username: string, group: string): Promise<readonly Buddy[]> {
    this.buddies = this.buddies.map((b) => (b.username === username ? { ...b, group } : b));
    return Promise.resolve(this.buddies);
  }
  // The built-ins' current display labels (their internal keys never change), mirroring the real
  // controller: listGroups brackets the customs with the two role entries.
  defaultName = 'Buddies';
  blockedName = 'Blocked';
  listGroups(): Promise<readonly GroupSummary[]> {
    return Promise.resolve([
      { name: this.defaultName, role: 'default' as const },
      ...this.groups,
      { name: this.blockedName, role: 'blocked' as const },
    ]);
  }
  addGroup(name: string): Promise<readonly GroupSummary[]> {
    const g = name.trim();
    if (g.length > 0 && g !== 'Buddies' && !this.groups.some((x) => x.name === g)) {
      this.groups = [...this.groups, { name: g }];
    }
    return this.listGroups();
  }
  renameGroup(role: 'default' | 'blocked', name: string): Promise<readonly GroupSummary[]> {
    if (role === 'default') {
      this.defaultName = name;
    } else {
      this.blockedName = name;
    }
    return this.listGroups();
  }
  deleteGroup(name: string): Promise<readonly GroupSummary[]> {
    this.groups = this.groups.filter((x) => x.name !== name);
    this.buddies = this.buddies.map((b) => (b.group === name ? { ...b, group: 'Buddies' } : b));
    return Promise.resolve(this.groups);
  }
  listBlocked(): Promise<readonly BlockedContact[]> {
    return Promise.resolve(this.blocked);
  }
  unblock(key: string): Promise<readonly BlockedContact[]> {
    this.blocked = this.blocked.filter((b) => b.key !== key);
    return Promise.resolve(this.blocked);
  }
}

function fakeTransport(
  responses: Record<string, { status: number; body?: Record<string, unknown> }>,
): AccountTransport & { calls: Array<{ path: string; body: Record<string, unknown> }> } {
  const calls: Array<{ path: string; body: Record<string, unknown> }> = [];
  // Defaults reflecting a normal server: this device enrolls and appears in its own device list as the
  // current, non-revoked device, so the fail-closed revocation check in doLogin reads 'clear'. Per-test
  // responses override these (e.g. to model a revoked device, a multi-device account, or a 5xx failure).
  const defaults: Record<string, { status: number; body?: Record<string, unknown> }> = {
    // A deployment WITHOUT the proof-of-work endpoint answers 404 there and registration proceeds
    // without a proof. The catch-all 500 below means "server fault", which registration now surfaces
    // as a server problem rather than silently sending a proofless request that is certain to fail.
    '/api/challenge': { status: 404 },
    '/api/add-device': { status: 200, body: { deviceId: 'd1' } },
    '/api/list-devices': { status: 200, body: { devices: [device({ deviceId: 'd1', deviceKey: SIG, current: true })] } },
  };
  const merged = { ...defaults, ...responses };
  return {
    calls,
    send(path, body) {
      calls.push({ path, body });
      const r = merged[path] ?? { status: 500 };
      return Promise.resolve({ status: r.status, body: r.body ?? {} });
    },
  };
}

async function waitFor(pred: () => boolean, tries = 100): Promise<void> {
  for (let i = 0; i < tries; i++) {
    if (pred()) {
      return;
    }
    await new Promise((r) => setTimeout(r, 1));
  }
  throw new Error('waitFor timed out');
}

function setup(account?: AccountClient, controller?: FakeController): { root: HTMLElement; ctl: FakeController } {
  const root = document.createElement('div');
  document.body.appendChild(root);
  const ctl = controller ?? new FakeController();
  mountApp(root, ctl, account !== undefined ? { wsUrl: 'ws://x/ws', account } : { wsUrl: 'ws://x/ws' });
  return { root, ctl };
}

function fill(root: HTMLElement, id: string, value: string): void {
  const el = root.querySelector(id);
  if (el instanceof HTMLInputElement) {
    el.value = value;
  }
}

function submitForm(root: HTMLElement): void {
  root.querySelector('#dd-unlock-form')?.dispatchEvent(new Event('submit', { cancelable: true, bubbles: true }));
}

function click(root: HTMLElement, sel: string): void {
  const el = root.querySelector(sel);
  if (el instanceof HTMLElement) {
    el.click();
  }
}

function selectOption(root: HTMLElement, sel: string, value: string): void {
  const el = root.querySelector(sel);
  if (el instanceof HTMLSelectElement) {
    el.value = value;
    el.dispatchEvent(new Event('change', { bubbles: true }));
  }
}

// Device keys now live in the DEAD DROP dropdown (open it, then choose the item).
function openDeviceKeys(root: HTMLElement): void {
  click(root, '[data-action="app-menu"]');
  click(root, '[data-action="device-keys"]');
}

function openSelfDestruct(root: HTMLElement): void {
  click(root, '[data-action="app-menu"]');
  click(root, '[data-action="self-destruct"]');
}

// Each test starts with a clean per-tab session (the S1 resume hint) and a no-op location.reload (Self
// Destruct and self-revoke end by reloading, which would otherwise be a no-op error in the test DOM).
beforeEach(() => {
  try {
    sessionStorage.clear();
  } catch {
    /* environment without sessionStorage */
  }
  try {
    vi.spyOn(window.location, 'reload').mockImplementation(() => undefined);
  } catch {
    /* reload not spy-able here: the assertions run before the reload anyway */
  }
});

describe('register flow', () => {
  it('creates the account, registers the identity key, and lands on channels', async () => {
    const t = fakeTransport({ '/api/register': { status: 201, body: { token: 'tok' } } });
    const { root, ctl } = setup(new AccountClient(t));

    click(root, '[data-action="to-register"]');
    fill(root, '#dd-user', 'alice');
    fill(root, '#dd-pass', 'hunter2');
    fill(root, '#dd-pass2', 'hunter2');
    submitForm(root);

    await waitFor(() => root.querySelector('.dd-blhead') !== null);
    expect(ctl.unlocks).toEqual([{ u: 'alice', p: 'hunter2' }]);
    expect(ctl.discarded).toEqual([]); // success: no rollback
    const reg = t.calls.find((c) => c.path === '/api/register');
    expect(reg?.body['identityKey']).toBe(SIG); // the directory entry is our signature key
  });

  it('ignores a second submit, so a double click cannot erase the account it just created', async () => {
    // The defect: doRegister had no in-flight guard, so a second click ran a second concurrent
    // registration. One POST got 201 and the other 409, and the 409 branch called discardAccount, which
    // crypto-erased the vault and account seed of the account that had JUST been created on the server.
    // The user was left with a live account whose keys existed nowhere. The proof of work makes a double
    // click MORE likely, by putting a visible pause between the click and any feedback.
    let registers = 0;
    const t: AccountTransport & { calls: Array<{ path: string; body: Record<string, unknown> }> } = {
      calls: [],
      send(path, body) {
        t.calls.push({ path, body });
        if (path === '/api/register') {
          registers += 1;
          return Promise.resolve(registers === 1
            ? { status: 201, body: { token: 'tok' } }
            : { status: 409, body: { error: 'username_taken' } });
        }
        if (path === '/api/challenge') {
          return Promise.resolve({ status: 404, body: {} });
        }
        if (path === '/api/add-device') {
          return Promise.resolve({ status: 200, body: { deviceId: 'd1' } });
        }
        if (path === '/api/list-devices') {
          return Promise.resolve({ status: 200, body: { devices: [device({ deviceId: 'd1', deviceKey: SIG, current: true })] } });
        }
        return Promise.resolve({ status: 500, body: {} });
      },
    };
    const { root, ctl } = setup(new AccountClient(t));

    click(root, '[data-action="to-register"]');
    fill(root, '#dd-user', 'alice');
    fill(root, '#dd-pass', 'hunter2');
    fill(root, '#dd-pass2', 'hunter2');
    submitForm(root);
    submitForm(root); // the second click, before the first has finished

    await waitFor(() => root.querySelector('.dd-blhead') !== null);
    expect(registers).toBe(1); // only ONE registration ever left the client
    expect(ctl.discarded).toEqual([]); // and the created account's keys were never destroyed
  });

  it('rejects a taken username and rolls back the local vault', async () => {
    const t = fakeTransport({ '/api/register': { status: 409, body: { error: 'username_taken' } } });
    const { root, ctl } = setup(new AccountClient(t));

    click(root, '[data-action="to-register"]');
    fill(root, '#dd-user', 'alice');
    fill(root, '#dd-pass', 'hunter2');
    fill(root, '#dd-pass2', 'hunter2');
    submitForm(root);

    await waitFor(() => ctl.discarded.length === 1);
    expect(ctl.discarded).toEqual(['alice']); // orphan local account destroyed
    expect(root.innerHTML).toContain('already taken');
    expect(root.querySelector('#dd-pass2')).not.toBeNull(); // still on the register screen
  });

  it('refuses mismatched passphrases without touching the vault or the server', async () => {
    const t = fakeTransport({ '/api/register': { status: 201, body: { token: 'tok' } } });
    const { root, ctl } = setup(new AccountClient(t));

    click(root, '[data-action="to-register"]');
    fill(root, '#dd-user', 'alice');
    fill(root, '#dd-pass', 'hunter2');
    fill(root, '#dd-pass2', 'nope');
    submitForm(root);

    await waitFor(() => root.innerHTML.includes('do not match'));
    expect(ctl.unlocks).toEqual([]);
    expect(t.calls).toEqual([]);
  });
});

describe('login flow', () => {
  it('authenticates against the server before unlocking the local vault', async () => {
    const t = fakeTransport({ '/api/login': { status: 200, body: { token: 'tok' } } });
    const { root, ctl } = setup(new AccountClient(t));

    fill(root, '#dd-user', 'alice');
    fill(root, '#dd-pass', 'hunter2');
    submitForm(root);

    await waitFor(() => root.querySelector('.dd-blhead') !== null);
    expect(t.calls[0]?.path).toBe('/api/login');
    expect(ctl.unlocks).toEqual([{ u: 'alice', p: 'hunter2' }]);
  });

  it('a server rejection blocks the local unlock entirely', async () => {
    const t = fakeTransport({ '/api/login': { status: 401, body: { error: 'unauthorized' } } });
    const { root, ctl } = setup(new AccountClient(t));

    fill(root, '#dd-user', 'alice');
    fill(root, '#dd-pass', 'wrong');
    submitForm(root);

    await waitFor(() => root.innerHTML.includes('wrong username or passphrase'));
    expect(ctl.unlocks).toEqual([]); // never reached the local vault
  });
});

describe('second-device login wizard', () => {
  const loginOk = (): ReturnType<typeof fakeTransport> =>
    fakeTransport({ '/api/login': { status: 200, body: { token: 'tok' } } });

  it('routes a valid-credentials login on an unauthorized device into the wizard, not empty channels', async () => {
    const { root, ctl } = setup(new AccountClient(loginOk()));
    ctl.authorizedState = { authorized: false, seedHolder: false };
    fill(root, '#dd-user', 'alice');
    fill(root, '#dd-pass', 'hunter2');
    submitForm(root);
    await waitFor(() => root.innerHTML.includes('CONNECT THIS DEVICE'));
    expect(root.innerHTML).toContain('not yet allowed to read your messages');
    expect(root.querySelector('[data-action="wizard-provision"]')).not.toBeNull();
    expect(root.querySelector('[data-action="wizard-recover"]')).not.toBeNull();
    expect(root.innerHTML).not.toContain('no channels yet');
  });

  it('an unauthorized login does NOT enroll before the wizard (no orphan device row)', async () => {
    const t = loginOk();
    const { root, ctl } = setup(new AccountClient(t));
    ctl.authorizedState = { authorized: false, seedHolder: false };
    fill(root, '#dd-user', 'alice');
    fill(root, '#dd-pass', 'hunter2');
    submitForm(root);
    await waitFor(() => root.innerHTML.includes('CONNECT THIS DEVICE'));
    expect(t.calls.some((c) => c.path === '/api/add-device')).toBe(false); // enrollment deferred to authorization
  });

  it('provisioning-authorized enrolls this device (add-device) then publishes, reaching DEVICE CONNECTED', async () => {
    const t = fakeTransport({
      '/api/login': { status: 200, body: { token: 'tok' } },
      '/api/publish-keys': { status: 201 },
    });
    const { root, ctl } = setup(new AccountClient(t));
    ctl.authorizedState = { authorized: false, seedHolder: false };
    fill(root, '#dd-user', 'alice');
    fill(root, '#dd-pass', 'hunter2');
    submitForm(root);
    await waitFor(() => root.innerHTML.includes('CONNECT THIS DEVICE'));
    click(root, '[data-action="wizard-provision"]');
    await waitFor(() => ctl.joined === 1);
    ctl.emit('provisioning-authorized', { accountPub: 'aa' });
    await waitFor(() => root.innerHTML.includes('DEVICE CONNECTED'));
    const addIdx = t.calls.findIndex((c) => c.path === '/api/add-device');
    const pubIdx = t.calls.findIndex((c) => c.path === '/api/publish-keys');
    expect(addIdx).toBeGreaterThanOrEqual(0); // enrolled at authorization, not at login
    expect(pubIdx).toBeGreaterThan(addIdx); // enroll strictly precedes publish
  });

  it('re-shows the wizard when the vault already exists but the device is still unauthorized', async () => {
    const { root, ctl } = setup(new AccountClient(loginOk()));
    ctl.unlockCreated = false; // a prior aborted attempt already made the vault
    ctl.authorizedState = { authorized: false, seedHolder: false };
    fill(root, '#dd-user', 'alice');
    fill(root, '#dd-pass', 'hunter2');
    submitForm(root);
    await waitFor(() => root.innerHTML.includes('CONNECT THIS DEVICE'));
    expect(root.querySelector('[data-action="wizard-provision"]')).not.toBeNull();
  });

  it('an authorized device skips the wizard and lands on channels', async () => {
    const { root, ctl } = setup(new AccountClient(loginOk()));
    ctl.authorizedState = { authorized: true, seedHolder: true };
    fill(root, '#dd-user', 'alice');
    fill(root, '#dd-pass', 'hunter2');
    submitForm(root);
    await waitFor(() => root.querySelector('.dd-blhead') !== null);
    expect(root.innerHTML).not.toContain('CONNECT THIS DEVICE');
  });

  it('the provision path delegates to joinDevice and leaves the chooser', async () => {
    const { root, ctl } = setup(new AccountClient(loginOk()));
    ctl.authorizedState = { authorized: false, seedHolder: false };
    fill(root, '#dd-user', 'alice');
    fill(root, '#dd-pass', 'hunter2');
    submitForm(root);
    await waitFor(() => root.innerHTML.includes('CONNECT THIS DEVICE'));
    click(root, '[data-action="wizard-provision"]');
    await waitFor(() => ctl.joined === 1);
    expect(root.querySelector('[data-action="wizard-provision"]')).toBeNull(); // moved into provisioning
  });

  it('the recover path authorizes via recoverWithSeed and lands on channels', async () => {
    const { root, ctl } = setup(new AccountClient(loginOk()));
    ctl.authorizedState = { authorized: false, seedHolder: false };
    fill(root, '#dd-user', 'alice');
    fill(root, '#dd-pass', 'hunter2');
    submitForm(root);
    await waitFor(() => root.innerHTML.includes('CONNECT THIS DEVICE'));
    click(root, '[data-action="wizard-recover"]');
    await waitFor(() => root.querySelector('#dd-recovery-input') !== null);
    const ta = root.querySelector('#dd-recovery-input');
    if (ta instanceof HTMLTextAreaElement) {
      ta.value = 'f'.repeat(64);
    }
    ctl.groupReady = true;
    click(root, '[data-action="recover-submit"]');
    await waitFor(() => root.querySelector('.dd-blhead') !== null);
    expect(ctl.recovered).toBe('f'.repeat(64));
  });

  it('cancelling recovery from the wizard returns to the wizard chooser', async () => {
    const { root, ctl } = setup(new AccountClient(loginOk()));
    ctl.authorizedState = { authorized: false, seedHolder: false };
    fill(root, '#dd-user', 'alice');
    fill(root, '#dd-pass', 'hunter2');
    submitForm(root);
    await waitFor(() => root.innerHTML.includes('CONNECT THIS DEVICE'));
    click(root, '[data-action="wizard-recover"]');
    await waitFor(() => root.querySelector('#dd-recovery-input') !== null);
    click(root, '[data-action="recover-cancel"]');
    await waitFor(() => root.querySelector('[data-action="wizard-provision"]') !== null);
  });

  it('the dead-end sign-out discards the local account and returns to login', async () => {
    const { root, ctl } = setup(new AccountClient(loginOk()));
    ctl.authorizedState = { authorized: false, seedHolder: false };
    fill(root, '#dd-user', 'alice');
    fill(root, '#dd-pass', 'hunter2');
    submitForm(root);
    await waitFor(() => root.innerHTML.includes('CONNECT THIS DEVICE'));
    click(root, '[data-action="wizard-deadend"]');
    await waitFor(() => root.innerHTML.includes('CANNOT CONNECT THIS DEVICE'));
    click(root, '[data-action="wizard-signout"]');
    await waitFor(() => root.querySelector('#dd-unlock-form') !== null);
    expect(ctl.discarded).toEqual(['alice']);
  });

  it('a local-only login with no account server never shows the wizard', async () => {
    const { root, ctl } = setup(); // no account server
    ctl.authorizedState = { authorized: false, seedHolder: false }; // would trip the gate if it ran
    fill(root, '#dd-user', 'alice');
    fill(root, '#dd-pass', 'hunter2');
    submitForm(root);
    await waitFor(() => root.querySelector('.dd-blhead') !== null);
    expect(root.innerHTML).not.toContain('CONNECT THIS DEVICE');
  });

  it('a wrong server password never reaches the wizard', async () => {
    const t = fakeTransport({ '/api/login': { status: 401, body: { error: 'unauthorized' } } });
    const { root, ctl } = setup(new AccountClient(t));
    ctl.authorizedState = { authorized: false, seedHolder: false };
    fill(root, '#dd-user', 'alice');
    fill(root, '#dd-pass', 'wrong');
    submitForm(root);
    await waitFor(() => root.innerHTML.includes('wrong username or passphrase'));
    expect(root.innerHTML).not.toContain('CONNECT THIS DEVICE');
    expect(ctl.unlocks).toEqual([]); // never even reached unlock
  });

  it('the menu bar cannot escape the wizard to an empty app', async () => {
    const { root, ctl } = setup(new AccountClient(loginOk()));
    ctl.authorizedState = { authorized: false, seedHolder: false };
    fill(root, '#dd-user', 'alice');
    fill(root, '#dd-pass', 'hunter2');
    submitForm(root);
    await waitFor(() => root.innerHTML.includes('CONNECT THIS DEVICE'));
    clickMenu(root, 'Channels');
    await new Promise((r) => setTimeout(r, 5));
    expect(root.innerHTML).toContain('CONNECT THIS DEVICE'); // still guided, not dropped on channels
    expect(root.innerHTML).not.toContain('no channels yet');
  });

  it('a background coded error never hijacks the wizard; a provisioning-error paints its error step', async () => {
    const { root, ctl } = setup(new AccountClient(loginOk()));
    ctl.authorizedState = { authorized: false, seedHolder: false };
    fill(root, '#dd-user', 'alice');
    fill(root, '#dd-pass', 'hunter2');
    submitForm(root);
    await waitFor(() => root.innerHTML.includes('CONNECT THIS DEVICE'));
    click(root, '[data-action="wizard-provision"]'); // enter the live provisioning ceremony
    await waitFor(() => ctl.joined === 1);
    const before = root.innerHTML;
    // A re-flushed decrypt failure after a reconnect used to repaint the open ceremony with raw MLS text.
    ctl.emit('error', { code: -1, detail: 'process message: ValidationError(UnableToDecrypt(SecretTreeError(RatchetTypeError)))' });
    await new Promise((r) => setTimeout(r, 5));
    expect(root.innerHTML).toBe(before); // background noise stays off the ceremony entirely
    expect(root.innerHTML).not.toContain('RatchetTypeError');
    // The provisioning machine's OWN failures still surface on the wizard, as friendly copy.
    ctl.emit('provisioning-error', { detail: 'authorization failed' });
    await waitFor(() => root.innerHTML.includes('authorization failed'));
  });
});

describe('directory lookup', () => {
  it('opens a group conversation from the directory device list', async () => {
    const t = fakeTransport({
      '/api/login': { status: 200, body: { token: 'tok' } },
      '/api/take-keys': { status: 200, body: { devices: [{ deviceKey: PEER_KEY, keyPackage: 'abcd', lastResort: false }] } },
    });
    const { root, ctl } = setup(new AccountClient(t));

    fill(root, '#dd-user', 'alice');
    fill(root, '#dd-pass', 'hunter2');
    submitForm(root);
    await waitFor(() => root.querySelector('.dd-blhead') !== null);

    clickMenu(root, 'Channels');
    await waitFor(() => root.querySelector('[data-action="new-channel"]') !== null);
    click(root, '[data-action="new-channel"]');
    await waitFor(() => root.querySelector('#dd-peer-username') !== null);
    fill(root, '#dd-peer-username', 'bob');
    click(root, '[data-action="accept-key"]');

    await waitFor(() => ctl.lastTargets !== null);
    expect(ctl.lastTargets?.some((d) => d.deviceKey === PEER_KEY)).toBe(true);
  });

  it('shows an error when the username is not in the directory', async () => {
    const t = fakeTransport({
      '/api/login': { status: 200, body: { token: 'tok' } },
      '/api/take-keys': { status: 404, body: { error: 'not_found' } },
    });
    const { root, ctl } = setup(new AccountClient(t));

    fill(root, '#dd-user', 'alice');
    fill(root, '#dd-pass', 'hunter2');
    submitForm(root);
    await waitFor(() => root.querySelector('.dd-blhead') !== null);

    clickMenu(root, 'Channels');
    await waitFor(() => root.querySelector('[data-action="new-channel"]') !== null);
    click(root, '[data-action="new-channel"]');
    await waitFor(() => root.querySelector('#dd-peer-username') !== null);
    fill(root, '#dd-peer-username', 'ghost');
    click(root, '[data-action="accept-key"]');

    await waitFor(() => root.innerHTML.includes('no user by that name'));
    expect(ctl.lastTargets).toBeNull();
  });

  it('routes starting a conversation with YOUR OWN username to Note to Self, not a peer channel', async () => {
    const t = fakeTransport({
      '/api/login': { status: 200, body: { token: 'tok' } },
      '/api/take-keys': { status: 200, body: { devices: [{ deviceKey: PEER_KEY, keyPackage: 'abcd', lastResort: false }] } },
    });
    const { root, ctl } = setup(new AccountClient(t));
    fill(root, '#dd-user', 'alice');
    fill(root, '#dd-pass', 'hunter2');
    submitForm(root);
    await waitFor(() => root.querySelector('.dd-blhead') !== null);
    ctl.emit('connection', { state: 'secure' }); // Note to Self rides the gateway
    clickMenu(root, 'Channels');
    await waitFor(() => root.querySelector('[data-action="new-channel"]') !== null);
    click(root, '[data-action="new-channel"]');
    await waitFor(() => root.querySelector('#dd-peer-username') !== null);
    fill(root, '#dd-peer-username', 'Alice'); // same account, different case: still yourself
    click(root, '[data-action="accept-key"]');
    await waitFor(() => root.innerHTML.includes('only your devices see this'));
    expect(root.innerHTML).toContain('Note to Self');
    expect(ctl.lastTargets).toBeNull(); // the peer startConversation path was NOT taken
  });
});

describe('device management', () => {
  it('enrolls this device on login', async () => {
    const t = fakeTransport({
      '/api/login': { status: 200, body: { token: 'tok' } },
      '/api/add-device': { status: 200, body: { deviceId: 'd1' } },
      '/api/list-devices': { status: 200, body: { devices: [device({ deviceId: 'd1', deviceKey: SIG, current: true })] } },
    });
    const { root } = setup(new AccountClient(t));
    fill(root, '#dd-user', 'alice');
    fill(root, '#dd-pass', 'pw');
    submitForm(root);
    await waitFor(() => root.querySelector('.dd-blhead') !== null);
    const enroll = t.calls.find((c) => c.path === '/api/add-device');
    expect(enroll?.body['deviceKey']).toBe(SIG); // this device's own key, re-derived from the session
  });

  it('locks out and crypto-erases a device the server reports as revoked', async () => {
    const t = fakeTransport({
      '/api/login': { status: 200, body: { token: 'tok' } },
      '/api/add-device': { status: 409, body: { error: 'device_revoked' } }, // this device's key was burned
    });
    const { root, ctl } = setup(new AccountClient(t));
    fill(root, '#dd-user', 'alice');
    fill(root, '#dd-pass', 'pw');
    submitForm(root);
    await waitFor(() => ctl.discarded.includes('alice')); // the local vault was crypto-erased
    expect(sessionStorage.getItem('dd-boot-notice')).toContain('This device was revoked');
    expect(root.querySelector('.dd-blhead')).toBeNull(); // never reached the buddy list
  });

  it('fails closed when this device cannot be verified against the account server', async () => {
    // login reached the server, but add-device/list-devices are blocked (attacker proxy, or a transient
    // 5xx). We must NOT fall through to the local auth gate and land on the buddy list.
    const t = fakeTransport({
      '/api/login': { status: 200, body: { token: 'tok' } },
      '/api/add-device': { status: 200, body: { deviceId: 'd1' } },
      '/api/list-devices': { status: 502 },
    });
    const { root, ctl } = setup(new AccountClient(t));
    fill(root, '#dd-user', 'alice');
    fill(root, '#dd-pass', 'pw');
    submitForm(root);
    await waitFor(() => root.innerHTML.includes('Could not verify this device'));
    expect(root.querySelector('.dd-blhead')).toBeNull(); // blocked, not on the buddy list
    expect(ctl.discarded).not.toContain('alice'); // fail-closed refuses; it does NOT wipe a maybe-good device
  });

  it('shows the active-device notice when the account has more than one device', async () => {
    const t = fakeTransport({
      '/api/login': { status: 200, body: { token: 'tok' } },
      '/api/add-device': { status: 200, body: { deviceId: 'd1' } },
      '/api/list-devices': {
        status: 200,
        body: {
          devices: [device({ deviceId: 'd1', deviceKey: SIG, current: true }), device({ deviceId: 'd2', deviceKey: 'e'.repeat(64) })],
        },
      },
    });
    const { root } = setup(new AccountClient(t));
    fill(root, '#dd-user', 'alice');
    fill(root, '#dd-pass', 'pw');
    submitForm(root);
    await waitFor(() => root.innerHTML.includes('Every device you are signed in on receives'));
    expect(root.innerHTML).toContain('2 devices');
  });

  it('lists devices in Settings, marks this device, and revokes another with an inline confirm', async () => {
    const calls: Array<{ path: string; body: Record<string, unknown> }> = [];
    let revoked = false;
    const transport: AccountTransport = {
      send(path, body) {
        calls.push({ path, body });
        if (path === '/api/login') {
          return Promise.resolve({ status: 200, body: { token: 'tok' } });
        }
        if (path === '/api/add-device') {
          return Promise.resolve({ status: 200, body: { deviceId: 'd1' } });
        }
        if (path === '/api/revoke-device') {
          revoked = true;
          return Promise.resolve({ status: 200, body: { ok: true } });
        }
        if (path === '/api/list-devices') {
          return Promise.resolve({
            status: 200,
            body: {
              devices: [
                device({ deviceId: 'd1', deviceKey: SIG, lastSeenAt: 9, current: true }),
                device({ deviceId: 'd2', deviceKey: 'e'.repeat(64), revoked }),
              ],
            },
          });
        }
        return Promise.resolve({ status: 500, body: {} });
      },
    };
    const { root } = setup(new AccountClient(transport));
    fill(root, '#dd-user', 'alice');
    fill(root, '#dd-pass', 'pw');
    submitForm(root);
    await waitFor(() => root.querySelector('.dd-blhead') !== null);

    openDeviceKeys(root);
    await waitFor(() => root.innerHTML.includes('THIS DEVICE'));
    expect(root.innerHTML).toContain('DEVICE KEYS');

    click(root, '[data-action="revoke-device"][data-device="d2"]'); // the other (non-current) device
    await waitFor(() => root.innerHTML.includes('Revoke this device?'));
    click(root, '[data-action="revoke-confirm"]');

    await waitFor(() => calls.some((c) => c.path === '/api/revoke-device'));
    expect(calls.find((c) => c.path === '/api/revoke-device')?.body['deviceId']).toBe('d2');
    expect(revoked).toBe(true);
  });

  it('arming a revoke keeps FOCUS on that device\'s confirm button so the second click cannot miss', async () => {
    // The repaint that inserts the inline confirm strip used to reset the list to the top, so the row
    // under the pointer silently became a DIFFERENT device and the confirm click nearly revoked the
    // wrong one (it happened live: the user almost revoked their laptop instead of their phone).
    // Anchoring on a scroll OFFSET proved fragile (parked windows mean several .dd-form elements, and
    // the first is not the live one), so the contract is now about the ELEMENT: after arming, focus is
    // ON the confirm button for the armed device.
    const transport = fakeTransport({
      '/api/login': { status: 200, body: { token: 'tok' } },
      '/api/add-device': { status: 200, body: { deviceId: 'd1' } },
      '/api/list-devices': {
        status: 200,
        body: {
          devices: [
            device({ deviceId: 'd1', deviceKey: SIG, current: true }),
            device({ deviceId: 'd2', deviceKey: 'e'.repeat(64) }),
            device({ deviceId: 'd3', deviceKey: 'f'.repeat(64) }),
          ],
        },
      },
    });
    const { root } = setup(new AccountClient(transport));
    fill(root, '#dd-user', 'alice');
    fill(root, '#dd-pass', 'pw');
    submitForm(root);
    await waitFor(() => root.querySelector('.dd-blhead') !== null);
    openDeviceKeys(root);
    await waitFor(() => root.innerHTML.includes('THIS DEVICE'));

    click(root, '[data-action="revoke-device"][data-device="d3"]');
    await waitFor(() => root.innerHTML.includes('Revoke this device?'));

    const confirm = root.querySelector('[data-action="revoke-confirm"][data-device="d3"]');
    expect(confirm).not.toBeNull();
    expect(document.activeElement).toBe(confirm);
  });

  it('a revoke mints the P7 record for that device key and sends it with the call', async () => {
    // The server-side burn only stops the device signing in. A device that still holds the account seed
    // re-certifies itself above any epoch floor and rejoins every group, so the SIGNED RECORD naming its
    // key has to be minted here (while this device holds the account key) and reach the wire.
    const calls: Array<{ path: string; body: Record<string, unknown> }> = [];
    const otherKey = 'e'.repeat(64);
    const transport: AccountTransport = {
      send(path, body) {
        calls.push({ path, body });
        if (path === '/api/login') {
          return Promise.resolve({ status: 200, body: { token: 'tok' } });
        }
        if (path === '/api/add-device') {
          return Promise.resolve({ status: 200, body: { deviceId: 'd1' } });
        }
        if (path === '/api/revoke-device') {
          return Promise.resolve({ status: 200, body: { ok: true, recordStored: true } });
        }
        if (path === '/api/list-devices') {
          return Promise.resolve({
            status: 200,
            body: {
              devices: [
                device({ deviceId: 'd1', deviceKey: SIG, current: true }),
                device({ deviceId: 'd2', deviceKey: otherKey }),
              ],
              accountEpoch: 2,
              revocations: ['ab'.repeat(140)],
            },
          });
        }
        return Promise.resolve({ status: 500, body: {} });
      },
    };
    const { root, ctl } = setup(new AccountClient(transport));
    fill(root, '#dd-user', 'alice');
    fill(root, '#dd-pass', 'pw');
    submitForm(root);
    await waitFor(() => root.querySelector('.dd-blhead') !== null);
    openDeviceKeys(root);
    await waitFor(() => root.innerHTML.includes('THIS DEVICE'));

    click(root, '[data-action="revoke-device"][data-device="d2"]');
    await waitFor(() => root.innerHTML.includes('Revoke this device?'));
    click(root, '[data-action="revoke-confirm"]');
    await waitFor(() => calls.some((c) => c.path === '/api/revoke-device'));

    // Minted for the TARGET's signature key, and carried on the same call that burns the row.
    expect(ctl.mintedRevocations.map((m) => m.key)).toEqual([otherKey]);
    expect(calls.find((c) => c.path === '/api/revoke-device')?.body['record']).toBe(`rec-${otherKey}`);
    // And the records the server already holds were ingested, so this device's denylist is current
    // before it certifies anything.
    await waitFor(() => ctl.ingested.includes('ab'.repeat(140)));
  });

  it('SG1: a non-designated device DEFERS to the minter, then mints itself once the grace window passes', async () => {
    // The election used to be absolute: only the lowest-keyed device ever minted the self-group. If that
    // device could not mint (a cert-only phone cannot anchor a solo group), NO device formed it and the
    // account sat with two healthy devices and no self-group FOREVER — observed live (no formation for 19
    // hours, both devices online, so nothing synced). The fallback keeps the single-minter behavior for
    // one grace window, then lets a device that CAN mint do it.
    const LOWER = '0'.repeat(64); // sorts BELOW our SIG ('a'*64), so the SIBLING is the designated minter
    const transport = fakeTransport({
      '/api/login': { status: 200, body: { token: 'tok' } },
      '/api/add-device': { status: 200, body: { deviceId: 'd1' } },
      '/api/publish-keys': { status: 201 },
      '/api/list-devices': {
        status: 200,
        body: {
          devices: [
            device({ deviceId: 'd1', deviceKey: SIG, current: true }),
            device({ deviceId: 'd2', deviceKey: LOWER }),
          ],
        },
      },
      '/api/take-keys': {
        status: 200,
        body: { devices: [{ deviceKey: LOWER, keyPackage: 'abcd', lastResort: false }] },
      },
    });
    const ctl = new FakeController();
    const { root } = setup(new AccountClient(transport), ctl);
    fill(root, '#dd-user', 'alice');
    fill(root, '#dd-pass', 'pw');
    submitForm(root);
    await waitFor(() => root.querySelector('.dd-blhead') !== null);
    await new Promise((r) => setTimeout(r, 20));

    // Inside the grace window this device DEFERS: the designated (lower-keyed) sibling owns the mint.
    expect(ctl.mints).toHaveLength(0);

    // Past the window, with the designated device having still produced nothing, this device mints so the
    // account is not stranded without a self-group. Advance only Date.now (the window is a wall-clock
    // comparison); real timers keep the app's async chain running normally.
    const realNow = Date.now;
    const skewed = realNow() + 60000;
    vi.spyOn(Date, 'now').mockImplementation(() => skewed);
    try {
      document.dispatchEvent(new Event('visibilitychange')); // any later trigger re-runs ensureSelfGroup
      await waitFor(() => ctl.mints.length === 1);
      expect(ctl.mints[0]?.[0]?.deviceKey).toBe(LOWER); // it added the sibling
    } finally {
      vi.mocked(Date.now).mockRestore();
    }
  });

  it('SG1: the grace window expires on its OWN timer, with no later external trigger', async () => {
    // The window was a wall-clock comparison with NOTHING scheduled to re-read it: arming
    // selfMintDeferredSince recorded a timestamp and returned. So it expired only if some unrelated
    // event happened along afterwards — which is exactly why the test above has to dispatch
    // visibilitychange to make its mint happen. On a quiet, foregrounded tab no such event arrives and
    // the account never forms its self-group (the recorded 19-hour non-formation). Here the only thing
    // that happens after the deferral is armed is the clock advancing.
    const LOWER = '0'.repeat(64);
    const transport = fakeTransport({
      '/api/login': { status: 200, body: { token: 'tok' } },
      '/api/add-device': { status: 200, body: { deviceId: 'd1' } },
      '/api/publish-keys': { status: 201 },
      '/api/list-devices': {
        status: 200,
        body: {
          devices: [
            device({ deviceId: 'd1', deviceKey: SIG, current: true }),
            device({ deviceId: 'd2', deviceKey: LOWER }),
          ],
        },
      },
      '/api/take-keys': {
        status: 200,
        body: { devices: [{ deviceKey: LOWER, keyPackage: 'abcd', lastResort: false }] },
      },
    });
    const ctl = new FakeController();
    ctl.selfGroupExists = true; // login finds one, so no deferral is armed on real timers during startup
    const { root } = setup(new AccountClient(transport), ctl);
    fill(root, '#dd-user', 'alice');
    fill(root, '#dd-pass', 'pw');
    submitForm(root);
    await waitFor(() => root.querySelector('.dd-blhead') !== null);
    await new Promise((r) => setTimeout(r, 20));
    expect(ctl.mints).toHaveLength(0);

    vi.useFakeTimers();
    let onRealTimers = false;
    try {
      // The self-group is gone; ONE trigger arms the deferral (and, with the fix, schedules its timer).
      ctl.selfGroupExists = false;
      document.dispatchEvent(new Event('visibilitychange'));
      await vi.advanceTimersByTimeAsync(50);
      expect(ctl.mints).toHaveLength(0); // deferring: the lower-keyed sibling owns the mint

      // From here NOTHING external happens — no focus, no reconnect, no user action. Only the clock.
      await vi.advanceTimersByTimeAsync(20000); // past SELF_MINT_FALLBACK_MS + its jitter
      vi.useRealTimers();
      onRealTimers = true;
      await waitFor(() => ctl.mints.length === 1);
      expect(ctl.mints[0]?.[0]?.deviceKey).toBe(LOWER);
    } finally {
      if (!onRealTimers) {
        vi.useRealTimers();
      }
    }
  });

  it('backfills P7 records for devices revoked before records existed, once each', async () => {
    // The migration. An account that has been revoking devices since before P7 has burned server rows
    // and no records, so those devices are held out only by the epoch floor, which a seed-holder walks
    // straight over. Any device holding the account key mints the missing records on its first look at
    // the device list. It must mint ONE per device: a second, differently-sequenced record for the same
    // target would be equally valid and would inflate the derived epoch.
    const calls: Array<{ path: string; body: Record<string, unknown> }> = [];
    const goneKey = 'a'.repeat(64);
    const alsoGoneKey = 'b'.repeat(64);
    const transport: AccountTransport = {
      send(path, body) {
        calls.push({ path, body });
        if (path === '/api/login') {
          return Promise.resolve({ status: 200, body: { token: 'tok' } });
        }
        if (path === '/api/add-device') {
          return Promise.resolve({ status: 200, body: { deviceId: 'd1' } });
        }
        if (path === '/api/revoke-device') {
          return Promise.resolve({ status: 200, body: { ok: true, recordStored: true } });
        }
        if (path === '/api/list-devices') {
          return Promise.resolve({
            status: 200,
            body: {
              devices: [
                device({ deviceId: 'd1', deviceKey: SIG, current: true }),
                device({ deviceId: 'old1', deviceKey: goneKey, revoked: true }),
                device({ deviceId: 'old2', deviceKey: alsoGoneKey, revoked: true }),
              ],
              accountEpoch: 15, // far above the two tombstones: history was pruned, the counter was not
            },
          });
        }
        return Promise.resolve({ status: 500, body: {} });
      },
    };
    const ctl = new FakeController();
    // Model the crypto layer's own dedupe: a key we already hold a record for is not minted again.
    const held = new Set<string>();
    ctl.revokeDeviceKey = (key: string, seq: number): Promise<string | null> => {
      ctl.mintedRevocations.push({ key, seq });
      held.add(key);
      return Promise.resolve(`rec-${key}`);
    };
    ctl.isDeviceRevoked = (key: string): Promise<boolean> => Promise.resolve(held.has(key));

    const { root } = setup(new AccountClient(transport), ctl);
    fill(root, '#dd-user', 'alice');
    fill(root, '#dd-pass', 'pw');
    submitForm(root);
    await waitFor(() => root.querySelector('.dd-blhead') !== null);
    await waitFor(() => ctl.mintedRevocations.length === 2);

    // One record per revoked device, and none for the live one.
    expect(ctl.mintedRevocations.map((m) => m.key).sort()).toEqual([goneKey, alsoGoneKey].sort());
    const posted = calls.filter((c) => c.path === '/api/revoke-device').map((c) => c.body['record']);
    expect(posted.sort()).toEqual([`rec-${goneKey}`, `rec-${alsoGoneKey}`].sort());

    // A later pass over the same list mints nothing more.
    const before = ctl.mintedRevocations.length;
    openDeviceKeys(root);
    await waitFor(() => root.innerHTML.includes('THIS DEVICE'));
    expect(ctl.mintedRevocations.length).toBe(before);
  });

  it('a revoke still burns the server row when this device cannot sign a record', async () => {
    // A cert-only device holds no account key, so it cannot author the record. It must still be able to
    // revoke: losing the server-side burn too would leave the user with no way to cut a lost device off.
    const calls: Array<{ path: string; body: Record<string, unknown> }> = [];
    const transport: AccountTransport = {
      send(path, body) {
        calls.push({ path, body });
        if (path === '/api/login') {
          return Promise.resolve({ status: 200, body: { token: 'tok' } });
        }
        if (path === '/api/add-device') {
          return Promise.resolve({ status: 200, body: { deviceId: 'd1' } });
        }
        if (path === '/api/revoke-device') {
          return Promise.resolve({ status: 200, body: { ok: true, recordStored: false } });
        }
        if (path === '/api/list-devices') {
          return Promise.resolve({
            status: 200,
            body: {
              devices: [
                device({ deviceId: 'd1', deviceKey: SIG, current: true }),
                device({ deviceId: 'd2', deviceKey: 'e'.repeat(64) }),
              ],
            },
          });
        }
        return Promise.resolve({ status: 500, body: {} });
      },
    };
    const ctl = new FakeController();
    ctl.revokeMintFails = true;
    const { root } = setup(new AccountClient(transport), ctl);
    fill(root, '#dd-user', 'alice');
    fill(root, '#dd-pass', 'pw');
    submitForm(root);
    await waitFor(() => root.querySelector('.dd-blhead') !== null);
    openDeviceKeys(root);
    await waitFor(() => root.innerHTML.includes('THIS DEVICE'));

    click(root, '[data-action="revoke-device"][data-device="d2"]');
    await waitFor(() => root.innerHTML.includes('Revoke this device?'));
    click(root, '[data-action="revoke-confirm"]');

    await waitFor(() => calls.some((c) => c.path === '/api/revoke-device'));
    const call = calls.find((c) => c.path === '/api/revoke-device');
    expect(call?.body['deviceId']).toBe('d2');
    expect('record' in (call?.body ?? {})).toBe(false); // no record, and no crash
  });

  it('the Device keys Back button returns to the buddy list', async () => {
    const transport = fakeTransport({
      '/api/login': { status: 200, body: { token: 'tok' } },
      '/api/add-device': { status: 200, body: { deviceId: 'd1' } },
      '/api/publish-keys': { status: 201 },
      '/api/list-devices': { status: 200, body: { devices: [device({ deviceId: 'd1', deviceKey: SIG, current: true })] } },
    });
    const { root } = setup(new AccountClient(transport));
    fill(root, '#dd-user', 'alice');
    fill(root, '#dd-pass', 'pw');
    submitForm(root);
    await waitFor(() => root.querySelector('.dd-blhead') !== null);
    openDeviceKeys(root);
    await waitFor(() => root.innerHTML.includes('DEVICE KEYS'));
    click(root, '[data-action="settings-back"]');
    // Back closes Device keys and reveals the buddy list behind it (the Device keys window is gone).
    await waitFor(() => !root.innerHTML.includes('DEVICE KEYS'));
    expect(root.querySelector('.dd-blhead')).not.toBeNull(); // landed on the buddy list
  });

  it('Back from Device keys reveals the buddy list SYNCHRONOUSLY (no waiting on the worker queue)', async () => {
    const transport = fakeTransport({
      '/api/login': { status: 200, body: { token: 'tok' } },
      '/api/add-device': { status: 200, body: { deviceId: 'd1' } },
      '/api/publish-keys': { status: 201 },
      '/api/list-devices': { status: 200, body: { devices: [device({ deviceId: 'd1', deviceKey: SIG, current: true })] } },
    });
    const { root } = setup(new AccountClient(transport));
    fill(root, '#dd-user', 'alice');
    fill(root, '#dd-pass', 'pw');
    submitForm(root);
    await waitFor(() => root.querySelector('.dd-blhead') !== null);
    openDeviceKeys(root); // parks the buddy-list window behind Device Keys
    await waitFor(() => root.innerHTML.includes('DEVICE KEYS'));
    click(root, '[data-action="settings-back"]');
    // The FIRST click must visibly close Device Keys by revealing the parked buddy-list snapshot, with
    // NO await: a busy worker chain (a revoke cascade) must not be able to make Back look dead.
    expect(root.innerHTML.includes('DEVICE KEYS')).toBe(false);
    expect(root.querySelector('.dd-blhead')).not.toBeNull();
  });

  it('a roster-changed storm on Device keys coalesces to one refresh and never rebuilds an unchanged screen', async () => {
    // A revoke's removal cascade fires roster-changed once per conversation over several seconds. Each
    // full-DOM Settings rebuild EATS any tap in flight, which read as "Back needs several taps". The storm
    // must coalesce to ONE debounced device-list fetch, and an unchanged list must not rebuild the DOM.
    const transport = fakeTransport({
      '/api/login': { status: 200, body: { token: 'tok' } },
      '/api/add-device': { status: 200, body: { deviceId: 'd1' } },
      '/api/publish-keys': { status: 201 },
      '/api/list-devices': { status: 200, body: { devices: [device({ deviceId: 'd1', deviceKey: SIG, current: true })] } },
    });
    const { root, ctl } = setup(new AccountClient(transport));
    fill(root, '#dd-user', 'alice');
    fill(root, '#dd-pass', 'pw');
    submitForm(root);
    await waitFor(() => root.querySelector('.dd-blhead') !== null);
    openDeviceKeys(root);
    await waitFor(() => root.innerHTML.includes('DEVICE KEYS'));
    const backBefore = root.querySelector('[data-action="settings-back"]');
    const fetchesBefore = transport.calls.filter((c) => c.path === '/api/list-devices').length;

    vi.useFakeTimers();
    try {
      ctl.emit('roster-changed', { conversationId: 'c1' });
      ctl.emit('roster-changed', { conversationId: 'c2' });
      ctl.emit('roster-changed', { conversationId: 'c3' });
      vi.advanceTimersByTime(400); // past the debounce: exactly one trailing refresh fires
    } finally {
      vi.useRealTimers();
    }
    await waitFor(() => transport.calls.filter((c) => c.path === '/api/list-devices').length >= fetchesBefore + 1);
    await new Promise((r) => setTimeout(r, 10)); // let the refresh + the per-event reconcile fetches settle
    // Each roster-changed also runs reconcileRemovals (one list fetch each); the SETTINGS refresh itself
    // must have coalesced to at most one, so the total stays at 3 reconcile + 1 refresh, not 3 + 3.
    expect(transport.calls.filter((c) => c.path === '/api/list-devices').length).toBeLessThanOrEqual(fetchesBefore + 4);
    // The list did not change, so the screen was NOT rebuilt: the Back button is the very same node, and a
    // tap in flight during the storm could not have been eaten.
    expect(root.querySelector('[data-action="settings-back"]')).toBe(backBefore);
    // And one Back tap leaves cleanly.
    click(root, '[data-action="settings-back"]');
    await waitFor(() => !root.innerHTML.includes('DEVICE KEYS'));
    expect(root.querySelector('.dd-blhead')).not.toBeNull();
  });

  it('revoking a device durably re-keys it out of the open group (the fork-free MLS half)', async () => {
    // The server marks d2 revoked once /api/revoke-device is called, so the post-revoke reconcileRemovals
    // sees the fresh revoked list and drives d2 out of every conversation.
    let d2Revoked = false;
    const calls: Array<{ path: string; body: Record<string, unknown> }> = [];
    const t = {
      calls,
      send(path: string, body: Record<string, unknown>) {
        calls.push({ path, body });
        if (path === '/api/revoke-device') {
          d2Revoked = true;
          return Promise.resolve({ status: 200, body: { ok: true } });
        }
        if (path === '/api/list-devices') {
          return Promise.resolve({
            status: 200,
            body: {
              devices: [
                device({ deviceId: 'd1', deviceKey: SIG, current: true }),
                device({ deviceId: 'd2', deviceKey: 'e'.repeat(64), revoked: d2Revoked }),
              ],
            },
          });
        }
        if (path === '/api/add-device') return Promise.resolve({ status: 200, body: { deviceId: 'd1' } });
        if (path === '/api/publish-keys') return Promise.resolve({ status: 201, body: {} });
        if (path === '/api/login') return Promise.resolve({ status: 200, body: { token: 'tok' } });
        return Promise.resolve({ status: 500, body: {} });
      },
    };
    const { root, ctl } = setup(new AccountClient(t));
    fill(root, '#dd-user', 'alice');
    fill(root, '#dd-pass', 'pw');
    submitForm(root);
    await waitFor(() => root.querySelector('.dd-blhead') !== null);
    openDeviceKeys(root);
    await waitFor(() => root.innerHTML.includes('THIS DEVICE'));
    click(root, '[data-action="revoke-device"][data-device="d2"]');
    await waitFor(() => root.innerHTML.includes('Revoke this device?'));
    click(root, '[data-action="revoke-confirm"]');
    // After the revoke, reconcileRemovals is driven with d2's now-revoked key (the fork-free staged remove
    // then re-keys it out of every conversation in the GroupChannel).
    await waitFor(() => ctl.reconciledRemovals.some((keys) => keys.includes('e'.repeat(64))));
    expect(ctl.reconciledRemovals.some((keys) => keys.includes('e'.repeat(64)))).toBe(true);
  });

  it('lets you revoke the device you are on when others remain, and signs this device out', async () => {
    const t = fakeTransport({
      '/api/login': { status: 200, body: { token: 'tok' } },
      '/api/add-device': { status: 200, body: { deviceId: 'd1' } },
      '/api/revoke-device': { status: 200, body: { ok: true } },
      '/api/publish-keys': { status: 201 },
      '/api/list-devices': {
        status: 200,
        body: { devices: [device({ deviceId: 'd1', deviceKey: SIG, current: true }), device({ deviceId: 'd2', deviceKey: 'e'.repeat(64) })] },
      },
    });
    const { root, ctl } = setup(new AccountClient(t));
    fill(root, '#dd-user', 'alice');
    fill(root, '#dd-pass', 'pw');
    submitForm(root);
    await waitFor(() => root.querySelector('.dd-blhead') !== null);
    openDeviceKeys(root);
    await waitFor(() => root.innerHTML.includes('THIS DEVICE'));
    // Revoking THIS device opens a dedicated confirmation that warns it is the device you are on.
    click(root, '[data-action="revoke-device"][data-device="d1"]');
    await waitFor(() => root.innerHTML.includes('REVOKE THIS DEVICE'));
    expect(root.innerHTML).toContain('the device you are using right now');
    expect(t.calls.some((c) => c.path === '/api/revoke-device')).toBe(false); // nothing happens before confirm
    click(root, '[data-action="revokeself-confirm"]');
    await waitFor(() => t.calls.some((c) => c.path === '/api/revoke-device'));
    expect(t.calls.find((c) => c.path === '/api/revoke-device')?.body['deviceId']).toBe('d1');
    await waitFor(() => ctl.discarded.includes('alice')); // this device is crypto-erased on self-revoke
  });

  it('lets you back out of revoking THIS device from the confirmation screen', async () => {
    const t = fakeTransport({
      '/api/login': { status: 200, body: { token: 'tok' } },
      '/api/add-device': { status: 200, body: { deviceId: 'd1' } },
      '/api/revoke-device': { status: 200, body: { ok: true } },
      '/api/publish-keys': { status: 201 },
      '/api/list-devices': {
        status: 200,
        body: { devices: [device({ deviceId: 'd1', deviceKey: SIG, current: true }), device({ deviceId: 'd2', deviceKey: 'e'.repeat(64) })] },
      },
    });
    const { root } = setup(new AccountClient(t));
    fill(root, '#dd-user', 'alice');
    fill(root, '#dd-pass', 'pw');
    submitForm(root);
    await waitFor(() => root.querySelector('.dd-blhead') !== null);
    openDeviceKeys(root);
    await waitFor(() => root.innerHTML.includes('THIS DEVICE'));
    click(root, '[data-action="revoke-device"][data-device="d1"]');
    await waitFor(() => root.innerHTML.includes('REVOKE THIS DEVICE'));
    click(root, '[data-action="revokeself-cancel"]');
    await waitFor(() => root.innerHTML.includes('DEVICE KEYS')); // back to the device list, nothing revoked
    expect(t.calls.some((c) => c.path === '/api/revoke-device')).toBe(false);
  });

  it('blocks revoking your only device and points to Self Destruct', async () => {
    const t = fakeTransport({
      '/api/login': { status: 200, body: { token: 'tok' } },
      '/api/add-device': { status: 200, body: { deviceId: 'd1' } },
      '/api/publish-keys': { status: 201 },
      '/api/list-devices': { status: 200, body: { devices: [device({ deviceId: 'd1', deviceKey: SIG, current: true })] } },
    });
    const { root } = setup(new AccountClient(t));
    fill(root, '#dd-user', 'alice');
    fill(root, '#dd-pass', 'pw');
    submitForm(root);
    await waitFor(() => root.querySelector('.dd-blhead') !== null);
    openDeviceKeys(root);
    await waitFor(() => root.innerHTML.includes('THIS DEVICE'));
    // The sole device offers no revoke button and points to Self Destruct instead.
    expect(root.querySelector('[data-action="revoke-device"]')).toBeNull();
    expect(root.innerHTML).toContain('Use Self Destruct');
  });
});

describe('self destruct', () => {
  function loggedIn(): { root: HTMLElement; ctl: FakeController; t: ReturnType<typeof fakeTransport> } {
    const t = fakeTransport({
      '/api/login': { status: 200, body: { token: 'tok' } },
      '/api/add-device': { status: 200, body: { deviceId: 'd1' } },
      '/api/publish-keys': { status: 201 },
      '/api/list-devices': { status: 200, body: { devices: [device({ deviceId: 'd1', deviceKey: SIG, current: true })] } },
      '/api/delete-account': { status: 200, body: { ok: true } },
    });
    const { root, ctl } = setup(new AccountClient(t));
    fill(root, '#dd-user', 'alice');
    fill(root, '#dd-pass', 'pw');
    submitForm(root);
    return { root, ctl, t };
  }
  function submitDestruct(root: HTMLElement): void {
    root.querySelector('#dd-destruct-form')?.dispatchEvent(new Event('submit', { cancelable: true, bubbles: true }));
  }

  it('is the bottom item in the DEAD DROP menu, framed with skull and crossbones', async () => {
    const { root } = loggedIn();
    await waitFor(() => root.querySelector('.dd-blhead') !== null);
    click(root, '[data-action="app-menu"]');
    // Scope to the DEAD DROP dropdown itself (the buddy-list status menu also uses .dd-menu-dropitem).
    const pop = root.querySelector('.dd-appmenu-pop');
    const items = Array.from(pop?.querySelectorAll('.dd-menu-dropitem') ?? []).map((e) => e.getAttribute('data-action'));
    expect(items[items.length - 1]).toBe('self-destruct'); // bottom-most option
    expect(root.innerHTML).toContain('☠️ Self Destruct ☠️');
  });

  it('requires the passphrase twice, matching and correct, then deletes the account and wipes the device', async () => {
    const { root, ctl, t } = loggedIn();
    await waitFor(() => root.querySelector('.dd-blhead') !== null);
    openSelfDestruct(root);
    await waitFor(() => root.innerHTML.includes('SELF DESTRUCT'));
    // Mismatched: rejected, nothing deleted.
    fill(root, '#dd-destruct-pass', 'pw');
    fill(root, '#dd-destruct-pass2', 'nope');
    submitDestruct(root);
    await waitFor(() => root.innerHTML.includes('do not match'));
    expect(t.calls.some((c) => c.path === '/api/delete-account')).toBe(false);
    // Wrong passphrase (verifyPassphrase says no): rejected, nothing deleted.
    ctl.verifyPassphraseOk = false;
    fill(root, '#dd-destruct-pass', 'pw');
    fill(root, '#dd-destruct-pass2', 'pw');
    submitDestruct(root);
    await waitFor(() => root.innerHTML.includes('wrong passphrase'));
    expect(t.calls.some((c) => c.path === '/api/delete-account')).toBe(false);
    // Correct twice: the server account is deleted and this device is crypto-erased.
    ctl.verifyPassphraseOk = true;
    fill(root, '#dd-destruct-pass', 'pw');
    fill(root, '#dd-destruct-pass2', 'pw');
    submitDestruct(root);
    await waitFor(() => t.calls.some((c) => c.path === '/api/delete-account'));
    await waitFor(() => ctl.discarded.includes('alice'));
  });
});

describe('session resume on refresh (S1)', () => {
  it('boots to the unlock screen with the username pre-filled when a tab session is in progress', () => {
    sessionStorage.setItem('dd-resume', JSON.stringify({ username: 'alice' }));
    const root = document.createElement('div');
    document.body.appendChild(root);
    mountApp(root, new FakeController(), { wsUrl: 'ws://x/ws' });
    const userInput = root.querySelector('#dd-user');
    expect(userInput instanceof HTMLInputElement ? userInput.value : '').toBe('alice');
    // It is an unlock, not a fresh login: the username is pre-filled and the fresh-login instruction
    // subtitle is suppressed (a resumed session shows just the logo over the passphrase field).
    expect(root.innerHTML).not.toContain('enter your username and passphrase');
  });

  it('returns to the conversation that was open before the refresh, after re-unlocking', async () => {
    sessionStorage.setItem('dd-resume', JSON.stringify({ username: 'alice', conversationId: 'c1' }));
    const root = document.createElement('div');
    document.body.appendChild(root);
    const ctl = new FakeController();
    ctl.channelsList = [{ id: 'c1', peer: 'PEER', fingerprint: 'fp', status: 'secure', preview: '', unread: 0 }];
    mountApp(root, ctl, { wsUrl: 'ws://x/ws' });
    fill(root, '#dd-user', 'alice');
    fill(root, '#dd-pass', 'pw');
    submitForm(root);
    // Lands straight back in the conversation, not the channels list.
    await waitFor(() => root.innerHTML.includes('TRANSMIT'));
  });

  it('resumes back into Note to Self even though the self chat has no channel summary', async () => {
    sessionStorage.setItem('dd-resume', JSON.stringify({ username: 'alice', conversationId: 'c-self' }));
    const root = document.createElement('div');
    document.body.appendChild(root);
    const ctl = new FakeController();
    ctl.selfNoteId = 'c-self'; // openChannel proves the id is the self chat
    mountApp(root, ctl, { wsUrl: 'ws://x/ws' }); // channels list is EMPTY: the summary check misses it
    fill(root, '#dd-user', 'alice');
    fill(root, '#dd-pass', 'pw');
    submitForm(root);
    await waitFor(() => root.innerHTML.includes('only your devices see this'));
    expect(root.querySelector('#dd-compose-form')).not.toBeNull(); // typeable, not the dead prompt
  });

  it('revives a DEAD conversation view (secure=false, untypeable prompt) when the link comes up', async () => {
    sessionStorage.setItem('dd-resume', JSON.stringify({ username: 'alice', conversationId: 'c1' }));
    const root = document.createElement('div');
    document.body.appendChild(root);
    const ctl = new FakeController();
    ctl.channelsList = [{ id: 'c1', peer: 'PEER', fingerprint: 'fp', status: 'secure', preview: '', unread: 0 }];
    ctl.deadIds.add('c1'); // the session has not finished restoring: the view renders dead
    mountApp(root, ctl, { wsUrl: 'ws://x/ws' });
    fill(root, '#dd-user', 'alice');
    fill(root, '#dd-pass', 'pw');
    submitForm(root);
    await waitFor(() => root.innerHTML.includes('TRANSMIT'));
    expect(root.querySelector('#dd-compose-form')).toBeNull(); // dead: the read-only prompt
    expect(root.innerHTML).toContain('dd-cursor');
    // The session finishes restoring and the link becomes secure: the open view heals in place.
    ctl.deadIds.delete('c1');
    ctl.emit('connection', { state: 'secure' });
    await waitFor(() => root.querySelector('#dd-compose-form') !== null);
  });
});

describe('Buddy List Setup (BL)', () => {
  async function signedIn(): Promise<{ root: HTMLElement; ctl: FakeController }> {
    const { root, ctl } = setup(); // a plain login lands on the buddy list (home)
    fill(root, '#dd-user', 'alice');
    fill(root, '#dd-pass', 'hunter2');
    submitForm(root);
    await waitFor(() => root.querySelector('.dd-blhead') !== null);
    return { root, ctl };
  }
  async function openSetup(root: HTMLElement): Promise<void> {
    // Setup left the app menu: it is reached from the buddy list's bottom toolbar now.
    clickMenu(root, 'Buddies');
    await waitFor(() => root.innerHTML.includes('data-action="tbar-setup"'));
    click(root, '[data-action="tbar-setup"]');
    await waitFor(() => root.innerHTML.includes('BUDDY LIST SETUP'));
  }

  it('reaches Buddy List Setup from the buddy-list toolbar, drafts a group, and Save commits it', async () => {
    const { root, ctl } = await signedIn();
    await openSetup(root);
    fill(root, '#dd-setup-group-input', 'Family');
    click(root, '[data-action="setup-add-group"]');
    // The group appears in the DRAFT tree, but the store is untouched until Save.
    await waitFor(() => root.querySelector('[data-setup-sel="group:Family"]') !== null);
    expect(ctl.groups.some((g) => g.name === 'Family')).toBe(false);
    click(root, '[data-action="setup-save"]');
    await waitFor(() => ctl.groups.some((g) => g.name === 'Family'));
    await waitFor(() => root.innerHTML.includes('BUDDY LIST') && !root.innerHTML.includes('BUDDY LIST SETUP')); // back on the list
  });

  it('renames the built-in Buddies and Blocked groups; Save commits label-only and they keep working', async () => {
    const { root, ctl } = await signedIn();
    await openSetup(root);
    // The Blocked drop is auto-present (nobody blocked yet) and selectable.
    await waitFor(() => root.querySelector('[data-setup-sel="gblocked:"]') !== null);
    expect(root.innerHTML).toContain('(0)');
    // Rename the default Buddies group in the draft.
    click(root, '[data-setup-sel="group:Buddies"]');
    await waitFor(() => !root.innerHTML.includes('data-action="setup-rename" disabled'));
    fill(root, '#dd-setup-rename-input', 'Pals');
    click(root, '[data-action="setup-rename"]');
    await waitFor(() => root.innerHTML.includes('Pals'));
    expect(ctl.defaultName).toBe('Buddies'); // draft only until Save
    // Rename the Blocked drop in the draft too.
    click(root, '[data-setup-sel="gblocked:"]');
    await waitFor(() => !root.innerHTML.includes('data-action="setup-rename" disabled'));
    fill(root, '#dd-setup-rename-input', 'Enemies');
    click(root, '[data-action="setup-rename"]');
    await waitFor(() => root.innerHTML.includes('Enemies'));
    expect(ctl.blockedName).toBe('Blocked');
    // Save commits both renames BY ROLE (label-only; no group add/delete is fabricated from them).
    click(root, '[data-action="setup-save"]');
    await waitFor(() => ctl.defaultName === 'Pals' && ctl.blockedName === 'Enemies');
    expect(ctl.groups.some((g) => g.name === 'Pals' || g.name === 'Enemies')).toBe(false);
    // Back on the buddy list, both built-ins show their new names.
    await waitFor(() => root.innerHTML.includes('BUDDY LIST') && !root.innerHTML.includes('BUDDY LIST SETUP'));
    expect(root.innerHTML).toContain('Enemies');
  });

  it('never enables Delete for the built-ins (Buddies and the Blocked drop)', async () => {
    const { root } = await signedIn();
    await openSetup(root);
    await waitFor(() => root.querySelector('[data-setup-sel="gblocked:"]') !== null);
    click(root, '[data-setup-sel="gblocked:"]');
    await new Promise((r) => setTimeout(r, 10));
    expect(root.innerHTML).toContain('data-action="setup-delete" disabled');
    click(root, '[data-setup-sel="group:Buddies"]');
    await new Promise((r) => setTimeout(r, 10));
    expect(root.innerHTML).toContain('data-action="setup-delete" disabled');
  });

  it('Cancel forgets every draft edit and returns to the buddy list', async () => {
    const { root, ctl } = await signedIn();
    await openSetup(root);
    fill(root, '#dd-setup-group-input', 'Family');
    click(root, '[data-action="setup-add-group"]');
    await waitFor(() => root.querySelector('[data-setup-sel="group:Family"]') !== null);
    fill(root, '#dd-setup-buddy-input', 'raven');
    click(root, '[data-action="setup-add-buddy"]');
    await waitFor(() => root.innerHTML.includes('data-setup-sel="buddy:raven"'));
    click(root, '[data-action="setup-cancel"]');
    await waitFor(() => root.innerHTML.includes('BUDDY LIST') && !root.innerHTML.includes('BUDDY LIST SETUP'));
    expect(ctl.groups.some((g) => g.name === 'Family')).toBe(false); // nothing was written
    expect(ctl.buddies.some((b) => b.username === 'raven')).toBe(false);
  });

  it('selects a group, deletes it in the draft, and Save commits the removal', async () => {
    const { root, ctl } = await signedIn();
    ctl.groups = [{ name: 'Co-Workers' }];
    await openSetup(root);
    await waitFor(() => root.innerHTML.includes('data-setup-sel="group:Co-Workers"'));
    // Delete starts disabled with nothing selected.
    expect(root.innerHTML).toContain('data-action="setup-delete" disabled');
    click(root, '[data-setup-sel="group:Co-Workers"]'); // select it
    // The re-render enables Delete for this non-default group.
    await waitFor(() => !root.innerHTML.includes('data-action="setup-delete" disabled'));
    click(root, '[data-action="setup-delete"]');
    // Gone from the draft tree, still in the store until Save.
    await waitFor(() => !root.innerHTML.includes('data-setup-sel="group:Co-Workers"'));
    expect(ctl.groups.some((g) => g.name === 'Co-Workers')).toBe(true);
    click(root, '[data-action="setup-save"]');
    await waitFor(() => !ctl.groups.some((g) => g.name === 'Co-Workers'));
  });

  it('opens a read-only Buddy List (selectable names + toolbar) from the top menu', async () => {
    const { root, ctl } = await signedIn();
    ctl.buddies = [{ username: 'raven', addedAt: 0, group: 'Buddies' }];
    clickMenu(root, 'Buddies');
    // clickMenu('Buddies') re-fetches the roster; wait for raven (BUDDY LIST is already on screen).
    await waitFor(() => root.innerHTML.includes('data-buddy-select="raven"'));
    expect(root.innerHTML).toContain('data-buddy-select="raven"'); // click to select
    expect(root.innerHTML).toContain('dd-tree-buddy'); // plain name row
    expect(root.innerHTML).toContain('data-action="tbar-setup"'); // the bottom toolbar is present
    expect(root.innerHTML).not.toContain('data-action="buddy-add"'); // editing is only in Setup
  });

  it('selects a buddy from the tree, then Send IM opens a 1:1 conversation', async () => {
    const t = fakeTransport({
      '/api/login': { status: 200, body: { token: 'tok' } },
      '/api/take-keys': { status: 200, body: { devices: [{ deviceKey: PEER_KEY, keyPackage: 'abcd', lastResort: false }] } },
    });
    const { root, ctl } = setup(new AccountClient(t));
    ctl.buddies = [{ username: 'raven', addedAt: 0, group: 'Buddies' }];
    fill(root, '#dd-user', 'alice');
    fill(root, '#dd-pass', 'hunter2');
    submitForm(root);
    await waitFor(() => root.querySelector('.dd-blhead') !== null);
    clickMenu(root, 'Buddies');
    await waitFor(() => root.innerHTML.includes('data-buddy-select="raven"'));
    // Send IM is disabled until a buddy is selected.
    expect(root.innerHTML).toContain('data-action="tbar-send-im" disabled');
    click(root, '[data-buddy-select="raven"]'); // select raven
    await waitFor(() => !root.innerHTML.includes('data-action="tbar-send-im" disabled'));
    click(root, '[data-action="tbar-send-im"]');
    await waitFor(() => ctl.lastTargets !== null); // startConversation was called with the peer's devices
    expect(ctl.lastTargets?.some((d) => d.deviceKey === PEER_KEY)).toBe(true);
  });

  it('double-clicking a buddy opens a 1:1 conversation and stays there (no bounce back)', async () => {
    const t = fakeTransport({
      '/api/login': { status: 200, body: { token: 'tok' } },
      '/api/take-keys': { status: 200, body: { devices: [{ deviceKey: PEER_KEY, keyPackage: 'abcd', lastResort: false }] } },
    });
    const { root, ctl } = setup(new AccountClient(t));
    ctl.buddies = [{ username: 'raven', addedAt: 0, group: 'Buddies' }];
    fill(root, '#dd-user', 'alice');
    fill(root, '#dd-pass', 'hunter2');
    submitForm(root);
    await waitFor(() => root.querySelector('.dd-blhead') !== null);
    clickMenu(root, 'Buddies');
    await waitFor(() => root.innerHTML.includes('data-buddy-select="raven"'));
    // A real double-click fires click (detail 1), click (detail 2), then dblclick.
    const row = root.querySelector('[data-buddy-select="raven"]');
    row?.dispatchEvent(new MouseEvent('click', { bubbles: true, detail: 1 }));
    row?.dispatchEvent(new MouseEvent('click', { bubbles: true, detail: 2 }));
    row?.dispatchEvent(new MouseEvent('dblclick', { bubbles: true }));
    await waitFor(() => root.innerHTML.includes('TRANSMIT')); // opened the conversation
    // Let any trailing async buddy-list reload settle; the nav-generation guard must keep us in the chat.
    await new Promise((r) => setTimeout(r, 5));
    // The live (focused, non-parked) window is the chat, not the buddy list — no bounce back. The buddy
    // list may still sit PARKED behind it (multi-window desktop), which is expected.
    const liveTitle = root.querySelector('.dd-window:not(.dd-window-parked) .dd-title')?.textContent ?? '';
    expect(liveTitle).toContain('TRANSMIT');
    expect(liveTitle).not.toContain('BUDDY LIST');
  });
});

describe('contact QR deep link (#dd=)', () => {
  it('opening the app from a contact link lands on a New Channel start screen with the handle pre-filled', async () => {
    // Simulate arriving from a scanned contact QR: the URL fragment carries the handle.
    window.location.hash = '#dd=raven&k=5F·A2·91·C4';
    const t = fakeTransport({ '/api/login': { status: 200, body: { token: 'tok' } } });
    const { root } = setup(new AccountClient(t));
    // The app captures and clears the fragment at mount.
    expect(window.location.hash).toBe('');
    fill(root, '#dd-user', 'alice');
    fill(root, '#dd-pass', 'hunter2');
    submitForm(root);
    // After sign-in it opens the by-username start screen, pre-filled with the scanned handle.
    await waitFor(() => root.innerHTML.includes('NEW CHANNEL'));
    const peer = root.querySelector('#dd-peer-username');
    expect(peer instanceof HTMLInputElement ? peer.value : '').toBe('raven');
  });

  it('a contact link for your own handle is ignored (you do not message yourself)', async () => {
    window.location.hash = '#dd=alice';
    const t = fakeTransport({ '/api/login': { status: 200, body: { token: 'tok' } } });
    const { root } = setup(new AccountClient(t));
    fill(root, '#dd-user', 'alice');
    fill(root, '#dd-pass', 'hunter2');
    submitForm(root);
    await waitFor(() => root.querySelector('.dd-blhead') !== null); // normal channels list, not a start screen
    expect(root.innerHTML).not.toContain('NEW CHANNEL');
  });

  it('a link scanned before an unauthorized-device login is honored when wizard recovery completes', async () => {
    // Scan a contact link, then log in on a device the wizard must authorize first: that login returns
    // early into the wizard without consuming the link, and completing recovery finishes the landing it
    // deferred — the pre-filled start screen, not bare channels with the link leaking to a later login.
    window.location.hash = '#dd=raven';
    const t = fakeTransport({ '/api/login': { status: 200, body: { token: 'tok' } } });
    const { root, ctl } = setup(new AccountClient(t));
    ctl.authorizedState = { authorized: false, seedHolder: false };
    fill(root, '#dd-user', 'alice');
    fill(root, '#dd-pass', 'hunter2');
    submitForm(root);
    await waitFor(() => root.innerHTML.includes('CONNECT THIS DEVICE'));
    click(root, '[data-action="wizard-recover"]');
    await waitFor(() => root.querySelector('#dd-recovery-input') !== null);
    const ta = root.querySelector('#dd-recovery-input');
    if (ta instanceof HTMLTextAreaElement) {
      ta.value = 'f'.repeat(64);
    }
    click(root, '[data-action="recover-submit"]');
    await waitFor(() => root.innerHTML.includes('NEW CHANNEL'));
    const peer = root.querySelector('#dd-peer-username');
    expect(peer instanceof HTMLInputElement ? peer.value : '').toBe('raven');
    expect(sessionStorage.getItem('dd-contact')).toBeNull(); // consumed: nothing pending for the next login
  });

  it('a link scanned before an unauthorized-device login is honored when wizard provisioning completes', async () => {
    window.location.hash = '#dd=raven';
    const t = fakeTransport({
      '/api/login': { status: 200, body: { token: 'tok' } },
      '/api/publish-keys': { status: 201 },
    });
    const { root, ctl } = setup(new AccountClient(t));
    ctl.authorizedState = { authorized: false, seedHolder: false };
    fill(root, '#dd-user', 'alice');
    fill(root, '#dd-pass', 'hunter2');
    submitForm(root);
    await waitFor(() => root.innerHTML.includes('CONNECT THIS DEVICE'));
    click(root, '[data-action="wizard-provision"]');
    await waitFor(() => ctl.joined === 1);
    ctl.emit('show-code', { words: 'one two three four five six' });
    await waitFor(() => root.innerHTML.includes('one two three'));
    ctl.emit('provisioning-authorized', { accountPub: 'aa' });
    await waitFor(() => root.innerHTML.includes('DEVICE CONNECTED'));
    click(root, '[data-action="prov-done"]');
    await waitFor(() => root.innerHTML.includes('NEW CHANNEL'));
    const peer = root.querySelector('#dd-peer-username');
    expect(peer instanceof HTMLInputElement ? peer.value : '').toBe('raven');
    expect(sessionStorage.getItem('dd-contact')).toBeNull(); // consumed: nothing pending for the next login
  });

  it('a link scanned before registering is honored after the recovery-secret screen', async () => {
    // Scan a contact link, then create a NEW account: continuing past the one-time recovery secret
    // must land on the pre-filled start screen, not bare channels with the link leaking to a later login.
    window.location.hash = '#dd=raven';
    const t = fakeTransport({
      '/api/register': { status: 201, body: { token: 'tok' } },
      '/api/publish-keys': { status: 201 },
    });
    const { root, ctl } = setup(new AccountClient(t));
    ctl.secret = 'cafef00d'.repeat(8);
    click(root, '[data-action="to-register"]');
    fill(root, '#dd-user', 'alice');
    fill(root, '#dd-pass', 'hunter2');
    fill(root, '#dd-pass2', 'hunter2');
    submitForm(root);
    await waitFor(() => root.innerHTML.includes('RECOVERY SECRET'));
    click(root, '[data-action="recovery-continue"]');
    await waitFor(() => root.innerHTML.includes('NEW CHANNEL'));
    const peer = root.querySelector('#dd-peer-username');
    expect(peer instanceof HTMLInputElement ? peer.value : '').toBe('raven');
    expect(sessionStorage.getItem('dd-contact')).toBeNull(); // consumed: nothing pending for the next login
  });

  it('a link scanned before registering is honored when no recovery secret is shown', async () => {
    window.location.hash = '#dd=raven';
    const t = fakeTransport({ '/api/register': { status: 201, body: { token: 'tok' } } });
    const { root } = setup(new AccountClient(t));
    click(root, '[data-action="to-register"]');
    fill(root, '#dd-user', 'alice');
    fill(root, '#dd-pass', 'hunter2');
    fill(root, '#dd-pass2', 'hunter2');
    submitForm(root);
    await waitFor(() => root.innerHTML.includes('NEW CHANNEL'));
    const peer = root.querySelector('#dd-peer-username');
    expect(peer instanceof HTMLInputElement ? peer.value : '').toBe('raven');
    expect(sessionStorage.getItem('dd-contact')).toBeNull(); // consumed: nothing pending for the next login
  });
});

describe('device provisioning (model b)', () => {
  it('shows the recovery secret once after registration, then continues to channels', async () => {
    const t = fakeTransport({ '/api/register': { status: 201, body: { token: 'tok' } }, '/api/publish-keys': { status: 201 } });
    const { root, ctl } = setup(new AccountClient(t));
    ctl.secret = 'cafef00d'.repeat(8);
    click(root, '[data-action="to-register"]');
    fill(root, '#dd-user', 'alice');
    fill(root, '#dd-pass', 'hunter2');
    fill(root, '#dd-pass2', 'hunter2');
    submitForm(root);
    await waitFor(() => root.innerHTML.includes('RECOVERY SECRET'));
    expect(ctl.seededAccount).toBe(true); // this device became the seed-holder
    expect(root.innerHTML).toContain('cafef00d');
    click(root, '[data-action="recovery-continue"]');
    await waitFor(() => root.querySelector('.dd-blhead') !== null);
  });

  it('seed-holder: opens a window and confirms after the six words match', async () => {
    const t = fakeTransport({
      '/api/login': { status: 200, body: { token: 'tok' } },
      '/api/add-device': { status: 200, body: { deviceId: 'd1' } },
      '/api/publish-keys': { status: 201 },
      '/api/list-devices': { status: 200, body: { devices: [device({ deviceId: 'd1', deviceKey: SIG, current: true })] } },
    });
    const { root, ctl } = setup(new AccountClient(t));
    fill(root, '#dd-user', 'alice');
    fill(root, '#dd-pass', 'pw');
    submitForm(root);
    await waitFor(() => root.querySelector('.dd-blhead') !== null);
    openDeviceKeys(root);
    await waitFor(() => root.innerHTML.includes('Add a device'));
    click(root, '[data-action="add-device"]');
    await waitFor(() => ctl.windowOpened === 1);
    ctl.emit('confirm-device', { words: 'alpha bravo charlie delta echo foxtrot' });
    await waitFor(() => root.innerHTML.includes('alpha bravo charlie'));
    expect(root.innerHTML).toContain('The words match');
    click(root, '[data-action="prov-confirm"]');
    expect(ctl.confirmed).toBe(1);
  });

  it('new device: connects, shows the words without a confirm, then reports success', async () => {
    const t = fakeTransport({
      '/api/login': { status: 200, body: { token: 'tok' } },
      '/api/add-device': { status: 200, body: { deviceId: 'd2' } },
      '/api/publish-keys': { status: 201 },
      '/api/list-devices': { status: 200, body: { devices: [device({ deviceId: 'd2', deviceKey: SIG, current: true })] } },
    });
    const { root, ctl } = setup(new AccountClient(t));
    fill(root, '#dd-user', 'alice');
    fill(root, '#dd-pass', 'pw');
    submitForm(root);
    await waitFor(() => root.querySelector('.dd-blhead') !== null);
    openDeviceKeys(root);
    await waitFor(() => root.innerHTML.includes('Connect this device'));
    click(root, '[data-action="connect-this-device"]');
    await waitFor(() => ctl.joined === 1);
    ctl.emit('show-code', { words: 'one two three four five six' });
    await waitFor(() => root.innerHTML.includes('one two three'));
    expect(root.innerHTML).not.toContain('The words match'); // the new device does not confirm
    ctl.emit('provisioning-authorized', { accountPub: 'aa' });
    await waitFor(() => root.innerHTML.includes('DEVICE CONNECTED'));
  });

  it('a heal Welcome (established) right after DEVICE CONNECTED does not yank the new device into a chat', async () => {
    const t = fakeTransport({
      '/api/login': { status: 200, body: { token: 'tok' } },
      '/api/add-device': { status: 200, body: { deviceId: 'd2' } },
      '/api/publish-keys': { status: 201 },
      '/api/list-devices': { status: 200, body: { devices: [device({ deviceId: 'd2', deviceKey: SIG, current: true })] } },
    });
    const { root, ctl } = setup(new AccountClient(t));
    fill(root, '#dd-user', 'alice');
    fill(root, '#dd-pass', 'pw');
    submitForm(root);
    await waitFor(() => root.querySelector('.dd-blhead') !== null);
    openDeviceKeys(root);
    await waitFor(() => root.innerHTML.includes('Connect this device'));
    click(root, '[data-action="connect-this-device"]');
    await waitFor(() => ctl.joined === 1);
    ctl.emit('show-code', { words: 'one two three four five six' });
    await waitFor(() => root.innerHTML.includes('one two three'));
    ctl.emit('provisioning-authorized', { accountPub: 'aa' });
    await waitFor(() => root.innerHTML.includes('DEVICE CONNECTED'));
    // The seed-holder's post-add heal streams peer Welcomes, each firing 'established'. The sliding
    // post-provision latch must keep the new device on the DONE screen instead of auto-opening the chat.
    const before = ctl.openChannelCount;
    ctl.emit('established', { conversationId: 'c-heal' });
    await new Promise((r) => setTimeout(r, 5));
    expect(root.innerHTML).toContain('DEVICE CONNECTED'); // still the wizard done screen, not a conversation
    expect(ctl.openChannelCount).toBe(before); // suppressed before it even opened the channel
  });

  it('recovers this device by entering the recovery secret', async () => {
    const t = fakeTransport({
      '/api/login': { status: 200, body: { token: 'tok' } },
      '/api/add-device': { status: 200, body: { deviceId: 'd1' } },
      '/api/publish-keys': { status: 201 },
      '/api/list-devices': { status: 200, body: { devices: [device({ deviceId: 'd1', deviceKey: SIG, current: true })] } },
    });
    const { root, ctl } = setup(new AccountClient(t));
    fill(root, '#dd-user', 'alice');
    fill(root, '#dd-pass', 'pw');
    submitForm(root);
    await waitFor(() => root.querySelector('.dd-blhead') !== null);
    openDeviceKeys(root);
    await waitFor(() => root.innerHTML.includes('Use recovery secret'));
    click(root, '[data-action="use-recovery"]');
    await waitFor(() => root.querySelector('#dd-recovery-input') !== null);
    const ta = root.querySelector('#dd-recovery-input');
    if (ta instanceof HTMLTextAreaElement) {
      ta.value = 'aa'.repeat(32);
    }
    click(root, '[data-action="recover-submit"]');
    await waitFor(() => ctl.recovered !== null);
    expect(ctl.recovered).toBe('aa'.repeat(32));
    await waitFor(() => root.querySelector('.dd-blhead') !== null); // lands back on channels
  });
});

// Regression: a newly authorized device publishes its key package only AFTER the seed-holder's
// 'device-added' event, so the one-shot reconcile finds nothing claimable and the new (cert-only) device
// would sit on SECURING forever. healNewSibling polls (by the device's own key, carried on the event)
// until it becomes authorized + claimable, then heals it into the hidden self-group via reconcileSelf
// (reachable even when the seed-holder is not the lowest-keyed device, so it covers the S1 case), and
// settles precisely on self-group membership.
describe('post-join self-group heal (healNewSibling)', () => {
  const SIB = 'c'.repeat(64); // the newly added device's key (carried on device-added)

  // A seed-holder controller that owns the self-group and records the reconcileSelf admits the poll drives.
  // selfSiblingState / reconcileSelf are non-adder-scoped, so this covers the S1 case where the
  // seed-holder is not the lowest-keyed member.
  class SiblingHealController extends FakeController {
    reconcileSelfCalls: string[][] = []; // ownDeviceKeys passed to each reconcileSelf
    admitted = false; // has the new device been admitted to the self-group?
    reconcileSelf(ownDeviceKeys: readonly string[], _candidates: readonly DeviceTarget[]): Promise<void> {
      this.reconcileSelfCalls.push([...ownDeviceKeys]);
      this.admitted = true; // the staged add confirms into the self-group
      return Promise.resolve();
    }
    selfSiblingState(_deviceKey: string): Promise<'member' | 'pending' | 'absent' | 'none'> {
      // The established seed-holder already owns the self-group; the new device is absent until healed in.
      return Promise.resolve(this.admitted ? 'member' : 'absent');
    }
  }

  it('heals a device that publishes AFTER device-added into the self-group, then settles', async () => {
    let siblingLive = false; // the new device has not finished adopt -> enroll -> publish yet
    const t: AccountTransport = {
      send(path: string): Promise<{ status: number; body: Record<string, unknown> }> {
        if (path === '/api/login') return Promise.resolve({ status: 200, body: { token: 'tok' } });
        if (path === '/api/add-device') return Promise.resolve({ status: 200, body: { deviceId: 'd1' } });
        if (path === '/api/publish-keys') return Promise.resolve({ status: 201, body: {} });
        if (path === '/api/list-devices') {
          const devices = siblingLive
            ? [device({ deviceId: 'd1', deviceKey: SIG, current: true }), device({ deviceId: 'd2', deviceKey: SIB })]
            : [device({ deviceId: 'd1', deviceKey: SIG, current: true })];
          return Promise.resolve({ status: 200, body: { devices } });
        }
        if (path === '/api/take-keys') {
          const devices = siblingLive ? [{ deviceKey: SIB, keyPackage: 'abcd' }] : [];
          return Promise.resolve({ status: 200, body: { devices } });
        }
        return Promise.resolve({ status: 500, body: {} });
      },
    };
    const ctl = new SiblingHealController();
    const { root } = setup(new AccountClient(t), ctl);
    fill(root, '#dd-user', 'alice');
    fill(root, '#dd-pass', 'pw');
    submitForm(root);
    await waitFor(() => root.querySelector('.dd-blhead') !== null);

    vi.useFakeTimers();
    let onRealTimers = false;
    try {
      // The seed-holder authorizes the new device; device-added fires (with its key) BEFORE it publishes.
      ctl.emit('device-added', { deviceKey: SIB });
      // First poll: the device has not published, so nothing is claimed and it is not healed in.
      await vi.advanceTimersByTimeAsync(3100);
      expect(ctl.reconcileSelfCalls.length).toBe(0);
      // The new device finishes publishing; it is now authorized + claimable.
      siblingLive = true;
      // Fire the next tick, then hand back to real timers: the admit path awaits real WebCrypto
      // (takeKeys -> deriveUsernameHash), which fake timers cannot flush, so let it settle for real.
      await vi.advanceTimersByTimeAsync(3100);
      vi.useRealTimers();
      onRealTimers = true;
      await waitFor(() => ctl.reconcileSelfCalls.length === 1);
      // Healed into the self-group with both device keys in the roster.
      expect(ctl.reconcileSelfCalls).toEqual([[SIG, SIB]]);
      expect(ctl.admitted).toBe(true); // now a member: the next tick settles and the poll stops
    } finally {
      if (!onRealTimers) {
        vi.useRealTimers();
      }
    }
  });
});

describe('Note to Self', () => {
  // Signed in WITH an account (the self-group is an own-devices group, so it needs the account context).
  function loggedIn(): { root: HTMLElement; ctl: FakeController } {
    const t = fakeTransport({
      '/api/login': { status: 200, body: { token: 'tok' } },
      '/api/add-device': { status: 200, body: { deviceId: 'd1' } },
      '/api/publish-keys': { status: 201 },
      '/api/list-devices': { status: 200, body: { devices: [device({ deviceId: 'd1', deviceKey: SIG, current: true })] } },
    });
    const { root, ctl } = setup(new AccountClient(t));
    fill(root, '#dd-user', 'alice');
    fill(root, '#dd-pass', 'pw');
    submitForm(root);
    return { root, ctl };
  }

  // Note to Self left the app menu: it opens by messaging YOURSELF (New Channel with your own name, or
  // Send IM on yourself in the buddy list). These tests drive the New Channel route.
  async function startWithOwnName(root: HTMLElement): Promise<void> {
    clickMenu(root, 'Channels');
    await waitFor(() => root.querySelector('[data-action="new-channel"]') !== null);
    click(root, '[data-action="new-channel"]');
    await waitFor(() => root.querySelector('#dd-peer-username') !== null); // the start screen is async
    fill(root, '#dd-peer-username', 'Alice'); // own account, different case: still yourself
    click(root, '[data-action="accept-key"]');
  }

  it('is absent from the DEAD DROP menu and opens by messaging yourself, with no peer controls', async () => {
    const { root, ctl } = loggedIn();
    await waitFor(() => root.querySelector('.dd-blhead') !== null);
    expect(root.querySelector('[data-action="note-to-self"]')).toBeNull(); // not a menu item anymore
    ctl.emit('connection', { state: 'secure' }); // Note to Self rides the gateway, so it needs a live link
    await startWithOwnName(root);
    await waitFor(() => root.innerHTML.includes('only your devices see this'));
    expect(root.innerHTML).toContain('Note to Self');
    // The peer-only controls must be absent: Add would inject a peer into the own-devices self-group.
    expect(root.querySelector('[data-action="add-person"]')).toBeNull();
    expect(root.querySelector('[data-action="block-peer"]')).toBeNull();
    // The compose form is present so notes can be typed.
    expect(root.querySelector('#dd-compose-form')).not.toBeNull();
  });

  it('does not open Note to Self while the link is offline', async () => {
    const { root, ctl } = loggedIn();
    await waitFor(() => root.querySelector('.dd-blhead') !== null);
    ctl.emit('connection', { state: 'offline' });
    await startWithOwnName(root);
    await waitFor(() => true);
    expect(root.innerHTML).not.toContain('only your devices see this'); // refused while offline
  });
});

describe('blocked buddies in the list + setup', () => {
  it('shows a blocked buddy under Blocked by name, and Delete in Setup unblocks it back to its group', async () => {
    const { root, ctl } = setup(); // local-only login
    ctl.buddies = [{ username: 'raven', addedAt: 0, group: 'Buddies' }];
    ctl.blocked = [{ key: 'k1', fingerprint: '5F·A2·91·C4', username: 'raven' }];
    fill(root, '#dd-user', 'alice');
    fill(root, '#dd-pass', 'pw');
    submitForm(root);
    await waitFor(() => root.querySelector('.dd-blhead') !== null);
    clickMenu(root, 'Buddies');
    await waitFor(() => root.innerHTML.includes('Blocked'));
    // Blocked: raven is NOT a selectable buddy row; the Blocked drop names them.
    expect(root.querySelector('[data-buddy-select="raven"]')).toBeNull();
    expect(root.innerHTML).toContain('raven');
    // Setup: select the blocked row, Delete drafts the unblock, Save commits it and returns to the list.
    click(root, '[data-action="tbar-setup"]');
    await waitFor(() => root.innerHTML.includes('BUDDY LIST SETUP'));
    expect(root.innerHTML).toContain('data-setup-sel="blocked:k1"');
    click(root, '[data-setup-sel="blocked:k1"]');
    // The re-render enables Delete for the blocked selection (string-match like the sibling tests;
    // happy-dom's attribute :not() matching is unreliable).
    await waitFor(() => !root.innerHTML.includes('data-action="setup-delete" disabled'));
    click(root, '[data-action="setup-delete"]');
    await waitFor(() => !root.innerHTML.includes('data-setup-sel="blocked:k1"')); // gone from the draft
    expect(ctl.blocked.length).toBe(1); // still blocked in the store until Save
    click(root, '[data-action="setup-save"]');
    await waitFor(() => ctl.blocked.length === 0); // unblocked on Save
    // Save lands back on the buddy list, where raven is a normal selectable buddy again.
    await waitFor(() => root.querySelector('[data-buddy-select="raven"]') !== null);
  });
});

describe('buddy list header status control (the little ◆)', () => {
  async function onBuddyList(ctl?: (c: FakeController) => void): Promise<{ root: HTMLElement; c: FakeController }> {
    const { root, ctl: c } = setup(); // login lands on the buddy list (home)
    ctl?.(c);
    fill(root, '#dd-user', 'devinjacks');
    fill(root, '#dd-pass', 'pw');
    submitForm(root);
    await waitFor(() => root.querySelector('.dd-blhead') !== null);
    return { root, c };
  }

  it('the Profile editor opens from the toolbar; Cancel and Save both return to the buddy list', async () => {
    const { root } = await onBuddyList();
    click(root, '[data-action="tbar-profile"]');
    await waitFor(() => root.innerHTML.includes('data-action="id-save"'));
    click(root, '[data-action="id-cancel"]');
    // Cancel closes the Profile editor and focuses the buddy list behind it (the editor is gone).
    await waitFor(() => !root.innerHTML.includes('data-action="id-save"'));
    expect(root.querySelector('.dd-blhead')).not.toBeNull();
    // Reopen and Save → also closes the editor, back to the buddy list.
    click(root, '[data-action="tbar-profile"]');
    await waitFor(() => root.innerHTML.includes('data-action="id-save"'));
    click(root, '[data-action="id-save"]');
    await waitFor(() => !root.innerHTML.includes('data-action="id-save"'));
    expect(root.querySelector('.dd-blhead')).not.toBeNull();
  });

  it('opens the dropdown, and New Away Message opens the editor', async () => {
    const { root } = await onBuddyList();
    const menu = root.querySelector('#dd-status-menu');
    expect(menu instanceof HTMLElement && menu.hidden).toBe(true);
    click(root, '[data-action="status-menu"]');
    expect(menu instanceof HTMLElement && menu.hidden).toBe(false); // the dropdown opened
    expect(root.innerHTML).toContain('New Away Message');
    expect(root.innerHTML).not.toContain('data-action="status-away"'); // the old bare toggle is gone
    click(root, '[data-action="status-edit-away"]');
    await waitFor(() => root.innerHTML.includes('AWAY MESSAGE')); // the editor opens
  });

  it('saving a NEW away message puts it up immediately and adds it to the synced library', async () => {
    const { root, c } = await onBuddyList();
    click(root, '[data-action="status-menu"]');
    click(root, '[data-action="status-edit-away"]');
    await waitFor(() => root.querySelector('#dd-away-msg') !== null);
    (root.querySelector('#dd-away-msg') as HTMLElement).textContent = 'gone fishing';
    click(root, '[data-action="away-save"]');
    await waitFor(() => (c.identity.away.saved ?? []).includes('gone fishing')); // landed in the library
    // Saving PUT IT UP: you are away with the new message the moment you save.
    expect(c.identity.away.enabled).toBe(true);
    expect(c.identity.away.message).toBe('gone fishing');
    await waitFor(() => root.querySelector('.dd-blhead') !== null); // and Save returned to the buddy list
    // Go Online, then put the saved message back up from the dropdown in one click.
    click(root, '[data-action="status-menu"]');
    click(root, '[data-action="status-online"]');
    await waitFor(() => c.identity.away.enabled === false);
    click(root, '[data-action="status-menu"]');
    await waitFor(() => root.querySelector('[data-action="status-saved"]') !== null);
    click(root, '[data-action="status-saved"]');
    await waitFor(() => c.identity.away.enabled === true);
    expect(c.identity.away.message).toBe('gone fishing');
    expect((c.identity.away.saved ?? []).includes('gone fishing')).toBe(true); // the library survives
  });

  it('signing on marks you ONLINE: a fresh login takes a leftover away message down', async () => {
    const { root, ctl: c } = setup();
    c.identity = { ...DEFAULT_IDENTITY, away: { enabled: true, message: 'gone fishing', serverSide: false, saved: ['gone fishing'] } };
    fill(root, '#dd-user', 'devinjacks');
    fill(root, '#dd-pass', 'pw');
    submitForm(root);
    await waitFor(() => root.querySelector('.dd-blhead') !== null);
    await waitFor(() => c.identity.away.enabled === false); // auto-online on sign-in
    expect((c.identity.away.saved ?? []).includes('gone fishing')).toBe(true); // the library keeps it
  });

  it('the away editor dropdown loads a saved message into the editor, and Delete + Save removes one', async () => {
    const { root, c } = await onBuddyList((c) => {
      c.identity = { ...DEFAULT_IDENTITY, away: { enabled: false, message: '', serverSide: false, saved: ['at lunch', 'on a call'] } };
    });
    click(root, '[data-action="status-menu"]');
    click(root, '[data-action="status-edit-away"]');
    await waitFor(() => root.innerHTML.includes('saved away messages'));
    // Pick the second saved message from the dropdown: it lands in the editor.
    selectOption(root, '#dd-away-pick', '1');
    await waitFor(() => root.querySelector('#dd-away-msg') !== null);
    expect((root.querySelector('#dd-away-msg') as HTMLElement).textContent).toContain('on a call');
    // Select the first saved message and delete it, then Save: the library persists without it.
    selectOption(root, '#dd-away-pick', '0');
    await waitFor(() => (root.querySelector('#dd-away-msg') as HTMLElement).textContent?.includes('at lunch') === true);
    click(root, '[data-action="away-del-sel"]');
    await waitFor(() => !root.innerHTML.includes('>at lunch<'));
    click(root, '[data-action="away-save"]');
    await waitFor(() => !(c.identity.away.saved ?? []).includes('at lunch'));
    expect((c.identity.away.saved ?? []).includes('on a call')).toBe(true);
  });

  it('saving through the editor puts up the talk bubble and Online takes it down', async () => {
    const { root, c } = await onBuddyList((c) => {
      c.identity = { ...DEFAULT_IDENTITY, away: { enabled: false, message: 'gone fishing', serverSide: false } };
    });
    // New Away Message: the editor opens pre-filled with the current text; Save puts it up.
    click(root, '[data-action="status-menu"]');
    click(root, '[data-action="status-edit-away"]');
    await waitFor(() => root.querySelector('#dd-away-msg') !== null);
    click(root, '[data-action="away-save"]');
    await waitFor(() => c.identity.away.enabled === true);
    await waitFor(() => root.querySelector('.dd-blhead-status') !== null); // the talk bubble is up
    expect(root.innerHTML).toContain('gone fishing');
    expect(root.innerHTML).toContain('dd-st-away'); // the ◆ tinted away
    // Back Online: the away flag drops and the bubble goes with it (no profile text set).
    click(root, '[data-action="status-menu"]');
    click(root, '[data-action="status-online"]');
    await waitFor(() => c.identity.away.enabled === false);
    await waitFor(() => root.querySelector('.dd-blhead-status') === null);
    expect(root.innerHTML).toContain('dd-st-online');
  });

  it('your OWN entry in the buddy list shows your icon and reads online (authenticated to yourself)', async () => {
    const { root } = await onBuddyList((c) => {
      c.identity = { ...DEFAULT_IDENTITY, icon: { kind: 'emoji', value: '🦉', bg: '#2a52d6' } };
      c.buddies = [
        { username: 'devinjacks', addedAt: 0, group: 'Buddies' }, // yourself
        { username: 'raven', addedAt: 0, group: 'Buddies' }, // a stranger with no presence shared
      ];
    });
    const selfRow = root.querySelector('[data-buddy-select="devinjacks"]');
    expect(selfRow).not.toBeNull();
    // Your live status (no server presence opt-in needed) and your own buddy icon, not the ghost.
    expect(selfRow!.innerHTML).toContain('dd-status-secure'); // green online dot
    expect(selfRow!.innerHTML).toContain('🦉');
    // The stranger stays offline-gray; the self rule never leaks onto other buddies.
    const peerRow = root.querySelector('[data-buddy-select="raven"]');
    expect(peerRow!.innerHTML).toContain('dd-status-offline');
    expect(peerRow!.innerHTML).not.toContain('🦉');
  });

  it('your own buddy entry reads away (yellow) while your away message is up', async () => {
    const { root, c } = await onBuddyList((cc) => {
      cc.buddies = [{ username: 'devinjacks', addedAt: 0, group: 'Buddies' }];
    });
    // Go away AFTER signing in: signing on always starts you ONLINE now, so a pre-set away flag
    // would be taken down during login.
    c.identity = { ...DEFAULT_IDENTITY, away: { enabled: true, message: 'bbl', serverSide: false } };
    clickMenu(root, 'Buddies'); // re-render the list with the away state up
    await waitFor(() => root.querySelector('[data-buddy-select="devinjacks"]')?.innerHTML.includes('dd-status-pending') === true);
  });

  it('Buddy Info on yourself shows your own card with your live status', async () => {
    const { root } = await onBuddyList((c) => {
      c.identity = { ...DEFAULT_IDENTITY, bio: 'the operator herself' };
      c.buddies = [{ username: 'devinjacks', addedAt: 0, group: 'Buddies' }];
    });
    click(root, '[data-buddy-select="devinjacks"]'); // select yourself
    await waitFor(() => root.querySelector('[data-action="tbar-info"][disabled]') === null);
    click(root, '[data-action="tbar-info"]');
    await waitFor(() => root.innerHTML.includes('GET INFO'));
    expect(root.innerHTML).toContain('the operator herself'); // your own profile, no peer lookup
    expect(root.innerHTML).toContain('online'); // authenticated to yourself: live status shown
    // Your own card carries the own-card note, never the peer trust warning.
    expect(root.innerHTML).toContain('This is your own buddy info');
    expect(root.innerHTML).not.toContain('does not prove who they are');
  });

  it('your live identity icon beats a stale cached icon under your own username', async () => {
    const { root } = await onBuddyList((c) => {
      c.identity = { ...DEFAULT_IDENTITY, icon: { kind: 'emoji', value: '🦉', bg: '#2a52d6' } };
      c.buddies = [
        { username: 'devinjacks', addedAt: 0, group: 'Buddies' },
        { username: 'raven', addedAt: 0, group: 'Buddies' },
      ];
      // A stale icon cache that holds an OLD icon under our own username (e.g. learned over the
      // self-group before an icon change); the live identity card must win on our own row.
      (c as unknown as Record<string, unknown>)['buddyIcons'] = (us: readonly string[]) =>
        Promise.resolve(Object.fromEntries(us.map((u) => [u, { kind: 'emoji', value: '🐌', bg: '#111' }])));
    });
    const selfRow = root.querySelector('[data-buddy-select="devinjacks"]');
    expect(selfRow!.innerHTML).toContain('🦉'); // the live icon, not the stale cache
    expect(selfRow!.innerHTML).not.toContain('🐌');
    const peerRow = root.querySelector('[data-buddy-select="raven"]');
    expect(peerRow!.innerHTML).toContain('🐌'); // a peer keeps its cached icon
  });

  it('the self rules still fire when the login was typed with different case', async () => {
    const { root, ctl: c } = setup();
    c.identity = { ...DEFAULT_IDENTITY, icon: { kind: 'emoji', value: '🦉', bg: '#2a52d6' } };
    c.buddies = [{ username: 'devinjacks', addedAt: 0, group: 'Buddies' }]; // stored normalized
    fill(root, '#dd-user', 'DevinJacks'); // typed with caps at login
    fill(root, '#dd-pass', 'pw');
    submitForm(root);
    await waitFor(() => root.querySelector('.dd-blhead') !== null);
    clickMenu(root, 'Buddies');
    await waitFor(() => root.querySelector('.dd-blhead') !== null);
    const selfRow = root.querySelector('[data-buddy-select="devinjacks"]');
    expect(selfRow!.innerHTML).toContain('dd-status-secure'); // normalizeUsername bridges the case gap
    expect(selfRow!.innerHTML).toContain('🦉');
  });

  it('Buddy List Setup also shows your own entry with your live status', async () => {
    const { root } = await onBuddyList((c) => {
      c.buddies = [{ username: 'devinjacks', addedAt: 0, group: 'Buddies' }];
    });
    click(root, '[data-action="tbar-setup"]');
    await waitFor(() => root.innerHTML.includes('BUDDY LIST SETUP'));
    const selfRow = root.querySelector('[data-setup-sel="buddy:devinjacks"]');
    expect(selfRow!.innerHTML).toContain('dd-status-secure'); // online here too, same self rule
  });

  it('the compose is a › prompt line with the ⏳ picker, and Send carries the picked lifetime', async () => {
    const { root, c } = await onBuddyList((cc) => {
      cc.buddies = [{ username: 'devinjacks', addedAt: 0, group: 'Buddies' }];
    });
    c.emit('connection', { state: 'secure' }); // Note to Self rides the gateway
    root.querySelector('[data-buddy-select="devinjacks"]')!.dispatchEvent(new Event('dblclick', { bubbles: true }));
    await waitFor(() => root.querySelector('#dd-compose-form') !== null);
    // The CRT prompt line + the lifetime picker; the app emoji dialog is gone (native input instead).
    expect(root.querySelector('.dd-compose-rich .dd-rt-line .dd-prompt')).not.toBeNull();
    expect(root.innerHTML).toContain('data-rt-pop="timer"');
    expect(root.innerHTML).not.toContain('data-rt-pop="emoji"');
    // EVERY protocol lifetime is offered now that the storage layer enforces them all: burn-on-read
    // (read latch + crypto-erase in openChannel), the durations, and until-revoked (revoke frames).
    expect(root.innerHTML).toContain('data-rt-life="burn"');
    expect(root.innerHTML).toContain('data-rt-life="keep"');
    // FIRST send without touching the picker: the long-standing 24h default must reach the wire.
    let input = root.querySelector('#dd-compose-input');
    (input as HTMLElement).textContent = 'default lifetime';
    root.querySelector('#dd-compose-form')!.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
    await waitFor(() => c.lastSendLifetime !== undefined);
    expect(c.lastSendLifetime).toEqual({ kind: 'duration', seconds: 86400 });
    // Now pick 5 seconds (toolbar buttons act on mousedown), type, and send again.
    await waitFor(() => root.querySelector('[data-rt-life="5"]') !== null);
    root.querySelector('[data-rt-life="5"]')!.dispatchEvent(new Event('mousedown', { bubbles: false, cancelable: true }));
    input = root.querySelector('#dd-compose-input');
    (input as HTMLElement).textContent = 'five seconds';
    root.querySelector('#dd-compose-form')!.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
    await waitFor(() => c.lastSendLifetime?.kind === 'duration' && c.lastSendLifetime.seconds === 5);
    expect(c.lastSendLifetime).toEqual({ kind: 'duration', seconds: 5 });
    // Burn on read reaches the wire as its protocol kind.
    root.querySelector('[data-rt-life="burn"]')!.dispatchEvent(new Event('mousedown', { bubbles: false, cancelable: true }));
    input = root.querySelector('#dd-compose-input');
    (input as HTMLElement).textContent = 'one look';
    root.querySelector('#dd-compose-form')!.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
    await waitFor(() => c.lastSendLifetime?.kind === 'burn-on-read');
    expect(c.lastSendLifetime).toEqual({ kind: 'burn-on-read' });
    // Until revoked too.
    root.querySelector('[data-rt-life="keep"]')!.dispatchEvent(new Event('mousedown', { bubbles: false, cancelable: true }));
    input = root.querySelector('#dd-compose-input');
    (input as HTMLElement).textContent = 'recallable';
    root.querySelector('#dd-compose-form')!.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
    await waitFor(() => c.lastSendLifetime?.kind === 'until-revoked');
    expect(c.lastSendLifetime).toEqual({ kind: 'until-revoked' });
    // Reset the module-level pick to the default so later tests see the 24h default.
    await waitFor(() => root.querySelector('[data-rt-life="86400"]') !== null);
    root.querySelector('[data-rt-life="86400"]')!.dispatchEvent(new Event('mousedown', { bubbles: false, cancelable: true }));
  });

  it('keeps the compose focused after a send, so you can keep typing without clicking back in', async () => {
    const { root, c } = await onBuddyList((cc) => {
      cc.buddies = [{ username: 'devinjacks', addedAt: 0, group: 'Buddies' }];
    });
    c.emit('connection', { state: 'secure' });
    root.querySelector('[data-buddy-select="devinjacks"]')!.dispatchEvent(new Event('dblclick', { bubbles: true }));
    await waitFor(() => root.querySelector('#dd-compose-form') !== null);
    const before = root.querySelector('#dd-compose-input') as HTMLElement;
    // Blur first, so the assertion can only pass if the SEND re-render actively re-focuses a fresh compose,
    // not because the pre-send element happened to already be focused (that would make the test a tautology).
    before.blur();
    expect(document.activeElement).not.toBe(before);
    before.textContent = 'first line';
    root.querySelector('#dd-compose-form')!.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
    // The send rebuilds the view: wait for a NEW compose element and assert THAT one holds focus.
    await waitFor(() => {
      const el = root.querySelector('#dd-compose-input');
      return el !== null && el !== before && document.activeElement === el;
    });
    expect((document.activeElement as HTMLElement).id).toBe('dd-compose-input');
    expect(document.activeElement).not.toBe(before); // it is the post-send element, not the stale one
  });

  it('a chrome-identical send takes the log-only fast path: the compose and log nodes survive (no teardown)', async () => {
    const { root, c } = await onBuddyList((cc) => {
      cc.buddies = [{ username: 'devinjacks', addedAt: 0, group: 'Buddies' }];
    });
    c.emit('connection', { state: 'secure' });
    root.querySelector('[data-buddy-select="devinjacks"]')!.dispatchEvent(new Event('dblclick', { bubbles: true }));
    await waitFor(() => root.querySelector('#dd-compose-form') !== null);
    // FIRST send: the view's peer label changes (open vs send models differ in the fake), so the full
    // render runs and replaces the DOM. That leaves the view chrome identical to any FURTHER send.
    (root.querySelector('#dd-compose-input') as HTMLElement).textContent = 'first';
    root.querySelector('#dd-compose-form')!.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
    await waitFor(() => root.querySelector('#dd-compose-input') !== null && document.activeElement === root.querySelector('#dd-compose-input'));
    const composeNode = root.querySelector('#dd-compose-input');
    const logNode = root.querySelector('.dd-log');
    expect(logNode).not.toBeNull();
    // SECOND send: nothing outside the log differs, so the fast path must reuse the live DOM. A teardown
    // here would replace both nodes (the pre-fast-path behavior) and cost a full rewire per message.
    (composeNode as HTMLElement).textContent = 'second';
    root.querySelector('#dd-compose-form')!.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
    await new Promise((r) => setTimeout(r, 10));
    expect(root.querySelector('#dd-compose-input')).toBe(composeNode); // same node: no innerHTML teardown
    expect(root.querySelector('.dd-log')).toBe(logNode); // the log element itself also survives
    expect(document.activeElement).toBe(composeNode); // and the caret never left the compose
  });

  it('a revoke control painted by the log-only fast path is live (rewired after the innerHTML swap)', async () => {
    const { root, c } = await onBuddyList((cc) => {
      cc.buddies = [{ username: 'devinjacks', addedAt: 0, group: 'Buddies' }];
    });
    c.emit('connection', { state: 'secure' });
    root.querySelector('[data-buddy-select="devinjacks"]')!.dispatchEvent(new Event('dblclick', { bubbles: true }));
    await waitFor(() => root.querySelector('#dd-compose-form') !== null);
    // FIRST send: full render (chrome differs on open vs send). Leaves the chrome identical for the next.
    (root.querySelector('#dd-compose-input') as HTMLElement).textContent = 'first';
    root.querySelector('#dd-compose-form')!.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
    await waitFor(() => root.querySelector('#dd-compose-input') !== null && document.activeElement === root.querySelector('#dd-compose-input'));
    const logNode = root.querySelector('.dd-log');
    // SECOND send returns an until-revoked message: the fast path repaints the log, and the fresh control
    // must be wired — an unwired button here silently disables message revocation during normal chatting.
    c.sendLog = [{ kind: 'message', sender: 'YOU', text: 'recallable', lifetime: { kind: 'until-revoked' }, remainingSeconds: null, messageId: 'm9', canRevoke: true }];
    (root.querySelector('#dd-compose-input') as HTMLElement).textContent = 'second';
    root.querySelector('#dd-compose-form')!.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
    await waitFor(() => root.querySelector('[data-action="revoke-msg"]') !== null);
    expect(root.querySelector('.dd-log')).toBe(logNode); // proves the FAST path painted this control
    click(root, '[data-action="revoke-msg"]');
    await waitFor(() => c.revoked.length === 1);
    expect(c.revoked[0]).toEqual({ conversationId: 'c1', messageId: 'm9' });
  });

  it('Remove Channel is two-tap: the first arms with a toast, the second retires and leaves the chat', async () => {
    const { root, c } = await onBuddyList((cc) => {
      cc.channelsList = [{ id: 'c1', peer: 'PEER', fingerprint: '', status: 'secure' as const, preview: '', unread: 0 }];
    });
    c.emit('connection', { state: 'secure' });
    clickMenu(root, 'Channels');
    await waitFor(() => root.querySelector('[data-channel="c1"]') !== null);
    click(root, '[data-channel="c1"]');
    await waitFor(() => root.querySelector('[data-action="remove-channel"]') !== null);
    click(root, '[data-action="remove-channel"]');
    await new Promise((r) => setTimeout(r, 5));
    expect(c.removed).toEqual([]); // armed only: nothing retired yet
    expect(root.querySelector('.dd-toast')).not.toBeNull(); // and the explainer toast is up
    click(root, '[data-action="remove-channel"]');
    await waitFor(() => c.removed.length === 1);
    expect(c.removed[0]).toBe('c1');
    await waitFor(() => root.querySelector('#dd-compose-input') === null); // the retired chat pane is gone
  });

  it('Block is two-tap now that it closes for good: the first arms, the second blocks', async () => {
    const { root, c } = await onBuddyList((cc) => {
      cc.channelsList = [{ id: 'c1', peer: 'PEER', fingerprint: '', status: 'secure' as const, preview: '', unread: 0 }];
    });
    c.emit('connection', { state: 'secure' });
    clickMenu(root, 'Channels');
    await waitFor(() => root.querySelector('[data-channel="c1"]') !== null);
    click(root, '[data-channel="c1"]');
    await waitFor(() => root.querySelector('[data-action="block-peer"]') !== null);
    click(root, '[data-action="block-peer"]');
    await new Promise((r) => setTimeout(r, 5));
    expect(c.blockedConvs).toEqual([]); // armed only
    click(root, '[data-action="block-peer"]');
    await waitFor(() => c.blockedConvs.length === 1);
    expect(c.blockedConvs[0]).toBe('c1');
  });

  it('the away-reply repaint never burns an on-screen burn-on-read message', async () => {
    const { root, c } = await onBuddyList((cc) => {
      cc.buddies = [{ username: 'devinjacks', addedAt: 0, group: 'Buddies' }];
      cc.conversationLog = [
        { kind: 'message', sender: 'PEER', text: 'read once and gone', lifetime: { kind: 'burn-on-read' }, remainingSeconds: null },
      ];
    });
    c.emit('connection', { state: 'secure' });
    root.querySelector('[data-buddy-select="devinjacks"]')!.dispatchEvent(new Event('dblclick', { bubbles: true }));
    await waitFor(() => root.innerHTML.includes('read once and gone'));
    const opensBefore = c.openChannelCount;
    // Our own away auto-reply lands while a burn-on-read message is on screen. Rebuilding would spend
    // its one permitted read and replace the plaintext with a tombstone, with nobody looking.
    c.emit('outbound-appended', { conversationId: 'c1' });
    await new Promise((r) => setTimeout(r, 10));
    expect(c.openChannelCount).toBe(opensBefore); // no rebuild at all
    expect(root.innerHTML).toContain('read once and gone'); // the plaintext survives
  });

  it("a sibling's away change lands on the PARKED buddy list, and returning home shows it", async () => {
    const { root, c } = await onBuddyList((cc) => {
      cc.buddies = [{ username: 'devinjacks', addedAt: 0, group: 'Buddies' }]; // our own row
      cc.channelsList = [{ id: 'c1', peer: 'PEER', fingerprint: '', status: 'secure' as const, preview: '', unread: 0 }];
    });
    c.emit('connection', { state: 'secure' });
    clickMenu(root, 'Channels'); // the buddy list parks behind Channels: it is still painted, frozen
    await waitFor(() => root.querySelector('[data-channel="c1"]') !== null);
    expect(root.innerHTML).not.toContain('gone fishing');
    // The laptop set an away message; this device adopted it while the buddy list sat parked. Before
    // the fix the event was dropped here and the stale bubble persisted until something re-read the card.
    const away = { ...c.identity, away: { ...c.identity.away, enabled: true, message: 'gone fishing' } };
    c.identity = away;
    c.emit('identity-updated', { profile: away });
    await waitFor(() => root.innerHTML.includes('gone fishing'));
    // And returning home hydrates rather than repainting the frozen snapshot verbatim.
    clickMenu(root, 'Buddy List');
    await waitFor(() => root.querySelector('.dd-blhead') !== null);
    expect(root.innerHTML).toContain('gone fishing');
  });

  it('a toast survives a full render that lands mid-lifetime', async () => {
    const { root, c } = await onBuddyList((cc) => {
      cc.buddies = [{ username: 'devinjacks', addedAt: 0, group: 'Buddies' }];
    });
    c.emit('connection', { state: 'secure' });
    c.emit('inbound-message', { conversationId: 'c9' }); // not the open conversation: notifies via a toast
    await waitFor(() => root.querySelector('.dd-toast') !== null);
    const toast = root.querySelector('.dd-toast');
    clickMenu(root, 'Channels'); // a full render (root.innerHTML swap) lands while the toast is alive
    await waitFor(() => root.querySelector('[data-action="new-channel"]') !== null);
    expect(root.querySelector('.dd-toast')).toBe(toast); // the same node outlived the swap
  });

  it("the mobile '‹ Channels' back button stashes a half-typed draft and reopening the row restores it", async () => {
    const { root, c } = await onBuddyList((cc) => {
      cc.channelsList = [{ id: 'c1', peer: 'PEER', fingerprint: '', status: 'secure', preview: '', unread: 0 }];
    });
    c.emit('connection', { state: 'secure' });
    clickMenu(root, 'Channels');
    await waitFor(() => root.querySelector('[data-channel="c1"]') !== null);
    click(root, '[data-channel="c1"]');
    await waitFor(() => root.querySelector('#dd-compose-input') !== null);
    (root.querySelector('#dd-compose-input') as HTMLElement).textContent = 'half typed thought';
    click(root, '[data-action="channels-show-list"]');
    await waitFor(() => root.querySelector('#dd-compose-input') === null); // back on the list: the pane is gone
    click(root, '[data-channel="c1"]');
    await waitFor(() => root.querySelector('#dd-compose-input') !== null);
    expect((root.querySelector('#dd-compose-input') as HTMLElement).textContent).toContain('half typed thought');
  });

  it('does NOT refocus the compose on an inbound message, so reading is not interrupted', async () => {
    const { root, c } = await onBuddyList((cc) => {
      cc.buddies = [{ username: 'devinjacks', addedAt: 0, group: 'Buddies' }];
    });
    c.emit('connection', { state: 'secure' });
    root.querySelector('[data-buddy-select="devinjacks"]')!.dispatchEvent(new Event('dblclick', { bubbles: true }));
    await waitFor(() => root.querySelector('#dd-compose-form') !== null);
    const before = root.querySelector('#dd-compose-input') as HTMLElement;
    before.blur(); // the user scrolled up reading, not typing
    expect(document.activeElement).not.toBe(before);
    // An inbound message for the OPEN conversation rebuilds it, but must NOT grab focus back to the compose
    // (a programmatic focus scrolls the mobile viewport and steals the caret mid-read).
    c.emit('inbound-message', { conversationId: 'c1' });
    await waitFor(() => {
      const el = root.querySelector('#dd-compose-input');
      return el !== null && el !== before; // the receive rebuilt the view (a fresh compose element)
    });
    expect(document.activeElement).not.toBe(root.querySelector('#dd-compose-input')); // receive did not refocus
  });

  it('the revoke control calls revokeMessage with the message id and re-renders the conversation', async () => {
    const { root, c } = await onBuddyList((cc) => {
      cc.buddies = [{ username: 'devinjacks', addedAt: 0, group: 'Buddies' }];
      cc.conversationLog = [
        { kind: 'message', sender: 'YOU', text: 'recallable', lifetime: { kind: 'until-revoked' }, remainingSeconds: null, messageId: 'm1', canRevoke: true },
      ];
    });
    c.emit('connection', { state: 'secure' });
    root.querySelector('[data-buddy-select="devinjacks"]')!.dispatchEvent(new Event('dblclick', { bubbles: true }));
    await waitFor(() => root.querySelector('[data-action="revoke-msg"]') !== null);
    click(root, '[data-action="revoke-msg"]');
    await waitFor(() => c.revoked.length === 1);
    expect(c.revoked[0]).toEqual({ conversationId: 'c1', messageId: 'm1' });
    // The refreshed view (the revoked copy is gone) replaces the old one: the control disappears.
    await waitFor(() => root.querySelector('[data-action="revoke-msg"]') === null);
  });

  it('a failed revoke keeps the message on screen and says so', async () => {
    const { root, c } = await onBuddyList((cc) => {
      cc.buddies = [{ username: 'devinjacks', addedAt: 0, group: 'Buddies' }];
      cc.revokeOk = false;
      cc.conversationLog = [
        { kind: 'message', sender: 'YOU', text: 'recallable', lifetime: { kind: 'until-revoked' }, remainingSeconds: null, messageId: 'm1', canRevoke: true },
      ];
    });
    c.emit('connection', { state: 'secure' });
    root.querySelector('[data-buddy-select="devinjacks"]')!.dispatchEvent(new Event('dblclick', { bubbles: true }));
    await waitFor(() => root.querySelector('[data-action="revoke-msg"]') !== null);
    click(root, '[data-action="revoke-msg"]');
    await waitFor(() => root.innerHTML.includes('could not revoke'));
    expect(root.innerHTML).toContain('recallable'); // the stored copy (and its control) survive
  });

  it('an erased event re-renders only its own conversation and never for a burn reason', async () => {
    const { root, c } = await onBuddyList((cc) => {
      cc.buddies = [{ username: 'devinjacks', addedAt: 0, group: 'Buddies' }];
    });
    c.emit('connection', { state: 'secure' });
    root.querySelector('[data-buddy-select="devinjacks"]')!.dispatchEvent(new Event('dblclick', { bubbles: true }));
    await waitFor(() => root.querySelector('#dd-compose-form') !== null);
    const before = c.openChannelCount;
    // A burn erase fires during the very view build that read the message: never re-render on it.
    c.emit('erased', { messageId: 'x', reason: 'burn', conversationId: 'c1' });
    // An expiry in a DIFFERENT conversation must not touch this view either (it would consume or
    // tombstone an on-screen burn message over an unrelated event).
    c.emit('erased', { messageId: 'y', reason: 'duration', conversationId: 'other' });
    await new Promise((r) => setTimeout(r, 5));
    expect(c.openChannelCount).toBe(before);
    // An expiry in THIS conversation refreshes it so the rendered copy drops.
    c.emit('erased', { messageId: 'y', reason: 'duration', conversationId: 'c1' });
    await waitFor(() => c.openChannelCount === before + 1);
  });

  it('carries a half-typed compose draft across a same-conversation re-render (incoming / expiry)', async () => {
    const { root, c } = await onBuddyList((cc) => {
      cc.buddies = [{ username: 'devinjacks', addedAt: 0, group: 'Buddies' }];
    });
    c.emit('connection', { state: 'secure' });
    root.querySelector('[data-buddy-select="devinjacks"]')!.dispatchEvent(new Event('dblclick', { bubbles: true }));
    await waitFor(() => root.querySelector('#dd-compose-form') !== null);
    const before = root.querySelector('#dd-compose-input') as HTMLElement;
    before.textContent = 'half typed reply';
    // A duration expiry in THIS conversation rebuilds the view (openChannel -> go). The draft lives only in
    // the DOM, so wait for a genuinely NEW compose element and assert the draft rode across it.
    c.emit('erased', { messageId: 'y', reason: 'duration', conversationId: 'c1' });
    await waitFor(() => {
      const el = root.querySelector('#dd-compose-input');
      return el !== null && el !== before && (el as HTMLElement).textContent === 'half typed reply';
    });
    expect((root.querySelector('#dd-compose-input') as HTMLElement).textContent).toBe('half typed reply');
  });

  it('the connection headline is E2E-first: SECURING while only the transport is up, SECURE LINK when E2E lands', async () => {
    const { root, c } = await onBuddyList();
    c.emit('connection', { state: 'live' });
    await waitFor(() => root.querySelector('#dd-conn')?.textContent === '◐ SECURING…');
    expect(root.querySelector('#dd-conn')?.className).toContain('dd-conn-live');
    c.emit('connection', { state: 'secure' });
    await waitFor(() => root.querySelector('#dd-conn')?.textContent === '● SECURE LINK');
    expect(root.querySelector('#dd-conn')?.className).toContain('dd-conn-secure');
    // 'live' must never DOWNGRADE an established 'secure': in the real worker the self-group's 'secure'
    // event lands BEFORE connectLive's own optimistic setConn('live'), so without a guard a returning
    // device would be clobbered back to SECURING. A late 'live' is ignored; the headline holds SECURE LINK.
    c.emit('connection', { state: 'live' });
    await new Promise((r) => setTimeout(r, 5));
    expect(root.querySelector('#dd-conn')?.textContent).toBe('● SECURE LINK');
    // Only a real drop takes it back down.
    c.emit('connection', { state: 'offline' });
    await waitFor(() => root.querySelector('#dd-conn')?.textContent !== '● SECURE LINK');
  });

  it('waking the tab (visibilitychange to visible) forces a reconnect, so the phone converges without a manual reload', async () => {
    // A mobile browser freezes a backgrounded tab and silently kills the WebSocket during sleep; on wake
    // the page believes it is still connected but the socket is dead. Requiring a force-reload on a phone
    // is not acceptable, so the tab becoming visible must re-run the reconnect + reconcile cascade (which
    // re-publishes the contact graph into the self-group and re-runs the self-group heal).
    const { root, c } = await onBuddyList();
    void root;
    const dialsAfterLogin = c.connects;

    // Simulate the phone waking: the tab becomes visible again.
    Object.defineProperty(document, 'visibilityState', { value: 'visible', configurable: true });
    document.dispatchEvent(new Event('visibilitychange'));
    await waitFor(() => c.connects > dialsAfterLogin);
    expect(c.connects).toBeGreaterThan(dialsAfterLogin); // a fresh reconnect ran on wake

    // Throttled: a second wake within the window collapses to no extra reconnect.
    const dialsAfterWake = c.connects;
    document.dispatchEvent(new Event('visibilitychange'));
    await new Promise((r) => setTimeout(r, 10));
    expect(c.connects).toBe(dialsAfterWake); // throttle held; no reconnect storm
  });

  it('a drop schedules a quiet countdown retry; the popover explains and Reconnect now redials at once', async () => {
    const { root, c } = await onBuddyList();
    const dialsAtLogin = c.connects;
    c.emit('connection', { state: 'secure' });
    await waitFor(() => root.querySelector('#dd-conn')?.textContent === '● SECURE LINK');
    // The link drops: the headline becomes a visible countdown (no popups), scheduled immediately.
    c.emit('connection', { state: 'offline' });
    await waitFor(() => /RETRY IN \d+s/.test(root.querySelector('#dd-conn')?.textContent ?? ''));
    // The popover explains the state in plain words and offers the manual retry.
    (root.querySelector('#dd-conn') as HTMLElement).click();
    await waitFor(() => root.querySelector('#dd-conn-pop')?.hasAttribute('hidden') === false);
    expect(root.querySelector('.dd-connp-exp')?.textContent).toContain('waits safely on this device');
    expect(root.querySelector('.dd-connp-gw')?.textContent).toContain('gateway x');
    const now = root.querySelector('.dd-connp-now') as HTMLElement;
    expect(now.hidden).toBe(false);
    now.click(); // skip the countdown
    await waitFor(() => c.connects === dialsAtLogin + 1); // redialed immediately
    await waitFor(() => root.querySelector('#dd-conn')?.textContent === '◐ SECURING…'); // transport up again
  });

  it("an unsolicited 'established' stashes an open Appearance draft to the tray instead of destroying it", async () => {
    const { root, c } = await onBuddyList();
    // Open the Appearance preferences from the buddy list's titlebar DEAD DROP menu.
    click(root, '.dd-winmenu [data-action="app-menu"]');
    click(root, '[data-action="appearance"]');
    await waitFor(() => root.innerHTML.includes('dd-appear-2pane'));
    // Make a DRAFT edit: pick the winamp theme card (draft-only; nothing applies until Save).
    click(root, '[data-appear-cat="themes"]');
    await waitFor(() => root.querySelector('[data-appear-theme="winamp"]') !== null);
    click(root, '[data-appear-theme="winamp"]');
    await waitFor(() => root.innerHTML.includes('dd-appear-theme-active" data-appear-theme="winamp"'));
    // A peer's Welcome adopts and pushes 'established' with no user action: the app navigates to the
    // new conversation, but the editor must be STASHED to the menu-bar tray, drafts intact — not dropped.
    c.emit('established', { conversationId: 'c1' });
    await waitFor(() => root.querySelector('#dd-compose-form') !== null);
    const chip = root.querySelector('[data-restore="kind:appearance"]');
    expect(chip).not.toBeNull();
    // Restoring brings the dialog back with the unsaved draft still in place (winamp still picked).
    (chip as HTMLElement).click();
    await waitFor(() => root.innerHTML.includes('dd-appear-2pane'));
    expect(root.innerHTML).toContain('dd-appear-theme-active" data-appear-theme="winamp"');
  });

  it("an unsolicited 'offer' stashes a half-written away message to the tray, drafts intact", async () => {
    const { root, c } = await onBuddyList();
    // Open the away editor via the buddy-list ◆ status control.
    click(root, '[data-action="status-menu"]');
    click(root, '[data-action="status-edit-away"]');
    await waitFor(() => root.querySelector('#dd-away-msg') !== null);
    (root.querySelector('#dd-away-msg') as HTMLElement).textContent = 'gone fishing';
    // A peer's offer navigates to the incoming key-exchange screen; the away editor must be stashed
    // with the DOM-held draft harvested (same care as Minimize), not silently destroyed.
    c.emit('offer', { conversationId: 'c9', peer: 'WREN', peerFingerprint: 'AA' });
    await waitFor(() => root.querySelector('#dd-away-msg') === null);
    const chip = root.querySelector('[data-restore="kind:away"]');
    expect(chip).not.toBeNull();
    (chip as HTMLElement).click();
    await waitFor(() => root.querySelector('#dd-away-msg') !== null);
    expect((root.querySelector('#dd-away-msg') as HTMLElement).textContent).toContain('gone fishing');
  });

  it('clears the compose after a send (the sent text is not carried back as a draft)', async () => {
    const { root, c } = await onBuddyList((cc) => {
      cc.buddies = [{ username: 'devinjacks', addedAt: 0, group: 'Buddies' }];
    });
    c.emit('connection', { state: 'secure' });
    root.querySelector('[data-buddy-select="devinjacks"]')!.dispatchEvent(new Event('dblclick', { bubbles: true }));
    await waitFor(() => root.querySelector('#dd-compose-form') !== null);
    const before = root.querySelector('#dd-compose-input') as HTMLElement;
    before.textContent = 'ship it';
    root.querySelector('#dd-compose-form')!.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
    await waitFor(() => {
      const el = root.querySelector('#dd-compose-input');
      return el !== null && el !== before; // the send re-rendered
    });
    expect((root.querySelector('#dd-compose-input') as HTMLElement).textContent).toBe(''); // empty, not the sent text
  });

  it('a half-typed message survives minimize and comes back on restore (drafts intact)', async () => {
    const { root, c } = await onBuddyList((cc) => {
      cc.buddies = [{ username: 'devinjacks', addedAt: 0, group: 'Buddies' }];
    });
    c.emit('connection', { state: 'secure' });
    root.querySelector('[data-buddy-select="devinjacks"]')!.dispatchEvent(new Event('dblclick', { bubbles: true }));
    await waitFor(() => root.querySelector('#dd-compose-form') !== null);
    (root.querySelector('#dd-compose-input') as HTMLElement).textContent = 'half typed thought';
    click(root, '[data-action="win-minimize"]');
    await waitFor(() => root.querySelector('.dd-blhead') !== null);
    click(root, '[data-restore]');
    await waitFor(() => root.querySelector('#dd-compose-input') !== null);
    expect((root.querySelector('#dd-compose-input') as HTMLElement).textContent).toContain('half typed thought');
  });

  it('AIM behavior: an arriving message POPS ITS WINDOW to the front so you can answer it', async () => {
    // A message used to raise only a toast ("message received"), leaving the conversation closed. That is
    // wrong twice over: AIM put the actual message in front of you, AND an inbound burn countdown only
    // arms when the message is VIEWED (hold-until-seen), so a message that merely toasted sat unseen with
    // its timer never started (observed live: the sender's countdown ran, the receiver's did not).
    const { root, c } = await onBuddyList();
    c.emit('connection', { state: 'secure' });
    expect(root.querySelector('#dd-compose-form')).toBeNull(); // no conversation open
    c.emit('inbound-message', { conversationId: 'c1' });
    // The conversation window is now open in front (which is also what arms the burn countdown).
    await waitFor(() => root.querySelector('#dd-compose-form') !== null);
  });

  it('an arrival for a PARKED conversation raises it instead of opening a SECOND window for it', async () => {
    // The duplicate-window bug. A window's key is conv:<id> for a standalone chat but kind:<kind> for
    // everything else, and the arrival handler asked "is this open?" by comparing the id against the LIVE
    // window plus a conv:<id> lookup in the dock — parked windows were never consulted. So a chat you had
    // navigated away from was judged "not open" and a second window was minted on top of the first.
    // The window must be the TWO-PANE Channels one: a parked standalone chat is keyed conv:<id>, which
    // go() already folds correctly. The two-pane is keyed kind:channels while DISPLAYING c1, so a
    // conv:c1 lookup misses it — that asymmetry is the entire bug.
    const { root, c } = await onBuddyList((cc) => {
      cc.channelsList = [{ id: 'c1', peer: 'PEER', fingerprint: '', status: 'secure' as const, preview: '', unread: 0 }];
    });
    c.emit('connection', { state: 'secure' });
    clickMenu(root, 'Channels');
    await waitFor(() => root.querySelector('[data-channel="c1"]') !== null);
    click(root, '[data-channel="c1"]'); // c1 now lives INSIDE the channels window
    await waitFor(() => root.querySelector('#dd-compose-form') !== null);

    // Navigate away so that two-pane window PARKS, still displaying c1.
    clickMenu(root, 'Buddies');
    // Wait for the LIVE window to actually become the buddy list. Waiting on '.dd-blhead' is not enough:
    // parked windows are fully painted, so that element already existed in the parked buddy window and
    // the wait passed before the navigation landed — leaving Channels live and the arrival taking the
    // in-place path, which is why every earlier version of this test could not fail.
    await waitFor(() => root.querySelector('[data-win-key]')?.getAttribute('data-win-key') === 'kind:buddies');
    expect(root.querySelector('[data-win-key="kind:channels"]')).not.toBeNull(); // parked, displaying c1
    const before = root.querySelectorAll('[data-win-key]').length;

    c.emit('inbound-message', { conversationId: 'c1' });
    await new Promise((r) => setTimeout(r, 30));

    // c1 is displayed by the parked kind:channels window, so a SECOND window keyed conv:c1 must never
    // appear beside it, and the desktop must not grow.
    expect(root.querySelector('[data-win-key="conv:c1"]')).toBeNull();
    expect(root.querySelectorAll('[data-win-key]').length).toBe(before);
  });

  it('an arrival does NOT steal focus or wipe the draft while the user is typing in another chat', async () => {
    // "should not steal the focus if the user is already typing into another chat". A cross-conversation
    // pop is by definition not an in-place refresh, so render() re-focused the compose box and rebuilt
    // root.innerHTML — and the draft lives ONLY in that DOM node, so the half-typed sentence vanished.
    const { root, c } = await onBuddyList((cc) => {
      cc.buddies = [{ username: 'devinjacks', addedAt: 0, group: 'Buddies' }];
    });
    c.emit('connection', { state: 'secure' });
    root.querySelector('[data-buddy-select="devinjacks"]')!.dispatchEvent(new Event('dblclick', { bubbles: true }));
    await waitFor(() => root.querySelector('#dd-compose-form') !== null);

    const compose = root.querySelector('#dd-compose-input') as HTMLElement;
    compose.textContent = 'half a sentence';
    compose.focus();
    compose.dispatchEvent(new Event('input', { bubbles: true }));

    c.emit('inbound-message', { conversationId: 'c-other' }); // a DIFFERENT conversation arrives
    await new Promise((r) => setTimeout(r, 20));

    const after = root.querySelector('#dd-compose-input') as HTMLElement;
    expect(after.textContent).toContain('half a sentence'); // the draft survived
    expect(document.activeElement).toBe(after); // and the caret was not yanked away
  });

  it('AIM behavior: a DOCKED conversation stays docked and its chip shows an unread indicator', async () => {
    // Docking is a deliberate choice, so an arrival must not yank the window back. It must also not be
    // silent: the chip carries a count so the user knows something is waiting.
    const { root, c } = await onBuddyList((cc) => {
      cc.buddies = [{ username: 'devinjacks', addedAt: 0, group: 'Buddies' }];
    });
    c.emit('connection', { state: 'secure' });
    root.querySelector('[data-buddy-select="devinjacks"]')!.dispatchEvent(new Event('dblclick', { bubbles: true }));
    await waitFor(() => root.querySelector('#dd-compose-form') !== null);
    const convId = 'c1'; // the id the fake controller's transmit model carries
    click(root, '[data-action="win-minimize"]');
    await waitFor(() => root.querySelector('.dd-blhead') !== null);
    expect(root.innerHTML).toContain('dd-menu-chip');
    expect(root.innerHTML).not.toContain('dd-menu-chip-unread'); // nothing waiting yet

    c.emit('inbound-message', { conversationId: convId });
    // Still docked (no window stolen back), but the chip now advertises the unread arrival.
    await waitFor(() => root.innerHTML.includes('dd-menu-chip-unread'));
    expect(root.querySelector('#dd-compose-form')).toBeNull(); // stayed docked
    expect(root.querySelector('.dd-chip-badge')?.textContent).toBe('1');

    // A second arrival increments rather than duplicating the chip.
    c.emit('inbound-message', { conversationId: convId });
    await waitFor(() => root.querySelector('.dd-chip-badge')?.textContent === '2');
    expect(root.querySelectorAll('.dd-menu-chip')).toHaveLength(1);

    // Restoring clears it (restore reopens the conversation, marking it seen).
    click(root, '[data-restore]');
    await waitFor(() => root.querySelector('#dd-compose-form') !== null);
    expect(root.innerHTML).not.toContain('dd-menu-chip-unread');
  });

  it('minimize sends the window to a menu-bar chip, the chip restores it, and close just dismisses', async () => {
    const { root, c } = await onBuddyList((cc) => {
      cc.buddies = [{ username: 'devinjacks', addedAt: 0, group: 'Buddies' }];
    });
    c.emit('connection', { state: 'secure' }); // Note to Self rides the gateway
    root.querySelector('[data-buddy-select="devinjacks"]')!.dispatchEvent(new Event('dblclick', { bubbles: true }));
    await waitFor(() => root.querySelector('#dd-compose-form') !== null);
    click(root, '[data-action="win-minimize"]');
    await waitFor(() => root.querySelector('.dd-blhead') !== null); // back on the buddy list
    expect(root.innerHTML).toContain('dd-menu-chip'); // the chat waits on the menu bar
    expect(root.innerHTML).toContain('Note to Self');
    click(root, '[data-restore]'); // restore: the conversation reopens fresh
    await waitFor(() => root.querySelector('#dd-compose-form') !== null);
    expect(root.innerHTML).not.toContain('dd-menu-chip');
    click(root, '[data-action="win-close"]'); // close: dismissed, NO chip left behind
    await waitFor(() => root.querySelector('.dd-blhead') !== null);
    expect(root.innerHTML).not.toContain('dd-menu-chip');
  });

  it('minimizing the buddy list itself leaves the bare desktop with a chip to bring it back', async () => {
    const { root } = await onBuddyList();
    click(root, '[data-action="win-minimize"]');
    await waitFor(() => root.querySelector('.dd-window') === null); // the bare desktop, menu bar only
    expect(root.innerHTML).toContain('dd-menu-chip');
    expect(root.innerHTML).toContain('BUDDY LIST');
    click(root, '[data-restore]');
    await waitFor(() => root.querySelector('.dd-blhead') !== null); // and it comes back
  });
});
