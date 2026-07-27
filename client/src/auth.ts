/**
 * Account client (M6): the main-thread half of the server-backed registration/authentication
 * workflow and the username -> identity-key directory.
 *
 * The server (control-plane) never sees a plaintext username or passphrase. This module pre-hashes
 * both with SHA-256 before they cross the wire (ADR for the server account model):
 *   - usernameHash : a domain-tagged hash of the normalized username (the registry key + directory
 *     lookup key). It identifies the account without revealing the handle to a seized server.
 *   - authSecret   : a domain-tagged hash of the normalized username bound to the passphrase. The
 *     server stores only password_hash(authSecret, argon2id), so it cannot reverse the passphrase.
 * The directory entry is the account's MLS signature public key (identityKey, 64 lowercase hex),
 * which a peer looks up by username to open a channel without pasting a raw key.
 *
 * Transport is injected so this stays testable with a fake; production wires fetch over same-origin
 * /api (Apache proxies it to the control-plane). The session token lives in memory only and is
 * re-minted on each login, so nothing authenticating is written to disk (P5/§5.10).
 */

const enc = new TextEncoder();

/** Domain separation so these hashes are never confusable with any other SHA-256 in the system. */
const DOMAIN_TAG = 'deaddrop-account-v1';
const US = ''; // unit separator: an unambiguous, never-typed field delimiter

const CONTACT_TAG = 'deaddrop';
const CONTACT_VERSION = '1';

/** Normalize a username for hashing: trim + lowercase, matching the at-rest account id (controller). */
export function normalizeUsername(username: string): string {
  return username.trim().toLowerCase();
}

function toHex(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(h: string): Uint8Array {
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

async function sha256HexOf(bytes: Uint8Array): Promise<string> {
  // Copy into a fresh ArrayBuffer-backed view so the type is a plain BufferSource (not SharedArrayBuffer).
  const digest = await crypto.subtle.digest('SHA-256', new Uint8Array(bytes));
  return toHex(new Uint8Array(digest));
}

async function sha256Hex(input: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', enc.encode(input));
  return toHex(new Uint8Array(digest));
}

/** The registry/directory key: a domain-tagged hash of the normalized username (64 lowercase hex). */
export function deriveUsernameHash(username: string): Promise<string> {
  return sha256Hex(`${DOMAIN_TAG}${US}user${US}${normalizeUsername(username)}`);
}

/** The auth verifier seed: a domain-tagged hash of the normalized username bound to the passphrase.
 * The server Argon2id-hashes this; it never sees the passphrase (64 lowercase hex). */
export function deriveAuthSecret(username: string, passphrase: string): Promise<string> {
  return sha256Hex(`${DOMAIN_TAG}${US}auth${US}${normalizeUsername(username)}${US}${passphrase}`);
}

/** Build the copy-pasteable contact string from a directory identity key (mirrors live.formatContact). */
export function contactFromIdentityKey(identityKey: string): string {
  return `${CONTACT_TAG}:${CONTACT_VERSION}:${identityKey}:${identityKey}`;
}

/** One control-plane request: a JSON POST to a path, yielding the status and decoded JSON body. The
 * body is `unknown`-valued so it can carry the key-package list (an array) as well as string fields. */
export interface AccountTransport {
  send(path: string, body: Record<string, unknown>): Promise<{ status: number; body: Record<string, unknown> }>;
}

/** fetch-backed transport over a base URL (same-origin '/api' in production). */
export function httpAccountTransport(baseUrl: string): AccountTransport {
  return {
    async send(path, body) {
      const res = await fetch(`${baseUrl}${path}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
        // No cookies or credentials: the session token is carried in the JSON body, not a cookie,
        // so there is no ambient authority and nothing for CSRF to ride.
        credentials: 'omit',
        cache: 'no-store',
      });
      let parsed: Record<string, unknown> = {};
      try {
        parsed = (await res.json()) as Record<string, unknown>;
      } catch {
        /* a non-JSON body (proxy error page) leaves parsed empty; the status still drives the result */
      }
      return { status: res.status, body: parsed };
    },
  };
}

export interface RegisterResult {
  readonly ok: boolean;
  readonly taken?: boolean; // the username is already registered (server said 409)
  readonly error?: string;
}

export interface AuthResult {
  readonly ok: boolean;
  readonly error?: string;
}

/** One device registered to the account, for the device-management screen. */
export interface DeviceInfo {
  readonly deviceId: string;
  readonly deviceKey: string; // the device's public identity key (64 hex)
  readonly addedAt: number; // unix seconds
  readonly lastSeenAt: number; // unix seconds
  readonly revoked: boolean;
  readonly current: boolean; // the server's view of which device this session is
  readonly authorized: boolean; // has published >=1 key package: a real device, not an unauthorized orphan
}

export interface EnrollResult {
  readonly ok: boolean;
  readonly deviceId?: string;
  readonly revoked?: boolean; // the server burned this device's key: it must lock out and re-provision
  readonly error?: string;
}

export interface DeviceListResult {
  readonly ok: boolean;
  readonly devices?: readonly DeviceInfo[];
  readonly error?: string;
}

/** A peer's device and a claimed one-time key package, for bootstrapping a group (ADR-022 P4). */
export interface PeerDevice {
  readonly deviceKey: string; // the device's signature key = its bootstrap mailbox
  readonly keyPackage: Uint8Array; // a claimed (single-use) key package to add it with
  readonly lastResort: boolean; // true when this is the reusable last-resort package (weaker FS)
}

function parsePeerDevice(d: unknown): PeerDevice | null {
  if (typeof d !== 'object' || d === null) {
    return null;
  }
  const o = d as Record<string, unknown>;
  if (typeof o['deviceKey'] !== 'string' || typeof o['keyPackage'] !== 'string') {
    return null;
  }
  if (!/^[0-9a-f]+$/.test(o['keyPackage']) || o['keyPackage'].length % 2 !== 0) {
    return null;
  }
  return { deviceKey: o['deviceKey'], keyPackage: hexToBytes(o['keyPackage']), lastResort: o['lastResort'] === true };
}

function parseDevice(d: unknown): DeviceInfo | null {
  if (typeof d !== 'object' || d === null) {
    return null;
  }
  const o = d as Record<string, unknown>;
  if (typeof o['deviceId'] !== 'string' || typeof o['deviceKey'] !== 'string') {
    return null;
  }
  return {
    deviceId: o['deviceId'],
    deviceKey: o['deviceKey'],
    addedAt: typeof o['addedAt'] === 'number' ? o['addedAt'] : 0,
    lastSeenAt: typeof o['lastSeenAt'] === 'number' ? o['lastSeenAt'] : 0,
    revoked: o['revoked'] === true,
    current: o['current'] === true,
    authorized: o['authorized'] === true, // absent (pre-F2 server) => false, i.e. fail-safe over-block
  };
}

/**
 * The account client. Holds the session token (memory only) issued by register/login and used to
 * authorize directory lookups.
 */
export class AccountClient {
  private token: string | null = null;

  constructor(private readonly transport: AccountTransport) {}

  /** True once register or login has issued a session token. */
  hasSession(): boolean {
    return this.token !== null;
  }

  /** Forget the session token (on logout/lock). */
  clearSession(): void {
    this.token = null;
  }

  /**
   * Register a new account. The server rejects a duplicate username atomically (taken === true);
   * on success it issues a session token. identityKey is this device's MLS signature public key,
   * which becomes the account's directory entry.
   */
  async register(username: string, passphrase: string, identityKey: string): Promise<RegisterResult> {
    const [usernameHash, authSecret] = await Promise.all([
      deriveUsernameHash(username),
      deriveAuthSecret(username, passphrase),
    ]);
    const { status, body } = await this.transport.send('/api/register', { usernameHash, authSecret, identityKey });
    if (status === 201) {
      this.token = typeof body['token'] === 'string' ? body['token'] : null;
      return { ok: true };
    }
    if (status === 409) {
      return { ok: false, taken: true, error: 'that username is already taken' };
    }
    return { ok: false, error: 'could not reach the account server' };
  }

  /** Authenticate against the server. On success it issues a fresh session token. */
  async login(username: string, passphrase: string): Promise<AuthResult> {
    const [usernameHash, authSecret] = await Promise.all([
      deriveUsernameHash(username),
      deriveAuthSecret(username, passphrase),
    ]);
    const { status, body } = await this.transport.send('/api/login', { usernameHash, authSecret });
    if (status === 200) {
      this.token = typeof body['token'] === 'string' ? body['token'] : null;
      return { ok: true };
    }
    if (status === 401) {
      return { ok: false, error: 'wrong username or passphrase' };
    }
    return { ok: false, error: 'could not reach the account server' };
  }

  /**
   * Enroll this device under the account. Two factors: the live session token AND the re-derived
   * auth secret, so a stolen token alone cannot add a device. Idempotent (a repeat login is a no-op).
   */
  async enrollDevice(username: string, passphrase: string, deviceKey: string): Promise<EnrollResult> {
    return this.enrollDeviceWithSecret(await deriveAuthSecret(username, passphrase), deviceKey);
  }

  /** Enroll with an ALREADY-DERIVED auth secret. The wizard reorder (enroll only after authorization)
   * derives once at login and re-uses the secret at the later provisioning-authorized point, so it never
   * re-derives (Argon2id) and never re-holds the plaintext passphrase. */
  async enrollDeviceWithSecret(authSecret: string, deviceKey: string): Promise<EnrollResult> {
    if (this.token === null) {
      return { ok: false, error: 'log in first' };
    }
    const { status, body } = await this.transport.send('/api/add-device', { token: this.token, authSecret, deviceKey });
    if (status === 201 || status === 200) {
      const deviceId = body['deviceId'];
      return typeof deviceId === 'string' ? { ok: true, deviceId } : { ok: true };
    }
    if (status === 409) {
      const revoked = body['error'] === 'device_revoked';
      return {
        ok: false,
        revoked,
        error: revoked ? 'this device was revoked' : 'this device key is already in use',
      };
    }
    if (status === 401) {
      this.token = null;
      return { ok: false, error: 'your session expired, log in again' };
    }
    return { ok: false, error: 'could not reach the account server' };
  }

  /** List the devices registered to the account (active and revoked), for the management screen. */
  async listDevices(): Promise<DeviceListResult> {
    if (this.token === null) {
      return { ok: false, error: 'log in first' };
    }
    const { status, body } = await this.transport.send('/api/list-devices', { token: this.token });
    if (status === 200 && Array.isArray(body['devices'])) {
      const devices = body['devices'].map(parseDevice).filter((d): d is DeviceInfo => d !== null);
      return { ok: true, devices };
    }
    if (status === 401) {
      this.token = null;
      return { ok: false, error: 'your session expired, log in again' };
    }
    return { ok: false, error: 'could not load your devices' };
  }

  /** Revoke a device: the server burns its key and cuts its sessions. Idempotent. */
  async revokeDevice(deviceId: string): Promise<AuthResult> {
    if (this.token === null) {
      return { ok: false, error: 'log in first' };
    }
    const { status } = await this.transport.send('/api/revoke-device', { token: this.token, deviceId });
    if (status === 200) {
      return { ok: true };
    }
    if (status === 404) {
      return { ok: false, error: 'that device is no longer on your account' };
    }
    if (status === 401) {
      this.token = null;
      return { ok: false, error: 'your session expired, log in again' };
    }
    return { ok: false, error: 'could not revoke that device' };
  }

  /** Self destruct: permanently delete this account from the server (every device key, key package,
   * session, and any away/presence state). Authorized by this session, so it only ever deletes the
   * caller's own account. Clears the local session token on success. */
  async deleteAccount(): Promise<AuthResult> {
    if (this.token === null) {
      return { ok: false, error: 'log in first' };
    }
    const { status } = await this.transport.send('/api/delete-account', { token: this.token });
    if (status === 200) {
      this.token = null;
      return { ok: true };
    }
    if (status === 401) {
      this.token = null;
      return { ok: false, error: 'your session expired, log in again' };
    }
    return { ok: false, error: 'could not delete the account' };
  }

  /** Publish this device's one-time key packages plus a reusable last-resort package, so it can be
   * added to groups without a live handshake (ADR-022 P3/P4). Each is referenced by its own hash so
   * a repeat publish is idempotent. */
  async publishKeys(oneTime: readonly Uint8Array[], lastResort: Uint8Array): Promise<AuthResult> {
    if (this.token === null) {
      return { ok: false, error: 'log in first' };
    }
    const keyPackages = await Promise.all([
      ...oneTime.map(async (kp) => ({ keyPackage: toHex(kp), ref: await sha256HexOf(kp), lastResort: false })),
      sha256HexOf(lastResort).then((ref) => ({ keyPackage: toHex(lastResort), ref, lastResort: true })),
    ]);
    const { status } = await this.transport.send('/api/publish-keys', { token: this.token, keyPackages });
    if (status === 201) {
      return { ok: true };
    }
    if (status === 401) {
      this.token = null;
      return { ok: false, error: 'your session expired, log in again' };
    }
    return { ok: false, error: 'could not publish keys' };
  }

  /** Claim one key package per active device of a username, to bootstrap a group with all of that
   * user's devices (ADR-022 P4). */
  async takeKeys(username: string): Promise<{ ok: boolean; devices?: readonly PeerDevice[]; error?: string }> {
    if (this.token === null) {
      return { ok: false, error: 'log in first' };
    }
    const usernameHash = await deriveUsernameHash(username);
    const { status, body } = await this.transport.send('/api/take-keys', { token: this.token, usernameHash });
    if (status === 200 && Array.isArray(body['devices'])) {
      const devices = body['devices'].map(parsePeerDevice).filter((d): d is PeerDevice => d !== null);
      return { ok: true, devices };
    }
    if (status === 401) {
      this.token = null;
      return { ok: false, error: 'your session expired, log in again' };
    }
    if (status === 404) {
      return { ok: false, error: 'no user by that name' };
    }
    return { ok: false, error: 'could not reach the account server' };
  }

  /**
   * Turn server-side away on with the given text, or off when the text is empty. OPT-IN relaxation of
   * the zero-knowledge model: the server stores the away text in readable form and serves it to senders
   * once every device is offline. Off by default; see honest-limits.
   */
  async setAway(text: string): Promise<AuthResult> {
    if (this.token === null) {
      return { ok: false, error: 'log in first' };
    }
    const { status } = await this.transport.send('/api/set-away', { token: this.token, awayText: text });
    if (status === 200) {
      return { ok: true };
    }
    if (status === 401) {
      this.token = null;
      return { ok: false, error: 'your session expired, log in again' };
    }
    return { ok: false, error: 'could not reach the account server' };
  }

  /** Turn server-side away off (clears the stored away text). */
  clearAway(): Promise<AuthResult> {
    return this.setAway('');
  }

  /** Heartbeat the server so it knows a device is online, which suppresses server-side away replies
   * while you are reachable. Sent periodically only while server-side away is on. Best-effort. */
  async awayBeat(): Promise<void> {
    if (this.token === null) {
      return;
    }
    await this.transport.send('/api/away-beat', { token: this.token });
  }

  /** Look up a username's server-side away message; returns the text only when they have it on AND
   * every device of theirs is offline, else null. Requires an active session. */
  async lookupAway(username: string): Promise<string | null> {
    if (this.token === null) {
      return null;
    }
    const usernameHash = await deriveUsernameHash(username);
    const { status, body } = await this.transport.send('/api/away', { token: this.token, usernameHash });
    return status === 200 && typeof body['away'] === 'string' ? body['away'] : null;
  }

  /** Share an opt-in presence status (online/away/idle) and refresh the heartbeat. The server can read
   * this status; off by default (see honest-limits). Best-effort. */
  async setPresence(status: 'online' | 'away' | 'idle'): Promise<void> {
    if (this.token === null) {
      return;
    }
    await this.transport.send('/api/set-presence', { token: this.token, status });
  }

  /** Turn presence off so buddies read this account as offline. Best-effort. */
  async clearPresence(): Promise<void> {
    if (this.token === null) {
      return;
    }
    await this.transport.send('/api/clear-presence', { token: this.token });
  }

  /** A buddy's presence: 'online' | 'away' | 'idle' | 'offline'. Offline when off, stale, or unknown. */
  async getPresence(username: string): Promise<string> {
    if (this.token === null) {
      return 'offline';
    }
    const usernameHash = await deriveUsernameHash(username);
    const { status, body } = await this.transport.send('/api/presence', { token: this.token, usernameHash });
    return status === 200 && typeof body['status'] === 'string' ? body['status'] : 'offline';
  }
}
