/**
 * Account client (M6): the main-thread half of the server-backed registration/authentication
 * workflow and the username -> identity-key directory.
 *
 * The server (control-plane) never sees a plaintext username or passphrase. This module pre-hashes
 * both with SHA-256 before they cross the wire (ADR for the server account model):
 *   - usernameHash : a domain-tagged hash of the normalized username (the registry key + directory
 *     lookup key). It identifies the account without revealing the handle to a seized server.
 *   - authSecret   : a domain-tagged hash of the normalized username bound to the passphrase. The
 *     server stores only a verifier for it, so it cannot reverse the passphrase. Two generations exist:
 *     v1 is a single SHA-256 that the SERVER then Argon2id-hashes, and v2 (deriveAuthSecretV2) runs
 *     Argon2id HERE and lets the server store a fast hash. v2 costs an attacker exactly the same per
 *     guessed passphrase while costing the server nothing per request. Both are sent until an account
 *     has migrated.
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

/** The v1 auth verifier seed: a domain-tagged SHA-256 of the normalized username bound to the
 * passphrase. ONE fast hash, which is why the server had to Argon2id it: that server-side KDF was the
 * only thing standing between a leaked database and a guessable passphrase. Kept for accounts that have
 * not yet migrated, and sent alongside v2 until they have. */
export function deriveAuthSecret(username: string, passphrase: string): Promise<string> {
  return sha256Hex(`${DOMAIN_TAG}${US}auth${US}${normalizeUsername(username)}${US}${passphrase}`);
}

/** A memory-hard key derivation (Argon2id), injected because it lives in wasm. Signature matches the
 * vault's `deriveMasterKey(credential, salt)`. */
export type MemoryHardKdf = (credential: string, salt: Uint8Array) => Promise<Uint8Array>;

/** The SALT for the v2 auth secret: deterministic (so any device can re-derive it from the username
 * alone, with no server round trip) and domain-separated from every other use of the passphrase.
 *
 * The vault's key-encryption-key uses a RANDOM per-account salt, so this deterministic one cannot
 * collide with it. That is belt; the brace is below. */
async function authSaltV2(username: string): Promise<Uint8Array> {
  return hexToBytes(await sha256Hex(`${DOMAIN_TAG}${US}authsalt-v2${US}${normalizeUsername(username)}`));
}

/**
 * The v2 auth verifier seed: Argon2id over the passphrase, then hashed again under its own tag.
 *
 * This inverts where the expensive work happens. The client pays the memory-hard cost once, and the
 * server stores a FAST hash of the result, so verifying a login costs microseconds instead of 64 MiB of
 * Argon2. Cracking resistance is unchanged: a leaked database still forces one Argon2id per guessed
 * passphrase, because the attacker must run the same derivation the client does. What changes is that
 * the attacker pays it on their own hardware, and an unauthenticated request can no longer make the
 * server spend real CPU.
 *
 * The final SHA-256 is what makes this safe rather than clever. The Argon2id output is key material of
 * the same shape the vault uses, and this value is SENT TO THE SERVER. Hashing it under a distinct tag
 * before it leaves the device means that even if the salts somehow collided, what crosses the wire is a
 * one-way function of the key and never the key itself.
 */
export async function deriveAuthSecretV2(
  username: string,
  passphrase: string,
  kdf: MemoryHardKdf,
): Promise<string> {
  const key = await kdf(passphrase, await authSaltV2(username));
  const tagged = enc.encode(`${DOMAIN_TAG}${US}authv2${US}`);
  const buf = new Uint8Array(tagged.length + key.length);
  buf.set(tagged, 0);
  buf.set(key, tagged.length);
  const out = await sha256HexOf(buf);
  buf.fill(0);
  key.fill(0); // the Argon2id output is key material: do not leave it lying in a buffer
  return out;
}

/** Count the leading zero BITS of a hex digest (the proof-of-work difficulty measure). */
function leadingZeroBits(hex: string): number {
  let bits = 0;
  for (const ch of hex) {
    const v = parseInt(ch, 16);
    if (v === 0) {
      bits += 4;
      continue;
    }
    // 8 -> 0 leading zeros in this nibble, 4 -> 1, 2 -> 2, 1 -> 3.
    bits += v >= 8 ? 0 : v >= 4 ? 1 : v >= 2 ? 2 : 3;
    break;
  }
  return bits;
}

/**
 * Give the event loop one turn WITHOUT a timer.
 *
 * The solver needs this: awaiting each digest looks like it yields, but the resolutions arrive as
 * microtasks that the loop drains without ever running another task, so 65k of them block the page
 * for the whole solve (measured: 210ms straight, nothing else ran). A timer was the obvious yield and
 * the wrong one. Browsers CLAMP setTimeout to one second in a hidden tab, and this fires ~64 times per
 * solve, so a user who switched tabs during registration waited about a minute instead of a second.
 * A MessageChannel delivery is an ordinary task and is not clamped, so it yields for real either way.
 */
function yieldToEventLoop(): Promise<void> {
  if (typeof MessageChannel === 'undefined') {
    return new Promise((resolve) => setTimeout(resolve, 0)); // non-browser host (tests, older runtimes)
  }
  const channel = new MessageChannel();
  return new Promise((resolve) => {
    channel.port1.onmessage = (): void => {
      channel.port1.close();
      channel.port2.close();
      resolve();
    };
    channel.port2.postMessage(0);
  });
}

/** Find a nonce whose digest over the server's challenge has `bits` leading zero bits. Verification on
 * the server is ONE hash; producing it costs about 2^bits. That asymmetry is the entire point. Yields
 * to the event loop periodically so the UI does not freeze while it grinds. */
export async function solveProofOfWork(challenge: string, bits: number): Promise<string> {
  if (bits <= 0) {
    return '0';
  }
  // Bounded, so a server that asks for an unreasonable difficulty cannot spin a tab forever. Hitting the
  // cap returns a wrong answer, which the server refuses cleanly, rather than hanging the registration.
  const MAX_TRIES = 1 << 22;
  for (let n = 0; n < MAX_TRIES; n++) {
    const digest = await sha256Hex(`${challenge}${US}${n}`);
    if (leadingZeroBits(digest) >= bits) {
      return String(n);
    }
    if ((n & 0x3ff) === 0x3ff) {
      await yieldToEventLoop(); // keep the page responsive (see above: NOT a timer)
    }
  }
  return '0';
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
  /** The account's authorization epoch: an explicit monotonic counter the server keeps, bumped once per
   * revocation. Absent from a server that predates it, in which case the caller falls back to counting
   * revoked rows (what this used to be derived from). A new device's certificate must be minted at or
   * above it, or every member refuses the new leaf. */
  readonly accountEpoch?: number;
  /** ADR-022 P7: the account's signed revocation records, as hex. This is the DENYLIST, and it is what
   * actually excludes a revoked device: the epoch above is a lower bound, and a revoked device that
   * still holds the account seed re-certifies itself above any bound. Each record is verified inside
   * the crypto layer against our own account key, so these arrive untrusted. Empty from a server that
   * predates P7. */
  readonly revocations?: readonly string[];
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

/** The ADR-022 P7 revocation records from a response body, shape-checked only. Each record's SIGNATURE
 * is verified inside the crypto layer against our own account key, which is the check that matters; this
 * just refuses anything that is not exactly one record's worth of lowercase hex, so junk from a hostile
 * server never reaches the wasm boundary. Anything unexpected yields an empty list, never a throw. */
function parseRecords(v: unknown): readonly string[] {
  if (!Array.isArray(v)) {
    return [];
  }
  return v.filter((r): r is string => typeof r === 'string' && /^[0-9a-f]{280}$/.test(r));
}

/**
 * The account client. Holds the session token (memory only) issued by register/login and used to
 * authorize directory lookups.
 */
export class AccountClient {
  private token: string | null = null;
  /** The memory-hard KDF, wired after construction because it lives in wasm (see useStrongKdf). */
  private kdf: MemoryHardKdf | null = null;

  constructor(private readonly transport: AccountTransport) {}

  /** Supply the Argon2id implementation used for the v2 auth secret. Until this is called the client
   * sends v1 only, which still works: the server keeps the old verifier for accounts it has not
   * migrated. So a host without wasm degrades to the previous behaviour rather than failing. */
  useStrongKdf(kdf: MemoryHardKdf): void {
    this.kdf = kdf;
  }

  /** The v2 secret, or null when no memory-hard KDF is available or it fails. Never throws: a broken
   * KDF must not make the account unreachable, it must fall back to v1. */
  private async deriveV2(username: string, passphrase: string): Promise<string | null> {
    if (this.kdf === null) {
      return null;
    }
    try {
      return await deriveAuthSecretV2(username, passphrase, this.kdf);
    } catch {
      return null;
    }
  }

  /**
   * Fetch and solve the registration proof of work. Returns null when the server does not ask for one
   * (older deployments), so registration still works against either.
   *
   * This does not defend the server's CPU: after the v2 migration neither endpoint costs it real work.
   * What it prices is ACCOUNT MINTING. A free account carries a directory-probe budget, so an attacker
   * who wants a bigger budget just makes more accounts; this makes each one cost measurable work.
   */
  private async solveRegistrationWork(): Promise<Record<string, unknown> | null> {
    try {
      const { status, body } = await this.transport.send('/api/challenge', {});
      if (status === 404) {
        return null; // an older deployment that does not ask for a proof: register without one
      }
      if (status !== 200 || typeof body['challenge'] !== 'string' || typeof body['mac'] !== 'string') {
        // The server offers the endpoint but did not answer usefully. Returning null here would send a
        // proofless registration that is certain to be refused as "invalid request", which reads to the
        // user as a problem with what they typed. Fail loudly and specifically instead.
        throw new Error('challenge-unavailable');
      }
      const challenge = body['challenge'];
      const bits = typeof body['bits'] === 'number' ? body['bits'] : 0;
      const nonce = await solveProofOfWork(challenge, bits);
      return { challenge, mac: body['mac'], expiresAt: body['expiresAt'], nonce };
    } catch (e) {
      if (e instanceof Error && e.message === 'challenge-unavailable') {
        throw e;
      }
      return null; // a transport failure: fall back to a proofless attempt rather than blocking
    }
  }

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
    let usernameHash: string;
    let authSecret: string;
    let authSecretV2: string | null;
    let pow: Record<string, unknown> | null;
    try {
      [usernameHash, authSecret, authSecretV2, pow] = await Promise.all([
        deriveUsernameHash(username),
        deriveAuthSecret(username, passphrase),
        this.deriveV2(username, passphrase),
        this.solveRegistrationWork(),
      ]);
    } catch (e) {
      // A server that offers the challenge endpoint but cannot answer it is a SERVER problem. Saying so
      // matters: the alternative is a proofless registration refused as "invalid request", which reads
      // to the user as though they typed something wrong and sends them round the form again.
      return e instanceof Error && e.message === 'challenge-unavailable'
        ? { ok: false, error: 'the account server is not ready to accept new accounts, try again' }
        : { ok: false, error: 'could not reach the account server' };
    }
    const { status, body } = await this.transport.send('/api/register', {
      usernameHash,
      authSecret,
      identityKey,
      ...(authSecretV2 !== null ? { authSecretV2 } : {}),
      ...(pow !== null ? { pow } : {}),
    });
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
    const [usernameHash, authSecret, authSecretV2] = await Promise.all([
      deriveUsernameHash(username),
      deriveAuthSecret(username, passphrase),
      this.deriveV2(username, passphrase),
    ]);
    // Both are sent during the migration: the server verifies whichever verifier it holds for this
    // account, and upgrades a v1 row to v2 on a successful v1 login so the next one is cheap.
    const { status, body } = await this.transport.send('/api/login', {
      usernameHash,
      authSecret,
      ...(authSecretV2 !== null ? { authSecretV2 } : {}),
    });
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
   * re-derives and never re-holds the plaintext passphrase. (An earlier version of this comment said the
   * re-derivation was Argon2id. It was not: deriveAuthSecret is a single SHA-256, which is exactly why
   * the server had to do the memory-hard work. deriveAuthSecretV2 is what moved that cost here.) */
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
      const epoch = body['accountEpoch'];
      const revocations = parseRecords(body['revocations']);
      // Only a finite non-negative number counts; anything else leaves it undefined so the caller uses
      // its fallback rather than minting a certificate at NaN or at a negative epoch.
      return typeof epoch === 'number' && Number.isFinite(epoch) && epoch >= 0
        ? { ok: true, devices, accountEpoch: Math.floor(epoch), revocations }
        : { ok: true, devices, revocations };
    }
    if (status === 401) {
      this.token = null;
      return { ok: false, error: 'your session expired, log in again' };
    }
    return { ok: false, error: 'could not load your devices' };
  }

  /** Revoke a device: the server burns its key and cuts its sessions. Idempotent.
   *
   * `record` is the ADR-022 P7 signed revocation record (hex), which is the half that actually excludes
   * the device: the server's own burn stops it logging in, but a device that still holds the account
   * seed re-certifies itself and rejoins groups regardless, and only a record naming its key stops that.
   * Optional because a cert-only device can still ask the server to revoke; it just cannot author one. */
  async revokeDevice(deviceId: string, record?: string): Promise<AuthResult> {
    if (this.token === null) {
      return { ok: false, error: 'log in first' };
    }
    const body: Record<string, unknown> = { token: this.token, deviceId };
    if (record !== undefined) {
      body['record'] = record;
    }
    const { status } = await this.transport.send('/api/revoke-device', body);
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

  /** The account's ADR-022 P7 revocation records. Separate from listDevices so any device can refresh
   * the denylist on login and reconnect without pulling the device table. A failure yields an empty
   * list: the caller's denylist is append-only, so a missed fetch delays learning about a revocation
   * (liveness) and can never un-revoke anything already known. */
  async revocations(): Promise<readonly string[]> {
    if (this.token === null) {
      return [];
    }
    const { status, body } = await this.transport.send('/api/revocations', { token: this.token });
    return status === 200 ? parseRecords(body['revocations']) : [];
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
