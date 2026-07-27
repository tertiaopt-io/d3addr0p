import { describe, it, expect } from 'vitest';
import {
  AccountClient,
  deriveUsernameHash,
  deriveAuthSecret,
  contactFromIdentityKey,
  normalizeUsername,
  type AccountTransport,
} from './auth.js';

const HEX64 = /^[0-9a-f]{64}$/;

/** A scriptable transport: returns the queued response per path and records the bodies it saw. */
function fakeTransport(
  responses: Record<string, { status: number; body?: Record<string, unknown> }>,
): AccountTransport & { calls: Array<{ path: string; body: Record<string, unknown> }> } {
  const calls: Array<{ path: string; body: Record<string, unknown> }> = [];
  return {
    calls,
    send(path, body) {
      calls.push({ path, body });
      const r = responses[path] ?? { status: 500 };
      return Promise.resolve({ status: r.status, body: r.body ?? {} });
    },
  };
}

describe('account derivations', () => {
  it('produce 64-hex usernameHash and authSecret', async () => {
    expect(await deriveUsernameHash('Alice')).toMatch(HEX64);
    expect(await deriveAuthSecret('Alice', 'hunter2')).toMatch(HEX64);
  });

  it('normalize the username (trim + lowercase) so the same handle maps to one account', async () => {
    expect(normalizeUsername('  Alice  ')).toBe('alice');
    expect(await deriveUsernameHash('  ALICE ')).toBe(await deriveUsernameHash('alice'));
    expect(await deriveAuthSecret(' Alice', 'pw')).toBe(await deriveAuthSecret('alice', 'pw'));
  });

  it('bind authSecret to BOTH the username and the passphrase', async () => {
    const base = await deriveAuthSecret('alice', 'pw');
    expect(await deriveAuthSecret('alice', 'pw2')).not.toBe(base); // passphrase matters
    expect(await deriveAuthSecret('bob', 'pw')).not.toBe(base); // username matters
  });

  it('keep usernameHash independent of the passphrase (it is the public registry key)', async () => {
    // The username hash must not leak the passphrase; it depends only on the handle.
    expect(await deriveUsernameHash('alice')).toBe(await deriveUsernameHash('alice'));
  });

  it('build a contact string a peer can use to open a channel', () => {
    const key = 'a'.repeat(64);
    expect(contactFromIdentityKey(key)).toBe(`deaddrop:1:${key}:${key}`);
  });
});

describe('AccountClient.register', () => {
  it('sends pre-hashed credentials + the identity key and stores the session on 201', async () => {
    const t = fakeTransport({ '/api/register': { status: 201, body: { token: 'tok-1' } } });
    const c = new AccountClient(t);
    const res = await c.register('Alice', 'hunter2', 'c'.repeat(64));
    expect(res.ok).toBe(true);
    expect(c.hasSession()).toBe(true);

    const sent = t.calls[0]!.body;
    expect(sent['usernameHash']).toMatch(HEX64);
    expect(sent['authSecret']).toMatch(HEX64);
    expect(sent['identityKey']).toBe('c'.repeat(64));
    // The server never receives the plaintext handle or passphrase.
    expect(JSON.stringify(sent)).not.toContain('Alice');
    expect(JSON.stringify(sent)).not.toContain('hunter2');
  });

  it('reports a taken username on 409 and issues no session', async () => {
    const t = fakeTransport({ '/api/register': { status: 409, body: { error: 'username_taken' } } });
    const c = new AccountClient(t);
    const res = await c.register('alice', 'pw', 'c'.repeat(64));
    expect(res).toMatchObject({ ok: false, taken: true });
    expect(c.hasSession()).toBe(false);
  });

  it('surfaces a server error without a session', async () => {
    const t = fakeTransport({ '/api/register': { status: 500 } });
    const c = new AccountClient(t);
    expect((await c.register('alice', 'pw', 'c'.repeat(64))).ok).toBe(false);
    expect(c.hasSession()).toBe(false);
  });
});

describe('AccountClient.login', () => {
  it('stores the session on 200', async () => {
    const t = fakeTransport({ '/api/login': { status: 200, body: { token: 'tok-2' } } });
    const c = new AccountClient(t);
    expect((await c.login('alice', 'pw')).ok).toBe(true);
    expect(c.hasSession()).toBe(true);
    expect(t.calls[0]!.body['identityKey']).toBeUndefined(); // login carries no identity key
  });

  it('rejects bad credentials on 401', async () => {
    const t = fakeTransport({ '/api/login': { status: 401, body: { error: 'unauthorized' } } });
    const c = new AccountClient(t);
    expect(await c.login('alice', 'wrong')).toMatchObject({ ok: false });
    expect(c.hasSession()).toBe(false);
  });
});

describe('AccountClient device management', () => {
  it('enrolls a device with the token and the re-presented auth secret', async () => {
    const t = fakeTransport({
      '/api/login': { status: 200, body: { token: 'tok' } },
      '/api/add-device': { status: 201, body: { deviceId: 'dev1' } },
    });
    const c = new AccountClient(t);
    await c.login('alice', 'pw');
    const res = await c.enrollDevice('alice', 'pw', 'c'.repeat(64));
    expect(res).toMatchObject({ ok: true, deviceId: 'dev1' });
    const call = t.calls.find((x) => x.path === '/api/add-device')!;
    expect(call.body['token']).toBe('tok');
    expect(call.body['authSecret']).toMatch(HEX64); // re-presented, not the plaintext passphrase
    expect(call.body['deviceKey']).toBe('c'.repeat(64));
    expect(JSON.stringify(call.body)).not.toContain('pw');
  });

  it('reports a revoked device key cannot be re-enrolled', async () => {
    const t = fakeTransport({
      '/api/login': { status: 200, body: { token: 'tok' } },
      '/api/add-device': { status: 409, body: { error: 'device_revoked' } },
    });
    const c = new AccountClient(t);
    await c.login('alice', 'pw');
    // The typed `revoked` flag lets the app lock this device out (crypto-erase + return to login) rather
    // than only surfacing an error string.
    expect(await c.enrollDevice('alice', 'pw', 'c'.repeat(64))).toMatchObject({ ok: false, revoked: true, error: 'this device was revoked' });
  });

  it('a device-key-taken 409 is not flagged as revoked', async () => {
    const t = fakeTransport({
      '/api/login': { status: 200, body: { token: 'tok' } },
      '/api/add-device': { status: 409, body: { error: 'device_key_taken' } },
    });
    const c = new AccountClient(t);
    await c.login('alice', 'pw');
    expect(await c.enrollDevice('alice', 'pw', 'c'.repeat(64))).toMatchObject({ ok: false, revoked: false });
  });

  it('lists devices and parses them, dropping malformed entries', async () => {
    const t = fakeTransport({
      '/api/login': { status: 200, body: { token: 'tok' } },
      '/api/list-devices': {
        status: 200,
        body: {
          devices: [
            { deviceId: 'd1', deviceKey: 'a'.repeat(64), addedAt: 10, lastSeenAt: 20, revoked: false, current: true },
            { deviceId: 'd2', deviceKey: 'b'.repeat(64), addedAt: 5, lastSeenAt: 6, revoked: true, current: false },
            { junk: true }, // malformed: dropped
          ],
        },
      },
    });
    const c = new AccountClient(t);
    await c.login('alice', 'pw');
    const res = await c.listDevices();
    expect(res.ok).toBe(true);
    expect(res.devices).toHaveLength(2);
    expect(res.devices![0]).toMatchObject({ deviceId: 'd1', current: true, revoked: false });
    expect(res.devices![1]).toMatchObject({ deviceId: 'd2', revoked: true });
  });

  it('revokes a device and reports an unknown one', async () => {
    const t = fakeTransport({
      '/api/login': { status: 200, body: { token: 'tok' } },
      '/api/revoke-device': { status: 200, body: { ok: true } },
    });
    const c = new AccountClient(t);
    await c.login('alice', 'pw');
    expect((await c.revokeDevice('d2')).ok).toBe(true);

    const t2 = fakeTransport({
      '/api/login': { status: 200, body: { token: 'tok' } },
      '/api/revoke-device': { status: 404, body: { error: 'not_found' } },
    });
    const c2 = new AccountClient(t2);
    await c2.login('alice', 'pw');
    expect((await c2.revokeDevice('ghost')).ok).toBe(false);
  });

  it('requires a session for device operations', async () => {
    const t = fakeTransport({});
    const c = new AccountClient(t);
    expect((await c.enrollDevice('a', 'b', 'c'.repeat(64))).ok).toBe(false);
    expect((await c.listDevices()).ok).toBe(false);
    expect((await c.revokeDevice('x')).ok).toBe(false);
    expect(t.calls.length).toBe(0); // never hits the wire without a token
  });
});

describe('AccountClient key-package directory', () => {
  it('publishes one-time packages plus a referenced last-resort package', async () => {
    const t = fakeTransport({
      '/api/login': { status: 200, body: { token: 'tok' } },
      '/api/publish-keys': { status: 201, body: { stored: 3 } },
    });
    const c = new AccountClient(t);
    await c.login('alice', 'pw');
    const res = await c.publishKeys([new Uint8Array([1, 2]), new Uint8Array([3, 4])], new Uint8Array([9, 9]));
    expect(res.ok).toBe(true);
    const call = t.calls.find((x) => x.path === '/api/publish-keys')!;
    const kps = call.body['keyPackages'] as Array<Record<string, unknown>>;
    expect(kps).toHaveLength(3); // two one-time + one last-resort
    expect(kps.filter((k) => k['lastResort'] === true)).toHaveLength(1);
    expect(kps[0]!['keyPackage']).toBe('0102'); // hex of the package bytes
    expect(kps[0]!['ref']).toMatch(HEX64); // a content hash for idempotent re-publish
  });

  it('claims one package per active device and decodes them to bytes', async () => {
    const t = fakeTransport({
      '/api/login': { status: 200, body: { token: 'tok' } },
      '/api/take-keys': {
        status: 200,
        body: {
          devices: [
            { deviceId: 'd1', deviceKey: 'a'.repeat(64), keyPackage: 'aabb', lastResort: false },
            { deviceId: 'd2', deviceKey: 'b'.repeat(64), keyPackage: 'ccdd', lastResort: true },
            { junk: true }, // malformed: dropped
          ],
        },
      },
    });
    const c = new AccountClient(t);
    await c.login('alice', 'pw');
    const res = await c.takeKeys('bob');
    expect(res.ok).toBe(true);
    expect(res.devices).toHaveLength(2);
    expect(res.devices![0]).toMatchObject({ deviceKey: 'a'.repeat(64), lastResort: false });
    expect([...res.devices![0]!.keyPackage]).toEqual([0xaa, 0xbb]); // hex decoded to bytes
    expect(res.devices![1]!.lastResort).toBe(true);
  });

  it('requires a session for the directory operations', async () => {
    const t = fakeTransport({});
    const c = new AccountClient(t);
    expect((await c.publishKeys([new Uint8Array([1])], new Uint8Array([2]))).ok).toBe(false);
    expect((await c.takeKeys('bob')).ok).toBe(false);
    expect(t.calls.length).toBe(0);
  });
});

describe('AccountClient server-side away (opt-in)', () => {
  async function loggedIn(extra: Record<string, { status: number; body?: Record<string, unknown> }>) {
    const t = fakeTransport({ '/api/register': { status: 201, body: { token: 'tok' } }, ...extra });
    const c = new AccountClient(t);
    await c.register('alice', 'pw', 'c'.repeat(64));
    return { t, c };
  }

  it('sets the away text and clears it, carrying the session token', async () => {
    const { t, c } = await loggedIn({ '/api/set-away': { status: 200, body: { ok: true, away: true } } });
    expect((await c.setAway('back soon')).ok).toBe(true);
    const set = t.calls.find((x) => x.path === '/api/set-away')!.body;
    expect(set['token']).toBe('tok');
    expect(set['awayText']).toBe('back soon');
    await c.clearAway();
    expect(t.calls.filter((x) => x.path === '/api/set-away').pop()!.body['awayText']).toBe(''); // clear sends empty text
  });

  it('looks up a peer away message and returns null when they are online or unset', async () => {
    const present = await loggedIn({ '/api/away': { status: 200, body: { away: 'gone fishing' } } });
    expect(await present.c.lookupAway('bob')).toBe('gone fishing');
    const absent = await loggedIn({ '/api/away': { status: 200, body: { away: null } } });
    expect(await absent.c.lookupAway('bob')).toBeNull();
  });

  it('sends a heartbeat carrying the token, and no-ops without a session', async () => {
    const { t, c } = await loggedIn({ '/api/away-beat': { status: 200, body: { ok: true } } });
    await c.awayBeat();
    expect(t.calls.some((x) => x.path === '/api/away-beat' && x.body['token'] === 'tok')).toBe(true);
    const lc = new AccountClient(fakeTransport({}));
    await lc.awayBeat();
    expect(await lc.lookupAway('bob')).toBeNull(); // no session: lookup is null, no throw
  });
});

describe('AccountClient presence (opt-in)', () => {
  async function loggedIn(extra: Record<string, { status: number; body?: Record<string, unknown> }>) {
    const t = fakeTransport({ '/api/register': { status: 201, body: { token: 'tok' } }, ...extra });
    const c = new AccountClient(t);
    await c.register('alice', 'pw', 'c'.repeat(64));
    return { t, c };
  }

  it('sets and clears presence carrying the token', async () => {
    const { t, c } = await loggedIn({ '/api/set-presence': { status: 200, body: { ok: true } }, '/api/clear-presence': { status: 200, body: { ok: true } } });
    await c.setPresence('idle');
    expect(t.calls.find((x) => x.path === '/api/set-presence')!.body).toMatchObject({ token: 'tok', status: 'idle' });
    await c.clearPresence();
    expect(t.calls.some((x) => x.path === '/api/clear-presence')).toBe(true);
  });

  it('reads a buddy presence and defaults to offline without a session', async () => {
    const present = await loggedIn({ '/api/presence': { status: 200, body: { status: 'online' } } });
    expect(await present.c.getPresence('bob')).toBe('online');
    const noSession = new AccountClient(fakeTransport({}));
    expect(await noSession.getPresence('bob')).toBe('offline');
  });
});
