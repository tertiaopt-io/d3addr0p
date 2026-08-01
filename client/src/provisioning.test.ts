import { describe, it, expect } from 'vitest';
import {
  encodeChallenge,
  decodeChallenge,
  encodeRequest,
  decodeRequest,
  encodeGrant,
  decodeGrant,
  deriveProvMailbox,
  deriveQrReplyMailbox,
  encodeQrPairing,
  decodeQrPairing,
  Provisioning,
  type ProvFrame,
  type ProvisioningDeps,
} from './provisioning.js';
import { renderSas } from './sas.js';

const fill = (n: number, byte: number) => new Uint8Array(n).fill(byte);
const hex = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
function hexToBytes(h: string): Uint8Array {
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

describe('provisioning codecs', () => {
  it('round-trips a Challenge and pads to a fixed size', () => {
    const c = { sessionNonce: fill(32, 1), certEpoch: 7, accountPubKey: fill(32, 2) };
    const enc = encodeChallenge(c);
    expect(enc.length).toBe(256); // fixed-size on the wire
    const back = decodeChallenge(enc)!;
    expect(hex(back.sessionNonce)).toBe(hex(c.sessionNonce));
    expect(back.certEpoch).toBe(7);
    expect(hex(back.accountPubKey)).toBe(hex(c.accountPubKey));
  });

  it('round-trips a Request', () => {
    const r = { sessionNonce: fill(32, 3), deviceSigKey: fill(32, 4), replyMailbox: fill(32, 5), requestId: fill(16, 6) };
    const back = decodeRequest(encodeRequest(r))!;
    expect(hex(back.deviceSigKey)).toBe(hex(r.deviceSigKey));
    expect(hex(back.replyMailbox)).toBe(hex(r.replyMailbox));
    expect(hex(back.requestId)).toBe(hex(r.requestId));
  });

  it('round-trips a Grant', () => {
    const g = { accountPubKey: fill(32, 7), certEpoch: 0, cert: fill(64, 8), sessionNonce: fill(32, 9) };
    const back = decodeGrant(encodeGrant(g))!;
    expect(hex(back.cert)).toBe(hex(g.cert));
    expect(back.certEpoch).toBe(0);
    expect(hex(back.sessionNonce)).toBe(hex(g.sessionNonce));
  });

  it('decoders reject a wrong message type or version', () => {
    const req = encodeRequest({ sessionNonce: fill(32, 1), deviceSigKey: fill(32, 2), replyMailbox: fill(32, 3), requestId: fill(16, 4) });
    expect(decodeChallenge(req)).toBeNull(); // a Request is not a Challenge
    expect(decodeGrant(req)).toBeNull();
    const tampered = req.slice();
    tampered[1] = 99; // bad version
    expect(decodeRequest(tampered)).toBeNull();
  });

  it('derives a deterministic rendezvous mailbox from the account id', async () => {
    const m1 = await deriveProvMailbox('aa'.repeat(32));
    expect(m1).toBe(await deriveProvMailbox('aa'.repeat(32)));
    expect(m1).toMatch(/^[0-9a-f]{64}$/);
    expect(await deriveProvMailbox('bb'.repeat(32))).not.toBe(m1);
  });
});

// A deterministic, symmetric stand-in for the wasm SAS digest (the real one is proven in Rust). It
// folds the WHOLE transcript into 32 bytes, so any field difference changes the digest.
function fakeSas(nonceHex: string, aHex: string, bHex: string, epoch: number): string {
  const [lo, hi] = aHex <= bHex ? [aHex, bHex] : [bHex, aHex];
  const seed = `${nonceHex}|${lo}|${hi}|${epoch}`;
  const out = new Uint8Array(32);
  for (let i = 0; i < seed.length; i++) {
    out[i % 32] = (out[i % 32]! + seed.charCodeAt(i) * (i + 1)) & 0xff;
  }
  return [...out].map((x) => x.toString(16).padStart(2, '0')).join('');
}

describe('Provisioning orchestration (two-leg handshake)', () => {
  const ACCOUNT = 'aa'.repeat(32);
  const D2KEY = 'dd'.repeat(32);

  function harness() {
    const bus = new Map<string, Array<(env: ProvFrame) => void>>();
    let ctr = 1;
    const rnd = (n: number): Uint8Array => new Uint8Array(n).fill(ctr++ & 0xff);
    const sub = (key: string, h: (env: ProvFrame) => void): void => {
      const a = bus.get(key) ?? [];
      a.push(h);
      bus.set(key, a);
    };
    const pub = (key: string, payload: Uint8Array): void => {
      for (const h of [...(bus.get(key) ?? [])]) {
        h({ messageId: rnd(1), routingKey: key, payload });
      }
    };
    const d1ev: Array<{ k: string; p: Record<string, unknown> }> = [];
    const d2ev: Array<{ k: string; p: Record<string, unknown> }> = [];
    let adopted: { ap: string; ep: number; c: string } | null = null;
    let injectedRequestKey: string | null = null;

    // eslint-disable-next-line prefer-const
    let d1: Provisioning;
    // eslint-disable-next-line prefer-const
    let d2: Provisioning;
    const base = (random: (n: number) => Uint8Array): Pick<ProvisioningDeps, 'publish' | 'ack' | 'sasDigestHex' | 'renderSas' | 'random' | 'schedule' | 'cancel' | 'mintEpoch'> => ({
      publish: pub,
      ack: () => {},
      sasDigestHex: fakeSas,
      renderSas: (d) => renderSas(hexToBytes(d)),
      random,
      schedule: () => 0,
      cancel: () => {},
      mintEpoch: () => 0,
    });
    const d1deps: ProvisioningDeps = {
      ...base(rnd),
      subscribe: (k) => sub(k, (e) => d1.handle(e)),
      accountKeyHex: () => ACCOUNT,
      deviceKeyHex: () => 'd1'.repeat(32),
      authorizeDevice: (dk, ep, nh, cs) => {
        // Mirror the wasm signer guard: refuse unless the confirmed SAS matches the key being signed.
        if (cs !== fakeSas(nh, ACCOUNT, dk, ep)) {
          throw new Error('signer guard rejected');
        }
        injectedRequestKey = dk;
        return ACCOUNT + '0000000000000000' + 'cc'.repeat(64);
      },
      adoptCertificate: () => {},
      pushEvent: (k, p) => d1ev.push({ k, p: p as Record<string, unknown> }),
    };
    const d2deps: ProvisioningDeps = {
      ...base(rnd),
      subscribe: (k) => sub(k, (e) => d2.handle(e)),
      accountKeyHex: () => '',
      deviceKeyHex: () => D2KEY,
      authorizeDevice: () => {
        throw new Error('a pending device cannot authorize');
      },
      adoptCertificate: (ap, ep, c) => {
        adopted = { ap, ep, c };
      },
      pushEvent: (k, p) => d2ev.push({ k, p: p as Record<string, unknown> }),
    };
    d1 = new Provisioning(d1deps);
    d2 = new Provisioning(d2deps);
    return {
      d1,
      d2,
      d1ev,
      d2ev,
      pub,
      get adopted() {
        return adopted;
      },
      get signedKey() {
        return injectedRequestKey;
      },
    };
  }

  it('completes the handshake: the codes match and the new device adopts the certificate', () => {
    const h = harness();
    h.d2.startJoin('prov-mbox'); // the new device waits first
    h.d1.openWindow('prov-mbox'); // the seed-holder challenges

    const shown = h.d2ev.find((e) => e.k === 'show-code')?.p['words'];
    const toConfirm = h.d1ev.find((e) => e.k === 'confirm-device')?.p['words'];
    expect(shown).toBeTruthy();
    expect(toConfirm).toBe(shown); // the six words match across both devices (no substitution)

    h.d1.confirm();
    expect(h.adopted).toMatchObject({ ap: ACCOUNT });
    expect(h.signedKey).toBe(D2KEY); // the key signed is the device that was added
    expect(h.d2ev.some((e) => e.k === 'provisioning-authorized')).toBe(true);
  });

  it('a substituted device key yields a different code, so the out-of-band compare catches it', () => {
    const h = harness();
    h.d2.startJoin('prov-mbox');
    h.d1.openWindow('prov-mbox');
    const honest = h.d1ev.find((e) => e.k === 'confirm-device')?.p['words'];

    // A relay injects a forged Request carrying an ATTACKER device key under the live nonce.
    const challenge = h.d2ev.length; // (the real request already arrived; inject another)
    h.pub(
      'prov-mbox',
      encodeRequest({
        sessionNonce: fill(32, 1), // the live nonce (rnd's first value)
        deviceSigKey: fill(32, 0xee), // attacker's key, not D2's
        replyMailbox: fill(32, 7),
        requestId: fill(16, 9),
      }),
    );
    const forged = h.d1ev.filter((e) => e.k === 'confirm-device').slice(-1)[0]?.p['words'];
    expect(forged).toBeTruthy();
    expect(forged).not.toBe(honest); // the attacker's key produces different words; the user sees a mismatch
    expect(challenge).toBeGreaterThan(0);
  });

  it('the seed-holder ignores a request that does not carry the live session nonce', () => {
    const h = harness();
    h.d1.openWindow('prov-mbox');
    const before = h.d1ev.filter((e) => e.k === 'confirm-device').length;
    h.pub(
      'prov-mbox',
      encodeRequest({ sessionNonce: fill(32, 0x99), deviceSigKey: fill(32, 0xdd), replyMailbox: fill(32, 7), requestId: fill(16, 3) }),
    );
    expect(h.d1ev.filter((e) => e.k === 'confirm-device').length).toBe(before); // dropped, no prompt
  });
});

describe('QR pairing (add-a-device-by-scan)', () => {
  const ACCOUNT = 'aa'.repeat(32);
  const D1KEY = 'd1'.repeat(32);
  const D2KEY = 'd2'.repeat(32);

  it('round-trips a pairing payload and rejects foreign codes', () => {
    const payload = encodeQrPairing(fill(32, 0x22), fill(32, 0x33));
    expect(payload.startsWith('ddpair:')).toBe(true);
    const back = decodeQrPairing(payload)!;
    expect(hex(back.deviceSigKey)).toBe(hex(fill(32, 0x22)));
    expect(hex(back.ephPub)).toBe(hex(fill(32, 0x33)));
    expect(decodeQrPairing('https://example.com/#dd=bob')).toBeNull(); // a Profile link, not a pairing code
    expect(decodeQrPairing('ddpair:@@not-base64@@')).toBeNull(); // malformed body is refused, not thrown
  });

  // A deterministic stand-in for the wasm ECIES box (proven in Rust). The ephemeral public key is the
  // byte-complement of its secret, and the "box" records the recipient public key ahead of the plaintext,
  // so open() succeeds only for the holder of the matching secret. This proves the ORCHESTRATION (mailbox
  // derivation, certify, seal, publish, receive, open, adopt), not the crypto, which Rust already covers.
  function qrHarness(accountEpoch = 0) {
    const bus = new Map<string, Array<(env: ProvFrame) => void>>();
    const sub = (key: string, h: (env: ProvFrame) => void): void => {
      const a = bus.get(key) ?? [];
      a.push(h);
      bus.set(key, a);
    };
    const pub = (key: string, payload: Uint8Array): void => {
      for (const h of [...(bus.get(key) ?? [])]) {
        h({ messageId: fill(1, 1), routingKey: key, payload });
      }
    };
    const ephKeypair = (): Uint8Array => {
      const kp = new Uint8Array(64);
      kp.set(fill(32, 0x11), 0); // secret
      kp.set(fill(32, 0xee), 32); // public = secret ^ 0xff
      return kp;
    };
    const seal = (recipPub: Uint8Array, plaintext: Uint8Array): Uint8Array => {
      const out = new Uint8Array(32 + plaintext.length);
      out.set(recipPub.subarray(0, 32), 0);
      out.set(plaintext, 32);
      return out;
    };
    const open = (recipSecret: Uint8Array, box: Uint8Array): Uint8Array => {
      for (let i = 0; i < 32; i++) {
        if (box[i] !== (recipSecret[i]! ^ 0xff)) {
          throw new Error('sealed to a different key');
        }
      }
      return box.slice(32);
    };
    let scannedKey: string | null = null;
    const authorizeScanned = (deviceSigKey: Uint8Array, certEpoch: number): Uint8Array => {
      scannedKey = hex(deviceSigKey);
      const g = new Uint8Array(104);
      g.set(fill(32, 0xa1), 0); // account pub
      new DataView(g.buffer).setUint32(36, certEpoch, false); // epoch, low 32 bits, big-endian
      g.set(fill(64, 0xcc), 40); // cert
      return g;
    };
    const d1ev: Array<{ k: string; p: Record<string, unknown> }> = [];
    const d2ev: Array<{ k: string; p: Record<string, unknown> }> = [];
    let adopted: { ap: string; ep: number; c: string } | null = null;
    let acked = false;
    // eslint-disable-next-line prefer-const
    let d1: Provisioning;
    // eslint-disable-next-line prefer-const
    let d2: Provisioning;
    const base = (): Pick<ProvisioningDeps, 'publish' | 'sasDigestHex' | 'renderSas' | 'random' | 'schedule' | 'cancel' | 'mintEpoch'> => ({
      publish: pub,
      sasDigestHex: fakeSas,
      renderSas: (d) => renderSas(hexToBytes(d)),
      random: (n) => fill(n, 5),
      schedule: () => 0,
      cancel: () => {},
      mintEpoch: () => accountEpoch,
    });
    const d1deps: ProvisioningDeps = {
      ...base(),
      subscribe: (k) => sub(k, (e) => d1.handle(e)),
      ack: () => {},
      accountKeyHex: () => ACCOUNT, // an authorized device can certify a scan
      deviceKeyHex: () => D1KEY,
      authorizeDevice: () => {
        throw new Error('the six-word path is not exercised here');
      },
      adoptCertificate: () => {},
      pushEvent: (k, p) => d1ev.push({ k, p: p as Record<string, unknown> }),
      provisionEphemeralKeypair: ephKeypair,
      provisionSeal: seal,
      provisionOpen: open,
      authorizeScannedDevice: authorizeScanned,
    };
    const d2deps: ProvisioningDeps = {
      ...base(),
      subscribe: (k) => sub(k, (e) => d2.handle(e)),
      ack: () => {
        acked = true;
      },
      accountKeyHex: () => '', // a fresh device holds no account key
      deviceKeyHex: () => D2KEY,
      authorizeDevice: () => {
        throw new Error('a pending device cannot authorize');
      },
      adoptCertificate: (ap, ep, c) => {
        adopted = { ap, ep, c };
      },
      pushEvent: (k, p) => d2ev.push({ k, p: p as Record<string, unknown> }),
      provisionEphemeralKeypair: ephKeypair,
      provisionSeal: seal,
      provisionOpen: open,
      authorizeScannedDevice: authorizeScanned,
    };
    d1 = new Provisioning(d1deps);
    d2 = new Provisioning(d2deps);
    return {
      d1,
      d2,
      d1ev,
      d2ev,
      pub,
      get scannedKey() {
        return scannedKey;
      },
      get adopted() {
        return adopted;
      },
      get acked() {
        return acked;
      },
    };
  }

  it('D1 scans D2 and D2 adopts the sealed certificate (no six-word code)', async () => {
    const h = qrHarness();
    const payload = await h.d2.startQrShow();
    expect(payload.startsWith('ddpair:')).toBe(true);
    expect(h.d2ev.some((e) => e.k === 'provisioning-waiting')).toBe(true);

    await h.d1.grantScanned(payload);

    expect(h.scannedKey).toBe(D2KEY); // D1 certified exactly the scanned key, nothing else
    expect(h.d1ev.some((e) => e.k === 'device-added')).toBe(true);
    expect(h.adopted).toEqual({ ap: 'a1'.repeat(32), ep: 0, c: 'cc'.repeat(64) });
    expect(h.acked).toBe(true);
    expect(h.d2ev.some((e) => e.k === 'provisioning-authorized')).toBe(true);
  });

  it('certifies a scanned device at the ACCOUNT epoch, not 0, so the new leaf clears the floor', async () => {
    // The bug this pins: the minted epoch was the literal 0. The account's authorization floor is the
    // number of devices it has ever revoked, and the crypto gate refuses any leaf below that floor. So
    // on any account that had revoked even once, every scanned device was certified dead on arrival:
    // the pairing reported success and the server row was created, but the add failed forever and the
    // app told the user to revoke and pair again, which raised the floor and made it strictly worse.
    const h = qrHarness(14); // an account with 14 revoked devices, exactly the reported case
    const payload = await h.d2.startQrShow();
    await h.d1.grantScanned(payload);

    expect(h.scannedKey).toBe(D2KEY);
    expect(h.adopted).toEqual({ ap: 'a1'.repeat(32), ep: 14, c: 'cc'.repeat(64) });
    expect(h.d2ev.some((e) => e.k === 'provisioning-authorized')).toBe(true);
  });

  it('a device that holds no account key cannot certify a scan', async () => {
    const h = qrHarness();
    const payload = await h.d2.startQrShow();
    await h.d2.grantScanned(payload); // D2 has an empty account key: it may never certify
    expect(h.d2ev.some((e) => e.k === 'provisioning-error')).toBe(true);
    expect(h.adopted).toBeNull();
  });

  it('a grant sealed to a different ephemeral key is ignored (fail-closed)', async () => {
    const h = qrHarness();
    await h.d2.startQrShow(); // D2's ephemeral public key is 0xee..; its reply mailbox derives from it
    const mailbox = await deriveQrReplyMailbox(fill(32, 0xee));
    // Forge a sealed grant addressed to an ATTACKER key (0x77..), framed exactly like the real one, and
    // drop it on D2's real reply mailbox. D2 must fail to open it and adopt nothing.
    const grant = new Uint8Array(104);
    grant.set(fill(32, 0xa1), 0);
    grant.set(fill(64, 0xcc), 40);
    const box = new Uint8Array(32 + 104);
    box.set(fill(32, 0x77), 0); // sealed to the attacker key, not D2's ephemeral key
    box.set(grant, 32);
    const frame = new Uint8Array(256);
    frame[0] = (box.length >> 8) & 0xff;
    frame[1] = box.length & 0xff;
    frame.set(box, 2);
    h.pub(mailbox, frame);
    expect(h.adopted).toBeNull();
    expect(h.d2ev.some((e) => e.k === 'provisioning-authorized')).toBe(false);
  });
});
