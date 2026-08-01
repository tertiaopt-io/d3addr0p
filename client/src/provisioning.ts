/**
 * Device-provisioning wire formats + rendezvous derivation (ADR-022 P4, model b).
 *
 * The hardened two-leg handshake (per the adversarial review): a seed-holder D1 opens a short
 * add-a-device window, publishes a Challenge (a fresh session nonce + the account public key + the
 * cert epoch) to the account rendezvous mailbox; the new device D2 answers with a Request (its device
 * key + a random reply mailbox); both render the 66-bit SAS as six words from the transcript; the user
 * compares them out of band and confirms on D1; D1 publishes a Grant (the AAK-signed certificate) to
 * D2's reply mailbox. This module is the wire layer (codecs + the rendezvous derivation). The crypto
 * (SAS digest, the signer guard, adopt) is in crypto/src/*.rs; the orchestration that drives the
 * window and the user prompts is wired on top.
 *
 * All three messages are padded to a fixed length so the gateway learns nothing from size, and the
 * reply never uses the public device-key routing key (D2 picks a random reply mailbox per attempt).
 */

const VER = 2;
const MSG_CHALLENGE = 0;
const MSG_REQUEST = 1;
const MSG_GRANT = 2;
const PAD = 256; // every provisioning frame is padded to this fixed size

export interface Challenge {
  readonly sessionNonce: Uint8Array; // 32 bytes, D1-chosen, fresh per window
  readonly certEpoch: number;
  readonly accountPubKey: Uint8Array; // 32 bytes, so D2 can compute the SAS
}

export interface ProvRequest {
  readonly sessionNonce: Uint8Array; // echoed from the Challenge
  readonly deviceSigKey: Uint8Array; // 32 bytes, D2's MLS signature key
  readonly replyMailbox: Uint8Array; // 32 bytes, random, D2-chosen
  readonly requestId: Uint8Array; // 16 bytes, random
}

export interface Grant {
  readonly accountPubKey: Uint8Array; // 32 bytes
  readonly certEpoch: number;
  readonly cert: Uint8Array; // 64 bytes
  readonly sessionNonce: Uint8Array; // echoed, so D2 binds the grant to its live attempt
}

function pad(buf: Uint8Array): Uint8Array {
  const out = new Uint8Array(PAD);
  out.set(buf.subarray(0, PAD));
  return out;
}

function dv(buf: Uint8Array): DataView {
  return new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
}

export function encodeChallenge(c: Challenge): Uint8Array {
  const b = new Uint8Array(70);
  b[0] = MSG_CHALLENGE;
  b[1] = VER;
  b.set(c.sessionNonce, 2);
  dv(b).setUint32(34, c.certEpoch, false);
  b.set(c.accountPubKey, 38);
  return pad(b);
}

export function decodeChallenge(buf: Uint8Array): Challenge | null {
  if (buf.length < 70 || buf[0] !== MSG_CHALLENGE || buf[1] !== VER) {
    return null;
  }
  return {
    sessionNonce: buf.slice(2, 34),
    certEpoch: dv(buf).getUint32(34, false),
    accountPubKey: buf.slice(38, 70),
  };
}

export function encodeRequest(r: ProvRequest): Uint8Array {
  const b = new Uint8Array(114);
  b[0] = MSG_REQUEST;
  b[1] = VER;
  b.set(r.sessionNonce, 2);
  b.set(r.deviceSigKey, 34);
  b.set(r.replyMailbox, 66);
  b.set(r.requestId, 98);
  return pad(b);
}

export function decodeRequest(buf: Uint8Array): ProvRequest | null {
  if (buf.length < 114 || buf[0] !== MSG_REQUEST || buf[1] !== VER) {
    return null;
  }
  return {
    sessionNonce: buf.slice(2, 34),
    deviceSigKey: buf.slice(34, 66),
    replyMailbox: buf.slice(66, 98),
    requestId: buf.slice(98, 114),
  };
}

export function encodeGrant(g: Grant): Uint8Array {
  const b = new Uint8Array(134);
  b[0] = MSG_GRANT;
  b[1] = VER;
  b.set(g.accountPubKey, 2);
  dv(b).setUint32(34, g.certEpoch, false);
  b.set(g.cert, 38);
  b.set(g.sessionNonce, 102);
  return pad(b);
}

export function decodeGrant(buf: Uint8Array): Grant | null {
  if (buf.length < 134 || buf[0] !== MSG_GRANT || buf[1] !== VER) {
    return null;
  }
  return {
    accountPubKey: buf.slice(2, 34),
    certEpoch: dv(buf).getUint32(34, false),
    cert: buf.slice(38, 102),
    sessionNonce: buf.slice(102, 134),
  };
}

function toHex(b: Uint8Array): string {
  return [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(h: string): Uint8Array {
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/** The account rendezvous mailbox where a seed-holder listens during an add-a-device window. The
 * gateway can precompute this from the account id, so the seed-holder subscribes ONLY during the
 * window (the orchestration enforces that); it is a meeting point, not a secret. */
export async function deriveProvMailbox(usernameHash: string): Promise<string> {
  const domain = new TextEncoder().encode('deaddrop-provision-v1');
  const input = new Uint8Array([...domain, ...hexToBytes(usernameHash)]);
  const digest = await crypto.subtle.digest('SHA-256', input);
  return toHex(new Uint8Array(digest));
}

// --- QR pairing (add-a-device-by-QR) --------------------------------------------------------------
// The NEW device (D2) shows a QR carrying its MLS signature key + a fresh ephemeral X25519 public key;
// the EXISTING device (D1) SCANS it (optical, gateway-blind), certifies the scanned key, and seals the
// certificate to the ephemeral key, published to a reply mailbox DERIVED from that ephemeral key (so it
// need not be transmitted). The ephemeral key never traverses the gateway, so a malicious gateway can
// neither read nor forge the sealed grant. The payload is kept small (65 bytes -> ~90 base64 chars) so
// it fits the compact QR encoder.

const QR_PREFIX = 'ddpair:';
const QR_VER = 1;

function toB64Url(b: Uint8Array): string {
  let s = '';
  for (const x of b) {
    s += String.fromCharCode(x);
  }
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function fromB64Url(s: string): Uint8Array {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    out[i] = bin.charCodeAt(i);
  }
  return out;
}

/** Encode the new device's pairing QR: version + its MLS signature key(32) + its ephemeral X25519
 * public key(32), base64url with a scheme prefix. Read only by the in-app scanner. */
export function encodeQrPairing(deviceSigKey: Uint8Array, ephPub: Uint8Array): string {
  const b = new Uint8Array(1 + 32 + 32);
  b[0] = QR_VER;
  b.set(deviceSigKey.subarray(0, 32), 1);
  b.set(ephPub.subarray(0, 32), 33);
  return QR_PREFIX + toB64Url(b);
}

/** Decode a scanned pairing QR, or null if it is not one of ours. */
export function decodeQrPairing(text: string): { deviceSigKey: Uint8Array; ephPub: Uint8Array } | null {
  if (!text.startsWith(QR_PREFIX)) {
    return null;
  }
  try {
    const b = fromB64Url(text.slice(QR_PREFIX.length));
    if (b.length < 65 || b[0] !== QR_VER) {
      return null;
    }
    return { deviceSigKey: b.slice(1, 33), ephPub: b.slice(33, 65) };
  } catch {
    return null;
  }
}

/** The reply mailbox for a QR pairing attempt, DERIVED from the ephemeral public key so both devices
 * compute it without transmitting it. It is a rendezvous, not a secret; the security is that only the
 * scanner learned the ephemeral key it must seal to. */
export async function deriveQrReplyMailbox(ephPub: Uint8Array): Promise<string> {
  const domain = new TextEncoder().encode('deaddrop-qr-reply-v1');
  const input = new Uint8Array([...domain, ...ephPub]);
  const digest = await crypto.subtle.digest('SHA-256', input);
  return toHex(new Uint8Array(digest));
}

/** Frame a sealed grant for the reply mailbox: len(2, big-endian) || box, padded to the fixed size so
 * the gateway learns nothing from size. */
function encodeSealedGrant(box: Uint8Array): Uint8Array {
  const out = new Uint8Array(PAD);
  out[0] = (box.length >> 8) & 0xff;
  out[1] = box.length & 0xff;
  out.set(box.subarray(0, PAD - 2), 2);
  return out;
}

function decodeSealedGrant(buf: Uint8Array): Uint8Array | null {
  if (buf.length < 2) {
    return null;
  }
  const len = (buf[0]! << 8) | buf[1]!;
  if (len < 32 || 2 + len > buf.length) {
    return null;
  }
  return buf.slice(2, 2 + len);
}

export const PROVISIONING_MESSAGE_TYPES = { MSG_CHALLENGE, MSG_REQUEST, MSG_GRANT } as const;

/** One inbound frame to route through the provisioning state machine. */
export interface ProvFrame {
  readonly messageId: Uint8Array;
  readonly routingKey: string;
  readonly payload: Uint8Array;
}

/** Browser-only dependencies injected by the worker host (the transport + the wasm primitives). */
export interface ProvisioningDeps {
  publish(routingKey: string, payload: Uint8Array): void;
  subscribe(routingKey: string): void;
  ack(messageId: Uint8Array): void;
  /** Our account authorization-key public value (non-empty only on a seed-holder). */
  accountKeyHex(): string;
  /** This device's MLS signature key (its bootstrap mailbox). */
  deviceKeyHex(): string;
  sasDigestHex(nonceHex: string, accountPubHex: string, deviceKeyHex: string, certEpoch: number): string;
  authorizeDevice(deviceKeyHex: string, certEpoch: number, nonceHex: string, confirmedSasHex: string): string;
  adoptCertificate(accountPubHex: string, certEpoch: number, certHex: string): void;
  renderSas(digestHex: string): string;
  pushEvent(kind: string, payload: unknown): void;
  random(n: number): Uint8Array;
  schedule(delayMs: number, cb: () => void): unknown;
  cancel(handle: unknown): void;
  // QR pairing (add-a-device-by-QR); optional so degraded/legacy hosts without the wasm boxes still run
  // the 6-word flow. A fresh ephemeral X25519 keypair (secret||public); seal a grant to a public key;
  // open a sealed grant with a secret; certify a scanned device key (no SAS; the scan is the auth).
  provisionEphemeralKeypair?: (() => Uint8Array) | undefined;
  provisionSeal?: ((recipPub: Uint8Array, plaintext: Uint8Array) => Uint8Array) | undefined;
  provisionOpen?: ((recipSecret: Uint8Array, sealedBox: Uint8Array) => Uint8Array) | undefined;
  authorizeScannedDevice?: ((deviceSigKey: Uint8Array, certEpoch: number) => Uint8Array) | undefined;
  /** The epoch to MINT a new device's certificate at. It must be at least the account's authorization
   * floor, or the certificate is refused by every member the moment the new device is staged into a
   * group ("certificate epoch below floor"). This was hard-coded to 0, which meant that on any account
   * that had EVER revoked a device the floor was above 0 and every paired device was dead on arrival:
   * pairing reported success, the server row was created, and the add then failed forever. */
  mintEpoch(): number;
}

const WINDOW_MS = 120_000; // an add-a-device window; the review hard-caps this at 300s
const QR_SHOW_MS = 180_000; // a shown-QR lives this long, then the one-shot ephemeral burns (under the 300s review cap and PROV_TTL)

/**
 * The device-provisioning state machine (model b). A device acts as the SEED-HOLDER (openWindow) when
 * the user adds another device to this account, or as the NEW DEVICE (startJoin) when this device is
 * being added. `handle` routes inbound frames; the worker dispatches frames on the rendezvous and the
 * reply mailboxes here. The seed-holder NEVER authorizes from an inbound handler: it only ever
 * authorizes from confirm(), which the UI calls after the user compares the six words out of band.
 */
export class Provisioning {
  private role: 'idle' | 'seedholder' | 'newdevice' | 'newdevice-qr' = 'idle';

  /** Whether a pairing ceremony is in progress (any role). Gateway-level transport failures are
   * surfaced on the wizard only while this is true. */
  active(): boolean {
    return this.role !== 'idle';
  }
  private provMailbox = '';

  // New-device QR state: the ephemeral X25519 secret (kept in memory only) and the derived reply mailbox.
  private qrEphSecret: Uint8Array | null = null;
  private qrReplyMailbox = '';
  private qrShowHandle: unknown = null; // the shown-QR expiry timer (worker-side, survives socket churn)

  // Seed-holder state.
  private sessionNonce: Uint8Array | null = null;
  private certEpoch = 0;
  private windowHandle: unknown = null;
  private readonly seenRequests = new Set<string>();
  private pending: { deviceKey: Uint8Array; replyMailbox: Uint8Array; sasDigestHex: string } | null = null;

  // New-device state.
  private myDeviceKey = '';
  private accountPub = '';
  private replyMailbox = '';
  private joinNonceHex = '';
  private joinEpoch = 0;

  constructor(private readonly deps: ProvisioningDeps) {}

  /** SEED-HOLDER: open an add-a-device window. Subscribes to the rendezvous mailbox only for the
   * window's lifetime and publishes a Challenge with a fresh nonce. */
  openWindow(provMailbox: string): void {
    this.cancelQrShow(); // switching to the seed-holder flow: burn any pending QR show + its timer
    const accountPub = this.deps.accountKeyHex();
    if (accountPub === '') {
      this.deps.pushEvent('provisioning-error', { detail: 'this device cannot authorize others' });
      return;
    }
    this.role = 'seedholder';
    this.provMailbox = provMailbox;
    this.sessionNonce = this.deps.random(32);
    // The account's CURRENT epoch, not 0. It is bound into the Challenge below and therefore into the
    // six-word SAS both sides compare, so it has to be settled here, before the Challenge is published.
    this.certEpoch = this.deps.mintEpoch();
    this.seenRequests.clear();
    this.pending = null;
    this.deps.subscribe(provMailbox);
    this.deps.publish(
      provMailbox,
      encodeChallenge({ sessionNonce: this.sessionNonce, certEpoch: this.certEpoch, accountPubKey: hexToBytes(accountPub) }),
    );
    this.windowHandle = this.deps.schedule(WINDOW_MS, () => this.closeWindow());
    this.deps.pushEvent('provisioning-window-open', {});
  }

  /** Close the window: discard the nonce so no further request is processed. */
  closeWindow(): void {
    if (this.role !== 'seedholder') {
      return;
    }
    if (this.windowHandle !== null) {
      this.deps.cancel(this.windowHandle);
      this.windowHandle = null;
    }
    this.role = 'idle';
    this.sessionNonce = null;
    this.pending = null;
    this.deps.pushEvent('provisioning-window-closed', {});
  }

  /** NEW DEVICE: begin being added; subscribe to the rendezvous and wait for the Challenge. */
  startJoin(provMailbox: string): void {
    this.cancelQrShow(); // switching to the six-word flow: burn any pending QR show + its timer
    this.role = 'newdevice';
    this.provMailbox = provMailbox;
    this.myDeviceKey = this.deps.deviceKeyHex();
    this.accountPub = '';
    this.replyMailbox = ''; // clear any prior attempt's reply mailbox so owns() only claims this one
    this.deps.subscribe(provMailbox);
    this.deps.pushEvent('provisioning-waiting', {});
  }

  /** SEED-HOLDER: the user confirmed the six words match. Authorize the pending device (the signer
   * guard re-checks the confirmed code) and deliver the Grant, then close the window. */
  confirm(): void {
    if (this.role !== 'seedholder' || this.pending === null || this.sessionNonce === null) {
      return;
    }
    const p = this.pending;
    let grantHex: string;
    try {
      grantHex = this.deps.authorizeDevice(toHex(p.deviceKey), this.certEpoch, toHex(this.sessionNonce), p.sasDigestHex);
    } catch {
      this.deps.pushEvent('provisioning-error', { detail: 'authorization failed' });
      return;
    }
    // Grant hex = accountPub(64) || certEpoch(16) || cert(128).
    const accountPubKey = hexToBytes(grantHex.slice(0, 64));
    const certEpoch = parseInt(grantHex.slice(72, 80), 16); // low 32 bits of the epoch
    const cert = hexToBytes(grantHex.slice(80));
    this.deps.publish(toHex(p.replyMailbox), encodeGrant({ accountPubKey, certEpoch, cert, sessionNonce: this.sessionNonce }));
    // Carry the authorized device's key so the seed-holder can poll it into the self-group by key.
    this.deps.pushEvent('device-added', { deviceKey: toHex(p.deviceKey) });
    this.closeWindow();
  }

  /** NEW DEVICE (QR): generate an ephemeral keypair, subscribe to the derived reply mailbox, and return
   * the pairing QR payload to display. The existing device scans it, seals a certificate to the
   * ephemeral key, and publishes it to the reply mailbox; onQrGrant then adopts it. No 6-word code. */
  async startQrShow(): Promise<string> {
    if (this.deps.provisionEphemeralKeypair === undefined) {
      throw new Error('QR pairing not available');
    }
    this.cancelQrShow(); // a fresh code supersedes any prior shown QR (burn the old one-shot secret)
    const kp = this.deps.provisionEphemeralKeypair();
    this.qrEphSecret = kp.slice(0, 32);
    const ephPub = kp.slice(32, 64);
    this.qrReplyMailbox = await deriveQrReplyMailbox(ephPub);
    this.role = 'newdevice-qr';
    this.deps.subscribe(this.qrReplyMailbox);
    this.qrShowHandle = this.deps.schedule(QR_SHOW_MS, () => this.expireQrShow());
    this.deps.pushEvent('provisioning-waiting', {});
    return encodeQrPairing(hexToBytes(this.deps.deviceKeyHex()), ephPub);
  }

  /** True while a shown QR is live (this device is waiting for its sealed grant). The transport layer uses
   * this to PRESERVE this machine across a gateway reconnect instead of dropping it. */
  qrShowLive(): boolean {
    return this.role === 'newdevice-qr' && this.qrEphSecret !== null;
  }

  /** Re-subscribe the QR reply mailbox on a NEW transport (after a reconnect). The mailbox derives from the
   * ephemeral PUBLIC half, so this re-subscribes only; it never re-mints and never invalidates the QR the
   * peer already scanned. */
  resubscribeLive(): void {
    if (this.role === 'newdevice-qr' && this.qrReplyMailbox !== '') {
      this.deps.subscribe(this.qrReplyMailbox);
    }
  }

  /** Cancel a shown QR (a flow switch, or an explicit cancel): stop the timer and burn the one-shot secret
   * so no late grant can adopt. Silent (no event). */
  cancelQrShow(): void {
    if (this.qrShowHandle !== null) {
      this.deps.cancel(this.qrShowHandle);
      this.qrShowHandle = null;
    }
    if (this.role === 'newdevice-qr') {
      this.qrEphSecret = null;
      this.role = 'idle';
    }
  }

  /** The shown QR expired before the peer scanned it: burn the one-shot secret (a late grant can never
   * adopt) but KEEP qrReplyMailbox so owns() still swallows a straggler grant off the group path, then
   * surface the expiry so the UI can offer a fresh code. */
  private expireQrShow(): void {
    this.qrShowHandle = null;
    if (this.role !== 'newdevice-qr') {
      return;
    }
    this.qrEphSecret = null;
    this.role = 'idle';
    this.deps.pushEvent('provisioning-expired', {});
  }

  /** SEED-HOLDER (scan): the user scanned a new device's pairing QR. Certify the scanned key (the scan
   * is the out-of-band authentication; no SAS), seal the grant to the scanned ephemeral key, and publish
   * it to the derived reply mailbox. The scanned key MUST come from the camera, never the gateway. */
  async grantScanned(qrPayload: string): Promise<void> {
    if (this.deps.authorizeScannedDevice === undefined || this.deps.provisionSeal === undefined) {
      throw new Error('QR pairing not available');
    }
    if (this.deps.accountKeyHex() === '') {
      this.deps.pushEvent('provisioning-error', { detail: 'this device cannot authorize others' });
      return;
    }
    const parsed = decodeQrPairing(qrPayload);
    if (parsed === null) {
      this.deps.pushEvent('provisioning-error', { detail: 'that is not a DEAD DROP pairing code' });
      return;
    }
    try {
      // The QR flow has no window and no Challenge, so certEpoch is never set by openWindow: read the
      // account's epoch here. Minting at the stale field (0) is what bricked every scanned device.
      this.certEpoch = this.deps.mintEpoch();
      const grant = this.deps.authorizeScannedDevice(parsed.deviceSigKey, this.certEpoch);
      const box = this.deps.provisionSeal(parsed.ephPub, grant);
      const mailbox = await deriveQrReplyMailbox(parsed.ephPub);
      this.deps.publish(mailbox, encodeSealedGrant(box));
      // Carry the scanned device's key so the seed-holder can poll it into the self-group by key.
      this.deps.pushEvent('device-added', { deviceKey: toHex(parsed.deviceSigKey) });
    } catch (err: unknown) {
      // Carry the REAL reason through. This used to collapse every failure into one generic sentence,
      // which is how a mint refused for a concrete, printable reason (an epoch below the account floor,
      // a key on the revocation denylist) reached the user as "could not authorize that device" and
      // stayed undiagnosable across days of retries. The messages this layer raises are counters and
      // states, never key material.
      const detail = err instanceof Error && err.message !== '' ? err.message : 'could not authorize that device';
      this.deps.pushEvent('provisioning-error', { detail });
    }
  }

  private onQrGrant(payload: Uint8Array, messageId: Uint8Array): void {
    if (this.qrEphSecret === null || this.deps.provisionOpen === undefined) {
      return;
    }
    const box = decodeSealedGrant(payload);
    if (box === null) {
      return;
    }
    let grant: Uint8Array;
    try {
      grant = this.deps.provisionOpen(this.qrEphSecret, box); // only WE can open it (gateway-blind)
    } catch {
      return; // not addressed to us / tampered: ignore, keep waiting
    }
    if (grant.length !== 32 + 8 + 64) {
      return;
    }
    const accountPubHex = toHex(grant.slice(0, 32));
    const certEpoch = dv(grant.slice(32, 40)).getUint32(4, false); // low 32 bits of the big-endian epoch
    const certHex = toHex(grant.slice(40, 104));
    try {
      this.deps.adoptCertificate(accountPubHex, certEpoch, certHex);
    } catch {
      this.deps.pushEvent('provisioning-error', { detail: 'could not adopt the authorization' });
      return;
    }
    this.deps.ack(messageId);
    this.qrEphSecret = null; // one-shot: discard the ephemeral secret
    if (this.qrShowHandle !== null) {
      this.deps.cancel(this.qrShowHandle);
      this.qrShowHandle = null;
    }
    this.role = 'idle';
    this.deps.pushEvent('provisioning-authorized', { accountPub: accountPubHex });
  }

  /** True when a routing key belongs to this provisioning attempt (the rendezvous or the reply
   * mailbox). The transport uses this to keep provisioning frames off the group message path, even an
   * own-Challenge echo or a stale frame after the window closes. */
  owns(routingKey: string): boolean {
    return routingKey !== '' && (routingKey === this.provMailbox || routingKey === this.replyMailbox || routingKey === this.qrReplyMailbox);
  }

  /** Route an inbound frame. Returns true if it was a provisioning frame this instance consumed. */
  handle(env: ProvFrame): boolean {
    if (this.role === 'seedholder' && env.routingKey === this.provMailbox) {
      const req = decodeRequest(env.payload);
      if (req !== null) {
        this.onRequest(req, env.messageId);
        return true;
      }
      return false; // e.g. our own Challenge echo
    }
    if (this.role === 'newdevice' && env.routingKey === this.provMailbox) {
      const ch = decodeChallenge(env.payload);
      if (ch !== null) {
        this.onChallenge(ch);
        return true;
      }
      return false;
    }
    if (this.role === 'newdevice' && env.routingKey === this.replyMailbox) {
      const g = decodeGrant(env.payload);
      if (g !== null) {
        this.onGrant(g, env.messageId);
        return true;
      }
    }
    if (this.role === 'newdevice-qr' && env.routingKey === this.qrReplyMailbox) {
      this.onQrGrant(env.payload, env.messageId);
      return true;
    }
    return false;
  }

  private onRequest(req: ProvRequest, messageId: Uint8Array): void {
    if (this.sessionNonce === null || toHex(req.sessionNonce) !== toHex(this.sessionNonce)) {
      return; // not for our live window
    }
    const rid = toHex(req.requestId);
    if (this.seenRequests.has(rid)) {
      return; // dedup replays
    }
    this.seenRequests.add(rid);
    this.deps.ack(messageId);
    const digest = this.deps.sasDigestHex(toHex(this.sessionNonce), this.deps.accountKeyHex(), toHex(req.deviceSigKey), this.certEpoch);
    this.pending = { deviceKey: req.deviceSigKey, replyMailbox: req.replyMailbox, sasDigestHex: digest };
    this.deps.pushEvent('confirm-device', { words: this.deps.renderSas(digest) });
  }

  private onChallenge(ch: Challenge): void {
    if (this.accountPub !== '') {
      return; // already handling a challenge
    }
    this.accountPub = toHex(ch.accountPubKey);
    this.joinNonceHex = toHex(ch.sessionNonce);
    this.joinEpoch = ch.certEpoch;
    this.replyMailbox = toHex(this.deps.random(32));
    const requestId = this.deps.random(16);
    const digest = this.deps.sasDigestHex(this.joinNonceHex, this.accountPub, this.myDeviceKey, this.joinEpoch);
    this.deps.subscribe(this.replyMailbox);
    this.deps.publish(
      this.provMailbox,
      encodeRequest({
        sessionNonce: ch.sessionNonce,
        deviceSigKey: hexToBytes(this.myDeviceKey),
        replyMailbox: hexToBytes(this.replyMailbox),
        requestId,
      }),
    );
    this.deps.pushEvent('show-code', { words: this.deps.renderSas(digest) });
  }

  private onGrant(g: Grant, messageId: Uint8Array): void {
    if (toHex(g.sessionNonce) !== this.joinNonceHex || toHex(g.accountPubKey) !== this.accountPub) {
      return; // not bound to our live attempt
    }
    try {
      this.deps.adoptCertificate(toHex(g.accountPubKey), g.certEpoch, toHex(g.cert));
    } catch {
      this.deps.pushEvent('provisioning-error', { detail: 'could not adopt the authorization' });
      return;
    }
    this.deps.ack(messageId);
    this.role = 'idle';
    this.deps.pushEvent('provisioning-authorized', { accountPub: this.accountPub });
  }
}
