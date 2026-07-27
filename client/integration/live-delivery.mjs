/*
 * Live multi-device delivery verification (ADR-022 model B). Drives REAL GroupChannel clients with
 * the REAL wasm crypto over a REAL running gateway, proving the owner requirement end to end:
 *   1. PROVISIONING (model b): a new device joins the account through the two-leg SAS handshake
 *      (openProvisioningWindow / joinDevice / compare six words / confirmProvisioning / adopt), never
 *      learning the recovery seed.
 *   2. DELIVERY: every device of a user receives each message and any device can reply.
 *   3. P5 add-device: a device joins an ALREADY-established group and starts receiving.
 *   4. P6 revoke: an excluded device is evicted and stops receiving new messages.
 * Unlike the unit suites (which use fakes), this exercises the actual transport + crypto end to end.
 *
 * Run:
 *   1. (terminal A) cd ../../gateway && DD_ALLOWED_ORIGINS='*' go run ./cmd/gateway
 *   2. (terminal B) cd .. && npm run build && node integration/live-delivery.mjs
 * Exits non-zero on failure.
 */
import init, { Conversation, sasDigestHex } from '../wasm/deaddrop_crypto.js';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { connect } from '../dist/wsadapter.bundle.js';
import { GroupChannel } from '../dist/groupchannel.js';
import { GroupSession } from '../dist/group.js';

await init(readFileSync(fileURLToPath(new URL('../wasm/deaddrop_crypto_bg.wasm', import.meta.url))));
const WS = process.env.DD_WS_URL ?? 'ws://127.0.0.1:8443/ws';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function waitFor(pred, ms = 5000) { const s = Date.now(); while (Date.now() - s < ms) { if (pred()) return true; await sleep(20); } return false; }
const dec = new TextDecoder();
function chan(conv, inbox, ev) {
  const deps = { connect, makeConversation: () => conv, pushEvent: (k, p) => ev.push({ k, p }),
    schedule: (ms, cb) => setTimeout(cb, ms), cancel: (h) => clearTimeout(h),
    sealConversation: () => new Uint8Array(), restoreConversation: () => conv,
    sasDigestHex: (n, a, d, e) => sasDigestHex(n, a, d, e) };
  return new GroupChannel(deps, () => Promise.resolve(),
    (meta, pt) => { inbox.push({ dir: meta.direction, text: dec.decode(pt) }); return Promise.resolve(); }, undefined);
}
const fail = (m) => { console.error('FAIL:', m); process.exit(1); };
const words = (ev, kind) => ev.find((e) => e.k === kind)?.p?.words;

const ALICE_SEED = 'aa'.repeat(32);
const aliceD1 = Conversation.newAuthorized('alice-d1', ALICE_SEED, 0); // the seed-holder
const aliceD2 = new Conversation('alice-d2'); // a NEW, UNAUTHORIZED device joining by provisioning
const bobConv = Conversation.newAuthorized('bob', 'bb'.repeat(32), 0);
const ALICE_HASH = 'a1'.repeat(32); // alice's account id (= username hash); the rendezvous derives from it

const d1Ev = [], d2Ev = [], bEv = [], d1In = [], d2In = [], bIn = [];
const cd1 = chan(aliceD1, d1In, d1Ev), cd2 = chan(aliceD2, d2In, d2Ev), cb = chan(bobConv, bIn, bEv);
await cd1.connectGateway(WS); await cd2.connectGateway(WS); await cb.connectGateway(WS);
await sleep(300);

// === 1. PROVISIONING: add alice's 2nd device through the real two-leg SAS handshake ===
await cd2.joinDevice(ALICE_HASH); // the new device waits for the challenge
await cd1.openProvisioningWindow(ALICE_HASH); // the seed-holder opens the window and challenges
if (!(await waitFor(() => words(d2Ev, 'show-code') && words(d1Ev, 'confirm-device')))) fail('provisioning handshake did not reach the compare step');
if (words(d2Ev, 'show-code') !== words(d1Ev, 'confirm-device')) fail('the six words did not match across the two devices');
await cd1.confirmProvisioning(); // the user compared the words out of band and confirmed
if (!(await waitFor(() => d2Ev.some((e) => e.k === 'provisioning-authorized')))) fail('the new device did not adopt its authorization');
if (aliceD2.accountKeyHex() !== '') fail('a provisioned device must not hold the account key (model b)');

// === 2. DELIVERY: alice-d1 opens a group with bob and her now-authorized 2nd device ===
const d2Kp = aliceD2.keyPackage(), d2Key = aliceD2.signaturePublicKeyHex();
const bobKp = bobConv.keyPackage(), bobKey = bobConv.signaturePublicKeyHex();
await cd1.startConversation([{ deviceKey: bobKey, keyPackage: bobKp }, { deviceKey: d2Key, keyPackage: d2Kp }]);
if (!(await waitFor(() => bEv.some((e) => e.k === 'established') && d2Ev.some((e) => e.k === 'established')))) fail('peers did not join the group');
const convId = bEv.find((e) => e.k === 'established').p.conversationId;

await cb.sendMessage(convId, 'package is at the usual spot');
if (!(await waitFor(() => d1In.some((m) => m.dir === 'in') && d2In.some((m) => m.dir === 'in')))) fail('not all of alice\'s devices received');
await cd2.sendMessage(d2Ev.find((e) => e.k === 'established').p.conversationId, 'got it, leaving now');
if (!(await waitFor(() => bIn.some((m) => m.dir === 'in') && d1In.some((m) => m.text === 'got it, leaving now')))) fail('reply from the 2nd device did not reach the group');

// === 3. P5: add a 3rd device to the ALREADY-established group ===
const aliceD3 = new Conversation('alice-d3');
const n3 = '33'.repeat(32);
const g3 = aliceD1.authorizeDevice(aliceD3.signaturePublicKeyHex(), 0, n3, sasDigestHex(n3, aliceD1.accountKeyHex(), aliceD3.signaturePublicKeyHex(), 0));
aliceD3.adoptCertificate(g3.slice(0, 64), parseInt(g3.slice(72, 80), 16), g3.slice(80));
const d3Ev = [], d3In = [];
const cd3 = chan(aliceD3, d3In, d3Ev);
await cd3.connectGateway(WS); await sleep(200);
await cd1.addDevice({ deviceKey: aliceD3.signaturePublicKeyHex(), keyPackage: aliceD3.keyPackage() });
if (!(await waitFor(() => d3Ev.some((e) => e.k === 'established')))) fail('P5: the added device did not join');
if (!(await waitFor(() => bEv.some((e) => e.k === 'roster-changed')))) fail('P5: existing members did not see the roster change');
await cb.sendMessage(convId, 'third device check');
if (!(await waitFor(() => d3In.some((m) => m.text === 'third device check') && d1In.some((m) => m.text === 'third device check') && d2In.some((m) => m.text === 'third device check')))) fail('P5: not every device received after the add');

// === 4. P6: revoke alice-d2; it must be evicted and stop receiving new messages ===
const d2InBefore = d2In.length;
await cd1.removeDevice(d2Key);
if (!(await waitFor(() => d2Ev.some((e) => e.k === 'connection' && e.p.state === 'offline')))) fail('P6: the revoked device was not evicted');
await cb.sendMessage(convId, 'rotate the drop point');
if (!(await waitFor(() => d1In.some((m) => m.text === 'rotate the drop point') && d3In.some((m) => m.text === 'rotate the drop point')))) fail('P6: remaining devices did not receive after the revoke');
await sleep(500); // give any (incorrect) delivery to the revoked device time to land
if (d2In.length !== d2InBefore) fail('P6: the revoked device received a message after exclusion');

// === 5. RECOVERY: a brand-new device becomes authorized by entering the recovery secret ===
const aliceD5 = new Conversation('alice-d5'); // fresh, unauthorized
const d5KeyBefore = aliceD5.signaturePublicKeyHex();
aliceD5.recoverWithSeed(ALICE_SEED, 0); // the user types their recovery secret
if (aliceD5.accountKeyHex() !== aliceD1.accountKeyHex()) fail('recovery: account key does not match the seed-holder');
if (aliceD5.signaturePublicKeyHex() !== d5KeyBefore) fail('recovery: the device key must not change');
const d5Ev = [], d5In = [];
const cd5 = chan(aliceD5, d5In, d5Ev);
await cd5.connectGateway(WS); await sleep(200);
// bob opens a fresh conversation with the recovered device; it joins and receives.
const bob2 = Conversation.newAuthorized('bob2', 'b2'.repeat(32), 0);
const b2Ev = [], b2In = [];
const cb2 = chan(bob2, b2In, b2Ev);
await cb2.connectGateway(WS); await sleep(200);
const model2 = await cb2.startConversation([{ deviceKey: aliceD5.signaturePublicKeyHex(), keyPackage: aliceD5.keyPackage() }]);
if (!(await waitFor(() => d5Ev.some((e) => e.k === 'established')))) fail('recovery: the recovered device did not join');
const conv2 = model2.conversationId;
await cb2.sendMessage(conv2, 'welcome back');
if (!(await waitFor(() => d5In.some((m) => m.text === 'welcome back')))) fail('recovery: the recovered device did not receive');

// === 6. P6 EPOCH BUMP: the gate rejects an old-epoch device once the floor rises ===
// Mirror the post-revoke state with the REAL wasm via GroupSession (raw gate, no transport needed).
const peerX = Conversation.newAuthorized('peerX', 'cc'.repeat(32), 0);
const aliceUp = Conversation.newAuthorized('alice-up', ALICE_SEED, 0);
aliceUp.reauthorizeAtEpoch(1); // a remaining device re-certifies at the bumped epoch
if (aliceUp.certEpoch() !== 1) fail('epoch bump: certEpoch did not advance');
const peerS = new GroupSession(peerX, 'cx');
const aliceUpS = new GroupSession(aliceUp, 'cx');
const w = peerS.bootstrap([aliceUp.keyPackage()]); // group {peerX, aliceUp@1} -> floor for alice = 1
aliceUpS.join(w);
const staleOld = Conversation.newAuthorized('alice-stale', ALICE_SEED, 0); // an old-epoch (0) device
const { commit } = peerS.addDevice(staleOld.keyPackage());
let rejected = false;
try { aliceUpS.receive(commit); } catch (e) { rejected = /below floor/.test(String(e)); }
if (!rejected) fail('epoch bump: the gate did NOT reject the below-floor (old-epoch) device');

console.log('LIVE MULTI-DEVICE: PASS (SAS provision; all receive; P5 add; P6 revoke excludes; recovery; epoch-floor rejects old cert)');
process.exit(0);
