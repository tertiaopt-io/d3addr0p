// DEAD DROP owning Web Worker (M5 hardening): the SOLE writer to IndexedDB and the sole holder of
// the unlocked MSK and the wasm Conversation objects. Keeping these off the main thread means a
// compromised renderer or a second tab cannot read keys or race the stores. The main thread talks
// to this worker via {id, op, args} -> {id, ok, result|error} messages (see src/workerproxy.ts).
//
// This is plain JS served directly (not compiled by tsc) because it imports the web-target wasm,
// which is not part of the typecheck/lint gate. The controller logic it hosts (AppControllerImpl)
// and the proxy that talks to it ARE gate-checked and unit-tested; this file is the irreducible
// glue: load the wasm, open the database, and pump messages. Keep logic here minimal.

import { AppControllerImpl } from './dist/controller.js';
import { openDeadDropDb, MskVault, ChannelStore, IndexedDbKeyvaultStore, SealedSessionStore } from './dist/idb.js';
import { connect } from './dist/wsadapter.bundle.js';
import init, {
  deriveMasterKey,
  Conversation,
  sasDigestHex,
  provisionEphemeralKeypair,
  provisionSealToPub,
  provisionOpenToPriv,
} from './wasm/deaddrop_crypto.js';

let controller = null;

const ready = (async () => {
  await init();
  const db = await openDeadDropDb();
  const deriveKek = (passphrase, salt) => Promise.resolve(deriveMasterKey(passphrase, salt));
  const identity = () => {
    const conv = new Conversation('me');
    const hex = conv.signaturePublicKeyHex();
    conv.free();
    return Promise.resolve([0, 2, 4, 6].map((i) => hex.slice(i, i + 2).toUpperCase()).join('·'));
  };
  // Live-transport dependencies stay in the worker (the sole key holder): the WebSocket connect,
  // the wasm Conversation factory, and a sink that forwards unsolicited events to the main thread.
  const live = {
    connect,
    // The seed-holder's durable identity is an AUTHORIZED signer derived from the account recovery
    // seed: its account-authorization key signs device certificates and roots the group's trust. A
    // device joining by provisioning has no seed (seedHex === ''), so it starts UNAUTHORIZED and adopts
    // a certificate from the seed-holder (model b); it never holds the account seed.
    // Registration always certifies at epoch 0 (a brand-new account has no revokes); a device that is
    // behind re-certifies later via syncEpoch. A seedless device starts unauthorized and adopts a cert.
    makeConversation: (label, seedHex) => (seedHex ? Conversation.newAuthorized(label, seedHex, 0) : new Conversation(label)),
    pushEvent: (kind, payload) => postMessage({ event: kind, payload }),
    schedule: (delayMs, cb) => setTimeout(cb, delayMs),
    cancel: (handle) => clearTimeout(handle),
    // wasm at-rest seal/restore of MLS state under the raw MSK (Conversation.exportSealed/fromSealed).
    sealConversation: (conv, msk) => conv.exportSealed(msk),
    restoreConversation: (msk, sealed) => Conversation.fromSealed(msk, sealed),
    // The 66-bit device-provisioning SAS digest, bound to the full transcript (wasm free function).
    sasDigestHex: (nonceHex, accountPubHex, deviceKeyHex, certEpoch) => sasDigestHex(nonceHex, accountPubHex, deviceKeyHex, certEpoch),
    // QR-pairing box (wasm free functions): ephemeral X25519 keypair, seal a grant to a public key,
    // open a sealed grant with a secret. Used by add-a-device-by-QR.
    provisionEphemeralKeypair: () => provisionEphemeralKeypair(),
    provisionSeal: (recipPub, plaintext) => provisionSealToPub(recipPub, plaintext),
    provisionOpen: (recipSecret, sealedBox) => provisionOpenToPriv(recipSecret, sealedBox),
  };
  controller = new AppControllerImpl(
    new MskVault(db, deriveKek),
    new ChannelStore(db),
    new IndexedDbKeyvaultStore(db),
    undefined,
    identity,
    live,
    new SealedSessionStore(db),
  );
})();

const OPS = {
  ping: () => Promise.resolve(true),
  unlock: (a) => controller.unlock(a[0], a[1]),
  verifyPassphrase: (a) => controller.verifyPassphrase(a[0], a[1]),
  deviceAuthState: () => controller.deviceAuthState(),
  discardAccount: (a) => controller.discardAccount(a[0]),
  listChannels: () => controller.listChannels(),
  peerFor: (id) => controller.peerFor(id),
  openChannel: (a) => controller.openChannel(a[0]),
  openNoteToSelf: () => controller.openNoteToSelf(),
  startKeyExchange: () => controller.startKeyExchange(),
  channelKeyExchange: (a) => controller.channelKeyExchange(a[0]),
  acceptKeyExchange: (a) => controller.acceptKeyExchange(a[0]),
  connectGateway: (a) => controller.connectGateway(a[0]),
  startConversation: (a) => controller.startConversation(a[0]),
  sendMessage: (a) => controller.sendMessage(a[0], a[1], a[2]),
  revokeMessage: (a) => controller.revokeMessage(a[0], a[1]),
  recoverySecret: () => controller.recoverySecret(),
  ensureAccountSeed: () => controller.ensureAccountSeed(),
  openProvisioningWindow: () => controller.openProvisioningWindow(),
  joinDevice: () => controller.joinDevice(),
  confirmProvisioning: () => controller.confirmProvisioning(),
  closeProvisioning: () => controller.closeProvisioning(),
  startQrPairing: () => controller.startQrPairing(),
  grantScannedDevice: (a) => controller.grantScannedDevice(a[0]),
  keyPackages: (a) => controller.keyPackages(a[0]),
  isGroupReady: () => controller.isGroupReady(),
  recoverWithSeed: (a) => controller.recoverWithSeed(a[0], a[1]),
  syncEpoch: (a) => controller.syncEpoch(a[0]),
  certEpoch: () => controller.certEpoch(),
  accountFingerprint: () => controller.accountFingerprint(),
  addDevice: (a) => controller.addDevice(a[0], a[1]),
  excludeDevice: (a) => controller.excludeDevice(a[0]),
  // Self-heal (H1): admit this account's authorized devices not yet in the open conversation. The app
  // claims key packages and passes them as data; only the resulting DeviceTargets cross to the worker.
  hasMissingSiblings: (a) => controller.hasMissingSiblings(a[0]),
  reconcileSiblings: (a) => controller.reconcileSiblings(a[0], a[1]),
  reconcileRemovals: (a) => controller.reconcileRemovals(a[0], a[1]),
  reconcileSelf: (a) => controller.reconcileSelf(a[0], a[1]),
  selfSiblingState: (a) => controller.selfSiblingState(a[0]),
  // Hidden self-group: the private channel that syncs the buddy list across this account's own devices.
  hasSelfGroup: () => controller.hasSelfGroup(),
  ensureSelfGroup: (a) => controller.ensureSelfGroup(a[0]),
  // N-series: MSK-sealed identity card, buddy list, block list, and presence/notify toggles. The proxy
  // forwards these so they no longer silently no-op on the worker path. Payloads are plain JSON.
  getIdentity: () => controller.getIdentity(),
  setIdentity: (a) => controller.setIdentity(a[0]),
  getPeerIdentities: (a) => controller.getPeerIdentities(a[0]),
  tagConversationHandle: (a) => controller.tagConversationHandle(a[0], a[1]),
  getBuddyInfo: (a) => controller.getBuddyInfo(a[0]),
  buddyIcons: (a) => controller.buddyIcons(a[0]),
  listBuddies: () => controller.listBuddies(),
  addBuddy: (a) => controller.addBuddy(a[0], a[1]),
  removeBuddy: (a) => controller.removeBuddy(a[0]),
  setBuddyGroup: (a) => controller.setBuddyGroup(a[0], a[1]),
  listGroups: () => controller.listGroups(),
  addGroup: (a) => controller.addGroup(a[0]),
  renameGroup: (a) => controller.renameGroup(a[0], a[1]),
  deleteGroup: (a) => controller.deleteGroup(a[0]),
  blockConversation: (a) => controller.blockConversation(a[0]),
  removeConversation: (a) => controller.removeConversation(a[0]),
  listBlocked: () => controller.listBlocked(),
  unblock: (a) => controller.unblock(a[0]),
  getPresenceEnabled: () => controller.getPresenceEnabled(),
  setPresenceEnabled: (a) => controller.setPresenceEnabled(a[0]),
  getNotifyEnabled: () => controller.getNotifyEnabled(),
  setNotifyEnabled: (a) => controller.setNotifyEnabled(a[0]),
  // P2P signaling: publish the small WebRTC handshake over the E2E group (file transfer + calls). The
  // media/file bytes never enter the worker; the RTCPeerConnection lives on the main thread.
  sendFileSignal: (a) => Promise.resolve(controller.sendFileSignal(a[0], a[1])),
  sendCallSignal: (a) => Promise.resolve(controller.sendCallSignal(a[0], a[1])),
};

// Single-writer queue: every op runs strictly one at a time, in arrival order, WITHIN THIS WORKER.
// Rapid UI actions in one tab cannot interleave reads and writes against the MSK-protected stores.
// It is NOT a cross-tab guarantee: each tab constructs its own dedicated worker over the one shared
// database, so cross-tab races are guarded where they matter (the burn-on-read read latch takes a
// cross-tab Web Lock inside lifetime.ts).
let chain = ready;

onmessage = (e) => {
  const { id, op, args } = e.data;
  chain = chain
    .then(() => {
      const fn = OPS[op];
      if (!fn) {
        throw new Error('unknown op: ' + op);
      }
      return fn(args || []);
    })
    .then(
      (result) => {
        postMessage({ id, ok: true, result });
      },
      (err) => {
        postMessage({ id, ok: false, error: err && err.message ? err.message : String(err) });
      },
    );
};
