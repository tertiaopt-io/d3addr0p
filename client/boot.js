// DEAD DROP bootstrap. External (not inline) so a strict CSP needs no script-src 'unsafe-inline',
// and so the integrity-pinned service worker covers it like any other shell asset. Lives at the web
// root so its relative imports ('./dist/…', './worker.js', './wasm/…') resolve against the root.
import { mountApp, DemoController } from './dist/app.js';
import { AccountClient, httpAccountTransport } from './dist/auth.js';

const root = document.getElementById('app');
if (!root) {
  throw new Error('no #app');
}

// Integrity-pinned PWA shell (ADR-004): once installed, app code is served from a hash-verified
// cache instead of refetched from the origin each load. Inert until sw.js ships a populated pin set
// (the deploy build injects it), so this is a no-op in local dev.
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/sw.js').catch((e) => console.warn('sw register failed', e));
  });
}

// Gateway WebSocket: same-origin WSS in production (Apache proxies /ws to the loopback gateway); a
// direct loopback port for local dev. Override with window.DD_WS_URL if needed.
const wsUrl =
  window.DD_WS_URL ??
  (location.protocol === 'https:' ? `wss://${location.host}/ws` : `ws://${location.hostname}:8443/ws`);

// Account server (control-plane): same-origin /api in production (Apache proxies it to PHP-FPM). It
// is enabled where there is a real backend (https) and can be forced with window.DD_API_BASE (set to
// '' for same-origin, or a full base URL). When absent (local dev with no control-plane) the app
// runs local-only: register/login just open the local vault, with no server username uniqueness.
const apiBase = window.DD_API_BASE ?? (location.protocol === 'https:' ? '' : null);
const account = apiBase !== null ? new AccountClient(httpAccountTransport(apiBase)) : undefined;
// Direct P2P file transfer (N7) + audio/video calls (P2): adapt the browser RTCPeerConnection to the
// injected factory shape. One adapter serves both: a file transfer uses the data-channel members; a
// call uses the media members (addTrack/ontrack). STUN is used only for connection setup (NAT
// discovery); it never relays the bytes or media, and there is no TURN relay, so a strict NAT can
// prevent a direct connection (disclosed in honest-limits). Each peer learns the other's IP.
const rtcFactory =
  typeof RTCPeerConnection === 'undefined'
    ? undefined
    : () => {
        const pc = new RTCPeerConnection({ iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] });
        return {
          createDataChannel: (label) => pc.createDataChannel(label),
          createOffer: () => pc.createOffer(),
          createAnswer: () => pc.createAnswer(),
          setLocalDescription: (d) => pc.setLocalDescription(d),
          setRemoteDescription: (d) => pc.setRemoteDescription(d),
          addIceCandidate: (c) => pc.addIceCandidate(c),
          addTrack: (track, stream) => pc.addTrack(track, stream),
          get connectionState() {
            return pc.connectionState;
          },
          set onicecandidate(h) {
            pc.onicecandidate = h;
          },
          set ondatachannel(h) {
            pc.ondatachannel = h;
          },
          set ontrack(h) {
            pc.ontrack = h;
          },
          set onconnectionstatechange(h) {
            pc.onconnectionstatechange = h;
          },
          close: () => pc.close(),
        };
      };
// getUserMedia for calls. Audio is captured with echo cancellation / noise suppression for a clean,
// low-latency Opus stream; video is held to a modest resolution and frame rate to keep latency and
// bandwidth sane. Absent where the browser has no camera/mic API (then calls are unavailable).
const media =
  typeof navigator !== 'undefined' && navigator.mediaDevices && navigator.mediaDevices.getUserMedia
    ? ({ audio, video, facingMode }) =>
        navigator.mediaDevices.getUserMedia({
          audio: audio ? { echoCancellation: true, noiseSuppression: true, autoGainControl: true } : false,
          // facingMode is advisory ('ideal'): the QR scanner asks for the rear camera on phones, but a
          // single-camera device (laptop) still gets its one camera instead of failing.
          video: video
            ? { width: { ideal: 640 }, height: { ideal: 480 }, frameRate: { ideal: 24 }, ...(facingMode ? { facingMode: { ideal: facingMode } } : {}) }
            : false,
        })
    : undefined;
const mount = (controller, withAccounts = true) =>
  mountApp(root, controller, { wsUrl, account: withAccounts ? account : undefined, rtcFactory, media });

const withTimeout = (p, ms) =>
  Promise.race([p, new Promise((_r, reject) => setTimeout(() => reject(new Error('timeout')), ms))]);

// Preferred path: the owning Web Worker (worker.js) is the SOLE writer to storage and the sole
// holder of the unlocked MSK and wasm keys, so secrets stay off the main thread and two tabs cannot
// race the stores. We construct it, then probe with ping() so a worker whose wasm failed to load
// falls back rather than leaving the UI wedged.
const tryWorker = async () => {
  if (typeof Worker === 'undefined') {
    return null;
  }
  const { WorkerController, workerTransport } = await import('./dist/workerproxy.js');
  const worker = new Worker('./worker.js', { type: 'module' });
  const controller = new WorkerController(workerTransport(worker));
  await withTimeout(controller.ping(), 8000); // wasm + Argon2id init can be slow on first load
  return controller;
};

// Fallback path: run the same real controller on the main thread (wasm Argon2id unlock +
// IndexedDB-backed channels and history). Loses the off-thread isolation but is fully functional.
const tryMainThread = async () => {
  const [{ AppControllerImpl }, idb, wasm] = await Promise.all([
    import('./dist/controller.js'),
    import('./dist/idb.js'),
    import('./wasm/deaddrop_crypto.js'),
  ]);
  await wasm.default();
  const db = await idb.openDeadDropDb();
  const deriveKek = (passphrase, salt) => Promise.resolve(wasm.deriveMasterKey(passphrase, salt));
  const identity = () => {
    const conv = new wasm.Conversation('me');
    const hex = conv.signaturePublicKeyHex();
    conv.free();
    return Promise.resolve([0, 2, 4, 6].map((i) => hex.slice(i, i + 2).toUpperCase()).join('·'));
  };
  return new AppControllerImpl(
    new idb.MskVault(db, deriveKek),
    new idb.ChannelStore(db),
    new idb.IndexedDbKeyvaultStore(db),
    undefined,
    identity,
  );
};

// worker -> main-thread -> demo. The demo keeps the shell usable on an older preview with no wasm.
(async () => {
  try {
    const fromWorker = await tryWorker();
    if (fromWorker) {
      mount(fromWorker);
      return;
    }
  } catch (err) {
    console.warn('owning worker unavailable; trying main thread', err);
  }
  try {
    mount(await tryMainThread());
  } catch (err) {
    console.warn('real backend unavailable; using demo', err);
    mount(new DemoController(), false); // demo is local-only sample data; no account server
  }
})();
