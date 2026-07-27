# Third-party code

DEAD DROP ships no third-party runtime npm dependencies. The single exception is one vendored library,
checked into the source tree and bundled at build time so the exact bytes that run are fixed and pinned
by the service worker.

## jsQR 1.4.0 (QR code decoder)

- Source: https://github.com/cozmo/jsQR (npm package `jsqr@1.4.0`).
- Author: Cosmo Wolfe and contributors.
- License: Apache-2.0. Full text: [`client/src/vendor/jsqr.LICENSE`](../client/src/vendor/jsqr.LICENSE).
- Vendored file: [`client/src/vendor/jsqr.cjs`](../client/src/vendor/jsqr.cjs) (copied verbatim from the
  package's `dist/jsQR.js`, with a provenance header prepended).
- What it does: decodes a QR code from a raw RGBA image frame. It is pure computation: no `eval` or
  `new Function`, no network, no DOM, no storage, so it is safe under the app's strict CSP.
- Where it runs: bundled by esbuild into `dist/qrdecode.bundle.js` and lazy-loaded ONLY by the add-a-device
  camera scanner, and ONLY as the fallback for browsers without the native `BarcodeDetector` API (for
  example iOS Safari and Firefox). Chromium-based browsers use `BarcodeDetector` and never load it.
- Why vendored rather than an npm dependency: a correct QR decoder (Reed-Solomon error correction,
  perspective detection, binarization) is large and error-prone to hand-roll, and the encoder we hand-rolled
  covers only encoding. Vendoring the reviewed, license-compatible library keeps the build dependency-free
  and the running bytes fixed. To update, re-vendor from npm and refresh `jsqr.LICENSE`.
