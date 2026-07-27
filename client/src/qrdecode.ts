/**
 * The camera-scan QR decoder, used ONLY as the fallback when the browser has no native BarcodeDetector
 * (iOS Safari, Firefox). It wraps the vendored jsQR (Apache-2.0, pure computation, CSP-safe). This module
 * is excluded from tsc's emit (like wsadapter.ts) and bundled on its own by esbuild into
 * dist/qrdecode.bundle.js, which app.ts lazy-imports so the ~40KB decoder never weighs on startup.
 */
import jsQR from './vendor/jsqr.cjs';

/** Decode a single RGBA frame; returns the decoded text, or null when no QR is found. */
export function decodeQr(data: Uint8ClampedArray, width: number, height: number): string | null {
  const code = jsQR(data, width, height);
  return code !== null ? code.data : null;
}
