// Ambient types for dist/qrdecode.bundle.js (produced by esbuild from qrdecode.ts, with the vendored
// jsQR inlined). Lets app.ts do `await import('./qrdecode.bundle.js')` with types, while the actual
// source lives in qrdecode.ts. There is no runtime .js for this .d.ts; esbuild writes the bundle.
export function decodeQr(data: Uint8ClampedArray, width: number, height: number): string | null;
