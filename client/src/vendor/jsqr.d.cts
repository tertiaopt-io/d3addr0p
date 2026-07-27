// Types for the vendored jsQR 1.4.0 CommonJS/UMD bundle (src/vendor/jsqr.cjs). Only the surface we use.
declare function jsQR(data: Uint8ClampedArray, width: number, height: number): { data: string } | null;
export = jsQR;
