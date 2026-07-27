/**
 * A small, dependency-free QR code encoder — just enough to render a shareable contact link as an
 * inline SVG under the strict CSP (no runtime npm dependency, matching the project's hand-rolled ethos).
 *
 * Scope, chosen for CORRECTNESS over generality: byte mode, error-correction level L, single ERROR
 * CORRECTION BLOCK, versions 1..5 (21x21 .. 37x37, up to 108 data bytes). Single-block avoids the
 * interleaving machinery, which is the most bug-prone part of a QR encoder, while 108 bytes is far more
 * than a `https://.../#dd=<name>&k=<fp>` contact link needs. All 8 data masks are tried and the lowest
 * penalty wins, so the output scans reliably. Output is an inline <svg> of black/white module <rect>s
 * colored by PRESENTATION ATTRIBUTES + a CSS class (never an inline style=), so it is CSP-safe.
 *
 * References: ISO/IEC 18004. The GF(256) arithmetic, format-info BCH, and mask penalty rules are the
 * standard ones. Verified by round-tripping generated codes through the browser BarcodeDetector.
 */

// --- GF(256) arithmetic for Reed-Solomon (primitive polynomial 0x11d, generator 2) -----------------

const GF_EXP = new Uint8Array(512);
const GF_LOG = new Uint8Array(256);
(() => {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    GF_EXP[i] = x;
    GF_LOG[x] = i;
    x <<= 1;
    if (x & 0x100) {
      x ^= 0x11d;
    }
  }
  for (let i = 255; i < 512; i++) {
    GF_EXP[i] = GF_EXP[i - 255]!;
  }
})();

function gfMul(a: number, b: number): number {
  if (a === 0 || b === 0) {
    return 0;
  }
  return GF_EXP[GF_LOG[a]! + GF_LOG[b]!]!;
}

/** The Reed-Solomon generator polynomial of the given degree (number of EC codewords). */
function rsGenerator(degree: number): Uint8Array {
  let poly = new Uint8Array([1]);
  for (let d = 0; d < degree; d++) {
    const next = new Uint8Array(poly.length + 1);
    for (let i = 0; i < poly.length; i++) {
      next[i] = next[i]! ^ poly[i]!;
      next[i + 1] = next[i + 1]! ^ gfMul(poly[i]!, GF_EXP[d]!);
    }
    poly = next;
  }
  return poly;
}

/** The EC codewords for one block of data codewords. */
function rsEncode(data: Uint8Array, ecCount: number): Uint8Array {
  const gen = rsGenerator(ecCount);
  const res = new Uint8Array(data.length + ecCount);
  res.set(data);
  for (let i = 0; i < data.length; i++) {
    const factor = res[i]!;
    if (factor !== 0) {
      for (let j = 0; j < gen.length; j++) {
        res[i + j] = res[i + j]! ^ gfMul(gen[j]!, factor);
      }
    }
  }
  return res.slice(data.length);
}

// --- per-version characteristics (EC level L, single block) ------------------------------------------

// Total data codewords (bytes) available at EC level L for versions 1..5.
const DATA_CODEWORDS_L = [19, 34, 55, 80, 108];
// EC codewords per (single) block at EC level L for versions 1..5.
const EC_CODEWORDS_L = [7, 10, 15, 20, 26];

/** The smallest version (1..5) whose byte-mode capacity fits `byteLen`, or 0 if it does not fit. */
function pickVersion(byteLen: number): number {
  for (let v = 1; v <= 5; v++) {
    // Overhead: 4-bit mode indicator + 8-bit char count (byte mode, versions 1..9) = 12 bits = 1.5 bytes.
    const capacityBytes = DATA_CODEWORDS_L[v - 1]! - 2; // 12 header bits round up to 2 reserved bytes
    if (byteLen <= capacityBytes) {
      return v;
    }
  }
  return 0;
}

// --- bit buffer --------------------------------------------------------------------------------------

class BitBuffer {
  private bits: number[] = [];
  put(value: number, length: number): void {
    for (let i = length - 1; i >= 0; i--) {
      this.bits.push((value >>> i) & 1);
    }
  }
  get length(): number {
    return this.bits.length;
  }
  toBytes(): Uint8Array {
    const out = new Uint8Array(Math.ceil(this.bits.length / 8));
    for (let i = 0; i < this.bits.length; i++) {
      if (this.bits[i]) {
        out[i >>> 3] = out[i >>> 3]! | (0x80 >>> (i & 7));
      }
    }
    return out;
  }
}

// --- matrix placement --------------------------------------------------------------------------------

const enum Cell {
  EMPTY = -1,
}

/** A version's module grid (functional patterns + data), plus a reservation map for non-data modules. */
function newMatrix(size: number): { m: Int8Array; reserved: Uint8Array; size: number } {
  return { m: new Int8Array(size * size).fill(Cell.EMPTY), reserved: new Uint8Array(size * size), size };
}

function setModule(mx: { m: Int8Array; reserved: Uint8Array; size: number }, r: number, c: number, dark: boolean, reserve = true): void {
  mx.m[r * mx.size + c] = dark ? 1 : 0;
  if (reserve) {
    mx.reserved[r * mx.size + c] = 1;
  }
}

function placeFinder(mx: { m: Int8Array; reserved: Uint8Array; size: number }, top: number, left: number): void {
  for (let r = -1; r <= 7; r++) {
    for (let c = -1; c <= 7; c++) {
      const rr = top + r;
      const cc = left + c;
      if (rr < 0 || rr >= mx.size || cc < 0 || cc >= mx.size) {
        continue;
      }
      const inRing = r >= 0 && r <= 6 && c >= 0 && c <= 6;
      const isBorder = r === 0 || r === 6 || c === 0 || c === 6;
      const isCore = r >= 2 && r <= 4 && c >= 2 && c <= 4;
      const dark = inRing && (isBorder || isCore);
      setModule(mx, rr, cc, dark); // includes the 1-module light separator (r/c === -1 or 7)
    }
  }
}

function placeAlignment(mx: { m: Int8Array; reserved: Uint8Array; size: number }, cr: number, cc: number): void {
  for (let r = -2; r <= 2; r++) {
    for (let c = -2; c <= 2; c++) {
      const dark = Math.max(Math.abs(r), Math.abs(c)) !== 1; // 5x5: dark border + dark center, light ring
      setModule(mx, cr + r, cc + c, dark);
    }
  }
}

/** Reserve the two format-info strips (they are written after masking). */
function reserveFormat(mx: { m: Int8Array; reserved: Uint8Array; size: number }): void {
  const n = mx.size;
  for (let i = 0; i <= 8; i++) {
    if (i !== 6) {
      mx.reserved[8 * n + i] = 1; // horizontal strip near the top-left finder
      mx.reserved[i * n + 8] = 1; // vertical strip near the top-left finder
    }
  }
  for (let i = 0; i < 8; i++) {
    mx.reserved[8 * n + (n - 1 - i)] = 1; // horizontal strip near the top-right finder
    mx.reserved[(n - 1 - i) * n + 8] = 1; // vertical strip near the bottom-left finder
  }
  mx.reserved[(n - 8) * n + 8] = 1; // the always-dark module
  mx.m[(n - 8) * n + 8] = 1;
}

function buildFunctionalPatterns(version: number): { m: Int8Array; reserved: Uint8Array; size: number } {
  const size = 17 + 4 * version;
  const mx = newMatrix(size);
  placeFinder(mx, 0, 0);
  placeFinder(mx, 0, size - 7);
  placeFinder(mx, size - 7, 0);
  // Timing patterns.
  for (let i = 8; i < size - 8; i++) {
    const dark = i % 2 === 0;
    setModule(mx, 6, i, dark);
    setModule(mx, i, 6, dark);
  }
  // Single alignment pattern for versions 2..5, centered at (p, p), p = 4*version + 10.
  if (version >= 2) {
    const p = 4 * version + 10;
    placeAlignment(mx, p, p);
  }
  reserveFormat(mx);
  return mx;
}

/** Place the data + EC bitstream in the standard zig-zag, skipping reserved modules. */
function placeData(mx: { m: Int8Array; reserved: Uint8Array; size: number }, bytes: Uint8Array): void {
  const n = mx.size;
  let bitIndex = 0;
  const totalBits = bytes.length * 8;
  const bitAt = (i: number): number => (i < totalBits ? (bytes[i >>> 3]! >>> (7 - (i & 7))) & 1 : 0);
  let col = n - 1;
  let upward = true;
  while (col > 0) {
    if (col === 6) {
      col--; // skip the vertical timing column
    }
    for (let i = 0; i < n; i++) {
      const row = upward ? n - 1 - i : i;
      for (let dc = 0; dc < 2; dc++) {
        const c = col - dc;
        if (mx.reserved[row * n + c]) {
          continue;
        }
        mx.m[row * n + c] = bitAt(bitIndex) as 0 | 1;
        bitIndex++;
      }
    }
    upward = !upward;
    col -= 2;
  }
}

// --- masking + format info ---------------------------------------------------------------------------

function maskCondition(mask: number, r: number, c: number): boolean {
  switch (mask) {
    case 0:
      return (r + c) % 2 === 0;
    case 1:
      return r % 2 === 0;
    case 2:
      return c % 3 === 0;
    case 3:
      return (r + c) % 3 === 0;
    case 4:
      return (Math.floor(r / 2) + Math.floor(c / 3)) % 2 === 0;
    case 5:
      return ((r * c) % 2) + ((r * c) % 3) === 0;
    case 6:
      return (((r * c) % 2) + ((r * c) % 3)) % 2 === 0;
    default:
      return (((r + c) % 2) + ((r * c) % 3)) % 2 === 0;
  }
}

/** Penalty score of a finished matrix, used to choose the best mask (lower is better). */
function penalty(m: Int8Array, n: number): number {
  const at = (r: number, c: number): number => m[r * n + c]!;
  let score = 0;
  // Rule 1: runs of 5+ same-color modules in a row/column.
  for (let r = 0; r < n; r++) {
    for (let axis = 0; axis < 2; axis++) {
      let run = 1;
      let prev = axis === 0 ? at(r, 0) : at(0, r);
      for (let c = 1; c < n; c++) {
        const cur = axis === 0 ? at(r, c) : at(c, r);
        if (cur === prev) {
          run++;
          if (run === 5) {
            score += 3;
          } else if (run > 5) {
            score += 1;
          }
        } else {
          run = 1;
          prev = cur;
        }
      }
    }
  }
  // Rule 2: 2x2 blocks of the same color.
  for (let r = 0; r < n - 1; r++) {
    for (let c = 0; c < n - 1; c++) {
      const v = at(r, c);
      if (v === at(r, c + 1) && v === at(r + 1, c) && v === at(r + 1, c + 1)) {
        score += 3;
      }
    }
  }
  // Rule 3: finder-like 1:1:3:1:1 patterns (dark-light-dark-dark-dark-light-dark with light padding).
  const p1 = [1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0];
  const p2 = [0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1];
  for (let r = 0; r < n; r++) {
    for (let c = 0; c < n; c++) {
      for (let axis = 0; axis < 2; axis++) {
        if (axis === 0 ? c + 11 <= n : r + 11 <= n) {
          let m1 = true;
          let m2 = true;
          for (let k = 0; k < 11; k++) {
            const val = axis === 0 ? at(r, c + k) : at(r + k, c);
            if (val !== p1[k]) {
              m1 = false;
            }
            if (val !== p2[k]) {
              m2 = false;
            }
          }
          if (m1 || m2) {
            score += 40;
          }
        }
      }
    }
  }
  // Rule 4: proportion of dark modules.
  let dark = 0;
  for (let i = 0; i < n * n; i++) {
    if (m[i] === 1) {
      dark++;
    }
  }
  const percent = (dark * 100) / (n * n);
  score += Math.floor(Math.abs(percent - 50) / 5) * 10;
  return score;
}

/** The 15-bit format information for EC level L (bits 01) and a mask, with BCH ECC and the 0x5412 mask. */
function formatBits(mask: number): number {
  const data = (0b01 << 3) | mask; // EC level L = 0b01
  let bch = data << 10;
  const g = 0b10100110111;
  for (let i = 14; i >= 10; i--) {
    if ((bch >>> i) & 1) {
      bch ^= g << (i - 10);
    }
  }
  return ((data << 10) | bch) ^ 0b101010000010010;
}

function writeFormat(mx: { m: Int8Array; reserved: Uint8Array; size: number }, mask: number): void {
  const n = mx.size;
  const bits = formatBits(mask);
  const bit = (i: number): 0 | 1 => (((bits >>> i) & 1) as 0 | 1);
  // Top-left strips.
  for (let i = 0; i <= 5; i++) {
    mx.m[8 * n + i] = bit(i);
  }
  mx.m[8 * n + 7] = bit(6);
  mx.m[8 * n + 8] = bit(7);
  mx.m[7 * n + 8] = bit(8);
  for (let i = 9; i <= 14; i++) {
    mx.m[(14 - i) * n + 8] = bit(i);
  }
  // Top-right and bottom-left copies.
  for (let i = 0; i <= 7; i++) {
    mx.m[8 * n + (n - 1 - i)] = bit(i);
  }
  for (let i = 8; i <= 14; i++) {
    mx.m[(n - 15 + i) * n + 8] = bit(i);
  }
}

// --- public API --------------------------------------------------------------------------------------

/** The finished module grid for `text` (byte mode, EC-L). Throws if the text does not fit v1..5. */
export function qrMatrix(text: string): { modules: boolean[][]; size: number } {
  const data = new TextEncoder().encode(text);
  const version = pickVersion(data.length);
  if (version === 0) {
    throw new Error('qr: text too long for a v1-5 code');
  }
  const dataCodewords = DATA_CODEWORDS_L[version - 1]!;
  const ecCodewords = EC_CODEWORDS_L[version - 1]!;

  // Build the data bitstream: mode (byte=0100), 8-bit length, the bytes, terminator, then bit/byte pad.
  const bb = new BitBuffer();
  bb.put(0b0100, 4);
  bb.put(data.length, 8);
  for (const byte of data) {
    bb.put(byte, 8);
  }
  const capacityBits = dataCodewords * 8;
  const terminator = Math.min(4, capacityBits - bb.length);
  bb.put(0, terminator);
  while (bb.length % 8 !== 0) {
    bb.put(0, 1);
  }
  const dataBytes = new Uint8Array(dataCodewords);
  dataBytes.set(bb.toBytes());
  for (let i = bb.length / 8, pad = 0; i < dataCodewords; i++, pad++) {
    dataBytes[i] = pad % 2 === 0 ? 0xec : 0x11; // standard alternating pad codewords
  }

  const ec = rsEncode(dataBytes, ecCodewords);
  const all = new Uint8Array(dataCodewords + ecCodewords);
  all.set(dataBytes);
  all.set(ec, dataCodewords);

  // Try all 8 masks; keep the one with the lowest penalty.
  let best: Int8Array | null = null;
  let bestScore = Infinity;
  let bestSize = 0;
  for (let mask = 0; mask < 8; mask++) {
    const mx = buildFunctionalPatterns(version);
    placeData(mx, all);
    for (let r = 0; r < mx.size; r++) {
      for (let c = 0; c < mx.size; c++) {
        if (!mx.reserved[r * mx.size + c] && maskCondition(mask, r, c)) {
          mx.m[r * mx.size + c] = (mx.m[r * mx.size + c]! ^ 1) as 0 | 1;
        }
      }
    }
    writeFormat(mx, mask);
    const score = penalty(mx.m, mx.size);
    if (score < bestScore) {
      bestScore = score;
      best = mx.m;
      bestSize = mx.size;
    }
  }
  const size = bestSize;
  const grid = best!;
  const modules: boolean[][] = [];
  for (let r = 0; r < size; r++) {
    const row: boolean[] = [];
    for (let c = 0; c < size; c++) {
      row.push(grid[r * size + c] === 1);
    }
    modules.push(row);
  }
  return { modules, size };
}

/**
 * An inline SVG rendering of the QR for `text`, with a 4-module quiet zone. CSP-safe: the dark modules
 * are a single black <path>; colors come from presentation attributes, never an inline style. The
 * background is a white <rect> so the code scans on any surface. `px` is the pixel size of the whole svg.
 */
export function qrSvg(text: string, px = 200): string {
  const { modules, size } = qrMatrix(text);
  const quiet = 4;
  const dim = size + quiet * 2;
  let path = '';
  for (let r = 0; r < size; r++) {
    for (let c = 0; c < size; c++) {
      if (modules[r]![c]) {
        path += `M${c + quiet} ${r + quiet}h1v1h-1z`;
      }
    }
  }
  return (
    `<svg class="dd-qr-svg" viewBox="0 0 ${dim} ${dim}" width="${px}" height="${px}" ` +
    `shape-rendering="crispEdges" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="QR code">` +
    `<rect width="${dim}" height="${dim}" fill="#ffffff"/>` +
    `<path d="${path}" fill="#000000"/>` +
    '</svg>'
  );
}
