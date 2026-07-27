// Generate the PWA cover icons (the "Midnight" companion app's mark) with no dependencies: a
// crescent moon on the brand navy. Dependency-free PNG encoder (zlib + a CRC table). Run:
//   node scripts/gen-icons.mjs
import zlib from 'node:zlib';
import { writeFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const OUT = join(dirname(fileURLToPath(import.meta.url)), '..', 'public', 'icons');

const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) {
      c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    t[n] = c >>> 0;
  }
  return t;
})();

function crc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) {
    c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  }
  return (c ^ 0xffffffff) >>> 0;
}

function chunk(type, data) {
  const typeBuf = Buffer.from(type, 'ascii');
  const body = Buffer.concat([typeBuf, data]);
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length, 0);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body), 0);
  return Buffer.concat([len, body, crc]);
}

function encodePng(width, height, rgba) {
  const sig = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 6; // color type RGBA
  const stride = width * 4;
  const raw = Buffer.alloc(height * (1 + stride));
  for (let y = 0; y < height; y++) {
    raw[y * (1 + stride)] = 0; // filter: none
    rgba.copy(raw, y * (1 + stride) + 1, y * stride, y * stride + stride);
  }
  const idat = zlib.deflateSync(raw, { level: 9 });
  return Buffer.concat([sig, chunk('IHDR', ihdr), chunk('IDAT', idat), chunk('IEND', Buffer.alloc(0))]);
}

// Colors
const NAVY = [10, 24, 168, 255]; // #0a18a8 brand background
const MOON = [206, 224, 255, 255]; // pale blue crescent

function makeIcon(size) {
  const rgba = Buffer.alloc(size * size * 4);
  const cx = size * 0.46;
  const cy = size * 0.46;
  const r = size * 0.30; // outer moon radius (keeps a safe maskable margin)
  const ox = size * 0.60; // cutout circle center (offset right) carves the crescent
  const oy = size * 0.40;
  const or = size * 0.27;
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const inMoon = (x - cx) ** 2 + (y - cy) ** 2 <= r * r;
      const inCut = (x - ox) ** 2 + (y - oy) ** 2 <= or * or;
      const c = inMoon && !inCut ? MOON : NAVY;
      const i = (y * size + x) * 4;
      rgba[i] = c[0];
      rgba[i + 1] = c[1];
      rgba[i + 2] = c[2];
      rgba[i + 3] = c[3];
    }
  }
  return encodePng(size, size, rgba);
}

mkdirSync(OUT, { recursive: true });
for (const size of [192, 512]) {
  const png = makeIcon(size);
  writeFileSync(join(OUT, `icon-${size}.png`), png);
  console.log(`wrote icon-${size}.png (${png.length} bytes)`);
}
