// Generate the native app icons from the DEAD DROP mark (the same teardrop-and-keyhole the PWA uses),
// so the desktop build carries the product icon instead of the default Electron one. Dependency-free:
// resizing uses macOS `sips` and the .icns container uses `iconutil` (this is the mac build host); the
// .ico container is assembled here, since ICO can embed PNG frames directly (Vista and later).
//
//   npm run icons
//
// Source: client/public/icons/icon-512.png (512x512 RGBA, full-bleed brand navy).
import { execFileSync } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
const SRC = join(HERE, '..', '..', 'client', 'public', 'icons', 'icon-512.png');
const BUILD = join(HERE, '..', 'build');
const TMP = join(BUILD, '.iconset-tmp');

function resize(size, out) {
  execFileSync('sips', ['-z', String(size), String(size), SRC, '--out', out], { stdio: 'ignore' });
}

/** macOS .icns: the nominal sizes plus their @2x retina twins, packed by iconutil. */
function buildIcns() {
  const set = join(BUILD, 'icon.iconset');
  rmSync(set, { recursive: true, force: true });
  mkdirSync(set, { recursive: true });
  for (const s of [16, 32, 128, 256, 512]) {
    resize(s, join(set, `icon_${s}x${s}.png`));
    resize(s * 2, join(set, `icon_${s}x${s}@2x.png`));
  }
  execFileSync('iconutil', ['-c', 'icns', set, '-o', join(BUILD, 'icon.icns')], { stdio: 'ignore' });
  rmSync(set, { recursive: true, force: true });
}

/** Windows .ico: a 6-byte header, one 16-byte directory entry per frame, then the PNG payloads. */
function buildIco() {
  const sizes = [16, 24, 32, 48, 64, 128, 256];
  rmSync(TMP, { recursive: true, force: true });
  mkdirSync(TMP, { recursive: true });
  const frames = sizes.map((s) => {
    const out = join(TMP, `${s}.png`);
    resize(s, out);
    return { size: s, data: readFileSync(out) };
  });
  const header = Buffer.alloc(6);
  header.writeUInt16LE(0, 0); // reserved
  header.writeUInt16LE(1, 2); // type 1 = icon
  header.writeUInt16LE(frames.length, 4);
  const dir = Buffer.alloc(16 * frames.length);
  let offset = header.length + dir.length;
  frames.forEach((f, i) => {
    const at = i * 16;
    dir.writeUInt8(f.size >= 256 ? 0 : f.size, at); // 0 means 256
    dir.writeUInt8(f.size >= 256 ? 0 : f.size, at + 1);
    dir.writeUInt8(0, at + 2); // palette count (0 = truecolor)
    dir.writeUInt8(0, at + 3); // reserved
    dir.writeUInt16LE(1, at + 4); // color planes
    dir.writeUInt16LE(32, at + 6); // bits per pixel
    dir.writeUInt32LE(f.data.length, at + 8);
    dir.writeUInt32LE(offset, at + 12);
    offset += f.data.length;
  });
  writeFileSync(join(BUILD, 'icon.ico'), Buffer.concat([header, dir, ...frames.map((f) => f.data)]));
  rmSync(TMP, { recursive: true, force: true });
}

mkdirSync(BUILD, { recursive: true });
buildIcns();
buildIco();
console.log('wrote build/icon.icns and build/icon.ico from', SRC);
