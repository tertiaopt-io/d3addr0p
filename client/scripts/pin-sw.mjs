// Generate the integrity-pinned service worker for a deploy (ADR-004). Hashes every assembled
// web-root asset (SHA-256, matching src/integrity.ts) and bakes the pin set into sw.js, so an
// installed PWA serves only hash-verified app code from cache. Run AFTER the web root is assembled:
//   node scripts/pin-sw.mjs <webroot-dir> <path-to-source-sw.js>
import { readFileSync, writeFileSync, readdirSync, statSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join, relative, sep } from 'node:path';

const [webroot, swSrc] = process.argv.slice(2);
if (!webroot || !swSrc) {
  console.error('usage: node pin-sw.mjs <webroot-dir> <source-sw.js>');
  process.exit(1);
}

function walk(dir, out = []) {
  for (const entry of readdirSync(dir)) {
    const p = join(dir, entry);
    if (statSync(p).isDirectory()) {
      walk(p, out);
    } else {
      out.push(p);
    }
  }
  return out;
}

const pins = {};
for (const file of walk(webroot)) {
  const urlPath = '/' + relative(webroot, file).split(sep).join('/');
  if (urlPath === '/sw.js') {
    continue; // the service worker is never served through itself
  }
  if (urlPath.startsWith('/downloads/')) {
    // The desktop installers are large one-time downloads, never part of the app shell. Pinning them
    // would put hundreds of megabytes into the precache and make every deploy re-fetch them.
    continue;
  }
  pins[urlPath] = createHash('sha256').update(readFileSync(file)).digest('hex');
}
// Pin the bare document path too, since a navigation to "/" returns index.html.
if (pins['/index.html'] !== undefined) {
  pins['/'] = pins['/index.html'];
}

const placeholder = 'const PINNED_ASSETS = {};';
const src = readFileSync(swSrc, 'utf8');
if (!src.includes(placeholder)) {
  console.error('could not find PINNED_ASSETS placeholder in', swSrc);
  process.exit(1);
}
// The cache name embeds a hash of the pin set, so each build installs into its OWN cache and the
// old→new swap is atomic at activate (a failed install can never poison the serving cache).
const manifestJson = JSON.stringify(pins, null, 2);
const cachePlaceholder = "const CACHE = 'deaddrop-pinned-MANIFEST';";
if (!src.includes(cachePlaceholder)) {
  console.error('could not find CACHE placeholder in', swSrc);
  process.exit(1);
}
const version = createHash('sha256').update(manifestJson).digest('hex').slice(0, 16);
const baked = src
  .replace(cachePlaceholder, `const CACHE = 'deaddrop-pinned-${version}';`)
  .replace(placeholder, `const PINNED_ASSETS = ${manifestJson};`);
writeFileSync(join(webroot, 'sw.js'), baked);

// The BUILD HASH: one value covering every pinned asset in this web root. honest-limits tells users to
// verify the published build hash before relying on the app, so the build has to actually publish one.
// Written into the web root (served, so a user can read what their browser is running) and echoed here
// for the release notes. It deliberately excludes /downloads and sw.js itself, exactly like the pin set.
const fullHash = createHash('sha256').update(manifestJson).digest('hex');
writeFileSync(
  join(webroot, 'build.txt'),
  `DEAD DROP build\nassets: ${Object.keys(pins).length}\nbuild-hash: ${fullHash}\ncache: deaddrop-pinned-${version}\n`,
);
console.log(`pinned ${Object.keys(pins).length} assets into ${join(webroot, 'sw.js')} (cache deaddrop-pinned-${version})`);
console.log(`BUILD HASH ${fullHash}`);
