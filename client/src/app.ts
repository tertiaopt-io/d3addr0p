/**
 * App shell renderer (M5): renders the transmit screen using the `.dd` skin (skin/transmit.css).
 * This is the single source of the transmit markup; index.html mounts it. The broader app screens
 * (conversation list, handshake, unlock) build on this shell once their reference UI is provided.
 *
 * SECURITY: message text is decrypted peer content (attacker-influenced), so every dynamic string
 * is HTML-escaped before it reaches innerHTML. Never interpolate raw content into the markup.
 */

import type { Lifetime } from './index.js';
import { substituteSpecials } from './specials.js';
import { requestPersistentStorage } from './persist.js';
import { qrSvg } from './qr.js';
import { normalizeUsername, deriveAuthSecret } from './auth.js';
import type { AccountClient, DeviceInfo } from './auth.js';
import type { DeviceTarget } from './groupchannel.js';
import { FileTransfer, BlobSink, type FileSink, type RtcFactory } from './filetransfer.js';
import {
  CallSession,
  type CallState,
  type GetUserMedia,
  type MediaStreamLike,
  type RtcMediaFactory,
} from './callsession.js';

export type LogEntry =
  | { readonly kind: 'system'; readonly text: string }
  | {
      readonly kind: 'message';
      readonly sender: string;
      readonly text: string;
      readonly lifetime: Lifetime;
      readonly remainingSeconds: number | null; // live countdown for a duration/burn message
      // Absolute expiry (epoch ms) for an ARMED duration message, so the client can tick the countdown
      // live every second without a re-fetch (see the burn ticker). null/absent for an unarmed message
      // (its countdown has not started), a burn-on-read, or an until-revoked message.
      readonly expiresAtMs?: number | null;
      readonly messageId?: string; // the keyvault id, so a per-message action (revoke) can target it
      readonly canRevoke?: boolean; // our account's until-revoked message (any of our devices): show its revoke control
    }
  | { readonly kind: 'destroyed' };

export interface TransmitModel {
  readonly secure: boolean;
  readonly peer: string | null; // null until a conversation is open
  readonly fingerprint: string | null; // verified key fingerprint (sealed-sender recognition)
  readonly log: readonly LogEntry[];
  readonly compose: string;
  readonly conversationId: string | null; // the live conversation this view drives, when any
  readonly selfNote?: boolean; // the Note to Self view (own-devices self-group): hide peer-only controls
  // Self-group split diagnostic shown beside the group id: "<n> devices · W<seen>/<joined> · <error>".
  readonly selfDiag?: string;
  readonly peerHandle?: string | null; // the buddy handle this conversation was tagged with, when known
  readonly peerIsBuddy?: boolean; // whether that handle is already on the buddy list (hides Add Buddy)
  readonly verifyState?: BuddyVerifyInfo['state']; // contact verification for this conversation's peer
}

const HTML_ESCAPES: Record<string, string> = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;',
};

export function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => HTML_ESCAPES[c] ?? c);
}

/** AIM-style text emoticons, longest patterns first so ':-)' wins over ':)'. */
const EMOTICONS: ReadonlyArray<readonly [string, string]> = [
  [':-)', '🙂'], [':)', '🙂'], [':-(', '🙁'], [':(', '🙁'],
  [';-)', '😉'], [';)', '😉'], [':-D', '😀'], [':D', '😀'],
  [':-P', '😛'], [':P', '😛'], [":'(", '😢'], ['<3', '❤️'],
  [':-O', '😮'], [':O', '😮'], ['B-)', '😎'], [':-/', '😕'],
];

// Rich-text palettes. ALL formatting renders WITHOUT inline styles, because the production CSP is
// `style-src 'self'` (no inline styles): text color/size/font become <font color/size/face> attributes
// (CSP-safe), highlight becomes a CSS class (.dd-hl-K), and bold/italic/underline are <strong>/<em>/<u>.
// The values are fixed palettes, so the output is always a small known set, never attacker-controlled CSS.
export const RT_TEXT_COLORS: ReadonlyArray<{ readonly k: string; readonly hex: string }> = [
  { k: 'wh', hex: '#ffffff' }, { k: 'sl', hex: '#c8ccd8' }, { k: 'gy', hex: '#9aa0b0' },
  { k: 'dg', hex: '#555a68' }, { k: 'bk', hex: '#000000' }, { k: 'rd', hex: '#e0504a' },
  { k: 'mr', hex: '#a02828' }, { k: 'or', hex: '#e0883b' }, { k: 'br', hex: '#8a5a2b' },
  { k: 'yl', hex: '#e8c84a' }, { k: 'gd', hex: '#d4af37' }, { k: 'lm', hex: '#a8e05a' },
  { k: 'gn', hex: '#54c878' }, { k: 'tl', hex: '#1f9d8e' }, { k: 'cy', hex: '#48c0d0' },
  { k: 'bl', hex: '#5a9be0' }, { k: 'nv', hex: '#3a55b0' }, { k: 'pu', hex: '#b07ad0' },
  { k: 'mg', hex: '#d04ad0' }, { k: 'pk', hex: '#e088c0' },
];
// Highlight (text-background) swatches MIRROR the text-color palette (same keys + hexes), so the
// background chooser offers exactly the options the text-color chooser does. Each renders as a
// .dd-hl-K class (a coloured background with a legible ink). Legacy single-letter highlight markers
// (an earlier 12-swatch set) still parse and render for text saved before this switch.
export const RT_HL_COLORS: ReadonlyArray<{ readonly k: string; readonly hex: string }> = RT_TEXT_COLORS;
const LEGACY_HL_KEYS: readonly string[] = ['y', 'o', 'r', 'k', 'm', 'p', 'b', 'c', 'g', 's', 'w', 'd'];
// Professional through wacky, all web-safe stacks (no downloaded fonts: font-src stays 'self' and we
// ship none). A platform missing a face falls through the stack; the generic at the end keeps the vibe.
export const RT_FONTS: ReadonlyArray<{ readonly k: string; readonly label: string; readonly face: string }> = [
  { k: 'h', label: 'Helvetica', face: '"Helvetica Neue", Helvetica, Arial, sans-serif' },
  { k: 'v', label: 'Verdana', face: 'Verdana, Geneva, sans-serif' },
  { k: 'b', label: 'Trebuchet', face: '"Trebuchet MS", "Lucida Grande", sans-serif' },
  { k: 's', label: 'Serif', face: 'Georgia, "Times New Roman", serif' },
  { k: 'g', label: 'Garamond', face: 'Garamond, "Apple Garamond", "Palatino Linotype", serif' },
  { k: 'd', label: 'Didot', face: 'Didot, "Bodoni MT", "Times New Roman", serif' },
  { k: 'k', label: 'Baskerville', face: 'Baskerville, "Palatino Linotype", Palatino, serif' },
  { k: 'n', label: 'Rockwell', face: 'Rockwell, "Courier Bold", "Courier New", serif' },
  { k: 'm', label: 'Mono', face: '"Courier New", monospace' },
  { k: 't', label: 'Typewriter', face: '"American Typewriter", "Courier New", monospace' },
  { k: 'f', label: 'Futura', face: 'Futura, "Century Gothic", "Trebuchet MS", sans-serif' },
  { k: 'w', label: 'Wide', face: '"Arial Black", Impact, sans-serif' },
  { k: 'o', label: 'Copperplate', face: 'Copperplate, "Copperplate Gothic Light", fantasy' },
  { k: 'r', label: 'Round', face: '"Comic Sans MS", "Comic Sans", cursive' },
  { k: 'c', label: 'Chalkboard', face: '"Chalkboard SE", Chalkboard, "Comic Sans MS", cursive' },
  { k: 'y', label: 'Marker', face: '"Marker Felt", "Comic Sans MS", cursive' },
  { k: 'u', label: 'Script', face: '"Snell Roundhand", "Brush Script MT", cursive' },
  { k: 'p', label: 'Papyrus', face: 'Papyrus, fantasy' },
  // A fuller bench of web-safe system faces so the list scrolls. Two-letter keys keep the single-letter
  // ones above valid for text already saved. Any face a platform lacks falls through its stack.
  { k: 'ti', label: 'Times', face: '"Times New Roman", Times, serif' },
  { k: 'pa', label: 'Palatino', face: 'Palatino, "Palatino Linotype", "Book Antiqua", serif' },
  { k: 'bo', label: 'Bookman', face: '"Bookman Old Style", "URW Bookman L", serif' },
  { k: 'ce', label: 'Century Gothic', face: '"Century Gothic", "URW Gothic L", sans-serif' },
  { k: 'gi', label: 'Gill Sans', face: '"Gill Sans", "Gill Sans MT", Calibri, sans-serif' },
  { k: 'op', label: 'Optima', face: 'Optima, "Segoe UI", Candara, sans-serif' },
  { k: 'ta', label: 'Tahoma', face: 'Tahoma, Geneva, sans-serif' },
  { k: 'se', label: 'Segoe', face: '"Segoe UI", Segoe, Tahoma, sans-serif' },
  { k: 'ca', label: 'Calibri', face: 'Calibri, Candara, "Segoe UI", sans-serif' },
  { k: 'cm', label: 'Cambria', face: 'Cambria, Georgia, serif' },
  { k: 'co', label: 'Consolas', face: 'Consolas, "Lucida Console", monospace' },
  { k: 'lu', label: 'Lucida', face: '"Lucida Sans", "Lucida Grande", sans-serif' },
  { k: 'mo', label: 'Monaco', face: 'Monaco, Menlo, "Lucida Console", monospace' },
  { k: 'me', label: 'Menlo', face: 'Menlo, Monaco, monospace' },
  { k: 'im', label: 'Impact', face: 'Impact, Haettenschweiler, "Arial Narrow", sans-serif' },
  { k: 'fr', label: 'Franklin', face: '"Franklin Gothic Medium", "Arial Narrow", sans-serif' },
  { k: 'an', label: 'Arial Narrow', face: '"Arial Narrow", Arial, sans-serif' },
  { k: 'ho', label: 'Hoefler', face: '"Hoefler Text", Georgia, serif' },
  { k: 'ch', label: 'Cochin', face: 'Cochin, Georgia, serif' },
  { k: 'bc', label: 'Big Caslon', face: '"Big Caslon", "Book Antiqua", serif' },
  { k: 'ac', label: 'Chancery', face: '"Apple Chancery", "Snell Roundhand", cursive' },
  { k: 'za', label: 'Zapfino', face: 'Zapfino, "Snell Roundhand", cursive' },
  { k: 'bh', label: 'Bradley Hand', face: '"Bradley Hand", "Comic Sans MS", cursive' },
  { k: 'nw', label: 'Noteworthy', face: 'Noteworthy, "Comic Sans MS", cursive' },
  { k: 'he', label: 'Herculanum', face: 'Herculanum, Papyrus, fantasy' },
];
const RT_SIZE = { s: '2', l: '5' } as const; // <font size> for small / large; default (3) carries no marker
const TEXT_KEYS = new Set(RT_TEXT_COLORS.map((c) => c.k));
const HL_KEYS = new Set([...RT_HL_COLORS.map((c) => c.k), ...LEGACY_HL_KEYS]);
const FONT_KEYS = new Set(RT_FONTS.map((f) => f.k));

interface RTOpen {
  readonly type: string;
  readonly openTag: string;
  readonly closeTag: string;
}

/**
 * Render message/profile/away text safely with emoticons and rich formatting. HTML is escaped FIRST, so
 * the ONLY tags that appear are the controlled ones this function emits from a fixed grammar; attacker
 * text cannot inject markup. A stack parser composes nested formatting and rebalances improper nesting,
 * so the output is always well-formed. Markers: `*bold*`, `_italic_`, `[u]..[/u]` underline,
 * `[c#hex]..[/c]` color (legacy `[#hex]..[/]` still parses), `[h:k]..[/h]` highlight, `[z:s|l]..[/z]`
 * size, `[f:k]..[/f]` font. Output uses <font color/size/face> attributes + the .dd-hl-k class, never an
 * inline style, so it renders under the strict CSP.
 */
/** A strict data-URL for a raster image the renderer will trust as an <img src>. Only the four raster
 * types we ever produce/accept, base64 only, and NO svg+xml (SVG can carry script). The base64 alphabet
 * has no `]`, `"`, `<`, or `>`, so a marker `[img:<this>]` cannot break out of either the marker or the
 * quoted attribute — the value is safe to drop straight into src without further escaping. */
export const INLINE_IMG_RE = /^data:image\/(?:png|jpe?g|gif|webp);base64,[A-Za-z0-9+/]+={0,2}$/;

// Receive-side caps on an inline image. A message is UNTRUSTED input (from a peer or a possibly-compromised
// own device), so the send-path budget/downscale guarantees do NOT apply. Without a bound a tiny data-URL
// can DECLARE huge dimensions (e.g. a lossless WebP up to 16383×16383 ≈ 1 GB decoded RGBA) and OOM the tab
// when the browser decodes it — a denial-of-availability bomb. So before we ever hand bytes to <img>, we
// cap the compressed size AND parse the header for declared dimensions, refusing to render an oversized one.
const RECV_IMG_MAX_DATAURI = 40 * 1024; // compressed data-URL length ceiling (transport already ~32 KiB)
const RECV_IMG_MAX_DIM = 2048; // max width OR height; our sender caps at 1024, so this leaves headroom

function read32be(b: Uint8Array, o: number): number {
  return ((b[o]! << 24) | (b[o + 1]! << 16) | (b[o + 2]! << 8) | b[o + 3]!) >>> 0;
}

/** Read declared pixel dimensions from a raster image's HEADER bytes (no pixel decode), or null if the
 * bytes are not a recognizable PNG/GIF/JPEG/WebP header. Covers the four types INLINE_IMG_RE admits. */
function imageHeaderDims(b: Uint8Array): { w: number; h: number } | null {
  // PNG: \x89PNG\r\n\x1a\n then IHDR width/height (big-endian) at bytes 16..23.
  if (b.length >= 24 && b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47) {
    return { w: read32be(b, 16), h: read32be(b, 20) };
  }
  // GIF: "GIF8" then logical-screen width/height (little-endian) at bytes 6..9.
  if (b.length >= 10 && b[0] === 0x47 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x38) {
    return { w: b[6]! | (b[7]! << 8), h: b[8]! | (b[9]! << 8) };
  }
  // WebP: RIFF....WEBP then a VP8X / VP8(space) / VP8L chunk.
  if (b.length >= 30 && b[0] === 0x52 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x46 && b[8] === 0x57 && b[9] === 0x45 && b[10] === 0x42 && b[11] === 0x50) {
    const cc = String.fromCharCode(b[12]!, b[13]!, b[14]!, b[15]!);
    if (cc === 'VP8X') {
      return { w: 1 + (b[24]! | (b[25]! << 8) | (b[26]! << 16)), h: 1 + (b[27]! | (b[28]! << 8) | (b[29]! << 16)) };
    }
    if (cc === 'VP8 ') {
      return { w: (b[26]! | (b[27]! << 8)) & 0x3fff, h: (b[28]! | (b[29]! << 8)) & 0x3fff };
    }
    if (cc === 'VP8L' && b[20] === 0x2f) {
      const bits = (b[21]! | (b[22]! << 8) | (b[23]! << 16) | (b[24]! << 24)) >>> 0;
      return { w: (bits & 0x3fff) + 1, h: ((bits >>> 14) & 0x3fff) + 1 };
    }
    return null;
  }
  // JPEG: SOI then scan segments to the first SOF (frame header) marker, which carries height/width.
  if (b.length >= 4 && b[0] === 0xff && b[1] === 0xd8) {
    let i = 2;
    while (i + 9 < b.length) {
      if (b[i] !== 0xff) {
        i++;
        continue;
      }
      const marker = b[i + 1]!;
      if (marker >= 0xc0 && marker <= 0xcf && marker !== 0xc4 && marker !== 0xc8 && marker !== 0xcc) {
        return { w: (b[i + 7]! << 8) | b[i + 8]!, h: (b[i + 5]! << 8) | b[i + 6]! };
      }
      if (marker === 0xd8 || marker === 0xd9 || (marker >= 0xd0 && marker <= 0xd7)) {
        i += 2; // markers with no length payload
        continue;
      }
      const len = (b[i + 2]! << 8) | b[i + 3]!;
      if (len < 2) {
        return null;
      }
      i += 2 + len;
    }
  }
  return null;
}

/** Whether a validated inline-image data-URL is safe to render: within the compressed-size ceiling, and —
 * if we can read its header — within the decoded-dimension ceiling. A header we cannot parse is allowed
 * (an invalid image just renders broken; the DECODE bomb needs a VALID header, which we do parse). */
function inlineImageAllowed(dataUrl: string): boolean {
  if (dataUrl.length > RECV_IMG_MAX_DATAURI) {
    return false;
  }
  const comma = dataUrl.indexOf(',');
  if (comma < 0) {
    return false;
  }
  let dims: { w: number; h: number } | null = null;
  try {
    // The data-URL passed the byte-length ceiling above, so the decoded bytes are small (~≤30 KiB): decode
    // them all so a JPEG whose SOF marker sits behind padded APP segments is still found (PNG/GIF/WebP put
    // dimensions in the first ~30 bytes regardless).
    const bin = atob(dataUrl.slice(comma + 1));
    const bytes = new Uint8Array(bin.length);
    for (let k = 0; k < bin.length; k++) {
      bytes[k] = bin.charCodeAt(k);
    }
    dims = imageHeaderDims(bytes);
  } catch {
    return true; // cannot base64-decode here (e.g. the test DOM lacks atob): the format regex already ran
  }
  if (dims === null) {
    return true; // unrecognized header: not a valid image, so no decode bomb to fear
  }
  return dims.w > 0 && dims.h > 0 && dims.w <= RECV_IMG_MAX_DIM && dims.h <= RECV_IMG_MAX_DIM;
}

export function formatMessageText(text: string, opts: { images?: boolean } = {}): string {
  let out = '';
  const stack: RTOpen[] = [];
  let buf = '';
  const flush = (): void => {
    if (buf.length === 0) {
      return;
    }
    let t = escapeHtml(buf);
    for (const [from, to] of EMOTICONS) {
      t = t.split(escapeHtml(from)).join(to);
    }
    out += t;
    buf = '';
  };
  const openFmt = (o: RTOpen): void => {
    flush();
    out += o.openTag;
    stack.push(o);
  };
  const closeType = (type: string): void => {
    flush();
    const idx = stack.map((s) => s.type).lastIndexOf(type);
    if (idx === -1) {
      return; // unmatched close: ignore (output stays well-formed)
    }
    const above = stack.slice(idx + 1);
    for (let j = stack.length - 1; j >= idx; j--) {
      out += stack[j]!.closeTag; // close from the top down to (and including) the match
    }
    stack.length = idx;
    for (const a of above) {
      out += a.openTag; // reopen the formats that were nested above the one we closed
      stack.push(a);
    }
  };
  const toggle = (o: RTOpen): void => {
    if (stack.some((s) => s.type === o.type)) {
      closeType(o.type);
    } else {
      openFmt(o);
    }
  };
  let i = 0;
  while (i < text.length) {
    const c = text[i]!;
    if (c === '\\' && i + 1 < text.length) {
      buf += text[i + 1]!; // a backslash escapes the next character so a literal * _ [ is not a marker
      i += 2;
      continue;
    }
    if (c === '*') {
      toggle({ type: 'b', openTag: '<strong>', closeTag: '</strong>' });
      i += 1;
      continue;
    }
    if (c === '_') {
      toggle({ type: 'i', openTag: '<em>', closeTag: '</em>' });
      i += 1;
      continue;
    }
    if (c === '[') {
      const rest = text.slice(i);
      let m: RegExpMatchArray | null;
      // An inline image marker: rendered ONLY where images are allowed (chat messages + the compose
      // editor that seeds from them), never in profile/away text. The captured data-URL is re-validated
      // against the strict raster whitelist, so a crafted `[img:...]` from a peer cannot inject anything
      // but a bounded data: image (CSP already restricts img-src to 'self' data:). flush() first so the
      // image lands in reading order relative to the surrounding text.
      if (opts.images === true && (m = rest.match(/^\[img:(data:image\/(?:png|jpe?g|gif|webp);base64,[A-Za-z0-9+/]+={0,2})\]/)) && INLINE_IMG_RE.test(m[1]!)) {
        flush();
        // Refuse to render an image whose compressed size or DECLARED dimensions exceed the receive caps —
        // an untrusted message can otherwise ship a tiny data-URL that decodes to a tab-crashing bitmap.
        out += inlineImageAllowed(m[1]!)
          ? `<img class="dd-img" src="${m[1]}" alt="shared image" decoding="async" />`
          : '<span class="dd-img-blocked">▢ image too large</span>';
        i += m[0].length;
        continue;
      }
      // A close token is consumed only when its format is actually open; otherwise it stays literal text
      // (so an invalid marker like `[#zz]x[/]` is left exactly as typed).
      if ((m = rest.match(/^\[\/(u|c|h|z|f)\]/)) && stack.some((s) => s.type === m![1])) {
        closeType(m[1]!);
        i += m[0].length;
        continue;
      }
      if (rest.startsWith('[/]') && stack.some((s) => s.type === 'c')) {
        closeType('c'); // legacy color closer
        i += 3;
        continue;
      }
      if (rest.startsWith('[u]')) {
        openFmt({ type: 'u', openTag: '<u>', closeTag: '</u>' });
        i += 3;
        continue;
      }
      if ((m = rest.match(/^\[c:([a-z]{2})\]/)) && TEXT_KEYS.has(m[1]!)) {
        openFmt({ type: 'c', openTag: `<span class="dd-c-${m[1]}">`, closeTag: '</span>' });
        i += m[0].length;
        continue;
      }
      if ((m = rest.match(/^\[c?#([0-9a-fA-F]{6}|[0-9a-fA-F]{3})\]/))) {
        // Legacy color marker (a raw hex): kept for text saved before the palette switch. Renders as a
        // CSP-safe <font color> attribute (never an inline style).
        openFmt({ type: 'c', openTag: `<font color="#${m[1]}">`, closeTag: '</font>' });
        i += m[0].length;
        continue;
      }
      if ((m = rest.match(/^\[h:([a-z]{1,2})\]/)) && HL_KEYS.has(m[1]!)) {
        openFmt({ type: 'h', openTag: `<span class="dd-hl-${m[1]}">`, closeTag: '</span>' });
        i += m[0].length;
        continue;
      }
      if ((m = rest.match(/^\[z:(s|l|[1-7])\]/))) {
        // Size is a 7-level scale: 4 is the normal baseline, 1-3 the three smaller steps, 5-7 the three
        // larger. Legacy `s`/`l` (the old two-level markers) still parse, mapping onto the same scale.
        const g = m[1]!;
        const sz = g === 's' ? RT_SIZE.s : g === 'l' ? RT_SIZE.l : g;
        openFmt({ type: 'z', openTag: `<font size="${sz}">`, closeTag: '</font>' });
        i += m[0].length;
        continue;
      }
      if ((m = rest.match(/^\[f:([a-z]{1,2})\]/)) && FONT_KEYS.has(m[1]!)) {
        openFmt({ type: 'f', openTag: `<span class="dd-ft-${m[1]}">`, closeTag: '</span>' });
        i += m[0].length;
        continue;
      }
    }
    buf += c;
    i += 1;
  }
  flush();
  while (stack.length > 0) {
    out += stack.pop()!.closeTag; // auto-close anything left open so the HTML is always balanced
  }
  return out;
}

/** Escape the characters that would otherwise be read as markers, so a literal one a user typed survives. */
function escMarker(s: string): string {
  return s.replace(/[\\*_[]/g, (ch) => `\\${ch}`);
}

/** The open/close rich-text marker pairs a MessageLook expands to, outer→inner. Only validated palette
 * keys reach the markers, so the output is always a small known grammar (never attacker-controlled). */
function messageLookParts(look: MessageLook): ReadonlyArray<readonly [string, string]> {
  const parts: Array<readonly [string, string]> = [];
  if (look.font !== undefined && FONT_KEYS.has(look.font)) {
    parts.push([`[f:${look.font}]`, '[/f]']);
  }
  if (look.color !== undefined && TEXT_KEYS.has(look.color)) {
    parts.push([`[c:${look.color}]`, '[/c]']);
  }
  if (look.hl !== undefined && HL_KEYS.has(look.hl)) {
    parts.push([`[h:${look.hl}]`, '[/h]']);
  }
  if (look.size === 's' || look.size === 'l') {
    parts.push([`[z:${look.size}]`, '[/z]']);
  }
  return parts;
}

/** Apply the default outgoing-message look to composed marker text (AIM24): wrap it in the look's markers
 * so peers render it in that font/color/size/highlight. These are open/close markers, so any formatting the
 * sender applied inline nests inside and overrides per run (the stack parser in formatMessageText balances
 * it). A message with no look, or an empty look, is returned unchanged. */
export function wrapMessageLook(look: MessageLook | undefined, markers: string): string {
  if (look === undefined) {
    return markers;
  }
  const parts = messageLookParts(look);
  if (parts.length === 0) {
    return markers;
  }
  const open = parts.map((p) => p[0]).join('');
  const close = parts
    .slice()
    .reverse()
    .map((p) => p[1])
    .join('');
  return open + markers + close;
}

/** Coerce an untrusted value into a safe MessageLook (device-local store read), or undefined when empty.
 * Every field is checked against its palette allowlist, mirroring sanitizeAppearance for the tokens. */
export function sanitizeMessageLook(raw: unknown): MessageLook | undefined {
  if (raw === null || typeof raw !== 'object') {
    return undefined;
  }
  const o = raw as { font?: unknown; color?: unknown; size?: unknown; hl?: unknown };
  const look: { font?: string; color?: string; size?: 's' | 'l'; hl?: string } = {};
  if (typeof o.font === 'string' && FONT_KEYS.has(o.font)) {
    look.font = o.font;
  }
  if (typeof o.color === 'string' && TEXT_KEYS.has(o.color)) {
    look.color = o.color;
  }
  if (o.size === 's' || o.size === 'l') {
    look.size = o.size;
  }
  if (typeof o.hl === 'string' && HL_KEYS.has(o.hl)) {
    look.hl = o.hl;
  }
  return Object.keys(look).length > 0 ? look : undefined;
}

/** Normalize a <font color> value (a #hex, bare hex, or rgb(...)) to a 3/6-digit hex, or null if unusable. */
function colorToHex(c: string): string | null {
  const s = c.trim();
  let m = s.match(/^#?([0-9a-fA-F]{6})$/) ?? s.match(/^#?([0-9a-fA-F]{3})$/);
  if (m !== null) {
    return m[1]!;
  }
  m = s.match(/^rgb\(\s*(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*(\d{1,3})\s*\)$/);
  if (m !== null) {
    const h = (n: string): string => Math.max(0, Math.min(255, parseInt(n, 10))).toString(16).padStart(2, '0');
    return h(m[1]!) + h(m[2]!) + h(m[3]!);
  }
  return null;
}

/**
 * Serialize a contenteditable's DOM into the safe marker text the app stores, syncs, and renders (the
 * inverse of formatMessageText). The editor applies formatting as <b>/<i>/<u>, <font size>, and the
 * dd-c-/dd-hl-/dd-ft- classes; this walks that tree and emits the matching markers, backslash-escaping
 * literal marker characters so they round-trip. Unknown elements contribute only their text, so nothing
 * outside the known grammar ever reaches storage.
 */
export function serializeRichText(node: Node): string {
  let out = '';
  node.childNodes.forEach((child) => {
    if (child.nodeType === 3) {
      // Strip any zero-width space (U+200B): it is only the caret-holder a color/highlight/font pick with
      // no selection leaves inside its otherwise-empty run, never text the user meant to store or send.
      out += escMarker((child.textContent ?? '').replace(/\u200b/g, ''));
      return;
    }
    if (child.nodeType !== 1) {
      return;
    }
    const el = child as HTMLElement;
    const tag = el.tagName.toLowerCase();
    if (tag === 'br') {
      out += '\n';
      return;
    }
    if (tag === 'img') {
      // An inline image: emit the [img:] marker ONLY for a trusted raster data-URL (the kind we create on
      // insert/paste). An external or unknown <img src> (e.g. a tracker pasted in from rich HTML) carries
      // nothing — never store or send it. The base64 has no marker/attribute-breaking chars, so it needs
      // no escaping.
      const src = el.getAttribute('src') ?? '';
      if (INLINE_IMG_RE.test(src)) {
        out += `[img:${src}]`;
      }
      return;
    }
    const inner = serializeRichText(el);
    // An inline formatting run that ended up empty (e.g. an untouched B/I/U/color/font caret-holder the
    // user opened but never typed into) carries nothing: emit no markers, so it cannot serialize to a
    // non-empty string like `**` that would slip past the send-empty guard as a blank bubble.
    const inlineFmt =
      tag === 'b' || tag === 'strong' || tag === 'i' || tag === 'em' || tag === 'u' || tag === 'font' || tag === 'span';
    if (inlineFmt && inner === '') {
      return;
    }
    if (tag === 'b' || tag === 'strong') {
      out += `*${inner}*`;
    } else if (tag === 'i' || tag === 'em') {
      out += `_${inner}_`;
    } else if (tag === 'u') {
      out += `[u]${inner}[/u]`;
    } else if (tag === 'font') {
      const size = el.getAttribute('size');
      const color = el.getAttribute('color');
      if (size !== null) {
        const n = parseInt(size, 10);
        // Font size 4 is the normal baseline (carries no marker); 1-3 and 5-7 each round-trip as [z:N] so
        // the exact step the sender picked survives, not just "small" or "large".
        out += n >= 1 && n <= 7 && n !== 4 ? `[z:${n}]${inner}[/z]` : inner;
      } else if (color !== null) {
        const hex = colorToHex(color);
        out += hex !== null ? `[c#${hex}]${inner}[/c]` : inner;
      } else {
        out += inner;
      }
    } else if (tag === 'span') {
      const cls = Array.from(el.classList);
      const ck = cls.find((c) => c.startsWith('dd-c-'))?.slice(5);
      const hk = cls.find((c) => c.startsWith('dd-hl-'))?.slice(6);
      const fk = cls.find((c) => c.startsWith('dd-ft-'))?.slice(6);
      if (ck !== undefined && TEXT_KEYS.has(ck)) {
        out += `[c:${ck}]${inner}[/c]`;
      } else if (hk !== undefined && HL_KEYS.has(hk)) {
        out += `[h:${hk}]${inner}[/h]`;
      } else if (fk !== undefined && FONT_KEYS.has(fk)) {
        out += `[f:${fk}]${inner}[/f]`;
      } else {
        out += inner;
      }
    } else if (tag === 'div' || tag === 'p') {
      // contenteditable wraps later lines in a block element: treat the boundary as a newline.
      if (out.length > 0 && !out.endsWith('\n')) {
        out += '\n';
      }
      out += inner;
    } else {
      out += inner; // unknown element: keep only its text content
    }
  });
  return out;
}

// --- inline images (AIM16): a small image rides INSIDE the encrypted message as an [img:data-url] marker,
// so it is E2E, works offline/async like text, echoes to your own log, and reaches Note to Self / your
// own devices over the same rails as text. It is downscaled + recompressed client-side to fit one padding
// bucket; larger originals go over the P2P file path instead (peers) or are shrunk harder (Note to Self,
// which has no peer). CSP already permits img-src 'self' data:, so no server change is needed. ---

/** Cap on one inline image's data-URL (bytes; base64 is ASCII), kept well under the 32 KiB padding bucket
 * so the image + any accompanying text still fits with framing/overhead to spare. */
const INLINE_IMG_MAX_DATAURI = 28 * 1024;
/** Cap on a whole outgoing message (text + image markers) in UTF-8 bytes, so the padded ciphertext lands
 * in the 32 KiB bucket the gateway accepts; the next bucket up (256 KiB) is rejected as oversize. */
const MESSAGE_BYTES_MAX = 31 * 1024;
/** Refuse to even decode an absurdly large source file before it can blow up canvas memory. */
const IMG_SOURCE_BYTES_MAX = 25 * 1024 * 1024;

/** UTF-8 byte length of a string (what the transport actually pads + encrypts). */
function utf8Bytes(s: string): number {
  return new TextEncoder().encode(s).length;
}

let webpEncodeOk: boolean | null = null;
/** Whether this browser can ENCODE WebP via canvas (Chrome/Firefox/modern Safari yes; older Safari falls
 * back to PNG, which we detect and avoid by using JPEG there). Every target can DECODE WebP either way. */
function canEncodeWebp(): boolean {
  if (webpEncodeOk === null) {
    try {
      const c = document.createElement('canvas');
      c.width = 1;
      c.height = 1;
      webpEncodeOk = c.toDataURL('image/webp').startsWith('data:image/webp');
    } catch {
      webpEncodeOk = false;
    }
  }
  return webpEncodeOk;
}

interface DecodedImage {
  readonly width: number;
  readonly height: number;
  readonly draw: (ctx: CanvasRenderingContext2D, w: number, h: number) => void;
}

/** Decode an image file to something drawable, preferring createImageBitmap and falling back to an <img>. */
async function decodeImage(file: Blob): Promise<DecodedImage | null> {
  try {
    const bmp = await createImageBitmap(file);
    return { width: bmp.width, height: bmp.height, draw: (ctx, w, h) => ctx.drawImage(bmp, 0, 0, w, h) };
  } catch {
    /* createImageBitmap unavailable or failed: fall back to <img> */
  }
  return new Promise((resolve) => {
    const img = new Image();
    const url = URL.createObjectURL(file);
    img.onload = () => {
      URL.revokeObjectURL(url);
      resolve({ width: img.naturalWidth, height: img.naturalHeight, draw: (ctx, w, h) => ctx.drawImage(img, 0, 0, w, h) });
    };
    img.onerror = () => {
      URL.revokeObjectURL(url);
      resolve(null);
    };
    img.src = url;
  });
}

/** Draw the image scaled to fit `maxDim` and return a compressed data-URL (WebP where supported, else JPEG). */
function encodeScaled(src: DecodedImage, maxDim: number, quality: number): string | null {
  const scale = Math.min(1, maxDim / Math.max(src.width, src.height, 1));
  const w = Math.max(1, Math.round(src.width * scale));
  const h = Math.max(1, Math.round(src.height * scale));
  const canvas = document.createElement('canvas');
  canvas.width = w;
  canvas.height = h;
  const ctx = canvas.getContext('2d');
  if (ctx === null) {
    return null;
  }
  const type = canEncodeWebp() ? 'image/webp' : 'image/jpeg';
  if (type === 'image/jpeg') {
    ctx.fillStyle = '#ffffff'; // JPEG has no alpha; flatten transparency onto white so it isn't black
    ctx.fillRect(0, 0, w, h);
  }
  src.draw(ctx, w, h);
  try {
    return canvas.toDataURL(type, quality);
  } catch {
    return null;
  }
}

/** Downscale + recompress an image to a data-URL that fits one inline message, or null if it will not /
 * cannot be decoded. `mode` 'good' only accepts a near-full-size encoding (so a large original that would
 * look bad crushed inline can be sent P2P at full quality instead); 'fit' shrinks harder until it fits,
 * for insert/paste and for Note to Self (which has no peer to fall back to). */
async function prepareInlineImage(file: Blob, mode: 'good' | 'fit'): Promise<string | null> {
  if (file.size > IMG_SOURCE_BYTES_MAX) {
    return null;
  }
  const src = await decodeImage(file);
  if (src === null) {
    return null;
  }
  const goodSteps: ReadonlyArray<readonly [number, number]> = [
    [1024, 0.85],
    [1024, 0.72],
    [1024, 0.6],
    [896, 0.6],
    [768, 0.6],
  ];
  const fitSteps: ReadonlyArray<readonly [number, number]> = [
    [640, 0.55],
    [512, 0.52],
    [448, 0.5],
    [384, 0.48],
    [320, 0.45],
  ];
  const steps = mode === 'good' ? goodSteps : [...goodSteps, ...fitSteps];
  for (const [dim, q] of steps) {
    const uri = encodeScaled(src, dim, q);
    if (uri !== null && INLINE_IMG_RE.test(uri) && uri.length <= INLINE_IMG_MAX_DATAURI) {
      return uri;
    }
  }
  return null;
}

/** Insert a prepared inline-image data-URL into a compose editor at the caret (or at the end if the caret
 * is not inside it), then fire `input` so the placeholder/height logic updates. */
/** Insert an image into the compose at the right spot. `at` is the caret CAPTURED BEFORE a file dialog
 * opened (the dialog clears the selection, and a later editor.focus() would mint a NEW caret at offset 0 —
 * which used to drop the image IN FRONT of everything already typed). Order matters: resolve the insertion
 * range FIRST, then insert, then focus — focus() clobbers the selection state being read. Fallbacks: a live
 * in-editor selection (the paste path, where it is trustworthy), else append at the END, which is what a
 * typist expects. */
function insertInlineImage(editor: HTMLElement, dataUri: string, at?: Range | null): void {
  const img = document.createElement('img');
  img.className = 'dd-img';
  img.src = dataUri;
  img.alt = 'shared image';
  const sel = window.getSelection();
  let range: Range;
  if (at != null && editor.contains(at.startContainer)) {
    range = at; // the caret from before the dialog (guarded: a re-render may have detached it)
    range.deleteContents();
  } else if (sel !== null && sel.rangeCount > 0 && editor.contains(sel.getRangeAt(0).commonAncestorContainer)) {
    range = sel.getRangeAt(0);
    range.deleteContents();
  } else {
    range = document.createRange();
    range.selectNodeContents(editor);
    range.collapse(false); // no usable caret: AFTER the typed text, never in front of it
  }
  range.insertNode(img);
  editor.focus();
  const after = document.createRange();
  after.setStartAfter(img);
  after.collapse(true);
  if (sel !== null) {
    sel.removeAllRanges();
    sel.addRange(after);
  }
  editor.dispatchEvent(new Event('input', { bubbles: true }));
}

const KEY_PACKAGE_COUNT = 6; // one-time packages to publish, plus the last one as last-resort
const EXCLUDE_DEVICE_TIMEOUT_MS = 10_000; // cap the self-revoke exclusion so a hung worker RPC cannot block the crypto-erase
const ENROLL_RETRY_COPY =
  'This device is authorized but could not be registered with the account server. Check your connection and try again.';
const RECOVERY_ENROLL_RETRY_COPY =
  'Recovery succeeded but this device could not be registered with the account server. Check your connection and try again.';

function hexToBytesLocal(h: string): Uint8Array {
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function clock(totalSeconds: number): string {
  const m = Math.floor(totalSeconds / 60);
  const s = totalSeconds % 60;
  return `${m}:${s < 10 ? `0${s}` : s}`;
}

/** The slice of the File System Access save handle we use to stream a received file to disk. */
interface SaveHandleLike {
  createWritable(): Promise<{ write(data: Uint8Array): Promise<void>; close(): Promise<void> }>;
}

function formatBytes(n: number): string {
  if (n < 1024) {
    return `${n} B`;
  }
  const units = ['KB', 'MB', 'GB', 'TB'];
  let value = n / 1024;
  let i = 0;
  while (value >= 1024 && i < units.length - 1) {
    value /= 1024;
    i += 1;
  }
  return `${value < 10 ? value.toFixed(1) : Math.round(value)} ${units[i]}`;
}

function renderEntry(e: LogEntry): string {
  if (e.kind === 'system') {
    return `<div class="dd-msg dd-sys">${escapeHtml(e.text)}</div>`;
  }
  if (e.kind === 'destroyed') {
    return '<div class="dd-gone">▢ message destroyed</div>';
  }
  const near = e.remainingSeconds !== null && e.remainingSeconds <= 10;
  const warn = near ? ' dd-warn' : '';
  const burn =
    e.remainingSeconds !== null
      ? `burns ${clock(e.remainingSeconds)}`
      : e.lifetime.kind === 'burn-on-read'
        ? 'burns after this viewing'
        : e.lifetime.kind === 'until-revoked'
          ? 'kept until revoked'
          : '';
  // Our own until-revoked message carries its recall control (cooperative revoke: every member
  // device destroys its stored copy; it cannot recall a copy someone already captured).
  const revoke =
    e.canRevoke === true && typeof e.messageId === 'string'
      ? `<button type="button" class="dd-msg-revoke" data-action="revoke-msg" data-mid="${escapeHtml(e.messageId)}" title="destroy the stored copy on every device">revoke</button>`
      : '';
  // The ephemeral markers (burn countdown / recall control) trail the line quietly so DEAD DROP's
  // disappearing-message controls stay visible without breaking the classic AIM "Name: message" line.
  // An armed duration message stamps its absolute expiry so the burn ticker can update the countdown
  // live every second (targeted DOM update, no re-render); other kinds carry no expiry and never tick.
  const hasExpiry = typeof e.expiresAtMs === 'number' && e.remainingSeconds !== null;
  const burnSpan =
    burn !== '' ? `<span class="dd-burn"${hasExpiry ? ` data-expires-at="${e.expiresAtMs}"` : ''}>${burn}</span>` : '';
  const meta =
    burnSpan !== '' || revoke !== ''
      ? `<span class="dd-meta${near ? ' dd-warn dd-near' : ''}">${burnSpan}${revoke}</span>`
      : '';
  // AIM-style inline line: the sender's name (yours one color, theirs another) then the message on
  // the same line. Own messages are labelled 'YOU' by the controller, so the color follows that.
  const self = e.sender === 'YOU';
  return (
    `<div class="dd-line${warn}">` +
    `<span class="dd-name ${self ? 'dd-name-self' : 'dd-name-peer'}">${escapeHtml(e.sender)}:</span> ` +
    `<span class="dd-msg${warn}">${formatMessageText(e.text, { images: true })}</span>` +
    meta +
    `</div>`
  );
}

export function renderTransmit(m: TransmitModel): string {
  // Bind the compose toolbar's ⏳ pick to THIS conversation (see composeLifetimes).
  composeConvId = m.conversationId ?? '';
  const secure = m.secure
    ? '<span class="dd-tx"></span>SECURE'
    : 'OFFLINE';
  // Note to Self carries none of the peer controls: there is no one to view, call, or block, and adding
  // anyone is deliberately impossible so a peer can never be injected into the own-devices self-group
  // (that would turn it into a mixed group and leak the buddy list on the next sync). Just a quiet
  // subtitle. A peer conversation keeps the name + key line here; the actions live in the bottom
  // toolbar (renderImToolbar), AIM-style.
  // DIAGNOSTIC (self-group split): show WHICH own-devices group this window is using. Notes stopped
  // crossing between devices and the deciding question — one shared group with broken delivery, or two
  // separate groups — is answerable only from device-local MLS state, which the keyless gateway cannot
  // show and Chrome/iOS has no console to print. Putting the id on screen makes it comparable by eye:
  // SAME id on both devices means one group (a delivery problem), DIFFERENT ids means they are split
  // (a formation/selection problem). The group id is not a secret (the server routes on its mailbox).
  // The id alone cannot say WHICH device minted the group; roster size can (a populated self-group
  // lists both devices, a solo one lists a single device), and the W<seen>/<joined> counters say what
  // an arriving Welcome actually did. Compare the whole line across devices by eye.
  const selfTag = (m.conversationId ?? '').replace(/^c-/, '').slice(0, 8);
  const selfDiag = (m.selfDiag ?? '').trim();
  const sub = m.selfNote === true
    ? `<div class="dd-sub"><span>${escapeHtml(m.peer ?? 'Note to Self')}</span><span>only your devices see this${
        selfTag !== '' ? ` &middot; group ${escapeHtml(selfTag)}` : ''
      }${selfDiag !== '' ? ` &middot; ${escapeHtml(selfDiag)}` : ''}</span></div>`
    : m.peer !== null
      ? `<div class="dd-sub"><span>${escapeHtml(m.peer)}</span><span>${
          m.fingerprint !== null ? `key ${escapeHtml(m.fingerprint)} &middot; verified` : 'unverified'
        }</span></div>`
      : '';
  const fileInput = m.secure ? '<input type="file" id="dd-file-input" hidden aria-hidden="true" />' : '';
  const compose = m.secure
    ? '<form class="dd-compose dd-compose-rich" id="dd-compose-form">' +
      renderRichEditor('dd-compose-input', m.compose, { placeholder: 'type a message · Enter to send', oneLine: true, timer: true, prompt: true, images: true }) +
      '<button class="dd-btn dd-btn-primary" data-action="send" type="submit">Send</button>' +
      '</form>'
    : '<div class="dd-compose"><span class="dd-prompt">&rsaquo;</span>' +
      `<span class="dd-msg">${formatMessageText(m.compose)}</span><span class="dd-cursor"></span></div>`;
  // The AIM-style icon column left of the log: the other person on top, you below (AIM23). The slots ship
  // empty and wireChatIcons fills them (own + peer identity, both async). Note-to-Self has only you, so it
  // shows a single self icon. No open conversation (peer === null) shows no column.
  const chatIcons =
    m.peer === null
      ? ''
      : m.selfNote === true
        ? `<div class="dd-chat-icons dd-chat-icons-solo" data-dd-chaticons="${escapeHtml(m.conversationId ?? '')}">` +
          '<div class="dd-ci-slot" data-icon-slot="self"></div></div>'
        : `<div class="dd-chat-icons" data-dd-chaticons="${escapeHtml(m.conversationId ?? '')}">` +
          '<div class="dd-ci-slot" data-icon-slot="peer"></div>' +
          '<div class="dd-ci-slot" data-icon-slot="self"></div></div>';
  return (
    '<div class="dd-sweep"></div>' +
    `<div class="dd-bar"><span>DEAD DROP</span><span>${secure}</span></div>` +
    sub +
    // The icon column sits beside the log + its retro scrollbar. The scrollbar rides INSIDE the chat area
    // and actually drives the log (arrows, track paging, thumb drag — wired in wireLogScrollbars); the
    // log's native scrollbar is hidden, so this is the one and only scrollbar.
    '<div class="dd-chatbody">' +
    chatIcons +
    `<div class="dd-logrow"><div class="dd-log">${m.log.map(renderEntry).join('')}</div>${renderScrollbar()}</div>` +
    '</div>' +
    fileInput +
    compose +
    renderImToolbar(m)
  );
}

// IM-toolbar icons (inline SVG, colored via CSS fill; static markup so no escaping needed). They sit at
// the bottom of the chat window like the classic AIM action bar.
const ICO_PROFILE = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm0 2c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4z"/></svg>';
const ICO_ADD_BUDDY = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M15 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zM6 10V7H4v3H1v2h3v3h2v-3h3v-2H6zm9 4c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4z"/></svg>';
const ICO_ATTACH = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M16.5 6v11.5c0 2.21-1.79 4-4 4s-4-1.79-4-4V5a2.5 2.5 0 0 1 5 0v10.5c0 .55-.45 1-1 1s-1-.45-1-1V6H10v9.5a2.5 2.5 0 0 0 5 0V5c0-2.21-1.79-4-4-4S7 2.79 7 5v12.5c0 3.04 2.46 5.5 5.5 5.5s5.5-2.46 5.5-5.5V6h-1.5z"/></svg>';
const ICO_CALL = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M6.62 10.79c1.44 2.83 3.76 5.14 6.59 6.59l2.2-2.2c.27-.27.67-.36 1.02-.24 1.12.37 2.33.57 3.57.57.55 0 1 .45 1 1V20c0 .55-.45 1-1 1-9.39 0-17-7.61-17-17 0-.55.45-1 1-1h3.5c.55 0 1 .45 1 1 0 1.25.2 2.45.57 3.57.11.35.03.74-.25 1.02l-2.2 2.2z"/></svg>';
const ICO_VIDEO = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M17 10.5V7c0-.55-.45-1-1-1H4c-.55 0-1 .45-1 1v10c0 .55.45 1 1 1h12c.55 0 1-.45 1-1v-3.5l4 4v-11l-4 4z"/></svg>';
const ICO_BLOCK = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zM4 12c0-4.42 3.58-8 8-8 1.85 0 3.55.63 4.9 1.69L5.69 16.9A7.9 7.9 0 0 1 4 12zm8 8c-1.85 0-3.55-.63-4.9-1.69L18.31 7.1A7.9 7.9 0 0 1 20 12c0 4.42-3.58 8-8 8z"/></svg>';
const ICO_REMOVE = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z"/></svg>';

/** The AIM-style action bar at the bottom of a conversation: Profile, Add Buddy (only when the peer is
 * known and NOT already a buddy), Attach File, Call, Video, and Block, each an icon button. Note to
 * Self keeps only Attach File — an attached image rides inline as a self-note message to your own devices
 * over the self-group (there is no peer to profile, call, or block, and Add would leak the buddy list by
 * admitting a peer to the self-group). File/Call/Video need the live E2E session, so they dim offline. */
function renderImToolbar(m: TransmitModel): string {
  if (m.peer === null) {
    return '';
  }
  const offline = !m.secure;
  if (m.selfNote === true) {
    return (
      '<div class="dd-tbar dd-imbar"><div class="dd-tbar-row">' +
      renderToolButton('send-file', 'Attach File', ICO_ATTACH, offline) +
      '</div></div>'
    );
  }
  const addBuddy = typeof m.peerHandle === 'string' && m.peerHandle.length > 0 && m.peerIsBuddy !== true
    ? renderToolButton('add-buddy', 'Add Buddy', ICO_ADD_BUDDY, false)
    : '';
  return (
    '<div class="dd-tbar dd-imbar"><div class="dd-tbar-row">' +
    renderToolButton('get-info', 'Profile', ICO_PROFILE, false) +
    addBuddy +
    renderToolButton('send-file', 'Attach File', ICO_ATTACH, offline) +
    renderToolButton('call-audio', 'Call', ICO_CALL, offline) +
    renderToolButton('call-video', 'Video', ICO_VIDEO, offline) +
    renderToolButton('block-peer', 'Block', ICO_BLOCK, false, 'dd-im-block') +
    renderToolButton('remove-channel', 'Remove', ICO_REMOVE, false) +
    '</div></div>'
  );
}

/** Mount the transmit shell into a root element, applying the skin class. */
export function mountTransmit(root: HTMLElement, m: TransmitModel): void {
  root.className = 'dd';
  root.innerHTML = renderTransmit(m);
}

/** The honest initial state: locked, no channel open, awaiting unlock. */
export const LOCKED_MODEL: TransmitModel = {
  secure: false,
  peer: null,
  fingerprint: null,
  log: [{ kind: 'system', text: '» channel locked · enter passphrase to open' }],
  compose: '',
  conversationId: null,
};

// --- chrome shell + screens (chrome.css): desktop + menu bar + window, content per view ---

// The first entry is the BRAND (icon + name, rendered with the logo mark); the rest are navigation.
const MENU_ITEMS: readonly string[] = ['DEAD DROP', 'Buddies', 'Channels'];

/** A saved contact in your buddy list, resolved to a conversation by username through the directory.
 * Presence (online/away/idle) is layered on in N5; for now a buddy is the handle and when you saved it. */
export interface Buddy {
  readonly username: string;
  readonly addedAt: number;
  readonly group: string; // the group (category) this buddy is filed under; defaults to 'Buddies'
}

/** The default group a buddy lands in when none is chosen. It is always present, so it is never stored
 * in (or deletable from) the synced group list; the UI supplies it. */
export const DEFAULT_BUDDY_GROUP = 'Buddies';

/** A named buddy-list group (folder). Empty groups exist only because the group list is synced separately
 * from the buddies filed under it (a buddy's own `group` field alone cannot represent an empty folder). */
export interface GroupSummary {
  readonly name: string;
  /** The two built-in groups every user has: 'default' (the Buddies group new buddies file into) and
   * 'blocked' (the drop blocked contacts land in). Built-ins cannot be deleted; renaming one changes
   * only this display name, so both keep working under whatever they are called. Absent on the
   * user-made groups. */
  readonly role?: 'default' | 'blocked';
}

/** A blocked contact for the manage-blocked screen: the blocked key, a short fingerprint of it, and,
 * when the block came from a conversation tagged with a buddy handle, the username, so the buddy
 * surfaces can show WHO is blocked instead of a bare key. */
export interface BlockedContact {
  readonly key: string;
  readonly fingerprint: string;
  readonly username?: string;
}

export interface ChannelSummary {
  readonly id: string;
  readonly peer: string;
  readonly fingerprint: string;
  readonly status: 'secure' | 'pending' | 'blocked';
  readonly preview: string;
  readonly unread: number;
}

/** The mutual key-exchange-and-accept handshake state (ADR-009). */
export interface KeyExchangeState {
  readonly mode: 'start' | 'incoming';
  readonly conversationId: string;
  readonly selfFingerprint: string;
  readonly peer?: string;
  readonly peerFingerprint?: string;
  readonly selfContact?: string; // our copy-pasteable contact string (start mode, live channel)
  readonly byUsername?: boolean; // start mode: open a channel by directory username, not a pasted key
  readonly selfUsername?: string; // our own username to share, shown in by-username start mode
  readonly peerUsername?: string; // pre-filled peer handle (from a scanned/opened contact QR link)
  readonly error?: string; // a directory-lookup error to surface on the start screen
}

/** An unsolicited update pushed from the worker (incoming offer, established channel, new message). */
export interface WorkerEvent {
  readonly event: string;
  readonly payload: unknown;
}

/** The add-a-device screen state. `role` is which side of the handshake this device is on; `step`
 * tracks the two-leg flow; `words` are the six SAS words shown for the user to compare out of band. */
export interface ProvisioningView {
  readonly role: 'seedholder' | 'newdevice';
  // 'scanning' (seedholder aims the camera at the new device) and 'showqr' (new device shows its code)
  // are the QR add-device path; the rest are the six-word fallback.
  readonly step: 'opening' | 'waiting' | 'compare' | 'done' | 'error' | 'scanning' | 'showqr' | 'qrexpired';
  readonly words?: string;
  readonly error?: string;
  // The new device's pairing payload to render as a QR (step 'showqr').
  readonly qr?: string;
}

/** The add-this-device wizard shown after a valid-credentials login on a device that is enrolled but
 * not yet authorized. It is a thin chooser that hands off to the existing provisioning and recovery
 * flows. `connected` is whether the gateway was reached (both authorization paths need it). */
export interface NewDeviceWizardView {
  readonly step: 'choose' | 'deadend';
  readonly connected: boolean;
  readonly error?: string;
}

/** A buddy icon: a chosen emoji, the user's initials on a color, or a small uploaded image. Emoji and
 * initials are tiny and ride the smallest padding bucket, so the server sees nothing different when
 * they are sent. An uploaded image is larger and is detectable on the wire by size, though it stays
 * unreadable; the Identity view discloses this. */
export interface BuddyIcon {
  readonly kind: 'emoji' | 'initials' | 'image';
  readonly value: string; // an emoji character, 1 to 2 initials, or a data: URL
  readonly bg: string; // a palette background color (unused for an image)
}

/** The away auto-responder. `serverSide` is the opt-in that lets the server reply while every device is
 * offline; it relaxes the zero-knowledge model and is off by default. `saved` is the away-message
 * LIBRARY (most recent first, capped): every message saved through the editor lands here so the buddy
 * list's ◆ dropdown can put one up in a click. It rides the away object, so the existing identity sync
 * (last-writer-wins by awayVersion) carries it to all of your devices unchanged. */
export interface AwayConfig {
  readonly enabled: boolean;
  readonly message: string;
  readonly serverSide: boolean;
  readonly saved?: readonly string[];
}

/** How many away messages the library keeps (most recent first; saving an existing one re-tops it). */
export const AWAY_SAVED_MAX = 8;

/** This device's identity card: a buddy icon, a short profile, and the away config, sealed under the
 * MSK on this device. The icon and profile travel only inside conversations you already have (E2E,
 * never a server directory); the away message stays on the device unless serverSide is turned on. */
export interface IdentityProfile {
  readonly icon: BuddyIcon | null;
  readonly bio: string;
  readonly away: AwayConfig;
  // Last-change timestamps for cross-device sync (icon, profile, and away config), so the most recent
  // change from any of your devices wins on every device. Absent/0 = oldest.
  readonly iconVersion?: number;
  readonly bioVersion?: number;
  readonly awayVersion?: number;
}

// 1024 characters, matching the profile cap of the last AOL Instant Messenger release. Enforced in the
// editor AND at both receive paths (a peer's or sibling's frame is clamped on adoption), so a modified
// client cannot bloat what this one stores or renders.
export const PROFILE_MAX_CHARS = 1024;
// The largest stored buddy-icon value (a 64x64 data URL is well under this); a peer-authored icon
// beyond it is dropped on adoption rather than stored.
export const ICON_VALUE_MAX = 32768;
export const AWAY_MAX_CHARS = 560;
export const DEFAULT_IDENTITY: IdentityProfile = {
  icon: null,
  bio: '',
  away: { enabled: false, message: '', serverSide: false },
  // -1 means "never set or adopted on this device", NOT 0. A sibling's real card carries a timestamp
  // version (setIdentity stamps now()); a legacy or unversioned card advertises v=0. Baselining at 0 made
  // a v=0 sibling frame lose the strict `incoming > current` adopt compare (0 <= 0), so a new device never
  // synced the account icon/profile even when the frame arrived. -1 lets the first frame (any v >= 0)
  // adopt, then it self-terminates: a duplicate echo at the same version is dropped, and a device that
  // itself has nothing set publishes v=-1, which every sibling correctly ignores.
  iconVersion: -1,
  bioVersion: -1,
  awayVersion: -1,
};

/** A peer's cached identity for the Get-Info panel: their buddy icon and profile, keyed by their
 * device signature key and shown with the key fingerprint, which is the real trust anchor (the
 * profile is peer-authored and does not prove identity). */
/** What the Verify Buddy panel renders.
 *
 * Two phrases, never one. Each side's words come from that side's OWN account key, so both people
 * read both halves to each other. A single phrase over both keys was the first design and it was
 * broken: the attacker picks the key he shows to each side, so he needs only a collision between two
 * sets he generates himself, not a preimage on a fixed target.
 *
 * `state`: 'none' = both halves readable, never verified; 'verified' = pinned and the current key
 * still matches; 'changed' = pinned and the current key positively DIFFERS (loud); 'stale' = pinned
 * but the current key cannot be read right now, so nothing can be checked and nothing is claimed;
 * 'unavailable' = nothing to compare at all (no conversation with them, no live session, older wasm). */
/** The buddy-list verification badge. 'stale' exists so a pin the app cannot currently check never
 * renders as a confident green check. */
export type BuddyVerifyBadge = 'verified' | 'changed' | 'stale';

export interface BuddyVerifyInfo {
  peerKey: string;
  peerFingerprint: string;
  ourFingerprint: string;
  ourWords: string; // OUR account's phrase, which we read to them
  theirWords: string; // the phrase for the key we currently see for them, which they read to us
  verifiedKey: string;
  state: 'none' | 'verified' | 'changed' | 'stale' | 'unavailable';
}

export interface PeerIdentity {
  readonly key: string;
  readonly fingerprint: string;
  readonly icon: BuddyIcon | null;
  readonly bio: string;
  readonly away: string; // the peer's shared away MESSAGE (empty when their away is off); the buddy-list subtitle
}

/** The look of the client (AIM18). A built-in theme id + a map of user/theme-pack CSS-variable overrides
 * (validated, applied via the CSSOM — never as inline CSS, so the strict CSP is intact). Device-local. */
export type ThemeId = 'default' | 'winamp' | 'win98' | 'h4x0r' | 'aim';
/** The default outgoing-message style (AIM24, "My Message Look"): the font, color, size, and highlight that
 * your messages carry to the people you talk with. It is applied at send time by wrapping the composed text
 * in the matching rich-text markers (which ride E2E and render on the recipient), so peers see your chosen
 * look; any formatting you apply while typing nests inside and wins per run. Only the open/close marker
 * attributes are kept (font/color/size/highlight) — bold/italic stay per-message because their `*`/`_`
 * toggle markers would flip an inline emphasis under a bold/italic default. Device-local, never synced. */
export interface MessageLook {
  readonly font?: string; // an RT_FONTS key
  readonly color?: string; // an RT_TEXT_COLORS key
  readonly size?: 's' | 'l'; // small / large (normal carries no marker)
  readonly hl?: string; // an RT_HL_COLORS key (highlight)
}
export interface Appearance {
  readonly theme: ThemeId;
  readonly tokens: Readonly<Record<string, string>>; // e.g. { '--dd-ink': '#eef3ff', '--dd-font-msg': '...' }
  readonly messageLook?: MessageLook; // your default outgoing-message style (AIM24)
}
export const DEFAULT_APPEARANCE: Appearance = { theme: 'default', tokens: {} };
export const THEME_META: ReadonlyArray<{ readonly id: ThemeId; readonly label: string; readonly blurb: string }> = [
  { id: 'default', label: 'Default', blurb: 'The signature blue CRT terminal.' },
  { id: 'winamp', label: 'Winamp', blurb: 'Dark metallic player, green LCD readout.' },
  { id: 'win98', label: 'Windows 98', blurb: 'Silver 3D chrome, navy titlebars, Notepad chat.' },
  { id: 'h4x0r', label: 'h4x0r', blurb: 'Green-on-black terminal with a Matrix rain.' },
  { id: 'aim', label: 'AIM', blurb: 'The classic instant messenger: silver frame, blue titlebar, running-man mark.' },
];
export const THEME_CLASS: Record<ThemeId, string> = { default: '', winamp: 'dd-theme-winamp', win98: 'dd-theme-win98', h4x0r: 'dd-theme-h4x0r', aim: 'dd-theme-aim' };
/** The ONLY CSS variables a user (or an imported theme pack) may override. Everything else is theme-only.
 * Message tokens style the chat terminal; buddy tokens style the buddy-list tree (AIM19). */
export const APPEARANCE_TOKENS: readonly string[] = [
  '--dd-ink', // message text color
  '--dd-field', // message background
  '--dd-secure', // accent (secure marks, system lines)
  '--dd-font-msg', // message typeface
  '--dd-msg-user-size', // message type size (overrides the window-width auto-scale)
  '--dd-buddy-font', // buddy-list typeface
  '--dd-buddy-size', // buddy-list type size
  '--dd-buddy-ink', // buddy-list text color
];
const APPEARANCE_FONT_TOKENS: ReadonlySet<string> = new Set(['--dd-font-msg', '--dd-buddy-font']);
const APPEARANCE_SIZE_TOKENS: ReadonlySet<string> = new Set(['--dd-msg-user-size', '--dd-buddy-size']);
/** The sizes the pickers offer (classic AIM point sizes, as px). A strict allowlist: a size is only ever
 * applied from this set, so no free-form length can reach the CSSOM. */
export const APPEARANCE_SIZES: readonly string[] = ['10px', '11px', '12px', '13px', '14px', '16px', '18px', '20px', '24px'];
/** Legacy AIM18 font stacks: still VALID (an already-saved appearance keeps working) though the pickers
 * now offer the editor's full RT_FONTS bench instead. */
export const APPEARANCE_FONTS: ReadonlyArray<{ readonly k: string; readonly label: string; readonly stack: string }> = [
  { k: 'mono', label: 'Monospace', stack: 'ui-monospace, "Cascadia Mono", "DejaVu Sans Mono", "Courier New", monospace' },
  { k: 'sans', label: 'Sans-serif', stack: 'system-ui, -apple-system, "Segoe UI", Helvetica, Arial, sans-serif' },
  { k: 'serif', label: 'Serif', stack: 'Georgia, "Times New Roman", Times, serif' },
  { k: 'rounded', label: 'Rounded', stack: '"Comic Sans MS", "Chalkboard SE", "Segoe Print", cursive' },
  { k: 'retro', label: 'Retro', stack: '"Chicago", "Geneva", system-ui, sans-serif' },
];
/** Every face a font token may take: the editor's RT_FONTS bench + the legacy AIM18 stacks. */
const APPEARANCE_FONT_STACKS: ReadonlySet<string> = new Set([...RT_FONTS.map((f) => f.face), ...APPEARANCE_FONTS.map((f) => f.stack)]);
/** The setting categories the Appearance preferences window lists down its left pane (AIM-prefs style). */
export const APPEARANCE_CATS: ReadonlyArray<{ readonly id: string; readonly label: string; readonly blurb: string }> = [
  { id: 'buddylist', label: 'Buddy List Appearance', blurb: 'Font, size, and color of the list' },
  { id: 'message', label: 'Message Appearance', blurb: 'How chat messages look to you' },
  { id: 'mymessage', label: 'My Message Look', blurb: 'How your messages look to others' },
  { id: 'themes', label: 'Themes', blurb: 'Whole looks + theme packs' },
];
/** Validate a token value before it is applied via CSSOM: colors must be hex/rgb(a) only; fonts must be an
 * allowlisted stack; sizes must be an allowlisted px step. Rejects anything else (e.g. url(), expression,
 * arbitrary text), so no attacker-controlled CSS can ride a theme pack into the CSSOM. */
export function isValidTokenValue(token: string, value: string): boolean {
  if (!APPEARANCE_TOKENS.includes(token)) {
    return false;
  }
  if (APPEARANCE_FONT_TOKENS.has(token)) {
    return APPEARANCE_FONT_STACKS.has(value);
  }
  if (APPEARANCE_SIZE_TOKENS.has(token)) {
    return APPEARANCE_SIZES.includes(value);
  }
  return /^#[0-9a-fA-F]{3,8}$/.test(value) || /^rgba?\(\s*[\d.,%\s/]+\)$/.test(value);
}
/** Coerce an untrusted parsed object into a safe Appearance (used for imported theme packs). */
export function sanitizeAppearance(raw: unknown): Appearance {
  const o = (raw ?? {}) as { theme?: unknown; tokens?: unknown; messageLook?: unknown };
  const theme: ThemeId = o.theme === 'winamp' || o.theme === 'win98' || o.theme === 'h4x0r' || o.theme === 'aim' ? o.theme : 'default';
  const tokens: Record<string, string> = {};
  if (o.tokens !== null && typeof o.tokens === 'object') {
    for (const [k, v] of Object.entries(o.tokens as Record<string, unknown>)) {
      if (typeof v === 'string' && isValidTokenValue(k, v)) {
        tokens[k] = v;
      }
    }
  }
  const messageLook = sanitizeMessageLook(o.messageLook);
  return { theme, tokens, ...(messageLook !== undefined ? { messageLook } : {}) };
}

export type AppView =
  | { readonly kind: 'desktop' } // every window minimized/closed: the bare desktop under the menu bar
  | { readonly kind: 'unlock'; readonly mode?: 'login' | 'register'; readonly error?: string; readonly prefillUser?: string }
  | { readonly kind: 'recovery'; readonly secret: string }
  | { readonly kind: 'appearance'; readonly draft: Appearance; readonly category: string; readonly error?: string; readonly packText?: string } // the Appearance preferences (draft edits; Save applies)
  | {
      readonly kind: 'channels';
      readonly channels: readonly ChannelSummary[];
      readonly notice?: string;
      // The two-pane (master-detail) IM window: `active` is the selected channel's chat, shown in the right
      // pane and driven exactly like a standalone conversation; `selectedId` highlights its row on the left.
      readonly active?: TransmitModel;
      readonly selectedId?: string;
    }
  | { readonly kind: 'keyexchange'; readonly state: KeyExchangeState }
  | { readonly kind: 'conversation'; readonly transmit: TransmitModel }
  | { readonly kind: 'provisioning'; readonly state: ProvisioningView }
  | { readonly kind: 'newdevice-wizard'; readonly state: NewDeviceWizardView }
  | { readonly kind: 'recover-entry'; readonly error?: string }
  | { readonly kind: 'selfdestruct'; readonly error?: string } // the Self Destruct confirmation (passphrase twice)
  | { readonly kind: 'revokeself'; readonly deviceId: string; readonly error?: string } // confirm revoking THIS device
  | {
      readonly kind: 'settings';
      readonly devices: readonly DeviceInfo[];
      readonly currentDeviceKey: string;
      readonly pending?: string; // a deviceId awaiting an inline revoke confirmation
      readonly historyOff?: boolean; // this device holds messages in memory only
      readonly historyArm?: boolean; // turning history-off ON is armed (it erases what is stored)
      readonly error?: string;
    }
  | {
      readonly kind: 'identity';
      readonly profile: IdentityProfile;
      readonly error?: string;
      readonly saved?: boolean; // true right after a successful save, to show the "Saved." note
    }
  | {
      readonly kind: 'away'; // the away-message editor, reached from the DEAD DROP menu
      readonly profile: IdentityProfile; // the full card, so a save preserves the icon and profile
      readonly saved?: boolean;
      readonly picked?: number; // the saved-message index chosen in the dropdown (kept selected across re-render)
    }
  | {
      readonly kind: 'getinfo';
      readonly conversationId: string;
      readonly peer: string;
      readonly peers: readonly PeerIdentity[];
      readonly origin?: 'buddies'; // when opened from the Buddy List (Back returns there, not to a chat)
      readonly fromChannels?: boolean; // opened from the two-pane Channels chat (Back returns to that pane)
      readonly presence?: string; // opt-in server status shown when opened by username from the buddy list
      readonly away?: string; // opt-in server away text shown when opened by username from the buddy list
      readonly self?: boolean; // Buddy Info on YOURSELF: your own card, no peer trust warning
      readonly verify?: BuddyVerifyInfo; // the Verify Buddy panel (only when opened by username)
      readonly verifyArm?: boolean; // re-verify after a key change is armed (two-tap)
    }
  | {
      readonly kind: 'buddies';
      readonly buddies: readonly Buddy[];
      readonly groups: readonly GroupSummary[]; // synced group folders (so empty ones still appear)
      readonly statuses: Record<string, string>; // buddy username -> 'online'|'away'|'idle'|'offline'
      readonly collapsed: readonly string[]; // group names currently collapsed in the list
      readonly blocked: readonly BlockedContact[]; // shown as the Blocked "drop" at the bottom
      readonly selected: readonly string[]; // usernames selected for the bottom toolbar actions
      readonly profile: IdentityProfile; // our identity card: the header icon + away/status bubble + toolbar check
      readonly ownName: string; // our handle, shown in the header (AIM-style)
      readonly icons: Record<string, BuddyIcon>; // cached buddy icons by username (absent = placeholder)
      readonly awayText: Record<string, string>; // cached E2E away messages by username (the dim subtitle while away)
      readonly verify?: Record<string, BuddyVerifyBadge>; // per-buddy verification badge (pinned keys only)
      readonly error?: string;
      readonly signals?: Record<string, 'on' | 'off'>; // one-shot sign-on/off flash for rows that just changed
    }
  | {
      readonly kind: 'buddysetup';
      // buddies/groups/blocked are the EDIT DRAFT: setup actions change only these until Save, which
      // diffs them against `orig` (the snapshot loaded when the screen opened) and applies the
      // difference; Cancel discards the draft. Both return to the buddy list.
      readonly buddies: readonly Buddy[];
      readonly groups: readonly GroupSummary[];
      readonly statuses: Record<string, string>;
      readonly blocked: readonly BlockedContact[];
      readonly orig: {
        readonly buddies: readonly Buddy[];
        readonly groups: readonly GroupSummary[];
        readonly blocked: readonly BlockedContact[];
      };
      readonly presenceOn: boolean; // whether THIS device shares its status (applies immediately)
      readonly notifyOn: boolean; // in-app notifications on/off (applies immediately)
      readonly selected: BuddySetupSelection | null; // the row Delete acts on
      readonly error?: string;
    }
  | { readonly kind: 'buddyscan' } // camera scan of a buddy's contact QR to start a conversation
  | { readonly kind: 'buddyqr'; readonly link: string } // show my contact QR for a buddy to scan
  | {
      readonly kind: 'addperson';
      readonly conversationId: string;
      readonly error?: string;
    };

/**
 * The app's backend seam. The real controller drives the MSK vault unlock and loads channels from
 * the storage worker; tests and the preview inject a fake/demo. Keeps app.ts free of crypto/IO.
 */
export interface AppController {
  unlock(username: string, passphrase: string): Promise<{ ok: boolean; created?: boolean; error?: string }>;
  /** Whether THIS device is authorized to read the account (seed-holder or provisioned), and whether it
   * holds the recovery seed. A login-created vault is enrolled but unauthorized; login routes it to the
   * add-device wizard. Absent on controllers that cannot report it (treated as authorized). */
  deviceAuthState?(): Promise<{ authorized: boolean; seedHolder: boolean }>;
  listChannels(): Promise<readonly ChannelSummary[]>;
  /** One channel's display name only (a notification label): O(1), never the full channel sweep.
   * Optional: a controller without it falls back to listChannels. */
  peerFor?(id: string): Promise<string>;
  openChannel(id: string): Promise<TransmitModel>;
  /** Open (creating if needed) the private Note to Self conversation over the own-devices self-group. */
  openNoteToSelf(): Promise<TransmitModel>;
  /** Begin a new conversation (we offer). Returns the handshake state to display. */
  startKeyExchange(): Promise<KeyExchangeState>;
  /** A pending channel we have an incoming offer for. */
  channelKeyExchange(id: string): Promise<KeyExchangeState>;
  /** Accept the mutual exchange and open the conversation. */
  acceptKeyExchange(conversationId: string): Promise<TransmitModel>;
  /** Roll back a just-created local account whose server registration was rejected (username taken). */
  discardAccount?(username: string): Promise<void>;
  /** Verify a typed passphrase against the account's vault without changing state. Gates Self Destruct. */
  verifyPassphrase?(username: string, passphrase: string): Promise<boolean>;
  /** Open the live gateway connection and subscribe to our bootstrap mailbox. */
  connectGateway(wsUrl: string): Promise<{ ok: boolean; selfContact: string; error?: string }>;
  /** Start a group conversation with every target device (the peer's devices plus our own siblings),
   * adding them all in one MLS commit and sending each a Welcome. */
  startConversation(targets: readonly DeviceTarget[]): Promise<TransmitModel>;
  /** Send a plaintext message on an established live channel. */
  sendMessage(conversationId: string, text: string, lifetime?: Lifetime): Promise<TransmitModel>;
  /** Revoke one of our own until-revoked messages: every member device crypto-erases its stored copy,
   * ours included. Returns the refreshed conversation view. */
  revokeMessage?(conversationId: string, messageId: string): Promise<TransmitModel>;
  /** The account recovery secret to show ONCE right after first creation, else null. */
  recoverySecret?(): Promise<string | null>;
  /** Create + seal the account recovery seed at registration, making this the seed-holder device. */
  ensureAccountSeed?(): Promise<void>;
  /** SEED-HOLDER: open a short add-a-device window (model b provisioning). */
  openProvisioningWindow?(): Promise<void>;
  /** NEW DEVICE: begin joining this account; surfaces six words to compare out of band. */
  joinDevice?(): Promise<void>;
  /** SEED-HOLDER: confirm the six words matched and grant the pending device. */
  confirmProvisioning?(): Promise<void>;
  /** SEED-HOLDER: dismiss the add-a-device window without authorizing. */
  closeProvisioning?(): Promise<void>;
  /** NEW DEVICE (QR): start listening and return the pairing QR payload for the user to display. */
  startQrPairing?(): Promise<string>;
  /** SEED-HOLDER (scan): certify the scanned device and seal the grant to its ephemeral key. */
  grantScannedDevice?(qrPayload: string): Promise<void>;
  /** Mint `n` fresh key packages (hex) for this device to publish to the directory. */
  keyPackages?(n: number): Promise<string[]>;
  /** True when this device may publish key packages (it is the seed-holder or has been provisioned). */
  isGroupReady?(): Promise<boolean>;
  /** Recovery: make this device an authorized seed-holder by entering the account recovery secret. */
  recoverWithSeed?(recoverySeedHex: string, epoch: number): Promise<{ ok: boolean; error?: string }>;
  /** P6: bring this device up to the account's current cert epoch; reports stale if it cannot. */
  syncEpoch?(epoch: number): Promise<{ ready: boolean; stale: boolean }>;
  /** This device's own certificate epoch (0 if unauthorized). */
  certEpoch?(): Promise<number>;
  /** ADR-022 P7: mint the signed revocation record that excludes a device by NAME, returned as hex to
   * publish. Null when this device holds no account key. The epoch above is only a lower bound and
   * cannot exclude a device that still holds the account seed; this is what does. */
  revokeDeviceKey?(deviceSigKeyHex: string, issuedSeq: number): Promise<string | null>;
  /** ADR-022 P7: accept revocation records fetched from the control plane, returning how many were new.
   * Each is verified against our own account key inside the worker, so these arrive untrusted. */
  ingestRevocations?(records: readonly string[]): Promise<number>;
  /** The record count (the derived epoch) and this device's certification floor, for diagnostics. */
  revocationState?(): Promise<{ revoked: number; floor: number }>;
  /** Whether we hold a verifying revocation record for this device key. */
  isDeviceRevoked?(deviceSigKeyHex: string): Promise<boolean>;
  /** A short fingerprint of this account's authorization key (stable across the user's devices), for the
   * shareable contact QR. Empty when unauthorized/legacy. */
  accountFingerprint?(): Promise<string>;
  /** Whether this device is holding messages in memory only (history-off / ephemeral mode). */
  historyOffEnabled?(): Promise<boolean>;
  /** Turn history-off on or off. Turning it ON crypto-erases the message history already on this
   * device, so the setting is not a promise the device fails to keep. */
  setHistoryOff?(on: boolean, purgeExisting?: boolean): Promise<void>;
  /** Everything the Verify Buddy panel shows for one buddy (phrase, keys, pinned state). */
  buddyVerifyInfo?(username: string): Promise<BuddyVerifyInfo>;
  /** The per-buddy verification badge for the list: present only for buddies with a pinned key. */
  buddyVerifyStates?(usernames: readonly string[]): Promise<Record<string, BuddyVerifyBadge>>;
  /** Pin `peerKey` after the user compared BOTH phrases. `expectedPrev` is the pin the panel was
   * rendered against (empty for a first verification); a mismatch means the screen is stale and the
   * call refuses. False = nothing was pinned, re-open and compare again. */
  markBuddyVerified?(username: string, peerKey: string, expectedPrev?: string): Promise<boolean>;
  /** Drop a buddy's pinned verification. */
  clearBuddyVerified?(username: string): Promise<void>;
  /** P5: add an already-enrolled device to one conversation. */
  addDevice?(conversationId: string, target: DeviceTarget): Promise<void>;
  /** P6: exclude a device from the open group (forward-secure exclusion); the MLS half of revoke. */
  excludeDevice?(sigKeyHex: string): Promise<void>;
  /** Self-heal (H1): cheap pre-check (no key-package claim) for whether this device should add a sibling
   * now, so the app skips claiming on a peer-only roster change. */
  hasMissingSiblings?(ownDeviceKeys: readonly string[]): Promise<boolean>;
  /** Self-heal (H1): admit this account's authorized devices not yet in the open conversation so every
   * signed-in device receives going forward. `candidates` are devices with a claimed single-use package
   * (supplied as data so it is structured-clone-safe across the worker boundary). */
  reconcileSiblings?(ownDeviceKeys: readonly string[], candidates: readonly DeviceTarget[]): Promise<void>;
  reconcileRemovals?(ownDeviceKeys: readonly string[], revokedKeys: readonly string[]): Promise<void>;
  /** Heal a just-authorized device into the hidden self-group from the seed-holder's post-add poll, even
   * when this device is not the lowest-keyed adder. Keeps the race-free election + failover; self only. */
  reconcileSelf?(ownDeviceKeys: readonly string[], candidates: readonly DeviceTarget[]): Promise<void>;
  /** Where a device stands relative to the hidden self-group: 'member' / 'pending' / 'absent' / 'none'.
   * Lets the seed-holder's post-add poll settle on membership and avoid burning key packages while pending. */
  selfSiblingState?(deviceKey: string): Promise<'member' | 'pending' | 'absent' | 'none'>;
  /** Whether the hidden self-group (a group of only our own devices) is open. Used so only the designated
   * device creates it, and only once. */
  hasSelfGroup?(): Promise<boolean>;
  /** Create the hidden self-group adding the given sibling devices: the private channel that syncs the
   * buddy list across this account's own devices, never surfaced as a conversation. */
  ensureSelfGroup?(targets: readonly DeviceTarget[]): Promise<void>;
  /** Register for unsolicited worker events (established, inbound message, roster change, provisioning). */
  onEvent?(handler: (ev: WorkerEvent) => void): void;
  /** Load this device's identity card (buddy icon, profile, away config), sealed under the MSK. */
  getIdentity?(): Promise<IdentityProfile>;
  /** Persist the identity card under the MSK and publish the icon + profile to open conversations (E2E). */
  setIdentity?(profile: IdentityProfile): Promise<void>;
  /** The cached buddy icon + profile of each peer device in a conversation (for the Get-Info panel). */
  getPeerIdentities?(conversationId: string): Promise<readonly PeerIdentity[]>;
  /** Remember (device-locally) which buddy handle a conversation was opened with, so Buddy Info can find
   * that conversation's cached peer profile later. The tag never leaves this device. */
  tagConversationHandle?(conversationId: string, username: string): Promise<void>;
  /** The cached peer profile(s) for a buddy by username, via the conversation tagged for that handle.
   * Empty when no conversation with them exists on this device (profiles are E2E, never on the server). */
  getBuddyInfo?(username: string): Promise<readonly PeerIdentity[]>;
  /** The cached buddy icons for a set of usernames in one call (for the buddy-list rows). */
  buddyIcons?(usernames: readonly string[]): Promise<Record<string, BuddyIcon>>;
  /** The cached E2E away messages for a set of usernames in one call (the dim buddy-list subtitle while away). */
  buddyAwayText?(usernames: readonly string[]): Promise<Record<string, string>>;
  /** The saved buddy list (handles you keep so you can reach people without re-typing them). */
  listBuddies?(): Promise<readonly Buddy[]>;
  /** Add a username to the buddy list under `group` (default 'Buddies'); returns the updated list. */
  addBuddy?(username: string, group?: string): Promise<readonly Buddy[]>;
  /** Remove a username from the buddy list; returns the updated list. */
  removeBuddy?(username: string): Promise<readonly Buddy[]>;
  /** Move a buddy to a different group (synced across your devices); returns the updated list. */
  setBuddyGroup?(username: string, group: string): Promise<readonly Buddy[]>;
  /** The named buddy-list groups (folders), including empty ones, synced across your devices. */
  listGroups?(): Promise<readonly GroupSummary[]>;
  /** Create a named group (empty groups are allowed); returns the updated group list. */
  addGroup?(name: string): Promise<readonly GroupSummary[]>;
  /** Rename a built-in group (label only, so it keeps working): the default group or the Blocked drop. */
  renameGroup?(role: 'default' | 'blocked', name: string): Promise<readonly GroupSummary[]>;
  /** Delete a group and move its buddies back to the default group; returns the updated group list. */
  deleteGroup?(name: string): Promise<readonly GroupSummary[]>;
  /** Block everyone in the open conversation and leave it (best-effort; a new key evades). */
  blockConversation?(conversationId: string): Promise<void>;
  removeConversation?(conversationId: string): Promise<void>;
  /** The blocked contacts (key + fingerprint) for the manage-blocked screen. */
  listBlocked?(): Promise<readonly BlockedContact[]>;
  /** Remove a key from the block list; returns the updated list. */
  unblock?(key: string): Promise<readonly BlockedContact[]>;
  /** Whether this device shares opt-in presence (online/away/idle) with buddies. Off by default. */
  getPresenceEnabled?(): Promise<boolean>;
  setPresenceEnabled?(on: boolean): Promise<void>;
  /** Whether in-app notifications (toasts, sounds, buddy sign-on) are on. Defaults ON. */
  getNotifyEnabled?(): Promise<boolean>;
  setNotifyEnabled?(on: boolean): Promise<void>;
  /** The device-local appearance (theme + validated token tweaks). Raw parsed value; the app sanitizes. */
  getAppearance?(): Promise<unknown>;
  setAppearance?(value: Appearance): Promise<void>;
  /** Relay a file-transfer signal (the WebRTC handshake) to one conversation over the E2E channel. */
  sendFileSignal?(conversationId: string, json: string): void;
  /** Relay a call signal (the WebRTC handshake) to one conversation over the E2E channel. */
  sendCallSignal?(conversationId: string, json: string): void;
}

/** The DEAD DROP mark: a dead-drop teardrop enclosing a keyhole (what a drop holds: a lock only the
 * right key opens). One evenodd path, so the keyhole is a true cutout; fills come from CSS classes
 * (currentColor), never an inline style, so it renders under the strict CSP. */
const LOGO_PATH =
  'M12 1.6 C 9.2 5.4 5 9.9 5 14.6 A 7 7 0 0 0 19 14.6 C 19 9.9 14.8 5.4 12 1.6 Z ' +
  'M 10.9 14.42 A 2.3 2.3 0 1 1 13.1 14.42 L 13.7 17.6 L 10.3 17.6 Z';
function logoSvg(cls: string): string {
  return `<svg class="${cls}" viewBox="0 0 24 24" aria-hidden="true"><path fill-rule="evenodd" d="${LOGO_PATH}"/></svg>`;
}

/** The unlock screen's hero brand: the mark large over the wordmark, the first thing a visitor sees. */
function renderLogoHero(): string {
  return (
    '<div class="dd-logo-hero">' +
    logoSvg('dd-logo-mark') +
    '<div class="dd-logo-word">DEAD DROP</div>' +
    '</div>'
  );
}

function renderMenubar(
  minimized: readonly { readonly key: string; readonly title: string; readonly unread?: number }[] = [],
): string {
  // Minimized windows live on the menu bar as chips (the AIM taskbar); clicking one restores it. A chip
  // with unread arrivals carries a count and an attention class, so a docked conversation never swallows
  // a message silently (the AIM taskbar flashed for exactly this).
  const chips = minimized
    .map((m) => {
      const n = m.unread ?? 0;
      const cls = n > 0 ? 'dd-menu-chip dd-menu-chip-unread' : 'dd-menu-chip';
      const badge = n > 0 ? `<span class="dd-chip-badge">${n > 99 ? '99+' : String(n)}</span>` : '';
      const label = n > 0 ? `restore ${m.title} (${String(n)} unread)` : `restore ${m.title}`;
      return (
        `<button type="button" class="${cls}" data-restore="${escapeHtml(m.key)}" title="${escapeHtml(label)}">` +
        `▪ ${escapeHtml(m.title)}${badge}</button>`
      );
    })
    .join('');
  // The brand is the app icon + name and opens the DEAD DROP menu (Device keys + Self Destruct). The same
  // menu also lives in the buddy-list titlebar corner; both share the app-menu wiring. Buddies/Channels
  // are direct navigation (they open/focus their windows without closing the others).
  const brand =
    '<span class="dd-menu-app">' +
    `<button type="button" class="dd-menu-item dd-menu-brand" data-action="app-menu">${logoSvg('dd-logo-ic')} DEAD DROP</button>` +
    '<span class="dd-menu-dropdown dd-appmenu-pop" hidden>' +
    '<button type="button" class="dd-menu-dropitem" data-action="appearance">Appearance</button>' +
    '<button type="button" class="dd-menu-dropitem" data-action="device-keys">Device keys</button>' +
    '<button type="button" class="dd-menu-dropitem dd-menu-destruct" data-action="self-destruct">☠️ Self Destruct ☠️</button>' +
    '</span></span>';
  const rest = MENU_ITEMS.slice(1)
    .map((label) => `<span class="dd-menu-item">${escapeHtml(label)}</span>`)
    .join('');
  return (
    `<div class="dd-menubar">${brand}${rest}${chips}</div>` // connection status now lives in the buddy-list titlebar
  );
}

/** The DEAD DROP app menu, anchored at the window titlebar's top-left (the classic Mac corner): the
 * app icon opens a dropdown holding what has no home on the buddy-list surfaces themselves, device
 * management and the account kill switch. Excluded on the same screens that hide the window controls
 * (pre-login and the guided/sensitive flows must not offer an escape hatch). */
function titlebarAppMenu(view: AppView): string {
  // The DEAD DROP menu lives in the titlebar corner of the buddy list (home), a standalone IM window, and
  // the two-pane Channels window; every other window's titlebar stays clean (the menu is always reachable
  // from the menu bar too). A standalone IM adds "Dock to Channels" (move it into the two-pane); the
  // Channels window, when a chat is open, adds "Pop out chat" (undock it to its own window).
  if (view.kind !== 'buddies' && view.kind !== 'conversation' && view.kind !== 'channels') {
    return '';
  }
  const dock = view.kind === 'conversation'
    ? '<button type="button" class="dd-menu-dropitem" data-action="dock-to-channels">⧉ Dock to Channels</button>'
    : view.kind === 'channels' && view.active !== undefined
      ? '<button type="button" class="dd-menu-dropitem" data-action="pop-out-chat">⧉ Pop out chat</button>'
      : '';
  // A CHAT window's menu holds only its own action (Dock to Channels): the app-level items — Appearance,
  // Device keys, Self Destruct — belong to the buddy list / Channels / menu bar, not to a conversation.
  const appItems = view.kind === 'conversation'
    ? ''
    : '<button type="button" class="dd-menu-dropitem" data-action="appearance">Appearance</button>' +
      '<button type="button" class="dd-menu-dropitem" data-action="device-keys">Device keys</button>' +
      '<button type="button" class="dd-menu-dropitem dd-menu-destruct" data-action="self-destruct">☠️ Self Destruct ☠️</button>';
  return (
    '<span class="dd-winmenu">' +
    `<button type="button" class="dd-winbtn dd-winbtn-app" data-action="app-menu" title="DEAD DROP menu" aria-label="DEAD DROP menu">${logoSvg('dd-logo-ic')}</button>` +
    '<span class="dd-menu-dropdown dd-appmenu-pop" hidden>' +
    dock +
    appItems +
    '</span></span>'
  );
}

/** Connection headline, E2E-readiness first (AIM21): SECURE LINK means the end-to-end session is live;
 * 'live' is the honest in-between (transport up, E2E not yet) and reads as SECURING, never as done.
 * Transitional states (connecting / reconnect countdown) are composed in connDisplayLabel(). */
const CONN_LABELS: Record<string, string> = {
  offline: '○ OFFLINE',
  connecting: '◌ CONNECTING…',
  live: '◐ SECURING…',
  secure: '● SECURE LINK',
};

function renderScrollbar(): string {
  return (
    '<div class="dd-scrollbar">' +
    '<div class="dd-sb-arrow">▲</div>' +
    '<div class="dd-sb-track"><div class="dd-sb-thumb"></div></div>' +
    '<div class="dd-sb-arrow">▼</div>' +
    '</div>'
  );
}

/**
 * Unlock screen: username + passphrase entry that drives the per-account MSK vault and the
 * server-backed account workflow. Login mode opens an existing account; register mode creates one,
 * adding a confirm-passphrase field and the note that the server denies a username already taken.
 * The first argument stays `error` for back-compatibility with the bare login screen.
 */
// The published desktop builds. Served from GitHub releases rather than this origin: the installers
// are ~100MB each and would otherwise spend the app server's bandwidth on every download. The
// "latest" form resolves to the newest release, so a new build needs no change here.
const RELEASES = 'https://github.com/tertiaopt-io/d3addr0p/releases';
const DOWNLOAD_MAC = `${RELEASES}/latest/download/DEAD-DROP-mac-arm64.zip`;
const DOWNLOAD_WIN = `${RELEASES}/latest/download/DEAD-DROP-win-x64.zip`;

/** Who makes this. Shown on the web landing page AND in the native app (it is attribution, not a
 * marketing panel). Opens in a new tab; rel keeps the opened page from touching this one. */
function renderProjectAttribution(): string {
  return (
    '<div class="dd-form-note dd-attrib">a ' +
    '<a class="dd-extlink" href="https://tertiaopt.io" target="_blank" rel="noopener noreferrer">tertiaopt.io</a>' +
    ' project</div>'
  );
}

/** The product's own argument, in the register of the AIM era it borrows from: presence used to be a
 * thing you declared, and signing off used to mean something. Explains the deliberate absence of a
 * mobile client as a design position rather than a gap. Web landing page only. */
function renderPitch(): string {
  return (
    '<div class="dd-pitch">' +
    '<div class="dd-pitch-lead">A messenger that lets you be gone.</div>' +
    '<p class="dd-pitch-p">There was a decade when being online was somewhere you went. You sat down, ' +
    'you signed on, a door opened somewhere and your name appeared on other people\u2019s screens. When ' +
    'you left you said so, in your own words, and the away message stood in for you while you were ' +
    'living the rest of your life. Everyone understood the difference between a person who was there ' +
    'and a person who was not.</p>' +
    '<p class="dd-pitch-p">Phones dissolved that line. Delivered turned into read, read turned into ' +
    'why the silence, and presence stopped being something you announced and became something your ' +
    'device leaked on your behalf, everywhere, always. The away message had nothing left to do.</p>' +
    '<p class="dd-pitch-p">DEAD DROP is built for the older arrangement. It runs on computers you sit ' +
    'down at, and it ships no mobile client on purpose. Your buddy list is a room you enter rather ' +
    'than a feed that follows you, your away message is a real statement again, and closing the ' +
    'window is a way of being unreachable that nobody has to interpret. Messages are end to end ' +
    'encrypted and can be built to expire, because being gone should apply to what you said as well ' +
    'as to where you are.</p>' +
    '</div>'
  );
}

/** How DEAD DROP differs from Signal at the level that actually decides safety: what the protocols
 * guarantee, what each one does after a device is compromised, what the server can still see, and what
 * each product does with a message once it has been read. Signal is the stronger, proven choice on the
 * things that protect most people most of the time; this states the real design trades without
 * overclaiming. Web only. Copy rules: no em-dashes, no "not X but Y". */
function renderComparison(): string {
  // data-col carries the column name so a phone can stack each row into labelled blocks (the header
  // row is hidden there, and CSS reads the label back with content: attr(data-col)). A three-column
  // table cannot fit 375px without either side-scrolling or clipping; see the media query in chrome.css.
  const row = (feature: string, dd: string, sig: string): string =>
    `<tr><th scope="row">${escapeHtml(feature)}</th>` +
    `<td data-col="DEAD DROP">${escapeHtml(dd)}</td>` +
    `<td data-col="Signal">${escapeHtml(sig)}</td></tr>`;
  return (
    '<div class="dd-compare">' +
    '<div class="dd-compare-title">How the two are built</div>' +
    '<table class="dd-compare-table">' +
    '<thead><tr><td></td><th scope="col">DEAD DROP</th><th scope="col">Signal</th></tr></thead>' +
    '<tbody>' +
    row(
      'Protocol',
      'MLS (RFC 9420). One group ratchet over a tree of members, so a group of any size shares one key schedule.',
      'The Signal Protocol. A Double Ratchet per pair of devices, fanned out to the group.',
    ) +
    row(
      'Adding a device',
      'The group re-keys as a membership change, so a new device is admitted by the group and cannot read what came before.',
      'A linked device is added to your account and pairs with each conversation.',
    ) +
    row(
      'After a key is stolen',
      'The next commit rotates the group key, so an attacker who stops receiving loses the thread. This is the property MLS is designed for.',
      'The ratchet heals as soon as both sides exchange again, per conversation.',
    ) +
    row(
      'Group size cost',
      'One commit re-keys the whole group, so cost grows with the log of the membership.',
      'A copy per recipient device, so cost grows with the membership.',
    ) +
    row(
      'What the server sees',
      'Ciphertext padded into fixed size buckets, delivered to per epoch mailboxes that rotate. It still sees when you connect.',
      'Sealed sender hides who sent a message, plus a much larger crowd to hide in.',
    ) +
    row(
      'Once a message is read',
      'Each message carries its own life: burn on read, a timer, or until you revoke it. Revoking destroys the stored copy on every device of everyone in the group.',
      'One disappearing timer for the whole conversation, and a delete for everyone that asks clients to remove it.',
    ) +
    row(
      'Where the keys live',
      'On your devices, in a store encrypted by your passphrase. There is no recovery.',
      'On your devices, with an encrypted backup you can restore from.',
    ) +
    row('Signing up', 'A username you choose. No phone number and no email.', 'A phone number.') +
    row('Who runs the server', 'You can. It is one small self-hosted service.', 'Signal runs it for everyone.') +
    row(
      'Confirming a contact',
      'A six word phrase per buddy, compared in person or over a call, pinned to their account key. First contact is still taken on trust until you compare.',
      'Safety numbers you compare in person or over a channel you already trust.',
    ) +
    row('Independent audit', 'None. This is a young project.', 'Audited, and the protocol is widely reviewed.') +
    '</tbody></table>' +
    '<div class="dd-compare-note">The honest summary: Signal has the reviewed protocol, the audits, ' +
    'the sealed sender, the recovery path, and the crowd, and for almost everyone it is the right ' +
    'answer. This project is for people who want an account with no phone number, a server they ' +
    'control, message lifetimes decided one message at a time, and a client that stays on the desk, ' +
    'and who accept a young unaudited build in exchange.</div>' +
    '</div>'
  );
}

/** Desktop builds, above the comparison. Web only, for the same reason. */
function renderDownloads(): string {
  return (
    '<div class="dd-downloads">' +
    '<div class="dd-downloads-title">Desktop app</div>' +
    '<div class="dd-downloads-row">' +
    `<a class="dd-btn dd-dl" href="${DOWNLOAD_MAC}" target="_blank" rel="noopener noreferrer">macOS (Apple silicon)</a>` +
    `<a class="dd-btn dd-dl" href="${DOWNLOAD_WIN}" target="_blank" rel="noopener noreferrer">Windows (64 bit)</a>` +
    '</div>' +
    '<div class="dd-form-note">Downloads come from the project releases on GitHub. The builds are ' +
    'unsigned, so your system will ask you to confirm the first launch. They open the same account as ' +
    'the web app and onboard as a new device.</div>' +
    '</div>'
  );
}

export function renderUnlock(error?: string, mode: 'login' | 'register' = 'login', prefillUser?: string): string {
  const err = error !== undefined ? `<div class="dd-form-error">${escapeHtml(error)}</div>` : '';
  // On a refresh of an open session the username is pre-filled so you only re-enter your passphrase.
  const userValue = prefillUser !== undefined && prefillUser.length > 0 ? ` value="${escapeHtml(prefillUser)}"` : '';
  const note =
    '<div class="dd-form-note">Account recovery is impossible. Nobody can reset your login, and if ' +
    'you lose your username or your passphrase, the account and every message in it are gone for ' +
    'good. Write down both your username and passphrase now and keep them somewhere only you can reach.</div>';
  if (mode === 'register') {
    return (
      '<form class="dd-form" id="dd-unlock-form" data-mode="register" autocomplete="off">' +
      renderLogoHero() +
      '<div class="dd-form-sub">choose a username and passphrase to create your account</div>' +
      '<div class="dd-stack">' +
      '<input class="dd-input" id="dd-user" type="text" placeholder="choose a username" aria-label="username" autocomplete="off" autocapitalize="none" spellcheck="false" />' +
      '<input class="dd-input" id="dd-pass" type="password" placeholder="choose a passphrase" aria-label="passphrase" />' +
      '<input class="dd-input" id="dd-pass2" type="password" placeholder="repeat passphrase" aria-label="repeat passphrase" />' +
      '<button class="dd-btn dd-btn-primary" type="submit">Create account</button>' +
      '</div>' +
      err +
      '<div class="dd-form-note">Usernames are unique. If the name you choose is already taken you ' +
      'will be asked to pick another.</div>' +
      note +
      '<button class="dd-link" type="button" data-action="to-login">Already have an account? Log in</button>' +
      renderProjectAttribution() +
      '</form>'
    );
  }
  // Returning-session (username pre-filled) shows no subtitle — the logo speaks for itself; a fresh
  // login keeps the one-line instruction.
  const sub = userValue !== '' ? '' : 'enter your username and passphrase to open your channels';
  return (
    '<form class="dd-form" id="dd-unlock-form" data-mode="login" autocomplete="off">' +
    renderLogoHero() +
    (sub !== '' ? `<div class="dd-form-sub">${sub}</div>` : '') +
    '<div class="dd-stack">' +
    `<input class="dd-input" id="dd-user" type="text" placeholder="username" aria-label="username" autocomplete="off" autocapitalize="none" spellcheck="false"${userValue} />` +
    '<input class="dd-input" id="dd-pass" type="password" placeholder="passphrase" aria-label="passphrase" />' +
    '<button class="dd-btn dd-btn-primary" type="submit">Unlock</button>' +
    '</div>' +
    err +
    note +
    '<button class="dd-link" type="button" data-action="to-register">New here? Create an account</button>' +
    renderProjectAttribution() +
    // The comparison panel and the desktop downloads belong to the WEB landing page. Inside the native
    // app they would be noise: you are already running the thing they advertise. Downloads come BEFORE
    // the comparison: the app is the thing to act on, and the comparison is long enough on a phone to
    // bury anything under it.
    (isNativeShell() ? '' : renderPitch() + renderDownloads() + renderComparison()) +
    '</form>'
  );
}

function renderChannelRow(c: ChannelSummary, selectedId?: string): string {
  const badge = c.unread > 0 ? `<span class="dd-badge">${c.unread}</span>` : '';
  const active = c.id === selectedId ? ' dd-channel-active' : '';
  return (
    `<button class="dd-channel${active}" data-channel="${escapeHtml(c.id)}" data-status="${c.status}">` +
    `<div class="dd-channel-top"><span class="dd-status-dot dd-status-${c.status}"></span>` +
    `<span class="dd-channel-name">${escapeHtml(c.peer)}</span>${badge}</div>` +
    `<div class="dd-channel-preview">${escapeHtml(c.preview)}</div>` +
    `<div class="dd-channel-meta">key ${escapeHtml(c.fingerprint)} · ${escapeHtml(c.status)}</div>` +
    '</button>'
  );
}

/** Channels screen: a two-pane (master-detail) IM window. The channel list is the LEFT pane; the selected
 * channel's chat "flows" into the RIGHT pane (`active`, driven exactly like a standalone conversation).
 * With nothing selected the right pane is a quiet placeholder. An optional notice banner leads the list. */
export function renderChannels(channels: readonly ChannelSummary[], notice?: string, active?: TransmitModel, selectedId?: string): string {
  const banner = notice !== undefined ? `<div class="dd-notice">${escapeHtml(notice)}</div>` : '';
  const left = channels.length === 0
    ? banner + '<div class="dd-form"><div class="dd-form-sub">no channels yet</div>' +
      '<button class="dd-btn dd-btn-primary" data-action="new-channel">New channel</button></div>'
    : banner + `<div class="dd-list">${channels.map((c) => renderChannelRow(c, selectedId)).join('')}</div>`;
  const right = active !== undefined
    ? // On a phone the panes swap instead of sharing the width, so the open chat needs its own way back
      // to the list; the button is display:none on wide screens (see .dd-chan-back in chrome.css).
      '<button type="button" class="dd-chan-back" data-action="channels-show-list">‹ Channels</button>' +
      `<div class="dd">${renderTransmit(active)}</div>` // the working scrollbar rides inside the terminal now
    : '<div class="dd-detail-empty">Select a channel to open its chat.</div>';
  return `<div class="dd-channels-2pane"><div class="dd-chan-list">${left}</div><div class="dd-chan-detail">${right}</div></div>`;
}

/** The Appearance preferences (AIM19): a two-pane window modeled on the classic AIM Preferences. The LEFT
 * pane lists the setting categories (Buddy List Appearance / Message Appearance / Themes); the RIGHT pane
 * shows editor-toolbar-style pickers, a live PREVIEW box, and Save/Cancel. Edits are a DRAFT: the preview
 * shows them, nothing applies to the app or persists until Save. All values are validated allowlists and
 * reach the DOM only via classes or the CSSOM, so the strict CSP holds. */

/** A labeled dropdown row (Font / Size / Color …) in the AIM-prefs style: the trigger shows the current
 * pick; the popup panel reuses the rich-text toolbar's chrome (.dd-rt-pop) for the authentic look. */
function appearRow(label: string, popId: string, current: string, body: string): string {
  return (
    '<div class="dd-appear-row">' +
    `<span class="dd-appear-lbl">${escapeHtml(label)}</span>` +
    '<span class="dd-rt-popwrap">' +
    `<button type="button" class="dd-rt-btn dd-rt-popbtn dd-appear-popbtn" data-appear-pop="${popId}">` +
    `<span class="dd-appear-cur">${escapeHtml(current)}</span><span class="dd-rt-caret">▾</span></button>` +
    `<span class="dd-rt-pop dd-appear-pop" data-appear-popid="${popId}" hidden>${body}</span>` +
    '</span></div>'
  );
}
/** The option list bodies: fonts (the editor's bench, each shown in its own face), sizes, and swatches. */
function appearFontRow(label: string, popId: string, token: string, current: string | undefined): string {
  const curLabel = current === undefined ? 'Default' : (RT_FONTS.find((f) => f.face === current)?.label ?? 'Custom');
  const opts =
    `<button type="button" class="dd-rt-fontopt" data-appear-set="${token}" data-appear-val="">Default</button>` +
    RT_FONTS.map((f) => `<button type="button" class="dd-rt-fontopt dd-ft-${f.k}" data-appear-set="${token}" data-appear-val="${escapeHtml(f.face)}">${escapeHtml(f.label)}</button>`).join('');
  return appearRow(label, popId, curLabel, `<div class="dd-rt-fonts">${opts}</div>`);
}
function appearSizeRow(label: string, popId: string, token: string, current: string | undefined): string {
  const opts =
    `<button type="button" class="dd-rt-fontopt" data-appear-set="${token}" data-appear-val="">Auto</button>` +
    APPEARANCE_SIZES.map((s) => `<button type="button" class="dd-rt-fontopt" data-appear-set="${token}" data-appear-val="${s}">${s.replace('px', '')}</button>`).join('');
  return appearRow(label, popId, current === undefined ? 'Auto' : current.replace('px', ''), `<div class="dd-rt-fonts dd-appear-sizes">${opts}</div>`);
}
function appearColorRow(label: string, popId: string, token: string, current: string | undefined): string {
  const sw = RT_TEXT_COLORS.map(
    (c) =>
      `<button type="button" class="dd-rt-sw${current === c.hex ? ' dd-appear-sw-on' : ''}" data-appear-set="${token}" data-appear-val="${c.hex}" title="${c.hex}">` +
      `<span class="dd-c-${c.k}">A</span></button>`,
  ).join('');
  const clear = `<button type="button" class="dd-rt-fontopt" data-appear-set="${token}" data-appear-val="">Default</button>`;
  return appearRow(label, popId, current ?? 'Default', `<div class="dd-rt-swrow">${sw}</div>${clear}`);
}

// "My Message Look" rows (AIM24): the same AIM-prefs dropdown chrome as the theming rows above, but bound to
// the MessageLook DRAFT (data-look-set/data-look-val) and using the rich-text palette KEYS, so a pick maps
// straight onto a [f:]/[c:]/[h:]/[z:] marker that rides E2E and renders on the recipient.
function lookFontRow(popId: string, current: string | undefined): string {
  const curLabel = current === undefined ? 'Default' : RT_FONTS.find((f) => f.k === current)?.label ?? 'Default';
  const opts =
    '<button type="button" class="dd-rt-fontopt" data-look-set="font" data-look-val="">Default</button>' +
    RT_FONTS.map(
      (f) =>
        `<button type="button" class="dd-rt-fontopt dd-ft-${f.k}${current === f.k ? ' dd-appear-sw-on' : ''}" data-look-set="font" data-look-val="${f.k}">${escapeHtml(f.label)}</button>`,
    ).join('');
  return appearRow('Font', popId, curLabel, `<div class="dd-rt-fonts">${opts}</div>`);
}
function lookSizeRow(popId: string, current: string | undefined): string {
  const cur = current === 's' ? 'Small' : current === 'l' ? 'Large' : 'Normal';
  const opt = (v: string, label: string): string =>
    `<button type="button" class="dd-rt-fontopt${(current ?? '') === v ? ' dd-appear-sw-on' : ''}" data-look-set="size" data-look-val="${v}">${label}</button>`;
  return appearRow('Size', popId, cur, `<div class="dd-rt-fonts dd-appear-sizes">${opt('', 'Normal')}${opt('s', 'Small')}${opt('l', 'Large')}</div>`);
}
function lookColorRow(popId: string, current: string | undefined): string {
  const curHex = current === undefined ? 'Default' : RT_TEXT_COLORS.find((c) => c.k === current)?.hex ?? 'Default';
  const sw = RT_TEXT_COLORS.map(
    (c) =>
      `<button type="button" class="dd-rt-sw${current === c.k ? ' dd-appear-sw-on' : ''}" data-look-set="color" data-look-val="${c.k}" title="${c.hex}"><span class="dd-c-${c.k}">A</span></button>`,
  ).join('');
  const clear = '<button type="button" class="dd-rt-fontopt" data-look-set="color" data-look-val="">Default</button>';
  return appearRow('Text color', popId, curHex, `<div class="dd-rt-swrow">${sw}</div>${clear}`);
}
function lookHlRow(popId: string, current: string | undefined): string {
  const curHex = current === undefined ? 'None' : RT_HL_COLORS.find((c) => c.k === current)?.hex ?? 'None';
  const sw = RT_HL_COLORS.map(
    (c) =>
      `<button type="button" class="dd-rt-sw${current === c.k ? ' dd-appear-sw-on' : ''}" data-look-set="hl" data-look-val="${c.k}" title="${c.hex}"><span class="dd-hl-${c.k}">A</span></button>`,
  ).join('');
  const clear = '<button type="button" class="dd-rt-fontopt" data-look-set="hl" data-look-val="">None</button>';
  return appearRow('Highlight', popId, curHex, `<div class="dd-rt-swrow">${sw}</div>${clear}`);
}

export function renderAppearance(draft: Appearance, category: string, error?: string, packText?: string): string {
  const cats = APPEARANCE_CATS.map((c) => {
    const on = c.id === category ? ' dd-appear-cat-active' : '';
    return (
      `<button type="button" class="dd-appear-cat${on}" data-appear-cat="${c.id}">` +
      `<span class="dd-appear-cat-label">${escapeHtml(c.label)}</span>` +
      `<span class="dd-appear-cat-blurb">${escapeHtml(c.blurb)}</span></button>`
    );
  }).join('');
  const t = draft.tokens;

  // The preview boxes, isolated from the SAVED look so the preview shows exactly what Save would apply:
  //  - .dd-appear-isolate: after render, every allowlisted token is set to 'initial' on it via the CSSOM
  //    (a guaranteed-invalid custom-property value), so the root's saved inline tokens and saved theme-class
  //    token values can NOT inherit into the preview; unset tokens fall to their stock var() fallbacks.
  //  - .dd-appear-themebox carries the DRAFT theme's class, so its token values and its
  //    .dd-appear-themebox.dd-theme-* surface rules apply inside (and the saved root class stays outside:
  //    the preview surfaces deliberately match no root-scoped theme selector like `.dd-theme-x .dd-tree`).
  //  - .dd-appear-preview gets the draft's own tokens via the CSSOM (they beat the theme's).
  const themeCls = THEME_CLASS[draft.theme];
  const wrap = (inner: string): string =>
    `<div class="dd-appear-isolate"><div class="dd-appear-themebox${themeCls === '' ? '' : ' ' + themeCls}">${inner}</div></div>`;
  const previewBl = wrap(
    '<div class="dd-appear-preview dd-appear-prevbl">' +
      '<div class="dd-apb dd-apb-enter"><span class="dd-status-dot dd-status-secure"></span>Entering Buddy</div>' +
      '<div class="dd-apb"><span class="dd-status-dot dd-status-secure"></span>Online Buddy</div>' +
      '<div class="dd-apb dd-apb-depart"><span class="dd-status-dot dd-status-blocked"></span>Departing Buddy</div>' +
      '</div>',
  );
  const previewMsg = wrap(
    '<div class="dd-appear-preview dd-appear-prevmsg">' +
      '<div class="dd-apm-sys">» channel established · forward secrecy active</div>' +
      '<div class="dd-apm-line"><span class="dd-apm-you">YOU:</span> the crow flies at midnight</div>' +
      '<div class="dd-apm-line"><span class="dd-apm-peer">RAVEN:</span> copy that. drop confirmed</div>' +
      '</div>',
  );

  let detail = '';
  if (category === 'buddylist') {
    detail =
      '<div class="dd-form-sub">Buddy List Font</div>' +
      appearFontRow('Font', 'bl-font', '--dd-buddy-font', t['--dd-buddy-font']) +
      appearSizeRow('Size', 'bl-size', '--dd-buddy-size', t['--dd-buddy-size']) +
      appearColorRow('Color', 'bl-color', '--dd-buddy-ink', t['--dd-buddy-ink']) +
      previewBl;
  } else if (category === 'message') {
    detail =
      '<div class="dd-form-sub">Message Font</div>' +
      appearFontRow('Font', 'msg-font', '--dd-font-msg', t['--dd-font-msg']) +
      appearSizeRow('Size', 'msg-size', '--dd-msg-user-size', t['--dd-msg-user-size']) +
      appearColorRow('Text', 'msg-ink', '--dd-ink', t['--dd-ink']) +
      appearColorRow('Background', 'msg-field', '--dd-field', t['--dd-field']) +
      appearColorRow('Accent', 'msg-accent', '--dd-secure', t['--dd-secure']) +
      previewMsg;
  } else if (category === 'mymessage') {
    // "My Message Look": the default style your OUTGOING messages carry to peers (font/color/size/highlight).
    // The preview renders a sample message exactly as it is wrapped + sent, so what you see is what they get.
    const look = draft.messageLook;
    const sample = formatMessageText(wrapMessageLook(look, escMarker('the eagle lands at midnight')));
    const previewMine = wrap(
      '<div class="dd-appear-preview dd-appear-prevmsg">' +
        '<div class="dd-apm-sys">» this is how your messages reach the people you talk with</div>' +
        `<div class="dd-apm-line"><span class="dd-apm-you">YOU:</span> ${sample}</div>` +
        '<div class="dd-apm-line"><span class="dd-apm-peer">RAVEN:</span> copy that. drop confirmed</div>' +
        '</div>',
    );
    detail =
      '<div class="dd-form-sub">My Message Look</div>' +
      '<div class="dd-form-sub dd-appear-note">The people you talk with see your messages in this style. You can still format single words while you type. Bold, italic, and underline stay per-message.</div>' +
      lookFontRow('my-font', look?.font) +
      lookSizeRow('my-size', look?.size) +
      lookColorRow('my-color', look?.color) +
      lookHlRow('my-hl', look?.hl) +
      previewMine;
  } else {
    // themes: whole looks + the pack import/export
    const cards = THEME_META.map((th) => {
      const on = th.id === draft.theme ? ' dd-appear-theme-active' : '';
      return (
        `<button type="button" class="dd-appear-theme${on}" data-appear-theme="${th.id}">` +
        `<span class="dd-appear-theme-name">${escapeHtml(th.label)}</span>` +
        `<span class="dd-appear-theme-blurb">${escapeHtml(th.blurb)}</span></button>`
      );
    }).join('');
    detail =
      `<div class="dd-appear-themes">${cards}</div>` +
      previewMsg +
      '<div class="dd-form-sub">Theme packs: a small JSON of validated tokens (no code, no external files).</div>' +
      '<textarea class="dd-appear-json" id="dd-appear-json" spellcheck="false" ' +
      `placeholder='{ "theme": "winamp", "tokens": { "--dd-ink": "#2be000" } }'>${escapeHtml(packText ?? '')}</textarea>` +
      '<div class="dd-appear-packbtns">' +
      '<button type="button" class="dd-btn" data-action="appear-import">Load pack</button>' +
      '<button type="button" class="dd-btn" data-action="appear-export">Export current</button>' +
      '<label class="dd-btn dd-appear-file">Load file<input type="file" id="dd-appear-file" accept="application/json,.json" /></label>' +
      '</div>';
  }

  const err = error !== undefined ? `<div class="dd-error">${escapeHtml(error)}</div>` : '';
  const footer =
    '<div class="dd-appear-foot">' +
    '<button type="button" class="dd-link" data-action="appear-reset">Reset to Default</button>' +
    '<span class="dd-appear-foot-btns">' +
    '<button type="button" class="dd-btn" data-action="appear-cancel">Cancel</button>' +
    '<button type="button" class="dd-btn dd-btn-primary" data-action="appear-save">Save</button>' +
    '</span></div>';
  return (
    '<div class="dd-appear-2pane">' +
    `<div class="dd-appear-cats">${cats}</div>` +
    `<div class="dd-appear-detail">${err}<div class="dd-appear-body">${detail}</div>${footer}</div>` +
    '</div>'
  );
}

function presenceDotClass(status: string | undefined): string {
  if (status === 'online') {
    return 'dd-status-secure';
  }
  if (status === 'idle' || status === 'away') {
    return 'dd-status-pending';
  }
  return 'dd-status-offline';
}

/** A buddy is "online" for the count/sort when we have a live status other than offline. */
function isBuddyOnline(status: string | undefined): boolean {
  return status === 'online' || status === 'away' || status === 'idle';
}
/** Sort rank so online buddies rise to the top of their group (online, away, idle, then offline). */
function statusRank(status: string | undefined): number {
  return status === 'online' ? 0 : status === 'away' ? 1 : status === 'idle' ? 2 : 3;
}
/** Order groups with the default group first, then the rest alphabetically. */
function orderedGroupNames(names: readonly string[]): string[] {
  return [...names].sort((a, b) =>
    a === DEFAULT_BUDDY_GROUP ? -1 : b === DEFAULT_BUDDY_GROUP ? 1 : a.localeCompare(b),
  );
}

// --- buddy list as an AIM-style tree: folders (groups) + plain buddy NAMES, with a "Blocked" drop -----
// The main Buddy List (renderBuddies) is READ-ONLY: buddies are names, not chunky buttons, and clicking a
// name opens a conversation. All add/remove/move and group create/delete live in Buddy List Setup
// (renderBuddySetup), reached from the DEAD DROP menu. Blocked contacts are their OWN group ("drop") at
// the bottom of the tree.

/** Label + reserved collapse key for the Blocked drop. The sentinel key keeps its collapse state separate
 * from a real group a user might happen to name "Blocked". */
const BLOCKED_GROUP_LABEL = 'Blocked';
const BLOCKED_COLLAPSE_KEY = ' blocked';

/** Where a selection lives in Buddy List Setup, so Delete knows what to remove. */
export interface BuddySetupSelection {
  /** 'gblocked' selects the built-in Blocked drop itself (renameable, never deletable); 'blocked'
   * selects one blocked contact inside it (Delete unblocks). */
  readonly type: 'group' | 'buddy' | 'blocked' | 'gblocked';
  readonly id: string;
}

/** The full, ordered set of group names to show: the default group, every synced group (so an EMPTY group
 * still appears), and every group a present buddy is filed under. Default first, then alphabetical. */
/** What the default group is currently CALLED (its internal key stays DEFAULT_BUDDY_GROUP). */
function defaultGroupLabel(groups: readonly GroupSummary[]): string {
  return groups.find((g) => g.role === 'default')?.name ?? DEFAULT_BUDDY_GROUP;
}

/** What the Blocked drop is currently called (blocks themselves live in the block list, not a group). */
function blockedGroupLabel(groups: readonly GroupSummary[]): string {
  return groups.find((g) => g.role === 'blocked')?.name ?? BLOCKED_GROUP_LABEL;
}

/** Render-time label for an INTERNAL group key: the default key shows its current display name. */
function groupLabelFor(internal: string, groups: readonly GroupSummary[]): string {
  return internal === DEFAULT_BUDDY_GROUP ? defaultGroupLabel(groups) : internal;
}

function allGroupOrder(buddies: readonly Buddy[], groups: readonly GroupSummary[]): string[] {
  const set = new Set<string>([DEFAULT_BUDDY_GROUP]);
  for (const g of groups) {
    // The built-in entries are labels, not storage keys: the default group is already seeded above under
    // its internal key, and Blocked renders as its own drop after the groups.
    if (g.role === undefined && g.name.length > 0) {
      set.add(g.name);
    }
  }
  for (const b of buddies) {
    set.add(b.group.length > 0 ? b.group : DEFAULT_BUDDY_GROUP);
  }
  return orderedGroupNames([...set]);
}

/** Bucket buddies by group name (empty group falls back to the default). */
function groupBuddies(buddies: readonly Buddy[]): Map<string, Buddy[]> {
  const grouped = new Map<string, Buddy[]>();
  for (const b of buddies) {
    const g = b.group.length > 0 ? b.group : DEFAULT_BUDDY_GROUP;
    const arr = grouped.get(g);
    if (arr !== undefined) {
      arr.push(b);
    } else {
      grouped.set(g, [b]);
    }
  }
  return grouped;
}

/** Buddies of a group sorted online-first (offline grayed but kept in place), tie-broken by name. */
function sortedMembers(members: readonly Buddy[], statuses: Record<string, string>): Buddy[] {
  return [...members].sort(
    (a, z) => statusRank(statuses[a.username]) - statusRank(statuses[z.username]) || a.username.localeCompare(z.username),
  );
}

/** One collapsible folder header in the tree: an open/closed folder, the name, and a count. `toggleKey` is
 * what the collapse handler stores (the group name, or the sentinel for the Blocked drop). */
function renderTreeGroupHeader(name: string, toggleKey: string, count: string, isCollapsed: boolean): string {
  return (
    `<button type="button" class="dd-tree-group" data-buddy-toggle="${escapeHtml(toggleKey)}" aria-expanded="${!isCollapsed}">` +
    `<span class="dd-tree-tri">${isCollapsed ? '▶' : '▼'}</span>` +
    `<span class="dd-tree-folder">${isCollapsed ? '\u{1F4C1}' : '\u{1F4C2}'}</span>` +
    `<span class="dd-tree-name">${escapeHtml(name)}</span>` +
    `<span class="dd-tree-count">${escapeHtml(count)}</span></button>`
  );
}

/** A deterministic placeholder icon for a buddy who never shared one: a GHOST (nobody has seen them
 * yet) on a palette color picked by hashing the username, so every device shows the same color without
 * storing anything. Never initials: handles are pseudonyms here, so rendering letters would suggest a
 * real-name convention the app deliberately avoids. The bg is always one of OUR palette entries, so the
 * CSS-class rendering stays CSP-safe. */
function buddyPlaceholderIcon(username: string): BuddyIcon {
  let h = 0;
  for (let i = 0; i < username.length; i++) {
    h = (h * 31 + username.charCodeAt(i)) >>> 0;
  }
  const bg = ICON_COLORS[h % ICON_COLORS.length] ?? ICON_COLORS[0] ?? '#2a52d6';
  return { kind: 'emoji', value: '\u{1F47B}', bg };
}

/** One SMALL buddy icon for a tree row (AIM-style). Same CSP rules as renderIconPreview: palette
 * backgrounds are CSS classes (never inline style), an unknown/peer-authored bg falls back to the first
 * palette entry, and an image icon is an <img> whose data: URL the CSP confines. */
function renderTreeBuddyIcon(icon: BuddyIcon | undefined, username: string): string {
  const ic = icon ?? buddyPlaceholderIcon(username);
  if (ic.kind === 'image') {
    return `<span class="dd-bic"><img class="dd-bic-img" src="${escapeHtml(ic.value)}" alt="" /></span>`;
  }
  const ch = ic.kind === 'emoji' ? ic.value : ic.value.slice(0, 2).toUpperCase();
  const idx = ICON_COLORS.indexOf(ic.bg);
  return `<span class="dd-bic dd-ic-${idx >= 0 ? idx : 0}">${escapeHtml(ch)}</span>`;
}

/** A short PLAIN-text preview of a rich away message for the ◆ dropdown: the format markers are
 * stripped (they would read as noise in a one-line menu item) and escapes unwrapped. */
function awayPreview(markers: string, maxLen = 26): string {
  // Strip the rich-text markers to a single plain line: the bold/italic toggles (* _), the bracket
  // markers ([c:..], [u], [z:N], [f:..], [img:..], closers), and backslash escapes (\* \[ …), so a
  // dropdown/subtitle preview reads as clean text. Walk char by char so an ESCAPED marker survives.
  let plain = '';
  for (let i = 0; i < markers.length; i++) {
    const c = markers[i]!;
    if (c === '\\' && i + 1 < markers.length) {
      plain += markers[i + 1]!; // \* \_ \[ \] \\ : the escaped literal
      i += 1;
      continue;
    }
    if (c === '*' || c === '_') {
      continue; // an unescaped bold/italic toggle
    }
    if (c === '[') {
      const close = markers.indexOf(']', i);
      if (close > i) {
        i = close; // drop the whole [..] marker (color/size/font/underline/image/closer)
        continue;
      }
    }
    plain += c;
  }
  plain = plain.replace(/\s+/g, ' ').trim();
  return plain.length > maxLen ? `${plain.slice(0, maxLen - 1)}…` : plain;
}

/** The AIM-style header at the top of the Buddy List: OUR buddy icon beside our handle, a little
 * DEAD DROP status control (click it to go Online or put up an away message, like the AIM running
 * man), and a talk bubble pointing back at the icon that boxes in the away message while away is on
 * (the profile text otherwise). The dropdown lists the SAVED away-message library (synced across your
 * devices with the identity card); with an empty library it falls back to a single Away toggle.
 * Everything shown here is already local (sealed under the MSK); setting a status saves through the
 * same path as the Away Message editor. */
/** The connection-status control (AIM26): a clickable headline (● SECURE LINK / ◐ SECURING… / …) with a
 * popover that explains the state in plain words. Filled by updateConnDisplay (textContent/CSSOM only, so
 * it is CSP-safe). It rides the far right of the buddy-list header; #dd-conn / #dd-conn-pop are the stable
 * hooks the display + click handlers target by id, so its location can move without touching that logic. */
function renderConnStatus(): string {
  return (
    '<span class="dd-blhead-conn">' +
    '<button type="button" class="dd-title-conn" id="dd-conn" aria-haspopup="true" title="connection details"></button>' +
    '<span class="dd-conn-pop" id="dd-conn-pop" hidden>' +
    '<span class="dd-connp-state"></span>' +
    '<span class="dd-connp-exp"></span>' +
    '<span class="dd-connp-gw"></span>' +
    '<span class="dd-connp-time"></span>' +
    '<button type="button" class="dd-btn dd-connp-now" data-action="conn-reconnect" hidden>Reconnect now</button>' +
    '</span></span>'
  );
}

function renderBuddyListHeader(profile: IdentityProfile, ownName: string): string {
  const away = profile.away.enabled;
  // The header bubble shows ONLY the away message, and ONLY while away. Online you are simply online: the
  // bubble stays blank (no profile/bio echoed here), matching AIM where the bubble is the away notice.
  const status = away && profile.away.message.length > 0
    ? `<div class="dd-blhead-status">${formatMessageText(profile.away.message)}</div>`
    : '';
  const savedList = profile.away.saved ?? [];
  const savedItems = savedList
    .map((msg, i) =>
      `<button type="button" class="dd-menu-dropitem" data-action="status-saved" data-saved-idx="${i}">` +
      `${away && profile.away.message === msg ? '✓ ' : ''}“${escapeHtml(awayPreview(msg))}”</button>`)
    .join('');
  // The status control reuses the app-menu dropdown look; the ◆ is the DEAD DROP mark, GREEN while
  // online (like an AIM presence light) and dimmed with a red caret while away. Order: Online, New
  // Away Message (write one; saving PUTS IT UP), then the saved library beneath it.
  const stButton =
    '<span class="dd-blhead-st">' +
    `<button type="button" class="dd-blhead-stbtn ${away ? 'dd-st-away' : 'dd-st-online'}" data-action="status-menu"` +
    ` title="set your status" aria-haspopup="true">◆<span class="dd-blhead-caret">▾</span></button>` +
    '<span class="dd-menu-dropdown dd-st-menu" id="dd-status-menu" hidden>' +
    `<button type="button" class="dd-menu-dropitem" data-action="status-online">${away ? '' : '✓ '}Online</button>` +
    '<button type="button" class="dd-menu-dropitem" data-action="status-edit-away">New Away Message</button>' +
    savedItems +
    '</span></span>';
  return (
    '<div class="dd-blhead">' +
    renderIconPreview(profile.icon) +
    `<div class="dd-blhead-txt"><div class="dd-blhead-name">${stButton}<span class="dd-blhead-handle">${escapeHtml(ownName)}</span></div>${status}</div>` +
    // The connection status sits at the far right of the header; the text column (flex:1, min-width:0)
    // shrinks first so this never overflows when the buddy list is resized narrow.
    renderConnStatus() +
    '</div>'
  );
}

/** One buddy as a plain NAME row in the read-only tree. It is a <button> only so it is keyboard-reachable;
 * it is styled as plain text, not a chunky button. Single-click SELECTS it (highlighted) for the bottom
 * toolbar; double-click opens a chat. */
function renderTreeBuddyName(b: Buddy, status: string | undefined, selected: boolean, icon?: BuddyIcon, signal?: 'on' | 'off', awayText?: string, verify?: BuddyVerifyBadge): string {
  const off = isBuddyOnline(status) ? '' : ' dd-tree-buddy-off';
  const sel = selected ? ' dd-tree-sel' : '';
  // A one-shot sign-on/sign-off flash (AIM-style): the row plays a brief highlight the render right
  // after a presence transition, then the class is gone so it never replays.
  const fx = signal === 'on' ? ' dd-tree-signon' : signal === 'off' ? ' dd-tree-signoff' : '';
  // AIM-style away subtitle: while a buddy's presence is AWAY, show a dim, single-line, plain-text preview
  // of their away MESSAGE (from the E2E cache) under their name; if they are away but shared no message,
  // show a plain "Away". The presence FLAG gates it, so a stale cached message never shows when online.
  const away = status === 'away';
  // A generous char cap; the CSS (.dd-tree-sub, ellipsis) does the visual truncation to the row width.
  const preview = away && awayText !== undefined && awayText.length > 0 ? awayPreview(awayText, 90) : '';
  const sub = away ? `<span class="dd-tree-sub">${preview.length > 0 ? escapeHtml(preview) : 'Away'}</span>` : '';
  // The verification badge: a quiet check for a pinned key, a loud warning when the key CHANGED under
  // a pinned one. Only verified buddies carry either; everyone else stays unadorned (no alarm fatigue).
  const badge = verify === 'verified'
    ? '<span class="dd-tree-verify" title="verified">\u2713</span>'
    : verify === 'changed'
      ? '<span class="dd-tree-verify dd-tree-verify-bad" title="identity changed">!</span>'
      : verify === 'stale'
        // Pinned but not checkable right now: a hollow marker, deliberately NOT the confident check.
        ? '<span class="dd-tree-verify dd-tree-verify-stale" title="verified earlier, cannot check right now">\u25cb</span>'
        : '';
  const nameCol = sub.length > 0
    ? `<span class="dd-tree-text"><span class="dd-tree-label">${escapeHtml(b.username)}${badge}</span>${sub}</span>`
    : `<span class="dd-tree-label">${escapeHtml(b.username)}${badge}</span>`;
  return (
    `<button type="button" class="dd-tree-buddy${off}${sel}${fx}${sub.length > 0 ? ' dd-tree-buddy-sub' : ''}" data-buddy-select="${escapeHtml(b.username)}" aria-pressed="${selected}">` +
    `<span class="dd-status-dot ${presenceDotClass(status)}"></span>` +
    renderTreeBuddyIcon(icon, b.username) +
    nameCol +
    '</button>'
  );
}

/** One SVG toolbar button (icon over an optional caption). `extra` adds state classes (e.g. the away
 * check color); `disabled` dims and blocks it. All coloring is by CSS class (no inline style, per CSP). */
function renderToolButton(action: string, label: string, svg: string, disabled: boolean, extra = ''): string {
  return (
    `<button type="button" class="dd-tbar-btn${extra.length > 0 ? ' ' + extra : ''}" data-action="${action}"` +
    (disabled ? ' disabled' : '') +
    ` title="${escapeHtml(label)}" aria-label="${escapeHtml(label)}">` +
    `<span class="dd-tbar-ico">${svg}</span>` +
    `<span class="dd-tbar-cap">${escapeHtml(label)}</span></button>`
  );
}

// Toolbar icons (inline SVG, colored via CSS `fill`; static markup so no escaping needed). Material-style.
const ICO_SEND = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M20 2H4a2 2 0 0 0-2 2v18l4-4h14a2 2 0 0 0 2-2V4a2 2 0 0 0-2-2zM7 9h10v2H7zm0 4h7v2H7z"/></svg>';
const ICO_GROUP = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M21 6h-2v9H6v2c0 .55.45 1 1 1h11l4 4V7c0-.55-.45-1-1-1zm-4 6V3c0-.55-.45-1-1-1H3c-.55 0-1 .45-1 1v14l4-4h10c.55 0 1-.45 1-1z"/></svg>';
const ICO_INFO = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-6h2v6zm0-8h-2V7h2v2z"/></svg>';
// A two-pane (list + chat) glyph for the buddy-list toolbar's Channels button — it mirrors the
// master-detail Channels screen (a narrow list column beside a wider conversation pane).
const ICO_CHANNELS = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 4h16a1 1 0 0 1 1 1v14a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V5a1 1 0 0 1 1-1zm1 2v12h4V6H5zm6 0v12h8V6h-8zm1 2h6v2h-6V8zm0 3h6v2h-6v-2z"/></svg>';
const ICO_GEAR = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M19.14 12.94c.04-.3.06-.61.06-.94 0-.32-.02-.64-.07-.94l2.03-1.58a.49.49 0 0 0 .12-.61l-1.92-3.32a.49.49 0 0 0-.59-.22l-2.39.96c-.5-.38-1.03-.7-1.62-.94l-.36-2.54a.48.48 0 0 0-.48-.41h-3.84a.48.48 0 0 0-.48.41l-.36 2.54c-.59.24-1.13.57-1.62.94l-2.39-.96a.48.48 0 0 0-.59.22L2.74 8.87a.48.48 0 0 0 .12.61l2.03 1.58c-.05.3-.09.63-.09.94s.02.64.07.94l-2.03 1.58a.49.49 0 0 0-.12.61l1.92 3.32c.12.22.37.29.59.22l2.39-.96c.5.38 1.03.7 1.62.94l.36 2.54c.05.24.24.41.48.41h3.84c.24 0 .44-.17.48-.41l.36-2.54c.59-.24 1.13-.56 1.62-.94l2.39.96c.22.08.47 0 .59-.22l1.92-3.32a.49.49 0 0 0-.12-.61l-2.01-1.58zM12 15.6a3.6 3.6 0 1 1 0-7.2 3.6 3.6 0 0 1 0 7.2z"/></svg>';

/** The bottom buddy-list toolbar (AIM-style): row 1 acts on the selected buddy/buddies (Send IM, Group
 * Chat, Buddy Info); row 2 opens the Profile editor and Buddy List Setup. The away message lives in the
 * header's ◆ status control now, so it no longer needs a toolbar slot. */
function renderBuddyToolbar(selectedCount: number): string {
  const one = selectedCount === 1;
  const any = selectedCount >= 1;
  return (
    '<div class="dd-tbar">' +
    '<div class="dd-tbar-row">' +
    renderToolButton('tbar-send-im', 'Send IM', ICO_SEND, !one) +
    renderToolButton('tbar-group-chat', 'Group Chat', ICO_GROUP, !any) +
    renderToolButton('tbar-channels', 'Channels', ICO_CHANNELS, false) +
    renderToolButton('tbar-info', 'Buddy Info', ICO_INFO, !one) +
    '</div>' +
    '<div class="dd-tbar-row">' +
    renderToolButton('tbar-profile', 'Profile', ICO_PROFILE, false, 'dd-tbar-wide') +
    renderToolButton('tbar-setup', 'Setup', ICO_GEAR, false, 'dd-tbar-wide') +
    '</div></div>'
  );
}

/** The presence + in-app-notification toggles (shared by the setup screen). */
function renderBuddyToggles(presenceOn: boolean, notifyOn: boolean): string {
  return (
    '<label class="dd-id-check"><input type="checkbox" id="dd-presence-toggle"' + (presenceOn ? ' checked' : '') +
    ' /> Share my status with buddies</label>' +
    (presenceOn
      ? '<div class="dd-form-note">Your online, away, and idle status is stored on the server and shown to ' +
        'buddies who look you up. The server can read it. Turn this off to keep your status to yourself.</div>'
      : '') +
    '<label class="dd-id-check"><input type="checkbox" id="dd-notify-toggle"' + (notifyOn ? ' checked' : '') +
    ' /> Notify me of new messages and sign-ons</label>'
  );
}

/** Buddy list (AIM-style tree): buddies filed into collapsible group folders shown as plain names, sorted
 * online-first, with a per-group online/total count. Blocked contacts appear as their own "Blocked" drop
 * at the bottom. This screen is read-only: clicking a name opens a chat; all editing is in Buddy List
 * Setup. `collapsed` is the set of collapsed group names (a per-tab UI preference the caller keeps). */
export function renderBuddies(
  buddies: readonly Buddy[],
  groups: readonly GroupSummary[],
  statuses: Record<string, string>,
  collapsed: readonly string[],
  blocked: readonly BlockedContact[],
  selected: readonly string[],
  profile: IdentityProfile,
  ownName: string,
  icons: Record<string, BuddyIcon>,
  awayText: Record<string, string> = {},
  error?: string,
  signals: Record<string, 'on' | 'off'> = {},
  verify: Record<string, BuddyVerifyBadge> = {},
): string {
  const err = error !== undefined ? `<div class="dd-form-error">${escapeHtml(error)}</div>` : '';
  const collapsedSet = new Set(collapsed);
  const selectedSet = new Set(selected);
  // A blocked buddy leaves its normal group and lives in the Blocked drop instead, so the list never
  // shows a blocked contact as messageable. Blocking records the buddy handle, which is what ties a
  // key-based block back to a username row here.
  const blockedNames = new Set(blocked.map((b) => b.username).filter((u): u is string => u !== undefined));
  const visible = buddies.filter((b) => !blockedNames.has(b.username));
  const grouped = groupBuddies(visible);
  const order = allGroupOrder(visible, groups);
  const groupNodes = order
    .map((g) => {
      const members = grouped.get(g) ?? [];
      const online = members.filter((b) => isBuddyOnline(statuses[b.username])).length;
      const isCollapsed = collapsedSet.has(g);
      const header = renderTreeGroupHeader(groupLabelFor(g, groups), g, `(${online}/${members.length})`, isCollapsed);
      if (isCollapsed) {
        return `<div class="dd-tree-node">${header}</div>`;
      }
      const kids = sortedMembers(members, statuses)
        .map((b) => renderTreeBuddyName(b, statuses[b.username], selectedSet.has(b.username), icons[b.username], signals[b.username], awayText[b.username], verify[b.username]))
        .join('');
      return `<div class="dd-tree-node">${header}<div class="dd-tree-kids">${kids}</div></div>`;
    })
    .join('');
  // The Blocked "drop": its own group at the bottom of the list (read-only here; unblock is in Setup).
  // ALWAYS present, even at (0), so there is a visible place blocked buddies land when you block one.
  const bc = collapsedSet.has(BLOCKED_COLLAPSE_KEY);
  const blockedHeader = renderTreeGroupHeader(blockedGroupLabel(groups), BLOCKED_COLLAPSE_KEY, `(${blocked.length})`, bc);
  const blockedKids = bc || blocked.length === 0
    ? ''
    : `<div class="dd-tree-kids">${blocked
        .map(
          (b) =>
            '<div class="dd-tree-buddy dd-tree-buddy-off">' +
            '<span class="dd-status-dot dd-status-blocked"></span>' +
            // The username when the block recorded one (a blocked buddy), the key fingerprint otherwise.
            `<span class="dd-tree-label">${b.username !== undefined ? escapeHtml(b.username) : `key ${escapeHtml(b.fingerprint)}`}</span></div>`,
        )
        .join('')}</div>`;
  const blockedNode = `<div class="dd-tree-node">${blockedHeader}${blockedKids}</div>`;
  const empty = buddies.length === 0 && groups.length === 0 && blocked.length === 0;
  const body = empty
    ? `<div class="dd-form-sub">no buddies yet</div><div class="dd-tree">${blockedNode}</div>`
    : `<div class="dd-tree">${groupNodes}${blockedNode}</div>`;
  const hint = '<div class="dd-form-note">Click a buddy to select. Add buddies and groups in Setup.</div>';
  // Selection count for the toolbar: only VISIBLE buddies (a stale or blocked selected name resolves to
  // 0 actions, so the toolbar cannot message a blocked contact).
  const present = new Set(visible.map((b) => b.username));
  const selectedCount = [...selectedSet].filter((u) => present.has(u)).length;
  const toolbar = renderBuddyToolbar(selectedCount);
  const head = renderBuddyListHeader(profile, ownName);
  // No in-body "BUDDY LIST" heading: the window titlebar already names the screen.
  return `<div class="dd-settings dd-buddies dd-buddytree">${head}${err}${body}${hint}${toolbar}</div>`;
}

/** Buddy List Setup: the management surface for the buddy list, reached from the DEAD DROP menu. A
 * selectable tree of groups, buddies, and blocked contacts, plus Add Buddy / Add Group / Delete and the
 * presence + notify toggles. Delete acts on the selected row (a buddy is removed, a group is deleted and
 * its buddies move back to Buddies, a blocked contact is unblocked); the default group cannot be deleted.
 * Add Buddy files the new buddy under the selected group. A buddy's group can also be changed inline. */
export function renderBuddySetup(
  buddies: readonly Buddy[],
  groups: readonly GroupSummary[],
  statuses: Record<string, string>,
  blocked: readonly BlockedContact[],
  presenceOn: boolean,
  notifyOn: boolean,
  selected: BuddySetupSelection | null,
  error?: string,
): string {
  const err = error !== undefined ? `<div class="dd-form-error">${escapeHtml(error)}</div>` : '';
  const toggle = renderBuddyToggles(presenceOn, notifyOn);
  const grouped = groupBuddies(buddies);
  const order = allGroupOrder(buddies, groups);
  const selGroup = selected !== null && selected.type === 'group' ? selected.id : null;
  const selBuddy = selected !== null && selected.type === 'buddy' ? selected.id : null;
  const selBlocked = selected !== null && selected.type === 'blocked' ? selected.id : null;
  const nodes = order
    .map((g) => {
      const members = grouped.get(g) ?? [];
      const groupSel = selGroup === g ? ' dd-tree-sel' : '';
      // data-setup-sel carries the INTERNAL key (the default group stays DEFAULT_BUDDY_GROUP no matter
      // what it is renamed to); only the visible name goes through the display label.
      const header =
        `<button type="button" class="dd-tree-group dd-tree-selectable${groupSel}" data-setup-sel="group:${escapeHtml(g)}">` +
        '<span class="dd-tree-folder">\u{1F4C2}</span>' +
        `<span class="dd-tree-name">${escapeHtml(groupLabelFor(g, groups))}</span>` +
        `<span class="dd-tree-count">(${members.length})</span></button>`;
      const kids = sortedMembers(members, statuses)
        .map((b) => {
          const bSel = selBuddy === b.username ? ' dd-tree-sel' : '';
          const opts = order
            .map((x) => `<option value="${escapeHtml(x)}"${x === b.group ? ' selected' : ''}>${escapeHtml(groupLabelFor(x, groups))}</option>`)
            .join('');
          return (
            '<div class="dd-setup-row">' +
            `<button type="button" class="dd-tree-buddy dd-tree-selectable${bSel}" data-setup-sel="buddy:${escapeHtml(b.username)}">` +
            `<span class="dd-status-dot ${presenceDotClass(statuses[b.username])}"></span>` +
            `<span class="dd-tree-label">${escapeHtml(b.username)}</span></button>` +
            `<select class="dd-buddy-group-sel" data-buddy-group="${escapeHtml(b.username)}" aria-label="group for ${escapeHtml(b.username)}">${opts}</select>` +
            '</div>'
          );
        })
        .join('');
      return `<div class="dd-tree-node">${header}<div class="dd-tree-kids">${kids}</div></div>`;
    })
    .join('');
  // The built-in Blocked drop is ALWAYS present (even empty), selectable so it can be renamed, and its
  // members auto-populate from the block list. Delete on the drop itself stays disabled (a built-in);
  // Delete on a selected member unblocks that contact.
  const gbSel = selected !== null && selected.type === 'gblocked' ? ' dd-tree-sel' : '';
  const blockedKids = blocked
    .map((b) => {
      const bSel = selBlocked === b.key ? ' dd-tree-sel' : '';
      // The username when the block recorded one (a blocked buddy), with the key fingerprint as the
      // trust anchor; a key-only block shows the fingerprint alone. Delete on a selected row unblocks.
      const label = b.username !== undefined
        ? `${escapeHtml(b.username)} <span class="dd-tree-count">key ${escapeHtml(b.fingerprint)}</span>`
        : `key ${escapeHtml(b.fingerprint)}`;
      return (
        '<div class="dd-setup-row">' +
        `<button type="button" class="dd-tree-buddy dd-tree-buddy-off dd-tree-selectable${bSel}" data-setup-sel="blocked:${escapeHtml(b.key)}">` +
        '<span class="dd-status-dot dd-status-blocked"></span>' +
        `<span class="dd-tree-label">${label}</span></button></div>`
      );
    })
    .join('');
  const blockedNode =
    '<div class="dd-tree-node">' +
    `<button type="button" class="dd-tree-group dd-tree-selectable${gbSel}" data-setup-sel="gblocked:">` +
    '<span class="dd-tree-folder">\u{1F6AB}</span>' +
    `<span class="dd-tree-name">${escapeHtml(blockedGroupLabel(groups))}</span>` +
    `<span class="dd-tree-count">(${blocked.length})</span></button>` +
    `<div class="dd-tree-kids">${blockedKids}</div></div>`;
  const tree = `<div class="dd-tree dd-setup-tree">${nodes}${blockedNode}</div>`;
  const addBuddy =
    '<div class="dd-field dd-setup-add">' +
    '<input class="dd-input" id="dd-setup-buddy-input" placeholder="add a buddy by username" aria-label="username" autocapitalize="none" spellcheck="false" />' +
    '<button class="dd-btn dd-setup-btn" data-action="setup-add-buddy">Add Buddy</button></div>';
  const addGroup =
    '<div class="dd-field dd-setup-add">' +
    '<input class="dd-input" id="dd-setup-group-input" placeholder="new group name" aria-label="new group name" />' +
    '<button class="dd-btn dd-setup-btn" data-action="setup-add-group">Add Group</button></div>';
  // Rename acts on the selected group, INCLUDING the two built-ins (which keep working under their new
  // name: new buddies still file into the default group, blocks still land in the Blocked drop).
  const renamable = selected !== null && (selected.type === 'group' || selected.type === 'gblocked');
  const rename =
    '<div class="dd-field dd-setup-add">' +
    '<input class="dd-input" id="dd-setup-rename-input" placeholder="rename selected group" aria-label="rename selected group" />' +
    `<button class="dd-btn dd-setup-btn" data-action="setup-rename"${renamable ? '' : ' disabled'}>Rename</button></div>`;
  // The two built-ins can never be deleted: the default group (buddies land there) and the Blocked drop
  // (blocks land there). Everything else deletes as before.
  const deletable =
    selected !== null &&
    selected.type !== 'gblocked' &&
    !(selected.type === 'group' && selected.id === DEFAULT_BUDDY_GROUP);
  const del =
    '<div class="dd-field"><button class="dd-btn dd-setup-btn dd-setup-delete" data-action="setup-delete"' +
    (deletable ? '' : ' disabled') +
    '>Delete</button></div>';
  const hint =
    '<div class="dd-form-note">Select a group, a buddy, or a blocked contact, then Delete. Deleting a ' +
    `group moves its buddies to ${escapeHtml(defaultGroupLabel(groups))}. Rename renames the selected group; ` +
    `${escapeHtml(defaultGroupLabel(groups))} and ${escapeHtml(blockedGroupLabel(groups))} are built in, so they can be renamed ` +
    'and never deleted. Add Buddy files the new buddy under the selected group. ' +
    'Nothing changes until you Save; Cancel forgets everything you did here.</div>';
  // Add a buddy by QR: scan their contact code, or show yours for them to scan. This is CONTACT exchange
  // (start a conversation), separate from device pairing under Device keys. Placed at the bottom, below
  // Delete, as an alternative to Add Buddy by username.
  const scan =
    '<div class="dd-field dd-setup-scan">' +
    '<button class="dd-btn dd-setup-btn" data-action="buddy-scan">Scan a buddy</button> ' +
    '<button class="dd-btn dd-setup-btn" data-action="buddy-showme">Scan me</button></div>';
  // Edits are a DRAFT until Save: Save applies every change and returns to the buddy list; Cancel
  // forgets the draft and returns without touching the stored list.
  const actions =
    '<div class="dd-field dd-form-actions dd-setup-actions">' +
    '<button class="dd-btn dd-btn-primary" data-action="setup-save">Save</button> ' +
    '<button class="dd-btn" data-action="setup-cancel">Cancel</button></div>';
  return `<div class="dd-settings dd-buddies dd-buddysetup"><div class="dd-form-title">BUDDY LIST SETUP</div>${err}${toggle}${tree}${addBuddy}${addGroup}${rename}${del}${scan}${hint}${actions}</div>`;
}

/** Scan a buddy: open the rear camera and read a buddy's contact QR (a `.../#dd=<user>` link), then start
 * a conversation with them. The video/canvas are wired imperatively by runCameraScan. Contact exchange,
 * NOT device pairing: this only opens a channel with another person, it never links a device. */
export function renderBuddyScan(): string {
  return (
    '<div class="dd-settings dd-buddies"><div class="dd-form-title">SCAN A BUDDY</div>' +
    '<div class="dd-scan"><video id="dd-scan-video" class="dd-scan-video" autoplay playsinline muted></video>' +
    '<canvas id="dd-scan-canvas" class="dd-scan-canvas"></canvas></div>' +
    '<div class="dd-form-sub">Point this camera at a buddy’s contact code (their Scan me screen, or their ' +
    'Profile QR) to start a conversation with them.</div>' +
    '<div class="dd-field"><button class="dd-btn" data-action="buddy-scan-cancel">Cancel</button></div></div>'
  );
}

/** Scan me: show this account’s contact QR (the same shareable link as the Profile screen) for a buddy
 * to scan with Scan a buddy. */
export function renderBuddyQr(link: string): string {
  let qr = '';
  try {
    qr = link !== '' ? qrSvg(link, 240) : '';
  } catch {
    qr = '';
  }
  const inner =
    qr !== ''
      ? `<div class="dd-scan"><div class="dd-qr">${qr}</div></div>` +
        '<div class="dd-form-sub">Have a buddy open Buddy list setup, choose Scan a buddy, and point their ' +
        'camera at this code to start a conversation with you.</div>'
      : '<div class="dd-form-error">Could not build your code here. Open your Profile to share your contact link instead.</div>';
  return (
    '<div class="dd-settings dd-buddies"><div class="dd-form-title">SCAN ME</div>' +
    inner +
    '<div class="dd-field"><button class="dd-btn" data-action="buddy-qr-back">Back</button></div></div>'
  );
}

/** Add-person screen: pull another account into the open conversation by username (a group chat). */
export function renderAddPerson(error?: string): string {
  const err = error !== undefined ? `<div class="dd-form-error">${escapeHtml(error)}</div>` : '';
  return (
    '<div class="dd-form">' +
    '<div class="dd-form-title">ADD PERSON</div>' +
    '<div class="dd-form-sub">add another person to this conversation by username</div>' +
    '<input class="dd-input" id="dd-addperson-input" placeholder="their username" aria-label="username" autocapitalize="none" spellcheck="false" />' +
    err +
    '<div class="dd-field"><button class="dd-btn dd-btn-primary" data-action="addperson-submit">Add</button> ' +
    '<button class="dd-btn" data-action="addperson-cancel">Cancel</button></div>' +
    '<div class="dd-form-note">Everyone in a conversation sees each other and every message. A person you add ' +
    'can read messages sent from now on. They cannot read the earlier ones. All of their devices join the ' +
    'group, and the first time you see their devices is trust on first use, so confirm their fingerprint ' +
    'through a channel you already trust.</div>' +
    '</div>'
  );
}

/** A short fingerprint of a device key for recognition (first 4 bytes), mirroring live.fingerprintOf. */
function deviceFp(hex: string): string {
  return [0, 2, 4, 6].map((i) => hex.slice(i, i + 2).toUpperCase()).join('·');
}

/** Format a unix-seconds timestamp as a short local date, or 'unknown' when absent. */
function shortDate(unixSeconds: number): string {
  if (unixSeconds <= 0) {
    return 'unknown';
  }
  const d = new Date(unixSeconds * 1000);
  const m = String(d.getMonth() + 1).padStart(2, '0');
  const day = String(d.getDate()).padStart(2, '0');
  return `${d.getFullYear()}-${m}-${day}`;
}

function renderDeviceRow(d: DeviceInfo, currentDeviceKey: string, hasOtherAuthorized: boolean, pending?: string): string {
  const isCurrent = d.deviceKey === currentDeviceKey;
  const status = d.revoked ? 'blocked' : isCurrent ? 'secure' : 'pending';
  const pill = isCurrent ? '<span class="dd-badge">THIS DEVICE</span>' : '';
  const state = d.revoked ? 'revoked' : 'active';
  let action: string;
  if (d.revoked) {
    action = '<span class="dd-channel-meta">revoked</span>';
  } else if (isCurrent && !hasOtherAuthorized) {
    // Your only device: revoking yourself is not allowed (you would lock yourself out with no way back).
    // Self Destruct is the way to remove the account entirely.
    action = '<span class="dd-channel-meta">signed in here · your only device. Use Self Destruct to remove your account.</span>';
  } else if (pending === d.deviceId) {
    // Only another device reaches the inline confirm; revoking THIS device uses the dedicated screen.
    action =
      '<span class="dd-confirm">Revoke this device? ' +
      `<button class="dd-btn dd-btn-danger" data-action="revoke-confirm" data-device="${escapeHtml(d.deviceId)}">Revoke</button> ` +
      '<button class="dd-btn" data-action="revoke-cancel">Cancel</button></span>';
  } else {
    action = `<button class="dd-btn" data-action="revoke-device" data-device="${escapeHtml(d.deviceId)}">${isCurrent ? 'Revoke this device' : 'Revoke'}</button>`;
  }
  return (
    `<div class="dd-channel" data-status="${status}">` +
    `<div class="dd-channel-top"><span class="dd-status-dot dd-status-${status}"></span>` +
    `<span class="dd-channel-name">key ${escapeHtml(deviceFp(d.deviceKey))}</span>${pill}</div>` +
    `<div class="dd-channel-meta">added ${escapeHtml(shortDate(d.addedAt))} · last seen ${escapeHtml(shortDate(d.lastSeenAt))} · ${state}</div>` +
    `<div class="dd-device-actions">${action}</div>` +
    '</div>'
  );
}

/** Settings → Devices screen: list the account's devices and revoke any that is not this one. */
/** The history-off control. Turning it ON destroys what is already stored on this device, so it is a
 * two-tap action: the first tap says exactly what will be lost, the second does it. */
function renderHistoryToggle(on: boolean, armed: boolean): string {
  const state = on
    ? '<div class="dd-verify-title">Messages are not being saved</div>' +
      '<div class="dd-form-note">This device keeps messages in memory only. They are gone when you sign ' +
      'out, reload, or close the app, and nothing about them is written to disk. Your account, your ' +
      'buddy list and your conversations themselves are still saved, so you stay reachable.</div>' +
      '<div class="dd-field"><button class="dd-btn" data-action="history-on">Start saving messages again</button></div>'
    : '<div class="dd-verify-title">Message history</div>' +
      '<div class="dd-form-note">Messages you send and receive are saved on this device, encrypted under ' +
      'your passphrase, until their lifetimes end. Turn that off to keep them in memory only for as long ' +
      'as the app is open.</div>' +
      `<div class="dd-field"><button class="dd-btn${armed ? ' dd-btn-danger' : ''}" data-action="history-off">${
        armed ? 'Tap again: this erases the messages stored here' : 'Stop saving messages'
      }</button></div>`;
  return `<div class="dd-verify${on ? ' dd-verify-ok' : ''}">${state}</div>`;
}

export function renderSettings(
  devices: readonly DeviceInfo[],
  currentDeviceKey: string,
  pending?: string,
  error?: string,
  historyOff?: boolean,
  historyArm?: boolean,
): string {
  const err = error !== undefined ? `<div class="dd-form-error">${escapeHtml(error)}</div>` : '';
  // A centered Back button returns to the buddy list from either state (Device keys is reached from the
  // DEAD DROP menu, and the buddy list is home).
  const back = '<div class="dd-field dd-form-actions"><button class="dd-btn" data-action="settings-back">Back</button></div>';
  if (devices.length === 0) {
    // No in-body "DEVICE KEYS" heading: the window titlebar already names the screen.
    return (
      '<div class="dd-form">' +
      err +
      '<div class="dd-form-sub">no devices to show</div>' +
      '<div class="dd-field dd-form-actions"><button class="dd-btn dd-btn-primary" data-action="devices-retry">Retry</button></div>' +
      back +
      '</div>'
    );
  }
  const activeCount = devices.filter((d) => !d.revoked).length;
  // The last-device guard blocks revoking the CURRENT device only when there is no OTHER AUTHORIZED device
  // (one that has published a key package), so an unauthorized orphan can no longer inflate the count and
  // let you strand yourself. Fallback: an old server without the `authorized` field falls back to the
  // legacy active count so the guard still functions during a deploy skew.
  const authorizedKnown = devices.some((d) => d.authorized);
  const hasOtherAuthorized = authorizedKnown
    ? devices.some((d) => !d.revoked && d.authorized && d.deviceKey !== currentDeviceKey)
    : activeCount > 1;
  // Show only active devices. A revoked device's row is hidden here, but its record is kept everywhere
  // else it matters: the server tombstone keeps the key burned (so it can never re-enroll) and the
  // revoked count still drives the anti-rollback epoch floor. We hide the row, we do not delete the key.
  const rows = devices
    .filter((d) => !d.revoked)
    .map((d) => renderDeviceRow(d, currentDeviceKey, hasOtherAuthorized, pending))
    .join('');
  const history = renderHistoryToggle(historyOff === true, historyArm === true);
  const actions =
    history +
    '<div class="dd-field">' +
    '<button class="dd-btn dd-btn-primary" data-action="scan-device">Scan a device</button> ' +
    '<button class="dd-btn dd-btn-primary" data-action="show-device-qr">Show this device</button>' +
    '</div>' +
    '<div class="dd-field">' +
    '<button class="dd-btn" data-action="add-device">Add a device (six words)</button> ' +
    '<button class="dd-btn" data-action="connect-this-device">Connect this device (six words)</button> ' +
    '<button class="dd-btn" data-action="use-recovery">Use recovery secret</button>' +
    '</div>' +
    '<div class="dd-form-note">To add another device with a QR: on the device you already use choose Scan ' +
    'a device, on the new one choose Show this device, then point the first camera at the second code. If ' +
    'a camera is not available, use the six-word options instead. On a device that has your recovery ' +
    'secret, choose Use recovery secret.</div>';
  const note =
    '<div class="dd-form-note">Revoking a device removes its key from your directory so peers stop ' +
    'addressing new messages to it, and stops it from signing in again. It cannot reach into a device ' +
    'that already holds your messages or erase them, and it does not wipe the device.</div>';
  // No in-body "DEVICE KEYS" heading: the window titlebar already names the screen.
  return `<div class="dd-settings">${err}${actions}<div class="dd-list">${rows}</div>${note}${back}</div>`;
}

/** Self Destruct confirmation: enter the passphrase twice to permanently erase the account. A
 * deliberately heavy, irreversible action, so the copy is blunt and the button is a danger button. */
export function renderSelfDestruct(error?: string): string {
  const err = error !== undefined ? `<div class="dd-form-error">${escapeHtml(error)}</div>` : '';
  return (
    '<form class="dd-form" id="dd-destruct-form" autocomplete="off">' +
    '<div class="dd-form-title">☠️ SELF DESTRUCT ☠️</div>' +
    '<div class="dd-form-sub">this permanently erases your account and everything in it</div>' +
    '<div class="dd-form-note">Your account, all of your devices, and all of your data are deleted from ' +
    'the server, and this device is wiped clean. This cannot be undone, and nobody can bring any of it ' +
    'back. Your other devices lose access too. Enter your passphrase twice to confirm.</div>' +
    '<div class="dd-stack">' +
    '<input class="dd-input" id="dd-destruct-pass" type="password" placeholder="passphrase" aria-label="passphrase" />' +
    '<input class="dd-input" id="dd-destruct-pass2" type="password" placeholder="passphrase again" aria-label="repeat passphrase" />' +
    '<button class="dd-btn dd-btn-danger" type="submit">Erase everything</button> ' +
    '<button class="dd-btn" type="button" data-action="destruct-cancel">Cancel</button>' +
    '</div>' +
    err +
    '</form>'
  );
}

/** Confirm revoking THIS device (the one you are using). A deliberate step, separate from revoking
 * another device, because it signs you out here. */
export function renderRevokeSelf(deviceId: string, error?: string): string {
  const err = error !== undefined ? `<div class="dd-form-error">${escapeHtml(error)}</div>` : '';
  return (
    '<div class="dd-form">' +
    '<div class="dd-form-title">REVOKE THIS DEVICE</div>' +
    '<div class="dd-form-sub">you are about to revoke the device you are using right now</div>' +
    '<div class="dd-form-note">This signs you out here and burns this device\'s key, so it can no longer ' +
    'reach your account. To use this device again you would re-add it from another device or with your ' +
    'recovery secret. Your account and your other devices keep working. This cannot be undone.</div>' +
    '<div class="dd-field">' +
    `<button class="dd-btn dd-btn-danger" data-action="revokeself-confirm" data-device="${escapeHtml(deviceId)}">Revoke this device</button> ` +
    '<button class="dd-btn" data-action="revokeself-cancel">Cancel</button>' +
    '</div>' +
    err +
    '</div>'
  );
}

// Identity (buddy icon, profile, away message). A small retro palette of emoji + colors keeps the
// common path tiny enough to ride the smallest padding bucket (no on-wire size signal); an uploaded
// image is offered with a plain disclosure that its size is detectable.
// A single balanced row of icons (owl, fox, moon, star, key, ghost): few enough to fit one row beside
// the color swatches at the window width, so the palette never wraps to a ragged second row.
const ICON_EMOJI: readonly string[] = ['\u{1F989}', '\u{1F98A}', '\u{1F311}', '⭐', '\u{1F511}', '\u{1F47B}'];
const ICON_COLORS: readonly string[] = ['#2a52d6', '#1f9d6b', '#b0431f', '#6b3fb0', '#0b7d8e', '#8e7a0b', '#444a5e'];

// No app-provided emoji picker: the editors are plain contenteditables, so the DEVICE-NATIVE emoji
// input works everywhere with the FULL emoji set (the mobile keyboard's emoji pane; Cmd+Ctrl+Space
// on macOS; Win+. on Windows). A curated in-app grid only limited what people could pick.

/** The compose ⏳ picker's choices: how long the recipient can read the message (§3.2 lifetimes; the
 * durations mirror SUGGESTED_DURATIONS_SECONDS). The policy is encoded inside the E2E payload and
 * enforced by the recipient's storage layer. Every kind offered here IS enforced end to end: durations
 * arm on first view (hold-until-seen) and crypto-erase on the timer; burn-on-read destroys the stored
 * key in the same step its first view is rendered (LifetimeManager.openBurnOnRead in openChannel);
 * until-revoked messages carry a revoke control that crypto-erases every member device's stored copy
 * (GroupChannel revoke frames -> LifetimeManager.revoke). */
const RT_LIFETIMES: ReadonlyArray<{ readonly v: string; readonly label: string; readonly short: string }> = [
  { v: 'burn', label: 'Burn on read', short: 'burn' },
  { v: '5', label: '5 seconds', short: '5s' },
  { v: '30', label: '30 seconds', short: '30s' },
  { v: '300', label: '5 minutes', short: '5m' },
  { v: '3600', label: '1 hour', short: '1h' },
  { v: '86400', label: '24 hours', short: '24h' },
  // 'keep' is the protocol's until-revoked kind: the message NEVER expires on its own; the sender can
  // still destroy every stored copy later with its revoke control. Labeled by what the user asked for.
  { v: 'keep', label: 'Never (revocable)', short: '∞' },
];
function lifetimeFromValue(v: string): Lifetime {
  if (v === 'burn') {
    return { kind: 'burn-on-read' };
  }
  if (v === 'keep') {
    return { kind: 'until-revoked' };
  }
  const seconds = Number(v);
  return { kind: 'duration', seconds: Number.isFinite(seconds) && seconds > 0 ? seconds : 86400 };
}
function lifetimeValue(l: Lifetime): string {
  return l.kind === 'burn-on-read' ? 'burn' : l.kind === 'until-revoked' ? 'keep' : String(l.seconds);
}
function lifetimeShort(l: Lifetime): string {
  return RT_LIFETIMES.find((o) => o.v === lifetimeValue(l))?.short ?? lifetimeValue(l);
}
/** The lifetime the NEXT sent message carries, PER CONVERSATION. Module state (not view state) so it
 * survives the full re-render every send triggers, and so the pure render functions can show the
 * current pick. Scoped by conversation so picking Burn on read in one chat can never quietly make a
 * later message in a different chat ephemeral; a conversation you never touched keeps the 24h
 * default. */
const DEFAULT_COMPOSE_LIFETIME: Lifetime = { kind: 'duration', seconds: 86400 };
const composeLifetimes = new Map<string, Lifetime>();
/** The conversation the rendered compose belongs to; set by renderTransmit (the toolbar renderers are
 * pure string builders with no model access, so they read the pick through this). */
let composeConvId = '';
function composeLifetime(): Lifetime {
  return composeLifetimes.get(composeConvId) ?? DEFAULT_COMPOSE_LIFETIME;
}

/** A toolbar dropdown: a trigger button and a hidden popup panel. */
function rtPop(id: string, label: string, body: string, title: string): string {
  return (
    `<span class="dd-rt-popwrap dd-rt-popwrap-${id}">` +
    `<button type="button" class="dd-rt-btn dd-rt-popbtn" data-rt-pop="${id}" title="${escapeHtml(title)}" aria-label="${escapeHtml(title)}">${label}<span class="dd-rt-caret">▾</span></button>` +
    `<span class="dd-rt-pop" data-rt-popid="${id}" hidden>${body}</span>` +
    '</span>'
  );
}

/** The AIM-style formatting toolbar: text color, highlight, three sizes, bold/italic/underline, font, and
 * an emoji dialog (in that order). Color/highlight/font are fixed palettes applied as CSS classes, and
 * size/B/I/U use execCommand with tag output, so EVERY format renders WITHOUT an inline style and survives
 * the strict `style-src 'self'` CSP. */
// The insert-image control (compose only): a small framed-picture glyph. Clicking it opens a file picker;
// the chosen image is downscaled to fit one encrypted message and inserted inline (see prepareInlineImage).
const ICO_IMG = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M21 19V5c0-1.1-.9-2-2-2H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2zM8.5 13.5l2.5 3.01L14.5 12l4.5 6H5l3.5-4.5z"/></svg>';

function renderRichToolbar(opts: { timer?: boolean; images?: boolean } = {}): string {
  const textSw = RT_TEXT_COLORS.map(
    (c) => `<button type="button" class="dd-rt-sw" data-rt-color="${c.k}" title="text color"><span class="dd-c-${c.k}">A</span></button>`,
  ).join('');
  // Same structure as the text-color swatches: the sample rides an inner span so the button keeps the
  // shared .dd-rt-sw chrome (the dd-hl-K class directly on the button used to stomp its background,
  // radius, and padding, making the two dropdowns look unrelated).
  const hlSw = RT_HL_COLORS.map(
    (c) => `<button type="button" class="dd-rt-sw" data-rt-hl="${c.k}" title="highlight"><span class="dd-hl-${c.k}">A</span></button>`,
  ).join('');
  const fontOpts =
    '<button type="button" class="dd-rt-fontopt" data-rt-font="" title="default font">Default</button>' +
    RT_FONTS.map((f) => `<button type="button" class="dd-rt-fontopt dd-ft-${f.k}" data-rt-font="${f.k}">${escapeHtml(f.label)}</button>`).join('');
  // The message-lifetime picker (compose only): how long the recipient can read this message. The
  // policy rides INSIDE the encrypted payload; the current pick shows on the ⏳ trigger.
  const lifeOpts = RT_LIFETIMES
    .map((o) => `<button type="button" class="dd-rt-fontopt dd-rt-lifeopt" data-rt-life="${o.v}">${lifetimeValue(composeLifetime()) === o.v ? '✓ ' : ''}${o.label}</button>`)
    .join('');
  // The lifetime picker LEADS the toolbar (it decides how long the whole message lives, so it reads
  // before the styling controls), with its separator trailing so the bar stays one visual run.
  const timer = opts.timer === true
    ? rtPop('timer', `<span class="dd-rt-life-cur">⏳${escapeHtml(lifetimeShort(composeLifetime()))}</span>`, `<div class="dd-rt-fonts dd-rt-lifetimes">${lifeOpts}</div>`, 'message lifetime') +
      '<span class="dd-rt-sep"></span>'
    : '';
  return (
    '<div class="dd-rt-bar">' +
    timer +
    rtPop('color', '<span class="dd-rt-A">A</span>', `<div class="dd-rt-swrow">${textSw}</div>`, 'text color') +
    rtPop('hl', '<span class="dd-rt-A dd-rt-A-hl">A</span>', `<div class="dd-rt-swrow">${hlSw}</div>`, 'highlight color') +
    '<span class="dd-rt-sep"></span>' +
    '<button type="button" class="dd-rt-btn" data-rt-size="s" title="smaller"><span class="dd-rt-A dd-rt-A-sm">A</span></button>' +
    '<button type="button" class="dd-rt-btn" data-rt-size="d" title="default size"><span class="dd-rt-A">A</span></button>' +
    '<button type="button" class="dd-rt-btn" data-rt-size="l" title="larger"><span class="dd-rt-A dd-rt-A-lg">A</span></button>' +
    '<span class="dd-rt-sep"></span>' +
    '<button type="button" class="dd-rt-btn" data-rt-cmd="bold" title="bold"><strong>B</strong></button>' +
    '<button type="button" class="dd-rt-btn" data-rt-cmd="italic" title="italic"><em>I</em></button>' +
    '<button type="button" class="dd-rt-btn" data-rt-cmd="underline" title="underline"><u>U</u></button>' +
    '<span class="dd-rt-sep"></span>' +
    rtPop('font', '<span class="dd-rt-Ff">F</span>', `<div class="dd-rt-fonts">${fontOpts}</div>`, 'font') +
    (opts.images === true
      ? '<span class="dd-rt-sep"></span>' +
        `<button type="button" class="dd-rt-btn dd-rt-imgbtn" data-rt-img title="insert image" aria-label="insert image">${ICO_IMG}</button>`
      : '') +
    '</div>'
  );
}

/** A WYSIWYG rich-text field: the toolbar plus a contenteditable seeded with the saved marker text rendered
 * as (CSP-safe) HTML, so existing formatting shows up formatted. `id` identifies the editable; the caller
 * reads it back on save/send with `serializeRichText`. */
function renderRichEditor(id: string, markers: string, opts: { placeholder?: string; oneLine?: boolean; tall?: boolean; timer?: boolean; prompt?: boolean; images?: boolean } = {}): string {
  const ph = opts.placeholder !== undefined ? ` data-rt-ph="${escapeHtml(opts.placeholder)}"` : '';
  const one = opts.oneLine === true ? ' dd-rt-edit-1' : '';
  const tall = opts.tall === true ? ' dd-rt-edit-tall' : '';
  // Images render only in the editors that accept them (the message compose), never in profile/away text.
  const edit = `<div class="dd-rt-edit${one}${tall}" id="${escapeHtml(id)}" contenteditable="true" role="textbox" aria-multiline="${opts.oneLine === true ? 'false' : 'true'}"${ph}>${formatMessageText(markers, { images: opts.images === true })}</div>`;
  // The compose variant leads the editable with the terminal's › prompt, so typing reads like the CRT
  // prompt line (the box itself is styled flat/transparent by the transmit skin).
  const body = opts.prompt === true ? `<div class="dd-rt-line"><span class="dd-prompt">&rsaquo;</span>${edit}</div>` : edit;
  return (
    '<div class="dd-rt">' +
    renderRichToolbar({ ...(opts.timer === true ? { timer: true } : {}), ...(opts.images === true ? { images: true } : {}) }) +
    body +
    '</div>'
  );
}

/** Wrap the current selection inside the editor in a class span (the CSP-safe way to apply color, highlight,
 * or font). No-op when the selection is empty or outside the editor. */
function wrapSelectionClass(editor: HTMLElement, cls: string): void {
  const sel = window.getSelection();
  if (sel === null || sel.rangeCount === 0) {
    return;
  }
  const range = sel.getRangeAt(0);
  if (!editor.contains(range.commonAncestorContainer)) {
    return;
  }
  const span = document.createElement('span');
  span.className = cls;
  if (range.collapsed) {
    // No selection: begin a styled run at the caret so the NEXT text you type takes the style, the way
    // picking a color then typing works in AIM (before, picking a color with nothing selected did nothing,
    // so the picker looked broken). A zero-width space holds the caret inside the otherwise-empty span;
    // serializeRichText strips it, so it never reaches the stored or sent text.
    span.textContent = String.fromCharCode(0x200b); // zero-width space
    range.insertNode(span);
    const caret = document.createRange();
    caret.setStart(span.firstChild!, 1);
    caret.collapse(true);
    sel.removeAllRanges();
    sel.addRange(caret);
    return;
  }
  try {
    span.appendChild(range.extractContents());
    range.insertNode(span);
    sel.removeAllRanges();
    const r = document.createRange();
    r.selectNodeContents(span);
    sel.addRange(r);
  } catch {
    /* a selection spanning element boundaries can refuse extraction: leave the text unchanged */
  }
}

/** Toggle an inline formatting tag (bold/italic/underline) on the selection with plain DOM operations,
 * so it behaves identically in every browser. Safari's execCommand is unreliable once the selection sits
 * inside nested class spans (a color + font + italic run), which is why clicking Bold on already-styled
 * text could do nothing there; wrapping the selection ourselves is deterministic. CSP-safe: it emits the
 * same <b>/<i>/<u> tags the serializer already understands (no inline styles). */
function toggleInlineTag(editor: HTMLElement, tag: 'b' | 'i' | 'u'): void {
  const sel = window.getSelection();
  if (sel === null || sel.rangeCount === 0) {
    return;
  }
  const range = sel.getRangeAt(0);
  if (!editor.contains(range.commonAncestorContainer)) {
    return;
  }
  const tags = tag === 'b' ? ['b', 'strong'] : tag === 'i' ? ['i', 'em'] : ['u'];
  const wrappingTag = (node: Node): HTMLElement | null => {
    let n: Node | null = node instanceof Element ? node : node.parentElement;
    while (n !== null && n !== editor && n instanceof HTMLElement) {
      if (tags.includes(n.tagName.toLowerCase())) {
        return n;
      }
      n = n.parentElement;
    }
    return null;
  };
  const stripped = (n: Node): string => (n.textContent ?? '').replace(/\u200b/g, '');
  if (range.collapsed) {
    // If the caret already sits in an EMPTY holder of this tag (only the zero-width caret-holder, no real
    // text), a second click toggles the format OFF: remove the holder instead of nesting a second one
    // inside it (which would serialize to doubled markers that render unformatted).
    const holder = wrappingTag(range.startContainer);
    if (holder !== null && holder.parentNode !== null && stripped(holder) === '') {
      const parent = holder.parentNode;
      const at = document.createRange();
      at.setStartBefore(holder);
      at.collapse(true);
      parent.removeChild(holder);
      sel.removeAllRanges();
      sel.addRange(at);
      return;
    }
    // Otherwise begin a run of this format so the NEXT text typed takes it (matches the color/font caret
    // behavior). The zero-width caret-holder is stripped on serialize.
    const el = document.createElement(tag);
    el.appendChild(document.createTextNode(String.fromCharCode(0x200b)));
    range.insertNode(el);
    const caret = document.createRange();
    caret.setStart(el.firstChild!, 1);
    caret.collapse(true);
    sel.removeAllRanges();
    sel.addRange(caret);
    return;
  }
  // The selection sits inside ONE matching tag: toggle the format OFF. Only the SELECTED span loses the
  // tag; text before/after the selection inside the same wrapper stays formatted (so un-bolding one word
  // does not un-bold the rest of the run). When the selection covers the whole wrapper this reduces to a
  // plain unwrap. Descendants of the wrapper that lie between the selection ends but are not direct text
  // children (partially-selected nested formatting) fall through to the whole-wrapper unwrap below.
  const startW = wrappingTag(range.startContainer);
  if (startW !== null && startW === wrappingTag(range.endContainer) && startW.parentNode !== null) {
    const parent = startW.parentNode;
    const flat = (n: Node): boolean => n === startW || n.parentNode === startW;
    if (flat(range.startContainer) && flat(range.endContainer)) {
      const doc = editor.ownerDocument;
      const beforeR = doc.createRange();
      beforeR.selectNodeContents(startW);
      beforeR.setEnd(range.startContainer, range.startOffset);
      const beforeFrag = beforeR.cloneContents();
      const afterR = doc.createRange();
      afterR.selectNodeContents(startW);
      afterR.setStart(range.endContainer, range.endOffset);
      const afterFrag = afterR.cloneContents();
      const midFrag = range.cloneContents();
      // Flatten any fully-selected same-tag descendants so the unwrapped middle never keeps the format.
      midFrag.querySelectorAll(tags.join(',')).forEach((m) => {
        while (m.firstChild !== null) {
          m.parentNode?.insertBefore(m.firstChild, m);
        }
        m.remove();
      });
      const out = doc.createDocumentFragment();
      const hasText = (f: DocumentFragment): boolean => (f.textContent ?? '').replace(/\u200b/g, '').length > 0;
      if (hasText(beforeFrag)) {
        const b = doc.createElement(tag);
        b.appendChild(beforeFrag);
        out.appendChild(b);
      }
      const startMark = doc.createTextNode('');
      const endMark = doc.createTextNode('');
      out.appendChild(startMark);
      out.appendChild(midFrag);
      out.appendChild(endMark);
      if (hasText(afterFrag)) {
        const a = doc.createElement(tag);
        a.appendChild(afterFrag);
        out.appendChild(a);
      }
      parent.replaceChild(out, startW);
      const r = doc.createRange();
      r.setStartAfter(startMark);
      r.setEndBefore(endMark);
      sel.removeAllRanges();
      sel.addRange(r);
      return;
    }
    const frag = document.createDocumentFragment();
    const first = startW.firstChild;
    const last = startW.lastChild;
    while (startW.firstChild !== null) {
      frag.appendChild(startW.firstChild);
    }
    parent.replaceChild(frag, startW);
    if (first !== null && last !== null) {
      const r = document.createRange();
      r.setStartBefore(first);
      r.setEndAfter(last);
      sel.removeAllRanges();
      sel.addRange(r);
    }
    return;
  }
  // Otherwise wrap the selection, first flattening any same-format descendants so it never doubles up.
  const el = document.createElement(tag);
  try {
    const contents = range.extractContents();
    contents.querySelectorAll(tags.join(',')).forEach((m) => {
      while (m.firstChild !== null) {
        m.parentNode?.insertBefore(m.firstChild, m);
      }
      m.remove();
    });
    el.appendChild(contents);
    range.insertNode(el);
    sel.removeAllRanges();
    const r = document.createRange();
    r.selectNodeContents(el);
    sel.addRange(r);
  } catch {
    /* a selection crossing element boundaries can refuse extraction: leave the text unchanged */
  }
}

function closeRtPops(rt: HTMLElement): void {
  rt.querySelectorAll('[data-rt-popid]').forEach((p) => {
    if (p instanceof HTMLElement) {
      p.hidden = true;
    }
  });
}

/** The current font-size level per editor, on a 1-7 scale where 4 is the normal baseline. Smaller/larger
 * step this one notch (down to 1, up to 7 — three steps either way) so the buttons keep working past the
 * first press, instead of both jumping to one fixed small/large size. Keyed by the live editor element so
 * a fresh compose (rebuilt on every send) starts back at normal. */
const rtSizeLevel = new WeakMap<HTMLElement, number>();

/** Wire every rich-text editor under `root`: the toolbar applies formatting to the contenteditable's
 * selection. Buttons use mousedown + preventDefault so the editor keeps its selection (clicking a button
 * would otherwise blur it). B/I/U and size go through execCommand (tag output, no inline style); color,
 * highlight, and font wrap the selection in a class span; the emoji button opens a dialog that inserts. */
function wireRichEditors(root: HTMLElement): void {
  root.querySelectorAll('.dd-rt').forEach((rtNode) => {
    if (!(rtNode instanceof HTMLElement)) {
      return;
    }
    const rt = rtNode;
    const editor = rt.querySelector('[contenteditable]');
    if (!(editor instanceof HTMLElement)) {
      return;
    }
    const exec = (cmd: string, val?: string): void => {
      editor.focus();
      try {
        document.execCommand('styleWithCSS', false, 'false'); // emit <b>/<font>, never an inline-style span
        document.execCommand(cmd, false, val);
      } catch {
        /* execCommand unsupported: the format is simply not applied */
      }
    };
    const on = (sel: string, fn: (el: HTMLElement) => void): void => {
      rt.querySelectorAll(sel).forEach((b) => {
        b.addEventListener('mousedown', (e) => {
          e.preventDefault();
          if (b instanceof HTMLElement) {
            fn(b);
          }
        });
      });
    };
    // Bold/italic/underline toggle via deterministic DOM wrapping (see toggleInlineTag) rather than
    // execCommand, so they work in every browser even on already-styled text.
    on('[data-rt-cmd]', (b) => {
      const cmd = b.dataset.rtCmd;
      toggleInlineTag(editor, cmd === 'bold' ? 'b' : cmd === 'italic' ? 'i' : 'u');
    });
    // Smaller/larger STEP the size one notch from wherever it is (default resets to the baseline), so
    // three presses reach the smallest/largest of the seven levels. execCommand('fontSize') replaces any
    // existing <font size> on the selection rather than nesting, so the levels never compound.
    on('[data-rt-size]', (b) => {
      const dir = b.dataset.rtSize;
      // Step from what the SELECTION actually shows when text is selected, so smaller/larger track the
      // real size of the run you highlighted; fall back to the per-editor counter for the empty-caret
      // "size of what I type next" case (where the browser would report the ambiguous default of 3).
      let cur = rtSizeLevel.get(editor) ?? 4;
      const sel = window.getSelection();
      if (sel !== null && sel.rangeCount > 0 && !sel.getRangeAt(0).collapsed && editor.contains(sel.getRangeAt(0).commonAncestorContainer)) {
        const q = Number(document.queryCommandValue('fontSize'));
        if (Number.isInteger(q) && q >= 1 && q <= 7) {
          cur = q;
        }
      }
      const next = dir === 'd' ? 4 : dir === 's' ? Math.max(1, cur - 1) : Math.min(7, cur + 1);
      rtSizeLevel.set(editor, next);
      exec('fontSize', String(next));
    });
    on('[data-rt-pop]', (b) => {
      const id = b.dataset.rtPop;
      const pop = rt.querySelector(`[data-rt-popid="${id}"]`);
      const show = pop instanceof HTMLElement && pop.hidden;
      closeRtPops(rt);
      if (pop instanceof HTMLElement) {
        pop.hidden = !show;
      }
    });
    on('[data-rt-color]', (b) => {
      wrapSelectionClass(editor, `dd-c-${b.dataset.rtColor}`);
      closeRtPops(rt);
    });
    on('[data-rt-hl]', (b) => {
      wrapSelectionClass(editor, `dd-hl-${b.dataset.rtHl}`);
      closeRtPops(rt);
    });
    on('[data-rt-font]', (b) => {
      const k = b.dataset.rtFont;
      if (k !== undefined && k.length > 0) {
        wrapSelectionClass(editor, `dd-ft-${k}`);
      }
      closeRtPops(rt);
    });
    // Pick a message lifetime: update the module state + the trigger/checkmarks IN PLACE (a full
    // re-render here would clobber the half-typed message in the compose).
    on('[data-rt-life]', (b) => {
      const v = b.dataset.rtLife ?? '86400';
      composeLifetimes.set(composeConvId, lifetimeFromValue(v));
      const cur = rt.querySelector('.dd-rt-life-cur');
      if (cur !== null) {
        cur.textContent = `⏳${lifetimeShort(composeLifetime())}`;
      }
      rt.querySelectorAll('[data-rt-life]').forEach((o) => {
        if (o instanceof HTMLElement) {
          const label = RT_LIFETIMES.find((x) => x.v === o.dataset.rtLife)?.label ?? '';
          o.textContent = `${o.dataset.rtLife === v ? '✓ ' : ''}${label}`;
        }
      });
      closeRtPops(rt);
    });
    editor.addEventListener('mousedown', () => closeRtPops(rt)); // clicking into the text closes any popup
  });
}

/** Read a rich-text editor's content back as the safe marker text, or '' when it is not present. */
function readRichEditor(root: HTMLElement, id: string): string {
  const el = root.querySelector(`#${id}`);
  return el instanceof HTMLElement ? serializeRichText(el) : '';
}

/** Focus a contenteditable and collapse the caret to the very end of its content, so typing continues
 * where the last message left off rather than at the start. Guarded for the headless test DOM. */
function focusAtEnd(el: HTMLElement): void {
  try {
    el.focus({ preventScroll: true }); // do not scroll the (mobile) layout viewport just to place the caret
    const sel = window.getSelection();
    if (sel !== null) {
      const range = document.createRange();
      range.selectNodeContents(el);
      range.collapse(false); // false = to the end
      sel.removeAllRanges();
      sel.addRange(range);
    }
  } catch {
    /* focus/selection APIs unavailable (headless): the field is still usable, just not pre-focused */
  }
}

function renderIconPreview(icon: BuddyIcon | null): string {
  if (icon === null) {
    // No icon yet: a ghost, matching the buddy-list placeholder (never initials or a bare symbol).
    return '<div class="dd-id-preview dd-id-preview-empty" aria-label="no icon">\u{1F47B}</div>';
  }
  if (icon.kind === 'image') {
    return `<div class="dd-id-preview"><img class="dd-id-img" src="${escapeHtml(icon.value)}" alt="buddy icon" /></div>`;
  }
  const ch = icon.kind === 'emoji' ? icon.value : icon.value.slice(0, 2).toUpperCase();
  // Render the palette background as a CSS class, never an inline style: the strict CSP (style-src
  // 'self', no unsafe-inline) strips inline style attributes, so an inline background would be dropped
  // (every icon would show the default dark background) and a peer-authored icon.bg would be an
  // unvalidated value in a CSS context. Unknown/peer values fall back to the first palette entry.
  const idx = ICON_COLORS.indexOf(icon.bg);
  const bgClass = idx >= 0 ? `dd-ic-${idx}` : 'dd-ic-0';
  return `<div class="dd-id-preview ${bgClass}">${escapeHtml(ch)}</div>`;
}

/** Identity view (AIM-style): set a buddy icon, a short profile others can read once you connect, and
 * an away message. Honest copy (no em-dashes, no "not X but Y"): the icon and profile ride your
 * encrypted conversations and the server never stores them; the away message stays on this device
 * unless you opt into server replies. */
// The shareable contact deep link for the Profile QR, cached at module scope so the Profile screen's
// icon-editor re-renders keep showing it without threading it through every go(). Set by openIdentity.
let profileContactLink = '';

/** Build the contact deep link: a URL FRAGMENT (so the server never sees who is being contacted) carrying
 * the handle and, when available, the account fingerprint for first-contact verification. */
function buildContactLink(username: string, fingerprint: string): string {
  if (username.length === 0) {
    return '';
  }
  const k = fingerprint.length > 0 ? `&k=${encodeURIComponent(fingerprint)}` : '';
  return `${location.origin}/#dd=${encodeURIComponent(username)}${k}`;
}

/** Your shareable contact QR (rendered from a deep link). Someone who scans it, or opens the link, is
 * taken to a "message you" flow with your handle pre-filled. The link is a URL FRAGMENT, so the server
 * never sees who is being contacted. Empty `contactLink` (e.g. before sign-in) hides the block. */
function renderContactQr(contactLink: string): string {
  if (contactLink.length === 0) {
    return '';
  }
  // The encoder covers realistic contact links; if one is ever too long, still show the copyable link.
  let qr = '';
  try {
    qr = qrSvg(contactLink, 180);
  } catch {
    qr = '';
  }
  return (
    '<div class="dd-id-section dd-qr-section">' +
    '<div class="dd-fp-label">your contact QR</div>' +
    (qr.length > 0 ? `<div class="dd-qr">${qr}</div>` : '') +
    `<div class="dd-qr-link"><code>${escapeHtml(contactLink)}</code></div>` +
    '<div class="dd-field"><button type="button" class="dd-btn" data-action="copy-contact-link">Copy link</button></div>' +
    '<div class="dd-form-note">Share this so someone can message you. They still confirm your key ' +
    'fingerprint on the first message. The link is a fragment, so the server never sees who scans it.</div>' +
    '</div>'
  );
}

export function renderIdentity(view: { profile: IdentityProfile; error?: string; saved?: boolean }, contactLink = ''): string {
  const p = view.profile;
  const err = view.error !== undefined ? `<div class="dd-form-error">${escapeHtml(view.error)}</div>` : '';
  const saved = view.saved === true ? '<div class="dd-form-sub">Saved.</div>' : '';
  const emojis = ICON_EMOJI.map((e) => `<button type="button" class="dd-id-emoji" data-emoji="${escapeHtml(e)}">${escapeHtml(e)}</button>`).join('');
  const removeImg = p.icon !== null && p.icon.kind === 'image'
    ? '<button type="button" class="dd-btn" data-action="id-clear-image">Remove image</button>'
    : '';

  return (
    // No in-body "PROFILE" heading: the window titlebar already names the screen.
    '<div class="dd-settings dd-id">' +
    saved + err +
    '<div class="dd-id-section">' +
    '<div class="dd-fp-label">buddy icon</div>' +
    '<div class="dd-id-row">' + renderIconPreview(p.icon) +
    '<div class="dd-id-palette">' +
    `<div class="dd-id-emoji-row">${emojis}</div>` +
    // No initials option: handles are pseudonyms here, and initials would nudge people toward real names.
    '<div class="dd-field"><label class="dd-btn dd-id-upload">Upload image<input type="file" id="dd-id-image" accept="image/*" hidden /></label>' + removeImg + '</div>' +
    '</div></div>' +
    '<div class="dd-form-note">Pick an emoji or upload a PNG, JPG, GIF, or WebP image, which is ' +
    'resized to a small 64 by 64 icon. Your buddy icon is sent inside your encrypted conversations. The server never ' +
    'stores it. People see it after you and they have connected once. A new contact sees a ghost until then. ' +
    'An emoji is small enough that the server cannot tell when you set one. An uploaded image is larger, so ' +
    'the server can tell when you publish a buddy icon. It still cannot read it.</div>' +
    '</div>' +
    '<div class="dd-id-section">' +
    '<div class="dd-fp-label">profile</div>' +
    renderRichEditor('dd-id-bio', p.bio, { placeholder: 'a short profile others can read once you have a conversation' }) +
    '<div class="dd-form-note dd-specials">Special characters: %n = whoever is viewing your profile · %d = the date · %t = the time</div>' +
    '<div class="dd-form-note">Your profile is sent inside your encrypted conversations. The server never stores it. ' +
    'Only people you have a conversation with can see it. It shows who wrote it. It does not prove who they are, so ' +
    'confirm a contact key fingerprint through a channel you already trust.</div>' +
    '</div>' +
    renderContactQr(contactLink) +
    '<div class="dd-field dd-form-actions"><button class="dd-btn dd-btn-primary" data-action="id-save">Save</button> ' +
    '<button class="dd-btn" data-action="id-cancel">Cancel</button></div>' +
    '</div>'
  );
}

/** The away-message editor, reached from the DEAD DROP menu. It edits only the away part of the identity
 * card; saving preserves the buddy icon and profile. */
export function renderAway(view: { profile: IdentityProfile; saved?: boolean; picked?: number }): string {
  const a = view.profile.away;
  const saved = view.saved === true ? '<div class="dd-form-sub">Saved.</div>' : '';
  const savedList = a.saved ?? [];
  // The saved-message library as a dropdown: pick one to load it into the editor, "New away message" to
  // start a fresh one, and Delete removes the picked one. Always shown (even with an empty library) so
  // there is always a clear way to see, choose, delete, and create away messages. Library edits apply on
  // Save, so nothing is committed while you are just tidying the list. The chosen option stays selected
  // across the re-render so Delete acts on the one you picked.
  const options =
    `<option value="new"${view.picked === undefined ? ' selected' : ''}>＋ New away message</option>` +
    savedList.map((msg, i) => `<option value="${i}"${view.picked === i ? ' selected' : ''}>${escapeHtml(awayPreview(msg))}</option>`).join('');
  const picker =
    '<label class="dd-fp-label" for="dd-away-pick">saved away messages</label>' +
    '<div class="dd-field dd-away-pickrow">' +
    `<select id="dd-away-pick" class="dd-input dd-away-pick" aria-label="saved away messages">${options}</select>` +
    `<button type="button" class="dd-btn dd-btn-danger dd-away-lib-del" data-action="away-del-sel"${savedList.length === 0 ? ' disabled' : ''} aria-label="delete the selected away message">Delete</button>` +
    '</div>' +
    (savedList.length === 0
      ? '<div class="dd-form-note">No saved away messages yet. Write one below and Save to add it to your list.</div>'
      : '');
  // The editor is ALWAYS available (not hidden when the auto-reply is off), so you can always write or
  // edit a message; the checkbox only decides whether it is actually put up as your away reply.
  const editor =
    renderRichEditor('dd-away-msg', a.message, { placeholder: 'I am away from my keyboard', tall: true }) +
    '<div class="dd-form-note dd-specials">Special characters:' +
    '<div class="dd-specials-line">%n = the person you are replying to</div>' +
    '<div class="dd-specials-line">%d = the date</div>' +
    '<div class="dd-specials-line">%t = the time</div>' +
    '</div>' +
    '<label class="dd-id-check"><input type="checkbox" id="dd-away-server"' + (a.serverSide ? ' checked' : '') +
    ' /> Let the server reply while all my devices are offline</label>' +
    '<div class="dd-form-note">Your away message is stored on this device. It is sent from your device as an ' +
    'encrypted reply when one of your devices is online. If every device is offline, it is sent the next time a ' +
    'device comes online. If you stay offline past seven days, or the server restarts, the reply is lost and the ' +
    'sender gets nothing. Server replies put your away message on the server and let the server tell when all your ' +
    'devices are offline. Leave server replies off to keep your offline status off the server.</div>';
  return (
    // No away on/off checkbox: SAVING a message puts it up (AIM semantics), and the ◆ dropdown's
    // Online item takes it down. The editor is reached as "New Away Message".
    '<div class="dd-settings dd-id">' +
    '<div class="dd-form-title">AWAY MESSAGE</div>' +
    saved +
    picker +
    editor +
    '<div class="dd-field dd-form-actions"><button class="dd-btn dd-btn-primary" data-action="away-save">I\'m Away</button> ' +
    '<button class="dd-btn" data-action="away-cancel">Cancel</button></div>' +
    '</div>'
  );
}

/** Read the away editor's DOM into the identity card (preserving icon and profile). */
function readAwayDraft(root: HTMLElement, profile: IdentityProfile): IdentityProfile {
  const enEl = root.querySelector('#dd-away-enabled');
  const msgEl = root.querySelector('#dd-away-msg');
  const srvEl = root.querySelector('#dd-away-server');
  const enabled = enEl instanceof HTMLInputElement ? enEl.checked : profile.away.enabled;
  const message = msgEl instanceof HTMLElement ? serializeRichText(msgEl) : profile.away.message;
  const serverSide = srvEl instanceof HTMLInputElement ? srvEl.checked : profile.away.serverSide;
  // Spread the existing config first so fields the form does not edit (the saved library) survive.
  return { ...profile, away: { ...profile.away, enabled, message: message.slice(0, AWAY_MAX_CHARS), serverSide } };
}

/** Read the Identity form's current DOM into an IdentityProfile, so icon/toggle picks can re-render
 * without losing typed text. Pass `iconOverride` to set the icon (or null to clear it); omit it to
 * keep the current icon. */
function readIdentityDraft(root: HTMLElement, view: AppView, iconOverride?: BuddyIcon | null): IdentityProfile {
  const base = view.kind === 'identity' ? view.profile : DEFAULT_IDENTITY;
  const bioEl = root.querySelector('#dd-id-bio');
  const enEl = root.querySelector('#dd-away-enabled');
  const msgEl = root.querySelector('#dd-away-msg');
  const srvEl = root.querySelector('#dd-away-server');
  const bio = bioEl instanceof HTMLElement ? serializeRichText(bioEl) : base.bio;
  const enabled = enEl instanceof HTMLInputElement ? enEl.checked : base.away.enabled;
  const message = msgEl instanceof HTMLElement ? serializeRichText(msgEl) : base.away.message;
  const serverSide = srvEl instanceof HTMLInputElement ? srvEl.checked : base.away.serverSide;
  const icon = iconOverride !== undefined ? iconOverride : base.icon;
  // Spread the base config first so fields this form does not edit (the saved library) survive.
  return { icon, bio: bio.slice(0, PROFILE_MAX_CHARS), away: { ...base.away, enabled, message: message.slice(0, AWAY_MAX_CHARS), serverSide } };
}

/** Downscale a chosen image to a 64x64 icon and return a data URL, or null if it cannot be read.
 * Capping the size keeps an uploaded icon small; even so it is larger than a text message, which the
 * Identity view discloses. */
function downscaleImage(file: File): Promise<string | null> {
  return new Promise((resolve) => {
    const reader = new FileReader();
    reader.onload = () => {
      const img = new Image();
      img.onload = () => {
        const canvas = document.createElement('canvas');
        canvas.width = 64;
        canvas.height = 64;
        const ctx = canvas.getContext('2d');
        if (ctx === null) {
          resolve(null);
          return;
        }
        const scale = Math.max(64 / img.width, 64 / img.height);
        const w = img.width * scale;
        const h = img.height * scale;
        ctx.drawImage(img, (64 - w) / 2, (64 - h) / 2, w, h);
        resolve(canvas.toDataURL('image/webp', 0.8));
      };
      img.onerror = () => resolve(null);
      img.src = typeof reader.result === 'string' ? reader.result : '';
    };
    reader.onerror = () => resolve(null);
    reader.readAsDataURL(file);
  });
}

/** Peer Get-Info panel (AIM "Get Info"): the contact's buddy icon and profile, kept de-emphasized
 * with the key fingerprint and the trust warning, because the profile is peer-authored and does not
 * prove identity. */
/** The Verify Buddy panel: TWO phrases (one per side), the two account fingerprints, and the pinned
 * state. Each phrase is derived from that side's own account key, so both people compare both halves;
 * comparing them over a channel you already trust defeats a server that substituted a key at first
 * contact (the honest-limits TOFU residual). */
function renderVerifySection(peer: string, v: BuddyVerifyInfo, armed: boolean): string {
  const title = (t: string): string => `<div class="dd-verify-title">${escapeHtml(t)}</div>`;
  if (v.state === 'unavailable') {
    return (
      '<div class="dd-verify">' + title('Verify buddy') +
      '<div class="dd-form-note">Nothing to compare yet. Open a conversation with this buddy first; ' +
      'the words appear once their account key is visible here.</div></div>'
    );
  }
  if (v.state === 'stale') {
    // Pinned, but unreadable right now. Say exactly that. Never imply the key is being watched when
    // it is not: a silent green check here was a real defect.
    return (
      '<div class="dd-verify dd-verify-stale">' + title('Verified, but not checkable right now') +
      `<div class="dd-form-note">You verified ${escapeHtml(peer)} before, and that is still stored. ` +
      'This device cannot read their current account key at the moment, so it cannot confirm the key ' +
      'still matches. Open a one to one conversation with them to check again. Until then, treat this ' +
      'channel as unconfirmed.</div>' +
      '<div class="dd-field"><button class="dd-btn" data-action="verify-clear">Forget verification</button></div></div>'
    );
  }
  // Both halves, always together: each side's words come from that side's own account key, so the two
  // people read both halves to each other. One shared phrase would let a man in the middle pick both
  // keys and search for a collision instead of a preimage.
  const phrases =
    '<div class="dd-verify-pair">' +
    `<div class="dd-verify-half"><div class="dd-verify-label">your words, read these out</div><div class="dd-sas-words dd-verify-words">${escapeHtml(v.ourWords)}</div></div>` +
    `<div class="dd-verify-half"><div class="dd-verify-label">their words, they read these to you</div><div class="dd-sas-words dd-verify-words">${escapeHtml(v.theirWords)}</div></div>` +
    '</div>';
  const fps = `<div class="dd-fp-label">you ${escapeHtml(v.ourFingerprint)} \u00b7 them ${escapeHtml(v.peerFingerprint)}</div>`;
  if (v.state === 'changed') {
    return (
      '<div class="dd-verify dd-verify-changed">' + title('Identity changed') +
      `<div class="dd-verify-warn">The account key is NOT the one you verified for ${escapeHtml(peer)}. ` +
      'That can mean they rebuilt their account, or that someone is in the middle. Confirm with them ' +
      'over a channel you already trust before saying anything private.</div>' +
      phrases + fps +
      `<div class="dd-field"><button class="dd-btn dd-btn-danger" data-action="verify-mark">${armed ? 'Tap again to trust the new key' : 'Verify the new key'}</button>` +
      '<button class="dd-btn" data-action="verify-clear">Forget verification</button></div></div>'
    );
  }
  if (v.state === 'verified') {
    return (
      '<div class="dd-verify dd-verify-ok">' + title('Verified buddy') +
      '<div class="dd-form-note">You compared the words and pinned this key. While this device can ' +
      'read their current key, a change is flagged here, in the buddy list, and in the conversation.</div>' +
      phrases + fps +
      '<div class="dd-field"><button class="dd-btn" data-action="verify-clear">Forget verification</button></div></div>'
    );
  }
  return (
    '<div class="dd-verify">' + title('Verify buddy') +
    `<div class="dd-form-note">Call ${escapeHtml(peer)}, or stand next to them, and compare BOTH sets ` +
    'of words. Read yours out; they should see the same words under "their words" on their screen. ' +
    'Then have them read theirs, and check it against the second box here. Mark them verified only if ' +
    'both halves match. If either half differs, the channel is not safe.</div>' +
    phrases + fps +
    '<div class="dd-field"><button class="dd-btn" data-action="verify-mark">Mark as Verified</button></div></div>'
  );
}

export function renderGetInfo(peer: string, peers: readonly PeerIdentity[], presence?: string, away?: string, self?: boolean, verify?: BuddyVerifyInfo, verifyArm?: boolean): string {
  const cards =
    peers.length === 0
      ? '<div class="dd-form-sub">No buddy info yet. It appears after they connect and share it.</div>'
      : peers
          .map((p) => {
            const bio = p.bio.length > 0 ? `<div class="dd-gi-bio">${formatMessageText(p.bio)}</div>` : '<div class="dd-form-sub">no profile set</div>';
            return (
              '<div class="dd-gi-card">' +
              renderIconPreview(p.icon) +
              `<div class="dd-gi-body"><div class="dd-fp-label">key ${escapeHtml(p.fingerprint)}</div>${bio}</div></div>`
            );
          })
          .join('');
  // When opened by username from the buddy list, show the opt-in server signals we have (status + away).
  const status = presence !== undefined ? `<div class="dd-gi-status">status: ${escapeHtml(presence)}</div>` : '';
  const awayLine = away !== undefined ? `<div class="dd-gi-away">away: ${formatMessageText(away)}</div>` : '';
  return (
    '<div class="dd-settings dd-gi">' +
    // No in-body "GET INFO" heading: the window titlebar already names the screen.
    `<div class="dd-form-sub">${escapeHtml(peer)}</div>` +
    status +
    awayLine +
    cards +
    (self !== true && verify !== undefined ? renderVerifySection(peer, verify, verifyArm === true) : '') +
    // Your OWN card needs no trust warning: you are signed in on this device, so this card is yours
    // by definition. A peer's card keeps the fingerprint-verification warning.
    (self === true
      ? '<div class="dd-form-note">This is your own buddy info: your account key, your profile, and your ' +
        'live status on this device. Buddies see your profile when they look you up; whether they see your ' +
        'status follows your sharing settings. Edit it all from the Profile button on the buddy list.</div>'
      : '<div class="dd-form-note">This buddy info is written by the other person. It does not prove who they are. ' +
        'Confirm their key fingerprint through a channel you already trust before you rely on it.</div>') +
    '<div class="dd-field"><button class="dd-btn" data-action="getinfo-back">Back</button></div>' +
    '</div>'
  );
}

/** One-time recovery-secret screen, shown right after registration. The secret is the account root;
 * it never reaches the server and is shown only once. */
export function renderRecovery(secret: string): string {
  const note =
    '<div class="dd-form-note">This is the only key to your account. It never reaches the server. ' +
    'Keep it somewhere safe and offline. If you lose every device you are signed in on and you do not ' +
    'have this, your account cannot be recovered. Anyone who has it can add a device to your account.</div>';
  return (
    '<div class="dd-form">' +
    '<div class="dd-form-title">RECOVERY SECRET</div>' +
    '<div class="dd-form-sub">Write this down before you continue. You will see it only once.</div>' +
    `<div class="dd-fingerprint dd-recovery-secret">${escapeHtml(secret)}</div>` +
    note +
    '<div class="dd-field"><button class="dd-btn dd-btn-primary" data-action="recovery-continue">I saved it, continue</button></div>' +
    '</div>'
  );
}

/** Recovery-secret entry: make this device an authorized member of the account by typing the recovery
 * secret. The secret is the account root; it is used locally and never sent anywhere. */
export function renderRecoverEntry(error?: string): string {
  const err = error !== undefined ? `<div class="dd-form-error">${escapeHtml(error)}</div>` : '';
  return (
    '<div class="dd-form">' +
    '<div class="dd-form-title">USE RECOVERY SECRET</div>' +
    '<div class="dd-form-sub">Enter the recovery secret you saved when you created the account. It stays on this device.</div>' +
    '<textarea class="dd-input dd-contact" id="dd-recovery-input" rows="2" aria-label="recovery secret" placeholder="your recovery secret" autocapitalize="none" spellcheck="false"></textarea>' +
    err +
    '<div class="dd-field">' +
    '<button class="dd-btn dd-btn-primary" data-action="recover-submit">Connect this device</button> ' +
    '<button class="dd-btn" data-action="recover-cancel">Cancel</button>' +
    '</div></div>'
  );
}

/** The add-this-device wizard (shown after a valid-credentials login on an unauthorized device). It is a
 * chooser that routes into the existing provisioning and recovery flows; it never authorizes by itself. */
export function renderNewDeviceWizard(s: NewDeviceWizardView): string {
  const err = s.error !== undefined ? `<div class="dd-form-error">${escapeHtml(s.error)}</div>` : '';
  if (s.step === 'deadend') {
    return (
      '<div class="dd-form">' +
      '<div class="dd-form-title">CANNOT CONNECT THIS DEVICE</div>' +
      '<div class="dd-form-sub">To read your messages here you need another device you are already signed ' +
      'in on, or the recovery secret you saved when you created the account. Without one of those, this ' +
      'device cannot reach your account.</div>' +
      '<div class="dd-form-note">Sign in on a device you already use, then approve this one from its ' +
      'Device keys (in the DEAD DROP menu on the buddy list). Or come back here with your recovery secret.</div>' +
      err +
      '<div class="dd-field">' +
      '<button class="dd-btn" data-action="wizard-back">Back</button> ' +
      '<button class="dd-btn dd-btn-danger" data-action="wizard-signout">Sign out of this device</button>' +
      '</div>' +
      '<div class="dd-form-note">Signing out removes this account from this device and leaves no copy ' +
      'behind. Your messages and your account are untouched.</div>' +
      '</div>'
    );
  }
  if (!s.connected) {
    return (
      '<div class="dd-form">' +
      '<div class="dd-form-title">CONNECT THIS DEVICE</div>' +
      '<div class="dd-form-sub">This device could not reach the server. Check your connection and try ' +
      'again.</div>' +
      err +
      '<div class="dd-field">' +
      '<button class="dd-btn dd-btn-primary" data-action="wizard-retry">Try again</button> ' +
      '<button class="dd-btn" data-action="wizard-deadend">More options</button>' +
      '</div></div>'
    );
  }
  return (
    '<div class="dd-form">' +
    '<div class="dd-form-title">CONNECT THIS DEVICE</div>' +
    '<div class="dd-form-sub">You are signed in, but this device is not yet allowed to read your messages. ' +
    'Choose one way to connect it.</div>' +
    err +
    '<div class="dd-field">' +
    '<button class="dd-btn dd-btn-primary" data-action="wizard-provision">Connect with six words</button>' +
    '</div>' +
    '<div class="dd-form-note">On a device where you are already signed in, open the DEAD DROP menu on the ' +
    'buddy list, choose Device keys, then Add a device. Both devices show six words. Confirm they match.</div>' +
    '<div class="dd-field">' +
    '<button class="dd-btn" data-action="show-device-qr">Show a code to scan</button>' +
    '</div>' +
    '<div class="dd-form-note">This device shows a QR code. On the device you are already signed in on, open ' +
    'the DEAD DROP menu, choose Device keys, then Scan a device, and point its camera at this code.</div>' +
    '<div class="dd-field">' +
    '<button class="dd-btn" data-action="wizard-recover">Use your recovery secret</button>' +
    '</div>' +
    '<div class="dd-form-note">Enter the 64-character recovery secret you saved when you created the ' +
    'account. It stays on this device and never reaches the server.</div>' +
    '<div class="dd-form-note">Once connected, this device receives your messages from here on. Messages ' +
    'from before are kept only on the device that received them.</div>' +
    '<div class="dd-field">' +
    '<button class="dd-btn" data-action="wizard-deadend">I do not have either</button>' +
    '</div></div>'
  );
}

/** Add-a-device screen (model b provisioning). Drives the two-leg SAS handshake: one device opens a
 * window, the other connects, both show the same six words, and the user confirms on the first. */
export function renderProvisioning(s: ProvisioningView): string {
  if (s.step === 'error') {
    return (
      '<div class="dd-form"><div class="dd-form-title">ADD A DEVICE</div>' +
      `<div class="dd-form-error">${escapeHtml(s.error ?? 'something went wrong')}</div>` +
      '<div class="dd-field"><button class="dd-btn" data-action="prov-done">Back</button></div></div>'
    );
  }
  if (s.step === 'done') {
    const msg =
      s.role === 'newdevice'
        ? 'This device is now part of your account. It will receive your messages.'
        : 'Your other device is now part of your account.';
    return (
      '<div class="dd-form"><div class="dd-form-title">DEVICE CONNECTED</div>' +
      `<div class="dd-form-sub">${escapeHtml(msg)}</div>` +
      '<div class="dd-field"><button class="dd-btn dd-btn-primary" data-action="prov-done">Done</button></div></div>'
    );
  }
  if (s.step === 'showqr') {
    // NEW DEVICE: show its pairing QR for the authorized device to scan. No six words to compare.
    let qr = '';
    try {
      qr = s.qr !== undefined && s.qr !== '' ? qrSvg(s.qr, 240) : '';
    } catch {
      qr = '';
    }
    const inner =
      qr !== ''
        ? `<div class="dd-scan"><div class="dd-qr">${qr}</div></div>` +
          '<div class="dd-form-sub">On your other device, open Device keys and choose Scan a device, ' +
          'then point its camera at this code. Only show this to your own device, it links whatever ' +
          'camera reads it.</div>'
        : '<div class="dd-form-error">Could not build a code on this device. Use Connect this device and ' +
          'compare the six words instead.</div>';
    return (
      '<div class="dd-form"><div class="dd-form-title">SHOW THIS CODE</div>' +
      inner +
      '<div class="dd-field"><button class="dd-btn" data-action="prov-cancel">Cancel</button></div></div>'
    );
  }
  if (s.step === 'qrexpired') {
    // The shown QR expired before the other device scanned it. Offer a fresh code (data-action already
    // bound per-render) or a way back to the chooser.
    return (
      '<div class="dd-form"><div class="dd-form-title">SHOW THIS CODE</div>' +
      '<div class="dd-form-error">The code expired before your other device scanned it.</div>' +
      '<div class="dd-field"><button class="dd-btn dd-btn-primary" data-action="show-device-qr">Show a new code</button> ' +
      '<button class="dd-btn" data-action="prov-cancel">Back</button></div></div>'
    );
  }
  if (s.step === 'scanning') {
    // AUTHORIZED DEVICE: aim the camera at the new device's code. The video/canvas are wired imperatively.
    return (
      '<div class="dd-form"><div class="dd-form-title">SCAN A DEVICE</div>' +
      '<div class="dd-scan"><video id="dd-scan-video" class="dd-scan-video" autoplay playsinline muted></video>' +
      '<canvas id="dd-scan-canvas" class="dd-scan-canvas"></canvas></div>' +
      '<div class="dd-form-sub">Point this camera at the code on the device you are adding. It shows the ' +
      'code under Device keys, Show this device. Only scan a code shown by a device you control: it adds ' +
      'whichever device shows the code.</div>' +
      '<div class="dd-field"><button class="dd-btn" data-action="prov-cancel">Cancel</button></div></div>'
    );
  }
  const title = s.role === 'newdevice' ? 'CONNECT THIS DEVICE' : 'ADD A DEVICE';
  let body: string;
  if (s.step === 'compare' && s.words !== undefined) {
    const guide =
      s.role === 'seedholder'
        ? 'Check that the same six words show on the device you are adding. If they match, confirm here.'
        : 'Check that the same six words show on your other device, then confirm there.';
    const confirm =
      s.role === 'seedholder'
        ? '<button class="dd-btn dd-btn-primary" data-action="prov-confirm">The words match</button> '
        : '';
    body =
      `<div class="dd-form-sub">${escapeHtml(guide)}</div>` +
      `<div class="dd-fingerprint dd-sas-words">${escapeHtml(s.words)}</div>` +
      `<div class="dd-field">${confirm}<button class="dd-btn" data-action="prov-cancel">Cancel</button></div>`;
  } else {
    const waitMsg =
      s.role === 'seedholder'
        ? 'Waiting for the device you are adding. On it, choose Connect with six words.'
        : 'Waiting for your other device. On it, open the DEAD DROP menu on the buddy list, choose Device keys, then Add a device.';
    body =
      `<div class="dd-form-sub">${escapeHtml(waitMsg)}</div>` +
      '<div class="dd-field"><button class="dd-btn" data-action="prov-cancel">Cancel</button></div>';
  }
  return `<div class="dd-form"><div class="dd-form-title">${title}</div>${body}</div>`;
}

/** Key-exchange + accept screen: shows fingerprints for recognition and the mutual-accept gate. */
export function renderKeyExchange(s: KeyExchangeState): string {
  const note =
    '<div class="dd-form-note">Confirm this key with your contact through a channel you trust ' +
    'before you rely on it.</div>';
  const accept = s.mode === 'incoming' ? 'Accept' : 'Continue';
  const cancel = s.mode === 'incoming' ? 'Reject' : 'Cancel';
  const title = s.mode === 'incoming' ? escapeHtml(s.peer ?? 'NEW CONTACT') : 'NEW CHANNEL';
  const sub = s.mode === 'incoming' ? 'wants to open a channel' : 'share your contact, then paste theirs';
  const fpLabel = s.mode === 'incoming' ? 'their key' : 'your key';
  const fp = s.mode === 'incoming' ? (s.peerFingerprint ?? '') : s.selfFingerprint;
  // Start mode, directory: open a channel by username. Show our own handle to share and a field for
  // theirs. Without the directory (no account), fall back to the copy-pasteable contact strings.
  let contactBlock = '';
  if (s.mode === 'start' && s.byUsername === true) {
    contactBlock =
      '<div class="dd-fp-label">your username</div>' +
      `<div class="dd-fingerprint">${escapeHtml(s.selfUsername ?? '')}</div>` +
      '<div class="dd-fp-label">their username</div>' +
      `<input class="dd-input" id="dd-peer-username" aria-label="their username" placeholder="the username your peer chose" value="${escapeHtml(s.peerUsername ?? '')}" autocapitalize="none" spellcheck="false" />`;
  } else if (s.mode === 'start' && s.selfContact !== undefined) {
    contactBlock =
      '<div class="dd-fp-label">your contact</div>' +
      `<textarea class="dd-input dd-contact" id="dd-self-contact" rows="2" readonly aria-label="your contact">${escapeHtml(s.selfContact)}</textarea>` +
      '<div class="dd-fp-label">paste their contact</div>' +
      '<input class="dd-input" id="dd-peer-contact" aria-label="their contact" placeholder="paste the contact your peer shared" />';
  }
  const lookupErr = s.error !== undefined ? `<div class="dd-form-error">${escapeHtml(s.error)}</div>` : '';
  return (
    '<div class="dd-form">' +
    `<div class="dd-form-title">${title}</div>` +
    `<div class="dd-form-sub">${sub}</div>` +
    `<div class="dd-fp-label">${fpLabel}</div>` +
    `<div class="dd-fingerprint">${escapeHtml(fp)}</div>` +
    contactBlock +
    lookupErr +
    '<div class="dd-field">' +
    `<button class="dd-btn dd-btn-primary" data-action="accept-key" data-conv="${escapeHtml(s.conversationId)}">${accept}</button>` +
    `<button class="dd-btn" data-action="cancel-key">${cancel}</button>` +
    '</div>' +
    note +
    '</div>'
  );
}

function windowTitle(view: AppView): string {
  if (view.kind === 'unlock' || view.kind === 'desktop') {
    return 'DEAD DROP';
  }
  if (view.kind === 'channels') {
    return view.active !== undefined && view.active.peer !== null ? `CHANNELS · ${view.active.peer}` : 'CHANNELS';
  }
  if (view.kind === 'keyexchange') {
    return 'KEY EXCHANGE';
  }
  if (view.kind === 'settings') {
    return 'DEVICE KEYS';
  }
  if (view.kind === 'recovery') {
    return 'RECOVERY';
  }
  if (view.kind === 'provisioning') {
    return 'ADD A DEVICE';
  }
  if (view.kind === 'newdevice-wizard') {
    return 'CONNECT THIS DEVICE';
  }
  if (view.kind === 'recover-entry') {
    return 'RECOVERY';
  }
  if (view.kind === 'selfdestruct') {
    return 'SELF DESTRUCT';
  }
  if (view.kind === 'revokeself') {
    return 'REVOKE THIS DEVICE';
  }
  if (view.kind === 'identity') {
    return 'PROFILE';
  }
  if (view.kind === 'away') {
    return 'AWAY MESSAGE';
  }
  if (view.kind === 'getinfo') {
    return 'GET INFO';
  }
  if (view.kind === 'appearance') {
    return 'APPEARANCE';
  }
  if (view.kind === 'buddies') {
    return 'BUDDY LIST';
  }
  if (view.kind === 'buddysetup') {
    return 'BUDDY LIST SETUP';
  }
  if (view.kind === 'buddyscan') {
    return 'SCAN A BUDDY';
  }
  if (view.kind === 'buddyqr') {
    return 'SCAN ME';
  }
  if (view.kind === 'addperson') {
    return 'ADD PERSON';
  }
  return view.transmit.peer !== null ? `TRANSMIT · ${view.transmit.peer}` : 'TRANSMIT';
}

function renderWindowContent(view: AppView): string {
  if (view.kind === 'desktop') {
    return ''; // unreachable: the shell skips the window entirely on the desktop
  }
  if (view.kind === 'unlock') {
    return renderUnlock(view.error, view.mode ?? 'login', view.prefillUser);
  }
  if (view.kind === 'recovery') {
    return renderRecovery(view.secret);
  }
  if (view.kind === 'channels') {
    return renderChannels(view.channels, view.notice, view.active, view.selectedId);
  }
  if (view.kind === 'keyexchange') {
    return renderKeyExchange(view.state);
  }
  if (view.kind === 'provisioning') {
    return renderProvisioning(view.state);
  }
  if (view.kind === 'newdevice-wizard') {
    return renderNewDeviceWizard(view.state);
  }
  if (view.kind === 'recover-entry') {
    return renderRecoverEntry(view.error);
  }
  if (view.kind === 'selfdestruct') {
    return renderSelfDestruct(view.error);
  }
  if (view.kind === 'revokeself') {
    return renderRevokeSelf(view.deviceId, view.error);
  }
  if (view.kind === 'settings') {
    return renderSettings(view.devices, view.currentDeviceKey, view.pending, view.error, view.historyOff, view.historyArm);
  }
  if (view.kind === 'identity') {
    return renderIdentity(view, profileContactLink);
  }
  if (view.kind === 'away') {
    return renderAway(view);
  }
  if (view.kind === 'getinfo') {
    return renderGetInfo(view.peer, view.peers, view.presence, view.away, view.self, view.verify, view.verifyArm);
  }
  if (view.kind === 'appearance') {
    return renderAppearance(view.draft, view.category, view.error, view.packText);
  }
  if (view.kind === 'buddies') {
    return renderBuddies(view.buddies, view.groups, view.statuses, view.collapsed, view.blocked, view.selected, view.profile, view.ownName, view.icons, view.awayText, view.error, view.signals ?? {}, view.verify ?? {});
  }
  if (view.kind === 'buddysetup') {
    return renderBuddySetup(view.buddies, view.groups, view.statuses, view.blocked, view.presenceOn, view.notifyOn, view.selected, view.error);
  }
  if (view.kind === 'buddyscan') {
    return renderBuddyScan();
  }
  if (view.kind === 'buddyqr') {
    return renderBuddyQr(view.link);
  }
  if (view.kind === 'addperson') {
    return renderAddPerson(view.error);
  }
  return `<div class="dd">${renderTransmit(view.transmit)}</div>`; // the working scrollbar rides inside the terminal
}

/** A window minimized to the menu bar: its restore chip label plus the stashed view (a conversation
 * restores FRESH through openChannel; other screens restore their stashed state, drafts included). */
export interface MinimizedWin {
  readonly key: string; // dedupe key: 'conv:<id>' for conversations, 'kind:<kind>' otherwise
  readonly title: string;
  readonly view: AppView;
  // Unread arrivals while this window sat MINIMIZED (docked). AIM never silently swallowed a message: a
  // docked conversation flashes its chip so the user knows something is waiting. Cleared on restore
  // (restoring opens the conversation, which marks it seen and starts any burn countdown).
  readonly unread?: number;
}

/** The stable identity of a window (one per conversation, one per other screen kind). Windows that share
 * a key are the same window: opening it again focuses/refreshes rather than stacking a duplicate. */
export function windowKey(view: AppView): string {
  return view.kind === 'conversation' && view.transmit.conversationId !== null
    ? `conv:${view.transmit.conversationId}`
    : `kind:${view.kind}`;
}

/** The conversation currently in focus, whether it is a STANDALONE conversation window or the chat embedded
 * in the two-pane Channels window. Every compose/send/file/call/revoke/receive path routes through this so
 * the embedded pane behaves identically to a standalone IM. Null when no chat is in focus. */
/** Ensure the two-pane channel LIST contains a row for `active`, synthesizing one if the list omits it —
 * chiefly Note to Self, which listChannels() deliberately excludes (the hidden self-group). Without this a
 * docked self chat shows in the right pane but has no highlightable row on the left. */
export function ensureActiveRow(channels: readonly ChannelSummary[], active: TransmitModel): readonly ChannelSummary[] {
  const id = active.conversationId;
  if (id === null || channels.some((c) => c.id === id)) {
    return channels;
  }
  const row: ChannelSummary = {
    id,
    peer: active.peer ?? 'Note to Self',
    fingerprint: active.fingerprint ?? '',
    status: active.secure ? 'secure' : 'pending',
    preview: active.selfNote === true ? 'only your devices see this' : '',
    unread: 0,
  };
  return [row, ...channels];
}

export function activeConv(v: AppView): { readonly id: string; readonly transmit: TransmitModel } | null {
  if (v.kind === 'conversation' && v.transmit.conversationId !== null) {
    return { id: v.transmit.conversationId, transmit: v.transmit };
  }
  if (v.kind === 'channels' && v.active !== undefined && v.active.conversationId !== null) {
    return { id: v.active.conversationId, transmit: v.active };
  }
  return null;
}

/** The windows that PERSIST when you open another on top of them (they park behind, still on the desktop):
 * the buddy list, the channels list, and conversations. Every other screen is a transient editor/flow
 * that dismisses when you leave it. */
const PRIMARY_WINDOW_KINDS: ReadonlySet<string> = new Set(['buddies', 'channels', 'conversation']);
export function isPrimaryWindow(view: AppView): boolean {
  return PRIMARY_WINDOW_KINDS.has(view.kind);
}

/** The Electron desktop shell (desktop/preload.js) exposes this bridge on `window` via contextBridge so
 * the client can present as a single frameless native window: it advertises native mode and drives the OS
 * window's minimize/close. Absent in a plain browser, so isNativeShell() is false and every native-only
 * branch below is dead for web users (the whole .dd-native CSS block is likewise never activated). */
interface ShellBridge {
  readonly native?: boolean;
  readonly minimize?: () => void;
  readonly close?: () => void;
}
function shellBridge(): ShellBridge | undefined {
  return (globalThis as unknown as { __ddShell?: ShellBridge }).__ddShell;
}
export function isNativeShell(): boolean {
  return shellBridge()?.native === true;
}

/** A window parked behind the focused one: rendered on the desktop but NOT wired (click it to bring it
 * forward). Its view is a snapshot from when it was parked, so background windows are static until
 * refocused (the focused window is always the live, interactive one). */
export interface ParkedWin {
  readonly key: string;
  readonly view: AppView;
}

/** One window's chrome + content. `live` is the focused, interactive window; parked windows get the
 * dd-window-parked class (dimmed, click-to-focus, content non-interactive). */
function renderOneWindow(view: AppView, live: boolean): string {
  return (
    `<div class="dd-window${live ? '' : ' dd-window-parked'}" data-win-key="${escapeHtml(windowKey(view))}">` +
    '<div class="dd-titlebar">' +
    titlebarAppMenu(view) +
    `<span class="dd-title">${escapeHtml(windowTitle(view))}</span>` +
    // The connection status now lives in the buddy-list HEADER (renderConnStatus, far right of the
    // username, beside the away bubble), not the titlebar, so it has room to stay visible on a phone.
    windowControls(view) +
    '</div>' +
    // A parked window's body is `inert`: frozen and fully non-interactive (no pointer, no keyboard/Tab
    // focus, no text selection) so a control inside a background window can never be reached or activated.
    // The titlebar stays outside the inert region, keeping click-to-focus alive.
    `<div class="dd-window-body"${live ? '' : ' inert'}><div class="dd-content-well">${renderWindowContent(view)}</div></div>` +
    '</div>'
  );
}

/** The full app shell: chrome desktop with every open window in the stage — parked windows behind, the
 * focused one on top. */
export function renderShell(view: AppView, minimized: readonly MinimizedWin[] = [], parked: readonly ParkedWin[] = []): string {
  // The menu bar (navigation + connection status) belongs to the signed-in app; the unlock screen and the
  // device-join / recovery screens stand on their own, so it is hidden until you are logged in.
  const preLogin =
    view.kind === 'unlock' ||
    view.kind === 'newdevice-wizard' ||
    view.kind === 'recovery' ||
    view.kind === 'recover-entry';
  // Pre-login is a single standalone modal (no desktop, no parked windows behind it).
  if (preLogin) {
    return `<div class="dd-stage">${renderOneWindow(view, true)}</div>`;
  }
  // Signed-in desktop. The focused window is rendered FIRST so global `root.querySelector` lookups (the
  // whole wire() layer) resolve to IT, not to a parked duplicate; CSS then lifts it above the parked
  // windows with z-index. Parked windows follow (bare desktop = every window minimized: only parked show).
  const liveHtml = view.kind === 'desktop' ? '' : renderOneWindow(view, true);
  const parkedHtml = parked.map((p) => renderOneWindow(p.view, false)).join('');
  return renderMenubar(minimized) + `<div class="dd-stage">${liveHtml}${parkedHtml}</div>`;
}

/** Window-decoration controls (AIM-style minimize + close), on every signed-in screen. Minimize sends
 * the window to the menu bar as a chip (click to restore, drafts intact); close dismisses it. Neither
 * destroys anything: a closed conversation stays in Channels and reopens right where it left off. */
function windowControls(view: AppView): string {
  // No controls pre-login or on guided/sensitive flows: the wizard screens must not offer an escape
  // hatch into the app on an unauthorized device, and leaving ADD A DEVICE must go through its own
  // Cancel (which closes the pairing window) rather than a minimize that leaves it silently open.
  // The bare desktop has no window, so never any controls.
  if (view.kind === 'desktop') {
    return '';
  }
  const guarded =
    view.kind === 'unlock' ||
    view.kind === 'newdevice-wizard' ||
    view.kind === 'recovery' ||
    view.kind === 'recover-entry' ||
    view.kind === 'provisioning';
  // In a plain browser these flows hide the controls (no OS window to run, and no escape hatch into the
  // app on an unauthorized device). In the native shell the buttons drive the OS WINDOW (minimize / close,
  // re-targeted below), which every screen needs — including the unlock and guided flows — and minimizing
  // or quitting the window is not an escape into the app.
  if (guarded && !isNativeShell()) {
    return '';
  }
  return (
    '<span class="dd-winctl">' +
    '<button type="button" class="dd-winbtn" data-action="win-minimize" title="Minimize" aria-label="Minimize">–</button>' +
    '<button type="button" class="dd-winbtn dd-winbtn-close" data-action="win-close" title="Close" aria-label="Close">✕</button>' +
    '</span>'
  );
}

// Per-tab session resume (S1). Held in sessionStorage, which survives a page refresh but is wiped when
// the tab or browser closes, so a closed or seized device reveals nothing. NOTHING secret goes here: only
// the username (so the unlock screen pre-fills it) and the conversation you had open (so a refresh returns
// you there). Your unlock key never touches storage; you still re-enter your passphrase on a refresh.
const RESUME_KEY = 'dd-resume';
const BOOT_KEY = 'dd-boot-mode';
const BOOT_NOTICE_KEY = 'dd-boot-notice';
interface ResumeState {
  readonly username: string;
  readonly conversationId?: string;
}
function loadResume(): ResumeState | null {
  try {
    const raw = sessionStorage.getItem(RESUME_KEY);
    if (raw === null) {
      return null;
    }
    const r = JSON.parse(raw) as ResumeState;
    return typeof r.username === 'string' && r.username.length > 0 ? r : null;
  } catch {
    return null; // sessionStorage unavailable or a corrupt value: behave as if there is no session
  }
}
function saveResume(state: ResumeState): void {
  try {
    sessionStorage.setItem(RESUME_KEY, JSON.stringify(state));
  } catch {
    /* sessionStorage unavailable (private mode / disabled): resume is best-effort */
  }
}
function clearResume(): void {
  try {
    sessionStorage.removeItem(RESUME_KEY);
  } catch {
    /* ignore */
  }
}
/** Read and consume a one-shot boot-mode hint (set just before a wipe + reload), or null. */
function takeBootMode(): 'login' | 'register' | null {
  try {
    const m = sessionStorage.getItem(BOOT_KEY);
    if (m !== null) {
      sessionStorage.removeItem(BOOT_KEY);
    }
    return m === 'register' || m === 'login' ? m : null;
  } catch {
    return null;
  }
}
function setBootMode(mode: 'login' | 'register'): void {
  try {
    sessionStorage.setItem(BOOT_KEY, mode);
  } catch {
    /* ignore */
  }
}
/** Read and consume a one-shot boot notice (e.g. the revoked-device lockout message), or null. Shown
 * on the login screen after the crypto-erase reload so the user learns why they were signed out. */
function takeBootNotice(): string | null {
  try {
    const n = sessionStorage.getItem(BOOT_NOTICE_KEY);
    if (n !== null) {
      sessionStorage.removeItem(BOOT_NOTICE_KEY);
    }
    return n;
  } catch {
    return null;
  }
}
function setBootNotice(notice: string): void {
  try {
    sessionStorage.setItem(BOOT_NOTICE_KEY, notice);
  } catch {
    /* ignore */
  }
}

// A contact QR/link opens the app at `#dd=<username>&k=<fp>`. We read that fragment ONCE at load, stash
// it (so it survives the login flow), and clear the fragment from the address bar. After sign-in the
// pending contact pre-fills a "message this user" start screen. The link is a fragment, so it never
// reaches the server. `k` (the account fingerprint) is carried for later cryptographic verification.
const CONTACT_KEY = 'dd-contact';
interface PendingContact {
  readonly username: string;
  readonly fingerprint: string;
}
function captureContactFromUrl(): void {
  try {
    const hash = location.hash.startsWith('#') ? location.hash.slice(1) : location.hash;
    if (hash.length === 0) {
      return;
    }
    const params = new URLSearchParams(hash);
    const username = (params.get('dd') ?? '').trim();
    if (username.length === 0) {
      return;
    }
    sessionStorage.setItem(CONTACT_KEY, JSON.stringify({ username, fingerprint: (params.get('k') ?? '').trim() }));
    // Clear the fragment so a refresh does not re-trigger it and the handle is not left in the address bar.
    history.replaceState(null, '', location.pathname + location.search);
  } catch {
    /* no sessionStorage / malformed link: ignore */
  }
}
function takePendingContact(): PendingContact | null {
  try {
    const raw = sessionStorage.getItem(CONTACT_KEY);
    if (raw === null) {
      return null;
    }
    sessionStorage.removeItem(CONTACT_KEY);
    const p = JSON.parse(raw) as { username?: unknown; fingerprint?: unknown };
    if (typeof p.username !== 'string' || p.username.length === 0) {
      return null;
    }
    return { username: p.username, fingerprint: typeof p.fingerprint === 'string' ? p.fingerprint : '' };
  } catch {
    return null;
  }
}

/** Parse a scanned contact QR/link (`.../#dd=<user>&k=<fp>`) into its username + account fingerprint, or
 * null if it is not one of ours. Mirrors captureContactFromUrl but reads an arbitrary scanned string
 * (the camera's decoded text) rather than the address bar. */
export function parseContactLink(text: string): { username: string; fingerprint: string } | null {
  const hashIdx = text.indexOf('#');
  if (hashIdx < 0) {
    return null;
  }
  try {
    const params = new URLSearchParams(text.slice(hashIdx + 1));
    const username = (params.get('dd') ?? '').trim();
    if (username.length === 0) {
      return null;
    }
    return { username, fingerprint: (params.get('k') ?? '').trim() };
  } catch {
    return null;
  }
}

// Which buddy groups the user has collapsed. A per-tab UI preference (survives a refresh, cleared on tab
// close). Never secret: just group names, and only while signed in.
const BGROUPS_KEY = 'dd-bgroups-collapsed';
function loadCollapsedGroups(): string[] {
  try {
    const raw = sessionStorage.getItem(BGROUPS_KEY);
    const arr = raw !== null ? (JSON.parse(raw) as unknown) : [];
    return Array.isArray(arr) ? arr.filter((x): x is string => typeof x === 'string') : [];
  } catch {
    return [];
  }
}
function toggleCollapsedGroup(name: string): string[] {
  const set = new Set(loadCollapsedGroups());
  if (set.has(name)) {
    set.delete(name);
  } else {
    set.add(name);
  }
  const next = [...set];
  try {
    sessionStorage.setItem(BGROUPS_KEY, JSON.stringify(next));
  } catch {
    /* ignore */
  }
  return next;
}

/** Mount the app: render the current view and wire interactions through the controller. */
export function mountApp(
  root: HTMLElement,
  controller: AppController,
  opts?: {
    readonly wsUrl?: string;
    readonly account?: AccountClient;
    readonly rtcFactory?: RtcFactory;
    readonly media?: GetUserMedia;
  },
): void {
  // On boot, decide the first screen from the per-tab session (S1). A refresh of an open session pre-fills
  // the username and remembers the conversation to reopen after unlock; a just-completed wipe boots to its
  // chosen mode; otherwise it is a normal first load.
  // If the app was opened from a contact QR/link (#dd=<user>), stash it now and clear the fragment; it is
  // consumed in doLogin to pre-fill a "message this user" start screen after sign-in.
  captureContactFromUrl();
  const bootMode = takeBootMode();
  const bootNotice = takeBootNotice();
  const bootResume = bootMode === null ? loadResume() : null;
  // The conversation to reopen after the user re-unlocks (consumed once in doLogin).
  let pendingResume: ResumeState | null = bootResume;
  let view: AppView =
    bootMode === 'register'
      ? { kind: 'unlock', mode: 'register' }
      : bootNotice !== null
        ? { kind: 'unlock', mode: 'login', error: bootNotice }
        : bootResume !== null
          ? { kind: 'unlock', mode: 'login', prefillUser: bootResume.username }
          : { kind: 'unlock' };
  let connState = 'offline';
  // The client's look (AIM18): a built-in theme + validated per-user token tweaks, loaded device-locally
  // after login and re-applied on every render so a rebuilt DOM keeps the chosen skin. It is device-local
  // (never synced) and defaults to the untouched base look until the user opens Appearance.
  let appearance: Appearance = DEFAULT_APPEARANCE;
  // The plaintext username is kept in memory after a successful login so it can seed a by-username
  // directory lookup and be shown to peers; it is never persisted.
  let currentUsername = '';
  // This device's public identity key (from the gateway self-contact), used to enroll the device and
  // to mark it as "this device" in the device list. In memory only.
  let currentDeviceKey = '';
  // True while the add-this-device wizard is driving an unauthorized device through provisioning or
  // recovery, so the reused provisioning/recovery Cancel paths return to the wizard, not to Settings.
  let joiningNewDevice = false;
  // A device that logs in unauthorized is guided to the wizard WITHOUT enrolling (so an abandoned attempt
  // leaves no orphan device row on the server). This memory-only stash holds the DERIVED login secret
  // (password-equivalent, a login-verifier preimage; never the typed passphrase) so enrollment can run once
  // at the provisioning-authorized point. Cleared on every exit path. THREAT NOTE (accepted residual): an
  // attacker who can edit IndexedDB AND knows the passphrase could delete the plaintext authorized marker
  // pre-login to take the wizard branch and skip the revoked-device wipe the old enroll-first order forced;
  // moot in practice (that attacker already reads the vault offline), but a strict behavior change.
  let pendingWizardEnroll: { user: string; authSecret: string } | null = null;
  const account = opts?.account;

  // Server-side away (opt-in): while it is on, heartbeat the control plane so it knows a device is
  // online and does NOT serve the away text until every device goes offline. The heartbeat is the
  // disclosed presence cost (honest-limits) and runs ONLY while server-side away is enabled.
  const AWAY_BEAT_MS = 30000;
  let awayBeatTimer: ReturnType<typeof setInterval> | null = null;
  function startAwayBeat(): void {
    if (account === undefined || awayBeatTimer !== null) {
      return;
    }
    void account.awayBeat();
    awayBeatTimer = setInterval(() => {
      void account?.awayBeat();
    }, AWAY_BEAT_MS);
  }
  function stopAwayBeat(): void {
    if (awayBeatTimer !== null) {
      clearInterval(awayBeatTimer);
      awayBeatTimer = null;
    }
  }
  // Push the server-side away setting to the control plane: set or clear the away text and start or
  // stop the presence heartbeat. Called on identity save and after login.
  async function applyServerAway(profile: IdentityProfile): Promise<void> {
    if (account === undefined) {
      return;
    }
    if (profile.away.serverSide && profile.away.enabled && profile.away.message.trim().length > 0) {
      await account.setAway(profile.away.message);
      startAwayBeat();
    } else {
      await account.clearAway();
      stopAwayBeat();
    }
  }
  async function restoreServerAway(): Promise<void> {
    const profile = (await controller.getIdentity?.()) ?? null;
    if (profile !== null) {
      await applyServerAway(profile);
    }
  }

  // Presence (opt-in): while on, heartbeat the control plane with this device's status so buddies can
  // see online/idle. Idle is detected from input activity. The server reads this status (disclosed).
  const PRESENCE_BEAT_MS = 30000;
  const IDLE_MS = 5 * 60 * 1000;
  let presenceTimer: ReturnType<typeof setInterval> | null = null;
  let lastActivityMs = Date.now();
  for (const evName of ['pointerdown', 'keydown', 'pointermove', 'touchstart']) {
    document.addEventListener(evName, () => {
      lastActivityMs = Date.now();
    }, { passive: true });
  }
  function currentStatus(): 'online' | 'idle' {
    return Date.now() - lastActivityMs > IDLE_MS ? 'idle' : 'online';
  }
  function startPresenceBeat(): void {
    if (account === undefined || presenceTimer !== null) {
      return;
    }
    void account.setPresence(currentStatus());
    presenceTimer = setInterval(() => {
      void account?.setPresence(currentStatus());
    }, PRESENCE_BEAT_MS);
  }
  function stopPresenceBeat(): void {
    if (presenceTimer !== null) {
      clearInterval(presenceTimer);
      presenceTimer = null;
    }
    void account?.clearPresence();
  }

  // In-app notifications: a toast, a short WebAudio beep, and a system notification when the tab is in
  // the background and permission was granted. Local only; no new server trust. Off mutes everything.
  let notifyEnabled = true;
  let audioCtx: AudioContext | null = null;
  function playBeep(freq: number): void {
    try {
      audioCtx = audioCtx ?? new AudioContext();
      const ctx = audioCtx;
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = 'sine';
      osc.frequency.value = freq;
      gain.gain.setValueAtTime(0.0001, ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.12, ctx.currentTime + 0.01);
      gain.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + 0.25);
      osc.connect(gain).connect(ctx.destination);
      osc.start();
      osc.stop(ctx.currentTime + 0.26);
    } catch {
      /* audio unavailable (no user gesture yet, or unsupported) */
    }
  }
  function showToast(text: string): void {
    const toast = document.createElement('div');
    toast.className = 'dd-toast';
    toast.textContent = text;
    root.appendChild(toast);
    setTimeout(() => {
      toast.remove();
    }, 4000);
  }
  function requestNotifyPermission(): void {
    try {
      if (typeof Notification !== 'undefined' && Notification.permission === 'default') {
        void Notification.requestPermission();
      }
    } catch {
      /* system notifications unsupported */
    }
  }
  function notify(title: string, body: string, freq = 660): void {
    if (!notifyEnabled) {
      return;
    }
    playBeep(freq);
    showToast(body !== '' ? `${title}: ${body}` : title);
    try {
      if (typeof Notification !== 'undefined' && Notification.permission === 'granted' && document.hidden) {
        new Notification(title, { body });
      }
    } catch {
      /* system notifications unavailable */
    }
  }

  // Buddy sign-on watcher: poll buddies' shared presence and announce an offline -> online transition
  // (the AIM "door"). Runs after login; harmless when buddies do not share presence.
  const buddyStatusPrev: Record<string, string> = {};
  // Buddies that just changed presence, awaiting a one-shot sign-on/off flash on the next buddy-list
  // render (openBuddies consumes + clears this). Per-tab UI state, never stored.
  let buddyFx: Record<string, 'on' | 'off'> = {};
  let buddyWatchSeeded = false; // the first poll records statuses WITHOUT firing (no burst on sign-in)
  let buddyWatchTimer: ReturnType<typeof setInterval> | null = null;
  function startBuddyWatch(): void {
    if (account === undefined || buddyWatchTimer !== null) {
      return;
    }
    const acct = account;
    const poll = async (): Promise<void> => {
      const buddies = (await controller.listBuddies?.()) ?? [];
      let changed = false;
      // Skip our OWN entry: our status is driven locally (the ◆ control), not the presence server.
      const watched = buddies.filter((b) => normalizeUsername(b.username) !== normalizeUsername(currentUsername));
      // One request per buddy, ISSUED TOGETHER. Awaiting each in turn meant 50 buddies cost 50 serial
      // round trips every 30 seconds, measured at 5.3s per cycle over a 100ms link and 10.2s over 200ms,
      // where the same work in parallel took 1.0s and 2.1s. loadBuddyStatuses already fetches this same
      // data with Promise.all; this is now consistent with it.
      const statuses = await Promise.all(watched.map((b) => acct.getPresence(b.username)));
      for (const [i, b] of watched.entries()) {
        const status = statuses[i] ?? 'offline';
        const prev = buddyStatusPrev[b.username] ?? 'offline';
        const wasOnline = prev !== 'offline';
        const nowOnline = status !== 'offline';
        // Only the online/offline BOUNDARY animates (a sign-on or sign-off), like AIM; away/idle flips
        // while already online do not. The very first poll only seeds, so signing in is not a burst.
        if (buddyWatchSeeded && !wasOnline && nowOnline) {
          notify(`${b.username} signed on`, '', 880);
          buddyFx[b.username] = 'on';
          changed = true;
        } else if (buddyWatchSeeded && wasOnline && !nowOnline) {
          buddyFx[b.username] = 'off';
          changed = true;
        }
        buddyStatusPrev[b.username] = status;
      }
      buddyWatchSeeded = true;
      // If the buddy list is open, re-render so the new dots + the flash show live (the flash rides the
      // next render's signals). Other views are untouched, so a status blip never yanks you out of a chat.
      if (changed && view.kind === 'buddies') {
        void openBuddies();
      }
    };
    void poll();
    buddyWatchTimer = setInterval(() => {
      void poll();
    }, 30000);
  }

  // Direct P2P file transfer (N7): the WebRTC connection lives here on the main thread (where the API
  // exists); only the small SDP/ICE signals ride the E2E channel via the controller. The file bytes go
  // peer-to-peer and never touch the server, and each peer learns the other's IP (disclosed).
  const fileTransfer =
    opts?.rtcFactory !== undefined
      ? new FileTransfer(opts.rtcFactory, {
          sendSignal: (signal) => {
            // Route the P2P handshake to the conversation the user is in (file transfers run from the
            // open conversation view, standalone or the embedded Channels pane). No-op if none active.
            const cid = activeConv(view)?.id ?? null;
            if (cid !== null) {
              controller.sendFileSignal?.(cid, JSON.stringify(signal));
            }
          },
          onProgress: () => {
            /* progress fires per chunk; the start + completion toasts are enough for now */
          },
          onIncoming: (id, name, size) => {
            promptIncomingFile(id, name, size);
          },
          onComplete: (_id, name, blob) => {
            if (blob !== null) {
              offerDownload(name, blob);
            }
            notify('File received', name, 880);
          },
          onError: (_id, message) => {
            showToast(message);
          },
        })
      : null;
  function offerDownload(name: string, blob: Blob): void {
    try {
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = name;
      a.click();
      setTimeout(() => {
        URL.revokeObjectURL(url);
      }, 10000);
    } catch {
      /* download unavailable in this environment */
    }
  }
  // Build the place a received file lands. With the File System Access API the file streams straight to
  // disk (close returns null because it is already saved); otherwise it accumulates into a Blob we then
  // offer as a download. showSaveFilePicker must be called from the accept click so it has user activation.
  async function makeSink(name: string): Promise<FileSink> {
    const picker = (window as unknown as { showSaveFilePicker?: (o: unknown) => Promise<SaveHandleLike> })
      .showSaveFilePicker;
    if (typeof picker === 'function') {
      try {
        const handle = await picker({ suggestedName: name });
        const writable = await handle.createWritable();
        return {
          write: (chunk) => writable.write(chunk),
          close: async () => {
            await writable.close();
            return null;
          },
        };
      } catch {
        /* the user cancelled the save dialog or it is unavailable; fall back to an in-memory Blob */
      }
    }
    return new BlobSink();
  }
  // Announce an incoming file and let the user accept (choosing where it saves) or decline. Going direct
  // reveals the sender's and receiver's addresses to each other, so accepting is an explicit choice.
  function promptIncomingFile(id: string, name: string, size: number): void {
    if (fileTransfer === null) {
      return;
    }
    const existing = root.querySelector(`.dd-file-prompt[data-id="${id}"]`);
    if (existing !== null) {
      return;
    }
    const el = document.createElement('div');
    el.className = 'dd-file-prompt';
    el.setAttribute('data-id', id);
    el.innerHTML =
      `<div class="dd-file-prompt-body"><div class="dd-file-prompt-title">Incoming file</div>` +
      `<div class="dd-file-prompt-name"></div>` +
      `<div class="dd-file-prompt-note">Accepting connects you directly to the sender and reveals your network address to them.</div>` +
      `<div class="dd-file-prompt-row"><button class="dd-btn dd-btn-primary" data-act="accept">Accept</button>` +
      `<button class="dd-btn" data-act="decline">Decline</button></div></div>`;
    const nameEl = el.querySelector('.dd-file-prompt-name');
    if (nameEl !== null) {
      nameEl.textContent = `${name} (${formatBytes(size)})`;
    }
    el.querySelector('[data-act="accept"]')?.addEventListener('click', () => {
      el.remove();
      showToast('receiving directly from your contact');
      void makeSink(name).then((sink) => fileTransfer.accept(id, sink));
    });
    el.querySelector('[data-act="decline"]')?.addEventListener('click', () => {
      el.remove();
      fileTransfer.decline(id);
    });
    root.appendChild(el);
  }
  /** Re-render the active chat in WHATEVER container currently holds it: the two-pane Channels pane (the
   * chat flows into the right pane) or a standalone conversation window. The single place send/receive/
   * revoke refreshes go through, so the embedded pane behaves exactly like a standalone IM. */
  function goToActive(transmit: TransmitModel): void {
    if (view.kind === 'channels') {
      const sid = transmit.conversationId ?? view.selectedId;
      go({ kind: 'channels', channels: view.channels, active: transmit, ...(sid !== undefined ? { selectedId: sid } : {}) });
    } else {
      go({ kind: 'conversation', transmit });
    }
  }

  /** Send text (or an [img:] marker) into the active conversation (standalone OR the embedded Channels
   * pane), guarding the transport size cap. Shared by the compose submit and by attaching an image. */
  function sendConversationText(text: string): void {
    const ac = activeConv(view);
    if (ac === null) {
      return;
    }
    const convId = ac.id;
    void controller
      .sendMessage(convId, text, composeLifetimes.get(convId) ?? DEFAULT_COMPOSE_LIFETIME)
      .then((transmit) => {
        // Set the refocus flag HERE, not at dispatch: go() -> render() is synchronous, so nothing can
        // interleave between this set and the send's own render. Set at dispatch, a faster inbound render
        // (openChannel needs no gateway round trip; the send does) would consume the one-shot flag first,
        // wrongly refocusing on receive AND losing the send's keep-typing focus.
        refocusComposeAfterRender = true;
        goToActive(transmit);
      })
      .catch((err: unknown) => {
        console.warn('send failed:', err instanceof Error ? err.message : String(err));
        const cur = activeConv(view);
        if (cur !== null && cur.id === convId) {
          const note: LogEntry = { kind: 'system', text: '» could not send · set this channel up again to keep talking' };
          refocusComposeAfterRender = true; // the failed-send repaint keeps you typing too
          goToActive({ ...cur.transmit, log: [...cur.transmit.log, note] });
        }
      });
  }

  /** Stream a file to the peer over the direct P2P (WebRTC) path — full size, no re-encoding, but online-
   * only and it reveals your network address. Used for non-image files and for large image originals. */
  function p2pSendFile(file: File): void {
    if (fileTransfer === null) {
      showToast('file sharing is unavailable here');
      return;
    }
    // Stream the file in slices so an arbitrarily large file is never held in memory whole.
    const source = {
      size: file.size,
      slice: async (start: number, end: number) => new Uint8Array(await file.slice(start, end).arrayBuffer()),
    };
    showToast('sending directly to your contact; this reveals your network address to them');
    void fileTransfer.sendFile(crypto.randomUUID(), file.name, source);
  }

  /** Handle a file chosen from the Attach File picker. Images ride INLINE as a message (visible to both,
   * works offline, echoes to your own log, and lands in Note to Self); a large image original in a peer
   * chat keeps full quality over P2P; a non-image file goes P2P (peers only — Note to Self has no peer). */
  async function sendFileFromPicker(file: File): Promise<void> {
    const isSelf = activeConv(view)?.transmit.selfNote === true;
    if (file.type.startsWith('image/')) {
      // Try a near-full-size inline encoding first. If it will not fit at good quality, a peer chat sends
      // the original P2P; Note to Self (no peer) shrinks harder to fit inline.
      let uri = await prepareInlineImage(file, 'good');
      if (uri === null && isSelf) {
        uri = await prepareInlineImage(file, 'fit');
      }
      if (uri !== null) {
        const marker = `[img:${uri}]`;
        if (utf8Bytes(marker) > MESSAGE_BYTES_MAX) {
          showToast('that image is too large to send');
          return;
        }
        sendConversationText(marker);
        return;
      }
      if (!isSelf && fileTransfer !== null) {
        p2pSendFile(file); // large original, peer present: full quality over P2P
        return;
      }
      showToast('could not add that image');
      return;
    }
    if (isSelf) {
      showToast('Note to Self supports images only');
      return;
    }
    p2pSendFile(file);
  }

  // Direct P2P audio/video calls (P2): like file transfer, the WebRTC connection lives here on the main
  // thread; only the SDP/ICE signals ride the E2E channel. The audio (Opus, compressed + low-latency)
  // and video media go peer-to-peer, are encrypted by WebRTC (DTLS-SRTP), and never touch the server.
  // Each peer learns the other's IP (disclosed in honest-limits). Calls are 1:1.
  let activeCallId: string | null = null;
  let callTimer: ReturnType<typeof setInterval> | null = null;
  let callStartMs = 0;
  let callMicOn = true;
  let callCamOn = true;
  const callSession =
    opts?.rtcFactory !== undefined && opts.media !== undefined
      ? new CallSession(opts.rtcFactory as unknown as RtcMediaFactory, opts.media, {
          sendSignal: (signal) => {
            // Route the call's P2P handshake to the conversation the user is in. No-op if none active.
            const cid = activeConv(view)?.id ?? null;
            if (cid !== null) {
              controller.sendCallSignal?.(cid, JSON.stringify(signal));
            }
          },
          onIncoming: (id, withVideo) => promptIncomingCall(id, withVideo),
          onState: (id, state) => onCallState(id, state),
          onLocalStream: (_id, stream) => attachStream('dd-call-local', stream),
          onRemoteStream: (_id, stream) => attachStream('dd-call-remote', stream),
          onError: (_id, message) => showToast(message),
        })
      : null;

  function currentPeerName(): string {
    return activeConv(view)?.transmit.peer ?? 'your contact';
  }
  function startOutgoingCall(withVideo: boolean): void {
    if (callSession === null) {
      showToast('calls are unavailable here');
      return;
    }
    if (activeConv(view)?.transmit.secure !== true) {
      showToast('open a secure conversation to call');
      return;
    }
    if (activeCallId !== null) {
      return;
    }
    const id = crypto.randomUUID();
    activeCallId = id;
    callMicOn = true;
    callCamOn = withVideo;
    showCallOverlay(id, currentPeerName(), withVideo);
    setCallStatus('calling…');
    void callSession.startCall(id, withVideo);
  }
  function promptIncomingCall(id: string, withVideo: boolean): void {
    if (callSession === null) {
      return;
    }
    if (activeCallId !== null) {
      callSession.decline(id); // 1:1 calls: busy
      return;
    }
    notify('Incoming call', withVideo ? 'Video call' : 'Audio call', 660);
    const el = document.createElement('div');
    el.className = 'dd-file-prompt dd-call-prompt';
    el.setAttribute('data-id', id);
    el.innerHTML =
      `<div class="dd-file-prompt-title">Incoming ${withVideo ? 'video ' : ''}call</div>` +
      `<div class="dd-file-prompt-name"></div>` +
      `<div class="dd-file-prompt-note">Accepting connects you directly and reveals your network address to them.</div>` +
      `<div class="dd-file-prompt-row"><button class="dd-btn dd-btn-primary" data-act="accept">Accept</button>` +
      `<button class="dd-btn" data-act="decline">Decline</button></div>`;
    const nameEl = el.querySelector('.dd-file-prompt-name');
    if (nameEl !== null) {
      nameEl.textContent = `from ${currentPeerName()}`;
    }
    el.querySelector('[data-act="accept"]')?.addEventListener('click', () => {
      el.remove();
      activeCallId = id;
      callMicOn = true;
      callCamOn = withVideo;
      showCallOverlay(id, currentPeerName(), withVideo);
      setCallStatus('connecting…');
      void callSession.accept(id);
    });
    el.querySelector('[data-act="decline"]')?.addEventListener('click', () => {
      el.remove();
      callSession.decline(id);
    });
    root.appendChild(el);
  }
  function onCallState(id: string, state: CallState): void {
    if (id !== activeCallId) {
      if (state === 'ended') {
        root.querySelector(`.dd-call-prompt[data-id="${id}"]`)?.remove();
      }
      return;
    }
    if (state === 'ended') {
      closeCallOverlay();
      return;
    }
    if (state === 'connected') {
      if (callTimer === null) {
        callStartMs = Date.now();
        callTimer = setInterval(updateCallClock, 1000);
      }
      updateCallClock();
    } else {
      setCallStatus(state === 'calling' ? 'calling…' : 'connecting…');
    }
  }
  function showCallOverlay(id: string, peer: string, withVideo: boolean): void {
    closeCallOverlay(false);
    const camBtn = withVideo
      ? '<button class="dd-btn" data-call="cam">Camera off</button>'
      : '';
    const el = document.createElement('div');
    el.className = 'dd-call';
    el.id = 'dd-call-overlay';
    el.innerHTML =
      `<div class="dd-call-stage${withVideo ? '' : ' dd-call-audio'}">` +
      `<video id="dd-call-remote" class="dd-call-remote" autoplay playsinline></video>` +
      `<video id="dd-call-local" class="dd-call-local" autoplay playsinline muted></video>` +
      `<div class="dd-call-avatar">${escapeHtml(peer.slice(0, 1).toUpperCase() || '?')}</div>` +
      `<div class="dd-call-bar"><span class="dd-call-peer"></span>` +
      `<span class="dd-call-status" id="dd-call-status"></span></div>` +
      `<div class="dd-call-controls"><button class="dd-btn" data-call="mic">Mute</button>` +
      `${camBtn}<button class="dd-btn dd-btn-danger" data-call="hangup">Hang up</button></div></div>`;
    const peerEl = el.querySelector('.dd-call-peer');
    if (peerEl !== null) {
      peerEl.textContent = peer;
    }
    el.querySelector('[data-call="mic"]')?.addEventListener('click', (e) => {
      callMicOn = !callMicOn;
      callSession?.setMicEnabled(id, callMicOn);
      if (e.target instanceof HTMLElement) {
        e.target.textContent = callMicOn ? 'Mute' : 'Unmute';
      }
    });
    el.querySelector('[data-call="cam"]')?.addEventListener('click', (e) => {
      callCamOn = !callCamOn;
      callSession?.setCameraEnabled(id, callCamOn);
      if (e.target instanceof HTMLElement) {
        e.target.textContent = callCamOn ? 'Camera off' : 'Camera on';
      }
    });
    el.querySelector('[data-call="hangup"]')?.addEventListener('click', () => {
      callSession?.hangup(id);
    });
    root.appendChild(el);
  }
  function setCallStatus(text: string): void {
    const el = root.querySelector('#dd-call-status');
    if (el !== null) {
      el.textContent = text;
    }
  }
  function updateCallClock(): void {
    setCallStatus(clock(Math.max(0, Math.floor((Date.now() - callStartMs) / 1000))));
  }
  function attachStream(elId: string, stream: MediaStreamLike): void {
    const el = root.querySelector(`#${elId}`);
    if (el !== null) {
      (el as unknown as { srcObject: unknown }).srcObject = stream;
    }
  }
  function closeCallOverlay(clearActive = true): void {
    if (callTimer !== null) {
      clearInterval(callTimer);
      callTimer = null;
    }
    root.querySelector('#dd-call-overlay')?.remove();
    if (clearActive) {
      activeCallId = null;
    }
  }

  // A monotonic navigation counter: bumped on every view change so a slow async loader can tell that a
  // newer navigation superseded it and bail instead of clobbering it (e.g. a double-click that opens a
  // conversation must not be bounced back to the buddy list by the preceding click's async re-render).
  // Add-a-device camera scan (QR): the live MediaStream and the frame-decode timer. Held here so any
  // navigation tears the camera down (stopScan is called at the top of go()).
  let scanStream: MediaStreamLike | null = null;
  let scanTimer: ReturnType<typeof setTimeout> | null = null;
  function stopScan(): void {
    if (scanTimer !== null) {
      clearTimeout(scanTimer);
      scanTimer = null;
    }
    if (scanStream !== null) {
      for (const t of scanStream.getTracks()) {
        t.stop();
      }
      scanStream = null;
    }
  }

  // Windows parked behind the focused one (the desktop). Per-tab UI state, never stored.
  let parkedWins: ParkedWin[] = [];
  // The two-tap confirm for DESTRUCTIVE channel actions (Remove and Block): the first tap arms with
  // an explainer toast, the second tap on the SAME action + conversation within the window executes.
  // Navigating away disarms, and the arm expires, so a stale first tap can never fire much later.
  const DESTRUCTIVE_ARM_MS = 8_000;
  let armedDestructiveTap: { action: string; id: string; at: number } | null = null;
  function armedDestructive(action: string, id: string, explainer: string): boolean {
    const a = armedDestructiveTap;
    if (a !== null && a.action === action && a.id === id && Date.now() - a.at <= DESTRUCTIVE_ARM_MS) {
      armedDestructiveTap = null;
      return true;
    }
    armedDestructiveTap = { action, id, at: Date.now() };
    showToast(explainer);
    return false;
  }
  /** Fold a freshly adopted identity card into every STORED buddy-list snapshot (parked windows and
   * minimize-tray stashes), then repaint the parked window's body in place. A parked window is drawn
   * from its snapshot on every render, so patching the DOM alone would be undone by the next repaint:
   * the snapshot itself has to move. The focused window is never touched, so a half-typed away message
   * or compose draft (which lives only in the DOM) survives. Mirrors openBuddies' own-row rules exactly,
   * so a patched snapshot and a freshly loaded one cannot disagree. */
  function patchBuddyView(adopted: IdentityProfile): (v: AppView) => AppView {
    return (v: AppView): AppView => {
      if (v.kind !== 'buddies') {
        return v;
      }
      const statuses = { ...v.statuses };
      const icons = { ...v.icons };
      const awayText = { ...v.awayText };
      for (const b of v.buddies) {
        if (normalizeUsername(b.username) !== normalizeUsername(v.ownName)) {
          continue;
        }
        statuses[b.username] = adopted.away.enabled ? 'away' : 'online';
        if (adopted.icon !== null) {
          icons[b.username] = adopted.icon;
        } else {
          delete icons[b.username]; // a sibling CLEARED the icon: no other source populates our own row
        }
        if (adopted.away.enabled && adopted.away.message.length > 0) {
          awayText[b.username] = adopted.away.message;
        } else {
          delete awayText[b.username];
        }
      }
      return { ...v, profile: adopted, statuses, icons, awayText };
    };
  }

  function patchBuddySnapshots(adopted: IdentityProfile): void {
    const patch = patchBuddyView(adopted);
    // Preserve the wrapper object for entries the patch does not touch: revealNextWindow consumes the
    // top parked entry by OBJECT IDENTITY, so rebuilding every wrapper on a background event would let
    // a revealed window stay parked (a ghost duplicate whose Close appears to do nothing).
    parkedWins = parkedWins.map((p) => {
      const v = patch(p.view);
      return v === p.view ? p : { key: p.key, view: v };
    });
    minimizedWins = minimizedWins.map((m) => ({ ...m, view: patch(m.view) }));
    // Repaint just the parked buddy list's body. It is inert and unwired by construction, so re-rendering
    // its content needs no re-wiring (and must not get any).
    const parked = parkedWins.find((p) => p.key === 'kind:buddies');
    if (parked !== undefined && parked.view.kind === 'buddies') {
      const well = root.querySelector('.dd-window-parked[data-win-key="kind:buddies"] .dd-content-well');
      if (well instanceof HTMLElement) {
        well.innerHTML = renderWindowContent(parked.view);
      }
    }
  }

  /** Drop every window-stack copy of a conversation being closed for good, so nothing on the desktop
   * (a parked window, a menu-bar chip, a two-pane snapshot) can reopen the retired channel. */
  function purgeWindowsFor(conversationId: string): void {
    parkedWins = parkedWins.filter((p) => p.key !== `conv:${conversationId}`);
    minimizedWins = minimizedWins.filter((m) => m.key !== `conv:${conversationId}`);
    const strip = (v: AppView): AppView =>
      v.kind === 'channels' && v.active?.conversationId === conversationId
        ? { kind: 'channels', channels: v.channels.filter((c) => c.id !== conversationId) }
        : v;
    parkedWins = parkedWins.map((p) => ({ ...p, view: strip(p.view) }));
    minimizedWins = minimizedWins.map((m) => ({ ...m, view: strip(m.view) }));
  }
  // Half-typed drafts stashed by the mobile "‹ Channels" back button, keyed by conversation id. The
  // draft lives only in the compose DOM; every other navigation harvests it into a surviving view,
  // yet back-to-list renders no compose at all, so the text needs a home until the row reopens.
  const chanDrafts = new Map<string, string>();

  let navGen = 0;
  /** Guards doRegister against a concurrent second run (see doRegister for what that destroyed). */
  let registerInFlight = false;
  // An explicit Back off the Settings (Device Keys) screen sets this synchronously, so the revoke
  // removal-heal cascade's background roster-changed refreshes cannot repaint Settings over the buddy list
  // (a navGen race: guard-less openSettings has fewer awaits than openBuddies and wins). Cleared only when
  // the user deliberately opens Settings again.
  let suppressSettingsRefresh = false;
  // A freshly added device is healed into every existing conversation, which streams peer Welcomes (each
  // firing 'established') for seconds, and with paced publishing well after the user taps Done and lands on
  // the buddy list. Suppress established-driven auto-open until that backfill goes quiet, so a late heal
  // Welcome never yanks the new device off the buddy list into a chat. Sliding: each suppressed heal
  // establish extends the window, so it self-tunes to the heal's real length rather than a fixed guess.
  let suppressAutoOpenUntil = 0;
  const POST_PROVISION_QUIET_MS = 4000;
  // A freshly-JOINED device gets a much longer auto-open quiet window: the seed-holder's self-group heal
  // is paced (3s polls over up to 120s), so the self-group Welcome can arrive minutes after Done, in the
  // window where a not-yet-settled certificate can make it momentarily unclassifiable as self. During
  // this window nothing AUTO-opens (established events land silently in the list); the user's own
  // navigation is never affected. Matches the heal window (SIBLING_HEAL_WINDOW_MS).
  const POST_JOIN_QUIET_MS = 120000;
  // Set by a user SEND so the very next render refocuses the compose (Enter and clicking Send both blur the
  // input, yet you must be able to keep typing). An inbound message rebuilds the same view WITHOUT setting
  // this, so receiving never steals focus back to the compose (which on mobile scrolls the viewport and
  // yanks the caret). One-shot: render consumes and clears it.
  let refocusComposeAfterRender = false;
  // Coalesce the revoke cascade's roster-changed storm (one event per conversation, spread over seconds by
  // publish pacing and the staged-remove backstops) into ONE trailing Settings refresh, instead of a
  // listDevices call + potential full-DOM rebuild per event.
  let settingsRefreshTimer: ReturnType<typeof setTimeout> | null = null;
  const SETTINGS_REFRESH_DEBOUNCE_MS = 350;
  // Coalesce the roster-changed reconcile trio the same way: one trailing heal pass per burst instead of
  // one per event, so a revoke cascade cannot flood the serialized worker chain (which starves every
  // other worker call, most visibly the Back button's buddy-list reads). The heal still converges: each
  // completed staged add fires another roster-changed, which re-arms the timer for the next pass.
  let reconcileTimer: ReturnType<typeof setTimeout> | null = null;
  const RECONCILE_DEBOUNCE_MS = 400;
  /** True when `next` differs from the current view ONLY in the active conversation's log/compose (a
   * send or an inbound message): everything rendered OUTSIDE the log (window set, header, peer name,
   * secure state, channel list, notices) is unchanged, so the fast log-only refresh is safe. Any doubt
   * answers false and the full render runs. */
  const isLogOnlyRefresh = (next: AppView): boolean => {
    const chrome = (a: TransmitModel, b: TransmitModel): boolean =>
      a.conversationId !== null &&
      a.conversationId === b.conversationId &&
      a.peer === b.peer &&
      a.secure === b.secure &&
      a.selfNote === b.selfNote &&
      a.fingerprint === b.fingerprint &&
      a.peerHandle === b.peerHandle &&
      a.peerIsBuddy === b.peerIsBuddy;
    if (view.kind === 'conversation' && next.kind === 'conversation') {
      return chrome(view.transmit, next.transmit);
    }
    if (view.kind === 'channels' && next.kind === 'channels') {
      return (
        view.channels === next.channels && // same list snapshot: rows/badges/previews unchanged
        view.selectedId === next.selectedId &&
        view.notice === next.notice &&
        view.active !== undefined &&
        next.active !== undefined &&
        chrome(view.active, next.active)
      );
    }
    return false;
  };

  /** Revoke one of our own until-revoked messages: every member device destroys its stored copy.
   * The controls live INSIDE the log entries, so both renderers create them listener-less: the full
   * render (wire) and the log-only fast path must each rewire them after their innerHTML swap. */
  function wireRevokeButtons(): void {
    root.querySelectorAll('[data-action="revoke-msg"]').forEach((el) => {
      el.addEventListener('click', () => {
        const ac = activeConv(view);
        if (!(el instanceof HTMLElement) || ac === null) {
          return;
        }
        const mid = el.dataset.mid;
        if (mid === undefined || controller.revokeMessage === undefined) {
          return;
        }
        void controller
          .revokeMessage(ac.id, mid)
          .then((transmit) => goToActive(transmit))
          .catch((err: unknown) => {
            // A dead transport leaves the stored copy (and this control) intact; say so.
            console.warn('revoke failed:', err instanceof Error ? err.message : String(err));
            const cur = activeConv(view);
            if (cur !== null && cur.id === ac.id) {
              const note: LogEntry = { kind: 'system', text: '» could not revoke · check the connection and try again' };
              goToActive({ ...cur.transmit, log: [...cur.transmit.log, note] });
            }
          });
      });
    });
  }

  /** The hot-path renderer: replace ONLY the chat log's children (plus the burn ticker / scrollbar sync
   * and the post-send refocus), leaving the rest of the DOM alive. The full render() tears down and
   * rewires the ENTIRE desktop per event, which made every send/receive O(whole UI); a message only
   * changes the log. Falls back to the full render when the log element is missing. */
  const renderLogOnly = (): void => {
    const ac = activeConv(view);
    const logEl = root.querySelector('.dd-log');
    if (ac === null || !(logEl instanceof HTMLElement)) {
      render();
      return;
    }
    const stick = logEl.scrollHeight - logEl.scrollTop - logEl.clientHeight < 48;
    const keep = logEl.scrollTop;
    logEl.innerHTML = ac.transmit.log.map(renderEntry).join('');
    logEl.scrollTop = stick ? logEl.scrollHeight : keep;
    logEl.dispatchEvent(new Event('scroll')); // the custom scrollbar thumb re-syncs off the live element
    wireRevokeButtons(); // the innerHTML swap created fresh, listener-less revoke controls
    syncBurnTicker();
    if (refocusComposeAfterRender) {
      refocusComposeAfterRender = false;
      const compose = root.querySelector('#dd-compose-input');
      if (compose instanceof HTMLElement) {
        focusAtEnd(compose);
      }
    }
    lastRenderedConvId = ac.id;
  };

  const go = (next: AppView): void => {
    if (view.kind === 'settings' && next.kind !== 'settings') {
      suppressSettingsRefresh = true; // leaving Settings: a background roster-changed refresh must not follow us back
    }
    // Settings -> Settings is a REPAINT of a list the user is pointing at (the revoked row appearing after
    // a revoke). Rebuilding resets the scroll container to the top, so the row under the cursor silently
    // becomes a DIFFERENT device: the next click revokes the wrong one. Carry the offset across the
    // rebuild. Only same-kind repaints, so a deliberate navigation still starts at the top.
    const keepScroll = view.kind === 'settings' && next.kind === 'settings' ? settingsScrollTop() : null;
    const fastLog = isLogOnlyRefresh(next); // decide against the OUTGOING view, before any mutation below
    navGen++;
    stopScan(); // any navigation ends an in-progress camera scan and releases the camera
    if (armedDestructiveTap !== null && activeConv(next)?.id !== armedDestructiveTap.id) {
      armedDestructiveTap = null; // leaving the conversation visibly disarms the pending destructive tap
    }
    // Carry a half-typed compose draft across a re-render of the SAME conversation. An incoming message or
    // an autonomous expiry rebuilds the whole view, and the draft lives ONLY in the contenteditable DOM
    // (the model never persists keystrokes), so without this it would be silently wiped mid-sentence. A
    // send clears the live compose first, so nothing is carried there; switching conversations or leaving
    // the view does not carry (the ids differ, or the next view is not a conversation).
    if (
      view.kind === 'conversation' &&
      next.kind === 'conversation' &&
      view.transmit.conversationId !== null &&
      view.transmit.conversationId === next.transmit.conversationId &&
      next.transmit.compose === ''
    ) {
      const liveCompose = root.querySelector('#dd-compose-input');
      if (liveCompose instanceof HTMLElement) {
        const draft = serializeRichText(liveCompose);
        if (draft.trim().length > 0) {
          next = { ...next, transmit: { ...next.transmit, compose: draft } };
        }
      }
    }
    // The same carry for the two-pane Channels chat: an incoming message re-renders the pane with compose=''
    // and would wipe a half-typed embedded draft without this.
    if (
      view.kind === 'channels' &&
      next.kind === 'channels' &&
      view.selectedId !== undefined &&
      view.selectedId === next.selectedId &&
      next.active !== undefined &&
      next.active.compose === ''
    ) {
      const liveCompose = root.querySelector('#dd-compose-input');
      if (liveCompose instanceof HTMLElement) {
        const draft = serializeRichText(liveCompose);
        if (draft.trim().length > 0) {
          next = { ...next, active: { ...next.active, compose: draft } };
        }
      }
    }
    // Multi-window desktop routing. Navigating to a DIFFERENT window (a different key) parks the current
    // one if it is a primary window (the buddy list, channels, or a conversation — these stay on the
    // desktop behind the new one, item 8) or drops it if it is a transient editor/flow (Profile, Away,
    // Setup, Get Info, key exchange, etc. — these dismiss when you leave them). A same-key navigation is
    // an in-place refresh of the focused window (send, receive, an error note), and pre-login/onboarding
    // is a single standalone modal with no desktop behind it.
    const gateNext =
      next.kind === 'unlock' || next.kind === 'newdevice-wizard' || next.kind === 'recovery' || next.kind === 'recover-entry';
    if (gateNext) {
      parkedWins = [];
    } else if (windowKey(next) !== windowKey(view)) {
      // Focusing an already-open (parked) window brings it forward: drop the stale parked copy; the fresh
      // `next` becomes live.
      parkedWins = parkedWins.filter((p) => p.key !== windowKey(next));
      if (isPrimaryWindow(view)) {
        // Park the outgoing primary window, harvesting a conversation's half-typed draft so it survives
        // behind the new window (the draft lives only in the DOM).
        let parkView = view;
        if (view.kind === 'conversation') {
          const liveCompose = root.querySelector('#dd-compose-input');
          const draft = liveCompose instanceof HTMLElement ? serializeRichText(liveCompose) : '';
          parkView = { ...view, transmit: { ...view.transmit, compose: draft, log: [] } };
        } else if (view.kind === 'channels' && view.active !== undefined) {
          // Park the two-pane keeping its embedded draft but DROPPING the decrypted log (never park plaintext).
          const liveCompose = root.querySelector('#dd-compose-input');
          const draft = liveCompose instanceof HTMLElement ? serializeRichText(liveCompose) : '';
          parkView = { ...view, active: { ...view.active, compose: draft, log: [] } };
        }
        parkedWins = [...parkedWins.filter((p) => p.key !== windowKey(view)), { key: windowKey(view), view: parkView }];
      }
    }
    // If the window we are navigating to was minimized, this navigation restores it: drop its tray chip so
    // a stale "restore" entry does not linger in the menu bar for a window that is now open and focused.
    minimizedWins = minimizedWins.filter((m) => m.key !== windowKey(next));
    view = next;
    // Keep the per-tab resume hint current so a refresh returns to the same place (S1). Only once logged
    // in (currentUsername set), and never on the unlock screen itself. The conversation id is remembered
    // when one is open, so the refresh reopens it; otherwise just the username (the screen pre-fill).
    if (currentUsername !== '' && next.kind !== 'unlock') {
      if (next.kind === 'conversation' && next.transmit.conversationId !== null) {
        saveResume({ username: currentUsername, conversationId: next.transmit.conversationId });
      } else {
        saveResume({ username: currentUsername });
      }
    }
    if (fastLog) {
      renderLogOnly(); // a send/receive touches only the log: skip the full-desktop teardown + rewire
    } else {
      render();
    }
    // A pending revoke confirm ANCHORS ON THE ROW ITSELF, not on a scroll offset. The offset restore
    // below proved fragile here (with parked windows on the desktop there can be several .dd-form
    // elements, and the first one is not necessarily the live list), and an offset is the wrong model
    // anyway: inserting the confirm strip shifts the rows, so the same offset can put a DIFFERENT
    // device under the pointer, and the user, mid-gesture, almost revokes it. block:'nearest' means a
    // row that is already visible does not move at all; focus lands on the confirm button so the next
    // tap or Enter lands on the SAME device the first click armed.
    if (next.kind === 'settings' && next.pending !== undefined) {
      const confirm = root.querySelector(`[data-action="revoke-confirm"][data-device="${cssEscape(next.pending)}"]`);
      if (confirm instanceof HTMLElement) {
        confirm.focus();
        if (typeof confirm.scrollIntoView === 'function') {
          confirm.scrollIntoView({ block: 'nearest' });
        }
      }
    } else if (keepScroll !== null) {
      restoreSettingsScroll(keepScroll); // put the list back where the user left it (see keepScroll above)
    }
  };

  /** The Device keys list scrolls inside the form; read/write its offset so a repaint does not move the
   * rows out from under the pointer. Returns null when that container is not on screen. */
  /** The LIVE window's scrolling form. With parked windows on the desktop several .dd-form elements
   * can coexist and the live window paints LAST, so querySelector (the first match) read a parked
   * snapshot's offset — always 0 — and the "restore" reset the real list to the top. */
  function liveSettingsForm(): HTMLElement | null {
    const forms = root.querySelectorAll('.dd-form');
    const el = forms.length > 0 ? forms[forms.length - 1] : null;
    return el instanceof HTMLElement ? el : null;
  }

  function settingsScrollTop(): number | null {
    const el = liveSettingsForm();
    return el !== null && el.scrollTop > 0 ? el.scrollTop : null;
  }

  function restoreSettingsScroll(top: number): void {
    const el = liveSettingsForm();
    if (el !== null) {
      el.scrollTop = top;
    }
  }

  /** CSS.escape with a fallback for environments without it (device ids are hex, so the escape is
   * belt-and-suspenders; the fallback strips anything that could break out of the selector). */
  function cssEscape(v: string): string {
    return typeof CSS !== 'undefined' && typeof CSS.escape === 'function' ? CSS.escape(v) : v.replace(/[^a-zA-Z0-9_-]/g, '');
  }

  // Whether the user asked the OS to reduce motion; animations are skipped (and their post-step runs
  // immediately) when true, matching the CSS `prefers-reduced-motion` rules.
  function reducedMotion(): boolean {
    try {
      return typeof window.matchMedia === 'function' && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    } catch {
      return false;
    }
  }

  // ── Appearance / theming (AIM18) ─────────────────────────────────────────────────────────────────
  // Put the chosen theme class on the desktop root and layer the user's validated token tweaks on top via
  // the CSSOM (setProperty is allowed under the strict CSP; only inline style ATTRIBUTES are blocked). The
  // default theme is the ABSENCE of a class, so the base skin is never touched. Called from render(), after
  // root.className/innerHTML are set, so a rebuilt DOM always keeps the look (and the matrix is re-attached).
  function applyAppearance(): void {
    const cls = THEME_CLASS[appearance.theme] ?? '';
    // dd-native switches the app to the single frameless-window layout when running inside the desktop
    // shell (see the .dd-native CSS + the re-targeted window controls); it is never present in a browser.
    root.className = ['dd-desk', cls, isNativeShell() ? 'dd-native' : ''].filter((c) => c !== '').join(' ');
    // Clear any token overrides from a previous appearance, then apply the current (already-validated) set.
    for (const token of APPEARANCE_TOKENS) {
      root.style.removeProperty(token);
    }
    for (const [token, value] of Object.entries(appearance.tokens)) {
      if (isValidTokenValue(token, value)) {
        root.style.setProperty(token, value);
      }
    }
  }

  // The Matrix "digital rain" that sits behind IM logs under the h4x0r theme. innerHTML wipes any injected
  // canvas on every render, so we rebuild the target list each time and keep ONE shared rAF loop that draws
  // to whatever canvases are currently attached. Reduced-motion (or any other theme) tears it down.
  interface MatrixTarget {
    readonly canvas: HTMLCanvasElement;
    readonly ctx: CanvasRenderingContext2D;
    cols: number;
    drops: number[];
    w: number;
    h: number;
  }
  // The current render's scrollbar syncs, so a size change with no scroll event (the grow-box resize)
  // can refresh every thumb (see wireWindowDrag's done()).
  const logScrollbarSyncs: (() => void)[] = [];

  // AIM23 chat-window icon column: cache the last-known own icon and each conversation's peer icon so a
  // re-render paints them instantly (no flicker) while wireChatIcons refreshes them from the controller.
  let chatSelfIcon: BuddyIcon | null = null;
  const chatPeerIconCache = new Map<string, BuddyIcon | null>();

  const MATRIX_GLYPHS = 'ｱｲｳｴｵｶｷｸｹｺｻｼｽ0123456789ABCDEF<>=*+-/\\|';
  const MATRIX_FONT = 14; // px per column/row cell
  const MATRIX_STEP_MS = 55; // advance the rain a row about every 55ms, independent of the display refresh
  let matrixTargets: MatrixTarget[] = [];
  let matrixRaf: number | null = null;
  let matrixLast = 0;

  function sizeMatrix(t: MatrixTarget): void {
    const host = t.canvas.parentElement;
    if (host === null) {
      return;
    }
    const w = host.clientWidth;
    const h = host.clientHeight;
    if (w === t.w && h === t.h) {
      return;
    }
    t.w = w;
    t.h = h;
    t.canvas.width = w;
    t.canvas.height = h;
    const cols = Math.max(1, Math.floor(w / MATRIX_FONT));
    const drops: number[] = [];
    for (let i = 0; i < cols; i++) {
      drops[i] = t.drops[i] ?? Math.floor((Math.random() * h) / MATRIX_FONT);
    }
    t.cols = cols;
    t.drops = drops;
  }

  function drawMatrix(now: number): void {
    matrixRaf = requestAnimationFrame(drawMatrix);
    if (now - matrixLast < MATRIX_STEP_MS) {
      return;
    }
    matrixLast = now;
    for (const t of matrixTargets) {
      sizeMatrix(t);
      const { ctx, w, h } = t;
      ctx.fillStyle = 'rgba(0, 4, 0, 0.10)'; // translucent black wash → glowing trails behind each head
      ctx.fillRect(0, 0, w, h);
      ctx.font = MATRIX_FONT + 'px monospace';
      for (let i = 0; i < t.cols; i++) {
        const drop = t.drops[i] ?? 0;
        const ch = MATRIX_GLYPHS.charAt(Math.floor(Math.random() * MATRIX_GLYPHS.length));
        const x = i * MATRIX_FONT;
        const y = drop * MATRIX_FONT;
        ctx.fillStyle = drop < 1.5 ? '#c9ffd4' : '#00ff41'; // brighter leading glyph, green tail
        ctx.fillText(ch, x, y);
        t.drops[i] = y > h && Math.random() > 0.975 ? 0 : drop + 1;
      }
    }
  }

  function syncMatrix(): void {
    // Any canvases from the prior render were wiped by innerHTML; rebuild the target list from live DOM.
    matrixTargets = [];
    const wantMatrix =
      appearance.theme === 'h4x0r' &&
      !reducedMotion() &&
      typeof document.createElement === 'function' &&
      typeof requestAnimationFrame === 'function';
    if (!wantMatrix) {
      if (matrixRaf !== null && typeof cancelAnimationFrame === 'function') {
        cancelAnimationFrame(matrixRaf);
      }
      matrixRaf = null;
      return;
    }
    // Host the rain inside the LIVE window's chat terminal ('.dd'), as its first child: a child paints
    // ABOVE the terminal's own opaque background but BELOW the log/compose (which themes.css lifts to
    // z-index 1), so the rain sits behind the messages. Scope to the focused window
    // ('.dd-window:not(.dd-window-parked)') so parked "frozen snapshot" windows stay static and we do not
    // animate/repaint them off-screen. '.dd' is the terminal container only (buddy list/forms use other
    // classes), and it does not itself scroll (the .dd-log inside it does), so the canvas stays put.
    root.querySelectorAll('.dd-window:not(.dd-window-parked) .dd').forEach((term) => {
      if (!(term instanceof HTMLElement)) {
        return;
      }
      const canvas = document.createElement('canvas');
      canvas.className = 'dd-matrix';
      canvas.setAttribute('aria-hidden', 'true');
      term.insertBefore(canvas, term.firstChild);
      const ctx = canvas.getContext('2d');
      if (ctx === null) {
        canvas.remove();
        return;
      }
      const target: MatrixTarget = { canvas, ctx, cols: 0, drops: [], w: 0, h: 0 };
      sizeMatrix(target);
      matrixTargets.push(target);
    });
    if (matrixTargets.length > 0 && matrixRaf === null) {
      matrixLast = 0;
      matrixRaf = requestAnimationFrame(drawMatrix);
    } else if (matrixTargets.length === 0 && matrixRaf !== null && typeof cancelAnimationFrame === 'function') {
      cancelAnimationFrame(matrixRaf);
      matrixRaf = null;
    }
  }

  // ── The working retro scrollbar (AIM20) ─────────────────────────────────────────────────────────
  // Each chat log renders with the beveled scrollbar beside it (.dd-logrow > .dd-log + .dd-scrollbar).
  // Wire it to actually drive the log: the thumb tracks scroll position/extent, the arrows step, the
  // track pages, and dragging the thumb scrubs. All styling lands via the CSSOM (CSP-safe). Bindings are
  // per-render (innerHTML replaces the nodes), so nothing accumulates.
  function wireLogScrollbars(): void {
    logScrollbarSyncs.length = 0; // the previous render's syncs point at detached nodes
    root.querySelectorAll('.dd-logrow').forEach((row) => {
      if (!(row instanceof HTMLElement)) {
        return;
      }
      const log = row.querySelector('.dd-log');
      const track = row.querySelector('.dd-sb-track');
      const thumb = row.querySelector('.dd-sb-thumb');
      const arrows = row.querySelectorAll('.dd-sb-arrow');
      if (!(log instanceof HTMLElement) || !(track instanceof HTMLElement) || !(thumb instanceof HTMLElement)) {
        return;
      }
      const sync = (): void => {
        const overflow = log.scrollHeight - log.clientHeight;
        const frac = log.scrollHeight > 0 ? log.clientHeight / log.scrollHeight : 1;
        const h = Math.max(14, Math.round(track.clientHeight * Math.min(1, frac)));
        const top = overflow > 0 ? Math.round((track.clientHeight - h) * (log.scrollTop / overflow)) : 0;
        thumb.style.height = `${h}px`;
        thumb.style.top = `${Math.max(0, top)}px`;
      };
      // The scroll listener keeps the thumb honest for wheel/keyboard scrolling; the control handlers ALSO
      // sync directly so the thumb tracks immediately (scroll events can be deferred in background tabs).
      log.addEventListener('scroll', sync);
      arrows[0]?.addEventListener('click', () => {
        log.scrollTop -= 48;
        sync();
      });
      arrows[1]?.addEventListener('click', () => {
        log.scrollTop += 48;
        sync();
      });
      // Click the open track (above/below the thumb) to page.
      track.addEventListener('pointerdown', (e) => {
        if (!(e instanceof PointerEvent) || e.target === thumb) {
          return;
        }
        const r = thumb.getBoundingClientRect();
        log.scrollTop += e.clientY < r.top ? -log.clientHeight : log.clientHeight;
        sync();
      });
      // Drag the thumb to scrub.
      thumb.addEventListener('pointerdown', (e) => {
        if (!(e instanceof PointerEvent)) {
          return;
        }
        e.preventDefault();
        e.stopPropagation(); // not a track page-click
        const startY = e.clientY;
        const startTop = log.scrollTop;
        const room = Math.max(1, track.clientHeight - thumb.offsetHeight);
        const scale = (log.scrollHeight - log.clientHeight) / room;
        const up = (): void => {
          document.removeEventListener('pointermove', move);
          document.removeEventListener('pointerup', up);
          document.removeEventListener('pointercancel', up);
        };
        const move = (ev: Event): void => {
          // A re-render mid-drag replaces the DOM: end the gesture instead of scrubbing a detached log.
          if (!log.isConnected) {
            up();
            return;
          }
          if (ev instanceof PointerEvent) {
            log.scrollTop = startTop + (ev.clientY - startY) * scale;
            sync();
          }
        };
        document.addEventListener('pointermove', move);
        document.addEventListener('pointerup', up);
        document.addEventListener('pointercancel', up);
      });
      sync();
      logScrollbarSyncs.push(sync);
    });
  }

  // ── The two-icon column beside each open chat (AIM23) ───────────────────────────────────────────
  // The classic AIM IM window shows both buddy icons stacked at the side: the person you are talking to
  // on top, you below. renderTransmit ships the column with empty slots (the icons load async — your own
  // identity plus the conversation's peer identity); this fills them. Cached values paint instantly so a
  // re-render never flickers; a background refresh keeps them current when either icon changes. Every
  // write is guarded by isConnected, so a fetch that resolves after the next render is dropped, not
  // written into a detached node.
  function wireChatIcons(): void {
    const cols = Array.from(root.querySelectorAll('.dd-chat-icons')).filter(
      (c): c is HTMLElement => c instanceof HTMLElement,
    );
    if (cols.length === 0) {
      return;
    }
    const fillSelf = (icon: BuddyIcon | null): void => {
      root.querySelectorAll('.dd-chat-icons [data-icon-slot="self"]').forEach((s) => {
        if (s instanceof HTMLElement && s.isConnected) {
          s.innerHTML = renderIconPreview(icon);
        }
      });
    };
    fillSelf(chatSelfIcon);
    void Promise.resolve(controller.getIdentity?.()).then((p) => {
      chatSelfIcon = (p ?? DEFAULT_IDENTITY).icon;
      fillSelf(chatSelfIcon);
    });
    const seen = new Set<string>();
    for (const col of cols) {
      const convId = col.getAttribute('data-dd-chaticons') ?? '';
      if (convId === '' || seen.has(convId)) {
        continue;
      }
      seen.add(convId);
      if (col.querySelector('[data-icon-slot="peer"]') === null) {
        continue; // Note-to-Self column carries only the self slot
      }
      const fillPeer = (icon: BuddyIcon | null): void => {
        for (const c of cols) {
          if ((c.getAttribute('data-dd-chaticons') ?? '') !== convId) {
            continue;
          }
          const s = c.querySelector('[data-icon-slot="peer"]');
          if (s instanceof HTMLElement && s.isConnected) {
            s.innerHTML = renderIconPreview(icon);
          }
        }
      };
      if (chatPeerIconCache.has(convId)) {
        fillPeer(chatPeerIconCache.get(convId) ?? null);
      }
      void Promise.resolve(controller.getPeerIdentities?.(convId)).then((peers) => {
        // Take the first peer entry that actually carries an icon, matching the buddy-list convention
        // (controller.buddyIcons): a peer's device that sent an away/bio update before its icon leaves an
        // icon:null entry first, so blindly taking peers[0] would show the ghost while the buddy list
        // shows the real icon for the same contact.
        const icon = (peers ?? []).find((p) => p.icon !== null)?.icon ?? null;
        chatPeerIconCache.set(convId, icon);
        fillPeer(icon);
      });
    }
  }

  // Play a brief exit animation on the open window, THEN run `then` (the navigation). Falls straight
  // through with no delay when motion is reduced or the window element is not present, so the flow is
  // identical either way; a safety timeout guarantees `then` runs even if animationend never fires.
  function runWindowExit(animClass: string, then: () => void): void {
    const win = root.querySelector('.dd-window');
    if (!(win instanceof HTMLElement) || reducedMotion()) {
      then();
      return;
    }
    win.classList.add(animClass);
    // Only wait when a stylesheet is actually driving an animation. In a headless/test DOM with no CSS
    // loaded (or when the class maps to no keyframes), there is nothing to wait for, so navigate at once.
    let anim = '';
    try {
      anim = window.getComputedStyle(win).animationName;
    } catch {
      /* no getComputedStyle: fall through to immediate */
    }
    if (anim === '' || anim === 'none') {
      then();
      return;
    }
    let done = false;
    const finish = (): void => {
      if (done) {
        return;
      }
      done = true;
      then();
    };
    win.addEventListener('animationend', finish, { once: true });
    window.setTimeout(finish, 320); // fallback: never strand the navigation on a missed event
  }

  // ── Connection status (AIM21) ───────────────────────────────────────────────────────────────────
  // Beyond the bare state string: when the link came up / last dropped, the reconnect backoff, and a
  // 1s ticker that keeps the countdown honest. The titlebar shows one composed headline; the popover
  // (click the status) explains it in plain words and offers Reconnect now.
  let connSince: number | null = null; // when the link came up (live/secure)
  let connLastDrop: number | null = null; // when it last went down
  let connAttempt = 0; // reconnect attempts since the last STABLE link (0 = first connect)
  let connRetryAt: number | null = null; // when the next automatic retry fires
  let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  let connTicker: ReturnType<typeof setInterval> | null = null;
  let connStableTimer: ReturnType<typeof setTimeout> | null = null; // resets the backoff only once the link HOLDS
  let siblingHealTimer: ReturnType<typeof setTimeout> | null = null; // polls a just-added device into the self-group
  let siblingHealGen = 0; // bumped on each heal arm + on teardown so a stale in-flight tick cannot re-arm
  // Deterministic adder-gate rejections per device key (certless, forged, or below-floor package). Two
  // strikes abort the heal poll for that device: every further tick would claim and burn one more of
  // its packages against a directory that can only serve rejected ones. Reset when a new heal arms.
  const siblingAddRejections = new Map<string, number>();
  // The last rejection REASON per device key, so the abort toast can say what actually happened instead
  // of leaving the only copy of it in a console line the user was never going to open.
  const siblingAddRejectReasons = new Map<string, string>();

  function connDisplayLabel(): string {
    if (connState === 'connecting' && connAttempt > 0) {
      return '◍ RECONNECTING…';
    }
    if (connState === 'offline' && connRetryAt !== null) {
      const s = Math.max(0, Math.ceil((connRetryAt - Date.now()) / 1000));
      return `◍ RETRY IN ${s}s`;
    }
    return CONN_LABELS[connState] ?? '';
  }

  // Plain words for the popover: what the state MEANS for the user's messages, E2E framing first.
  function connExplanation(): string {
    if (connState === 'secure') {
      return 'End-to-end encrypted session active. Messages travel only as sealed envelopes.';
    }
    if (connState === 'live') {
      return 'Gateway link up. The end-to-end session is not established yet.';
    }
    if (connState === 'connecting') {
      return connAttempt > 0 ? 'Trying to reach the gateway again.' : 'Reaching the gateway…';
    }
    return 'Not connected. Anything you send waits safely on this device until the link returns.';
  }

  function fmtClock(t: number): string {
    return new Date(t).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  }

  /** Refresh the titlebar headline + the popover rows from the current state (no re-render). */
  function updateConnDisplay(): void {
    const conn = root.querySelector('#dd-conn');
    if (conn instanceof HTMLElement) {
      conn.textContent = connDisplayLabel();
      conn.className = `dd-title-conn dd-conn-${connState}`;
    }
    const pop = root.querySelector('#dd-conn-pop');
    if (!(pop instanceof HTMLElement)) {
      return;
    }
    const put = (sel: string, text: string): void => {
      const el = pop.querySelector(sel);
      if (el instanceof HTMLElement) {
        el.textContent = text;
      }
    };
    put('.dd-connp-state', connDisplayLabel());
    put('.dd-connp-exp', connExplanation());
    let gw = 'no gateway configured';
    if (opts?.wsUrl !== undefined) {
      try {
        gw = `gateway ${new URL(opts.wsUrl).host}`;
      } catch {
        gw = 'gateway configured';
      }
    }
    put('.dd-connp-gw', gw);
    put(
      '.dd-connp-time',
      connSince !== null ? `connected since ${fmtClock(connSince)}` : connLastDrop !== null ? `link dropped at ${fmtClock(connLastDrop)}` : '',
    );
    const now = pop.querySelector('.dd-connp-now');
    if (now instanceof HTMLElement) {
      // Offer the manual retry whenever we are down and could actually try (signed in, gateway known).
      now.hidden = !(connState === 'offline' && opts?.wsUrl !== undefined && currentUsername !== '');
    }
  }

  function stopConnTicker(): void {
    if (connTicker !== null) {
      clearInterval(connTicker);
      connTicker = null;
    }
  }

  // ── Live burn countdown (AIM25) ──────────────────────────────────────────────────────────────────
  // A duration message's "burns m:ss" must tick every second while the conversation is open, not only
  // when the next message arrives. Mirroring connTicker, this is a TARGETED DOM update (textContent +
  // near-expiry classes on the .dd-burn[data-expires-at] nodes), so it never disturbs the compose caret or
  // scroll position the way a full re-render would. DESTRUCTION is left to the worker: its expiry timer
  // crypto-erases the message at 0 and fires the 'erased' event, which re-fetches the log and shows the
  // tombstone — so the ticker only paints the countdown (no re-fetch here, no race with that path).
  let burnTicker: ReturnType<typeof setInterval> | null = null;
  function stopBurnTicker(): void {
    if (burnTicker !== null) {
      clearInterval(burnTicker);
      burnTicker = null;
    }
  }
  // Returns whether at least one message is still counting down (rem > 0), so syncBurnTicker only starts an
  // interval when there is something live to tick (avoids a start→one-tick→self-stop churn per render).
  function updateBurnDisplay(): boolean {
    if (activeConv(view) === null) {
      stopBurnTicker();
      return false;
    }
    const nodes = root.querySelectorAll('.dd-log .dd-burn[data-expires-at]');
    if (nodes.length === 0) {
      stopBurnTicker();
      return false;
    }
    const now = Date.now();
    let anyLive = false;
    nodes.forEach((el) => {
      if (!(el instanceof HTMLElement)) {
        return;
      }
      const at = Number(el.getAttribute('data-expires-at'));
      if (!Number.isFinite(at)) {
        return;
      }
      const rem = Math.max(0, Math.round((at - now) / 1000));
      el.textContent = `burns ${clock(rem)}`;
      const near = rem <= 10;
      const meta = el.closest('.dd-meta');
      const line = el.closest('.dd-line');
      if (meta instanceof HTMLElement) {
        meta.classList.toggle('dd-warn', near);
        meta.classList.toggle('dd-near', near);
      }
      if (line instanceof HTMLElement) {
        line.classList.toggle('dd-warn', near);
        const msg = line.querySelector('.dd-msg');
        if (msg instanceof HTMLElement) {
          msg.classList.toggle('dd-warn', near);
        }
      }
      if (rem > 0) {
        anyLive = true;
      }
    });
    // Nothing left counting down (every stamped message reached 0): stop until the next render restarts us.
    // The worker's expiry timer + 'erased' event replace each expired message with the tombstone.
    if (!anyLive) {
      stopBurnTicker();
    }
    return anyLive;
  }
  // Start/stop the burn ticker for the freshly-rendered DOM: run only while a chat with at least one live
  // (armed-duration) countdown is open. Called from render() right after the DOM is rebuilt.
  function syncBurnTicker(): void {
    if (root.querySelector('.dd-log .dd-burn[data-expires-at]') === null) {
      stopBurnTicker();
      return;
    }
    const stillLive = updateBurnDisplay(); // paint the current second immediately
    if (stillLive && burnTicker === null && typeof setInterval === 'function') {
      burnTicker = setInterval(updateBurnDisplay, 1000);
    }
  }

  /** Stop every reconnect timer and forget the backoff (used when leaving the signed-in world without a
   * page reload, e.g. abandoning the add-this-device wizard). */
  function disarmReconnect(): void {
    if (reconnectTimer !== null) {
      clearTimeout(reconnectTimer);
      reconnectTimer = null;
    }
    if (connStableTimer !== null) {
      clearTimeout(connStableTimer);
      connStableTimer = null;
    }
    if (siblingHealTimer !== null) {
      clearTimeout(siblingHealTimer);
      siblingHealTimer = null;
    }
    siblingHealGen++; // invalidate any in-flight heal tick so it cannot re-arm after this teardown
    stopConnTicker();
    connRetryAt = null;
    connAttempt = 0;
  }

  /** Quiet auto-reconnect: exponential backoff 3s → 60s, countdown visible, no popups. */
  function scheduleReconnect(): void {
    if (opts?.wsUrl === undefined || currentUsername === '' || reconnectTimer !== null) {
      return;
    }
    const delay = Math.min(3000 * 2 ** connAttempt, 60000);
    connAttempt++;
    connRetryAt = Date.now() + delay;
    reconnectTimer = setTimeout(() => {
      reconnectTimer = null;
      void reconnectNow();
    }, delay);
    if (connTicker === null) {
      connTicker = setInterval(updateConnDisplay, 1000); // keeps RETRY IN Ns counting down
    }
  }

  /** Reconnect immediately (the popover button, or a fired backoff timer). On success, bring this
   * device current again exactly like a session resume: certs/keys to the account epoch, siblings
   * admitted, the hidden self-group ensured. */
  async function reconnectNow(): Promise<void> {
    if (reconnectTimer !== null) {
      clearTimeout(reconnectTimer);
      reconnectTimer = null;
    }
    connRetryAt = null;
    const { selfContact } = await connectLive();
    if (selfContact !== null) {
      currentDeviceKey = selfContact.split(':')[3] ?? currentDeviceKey;
      await syncAndPublish();
      void reconcileRemovals();
      void reconcileSiblings();
      void ensureSelfGroup();
    }
  }

  // A mobile browser FREEZES a backgrounded tab and routinely kills the WebSocket while the phone is
  // asleep. On wake the page still believes it is connected, its socket is dead, and nothing re-runs the
  // self-group convergence, so a device that has not finished syncing sits stuck until a MANUAL reload.
  // Requiring a force-reload on a phone is not acceptable, so on the tab becoming visible again (unlock /
  // tab focus), the network returning, or a bfcache restore, force a fresh reconnect: connectLive
  // supersedes the possibly-dead socket, re-subscribes every mailbox, re-publishes the contact graph into
  // the self-group (the reconnect resync), and re-runs the self-group heal + reconcile. Throttled so a
  // burst of focus/visibility events collapses to one reconnect, and skipped mid-pairing (a reconnect is
  // preserved for a live QR machine, but a fresh cascade during the scan is needless churn).
  const WAKE_RESYNC_MIN_MS = 4000;
  let lastWakeSyncMs = 0;
  function wakeResync(): void {
    if (currentUsername === '' || opts?.wsUrl === undefined || view.kind === 'provisioning') {
      return;
    }
    const now = Date.now();
    if (now - lastWakeSyncMs < WAKE_RESYNC_MIN_MS) {
      return; // throttle: rapid focus flapping collapses to a single reconnect
    }
    lastWakeSyncMs = now;
    void reconnectNow();
    // Repaint the buddy list if it is the open view, so freshly-adopted state shows without a manual
    // navigation. The worker's buddies-updated event also drives this, but a wake with no change still
    // wants the current view refreshed off any now-converged self-group.
    if (view.kind === 'buddies') {
      void openBuddies();
    }
  }
  if (typeof document !== 'undefined' && typeof document.addEventListener === 'function') {
    document.addEventListener('visibilitychange', () => {
      if (document.visibilityState === 'visible') {
        wakeResync();
      }
    });
  }
  if (typeof window !== 'undefined' && typeof window.addEventListener === 'function') {
    window.addEventListener('online', () => wakeResync());
    window.addEventListener('pageshow', () => wakeResync()); // bfcache restore (mobile back/forward)
  }

  function setConn(state: string): void {
    // 'secure' outranks 'live': never DOWNGRADE an established E2E session to the transitional SECURING.
    // The worker posts its 'connection' event (the accurate state, 'secure' when a session is restored)
    // BEFORE connectGateway's RPC response resolves, so connectLive's own optimistic setConn('live')
    // arrives second — without this guard it would clobber 'secure' and leave a returning device stuck on
    // SECURING forever. Only 'offline' (a real drop) may take the link back down.
    if (state === 'live' && connState === 'secure') {
      return;
    }
    const wasUp = connState === 'live' || connState === 'secure';
    connState = state;
    if (state === 'live' || state === 'secure') {
      if (!wasUp || connSince === null) {
        connSince = Date.now();
      }
      connRetryAt = null;
      if (reconnectTimer !== null) {
        clearTimeout(reconnectTimer);
        reconnectTimer = null;
      }
      stopConnTicker();
      // Reset the backoff only once the link HOLDS. The transport reports 'live' optimistically
      // (before the socket actually opens), so an unreachable gateway bounces live→offline every
      // cycle; resetting connAttempt here immediately would pin the retry delay at its 3s floor
      // forever. A link that survives 5s is genuinely back.
      if (connStableTimer !== null) {
        clearTimeout(connStableTimer);
      }
      connStableTimer = setTimeout(() => {
        connStableTimer = null;
        connAttempt = 0;
      }, 5000);
    } else if (state === 'offline') {
      if (connStableTimer !== null) {
        clearTimeout(connStableTimer); // the bounce proved the link is NOT back: keep escalating
        connStableTimer = null;
      }
      if (wasUp) {
        connLastDrop = Date.now();
      }
      connSince = null;
      scheduleReconnect(); // no-op before sign-in or without a gateway
    }
    updateConnDisplay();
  }

  // Windows minimized to the menu bar (the AIM taskbar). Per-tab UI state, never stored.
  let minimizedWins: MinimizedWin[] = [];

  // Per-window geometry the user set by dragging or resizing, keyed by screen (view kind). Per-tab UI
  // state, never stored: a window comes back where you put it across the constant re-renders, and a
  // fresh tab starts with the stock centered layout.
  const winGeom = new Map<string, { x: number | null; y: number | null; w: number | null; h: number | null }>();

  // Re-apply each window's geometry after a render replaced the DOM. Styles go through the CSSOM
  // (element.style.prop), which the strict CSP allows (only inline style ATTRIBUTES are blocked); the
  // position is clamped to the stage so a window can never be dragged or restored out of reach. Runs for
  // EVERY window on the desktop (focused + parked), each keyed by its data-win-key.
  function applyWindowGeometry(): void {
    const stage = root.querySelector('.dd-stage');
    if (!(stage instanceof HTMLElement)) {
      return;
    }
    // AIM19: every window is absolutely positioned from its FIRST paint, so opening a window can never
    // reflow or resize the ones already on the desktop (flex-flow siblings used to squeeze each other).
    // A window with no stored spot gets one now: top-centered, stepped down-right a notch per window
    // already on the stage (the classic cascade), and the spot is stored so it holds across re-renders.
    // After that only the user moves or resizes it (drag/grow-box below).
    const wins = Array.from(root.querySelectorAll('.dd-window[data-win-key]')).filter((w): w is HTMLElement => w instanceof HTMLElement);
    let placed = wins.filter((w) => winGeom.has(w.dataset.winKey ?? '')).length;
    for (const win of wins) {
      const key = win.dataset.winKey ?? '';
      if (key === '' || winGeom.has(key)) {
        continue;
      }
      win.style.position = 'absolute'; // out of the flow BEFORE measuring, so siblings never reflow
      const step = (placed % 8) * 26;
      // Clamp so the whole window stays on the stage: a cascade step may push a near-stage-width window
      // (a phone, or the wide two-pane on a small desktop) past the right edge, where its close button
      // would be unreachable. Fully-fitting beats fully-cascaded.
      const fitX = Math.max(0, stage.clientWidth - win.offsetWidth);
      const x = Math.min(Math.max(0, Math.round((stage.clientWidth - win.offsetWidth) / 2) + step), fitX);
      winGeom.set(key, { x, y: 16 + step, w: null, h: null });
      placed++;
    }
    root.querySelectorAll('.dd-window[data-win-key]').forEach((win) => {
      if (!(win instanceof HTMLElement)) {
        return;
      }
      const g = winGeom.get(win.dataset.winKey ?? '');
      if (g === undefined) {
        return;
      }
      // A stored size never exceeds the CURRENT stage (a resize saved on a wide screen must not leave the
      // window, and its grow box, stranded past the edge of a narrower one).
      if (g.w !== null) {
        win.style.width = `${Math.min(g.w, Math.max(240, stage.clientWidth))}px`;
        win.style.maxWidth = 'none';
      }
      if (g.h !== null) {
        win.style.height = `${Math.min(g.h, Math.max(180, stage.clientHeight))}px`;
      }
      if (g.x !== null && g.y !== null) {
        const maxX = Math.max(0, stage.clientWidth - 80);
        const maxY = Math.max(0, stage.clientHeight - 48);
        win.style.position = 'absolute';
        win.style.left = `${Math.min(Math.max(0, g.x), maxX)}px`;
        win.style.top = `${Math.min(Math.max(0, g.y), maxY)}px`;
        // Pull the window up until its BOTTOM fits too: max-height measures the whole stage, not the room
        // below an absolute top, so a low-dragged window would otherwise hang past the stage (on mobile,
        // that is the compose hiding under the on-screen keyboard after any re-render).
        const top = parseFloat(win.style.top) || 0;
        win.style.top = `${Math.max(0, Math.min(top, stage.clientHeight - win.offsetHeight))}px`;
      }
    });
  }

  // Wire drag + resize + click-to-focus on EVERY window on the desktop. Drag by the titlebar; the native
  // grow box (bottom-right corner) resizes; both remember their result per window (winGeom keyed by
  // data-win-key), so a window stays put across re-renders. Clicking a PARKED window brings it forward.
  function wireWindowDrag(): void {
    const stage = root.querySelector('.dd-stage');
    if (!(stage instanceof HTMLElement)) {
      return;
    }
    root.querySelectorAll('.dd-window[data-win-key]').forEach((winNode) => {
      if (!(winNode instanceof HTMLElement)) {
        return;
      }
      const win = winNode;
      const key = win.dataset.winKey ?? '';
      const parkedWin = win.classList.contains('dd-window-parked');
      const geo = (): { x: number | null; y: number | null; w: number | null; h: number | null } =>
        winGeom.get(key) ?? { x: null, y: null, w: null, h: null };
      // Clicking a parked (background) window brings it forward as the focused, live window. Uses click
      // (not pointerdown) so a drag of a background window rearranges it without stealing focus.
      if (parkedWin) {
        win.addEventListener('click', () => focusParkedWindow(key));
      }
      // A native grow-box resize has no event of its own: arm on a pointerdown in the corner zone and read
      // the final size once the pointer releases (next frame, after the UA applied it).
      win.addEventListener('pointerdown', (e) => {
        if (!(e instanceof PointerEvent)) {
          return;
        }
        const r = win.getBoundingClientRect();
        if (r.right - e.clientX > 24 || r.bottom - e.clientY > 24) {
          return; // not the grow box
        }
        // Remember the size at press time: a plain TAP on the corner (no actual resize) must not pin the
        // current size into winGeom — the window keeps its responsive CSS size until a real resize (AIM20).
        const startW = win.offsetWidth;
        const startH = win.offsetHeight;
        const pid = e.pointerId;
        const done = (ev: Event): void => {
          // Only the RESIZING pointer's release ends the gesture (a second finger tapping elsewhere must
          // not commit a mid-resize size and drop the final one).
          if (ev instanceof PointerEvent && ev.pointerId !== pid) {
            return;
          }
          document.removeEventListener('pointerup', done);
          document.removeEventListener('pointercancel', done);
          requestAnimationFrame(() => {
            // A re-render can replace the window before this frame runs: a detached element measures 0x0,
            // which must not overwrite the stored size. Store only when the size actually CHANGED.
            if (win.isConnected && win.offsetWidth > 0 && win.offsetHeight > 0 && (win.offsetWidth !== startW || win.offsetHeight !== startH)) {
              winGeom.set(key, { ...geo(), w: win.offsetWidth, h: win.offsetHeight });
            }
            // The resize changed the log's viewport with no scroll event: refresh every thumb.
            logScrollbarSyncs.forEach((s) => s());
          });
        };
        document.addEventListener('pointerup', done);
        document.addEventListener('pointercancel', done);
      });
      const bar = win.querySelector('.dd-titlebar');
      if (!(bar instanceof HTMLElement)) {
        return;
      }
      bar.addEventListener('pointerdown', (e) => {
        if (!(e instanceof PointerEvent) || (e.pointerType === 'mouse' && e.button !== 0)) {
          return;
        }
        if (e.target instanceof Element && e.target.closest('button, .dd-menu-dropdown, .dd-conn-pop') !== null) {
          return; // the window buttons, the app menu, its dropdown, and the connection popover are clicks, not drags
        }
        const wr = win.getBoundingClientRect();
        const sr = stage.getBoundingClientRect();
        const offX = e.clientX - wr.left;
        const offY = e.clientY - wr.top;
        // Moving a window changes ONLY its position. Windows are permanently absolute (AIM19), so there
        // is no flow layout to fall out of; pressing/dragging the titlebar must never touch the size
        // (the old pre-AIM19 width freeze could nudge it) — only the user's grow-box resize does (AIM20).
        win.style.position = 'absolute';
        win.style.left = `${wr.left - sr.left}px`;
        win.style.top = `${wr.top - sr.top}px`;
        let moved = false;
        const move = (ev: Event): void => {
          if (!(ev instanceof PointerEvent)) {
            return;
          }
          moved = true;
          const x = Math.min(Math.max(0, ev.clientX - sr.left - offX), Math.max(0, stage.clientWidth - 80));
          const y = Math.min(Math.max(0, ev.clientY - sr.top - offY), Math.max(0, stage.clientHeight - 48));
          win.style.left = `${x}px`;
          win.style.top = `${y}px`;
        };
        const up = (): void => {
          bar.removeEventListener('pointermove', move);
          bar.removeEventListener('pointerup', up);
          bar.removeEventListener('pointercancel', up);
          try {
            bar.releasePointerCapture(e.pointerId);
          } catch {
            /* no capture to release */
          }
          winGeom.set(key, { ...geo(), x: parseFloat(win.style.left) || 0, y: parseFloat(win.style.top) || 0 });
          // A parked window dragged (moved) stays parked; a titlebar TAP (no move) focuses it.
          if (parkedWin && !moved) {
            focusParkedWindow(key);
          }
        };
        try {
          bar.setPointerCapture(e.pointerId);
        } catch {
          /* pointer capture unavailable (test DOM): move/up still track while over the bar */
        }
        bar.addEventListener('pointermove', move);
        bar.addEventListener('pointerup', up);
        bar.addEventListener('pointercancel', up);
        e.preventDefault(); // no text selection while dragging
      });
    });
  }

  // Bring a parked (background) window forward as the focused, live one. Conversations reopen fresh (their
  // log may have moved on while parked); anything else re-renders its parked snapshot live and re-wired.
  function focusParkedWindow(key: string): void {
    const p = parkedWins.find((w) => w.key === key);
    if (p === undefined) {
      return;
    }
    if (p.view.kind === 'conversation' && p.view.transmit.conversationId !== null) {
      const draft = p.view.transmit.compose;
      // Re-fetching the channel is async; if the user navigates elsewhere (or focuses another window)
      // while it is in flight, that navigation bumps navGen and this stale result must not fire go() over
      // the newer view. Capture-and-check mirrors openBuddies.
      const gen = ++navGen;
      void controller
        .openChannel(p.view.transmit.conversationId)
        .then((transmit) => {
          if (gen === navGen) {
            go({ kind: 'conversation', transmit: { ...transmit, compose: draft } });
          }
        })
        .catch(() => {
          if (gen === navGen) {
            go(p.view);
          }
        });
    } else if (p.view.kind === 'channels' && p.view.active !== undefined && p.view.active.conversationId !== null) {
      // A parked two-pane whose active chat lost its log: reopen the channel fresh, keeping the draft.
      const pv = p.view;
      const draft = pv.active!.compose;
      const id = pv.active!.conversationId!;
      const gen = ++navGen;
      void controller
        .openChannel(id)
        .then((transmit) => {
          if (gen === navGen) {
            go({ kind: 'channels', channels: pv.channels, active: { ...transmit, compose: draft }, selectedId: id });
          }
        })
        .catch(() => {
          if (gen === navGen) {
            go(pv);
          }
        });
    } else if (p.view.kind === 'channels') {
      // A LIST-ONLY channels snapshot (pop-out filters the popped chat's row out): re-list fresh so no
      // conversation looks deleted when this window is brought forward.
      const pv = p.view;
      const gen = ++navGen;
      void controller
        .listChannels()
        .then((channels) => {
          if (gen === navGen) {
            go({ kind: 'channels', channels, ...(pv.notice !== undefined ? { notice: pv.notice } : {}) });
          }
        })
        .catch(() => {
          if (gen === navGen) {
            go(pv);
          }
        });
    } else if (p.view.kind === 'buddies') {
      // A parked buddy list is a FROZEN snapshot: its away bubble, status diamond, and own row were
      // captured when it parked, so a sibling identity sync that landed since then would be repainted
      // stale here. Reveal the snapshot synchronously for instant feedback, then hydrate in place (the
      // same two-step as Back from Device keys; openBuddies captures navGen after this go()).
      go(p.view);
      void openBuddies();
    } else {
      go(p.view);
    }
  }

  // Dismiss the focused window (close or minimize): it is NOT parked, and the topmost parked window takes
  // focus. Sets `view` directly so go()'s park heuristic never re-parks the window being dismissed; the
  // buddy list is home when nothing is parked behind (the bare desktop if the buddy list itself closed).
  function revealNextWindow(): void {
    stopScan();
    // This reveal is itself a navigation: bump navGen so any earlier in-flight reveal (e.g. a second
    // Close click during the exit animation) is superseded and cannot also render.
    const gen = ++navGen;
    // PEEK the topmost parked window; only remove it once we actually commit inside the guarded callback,
    // so a superseded async reveal leaves the desktop stack intact instead of silently dropping a window.
    const top = parkedWins[parkedWins.length - 1];
    if (top !== undefined) {
      const commit = (next: AppView): void => {
        if (gen !== navGen) {
          return;
        }
        parkedWins = parkedWins.filter((p) => p !== top);
        view = next;
        render();
      };
      if (top.view.kind === 'conversation' && top.view.transmit.conversationId !== null) {
        const draft = top.view.transmit.compose;
        void controller
          .openChannel(top.view.transmit.conversationId)
          .then((t) => commit({ kind: 'conversation', transmit: { ...t, compose: draft } }))
          .catch(() => commit(top.view));
        return;
      }
      if (top.view.kind === 'channels' && top.view.active !== undefined && top.view.active.conversationId !== null) {
        const tv = top.view;
        const draft = tv.active!.compose;
        const id = tv.active!.conversationId!;
        void controller
          .openChannel(id)
          .then((t) => commit({ kind: 'channels', channels: tv.channels, active: { ...t, compose: draft }, selectedId: id }))
          .catch(() => commit(tv));
        return;
      }
      if (top.view.kind === 'channels') {
        // A LIST-ONLY channels snapshot (e.g. parked by pop-out, which filters the popped chat's row out):
        // re-list fresh so no conversation looks deleted when this window comes back forward.
        const tv = top.view;
        void controller
          .listChannels()
          .then((channels) => commit({ kind: 'channels', channels, ...(tv.notice !== undefined ? { notice: tv.notice } : {}) }))
          .catch(() => commit(tv));
        return;
      }
      commit(top.view);
      // Revealing a parked BUDDY LIST paints its frozen snapshot; hydrate it for the same reason
      // focusParkedWindow does (a sibling's away or icon adopted while it sat parked). Guarded so a
      // superseded reveal cannot navigate over a newer view.
      if (top.view.kind === 'buddies' && gen === navGen) {
        void openBuddies();
      }
      return;
    }
    if (view.kind === 'buddies') {
      view = { kind: 'desktop' };
      render();
    } else {
      // Non-primary sentinel first, so openBuddies' go() does not re-park the window we are dismissing.
      view = { kind: 'desktop' };
      void openBuddies();
    }
  }

  /** DOCK: move a standalone IM window INTO the two-pane Channels window as its active chat (the IM window
   * disappears; its content flows into the right pane). Sets view + parkedWins directly (like reveal), so
   * the outgoing conversation window is NOT parked — it is converted, not stacked. */
  function dockActive(): void {
    if (view.kind !== 'conversation' || view.transmit.conversationId === null) {
      return;
    }
    const id = view.transmit.conversationId;
    const liveCompose = root.querySelector('#dd-compose-input');
    const draft = liveCompose instanceof HTMLElement ? serializeRichText(liveCompose) : '';
    const t: TransmitModel = { ...view.transmit, compose: draft };
    const gen = ++navGen;
    void controller.listChannels().then((channelsRaw) => {
      if (gen !== navGen) {
        return;
      }
      // Note to Self is absent from listChannels (hidden self-group): synthesize its row so the docked
      // chat has a highlightable entry in the left list.
      const channels = ensureActiveRow(channelsRaw, t);
      // Remove any parked channels copy (its content is now live) and the converted conversation.
      parkedWins = parkedWins.filter((p) => p.key !== 'kind:channels' && p.key !== `conv:${id}`);
      view = { kind: 'channels', channels, active: t, selectedId: id };
      saveResume({ username: currentUsername, conversationId: id });
      render();
    });
  }

  /** POP OUT: undock the two-pane's active chat into its OWN standalone IM window; the Channels window stays
   * (parked behind, now showing just the list). */
  function popOutActive(): void {
    if (view.kind !== 'channels' || view.active === undefined || view.active.conversationId === null) {
      return;
    }
    const liveCompose = root.querySelector('#dd-compose-input');
    const draft = liveCompose instanceof HTMLElement ? serializeRichText(liveCompose) : '';
    const t: TransmitModel = { ...view.active, compose: draft };
    const id = t.conversationId!;
    // The popped-out chat leaves the two-pane entirely: its row comes OFF the left list (it lives in its
    // own window now). Docking it again, or reopening Channels fresh, brings the row back.
    const listOnly: AppView = {
      kind: 'channels',
      channels: view.channels.filter((c) => c.id !== id),
      ...(view.notice !== undefined ? { notice: view.notice } : {}),
    };
    ++navGen;
    // Park the Channels window as LIST-ONLY behind the popped-out conversation (drop any stale copies first).
    parkedWins = [...parkedWins.filter((p) => p.key !== 'kind:channels' && p.key !== `conv:${id}`), { key: 'kind:channels', view: listOnly }];
    view = { kind: 'conversation', transmit: t };
    saveResume({ username: currentUsername, conversationId: id });
    render();
  }

  // The conversation whose log was on screen at the last render, so we can tell a re-render of the SAME
  // conversation (keep the reader's scroll position) from opening or switching one (start at the newest).
  let lastRenderedConvId: string | null = null;

  function render(): void {
    // Was the log already pinned to (near) its newest line before this rebuild? Capture it from the OLD
    // DOM, but only within the SAME conversation, so an incoming message re-pins to the bottom for someone
    // who was already there yet never YANKS someone who scrolled up to read back.
    // The active conversation (standalone OR the embedded Channels pane) uses the same scroll-stick + focus.
    const ac = activeConv(view);
    // In-place refresh of the SAME conversation (a send or an inbound message rebuilt the view) versus a
    // fresh navigation. On an in-place refresh we must NOT replay the full-height boot sweep or steal focus
    // back to the compose, both of which make the mobile view visibly jump and resize on every message.
    const inPlace = ac !== null && lastRenderedConvId === ac.id;
    // Refocus the compose when THIS render follows a send (one-shot flag) or freshly OPENS a conversation
    // (!inPlace, the long-standing click-to-type behavior). An in-place refresh from an INBOUND message is
    // neither, so receiving never steals focus mid-read.
    const refocusCompose = refocusComposeAfterRender || !inPlace;
    refocusComposeAfterRender = false;
    let stickLog = true;
    let keepScrollTop = 0; // where a scrolled-up reader WAS, restored after the rebuild (never yank to top)
    if (inPlace) {
      const oldLog = root.querySelector('.dd-log');
      if (oldLog instanceof HTMLElement) {
        stickLog = oldLog.scrollHeight - oldLog.scrollTop - oldLog.clientHeight < 48;
        keepScrollTop = oldLog.scrollTop;
      }
    }
    applyAppearance(); // theme class + validated token overrides on the root (before the DOM is styled)
    // Toasts must outlive any render that lands mid-lifetime (they carry errors like a failed revoke,
    // and a queued hydrate can repaint milliseconds after one appears). They are position:fixed and
    // their removal timers hold these same node references, so re-appending is transparent.
    const liveToasts = Array.from(root.querySelectorAll('.dd-toast'));
    root.innerHTML = renderShell(view, minimizedWins, parkedWins);
    for (const t of liveToasts) {
      root.appendChild(t);
    }
    if (inPlace) {
      root.querySelector('.dd-sweep')?.remove(); // do not replay the 1.25s boot sweep animation on every message
    }
    updateConnDisplay(); // repaint the fresh #dd-conn/#dd-conn-pop without re-running state transitions
    syncBurnTicker(); // tick any open ephemeral countdown live (targeted DOM update; runs only while visible)
    wire();
    syncMatrix(); // (re)attach the h4x0r digital-rain behind chat logs; a no-op under every other theme
    applyWindowGeometry(); // the user's drag/resize placement survives every re-render
    wireLogScrollbars(); // AFTER geometry, so the initial thumb sizing measures the real window size
    wireChatIcons(); // fill the side-by-side buddy icons beside each open chat (peer on top, you below)
    wireWindowDrag();
    // A conversation re-renders on every send and every received message. Keep the compose focused with
    // the caret at the end (so pressing Enter never costs you the ability to keep typing) and pin the log
    // to its newest line (the box stays put and the history scrolls under it, AIM-style) unless the reader
    // had scrolled up — a scrolled-up reader is put back exactly where they were, never yanked to the top.
    if (ac !== null) {
      const log = root.querySelector('.dd-log');
      if (log instanceof HTMLElement) {
        log.scrollTop = stickLog ? log.scrollHeight : keepScrollTop;
      }
      const compose = root.querySelector('#dd-compose-input');
      if (refocusCompose && compose instanceof HTMLElement) {
        // Refocus ONLY when this render follows a send (keep typing). Never grab focus on an inbound message
        // while the user is reading: a programmatic focus scrolls the mobile viewport and steals the caret,
        // which is the visible "jump".
        focusAtEnd(compose);
      }
    } else if (view.kind === 'away') {
      // Put the cursor straight in the away-message editor so you can type the moment it opens (it is the
      // one thing this screen is for), instead of having to click into it first.
      const ed = root.querySelector('#dd-away-msg');
      if (ed instanceof HTMLElement) {
        focusAtEnd(ed);
      }
    }
    lastRenderedConvId = ac !== null ? ac.id : null;
  }

  function wire(): void {
    const form = root.querySelector('#dd-unlock-form');
    form?.addEventListener('submit', (e) => {
      e.preventDefault();
      const userEl = root.querySelector('#dd-user');
      const passEl = root.querySelector('#dd-pass');
      const pass2El = root.querySelector('#dd-pass2');
      const user = userEl instanceof HTMLInputElement ? userEl.value : '';
      const pass = passEl instanceof HTMLInputElement ? passEl.value : '';
      const pass2 = pass2El instanceof HTMLInputElement ? pass2El.value : '';
      const mode = view.kind === 'unlock' ? (view.mode ?? 'login') : 'login';
      void (mode === 'register' ? doRegister(user, pass, pass2) : doLogin(user, pass));
    });
    root.querySelector('[data-action="to-register"]')?.addEventListener('click', () => {
      go({ kind: 'unlock', mode: 'register' });
    });
    root.querySelector('[data-action="to-login"]')?.addEventListener('click', () => {
      go({ kind: 'unlock', mode: 'login' });
    });
    root.querySelectorAll('[data-channel]').forEach((el) => {
      el.addEventListener('click', () => {
        if (!(el instanceof HTMLElement)) {
          return;
        }
        const id = el.dataset.channel;
        if (id === undefined) {
          return;
        }
        if (el.dataset.status === 'pending') {
          void controller.channelKeyExchange(id).then((state) => go({ kind: 'keyexchange', state }));
        } else if (view.kind === 'channels') {
          // Two-pane: the selected channel's chat flows into the RIGHT pane of this SAME window (no new
          // window). windowKey stays kind:channels, so go() treats it as an in-place refresh.
          const channels = view.channels;
          const gen = navGen;
          void controller.openChannel(id).then((transmit) => {
            if (gen === navGen) {
              const stashed = chanDrafts.get(id);
              chanDrafts.delete(id);
              const active = stashed !== undefined && transmit.compose === '' ? { ...transmit, compose: stashed } : transmit;
              go({ kind: 'channels', channels, active, selectedId: id });
            }
          });
        } else {
          void controller.openChannel(id).then((transmit) => go({ kind: 'conversation', transmit }));
        }
      });
    });
    // Mobile single-pane: "‹ Channels" closes the open chat pane and returns to the list (kept in the
    // same window; the row selection is cleared so the list reads as a fresh landing).
    root.querySelector('[data-action="channels-show-list"]')?.addEventListener('click', () => {
      if (view.kind === 'channels') {
        const id = view.active?.conversationId;
        if (id !== undefined && id !== null) {
          const liveCompose = root.querySelector('#dd-compose-input');
          const draft = liveCompose instanceof HTMLElement ? serializeRichText(liveCompose) : '';
          if (draft !== '') {
            chanDrafts.set(id, draft);
          } else {
            chanDrafts.delete(id); // the user cleared it; a stale stash must not resurrect old text
          }
        }
        go({ kind: 'channels', channels: view.channels });
      }
    });
    root.querySelector('[data-action="new-channel"]')?.addEventListener('click', () => {
      void controller.startKeyExchange().then((state) =>
        go({
          kind: 'keyexchange',
          // With the directory we open channels by username; without it, by pasted contact.
          state: account !== undefined ? { ...state, byUsername: true, selfUsername: currentUsername } : state,
        }),
      );
    });
    // Continue (start mode) addresses an offer to the contact, resolved by username via the
    // directory or read from a pasted contact; Accept (incoming) completes the mutual exchange.
    root.querySelector('[data-action="accept-key"]')?.addEventListener('click', () => {
      if (view.kind !== 'keyexchange') {
        return;
      }
      const st = view.state;
      if (st.mode === 'start') {
        void startConversation(st);
      } else {
        void controller.acceptKeyExchange(st.conversationId).then((transmit) => go({ kind: 'conversation', transmit }));
      }
    });
    root.querySelector('[data-action="cancel-key"]')?.addEventListener('click', () => {
      void controller.listChannels().then((channels) => go({ kind: 'channels', channels }));
    });
    // Enter sends the message; Shift+Enter inserts a newline (the compose is a rich contenteditable now).
    root.querySelector('#dd-compose-input')?.addEventListener('keydown', (e) => {
      if (e instanceof KeyboardEvent && e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        root.querySelector('#dd-compose-form')?.dispatchEvent(new Event('submit', { cancelable: true, bubbles: true }));
      }
    });
    root.querySelector('[data-action="send-file"]')?.addEventListener('click', () => {
      const inp = root.querySelector('#dd-file-input');
      if (inp instanceof HTMLInputElement) {
        inp.click();
      }
    });
    root.querySelector('#dd-file-input')?.addEventListener('change', (e) => {
      const inp = e.target;
      if (inp instanceof HTMLInputElement && inp.files !== null && inp.files[0] !== undefined) {
        void sendFileFromPicker(inp.files[0]);
      }
    });
    // Insert an inline image into the compose (compose-only; the ⛰ button renders only in that toolbar).
    // Paste of an image is handled the same way; a text/rich paste falls through to the default behavior.
    const addComposeImage = async (file: Blob, at?: Range | null): Promise<void> => {
      const uri = await prepareInlineImage(file, 'fit');
      if (uri === null) {
        showToast('could not add that image');
        return;
      }
      // Look the editor up AFTER the await: the encode can take up to a second, and a re-render in that
      // window (an incoming message, an expiry) replaces the DOM — inserting into the detached old editor
      // would silently drop the image. The contains() guard then demotes a stale captured range to the
      // append-at-end fallback.
      const editor = root.querySelector('#dd-compose-input');
      if (!(editor instanceof HTMLElement)) {
        return;
      }
      insertInlineImage(editor, uri, at);
    };
    root.querySelector('[data-rt-img]')?.addEventListener('click', () => {
      // Capture the caret NOW: the native file dialog clears the selection, and re-focusing afterwards
      // would put a fresh caret at position 0 — inserting the image in FRONT of the typed text.
      const editor = root.querySelector('#dd-compose-input');
      const sel = window.getSelection();
      const at =
        editor instanceof HTMLElement && sel !== null && sel.rangeCount > 0 && editor.contains(sel.getRangeAt(0).commonAncestorContainer)
          ? sel.getRangeAt(0).cloneRange()
          : null;
      const inp = document.createElement('input');
      inp.type = 'file';
      inp.accept = 'image/*';
      inp.addEventListener('change', () => {
        const f = inp.files?.[0];
        if (f !== undefined) {
          void addComposeImage(f, at);
        }
      });
      inp.click();
    });
    root.querySelector('#dd-compose-input')?.addEventListener('paste', (e) => {
      if (!(e instanceof ClipboardEvent) || e.clipboardData === null) {
        return;
      }
      const item = Array.from(e.clipboardData.items).find((it) => it.kind === 'file' && it.type.startsWith('image/'));
      if (item === undefined) {
        return; // not an image paste: let the default text/rich paste happen
      }
      const f = item.getAsFile();
      if (f === null) {
        return;
      }
      e.preventDefault();
      void addComposeImage(f);
    });
    root.querySelector('[data-action="call-audio"]')?.addEventListener('click', () => {
      startOutgoingCall(false);
    });
    root.querySelector('[data-action="call-video"]')?.addEventListener('click', () => {
      startOutgoingCall(true);
    });
    wireRevokeButtons();
    const composeForm = root.querySelector('#dd-compose-form');
    composeForm?.addEventListener('submit', (e) => {
      e.preventDefault();
      if (activeConv(view) === null) {
        return;
      }
      const typed = readRichEditor(root, 'dd-compose-input').trim();
      if (typed.length === 0) {
        return;
      }
      // Apply "My Message Look" (AIM24): wrap the composed markers in the user's default font/color/size/
      // highlight so the recipient renders the message in that style. Any formatting applied while typing
      // nests inside and wins per run. The look is device-local (appearance.messageLook); an empty look
      // leaves the text unchanged.
      const text = wrapMessageLook(appearance.messageLook, typed);
      // A message with a large inline image (or several) can exceed the transport's largest usable padding
      // bucket, which the gateway would reject. Refuse it here WITHOUT clearing the box, so the user can
      // remove an image and try again rather than lose what they typed. Check the STYLED text (with markers).
      if (utf8Bytes(text) > MESSAGE_BYTES_MAX) {
        showToast('message too large to send · remove an image and try again');
        return;
      }
      // Clear the live compose NOW (before the async send resolves and re-renders): a sent message must
      // leave an empty box, and this is what tells the same-conversation draft-carry in go() there is
      // nothing to preserve here (unlike an incoming message, where the draft stays and is carried).
      const composeEl = root.querySelector('#dd-compose-input');
      if (composeEl instanceof HTMLElement) {
        composeEl.innerHTML = '';
      }
      sendConversationText(text);
    });
    // The menu is inert before sign-in (unlock) and during the add-this-device onboarding (the wizard
    // and the provisioning/recovery screens it drives), so an unauthorized device cannot wander out of
    // the guided flow into an empty app. Once authorized, the menu works normally.
    const navLocked = (): boolean =>
      view.kind === 'unlock' || view.kind === 'newdevice-wizard' || joiningNewDevice;
    root.querySelectorAll('.dd-menu-item').forEach((el) => {
      if (el.textContent === 'Channels') {
        el.addEventListener('click', () => {
          if (!navLocked()) {
            void controller.listChannels().then((channels) => {
              go({ kind: 'channels', channels });
            });
          }
        });
      }
      if (el.textContent === 'Buddies') {
        el.addEventListener('click', () => {
          if (!navLocked()) {
            void openBuddies();
          }
        });
      }
    });
    // The DEAD DROP app menu appears in TWO places (the menu bar brand and the buddy-list titlebar); both
    // toggle their own adjacent dropdown, and both offer the same Device keys / Self Destruct.
    const closeAppMenus = (): void => {
      root.querySelectorAll('.dd-appmenu-pop, #dd-conn-pop').forEach((p) => {
        if (p instanceof HTMLElement) {
          p.hidden = true;
        }
      });
    };
    // The connection status popover: click the headline to toggle; Reconnect now skips the countdown.
    root.querySelector('#dd-conn')?.addEventListener('click', () => {
      const pop = root.querySelector('#dd-conn-pop');
      if (pop instanceof HTMLElement) {
        const show = pop.hidden;
        pop.hidden = !show;
        if (show) {
          updateConnDisplay(); // fill the rows the moment it opens
        }
      }
    });
    root.querySelector('[data-action="conn-reconnect"]')?.addEventListener('click', () => {
      void reconnectNow();
    });
    root.querySelectorAll('[data-action="app-menu"]').forEach((trigger) => {
      const pop = trigger.parentElement?.querySelector('.dd-appmenu-pop');
      trigger.addEventListener('click', (e) => {
        if (navLocked() || !(pop instanceof HTMLElement)) {
          return;
        }
        e.stopPropagation(); // so the document handler below does not immediately re-close it
        const willShow = pop.hidden;
        closeAppMenus();
        pop.hidden = !willShow;
      });
    });
    root.querySelectorAll('[data-action="device-keys"]').forEach((el) => {
      el.addEventListener('click', () => {
        closeAppMenus();
        // Device management needs the account server; without it (local-only) there is nothing to show.
        if (!navLocked() && account !== undefined) {
          void openSettings();
        }
      });
    });
    root.querySelectorAll('[data-action="self-destruct"]').forEach((el) => {
      el.addEventListener('click', () => {
        closeAppMenus();
        // Self Destruct deletes the account from the server, so it needs the account server.
        if (!navLocked() && account !== undefined) {
          go({ kind: 'selfdestruct' });
        }
      });
    });
    // ── Appearance (AIM19): draft edits + preview; Save applies ──
    root.querySelectorAll('[data-action="appearance"]').forEach((el) => {
      el.addEventListener('click', () => {
        closeAppMenus();
        // Already open: keep the window (and its unsaved draft) instead of silently resetting it.
        if (!navLocked() && view.kind !== 'appearance') {
          openAppearance();
        }
      });
    });
    if (view.kind === 'appearance') {
      const draft = view.draft;
      const category = view.category;
      root.querySelectorAll('[data-appear-cat]').forEach((el) => {
        el.addEventListener('click', () => openAppearance((el as HTMLElement).getAttribute('data-appear-cat') ?? 'buddylist', draft));
      });
      // The Font/Size/Color dropdowns: the trigger toggles its popup (one open at a time, same feel as the
      // rich-text toolbar); picking an option updates the DRAFT and re-renders (which closes the popup).
      root.querySelectorAll('[data-appear-pop]').forEach((el) => {
        el.addEventListener('click', () => {
          const id = (el as HTMLElement).getAttribute('data-appear-pop');
          const pop = root.querySelector(`[data-appear-popid="${id ?? ''}"]`);
          const show = pop instanceof HTMLElement && pop.hidden;
          root.querySelectorAll('.dd-appear-pop').forEach((p) => {
            if (p instanceof HTMLElement) {
              p.hidden = true;
            }
          });
          if (pop instanceof HTMLElement) {
            pop.hidden = !show;
          }
        });
      });
      root.querySelectorAll('[data-appear-set]').forEach((el) => {
        el.addEventListener('click', () => {
          const token = (el as HTMLElement).getAttribute('data-appear-set') ?? '';
          const val = (el as HTMLElement).getAttribute('data-appear-val') ?? '';
          draftAppearanceToken(draft, token, val, category);
        });
      });
      // "My Message Look" picks (AIM24): set/clear one field of the MessageLook draft and re-render.
      root.querySelectorAll('[data-look-set]').forEach((el) => {
        el.addEventListener('click', () => {
          const field = (el as HTMLElement).getAttribute('data-look-set') ?? '';
          const val = (el as HTMLElement).getAttribute('data-look-val') ?? '';
          draftMessageLook(draft, field, val, category);
        });
      });
      root.querySelectorAll('[data-appear-theme]').forEach((el) => {
        el.addEventListener('click', () => {
          const id = ((el as HTMLElement).getAttribute('data-appear-theme') as ThemeId | null) ?? 'default';
          // Preserve the message-look draft when switching theme (it is independent of the theme/tokens).
          openAppearance('themes', {
            theme: THEME_CLASS[id] !== undefined ? id : 'default',
            tokens: draft.tokens,
            ...(draft.messageLook !== undefined ? { messageLook: draft.messageLook } : {}),
          });
        });
      });
      root.querySelector('[data-action="appear-reset"]')?.addEventListener('click', () => openAppearance(category, DEFAULT_APPEARANCE));
      root.querySelector('[data-action="appear-save"]')?.addEventListener('click', () => {
        if (!navLocked()) {
          saveAppearance(draft);
        }
      });
      root.querySelector('[data-action="appear-cancel"]')?.addEventListener('click', () => {
        if (!navLocked()) {
          void openBuddies(); // discard the draft
        }
      });
      root.querySelector('[data-action="appear-import"]')?.addEventListener('click', () => {
        const ta = root.querySelector('#dd-appear-json');
        importAppearancePack(ta instanceof HTMLTextAreaElement ? ta.value : '', draft, category);
      });
      root.querySelector('[data-action="appear-export"]')?.addEventListener('click', () => {
        const ta = root.querySelector('#dd-appear-json');
        if (ta instanceof HTMLTextAreaElement) {
          ta.value = JSON.stringify(draft, null, 2);
        }
      });
      root.querySelector('#dd-appear-file')?.addEventListener('change', (e) => {
        const input = e.target;
        const file = input instanceof HTMLInputElement ? input.files?.[0] : undefined;
        if (file === undefined) {
          return;
        }
        const reader = new FileReader();
        // The read is async: if the user navigated away from the dialog before it resolves, drop the
        // result rather than yanking them back into Appearance (and parking whatever they just opened).
        reader.onload = (): void => {
          if (view.kind === 'appearance') {
            importAppearancePack(typeof reader.result === 'string' ? reader.result : '', draft, category);
          }
        };
        reader.onerror = (): void => {
          if (view.kind === 'appearance') {
            openAppearance(category, draft, 'could not read that file');
          }
        };
        reader.readAsText(file);
      });
      // The live PREVIEW: the isolate wall gets every allowlisted token set to 'initial' (a guaranteed-
      // invalid custom-property value), so NOTHING of the saved look on the root can inherit into the
      // preview — cleared tokens and the Default theme genuinely preview as stock (var() fallbacks). The
      // draft theme's class sits on the themebox (rendered in the markup); the draft's own tokens go on
      // the preview box itself, beating the theme's. All via the CSSOM; the app keeps the SAVED look.
      root.querySelectorAll('.dd-appear-isolate').forEach((iso) => {
        if (iso instanceof HTMLElement) {
          for (const token of APPEARANCE_TOKENS) {
            iso.style.setProperty(token, 'initial');
          }
        }
      });
      root.querySelectorAll('.dd-appear-preview').forEach((prev) => {
        if (!(prev instanceof HTMLElement)) {
          return;
        }
        for (const [token, value] of Object.entries(draft.tokens)) {
          if (isValidTokenValue(token, value)) {
            prev.style.setProperty(token, value);
          }
        }
      });
    }
    // Dock a standalone IM into the two-pane Channels window; pop the two-pane's active chat back out.
    root.querySelector('[data-action="dock-to-channels"]')?.addEventListener('click', () => {
      closeAppMenus();
      if (!navLocked()) {
        dockActive();
      }
    });
    root.querySelector('[data-action="pop-out-chat"]')?.addEventListener('click', () => {
      closeAppMenus();
      if (!navLocked()) {
        popOutActive();
      }
    });
    wireIdentity();
    wireAway();
    wireTextToolbars();
    wireBuddies();
    wireBuddySetup();
    // Device-management actions on the Settings screen.
    root.querySelector('[data-action="devices-retry"]')?.addEventListener('click', () => {
      void openSettings();
    });
    root.querySelector('[data-action="settings-back"]')?.addEventListener('click', () => {
      suppressSettingsRefresh = true; // an explicit Back must not be clobbered by a background settings refresh
      // Close SYNCHRONOUSLY: reveal the buddy-list snapshot already parked behind this window, so the
      // very first click visibly closes Device Keys even while the revoke cascade has the worker chain
      // busy. openBuddies alone gave zero immediate feedback (its reads queue behind the cascade for
      // seconds), which read as "Back needs several clicks" — each extra click just piled on more queued
      // reads. The async refresh then hydrates the snapshot in place (same window key, and it captures
      // navGen AFTER this go(), so it is not self-superseded).
      const parked = parkedWins.find((p) => p.key === 'kind:buddies');
      if (parked !== undefined) {
        go(parked.view);
      }
      void openBuddies(); // back to the buddy list (home); hydrates the revealed snapshot when one existed
    });
    root.querySelectorAll('[data-action="revoke-device"]').forEach((el) => {
      el.addEventListener('click', () => {
        if (view.kind !== 'settings' || !(el instanceof HTMLElement) || el.dataset.device === undefined) {
          return;
        }
        const target = view.devices.find((d) => d.deviceId === el.dataset.device);
        if (target !== undefined && target.deviceKey === view.currentDeviceKey) {
          // Revoking the device you are on: a deliberate, full-screen confirmation that warns it is THIS
          // device and that it signs you out, separate from the inline confirm for another device.
          go({ kind: 'revokeself', deviceId: el.dataset.device });
          return;
        }
        // Another device: show the inline confirm strip for this row (no native confirm() that would leak).
        go({ ...view, pending: el.dataset.device });
      });
    });
    root.querySelector('[data-action="revoke-cancel"]')?.addEventListener('click', () => {
      if (view.kind === 'settings') {
        const { pending: _cleared, ...rest } = view;
        go(rest);
      }
    });
    // Confirm revoking ANOTHER device (the inline strip). Revoking THIS device goes through the dedicated
    // revokeself confirmation below.
    root.querySelectorAll('[data-action="revoke-confirm"]').forEach((el) => {
      el.addEventListener('click', () => void (async () => {
        if (view.kind !== 'settings' || account === undefined || !(el instanceof HTMLElement) || el.dataset.device === undefined) {
          return;
        }
        const deviceId = el.dataset.device;
        // ADR-022 P7: mint the SIGNED REVOCATION RECORD before asking the server to burn the row, and
        // send it with the call. The server-side burn stops the device logging in; it does nothing about
        // a device that already holds the account seed, which simply re-certifies itself at a higher
        // epoch and is re-admitted to every group. Only a record naming its signature key excludes it,
        // and only a seed-holder can sign one, so this is minted here and now while we hold the key.
        // Best-effort: a device without the account key still revokes server-side, exactly as before.
        const targetKey = view.devices.find((d) => d.deviceId === deviceId)?.deviceKey;
        const seq = (await controller.revocationState?.())?.revoked ?? 0;
        const record =
          targetKey === undefined ? null : await controller.revokeDeviceKey?.(targetKey, seq + 1).catch(() => null);
        void account.revokeDevice(deviceId, record ?? undefined).then(async (result) => {
          if (!result.ok) {
            // Surface the failure only where the user still IS: a foreground openSettings would clear
            // the Back latch and repaint Device Keys over the buddy list they already returned to.
            if (!suppressSettingsRefresh) {
              void openSettings(result.error ?? 'could not revoke that device');
            } else {
              showToast(result.error ?? 'could not revoke that device');
            }
            return;
          }
          // The MLS half of revoke: durably re-key the revoked device out of every conversation via the
          // fork-free staged remove. reconcileRemovals re-reads the device list (now showing this device
          // revoked) and drains one removal per conversation; a group missed here self-heals on the next
          // reconnect/receive rather than forking on a dead socket. Fire-and-forget: these self-heal via
          // the roster-changed/connection events, and blocking the click on them lets the settings refresh
          // arrive seconds late (behind syncAndPublish's network round trip), which is when a Back tapped
          // in the meantime gets clobbered.
          void reconcileRemovals();
          // The revoke bumped the account epoch: re-certify this device at the new epoch and re-publish
          // its key packages so the gate's floor rises (ADR-022 P6).
          void syncAndPublish();
          // Background refresh: if the user is still on Settings it repaints the (now revoked) list; if they
          // already tapped Back it honors suppressSettingsRefresh and does NOT repaint Settings over the
          // buddy list (which would look like a dead Back and, on reload, drop to the login screen).
          await openSettings(undefined, true);
        });
      })());
    });
    // Revoke THIS device: the deliberate confirmation. On confirm, burn this device's key, rotate it out
    // of the groups, then crypto-erase it and return to the unlock screen.
    root.querySelector('[data-action="revokeself-confirm"]')?.addEventListener('click', () => {
      if (view.kind !== 'revokeself' || account === undefined) {
        return;
      }
      const deviceId = view.deviceId;
      const selfKey = currentDeviceKey;
      void account.revokeDevice(deviceId).then(async (result) => {
        if (!result.ok) {
          go({ kind: 'revokeself', deviceId, error: result.error ?? 'could not revoke this device' });
          return;
        }
        // Best-effort forward-secure self-exit. Wrapped so a rejected exclusion RPC can never skip the
        // wipe below: this device crypto-erases regardless (it cannot decrypt anything after), and the
        // OTHER devices durably remove this now-revoked key via their own reconcileRemovals.
        if (selfKey !== '') {
          try {
            // Bound the wait: a HUNG (never-settling) exclusion RPC must not block the crypto-erase below.
            // The server key burn already succeeded; a timeout degrades to the documented fallback (the
            // OTHER devices durably remove this now-revoked key via their own reconcileRemovals).
            const exclusion = controller.excludeDevice?.(selfKey);
            if (exclusion !== undefined) {
              exclusion.catch(() => {}); // a rejection AFTER the race must not surface as unhandled
              await Promise.race([exclusion, new Promise<void>((r) => setTimeout(r, EXCLUDE_DEVICE_TIMEOUT_MS))]);
            }
          } catch {
            /* the local wipe next makes this device unable to read anything regardless */
          }
        }
        await wipeLocalAndReload('login'); // crypto-erase this device; the account lives on your others
      });
    });
    root.querySelector('[data-action="revokeself-cancel"]')?.addEventListener('click', () => {
      void openSettings();
    });
    // Self Destruct confirmation: the passphrase, typed twice, then irreversible deletion.
    root.querySelector('#dd-destruct-form')?.addEventListener('submit', (e) => {
      e.preventDefault();
      const p1 = root.querySelector('#dd-destruct-pass');
      const p2 = root.querySelector('#dd-destruct-pass2');
      void doSelfDestruct(
        p1 instanceof HTMLInputElement ? p1.value : '',
        p2 instanceof HTMLInputElement ? p2.value : '',
      );
    });
    root.querySelector('[data-action="destruct-cancel"]')?.addEventListener('click', () => {
      void controller.listChannels().then((channels) => go({ kind: 'channels', channels }));
    });
    // Device provisioning (model b) and the one-time recovery secret.
    root.querySelector('[data-action="add-device"]')?.addEventListener('click', () => {
      void startProvisioning('seedholder');
    });
    root.querySelector('[data-action="connect-this-device"]')?.addEventListener('click', () => {
      void startProvisioning('newdevice');
    });
    root.querySelector('[data-action="scan-device"]')?.addEventListener('click', () => {
      void startQrScan();
    });
    root.querySelector('[data-action="show-device-qr"]')?.addEventListener('click', () => {
      void startQrShowThisDevice();
    });
    root.querySelector('[data-action="prov-confirm"]')?.addEventListener('click', () => {
      void controller.confirmProvisioning?.();
    });
    root.querySelector('[data-action="prov-cancel"]')?.addEventListener('click', () => {
      stopScan(); // release the camera at once (openSettings is async)
      void controller.closeProvisioning?.();
      if (joiningNewDevice) {
        backToWizard();
      } else {
        void openSettings();
      }
    });
    // Buddy contact-QR screens (Scan a buddy / Scan me): return to Buddy List Setup, releasing the camera.
    root.querySelector('[data-action="buddy-scan-cancel"]')?.addEventListener('click', () => {
      stopScan();
      void openBuddySetup();
    });
    root.querySelector('[data-action="buddy-qr-back"]')?.addEventListener('click', () => {
      void openBuddySetup();
    });
    root.querySelector('[data-action="prov-done"]')?.addEventListener('click', () => {
      // In the new-device wizard, a provisioning error returns to the chooser (the device is still
      // unauthorized); only a successful provision (the 'done' step) proceeds to channels.
      if (joiningNewDevice && view.kind === 'provisioning' && view.state.step === 'error') {
        // If adoption already succeeded and only the enroll/publish failed, retry the enrollment rather
        // than re-entering the chooser (which would demand a second grant).
        void (async () => {
          const st = (await controller.deviceAuthState?.()) ?? { authorized: false };
          if (st.authorized) {
            void finishWizardEnrollment();
          } else {
            backToWizard();
          }
        })();
        return;
      }
      joiningNewDevice = false;
      suppressAutoOpenUntil = Date.now() + POST_JOIN_QUIET_MS; // the paced heal can deliver Welcomes minutes later
      // Finish the login the wizard interrupted: a contact link scanned before it still wins.
      void openPendingContact().then(async (opened) => {
        if (!opened) {
          await openBuddies();
        }
      });
    });
    root.querySelector('[data-action="recovery-continue"]')?.addEventListener('click', () => {
      // The recovery view is only shown right after registration: a contact link scanned before
      // registering still wins over the plain channels landing.
      void openPendingContact().then(async (opened) => {
        if (!opened) {
          await openBuddies(); // home is the buddy list
        }
      });
    });
    root.querySelector('[data-action="use-recovery"]')?.addEventListener('click', () => {
      go({ kind: 'recover-entry' });
    });
    root.querySelector('[data-action="recover-cancel"]')?.addEventListener('click', () => {
      if (joiningNewDevice) {
        backToWizard();
      } else {
        void openSettings();
      }
    });
    root.querySelector('[data-action="recover-submit"]')?.addEventListener('click', () => {
      void submitRecovery();
    });
    // Add-this-device wizard (after a valid-credentials login on an unauthorized device). The two paths
    // reuse the existing provisioning and recovery flows; the wizard only adds the login-time entry.
    root.querySelector('[data-action="wizard-provision"]')?.addEventListener('click', () => {
      void startProvisioning('newdevice');
    });
    root.querySelector('[data-action="wizard-recover"]')?.addEventListener('click', () => {
      go({ kind: 'recover-entry' });
    });
    root.querySelector('[data-action="wizard-deadend"]')?.addEventListener('click', () => {
      go({ kind: 'newdevice-wizard', state: { step: 'deadend', connected: true } });
    });
    root.querySelector('[data-action="wizard-back"]')?.addEventListener('click', () => {
      backToWizard();
    });
    root.querySelector('[data-action="wizard-retry"]')?.addEventListener('click', () => {
      void retryWizardConnect();
    });
    root.querySelector('[data-action="wizard-signout"]')?.addEventListener('click', () => {
      void signOutNewDevice();
    });
    root.querySelector('[data-action="get-info"]')?.addEventListener('click', () => {
      void openGetInfo();
    });
    // Add Buddy (IM toolbar): put the person you are talking to on your buddy list. Shown only when the
    // conversation carries a known handle that is not already a buddy; re-opening the channel refreshes
    // the toolbar so the button disappears once they are added.
    root.querySelector('[data-action="add-buddy"]')?.addEventListener('click', () => {
      const ac = activeConv(view);
      if (ac === null) {
        return;
      }
      const handle = ac.transmit.peerHandle;
      const id = ac.id;
      if (typeof handle !== 'string' || handle.length === 0) {
        return;
      }
      void (controller.addBuddy?.(handle) ?? Promise.resolve([]))
        .then(() => controller.openChannel(id))
        .then((base) => {
          const note = { kind: 'system' as const, text: `» added ${handle} to your buddy list` };
          goToActive({ ...base, log: [...base.log, note] });
        });
    });
    root.querySelector('[data-action="getinfo-back"]')?.addEventListener('click', () => {
      if (view.kind !== 'getinfo') {
        return;
      }
      // Opened from the Buddy List (by username): return to the list. From the two-pane Channels chat:
      // return to that pane. Otherwise it was opened from a standalone conversation: reopen it.
      if (view.origin === 'buddies') {
        void openBuddies();
      } else if (view.fromChannels === true) {
        const id = view.conversationId;
        void Promise.all([controller.listChannels(), controller.openChannel(id)]).then(([channels, transmit]) =>
          go({ kind: 'channels', channels: ensureActiveRow(channels, transmit), active: transmit, selectedId: id }),
        );
      } else {
        void controller.openChannel(view.conversationId).then((transmit) => go({ kind: 'conversation', transmit }));
      }
    });
    root.querySelector('[data-action="history-off"]')?.addEventListener('click', () => {
      if (view.kind !== 'settings') {
        return;
      }
      const v = view;
      if (v.historyArm !== true) {
        // Say what the second tap costs BEFORE it happens: this erases what is already stored here.
        go({ ...v, historyArm: true });
        showToast('this erases the messages already saved on this device, and cannot be undone');
        return;
      }
      void (async () => {
        await controller.setHistoryOff?.(true, true);
        showToast('messages are no longer saved on this device');
        await openSettings();
      })();
    });
    root.querySelector('[data-action="history-on"]')?.addEventListener('click', () => {
      if (view.kind !== 'settings') {
        return;
      }
      void (async () => {
        await controller.setHistoryOff?.(false);
        showToast('messages are saved on this device again');
        await openSettings();
      })();
    });
    root.querySelector('[data-action="verify-mark"]')?.addEventListener('click', () => {
      if (view.kind !== 'getinfo' || view.verify === undefined || view.verify.peerKey.length === 0) {
        return;
      }
      const v = view;
      const vi = v.verify;
      if (vi === undefined) {
        return;
      }
      // Trusting a CHANGED key is the dangerous branch (it is exactly what an attacker wants after a
      // swap), so it takes two deliberate taps; a first-time verification is one tap.
      if (vi.state === 'changed' && v.verifyArm !== true) {
        go({ ...v, verifyArm: true });
        showToast('are you sure? only trust the new key after confirming with them directly');
        return;
      }
      void (async () => {
        const ok = (await controller.markBuddyVerified?.(v.peer, vi.peerKey, vi.verifiedKey)) ?? false;
        if (!ok) {
          showToast('could not verify: the key moved, look again');
        }
        await openBuddyInfo(v.peer); // re-fetch so the panel shows the stored state, not a guess
      })();
    });
    root.querySelector('[data-action="verify-clear"]')?.addEventListener('click', () => {
      if (view.kind !== 'getinfo') {
        return;
      }
      const peer = view.peer;
      void (async () => {
        await controller.clearBuddyVerified?.(peer);
        await openBuddyInfo(peer);
      })();
    });
    root.querySelector('[data-action="block-peer"]')?.addEventListener('click', () => {
      const ac = activeConv(view);
      if (ac === null) {
        return;
      }
      // Block now CLOSES the conversation for good too (the old cosmetic block quietly resurrected on
      // every reconnect), so it gets the same two-tap arm as Remove.
      if (!armedDestructive('block', ac.id, 'tap Block again to block everyone here and close this channel for good')) {
        return;
      }
      // Return to the buddy list after blocking, where the person now shows under the auto-populated
      // "Blocked" drop, so it is clear where a blocked contact goes (and Setup can unblock them).
      void (controller.blockConversation?.(ac.id) ?? Promise.resolve())
        .then(() => {
          purgeWindowsFor(ac.id);
          void openBuddies();
        })
        .catch(() => {
          showToast('could not block this channel, try again');
        });
    });
    // REMOVE this channel from the device for good, without blocking anyone: the way to retire a dead
    // or abandoned conversation. Two taps (the inline-confirm idiom, no native confirm dialog): the
    // first arms and explains, the second within the same conversation executes.
    root.querySelector('[data-action="remove-channel"]')?.addEventListener('click', () => {
      const ac = activeConv(view);
      if (ac === null) {
        return;
      }
      if (!armedDestructive('remove', ac.id, 'tap Remove again to close this channel for good. stored messages stay until their lifetimes end')) {
        return;
      }
      void (controller.removeConversation?.(ac.id) ?? Promise.resolve())
        .then(() => {
          purgeWindowsFor(ac.id);
          if (view.kind === 'channels') {
            void controller.listChannels().then((channels) => go({ kind: 'channels', channels }));
          } else {
            void openBuddies();
          }
        })
        .catch(() => {
          showToast('could not remove this channel, try again');
        });
    });
    // Every window's minimize / close controls. Minimize stashes the current screen as a menu-bar chip
    // (drafts intact) and falls back to the buddy list (or the bare desktop when the buddy list itself
    // was minimized); close just dismisses. Nothing is destroyed: a conversation stays in Channels.
    root.querySelector('[data-action="win-minimize"]')?.addEventListener('click', () => {
      // Native shell: minimize drives the OS window, not the menu-bar-chip stash (there is no menu bar in
      // the single-window native layout).
      if (isNativeShell()) {
        shellBridge()?.minimize?.();
        return;
      }
      const v = view;
      const key = v.kind === 'conversation' && v.transmit.conversationId !== null ? `conv:${v.transmit.conversationId}` : `kind:${v.kind}`;
      const title = v.kind === 'conversation' ? (v.transmit.peer ?? 'TRANSMIT') : windowTitle(v);
      // Harvest what only lives in the DOM (the half-typed compose / profile / away drafts) into the
      // stash NOW, before the exit animation, so "drafts intact" is true. A conversation stash also
      // DROPS its decrypted log: restore reopens the conversation fresh anyway, and a stash holding
      // plaintext would let text outlive a lifetime crypto-erase while it waits on the menu bar.
      let stash: AppView = v;
      if (v.kind === 'conversation') {
        stash = { ...v, transmit: { ...v.transmit, compose: readRichEditor(root, 'dd-compose-input'), log: [] } };
      } else if (v.kind === 'channels' && v.active !== undefined) {
        // The two-pane with a chat open: keep the embedded compose draft, drop its decrypted log (restore
        // reopens the channel fresh; a stash must never hold plaintext past a lifetime crypto-erase).
        stash = { ...v, active: { ...v.active, compose: readRichEditor(root, 'dd-compose-input'), log: [] } };
      } else if (v.kind === 'identity') {
        stash = { ...v, profile: readIdentityDraft(root, v) };
      } else if (v.kind === 'away') {
        stash = { ...v, profile: readAwayDraft(root, v.profile) };
      }
      minimizedWins = [...minimizedWins.filter((m) => m.key !== key), { key, title, view: stash }];
      runWindowExit('dd-win-minimizing', () => revealNextWindow());
    });
    root.querySelector('[data-action="win-close"]')?.addEventListener('click', () => {
      // Native shell: a ROOT/standalone window has nothing behind it to back out to, so its close quits
      // the OS window. That is the unlock screen and the buddy list, AND the pre-login guided flows
      // (the new-device wizard, recovery entry / secret) plus provisioning WHILE it is joining THIS device
      // — backing any of those out via revealNextWindow would fall through to openBuddies and escape the
      // guided flow into the app on an unauthorized device (the exact guard these screens exist to enforce)
      // or strand the single window on the empty desktop. Only a sub-window with a real window behind it
      // (a conversation, Channels, an editor opened from the buddy list) keeps "back out to the window
      // behind me". Provisioning reached from an AUTHORIZED device's Device keys backs out normally.
      const nativeRootClose =
        view.kind === 'unlock' ||
        view.kind === 'buddies' ||
        view.kind === 'newdevice-wizard' ||
        view.kind === 'recovery' ||
        view.kind === 'recover-entry' ||
        (view.kind === 'provisioning' && joiningNewDevice);
      if (isNativeShell() && nativeRootClose) {
        shellBridge()?.close?.();
        return;
      }
      runWindowExit('dd-win-closing', () => revealNextWindow());
    });
    // Restore a minimized window from its menu-bar chip. A conversation reopens FRESH (its log may have
    // moved on); anything else restores exactly the stashed view, unsaved drafts included.
    root.querySelectorAll('[data-restore]').forEach((el) => {
      el.addEventListener('click', () => {
        const key = el instanceof HTMLElement ? (el.dataset.restore ?? '') : '';
        const win = minimizedWins.find((m) => m.key === key);
        if (win === undefined) {
          return;
        }
        minimizedWins = minimizedWins.filter((m) => m.key !== key);
        if (win.view.kind === 'conversation' && win.view.transmit.conversationId !== null) {
          const draft = win.view.transmit.compose; // the harvested half-typed message survives the round trip
          void controller
            .openChannel(win.view.transmit.conversationId)
            .then((transmit) => go({ kind: 'conversation', transmit: { ...transmit, compose: draft } }))
            .catch(() => go(win.view)); // a dead session still shows the (log-less) stashed window
        } else if (win.view.kind === 'channels' && win.view.active !== undefined && win.view.active.conversationId !== null) {
          // The two-pane with a chat open: reopen the active channel fresh (its log was dropped), keep the draft.
          const wv = win.view;
          const draft = wv.active!.compose;
          const id = wv.active!.conversationId!;
          void controller
            .openChannel(id)
            .then((transmit) => go({ kind: 'channels', channels: wv.channels, active: { ...transmit, compose: draft }, selectedId: id }))
            .catch(() => go(wv));
        } else if (win.view.kind === 'buddies') {
          void openBuddies(); // the list re-reads stored truth (statuses/icons may have moved on)
        } else {
          go(win.view);
        }
      });
    });
    root.querySelector('[data-action="add-person"]')?.addEventListener('click', () => {
      const ac = activeConv(view);
      if (ac !== null) {
        go({ kind: 'addperson', conversationId: ac.id });
      }
    });
    root.querySelector('[data-action="addperson-submit"]')?.addEventListener('click', () => {
      if (view.kind !== 'addperson') {
        return;
      }
      const el = root.querySelector('#dd-addperson-input');
      const name = el instanceof HTMLInputElement ? el.value.trim() : '';
      void addPersonToConversation(view.conversationId, name);
    });
    root.querySelector('[data-action="addperson-cancel"]')?.addEventListener('click', () => {
      if (view.kind === 'addperson') {
        void controller.openChannel(view.conversationId).then((transmit) => go({ kind: 'conversation', transmit }));
      }
    });
  }

  // Recover this device by entering the account recovery secret: it becomes an authorized seed-holder,
  // certified at the account's current epoch, then publishes its key packages so peers can reach it.
  async function submitRecovery(): Promise<void> {
    if (controller.recoverWithSeed === undefined) {
      return;
    }
    const el = root.querySelector('#dd-recovery-input');
    const secret = el instanceof HTMLTextAreaElement ? el.value.trim() : '';
    if (secret.length === 0) {
      return;
    }
    try {
      const epoch = await currentAccountEpoch();
      const res = await controller.recoverWithSeed(secret, epoch);
      if (!res.ok) {
        go({ kind: 'recover-entry', error: res.error ?? 'could not recover with that secret' });
        return;
      }
      // Recovery authorized this device via the account seed. If it reached the wizard unauthorized (the
      // enroll-after-authorize reorder deferred enrollment), enroll it now with the stashed secret, running
      // the same fail-closed tri-state, before publishing. The Settings-reached recovery path (an already
      // enrolled seed-holder promotion) carries no stash and is untouched.
      if (pendingWizardEnroll !== null) {
        const enroll = await enrollAndNotice(pendingWizardEnroll.authSecret).catch(() => ({ status: 'unknown' as const }));
        if (enroll.status === 'revoked') {
          await wipeLocalAndReload(
            'login',
            'This device was revoked. Sign in on one of your active devices, or add this device again to keep using it here.',
          );
          return;
        }
        if (enroll.status === 'unknown') {
          go({ kind: 'recover-entry', error: RECOVERY_ENROLL_RETRY_COPY });
          return; // keep the stash so the retry re-uses it
        }
        pendingWizardEnroll = null;
      }
      await syncAndPublish();
      joiningNewDevice = false; // recovery authorized this device; the wizard is done
      // Finish the login the wizard interrupted: a contact link scanned before it still wins.
      if (await openPendingContact()) {
        return;
      }
      await openBuddies();
    } catch (err: unknown) {
      // A network or storage failure mid-recovery must not wedge the UI with no feedback.
      go({ kind: 'recover-entry', error: err instanceof Error ? err.message : 'could not complete recovery' });
    }
  }

  // The account's current certificate epoch: the number of revoked devices (monotonic, server-tracked).
  // A revoke bumps it; devices re-certify at the current epoch so the gate's floor rises (ADR-022 P6).
  /** ADR-022 P7 MIGRATION. Devices revoked before signed records existed carry a burned server row and
   * nothing else, so they are excluded only by the epoch floor, which a seed-holder walks straight over.
   * Any device that holds the account key mints the missing records the first time it sees the list and
   * publishes them, so an account that was revoking devices for months converges on the real exclusion
   * without the user doing anything.
   *
   * Guarded on ALREADY having a record for that key, so this runs once per revoked device and never
   * mints a second, differently-sequenced record for the same target. Entirely best-effort: a failure
   * here is retried on the next device-list read, and it must never break the login path it sits on.
   */
  async function backfillRevocationRecords(devices: readonly DeviceInfo[]): Promise<void> {
    if (account === undefined || controller.revokeDeviceKey === undefined || controller.isDeviceRevoked === undefined) {
      return;
    }
    let seq = (await controller.revocationState?.())?.revoked ?? 0;
    for (const d of devices) {
      if (!d.revoked) {
        continue;
      }
      try {
        if (await controller.isDeviceRevoked(d.deviceKey)) {
          continue; // already covered by a record we hold
        }
        seq += 1;
        const record = await controller.revokeDeviceKey(d.deviceKey, seq);
        if (record !== null) {
          await account.revokeDevice(d.deviceId, record); // idempotent: the row is already burned
        }
      } catch {
        // No account key on this device, or the server refused. Retried on the next list read.
      }
    }
  }

  async function currentAccountEpoch(): Promise<number> {
    if (account === undefined) {
      return 0;
    }
    try {
      const res = await account.listDevices();
      if (!res.ok || res.devices === undefined) {
        return 0;
      }
      // Prefer the server's EXPLICIT monotonic counter. Counting revoked rows was the old derivation
      // and it tied this security floor to how much device history happened to be retained: pruning
      // old tombstones walked the epoch backward while every device's local floor stayed put, so the
      // next paired device was certified below the floor and could never join. The count remains only
      // as the fallback for a server that predates the counter, where the two are still equal.
      // ADR-022 P7: the same response carries the account's signed revocation records, so take them
      // here rather than paying a second round trip. This is the call every pre-pairing and post-revoke
      // path already makes, which means a device cannot mint or publish without first having had the
      // chance to learn who was thrown out. Each record is signature-checked against our own account
      // key inside the worker, so a hostile server can withhold them (delaying exclusion) but cannot
      // inject one. Awaited, not fired off: minting before ingesting would certify against a stale
      // denylist, which is the exact ordering bug this whole mechanism exists to close.
      if (res.revocations !== undefined && res.revocations.length > 0) {
        await controller.ingestRevocations?.(res.revocations);
      }
      await backfillRevocationRecords(res.devices);
      if (res.accountEpoch !== undefined) {
        return res.accountEpoch;
      }
      return res.devices.filter((d) => d.revoked).length;
    } catch {
      return 0; // a network failure must not throw out of the login/recovery flow
    }
  }

  // Bring this device up to the account's current cert epoch, then publish its key packages, UNLESS it
  // is a stale seedless device that cannot self-certify (then it must be reconnected first).
  async function syncAndPublish(): Promise<void> {
    const epoch = await currentAccountEpoch();
    const sync = await controller.syncEpoch?.(epoch);
    if (sync !== undefined && sync.stale) {
      return; // do not publish old-epoch packages a peer would reject; the user reconnects this device
    }
    await publishOwnKeys();
  }

  // Begin adding a device. The seed-holder opens a window and challenges; the new device waits for it.
  // Both then surface six words (via the show-code/confirm-device events) for the user to compare.
  async function startProvisioning(role: 'seedholder' | 'newdevice'): Promise<void> {
    go({ kind: 'provisioning', state: { role, step: role === 'seedholder' ? 'opening' : 'waiting' } });
    try {
      if (role === 'seedholder') {
        await controller.openProvisioningWindow?.();
      } else {
        await controller.joinDevice?.();
      }
    } catch (err: unknown) {
      go({ kind: 'provisioning', state: { role, step: 'error', error: err instanceof Error ? err.message : 'could not start' } });
    }
  }

  // Add-a-device by QR. The NEW device shows its pairing code; the AUTHORIZED device scans it. The code
  // is optical only, so a malicious gateway can neither read nor re-target the sealed grant (the scan is
  // the out-of-band authentication, replacing the six words; see provisioning.ts). The six-word flow
  // remains the no-camera fallback.
  async function startQrShowThisDevice(): Promise<void> {
    if (controller.startQrPairing === undefined) {
      go({ kind: 'provisioning', state: { role: 'newdevice', step: 'error', error: 'QR pairing is not available on this device. Use Connect this device instead.' } });
      return;
    }
    try {
      const payload = await controller.startQrPairing();
      if (payload === undefined || payload === '') {
        go({ kind: 'provisioning', state: { role: 'newdevice', step: 'error', error: 'Could not build a code on this device. Use Connect this device instead.' } });
        return;
      }
      go({ kind: 'provisioning', state: { role: 'newdevice', step: 'showqr', qr: payload } });
    } catch (err: unknown) {
      go({ kind: 'provisioning', state: { role: 'newdevice', step: 'error', error: err instanceof Error ? err.message : 'could not build a code' } });
    }
  }

  // Open the camera, decode frames, and hand the first ddpair code to the worker to certify + seal. Uses
  // the native BarcodeDetector when present, else lazy-loads the vendored jsQR decoder (iOS Safari,
  // Firefox). stopScan() (from go()) releases the camera on any navigation, and navGen guards the async
  // gaps so leaving the screen mid-permission drops the stream.
  // Shared camera QR loop for the device-pairing scan and the buddy-contact scan. The caller has already
  // navigated to a view holding #dd-scan-video + #dd-scan-canvas; this opens the rear camera, decodes
  // frames (native BarcodeDetector, else the lazy jsQR fallback), and calls onFound with the first payload
  // accept() approves. onError(reason) fires only while still on the scan screen. navGen guards the async
  // gaps and stopScan() (from go()) releases the camera on any navigation.
  async function runCameraScan(
    accept: (text: string) => boolean,
    onFound: (text: string) => Promise<void> | void,
    onError: (reason: 'camera' | 'decoder') => void,
  ): Promise<void> {
    const media = opts?.media;
    if (media === undefined) {
      onError('camera');
      return;
    }
    const gen = navGen; // captured after the caller's go(): navGen === gen means still on the scan screen
    let stream: MediaStreamLike;
    try {
      stream = await media({ audio: false, video: true, facingMode: 'environment' });
    } catch {
      if (navGen === gen) {
        onError('camera');
      }
      return;
    }
    if (navGen !== gen) {
      for (const t of stream.getTracks()) {
        t.stop(); // the user left while the permission prompt was up; drop the camera
      }
      return;
    }
    scanStream = stream;
    const video = root.querySelector('#dd-scan-video');
    const canvas = root.querySelector('#dd-scan-canvas');
    if (!(video instanceof HTMLVideoElement) || !(canvas instanceof HTMLCanvasElement)) {
      stopScan();
      return;
    }
    (video as unknown as { srcObject: unknown }).srcObject = stream;
    void video.play().catch(() => {});
    // A native detector when the browser has one, else the lazy-loaded jsQR fallback.
    type Detector = { detect(src: CanvasImageSource): Promise<Array<{ rawValue: string }>> };
    const BD = (globalThis as { BarcodeDetector?: new (o: { formats: string[] }) => Detector }).BarcodeDetector;
    let detector: Detector | null = null;
    if (BD !== undefined) {
      try {
        detector = new BD({ formats: ['qr_code'] });
      } catch {
        detector = null;
      }
    }
    let jsqrDecode: ((d: Uint8ClampedArray, w: number, h: number) => string | null) | null = null;
    if (detector === null) {
      try {
        // The bundle is an esbuild-only artifact (dist/qrdecode.bundle.js), served beside app.js in the
        // browser. A non-literal specifier + @vite-ignore keeps vitest from resolving it from source; the
        // cast restores its type from the ambient qrdecode.bundle.d.ts.
        const bundlePath = './qrdecode.bundle.js';
        const mod = (await import(/* @vite-ignore */ bundlePath)) as typeof import('./qrdecode.bundle.js');
        jsqrDecode = mod.decodeQr;
      } catch {
        stopScan();
        if (navGen === gen) {
          onError('decoder');
        }
        return;
      }
    }
    if (scanStream !== stream) {
      return; // torn down while the decoder loaded
    }
    const ctx = canvas.getContext('2d');
    if (ctx === null) {
      stopScan();
      return;
    }
    let handling = false;
    const tick = async (): Promise<void> => {
      if (scanStream !== stream) {
        return; // superseded or torn down
      }
      const w = video.videoWidth;
      const h = video.videoHeight;
      if (w === 0 || h === 0) {
        scanTimer = setTimeout(() => void tick(), 120); // the camera is not ready yet
        return;
      }
      canvas.width = w;
      canvas.height = h;
      ctx.drawImage(video, 0, 0, w, h);
      let found: string | null = null;
      try {
        if (detector !== null) {
          const codes = await detector.detect(canvas);
          found = codes.length > 0 ? (codes[0]?.rawValue ?? null) : null;
        } else if (jsqrDecode !== null) {
          const img = ctx.getImageData(0, 0, w, h);
          found = jsqrDecode(img.data, w, h);
        }
      } catch {
        found = null; // a bad frame; keep scanning
      }
      if (scanStream !== stream) {
        return; // detect() is async; we may have been torn down meanwhile
      }
      if (found !== null && accept(found) && !handling) {
        handling = true;
        stopScan();
        await onFound(found);
        return;
      }
      scanTimer = setTimeout(() => void tick(), 200);
    };
    scanTimer = setTimeout(() => void tick(), 200);
  }

  // DEVICE PAIRING: the authorized device scans a new device's ddpair code (crypto seal + adopt). This is
  // account-linking, distinct from the buddy scan below, which only exchanges contacts.
  async function startQrScan(): Promise<void> {
    if (controller.grantScannedDevice === undefined || opts?.media === undefined) {
      go({ kind: 'provisioning', state: { role: 'seedholder', step: 'error', error: 'In-app scanning is not available here. Use Add a device and compare the six words.' } });
      return;
    }
    go({ kind: 'provisioning', state: { role: 'seedholder', step: 'scanning' } });
    await runCameraScan(
      (text) => text.startsWith('ddpair:'),
      async (text) => {
        try {
          await controller.grantScannedDevice?.(text);
        } catch {
          go({ kind: 'provisioning', state: { role: 'seedholder', step: 'error', error: 'Could not add that device. Try again.' } });
        }
      },
      (reason) => {
        const msg =
          reason === 'camera'
            ? 'Could not open the camera. Use Add a device and compare the six words instead.'
            : 'The scanner could not load. Use Add a device and compare the six words instead.';
        go({ kind: 'provisioning', state: { role: 'seedholder', step: 'error', error: msg } });
      },
    );
  }

  // BUDDY CONTACT EXCHANGE: scan a buddy's contact QR (a #dd=<user> link) and open a conversation with
  // them. This never links a device; it only starts a channel, gated by the usual key-exchange screen.
  async function startBuddyScan(): Promise<void> {
    if (opts?.media === undefined || account === undefined) {
      await openBuddySetup('In-app scanning is not available here. Add a buddy by username instead.');
      return;
    }
    go({ kind: 'buddyscan' });
    await runCameraScan(
      (text) => parseContactLink(text) !== null,
      async (text) => {
        const c = parseContactLink(text);
        if (c === null) {
          await openBuddySetup('That code is not a DEAD DROP contact.');
          return;
        }
        await openScannedContact(c.username);
      },
      (reason) => {
        const msg =
          reason === 'camera'
            ? 'Could not open the camera. Add a buddy by username instead.'
            : 'The scanner could not load. Add a buddy by username instead.';
        void openBuddySetup(msg);
      },
    );
  }

  // Open the key-exchange start screen pre-filled with a scanned buddy's username (directory-backed, like
  // opening a shared contact link). The user still confirms the key on that screen. Never yourself.
  async function openScannedContact(username: string): Promise<void> {
    const uname = username.trim();
    if (account === undefined || uname === '') {
      await openBuddySetup('That code is not a DEAD DROP contact.');
      return;
    }
    if (uname.toLowerCase() === currentUsername.trim().toLowerCase()) {
      await openBuddySetup('That is your own contact code.');
      return;
    }
    const state = await controller.startKeyExchange();
    go({ kind: 'keyexchange', state: { ...state, byUsername: true, selfUsername: currentUsername, peerUsername: uname } });
  }

  // Show this account's contact QR (the same shareable link as the Profile screen) for a buddy to scan.
  async function showMyContactQr(): Promise<void> {
    let fingerprint = '';
    try {
      fingerprint = (await controller.accountFingerprint?.()) ?? '';
    } catch {
      fingerprint = '';
    }
    profileContactLink = buildContactLink(currentUsername, fingerprint);
    go({ kind: 'buddyqr', link: profileContactLink });
  }

  // Publish this device's key packages to the directory so peers can add it to groups. Only a
  // group-ready device (the seed-holder or a provisioned one) publishes, so a peer never claims an
  // unauthorized package and fails the whole group's authorization gate.
  // Returns true only when a key-package batch was actually published, so the wizard enrollment can detect
  // a swallowed publish failure (an enrolled device with no key packages reads authorized=false forever).
  async function publishOwnKeys(): Promise<boolean> {
    if (account === undefined || controller.keyPackages === undefined) {
      return false;
    }
    try {
      if (controller.isGroupReady !== undefined && !(await controller.isGroupReady())) {
        return false;
      }
      const hexes = await controller.keyPackages(KEY_PACKAGE_COUNT);
      if (hexes.length < 2) {
        return false;
      }
      const bytes = hexes.map(hexToBytesLocal);
      const lastResort = bytes[bytes.length - 1];
      if (lastResort === undefined) {
        return false;
      }
      await account.publishKeys(bytes.slice(0, -1), lastResort);
      return true;
    } catch (err: unknown) {
      console.warn('could not publish key packages:', err instanceof Error ? err.message : String(err));
      return false;
    }
  }

  // Self-heal (H1): admit this account's authorized devices that are not yet in the open conversation,
  // so every signed-in device receives going forward. Idempotent: the GroupChannel runs the
  // designated-adder + staged add and claims a key package only for a genuinely missing device, so this
  // is safe to call on login, after a device is provisioned, and on each roster change (it no-ops when
  // nothing is missing). The claim is memoized per pass so one take-keys call serves every missing
  // sibling. A pass that consumed packages tops the directory back up (replenishment), so take-keys
  // always returns every authorized device next time.
  // Our account's AUTHORIZED, non-revoked device keys: the devices that have published a key package, so
  // an enrolled-but-never-authorized orphan can no longer inflate the self-group creator election (the
  // SECURING stall) or the reconcile candidate set. authorized is sticky after the first publish (the
  // server never clears it short of revoke), so this is safe on triggers that do not await a fresh publish.
  // Deploy-skew fallback: against a pre-F2 server (no authorized field on any row) it degrades to the
  // legacy non-revoked list, exactly as renderSettings and enrollAndNotice already do.
  function authorizedDeviceKeys(devices: readonly DeviceInfo[]): string[] {
    const authorizedKnown = devices.some((d) => d.authorized);
    return devices.filter((d) => !d.revoked && (authorizedKnown ? d.authorized : true)).map((d) => d.deviceKey);
  }
  let reconciling = false;
  async function reconcileSiblings(): Promise<void> {
    if (account === undefined || controller.reconcileSiblings === undefined || reconciling) {
      return;
    }
    reconciling = true;
    try {
      const list = await account.listDevices();
      if (!list.ok || list.devices === undefined) {
        return;
      }
      const ownDeviceKeys = authorizedDeviceKeys(list.devices);
      // Cheap pre-check: only claim key packages when this device actually has a sibling to add (skips a
      // peer-only roster change, which would otherwise burn one-time packages).
      if (controller.hasMissingSiblings !== undefined && !(await controller.hasMissingSiblings(ownDeviceKeys))) {
        return;
      }
      const own = await account.takeKeys(currentUsername);
      const candidates: DeviceTarget[] =
        own.ok && own.devices !== undefined
          ? own.devices.map((d) => ({ deviceKey: d.deviceKey, keyPackage: d.keyPackage }))
          : [];
      if (candidates.length === 0) {
        return; // nothing claimable: defer to the next trigger, never add partially
      }
      await controller.reconcileSiblings(ownDeviceKeys, candidates);
      await publishOwnKeys(); // the claim consumed one-time packages: top the directory back up
    } catch (err: unknown) {
      console.warn('reconcile siblings failed:', err instanceof Error ? err.message : String(err));
    } finally {
      reconciling = false;
    }
  }

  // A newly authorized device publishes its key package only AFTER the seed-holder's one-shot
  // 'device-added' reconcile has already run: the new device adopts its certificate, enrolls, and only
  // then publishes, all strictly after the sealed grant hits the wire. That publish pushes nothing back to
  // the seed-holder, and a cert-only new device (QR / six words, no account key) cannot add itself to the
  // hidden self-group (it can only receive the Welcome the seed-holder sends). So without a re-trigger the
  // new device would sit on SECURING forever. The seed-holder that authorized it knows its key (carried on
  // the device-added event), so poll until the device is authorized + claimable, then reconcile it into the
  // self-group via reconcileSelf. reconcileSelf keeps the RACE-FREE designated-adder election (it does NOT
  // bypass it): the lowest-keyed online device stages immediately and we defer; if that device is offline
  // our position-ranked failover heals it. The normal reconcileSiblings pre-check is adder-scoped and would
  // gate this off on a non-lowest-keyed device, so reconcileSelf is what makes the heal reachable here.
  // Settle precisely on self-group membership; skip claiming key packages while the device is unpublished or
  // an add is already under way. Bounded by the pairing window so a device that never completes cannot leave
  // the timer running.
  const SIBLING_HEAL_INTERVAL_MS = 3_000;
  const SIBLING_HEAL_WINDOW_MS = 120_000; // matches the seed-holder pairing window: after it the grant is dead
  function healNewSibling(newDeviceKey: string): void {
    const acct = account;
    if (
      acct === undefined ||
      newDeviceKey === '' ||
      controller.selfSiblingState === undefined ||
      controller.reconcileSelf === undefined
    ) {
      return;
    }
    // Invoke both AS methods on controller so `this` stays bound across the poll (the worker-proxy
    // controller dereferences `this`); an unbound capture would throw at call time.
    const siblingState = (k: string): Promise<'member' | 'pending' | 'absent' | 'none'> =>
      controller.selfSiblingState === undefined ? Promise.resolve('none') : controller.selfSiblingState(k);
    const reconcileSelf = (own: readonly string[], cands: readonly DeviceTarget[]): Promise<void> =>
      controller.reconcileSelf === undefined ? Promise.resolve() : controller.reconcileSelf(own, cands);
    if (siblingHealTimer !== null) {
      clearTimeout(siblingHealTimer);
      siblingHealTimer = null;
    }
    const gen = ++siblingHealGen; // this poll's identity; a newer heal or a teardown invalidates it
    siblingAddRejections.delete(newDeviceKey); // a fresh pairing starts with a clean slate
    siblingAddRejectReasons.delete(newDeviceKey);
    const deadline = Date.now() + SIBLING_HEAL_WINDOW_MS;
    const tick = async (): Promise<void> => {
      siblingHealTimer = null;
      if (gen !== siblingHealGen) {
        return; // superseded by a newer heal, or torn down (sign-out / abandon-wizard)
      }
      if ((siblingAddRejections.get(newDeviceKey) ?? 0) >= 2) {
        // The adder gate rejected this device's packages twice: deterministic for everything its
        // directory can serve, so further ticks would only burn more packages. Stop and tell the user.
        //
        // The old copy here told them to REVOKE the device and pair it again. That was actively harmful:
        // revoking is the one action that permanently burns the device's key and (ADR-022 P7) writes a
        // signed record excluding it forever, so following the advice made the state worse every time,
        // and the user could repeat it indefinitely without ever being told why. Say what happened and
        // point at starting the pairing over, which is what actually produces a fresh, admissible key.
        const reason = siblingAddRejectReasons.get(newDeviceKey);
        showToast(
          reason === undefined
            ? 'could not add the new device. start the pairing again from that device'
            : `could not add the new device (${reason}). start the pairing again from that device`,
        );
        return;
      }
      await reconcileRemovals();
      const state = await siblingState(newDeviceKey);
      if (state === 'member') {
        return; // settled: the new device is in the self-group; roster-changed drives any peer groups
      }
      if (state === 'none') {
        await ensureSelfGroup(); // no self-group yet: the designated creator mints it (with the sibling)
      } else if (state === 'absent') {
        const list = await acct.listDevices();
        const authed = list.ok && list.devices !== undefined ? authorizedDeviceKeys(list.devices) : [];
        if (authed.includes(newDeviceKey)) {
          // Authorized (published a claimable package) and no add under way: claim and heal it into the
          // self-group (the lowest-keyed device stages if online, else our position-ranked failover does).
          const own = await acct.takeKeys(currentUsername);
          const candidates: DeviceTarget[] =
            own.ok && own.devices !== undefined
              ? own.devices.map((d) => ({ deviceKey: d.deviceKey, keyPackage: d.keyPackage }))
              : [];
          if (candidates.length > 0) {
            await reconcileSelf(authed, candidates);
            await publishOwnKeys(); // the claim consumed one-time packages: top the directory back up
          }
        }
      }
      // state 'pending' (an add is in flight) or still unpublished: keep polling until it lands or the
      // window closes. Re-check the generation so a teardown during the awaits above cannot re-arm.
      if (gen !== siblingHealGen || Date.now() >= deadline) {
        return;
      }
      siblingHealTimer = setTimeout(() => void tick(), SIBLING_HEAL_INTERVAL_MS);
    };
    siblingHealTimer = setTimeout(() => void tick(), SIBLING_HEAL_INTERVAL_MS);
  }

  // P6 durable forward-secure exclusion: re-key any REVOKED device out of every open conversation it still
  // belongs to, so a device revoked while this device was offline is removed on the next sync (the mirror
  // of reconcileSiblings for removals). No key-package claim needed. The GroupChannel runs the
  // designated-adder + staged remove, targeting ONLY keys on the account's revoked list, so it can never
  // remove a re-added device (fresh key) or a peer.
  let reconcilingRemovals = false;
  async function reconcileRemovals(): Promise<void> {
    if (account === undefined || controller.reconcileRemovals === undefined || reconcilingRemovals) {
      return;
    }
    reconcilingRemovals = true;
    try {
      const list = await account.listDevices();
      if (!list.ok || list.devices === undefined) {
        return;
      }
      const ownDeviceKeys = authorizedDeviceKeys(list.devices);
      const revokedKeys = list.devices.filter((d) => d.revoked).map((d) => d.deviceKey);
      if (revokedKeys.length === 0) {
        return; // nothing revoked to drive out
      }
      await controller.reconcileRemovals(ownDeviceKeys, revokedKeys);
    } catch (err: unknown) {
      console.warn('reconcile removals failed:', err instanceof Error ? err.message : String(err));
    } finally {
      reconcilingRemovals = false;
    }
  }

  // The hidden self-group is the private channel that syncs the buddy list across this account's own
  // devices (the buddy list is the contact graph, so it must never ride a peer conversation). Only the
  // DESIGNATED device (the lexicographically lowest device key) creates it, and only once; every other
  // device waits for the Welcome and joins it silently. Triggered on login, a device add, and a roster
  // change, and a no-op once it exists (so re-triggering is cheap).
  //
  // LIVENESS FALLBACK (SG1): the election used to be absolute — if the designated device could not mint
  // (a cert-only phone cannot anchor a solo group; any of its guards can fail), NO device ever formed
  // the group, and the account sat with two healthy devices and no self-group, permanently (observed
  // live: no formation for 19 hours, both devices online). So a non-designated device now WAITS ONE
  // GRACE WINDOW for the designated device's group to appear, and then mints itself. The window keeps
  // the normal case race-free (one minter); the deterministic canonical selection (certified > largest
  // roster > lowest id) converges the rare double-mint. Formation can stall for a window; it can no
  // longer stall forever.
  // How long a non-designated device waits for the designated one to mint before minting itself. This
  // used to be 45s AND was never actually waited out: arming `selfMintDeferredSince` only recorded a
  // timestamp, and nothing scheduled the later pass that would read it — so the "fallback" fired only
  // if some UNRELATED trigger (a reconnect, a tab focus) happened along after the window. With no such
  // trigger it never fired at all, which is how an account sat unformed for hours. It is now armed with
  // a real timer, so 12s is a genuine bound rather than an optimistic one; both racing mints are
  // populated, and selfSessionBest's deterministic ranking converges them.
  const SELF_MINT_FALLBACK_MS = 12000;
  const SELF_MINT_JITTER_MS = 4000; // spread simultaneous wake-ups so two devices do not mint in lockstep
  let selfMintDeferredSince: number | null = null;
  let selfMintFallbackTimer: ReturnType<typeof setTimeout> | null = null;
  // Consecutive mint failures. Every attempt burns a one-time prekey per sibling, and the control plane
  // returns a take-keys THROTTLE as HTTP 200 with an empty device list — byte-identical to an account
  // with no other devices. Without a backoff a self-inflicted throttle reads to us as "nothing to claim
  // yet" and spins silently forever, draining prekeys the whole time.
  const SELF_MINT_MAX_FAILURES = 6;
  let selfMintFailures = 0;
  let ensuringSelfGroup = false;
  async function ensureSelfGroup(): Promise<void> {
    if (
      account === undefined ||
      controller.ensureSelfGroup === undefined ||
      controller.hasSelfGroup === undefined ||
      ensuringSelfGroup
    ) {
      return;
    }
    ensuringSelfGroup = true;
    try {
      const list = await account.listDevices();
      if (!list.ok || list.devices === undefined) {
        return;
      }
      const ownDeviceKeys = authorizedDeviceKeys(list.devices);
      if (currentDeviceKey === '') {
        return;
      }
      if (ownDeviceKeys.length < 2) {
        // Single-device account: still mint the SOLO self-group so this device has its OWN E2E session.
        // Without it a fresh account stays on "◐ SECURING…" forever (no conversation = no E2E session);
        // creating the hidden own-devices group gives a real established session, so the status reaches
        // "● SECURE LINK", and Note-to-Self + the buddy-list sync are ready from the first login.
        // openNoteToSelf's openSelfConversation is idempotent (returns any existing self-group) and emits
        // connection:'secure'; we create it in the BACKGROUND and never navigate to it (it stays hidden —
        // listChannels excludes it and the Note-to-Self row only appears when the user opens it). A
        // cert-only device (provisioned by QR / six words, no account key) cannot anchor a self-group and
        // throws: that edge case legitimately stays SECURING until it has a conversation.
        if (controller.hasSelfGroup !== undefined && !(await controller.hasSelfGroup())) {
          try {
            await controller.openNoteToSelf();
          } catch {
            /* cert-only device or transient failure: leave the connection state unchanged */
          }
        }
        return;
      }
      if (await controller.hasSelfGroup()) {
        selfMintDeferredSince = null; // a self-group exists: nothing to form, and no fallback is armed
        selfMintFailures = 0;
        if (selfMintFallbackTimer !== null) {
          clearTimeout(selfMintFallbackTimer);
          selfMintFallbackTimer = null;
        }
        return;
      }
      // Deterministic single creator: the lowest-keyed device creates it; others join via the Welcome.
      // A non-designated device no longer defers FOREVER: the first time it sees "no self-group and I am
      // not the minter" it arms a grace window; if the designated device's group has STILL not appeared
      // on a later trigger past that window, the designated device has failed to mint (it may be UNABLE
      // to — a cert-only device cannot anchor a solo group), so this device mints instead. The window
      // keeps the normal case single-minter; the deterministic canonical selection converges the rare
      // race where both mint near-simultaneously.
      if ([...ownDeviceKeys].sort()[0] !== currentDeviceKey) {
        if (selfMintDeferredSince === null) {
          selfMintDeferredSince = Date.now();
          // ARM A REAL TIMER. Recording the timestamp alone made the window depend on an unrelated
          // later trigger; on a quiet, foregrounded tab none arrives and the deferral never expires.
          if (selfMintFallbackTimer !== null) {
            clearTimeout(selfMintFallbackTimer);
          }
          selfMintFallbackTimer = setTimeout(
            () => {
              selfMintFallbackTimer = null;
              void ensureSelfGroup();
            },
            SELF_MINT_FALLBACK_MS + Math.floor(Math.random() * SELF_MINT_JITTER_MS),
          );
          return; // first sight: give the designated device its window
        }
        if (Date.now() - selfMintDeferredSince < SELF_MINT_FALLBACK_MS) {
          return; // still inside the window: keep waiting for the designated device's Welcome
        }
        console.warn('self-group fallback: the designated device has not formed the group; minting from this device');
      }
      if (selfMintFailures >= SELF_MINT_MAX_FAILURES) {
        // Parked. A roster change or a device-added clears this (see below); until then stop issuing
        // take-keys so a throttle or a genuinely uncertified sibling cannot be drained in a loop.
        return;
      }
      selfMintDeferredSince = null;
      const own = await account.takeKeys(currentUsername);
      const targets: DeviceTarget[] =
        own.ok && own.devices !== undefined
          ? own.devices
              .filter((d) => d.deviceKey !== currentDeviceKey)
              .map((d) => ({ deviceKey: d.deviceKey, keyPackage: d.keyPackage }))
          : [];
      if (targets.length === 0) {
        // THE THROTTLE SIGNATURE. listDevices saw siblings but take-keys returned none: that is either a
        // rate-limited claim (returned as 200 + empty list, not 429) or siblings with no publishable
        // package. Both are "stop asking for a while", and both used to look like a benign no-op.
        selfMintFailures += 1;
        if (ownDeviceKeys.length > 1) {
          console.warn(
            `self-group: ${ownDeviceKeys.length} devices in the directory but take-keys returned none ` +
              `(attempt ${selfMintFailures}/${SELF_MINT_MAX_FAILURES}) — rate limit or unpublished packages`,
          );
        }
        return; // no sibling key packages claimable yet: defer to the next trigger
      }
      await controller.ensureSelfGroup(targets);
      selfMintFailures = 0; // a real mint landed
      await publishOwnKeys(); // the claim consumed one-time packages: top the directory back up
    } catch (err: unknown) {
      console.warn('ensure self-group failed:', err instanceof Error ? err.message : String(err));
      selfMintFailures += 1; // a throwing mint burns prekeys too; back off like the empty-claim case
      // The claim above may still have consumed packages (a birth-gate rejection lands here): top our
      // own directory rows back up so peers are not pushed onto our last-resort package meanwhile.
      void publishOwnKeys();
    } finally {
      ensuringSelfGroup = false;
    }
  }

  // Open the live gateway connection (called on unlock). Resolves quietly if there is no gateway,
  // returning our self-contact so the register flow can read the identity key it must publish.
  async function connectLive(): Promise<{ selfContact: string | null }> {
    if (opts?.wsUrl === undefined) {
      return { selfContact: null };
    }
    setConn('connecting'); // reads RECONNECTING when this is a retry (connAttempt > 0)
    try {
      const res = await controller.connectGateway(opts.wsUrl);
      if (res.ok) {
        setConn('live');
        return { selfContact: res.selfContact };
      }
    } catch (err: unknown) {
      console.warn('gateway connect unavailable:', err instanceof Error ? err.message : String(err));
    }
    setConn('offline'); // schedules the next quiet retry once signed in
    return { selfContact: null };
  }

  // Consume the stashed contact link (#dd=<user>) and, when it can be honored, land on a "message this
  // user" start screen with the handle pre-filled (directory-backed, so it needs an account server;
  // never message yourself). Called wherever a sign-in lands: at the end of doLogin, at both
  // doRegister landings (after the one-time recovery-secret screen, or straight to channels when no
  // secret is shown), and when the add-this-device wizard completes (doLogin returned early into the
  // wizard without reaching the contact check, so the scanned link would otherwise silently survive
  // until a later login).
  // Returns true when it navigated; the stash is consumed either way.
  async function openPendingContact(): Promise<boolean> {
    const pendingContact = takePendingContact();
    if (pendingContact === null || account === undefined || pendingContact.username.trim().toLowerCase() === currentUsername.trim().toLowerCase()) {
      return false;
    }
    pendingResume = null;
    const state = await controller.startKeyExchange();
    go({ kind: 'keyexchange', state: { ...state, byUsername: true, selfUsername: currentUsername, peerUsername: pendingContact.username } });
    return true;
  }

  // Log in: authenticate against the account server (when present), then unlock the local vault and
  // connect. Logging in is when we connect and subscribe, so the gateway hands us any messages it
  // held while we were offline (hold-until-seen at the network layer).
  async function doLogin(user: string, pass: string): Promise<void> {
    joiningNewDevice = false;
    pendingWizardEnroll = null;
    if (account !== undefined) {
      const auth = await account.login(user, pass);
      if (!auth.ok) {
        go({ kind: 'unlock', mode: 'login', error: auth.error ?? 'wrong username or passphrase' });
        return;
      }
    }
    const res = await controller.unlock(user, pass);
    if (!res.ok) {
      go({ kind: 'unlock', mode: 'login', error: res.error ?? 'wrong username or passphrase' });
      return;
    }
    currentUsername = user.trim();
    // The vault is unlocked. Ask the browser to keep this origin's storage (the unrecoverable IndexedDB
    // vault) from being evicted under pressure. Best-effort and non-blocking, so a denial or a browser
    // that lacks the API never affects sign-in.
    void requestPersistentStorage();
    // Load this device's saved look (device-local; sanitized against the token allowlist). It is applied
    // on the next render via applyAppearance(); the default is the untouched base skin.
    appearance = sanitizeAppearance(await controller.getAppearance?.());
    const { selfContact } = await connectLive();
    currentDeviceKey = selfContact !== null ? (selfContact.split(':')[3] ?? '') : '';
    // Derive the login secret once (memory-only, password-equivalent; never the plaintext passphrase). It
    // is re-used for enrollment either now (authorized path) or later at the provisioning point (wizard).
    const authSecret = account !== undefined ? await deriveAuthSecret(user, pass) : '';
    // If the credentials were valid but THIS device is not authorized locally (no seed, no adopted
    // certificate), guide the user to authorize it WITHOUT enrolling, so an abandoned attempt leaves no
    // orphan device row on the server. deviceAuthState reads only the local vault, so it works pre-enroll.
    // Only with an account server (local-only logins have no second device to coordinate with), and after
    // connectLive, since both authorization paths need the gateway.
    if (account !== undefined) {
      const authState = (await controller.deviceAuthState?.()) ?? { authorized: true, seedHolder: false };
      if (!authState.authorized) {
        pendingWizardEnroll = { user: user.trim(), authSecret };
        joiningNewDevice = true;
        go({ kind: 'newdevice-wizard', state: { step: 'choose', connected: selfContact !== null } });
        return;
      }
    }
    // This device is authorized locally. Enroll it (idempotent) and run the fail-closed check that catches
    // a device revoked remotely (its local state still reads authorized). A hard network rejection throws
    // out of the account calls; coerce to 'unknown' so it lands on the retry screen, never an unhandled
    // reject on the frozen unlock screen.
    const enroll: { status: 'clear'; notice?: string } | { status: 'revoked' } | { status: 'unknown' } =
      account !== undefined
        ? await enrollAndNotice(authSecret).catch(() => ({ status: 'unknown' as const }))
        : { status: 'clear' };
    if (enroll.status === 'revoked') {
      await wipeLocalAndReload(
        'login',
        'This device was revoked. Sign in on one of your active devices, or add this device again to keep using it here.',
      );
      return;
    }
    if (enroll.status === 'unknown') {
      go({
        kind: 'unlock',
        mode: 'login',
        error: 'Could not verify this device with the account server. Check your connection and try again.',
        prefillUser: user.trim(),
      });
      return;
    }
    const notice = enroll.notice;
    // Bring this device up to the account's current cert epoch (after any revoke) and publish keys.
    await syncAndPublish();
    // Heal any restored conversation: admit siblings authorized while this device was offline, so every
    // signed-in device receives going forward (H1). No-op when no conversation is open.
    void reconcileRemovals();
    void reconcileSiblings();
    // Ensure the hidden self-group exists so the buddy list syncs across this account's own devices.
    void ensureSelfGroup();
    // If server-side away is on, re-assert it and start the presence heartbeat so the server knows we
    // are back online and stops serving the away text.
    await restoreServerAway();
    if ((await controller.getPresenceEnabled?.()) === true) {
      startPresenceBeat(); // resume sharing presence after login
    }
    notifyEnabled = (await controller.getNotifyEnabled?.()) ?? true;
    if (notifyEnabled) {
      requestNotifyPermission();
      startBuddyWatch();
    }
    // AIM semantics: signing on marks you ONLINE. A fresh sign-in takes any leftover away message down
    // (the message stays in the saved library); a page-refresh RESUME keeps whatever state you had.
    if (pendingResume?.username !== currentUsername) {
      const prof = (await controller.getIdentity?.()) ?? DEFAULT_IDENTITY;
      if (prof.away.enabled) {
        const online = { ...prof, away: { ...prof.away, enabled: false } };
        await (controller.setIdentity?.(online) ?? Promise.resolve());
        await applyServerAway(online);
      }
    }
    const channels = await controller.listChannels();
    // A scanned/opened contact link takes priority: land on a "message this user" start screen.
    if (await openPendingContact()) {
      return;
    }
    // S1: if this unlock is resuming a refreshed session, return to the conversation that was open (when
    // it still exists for this account); otherwise land on the channels list. Consume the hint either way.
    const resumeConv = pendingResume?.username === currentUsername ? pendingResume?.conversationId : undefined;
    pendingResume = null;
    if (resumeConv !== undefined) {
      if (channels.some((c) => c.id === resumeConv)) {
        const transmit = await controller.openChannel(resumeConv);
        go({ kind: 'conversation', transmit });
        return;
      }
      // Note to Self has NO channel summary (the self-group stays out of the channels list), so the
      // check above misses it; open it directly and resume only when it proves to be the self chat.
      const transmit = await controller.openChannel(resumeConv).catch(() => null);
      if (transmit !== null && transmit.selfNote === true) {
        go({ kind: 'conversation', transmit });
        return;
      }
    }
    // Home is the buddy list (AIM's Buddy List window opens on sign-on). The multi-device notice, when
    // any, rides the buddy list.
    await openBuddies(notice);
  }

  // Return to the add-this-device wizard chooser (used by the reused provisioning/recovery Cancel paths).
  function backToWizard(): void {
    go({ kind: 'newdevice-wizard', state: { step: 'choose', connected: true } });
  }

  // Retry reaching the gateway from the wizard when the first connect failed.
  async function retryWizardConnect(): Promise<void> {
    const { selfContact } = await connectLive();
    // Re-derive this device's key from the reconnected session, mirroring doLogin. Without this a
    // login-time connect failure leaves currentDeviceKey='' forever, so enrollAndNotice reads 'unknown' and
    // a successfully paired device dead-ends.
    currentDeviceKey = selfContact !== null ? (selfContact.split(':')[3] ?? '') : currentDeviceKey;
    go({ kind: 'newdevice-wizard', state: { step: 'choose', connected: selfContact !== null } });
  }

  // Abandon the add-this-device wizard: discard the local vault and the just-created (unauthorized)
  // identity so a seized device keeps no orphaned account state, then return to the login screen.
  // Disarm the reconnect engine too — a pending backoff timer would otherwise redial the gateway from
  // the LOGIN screen and resurrect the identity the user just deliberately discarded.
  async function signOutNewDevice(): Promise<void> {
    joiningNewDevice = false;
    pendingWizardEnroll = null;
    clearResume();
    if (currentUsername !== '') {
      await controller.discardAccount?.(currentUsername);
    }
    currentUsername = '';
    disarmReconnect();
    go({ kind: 'unlock', mode: 'login' });
  }

  // Crypto-erase this account's local data and reload to a clean boot. Destroying the MSK wrap
  // (discardAccount) renders every sealed store on this device permanently unreadable; the reload then
  // clears all in-memory state (the worker and its wasm), so no key bytes linger. Used by Self Destruct
  // (after the server account is deleted) and by revoking the device you are on. `bootMode` is the screen
  // to show after the reload: register after a self destruct (the account is gone), login after a
  // self-revoke (the account lives on your other devices).
  async function wipeLocalAndReload(bootMode: 'login' | 'register', notice?: string): Promise<void> {
    // The reload (which clears the worker + wasm in-memory key material) MUST happen even if the crypto-erase
    // rejects, so the finally block always runs it. A failed discardAccount leaves the sealed vault on disk,
    // but for a revoked device the next unlock re-runs the lockout check and retries the erase.
    try {
      if (currentUsername !== '') {
        await controller.discardAccount?.(currentUsername);
      }
    } finally {
      account?.clearSession?.();
      clearResume();
      pendingWizardEnroll = null;
      setBootMode(bootMode);
      if (notice !== undefined) {
        setBootNotice(notice);
      }
      currentUsername = '';
      currentDeviceKey = '';
      location.reload();
    }
  }

  // Self Destruct: verify the passphrase (typed twice), delete the entire account from the server, then
  // crypto-erase this device and reload. Irreversible.
  async function doSelfDestruct(pass1: string, pass2: string): Promise<void> {
    if (account === undefined) {
      go({ kind: 'selfdestruct', error: 'self destruct needs the account server' });
      return;
    }
    if (pass1.length === 0 || pass2.length === 0) {
      go({ kind: 'selfdestruct', error: 'enter your passphrase in both fields' });
      return;
    }
    if (pass1 !== pass2) {
      go({ kind: 'selfdestruct', error: 'the two passphrases do not match' });
      return;
    }
    const ok = (await controller.verifyPassphrase?.(currentUsername, pass1)) ?? false;
    if (!ok) {
      go({ kind: 'selfdestruct', error: 'wrong passphrase' });
      return;
    }
    const result = await account.deleteAccount();
    if (!result.ok) {
      go({ kind: 'selfdestruct', error: result.error ?? 'could not delete the account' });
      return;
    }
    await wipeLocalAndReload('register');
  }

  // Enroll this device (best-effort, idempotent), then report the active-device note when the account
  // has more than one active device, so a user knows only this device receives while signed in here.
  // Verify this device against the account server before trusting the local vault, returning a tri-state:
  //  - 'clear'   the server confirms this device is enrolled and NOT revoked (proceed).
  //  - 'revoked' the server burned this device's key (caller must crypto-erase + lock out).
  //  - 'unknown' we could not confirm either way (enroll or list failed, a 5xx, or no local device key).
  // 'unknown' FAILS CLOSED: /api/login already reached the account server, so a device that cannot prove it
  // is still authorized is refused rather than waved through on local-only auth state. Without this a seized
  // revoked device could bypass the lock simply by blocking the add-device / list-devices calls.
  async function enrollAndNotice(
    authSecret: string,
  ): Promise<{ status: 'clear'; notice?: string } | { status: 'revoked' } | { status: 'unknown' }> {
    if (account === undefined) {
      return { status: 'clear' }; // no account server configured: local-only, nothing to verify against
    }
    if (currentDeviceKey === '') {
      return { status: 'unknown' }; // cannot identify this device to the server, so cannot verify it
    }
    const enroll = await account.enrollDeviceWithSecret(authSecret, currentDeviceKey);
    if (!enroll.ok) {
      return enroll.revoked === true ? { status: 'revoked' } : { status: 'unknown' }; // 409-revoked vs any other failure
    }
    const list = await account.listDevices();
    if (!list.ok || list.devices === undefined) {
      return { status: 'unknown' }; // could not read the directory: fail closed
    }
    const own = list.devices.find((d) => d.deviceKey === currentDeviceKey);
    if (own === undefined) {
      return { status: 'unknown' }; // our own row is not visible: cannot confirm this device is clear
    }
    if (own.revoked) {
      return { status: 'revoked' };
    }
    // Count only AUTHORIZED devices so an unauthorized orphan does not inflate the "you have N devices"
    // notice. Fallback to the legacy active count against a pre-F2 server (no `authorized` field).
    const active = list.devices.filter((d) => !d.revoked).length;
    const authorizedKnown = list.devices.some((d) => d.authorized);
    const authorizedActive = authorizedKnown
      ? list.devices.filter((d) => !d.revoked && d.authorized).length
      : active;
    if (authorizedActive > 1) {
      return {
        status: 'clear',
        notice: `You have ${authorizedActive} devices on this account. Every device you are signed in on receives your messages. Manage devices in Device keys.`,
      };
    }
    return { status: 'clear' };
  }

  // Enroll a newly-authorized wizard device ONCE (the enroll-after-authorize reorder deferred enrollment
  // from login to this point) using the stashed login secret, run the SAME fail-closed tri-state, then
  // publish its key packages. Enroll MUST precede publish: /api/publish-keys 409s device_not_enrolled on a
  // session that has not run add-device. Fires from the single provisioning-authorized event (both the
  // six-word and QR-adopt paths), after the durable authorized-marker reseal.
  async function finishWizardEnrollment(): Promise<void> {
    if (pendingWizardEnroll !== null && pendingWizardEnroll.user === currentUsername) {
      const enroll = await enrollAndNotice(pendingWizardEnroll.authSecret).catch(() => ({ status: 'unknown' as const }));
      if (enroll.status === 'revoked') {
        await wipeLocalAndReload(
          'login',
          'This device was revoked. Sign in on one of your active devices, or add this device again to keep using it here.',
        );
        return;
      }
      if (enroll.status === 'unknown') {
        go({ kind: 'provisioning', state: { role: 'newdevice', step: 'error', error: ENROLL_RETRY_COPY } });
        return; // keep the stash so the retry re-uses it
      }
      pendingWizardEnroll = null; // 'clear'
    } else {
      pendingWizardEnroll = null; // a stale or mismatched stash: fall through and just publish
    }
    const published = await publishOwnKeys();
    if (!published) {
      go({ kind: 'provisioning', state: { role: 'newdevice', step: 'error', error: ENROLL_RETRY_COPY } });
      return;
    }
    // The seed-holder starts healing this device into every conversation right about now; suppress
    // established-driven auto-open through that backfill so a late heal Welcome cannot steal navigation.
    suppressAutoOpenUntil = Date.now() + POST_JOIN_QUIET_MS;
    go({ kind: 'provisioning', state: { role: 'newdevice', step: 'done' } });
  }

  // Load the device list and show the Settings screen (or a retryable error).
  // The fields renderSettings actually paints. A background refresh whose projection is unchanged is
  // skipped entirely: a revoke's removal cascade fires roster-changed once per conversation over several
  // seconds, and each full-DOM Settings rebuild EATS any tap in flight (the finger lands on a torn-down
  // node), which read as "Back needs several taps". Only the FIRST refresh (revoked row disappears)
  // changes the projection; the rest are visual no-ops and must not rebuild the DOM.
  function settingsProjection(devices: readonly DeviceInfo[]): string {
    return JSON.stringify(devices.map((d) => [d.deviceId, d.deviceKey, d.revoked, d.current, d.authorized]));
  }

  async function openSettings(error?: string, background = false): Promise<void> {
    if (account === undefined) {
      return;
    }
    if (!background) {
      suppressSettingsRefresh = false; // a deliberate open of Settings re-enables live refresh
    } else if (suppressSettingsRefresh) {
      return; // the user left Settings; a background roster-changed must not reopen it
    }
    const res = await account.listDevices();
    if (suppressSettingsRefresh && (background || error !== undefined)) {
      // Back fired while this refresh was loading: do not clobber the destination. Only the failed-revoke
      // branch passes an error into a foreground open, and its failure still surfaces, as a toast on the
      // screen the user chose (matching the branch's own already-suppressed path).
      if (error !== undefined) {
        showToast(error);
      }
      return;
    }
    if (res.ok && res.devices !== undefined) {
      if (background && error === undefined && view.kind === 'settings' && settingsProjection(view.devices) === settingsProjection(res.devices)) {
        return; // nothing the screen shows changed: skip the rebuild so it cannot eat an in-flight tap
      }
      const historyOff = (await controller.historyOffEnabled?.()) ?? false;
      go(
        error !== undefined
          ? { kind: 'settings', devices: res.devices, currentDeviceKey, historyOff, error }
          : { kind: 'settings', devices: res.devices, currentDeviceKey, historyOff },
      );
    } else {
      if (background) {
        // A transient device-list failure during a BACKGROUND refresh must not tear the screen down into
        // the "no devices to show" error view (which bypasses the projection skip and eats an in-flight
        // Back tap). The list simply stays as it was; the next refresh or a deliberate open retries.
        return;
      }
      go({ kind: 'settings', devices: [], currentDeviceKey, error: res.error ?? 'could not load your devices' });
    }
  }

  // ── Appearance preferences (AIM19) ─────────────────────────────────────────────────────────────
  // Open the two-pane Appearance window. Edits live in the view's DRAFT (seeded from the saved look) and
  // show only in the preview box; nothing touches the app or the store until Save.
  function openAppearance(category = 'buddylist', draft?: Appearance, error?: string, packText?: string): void {
    const d = draft ?? appearance;
    go({
      kind: 'appearance',
      draft: d,
      category,
      ...(error !== undefined ? { error } : {}),
      ...(packText !== undefined ? { packText } : {}),
    });
  }
  // Save: the draft becomes the live look (the next render reskins the whole app), persists device-locally,
  // and the preferences window closes back to the buddy list, AIM-style.
  function saveAppearance(draft: Appearance): void {
    appearance = draft;
    void controller.setAppearance?.(draft);
    void openBuddies();
  }
  // A draft edit: set (or clear, when value is '') one allowlisted token and re-render the dialog.
  function draftAppearanceToken(draft: Appearance, token: string, value: string, category: string): void {
    const tokens = { ...draft.tokens };
    if (value === '') {
      delete tokens[token];
    } else if (isValidTokenValue(token, value)) {
      tokens[token] = value;
    } else {
      return;
    }
    // Carry the message-look draft (independent of the CSS tokens) through the re-render.
    openAppearance(category, { theme: draft.theme, tokens, ...(draft.messageLook !== undefined ? { messageLook: draft.messageLook } : {}) });
  }
  // A "My Message Look" edit (AIM24): set (or clear, when value is '') one MessageLook field, keeping the
  // theme + tokens, then re-render the dialog. Only validated palette keys are accepted.
  function draftMessageLook(draft: Appearance, field: string, value: string, category: string): void {
    const look: { font?: string; color?: string; size?: 's' | 'l'; hl?: string } = { ...(draft.messageLook ?? {}) };
    if (field === 'font') {
      if (value === '') delete look.font;
      else if (FONT_KEYS.has(value)) look.font = value;
      else return;
    } else if (field === 'color') {
      if (value === '') delete look.color;
      else if (TEXT_KEYS.has(value)) look.color = value;
      else return;
    } else if (field === 'size') {
      if (value === '') delete look.size;
      else if (value === 's' || value === 'l') look.size = value;
      else return;
    } else if (field === 'hl') {
      if (value === '') delete look.hl;
      else if (HL_KEYS.has(value)) look.hl = value;
      else return;
    } else {
      return;
    }
    const messageLook = Object.keys(look).length > 0 ? look : undefined;
    openAppearance(category, { theme: draft.theme, tokens: draft.tokens, ...(messageLook !== undefined ? { messageLook } : {}) });
  }
  function importAppearancePack(json: string, draft: Appearance, category: string): void {
    let parsed: unknown;
    try {
      parsed = JSON.parse(json);
    } catch {
      // Keep the draft AND the typed JSON (the re-render would otherwise erase what the user is fixing).
      openAppearance(category, draft, 'that is not valid JSON', json);
      return;
    }
    openAppearance(category, sanitizeAppearance(parsed)); // into the DRAFT; Save applies it
  }

  // Load this device's sealed identity card and show the Identity screen.
  async function openIdentity(): Promise<void> {
    const profile = (await controller.getIdentity?.()) ?? DEFAULT_IDENTITY;
    const fingerprint = (await controller.accountFingerprint?.()) ?? '';
    profileContactLink = buildContactLink(currentUsername, fingerprint);
    go({ kind: 'identity', profile });
  }

  // Each buddy's shared status (only when a real account backend is present; otherwise everyone reads offline).
  async function loadBuddyStatuses(buddies: readonly Buddy[]): Promise<Record<string, string>> {
    const statuses: Record<string, string> = {};
    if (account !== undefined) {
      await Promise.all(
        buddies.map(async (b) => {
          statuses[b.username] = await account.getPresence(b.username);
        }),
      );
    }
    return statuses;
  }

  // The buddies selected in the read-only tree for the bottom toolbar's actions (per-session, not stored).
  const buddyListSel = new Set<string>();

  // Load the buddy list, its group folders, per-buddy status, the blocked drop, and the away on/off state,
  // then show the read-only Buddy List tree. Editing lives in Buddy List Setup.
  async function openBuddies(error?: string): Promise<void> {
    // Leaving to the buddy list: suppress a concurrent background settings refresh SYNCHRONOUSLY (before
    // the awaits below), so the revoke removal-heal cascade cannot repaint Settings and make this loader
    // self-abort on its late navGen check, stranding the user on Settings.
    suppressSettingsRefresh = true;
    // Snapshot the navigation before the awaits; if a newer navigation happens meanwhile (e.g. a
    // double-click opened a conversation), do not clobber it when this loader finally resolves.
    const gen = navGen;
    // PIPELINED, not sequential: each await used to gate the next postMessage, so opening the buddy list
    // cost the SUM of seven worker round-trips (and on the revoke path each waited behind the cascade
    // backlog in turn). Fire the independent reads together; the worker still executes them FIFO, but the
    // round-trips overlap and the list paints in roughly one queue-drain instead of seven.
    const [buddies, groups, blocked, profile] = await Promise.all([
      controller.listBuddies?.() ?? Promise.resolve([]),
      controller.listGroups?.() ?? Promise.resolve([]),
      controller.listBlocked?.() ?? Promise.resolve([]),
      controller.getIdentity?.() ?? Promise.resolve(DEFAULT_IDENTITY),
    ]);
    // These three depend on the buddy usernames, so they form the second (also parallel) wave. The cached
    // E2E buddy icons + away messages each come in ONE worker call; buddies with none get a placeholder /
    // no subtitle. Away text is shown as the dim subtitle only while the buddy's presence is away.
    const [statuses, icons, awayText, verify] = await Promise.all([
      loadBuddyStatuses(buddies),
      controller.buddyIcons?.(buddies.map((b) => b.username)) ?? Promise.resolve<Record<string, BuddyIcon>>({}),
      controller.buddyAwayText?.(buddies.map((b) => b.username)) ?? Promise.resolve<Record<string, string>>({}),
      controller.buddyVerifyStates?.(buddies.map((b) => b.username)) ?? Promise.resolve<Record<string, BuddyVerifyBadge>>({}),
    ]);
    // A buddy entry that is YOU is authenticated to yourself by definition: you are signed in right
    // here. Show your live status (the same online/away the header ◆ shows) and your own buddy icon
    // from your identity card, with no server presence opt-in and no peer icon exchange (there is no
    // peer). Without this, adding yourself read as a gray offline stranger with a ghost icon.
    for (const b of buddies) {
      if (normalizeUsername(b.username) === normalizeUsername(currentUsername)) {
        statuses[b.username] = profile.away.enabled ? 'away' : 'online';
        if (profile.icon !== null) {
          icons[b.username] = profile.icon;
        }
        // Your OWN row shows your own away message as the subtitle while you are away (no peer cache needed).
        if (profile.away.enabled && profile.away.message.length > 0) {
          awayText[b.username] = profile.away.message;
        }
      }
    }
    if (gen !== navGen) {
      return; // a newer navigation superseded this load
    }
    // Drop any selected names that are no longer present buddies, so the toolbar reflects reality.
    const present = new Set(buddies.map((b) => b.username));
    for (const u of [...buddyListSel]) {
      if (!present.has(u)) {
        buddyListSel.delete(u);
      }
    }
    // Consume any pending sign-on/off flashes: they play on THIS render, then are cleared so a later
    // navigation re-render does not replay them.
    const signals = buddyFx;
    buddyFx = {};
    go({
      kind: 'buddies',
      buddies,
      groups,
      statuses,
      collapsed: loadCollapsedGroups(),
      blocked,
      selected: [...buddyListSel],
      profile,
      ownName: currentUsername,
      icons,
      awayText,
      ...(Object.keys(verify).length > 0 ? { verify } : {}),
      ...(error !== undefined ? { error } : {}),
      ...(Object.keys(signals).length > 0 ? { signals } : {}),
    });
  }

  // The current Buddy List Setup selection (the row Delete acts on). A per-session UI cursor, not stored.
  let buddySetupSel: BuddySetupSelection | null = null;

  // Load the buddy list, groups, statuses, blocked contacts, and the presence/notify toggles, then show
  // the Buddy List Setup management screen.
  async function openBuddySetup(error?: string): Promise<void> {
    const buddies = (await controller.listBuddies?.()) ?? [];
    const groups = (await controller.listGroups?.()) ?? [];
    const blocked = (await controller.listBlocked?.()) ?? [];
    const presenceOn = (await controller.getPresenceEnabled?.()) ?? false;
    const notifyOn = (await controller.getNotifyEnabled?.()) ?? true;
    const statuses = await loadBuddyStatuses(buddies);
    // Same self rule as the main buddy list: your own entry always shows your live status.
    const ownProfile = (await controller.getIdentity?.()) ?? DEFAULT_IDENTITY;
    for (const b of buddies) {
      if (normalizeUsername(b.username) === normalizeUsername(currentUsername)) {
        statuses[b.username] = ownProfile.away.enabled ? 'away' : 'online';
      }
    }
    // The loaded lists seed BOTH the draft and the snapshot Save diffs against.
    go({
      kind: 'buddysetup',
      buddies,
      groups,
      statuses,
      blocked,
      orig: { buddies, groups, blocked },
      presenceOn,
      notifyOn,
      selected: buddySetupSel,
      ...(error !== undefined ? { error } : {}),
    });
  }

  // Which buddies are selected and present, in list order (for the toolbar's single/multi actions).
  function selectedBuddies(): string[] {
    if (view.kind !== 'buddies') {
      return [];
    }
    return view.buddies.map((b) => b.username).filter((u) => buddyListSel.has(u));
  }

  // Wire the read-only Buddy List tree: click a name to SELECT it (double-click opens a chat), collapse a
  // folder, and the bottom toolbar (Send IM / Group Chat / Buddy Info / Away / Setup).
  function wireBuddies(): void {
    if (view.kind !== 'buddies') {
      return;
    }
    root.querySelectorAll('[data-buddy-select]').forEach((el) => {
      if (!(el instanceof HTMLElement) || el.dataset.buddySelect === undefined) {
        return;
      }
      const username = el.dataset.buddySelect;
      // Single click toggles selection (highlighted); double click is a shortcut to open a 1:1 chat. Skip
      // the second click of a double-click (e.detail > 1) so it does not fight the dblclick's navigation.
      el.addEventListener('click', (e) => {
        if (e instanceof MouseEvent && e.detail > 1) {
          return;
        }
        if (buddyListSel.has(username)) {
          buddyListSel.delete(username);
        } else {
          buddyListSel.add(username);
        }
        void openBuddies();
      });
      el.addEventListener('dblclick', () => {
        buddyListSel.clear();
        void beginConversationWith(username, (msg) => {
          void openBuddies(msg);
        });
      });
    });
    // Collapse / expand a group folder (a per-tab UI preference, then re-render the tree).
    root.querySelectorAll('[data-buddy-toggle]').forEach((el) => {
      el.addEventListener('click', () => {
        if (el instanceof HTMLElement && el.dataset.buddyToggle !== undefined) {
          toggleCollapsedGroup(el.dataset.buddyToggle);
          void openBuddies();
        }
      });
    });
    // The header's status control (the little ◆): a dropdown that sets you Online or puts up your Away
    // message, saving through the SAME path as the Away Message editor (setIdentity + the server-side
    // opt-in push) so presence, sibling sync, and the server away all behave identically.
    const statusMenuEl = root.querySelector('#dd-status-menu');
    root.querySelector('[data-action="status-menu"]')?.addEventListener('click', (e) => {
      if (statusMenuEl instanceof HTMLElement) {
        e.stopPropagation(); // so the document outside-click handler does not immediately re-close it
        statusMenuEl.hidden = !statusMenuEl.hidden;
      }
    });
    root.querySelector('[data-action="status-online"]')?.addEventListener('click', () => {
      void (async () => {
        const current = (await controller.getIdentity?.()) ?? DEFAULT_IDENTITY;
        const profile = { ...current, away: { ...current.away, enabled: false } };
        await (controller.setIdentity?.(profile) ?? Promise.resolve());
        await applyServerAway(profile);
        await openBuddies(); // re-render: the ◆ tint, the check mark, and the bubble all follow
      })();
    });
    // A saved library message: put it up as the away message in one click (enabled + that text), saving
    // through the same path as the editor so siblings and the server-side opt-in all follow.
    root.querySelectorAll('[data-action="status-saved"]').forEach((el) => {
      el.addEventListener('click', () => {
        const idx = el instanceof HTMLElement ? Number(el.dataset.savedIdx) : NaN;
        void (async () => {
          const current = (await controller.getIdentity?.()) ?? DEFAULT_IDENTITY;
          const msg = (current.away.saved ?? [])[idx];
          if (msg === undefined) {
            return;
          }
          const profile = { ...current, away: { ...current.away, enabled: true, message: msg } };
          await (controller.setIdentity?.(profile) ?? Promise.resolve());
          await applyServerAway(profile);
          await openBuddies();
        })();
      });
    });
    // New Away Message: open the editor to write one; SAVING it puts it up (AIM semantics: writing an
    // away message is going away). This is the editor's only entry point.
    root.querySelector('[data-action="status-edit-away"]')?.addEventListener('click', () => {
      void openAway();
    });
    // Row 1 — actions on the selection.
    root.querySelector('[data-action="tbar-send-im"]')?.addEventListener('click', () => {
      const sel = selectedBuddies();
      if (sel.length !== 1) {
        return;
      }
      buddyListSel.clear();
      void beginConversationWith(sel[0]!, (msg) => {
        void openBuddies(msg);
      });
    });
    root.querySelector('[data-action="tbar-group-chat"]')?.addEventListener('click', () => {
      const sel = selectedBuddies();
      if (sel.length === 0) {
        return;
      }
      buddyListSel.clear();
      void beginGroupConversationWith(sel, (msg) => {
        void openBuddies(msg);
      });
    });
    root.querySelector('[data-action="tbar-channels"]')?.addEventListener('click', () => {
      // Open the two-pane Channels screen (same as the menu-bar Channels item); no selection needed.
      void controller.listChannels().then((channels) => go({ kind: 'channels', channels }));
    });
    root.querySelector('[data-action="tbar-info"]')?.addEventListener('click', () => {
      const sel = selectedBuddies();
      if (sel.length !== 1) {
        return;
      }
      void openBuddyInfo(sel[0]!);
    });
    // Row 2 — shortcuts to the Profile editor and Buddy List Setup (the away message lives in the ◆).
    root.querySelector('[data-action="tbar-profile"]')?.addEventListener('click', () => {
      void openIdentity();
    });
    root.querySelector('[data-action="tbar-setup"]')?.addEventListener('click', () => {
      buddySetupSel = null;
      void openBuddySetup();
    });
  }

  // Wire Buddy List Setup: the toggles, row selection, group move, add buddy/group, and Delete.
  function wireBuddySetup(): void {
    if (view.kind !== 'buddysetup') {
      return;
    }
    // Every list edit below changes only the view's DRAFT; Save diffs the draft against the snapshot and
    // applies the difference, Cancel throws the draft away. Both land back on the buddy list.
    const patch = (p: { buddies?: readonly Buddy[]; groups?: readonly GroupSummary[]; blocked?: readonly BlockedContact[]; presenceOn?: boolean; notifyOn?: boolean; selected?: BuddySetupSelection | null; error?: string }): void => {
      if (view.kind === 'buddysetup') {
        // A stale error never outlives the action that raised it: every patch drops the previous error
        // unless this one sets its own.
        const { error: _stale, ...rest } = view;
        go({ ...rest, ...p });
      }
    };
    // The two device toggles are settings, not buddy-list edits: they apply immediately (presence has
    // live server side effects) and only the view flag is refreshed, so the draft survives.
    root.querySelector('#dd-presence-toggle')?.addEventListener('change', (e) => {
      const on = e.target instanceof HTMLInputElement ? e.target.checked : false;
      void (controller.setPresenceEnabled?.(on) ?? Promise.resolve()).then(() => {
        if (on) {
          startPresenceBeat();
        } else {
          stopPresenceBeat();
        }
        patch({ presenceOn: on });
      });
    });
    root.querySelector('#dd-notify-toggle')?.addEventListener('change', (e) => {
      const on = e.target instanceof HTMLInputElement ? e.target.checked : true;
      notifyEnabled = on;
      void (controller.setNotifyEnabled?.(on) ?? Promise.resolve()).then(() => {
        if (on) {
          requestNotifyPermission();
          startBuddyWatch();
        }
        patch({ notifyOn: on });
      });
    });
    // Select a group, buddy, or blocked row (the target Delete acts on). The value is "type:id"; split on
    // the first ':' only so a group name that itself contains ':' still round-trips.
    root.querySelectorAll('[data-setup-sel]').forEach((el) => {
      el.addEventListener('click', () => {
        if (!(el instanceof HTMLElement) || el.dataset.setupSel === undefined) {
          return;
        }
        const raw = el.dataset.setupSel;
        const idx = raw.indexOf(':');
        if (idx < 0) {
          return;
        }
        const type = raw.slice(0, idx);
        if (type !== 'group' && type !== 'buddy' && type !== 'blocked' && type !== 'gblocked') {
          return;
        }
        buddySetupSel = { type, id: raw.slice(idx + 1) };
        patch({ selected: buddySetupSel });
      });
    });
    // Move a buddy to a different group (draft only; Save publishes the move).
    root.querySelectorAll('[data-buddy-group]').forEach((el) => {
      el.addEventListener('change', (e) => {
        if (el instanceof HTMLElement && el.dataset.buddyGroup !== undefined && e.target instanceof HTMLSelectElement && view.kind === 'buddysetup') {
          const u = el.dataset.buddyGroup;
          const g = e.target.value;
          patch({ buddies: view.buddies.map((b) => (b.username === u ? { ...b, group: g } : b)) });
        }
      });
    });
    root.querySelector('[data-action="setup-add-buddy"]')?.addEventListener('click', () => {
      const el = root.querySelector('#dd-setup-buddy-input');
      const name = el instanceof HTMLInputElement ? normalizeUsername(el.value) : '';
      if (name.length === 0 || view.kind !== 'buddysetup' || view.buddies.some((b) => b.username === name)) {
        return;
      }
      const group = buddySetupSel !== null && buddySetupSel.type === 'group' ? buddySetupSel.id : DEFAULT_BUDDY_GROUP;
      patch({ buddies: [...view.buddies, { username: name, addedAt: 0, group }] });
    });
    root.querySelector('[data-action="setup-add-group"]')?.addEventListener('click', () => {
      const el = root.querySelector('#dd-setup-group-input');
      const name = el instanceof HTMLInputElement ? el.value.trim() : '';
      // The dup check includes the built-ins' current labels (view.groups carries them), so a new group
      // can never answer to the same name as the default group or the Blocked drop.
      if (name.length === 0 || name === DEFAULT_BUDDY_GROUP || view.kind !== 'buddysetup' || view.groups.some((g) => g.name === name)) {
        return;
      }
      patch({ groups: [...view.groups, { name }] });
    });
    // Rename the selected group (draft only; Save publishes). A built-in renames by its role, so it keeps
    // working under the new name; a user-made group renames by moving its members along with it.
    root.querySelector('[data-action="setup-rename"]')?.addEventListener('click', () => {
      const el = root.querySelector('#dd-setup-rename-input');
      const name = el instanceof HTMLInputElement ? el.value.trim() : '';
      const sel = buddySetupSel;
      if (name.length === 0 || view.kind !== 'buddysetup' || sel === null) {
        return;
      }
      if (sel.type !== 'group' && sel.type !== 'gblocked') {
        return;
      }
      // 'Buddies' (the internal default key) is reserved for exactly one target: the default group
      // itself, which may always be renamed BACK to it.
      const isDefault = sel.type === 'group' && sel.id === DEFAULT_BUDDY_GROUP;
      if (name === DEFAULT_BUDDY_GROUP && !isDefault) {
        patch({ error: 'that name belongs to the built-in default group' });
        return;
      }
      if (view.groups.some((g) => g.name === name && !(isDefault && g.role === 'default'))) {
        patch({ error: 'a group already goes by that name' });
        return;
      }
      if (sel.type === 'gblocked') {
        patch({ groups: view.groups.map((g) => (g.role === 'blocked' ? { ...g, name } : g)) });
        return;
      }
      if (sel.id === DEFAULT_BUDDY_GROUP) {
        patch({ groups: view.groups.map((g) => (g.role === 'default' ? { ...g, name } : g)) });
        return;
      }
      buddySetupSel = { type: 'group', id: name };
      patch({
        groups: view.groups.map((g) => (g.role === undefined && g.name === sel.id ? { name } : g)),
        buddies: view.buddies.map((b) => (b.group === sel.id ? { ...b, group: name } : b)),
        selected: buddySetupSel,
      });
    });
    root.querySelector('[data-action="setup-delete"]')?.addEventListener('click', () => {
      const sel = buddySetupSel;
      if (sel === null || view.kind !== 'buddysetup') {
        return;
      }
      // The built-ins never delete: the Blocked drop by its own selection type, the default group by key.
      if (sel.type === 'gblocked' || (sel.type === 'group' && sel.id === DEFAULT_BUDDY_GROUP)) {
        return;
      }
      buddySetupSel = null;
      if (sel.type === 'buddy') {
        patch({ buddies: view.buddies.filter((b) => b.username !== sel.id), selected: null });
      } else if (sel.type === 'group') {
        // Deleting a group moves its buddies back to the default group (same as the stored semantics).
        patch({
          groups: view.groups.filter((g) => g.name !== sel.id),
          buddies: view.buddies.map((b) => (b.group === sel.id ? { ...b, group: DEFAULT_BUDDY_GROUP } : b)),
          selected: null,
        });
      } else {
        patch({ blocked: view.blocked.filter((b) => b.key !== sel.id), selected: null });
      }
    });
    // Save: apply the draft as the minimal set of store operations. Group adds go first so a buddy filed
    // under a new group lands in it; group deletes go LAST so the store's "move members back to Buddies"
    // cannot undo a move the draft made. Then back to the buddy list, which re-reads the stored truth.
    root.querySelector('[data-action="setup-save"]')?.addEventListener('click', () => {
      if (view.kind !== 'buddysetup') {
        return;
      }
      const d = view;
      void (async () => {
        for (const g of d.groups) {
          if (g.role === undefined && !d.orig.groups.some((x) => x.role === undefined && x.name === g.name)) {
            await controller.addGroup?.(g.name);
          }
        }
        for (const b of d.buddies) {
          const o = d.orig.buddies.find((x) => x.username === b.username);
          if (o === undefined) {
            await controller.addBuddy?.(b.username, b.group);
          } else if (o.group !== b.group) {
            await controller.setBuddyGroup?.(b.username, b.group);
          }
        }
        for (const o of d.orig.buddies) {
          if (!d.buddies.some((x) => x.username === o.username)) {
            await controller.removeBuddy?.(o.username);
          }
        }
        for (const g of d.orig.groups) {
          if (g.role === undefined && !d.groups.some((x) => x.role === undefined && x.name === g.name)) {
            await controller.deleteGroup?.(g.name);
          }
        }
        // Built-in renames LAST: a role entry whose display name changed renames by role (label only).
        // Running after the custom-group deletes means a rename to the name of a group you deleted in the
        // same draft no longer collides (the store already freed that name); role entries are labels, not
        // groups, so they never appear in the add/delete diffs above.
        for (const role of ['default', 'blocked'] as const) {
          const now = d.groups.find((g) => g.role === role);
          const was = d.orig.groups.find((g) => g.role === role);
          if (now !== undefined && was !== undefined && now.name !== was.name) {
            await controller.renameGroup?.(role, now.name);
          }
        }
        for (const bl of d.orig.blocked) {
          if (!d.blocked.some((x) => x.key === bl.key)) {
            await controller.unblock?.(bl.key);
          }
        }
        buddySetupSel = null;
        await openBuddies();
      })().catch(() => openBuddySetup('could not save all changes'));
    });
    // Cancel: forget the draft entirely and return to the buddy list.
    root.querySelector('[data-action="setup-cancel"]')?.addEventListener('click', () => {
      buddySetupSel = null;
      void openBuddies();
    });
    root.querySelector('[data-action="buddy-scan"]')?.addEventListener('click', () => {
      void startBuddyScan();
    });
    root.querySelector('[data-action="buddy-showme"]')?.addEventListener('click', () => {
      void showMyContactQr();
    });
  }

  // Load the cached buddy info for the open conversation's peers and show the Get-Info panel.
  async function openGetInfo(): Promise<void> {
    const ac = activeConv(view);
    if (ac === null) {
      return;
    }
    const id = ac.id;
    const fromChannels = view.kind === 'channels';
    // Substitute the AIM-style tokens in each peer's profile at view time: %n = you (the viewer, so a
    // profile can greet you), %d/%t = now. The stored profile keeps the tokens literal.
    const at = Date.now();
    const peers = ((await controller.getPeerIdentities?.(id)) ?? []).map((p) => ({
      ...p,
      bio: substituteSpecials(p.bio, { name: currentUsername, at }),
    }));
    go({ kind: 'getinfo', conversationId: id, peer: ac.transmit.peer ?? 'CONTACT', peers, ...(fromChannels ? { fromChannels: true } : {}) });
  }

  // Wire the Identity editor: each icon/color/initials/image/toggle pick captures the current text
  // fields (readIdentityDraft) before re-rendering, so typed bio/away text survives the re-render.
  function wireIdentity(): void {
    if (view.kind !== 'identity') {
      return;
    }
    const cur = view.profile.icon;
    const selBg = cur !== null && cur.kind !== 'image' ? cur.bg : (ICON_COLORS[0] ?? '#2a52d6');
    const draft = (iconOverride?: BuddyIcon | null): IdentityProfile => readIdentityDraft(root, view, iconOverride);
    root.querySelectorAll('[data-emoji]').forEach((el) => {
      el.addEventListener('click', () => {
        if (!(el instanceof HTMLElement) || el.dataset.emoji === undefined) {
          return;
        }
        go({ kind: 'identity', profile: draft({ kind: 'emoji', value: el.dataset.emoji, bg: selBg }) });
      });
    });
    root.querySelector('[data-action="id-clear-image"]')?.addEventListener('click', () => {
      go({ kind: 'identity', profile: draft(null) });
    });
    root.querySelector('#dd-id-image')?.addEventListener('change', (e) => {
      const input = e.target;
      if (!(input instanceof HTMLInputElement) || input.files === null || input.files[0] === undefined) {
        return;
      }
      const file = input.files[0];
      if (!file.type.startsWith('image/')) {
        go({ kind: 'identity', profile: draft(), error: 'choose an image file (PNG, JPG, GIF, or WebP)' });
        return;
      }
      void downscaleImage(file).then((dataUrl) => {
        if (dataUrl !== null) {
          go({ kind: 'identity', profile: draft({ kind: 'image', value: dataUrl, bg: '' }) });
        } else {
          go({ kind: 'identity', profile: draft(), error: 'could not read that image; try a different file' });
        }
      });
    });
    root.querySelector('[data-action="id-save"]')?.addEventListener('click', () => {
      const profile = draft();
      // Save, then return to the buddy list (the profile editor is reached from its toolbar), where the
      // header shows the new icon.
      void (controller.setIdentity?.(profile) ?? Promise.resolve()).then(() => openBuddies());
    });
    root.querySelector('[data-action="id-cancel"]')?.addEventListener('click', () => {
      void openBuddies(); // discard edits and return to the buddy list
    });
    root.querySelector('[data-action="copy-contact-link"]')?.addEventListener('click', (e) => {
      const btn = e.currentTarget;
      if (profileContactLink.length === 0 || !navigator.clipboard) {
        return;
      }
      void navigator.clipboard.writeText(profileContactLink).then(() => {
        if (btn instanceof HTMLElement) {
          btn.textContent = 'Copied';
        }
      });
    });
  }

  // The away-message editor (reached from the DEAD DROP menu). It edits only the away part of the card,
  // and a save preserves the buddy icon and profile, then pushes the server-side away opt-in.
  function wireAway(): void {
    if (view.kind !== 'away') {
      return;
    }
    const current = view.profile;
    root.querySelector('[data-action="away-save"]')?.addEventListener('click', () => {
      const draft = readAwayDraft(root, current);
      // Every saved message also lands in the away LIBRARY (most recent first, deduped, capped) so the
      // buddy list's ◆ dropdown can put it up again in one click on any of your devices.
      const msg = draft.away.message.trim();
      const saved = msg.length > 0
        ? [draft.away.message, ...(current.away.saved ?? []).filter((m) => m !== draft.away.message)].slice(0, AWAY_SAVED_MAX)
        : (current.away.saved ?? []);
      // Saving a message PUTS IT UP: you are away with it the moment you save (AIM semantics; the ◆
      // dropdown's Online takes it down). Saving with an empty editor never marks you away.
      const profile = { ...draft, away: { ...draft.away, enabled: msg.length > 0, saved } };
      void (controller.setIdentity?.(profile) ?? Promise.resolve())
        .then(() => applyServerAway(profile)) // push (or clear) the server-side away opt-in
        .then(() => openBuddies()); // back to the buddy list, where the header shows the new state
    });
    root.querySelector('[data-action="away-cancel"]')?.addEventListener('click', () => {
      void openBuddies(); // the editor is reached from the buddy list, so Cancel returns there too
    });
    // Pick from the saved-message dropdown: "New away message" clears the editor, an existing entry loads
    // it in for editing. Either way we keep the other unsaved edits (the auto-reply toggle, server-reply).
    root.querySelector('#dd-away-pick')?.addEventListener('change', (e) => {
      const val = e.target instanceof HTMLSelectElement ? e.target.value : 'new';
      const d = readAwayDraft(root, current);
      const message = val === 'new' ? '' : ((current.away.saved ?? [])[Number(val)] ?? d.away.message);
      const profile = { ...d, away: { ...d.away, message } };
      go(val === 'new' ? { kind: 'away', profile } : { kind: 'away', profile, picked: Number(val) });
    });
    // Delete the away message currently chosen in the dropdown. This edits the DRAFT list shown here;
    // Save (or Cancel) decides whether it sticks, so a mis-click is undoable by hitting Cancel. The editor
    // is cleared too, so a Save right after does not re-add the message you just deleted.
    root.querySelector('[data-action="away-del-sel"]')?.addEventListener('click', () => {
      const pick = root.querySelector('#dd-away-pick');
      const val = pick instanceof HTMLSelectElement ? pick.value : 'new';
      if (val === 'new') {
        return; // nothing selected to delete
      }
      const idx = Number(val);
      const d = readAwayDraft(root, current);
      const saved = (d.away.saved ?? []).filter((_, i) => i !== idx);
      // Omit picked (defaults to the "New" option) now that the chosen message is gone.
      go({ kind: 'away', profile: { ...d, away: { ...d.away, message: '', saved } } });
    });
  }

  // Wire each formatting toolbar (away + profile) to its textarea: bold/italic/color wrap the selection,
  // emoji inserts at the caret. The markup is the same one messages use, so it renders on display.
  function wireTextToolbars(): void {
    wireRichEditors(root); // WYSIWYG rich-text editors (away, profile, message compose)
  }

  async function openAway(): Promise<void> {
    const profile = (await controller.getIdentity?.()) ?? DEFAULT_IDENTITY;
    go({ kind: 'away', profile });
  }

  // Open the private "Note to Self" chat: a real conversation over the hidden own-devices self-group, so
  // notes you jot sync to every device you are signed in on and survive a reload. It rides the gateway,
  // so it needs a live connection; offline we say so rather than opening an empty, un-sendable window.
  async function openNoteToSelf(): Promise<void> {
    if (connState === 'offline') {
      notify('Note to Self needs a connection', '', 440);
      return;
    }
    try {
      const transmit = await controller.openNoteToSelf();
      go({ kind: 'conversation', transmit });
    } catch (err: unknown) {
      const detail = err instanceof Error ? err.message : String(err);
      console.warn('note to self failed:', detail);
      // Show the REAL reason, not a generic string. This one line reads identically whether the device
      // is cert-only and still waiting for a Welcome, whether the vault could not be sealed, or whether
      // the self-group is poisoned — and the phone has no console, so a generic message ends the
      // diagnosis right here. The wasm reasons name a cause and no secrets.
      notify('Could not open Note to Self', detail, 440);
    }
  }

  // Create an account: unlock the local vault (minting the durable identity on connect), then register
  // that identity with the server. The server rejects a username already taken; on rejection we roll
  // back the local vault so retrying is clean and the device keeps no orphaned account.
  async function doRegister(user: string, pass: string, pass2: string): Promise<void> {
    if (pass !== pass2) {
      go({ kind: 'unlock', mode: 'register', error: 'the passphrases do not match' });
      return;
    }
    // ONE registration at a time. Without this, a second click fired a second concurrent run: one POST
    // got 201 and the other 409, and the 409 branch called discardAccount, which crypto-erased the vault
    // and account seed of the account that had just been created on the server. The user was left with a
    // live account whose keys existed nowhere. The proof of work makes a double click likelier, not less,
    // by putting a visible pause between the click and any feedback.
    if (registerInFlight) {
      return;
    }
    registerInFlight = true;
    try {
      await doRegisterInner(user, pass);
    } finally {
      registerInFlight = false;
    }
  }

  async function doRegisterInner(user: string, pass: string): Promise<void> {
    const res = await controller.unlock(user, pass);
    if (!res.ok) {
      go({ kind: 'unlock', mode: 'register', error: res.error ?? 'could not create the account' });
      return;
    }
    // The new vault exists. Ask the browser to keep this origin's storage from being evicted (same
    // best-effort, non-blocking request as sign-in); a fresh vault is exactly what most needs it.
    void requestPersistentStorage();
    // This is the seed-holder device: create the account recovery seed BEFORE connecting, so the
    // durable identity is minted as an AAK-rooted authorized signer (the root of device authorization).
    await controller.ensureAccountSeed?.();
    // Connecting mints and persists this device's durable identity; its key is the first device in
    // the account's directory.
    const { selfContact } = await connectLive();
    currentDeviceKey = selfContact !== null ? (selfContact.split(':')[3] ?? '') : '';
    if (account !== undefined) {
      if (currentDeviceKey === '') {
        await controller.discardAccount?.(user);
        go({ kind: 'unlock', mode: 'register', error: 'could not reach the account server' });
        return;
      }
      const reg = await account.register(user, pass, currentDeviceKey);
      if (!reg.ok) {
        await controller.discardAccount?.(user);
        go({ kind: 'unlock', mode: 'register', error: reg.error ?? 'could not create the account' });
        return;
      }
    }
    currentUsername = user.trim();
    await syncAndPublish();
    // Show the recovery secret ONCE before continuing, so the user can write it down.
    const secret = (await controller.recoverySecret?.()) ?? null;
    if (secret !== null) {
      go({ kind: 'recovery', secret });
      return;
    }
    // A scanned/opened contact link takes priority: land on a "message this user" start screen.
    if (await openPendingContact()) {
      return;
    }
    await openBuddies(); // home is the buddy list
  }

  // Start a group conversation from the key-exchange start screen: resolve the peer's devices from
  // the key-package directory, add our OWN other signed-in devices too, and open one MLS group that
  // every device joins (so all of them receive and can reply).
  async function startConversation(st: KeyExchangeState): Promise<void> {
    if (st.byUsername !== true || account === undefined) {
      go({ kind: 'keyexchange', state: { ...st, error: 'enter a username to start a conversation' } });
      return;
    }
    const peerEl = root.querySelector('#dd-peer-username');
    const username = peerEl instanceof HTMLInputElement ? peerEl.value.trim() : '';
    if (username.length === 0) {
      return;
    }
    await beginConversationWith(username, (msg) => go({ kind: 'keyexchange', state: { ...st, error: msg } }));
  }

  // Resolve a username to its devices (plus our own siblings), open one MLS group with all of them, and
  // show the conversation. Shared by the key-exchange start screen and a buddy-list click; a failure is
  // reported through onError so the caller can show it on whichever screen the request came from.
  async function beginConversationWith(username: string, onError: (msg: string) => void): Promise<void> {
    // Starting a conversation with your OWN username opens Note to Self (the own-devices self-group).
    // Checked FIRST: it needs no directory lookup, so it works even without the account server (a
    // local-only login). The peer path cannot message yourself anyway: it would try to add this very
    // device (already the group creator) as a peer, which MLS rejects ("could not open that channel").
    if (currentUsername.length > 0 && normalizeUsername(username) === normalizeUsername(currentUsername)) {
      await openNoteToSelf();
      return;
    }
    if (account === undefined || username.length === 0) {
      onError('enter a username to start a conversation');
      return;
    }
    const peer = await account.takeKeys(username);
    if (!peer.ok || peer.devices === undefined || peer.devices.length === 0) {
      onError(peer.error ?? 'no user by that name');
      return;
    }
    // Add our own other devices so every device we are signed in on joins the group. Our current device
    // is already the group creator, so it is excluded from the target list.
    const own = await account.takeKeys(currentUsername);
    const ownSiblings = (own.devices ?? []).filter((d) => d.deviceKey !== currentDeviceKey);
    // Defense in depth: our current device must never be a PEER target (MLS rejects adding the group
    // creator, which is what opened a dead window). Drop it from the peer set; if nothing else is left,
    // the username resolved to only our own device, so this is really Note to Self (e.g. a stale
    // currentUsername let a self-message slip past the check above). Route it there instead of building
    // an empty/self peer group.
    const peerTargets = peer.devices.filter((d) => d.deviceKey !== currentDeviceKey);
    if (peerTargets.length === 0) {
      await openNoteToSelf();
      return;
    }
    const targets: DeviceTarget[] = [...peerTargets, ...ownSiblings].map((d) => ({ deviceKey: d.deviceKey, keyPackage: d.keyPackage }));
    try {
      // If the peer has server-side away on and all their devices are offline, the server returns their
      // away text; show it so the sender sees it like AIM did. Null when they are online or away is off.
      const away = await account.lookupAway(username);
      const base = await controller.startConversation(targets);
      // Tag this conversation with the buddy's handle (device-local) so Buddy Info can find its cached
      // profile by username later. The tag never leaves this device and is not part of the E2E payload.
      if (base.conversationId !== null) {
        void controller.tagConversationHandle?.(base.conversationId, username);
      }
      const transmit = away !== null
        ? { ...base, log: [...base.log, { kind: 'system' as const, text: `» ${username} is away: ${away}` }] }
        : base;
      go({ kind: 'conversation', transmit });
    } catch (err: unknown) {
      console.warn('start conversation failed:', err instanceof Error ? err.message : String(err));
      onError('could not open that channel');
    }
  }

  // Start ONE group conversation with several buddies at once. Resolves every selected username, fails
  // closed if ANY is unknown (so a bad name never opens a half-built group), dedupes devices by key, adds
  // our own siblings, and hands the union to the same startConversation primitive (one MLS group, one
  // Welcome to every device). No per-buddy away lookup (that is a 1:1 nicety).
  async function beginGroupConversationWith(usernames: readonly string[], onError: (msg: string) => void): Promise<void> {
    if (account === undefined || usernames.length === 0) {
      onError('pick at least one buddy');
      return;
    }
    // Your own username is never a PEER in a group: your devices join as siblings anyway. Drop it from
    // the peer set. If nothing else was picked, this is Note to Self, not a group of only your devices,
    // which would otherwise open a SECOND self-group and corrupt the buddy-list sync (is_self_conversation
    // would flag it too), so route it to the one hidden self-group instead.
    const peers = usernames.filter((u) => normalizeUsername(u) !== normalizeUsername(currentUsername));
    if (peers.length === 0) {
      await openNoteToSelf();
      return;
    }
    const acct = account;
    const peerLists = await Promise.all(peers.map((u) => acct.takeKeys(u)));
    for (let i = 0; i < peerLists.length; i++) {
      const p = peerLists[i];
      if (p === undefined || !p.ok || p.devices === undefined || p.devices.length === 0) {
        onError(p?.error ?? `no user by that name: ${peers[i]}`);
        return;
      }
    }
    const own = await acct.takeKeys(currentUsername);
    const ownSiblings = (own.devices ?? []).filter((d) => d.deviceKey !== currentDeviceKey);
    const seen = new Set<string>();
    const targets: DeviceTarget[] = [...peerLists.flatMap((p) => p.devices ?? []), ...ownSiblings]
      // Never re-add this very device: it is the group creator, and MLS rejects adding an existing member.
      .filter((d) => d.deviceKey !== currentDeviceKey)
      .filter((d) => (seen.has(d.deviceKey) ? false : (seen.add(d.deviceKey), true)))
      .map((d) => ({ deviceKey: d.deviceKey, keyPackage: d.keyPackage }));
    try {
      const base = await controller.startConversation(targets);
      if (base.conversationId !== null) {
        for (const u of peers) {
          void controller.tagConversationHandle?.(base.conversationId, u);
        }
      }
      go({ kind: 'conversation', transmit: base });
    } catch (err: unknown) {
      console.warn('start group conversation failed:', err instanceof Error ? err.message : String(err));
      onError('could not open that group');
    }
  }

  // Buddy Info: show what we honestly have about a buddy — their cached profile (icon + bio) IF we have a
  // conversation with them on this device, plus opt-in server presence and away text. Profiles are E2E and
  // only exist after a conversation delivers them, so with no conversation this shows the handle + status
  // and the standing "appears once you connect" note. Never claims a fingerprint we do not hold.
  async function openBuddyInfo(username: string): Promise<void> {
    const at = Date.now();
    // Buddy Info on YOURSELF: you are authenticated to yourself by definition (you are signed in on
    // this very device), so show your OWN identity card with your account fingerprint and your live
    // status. No peer lookup (there is no peer) and no server presence round-trip.
    if (normalizeUsername(username) === normalizeUsername(currentUsername)) {
      const profile = (await controller.getIdentity?.()) ?? DEFAULT_IDENTITY;
      const fingerprint = (await controller.accountFingerprint?.()) ?? '';
      const peers: PeerIdentity[] = [{
        key: '',
        fingerprint,
        icon: profile.icon,
        bio: substituteSpecials(profile.bio, { name: currentUsername, at }),
        away: profile.away.enabled ? profile.away.message : '',
      }];
      const selfAway = profile.away.enabled && profile.away.message.length > 0;
      go({
        kind: 'getinfo',
        conversationId: '',
        peer: username,
        peers,
        origin: 'buddies',
        presence: profile.away.enabled ? 'away' : 'online',
        self: true,
        ...(selfAway ? { away: profile.away.message } : {}),
      });
      return;
    }
    const raw = (await controller.getBuddyInfo?.(username)) ?? [];
    const peers = raw.map((p) => ({ ...p, bio: substituteSpecials(p.bio, { name: currentUsername, at }) }));
    let verify: BuddyVerifyInfo | undefined;
    try {
      verify = await controller.buddyVerifyInfo?.(username);
    } catch {
      verify = undefined; // no panel beats a wrong panel
    }
    let presence: string | undefined;
    let away: string | undefined;
    if (account !== undefined) {
      presence = await account.getPresence(username);
      const a = await account.lookupAway(username);
      if (a !== null) {
        away = a;
      }
    }
    go({ kind: 'getinfo', conversationId: '', peer: username, peers, origin: 'buddies', ...(verify !== undefined ? { verify } : {}), ...(presence !== undefined ? { presence } : {}), ...(away !== undefined ? { away } : {}) });
  }

  // Add another account to the open conversation: resolve all their devices and add each to the MLS
  // group, making it a multi-person chat. Earlier messages are not shared; only those sent from now on.
  async function addPersonToConversation(conversationId: string, username: string): Promise<void> {
    if (account === undefined) {
      go({ kind: 'addperson', conversationId, error: 'adding people needs the account server' });
      return;
    }
    if (username.length === 0) {
      go({ kind: 'addperson', conversationId, error: 'enter a username' });
      return;
    }
    const peer = await account.takeKeys(username);
    if (!peer.ok || peer.devices === undefined || peer.devices.length === 0) {
      go({ kind: 'addperson', conversationId, error: peer.error ?? 'no user by that name' });
      return;
    }
    try {
      for (const d of peer.devices) {
        await controller.addDevice?.(conversationId, { deviceKey: d.deviceKey, keyPackage: d.keyPackage });
      }
      const base = await controller.openChannel(conversationId);
      const transmit = { ...base, log: [...base.log, { kind: 'system' as const, text: `» added ${username} to the conversation` }] };
      go({ kind: 'conversation', transmit });
    } catch (err: unknown) {
      console.warn('add person failed:', err instanceof Error ? err.message : String(err));
      go({ kind: 'addperson', conversationId, error: 'could not add that person' });
    }
  }

  // An unsolicited conversation event (a peer's offer, an established Welcome) is about to navigate.
  // A TRANSIENT editor is not a primary window, so go() would drop it — and with it any unsaved draft
  // (Appearance picks, a half-written profile or away message). Stash it to the menu-bar tray first,
  // exactly like Minimize does: DOM-held drafts harvested, the Appearance draft already in its view.
  // (Same care the identity-updated handler below documents for live editors and sync events.)
  function stashTransientEditorForEvent(): void {
    const v = view;
    if (v.kind !== 'appearance' && v.kind !== 'identity' && v.kind !== 'away') {
      return;
    }
    let stash: AppView = v;
    if (v.kind === 'identity') {
      stash = { ...v, profile: readIdentityDraft(root, v) };
    } else if (v.kind === 'away') {
      stash = { ...v, profile: readAwayDraft(root, v.profile) };
    }
    const key = `kind:${v.kind}`;
    minimizedWins = [...minimizedWins.filter((m) => m.key !== key), { key, title: windowTitle(v), view: stash }];
  }

  // Unsolicited worker events. Conversation views are always re-fetched from the durable keyvault
  // (openChannel) rather than carried in the event, so what renders matches what is persisted and
  // opening a conversation is the single point that starts inbound countdowns (hold-until-seen).
  controller.onEvent?.((ev) => {
    if (ev.event === 'connection') {
      const state = (ev.payload as { state: string }).state;
      setConn(state);
      // On reaching a SECURE link (login or reconnect), drive out any device revoked while we were away,
      // so a sibling that stayed online across a peer's revoke still re-keys the revoked device out of
      // every conversation. Cheap: reconcileRemovals early-returns when nothing on the account is revoked.
      if (state === 'secure') {
        void reconcileRemovals();
      }
      // A conversation opened before the session finished restoring renders DEAD: secure=false, so the
      // compose is the read-only prompt and Note to Self can even label as UNKNOWN. When the link comes
      // up, re-open the conversation in place so it heals. Only a dead view is refreshed; a live one is
      // never re-rendered here (the user may be mid-sentence in the compose box).
      const acHeal = activeConv(view);
      if (state === 'secure' && acHeal !== null && !acHeal.transmit.secure) {
        const id = acHeal.id;
        void controller.openChannel(id).then((transmit) => {
          const cur = activeConv(view);
          if (cur !== null && cur.id === id && !cur.transmit.secure) {
            goToActive(transmit);
          }
        });
      }
      return;
    }
    if (ev.event === 'file-signal') {
      const p = ev.payload as { conversationId?: string; json?: string };
      // Route by the conversation the signal arrived in: handle it only for the conversation we are
      // viewing (where the transfer lives). A signal for any other conversation is dropped, so a second
      // conversation's transfer never crosses into this one's RTCPeerConnection.
      const active = activeConv(view)?.id ?? null;
      if (fileTransfer !== null && typeof p.json === 'string' && active !== null && p.conversationId === active) {
        try {
          void fileTransfer.handleSignal(JSON.parse(p.json));
        } catch {
          /* malformed file signal: drop */
        }
      }
      return;
    }
    if (ev.event === 'call-signal') {
      const p = ev.payload as { conversationId?: string; json?: string };
      const active = activeConv(view)?.id ?? null;
      if (callSession !== null && typeof p.json === 'string' && active !== null && p.conversationId === active) {
        try {
          void callSession.handleSignal(JSON.parse(p.json));
        } catch {
          /* malformed call signal: drop */
        }
      }
      return;
    }
    if (ev.event === 'offer') {
      const p = ev.payload as { conversationId: string; peer: string; peerFingerprint: string };
      stashTransientEditorForEvent(); // a peer's offer must not destroy an open editor's unsaved draft
      go({
        kind: 'keyexchange',
        state: { mode: 'incoming', conversationId: p.conversationId, selfFingerprint: '', peer: p.peer, peerFingerprint: p.peerFingerprint },
      });
      return;
    }
    if (ev.event === 'established') {
      const p = ev.payload as { conversationId: string };
      // Do NOT steal navigation while the add-this-device wizard is still on screen. The seed-holder's
      // post-add heal pushes this new device peer Welcomes; auto-opening one would yank the user off the
      // wizard's DONE screen into a random chat. The prov-done handler lands the buddy list instead.
      if (joiningNewDevice || view.kind === 'provisioning') {
        return;
      }
      if (Date.now() < suppressAutoOpenUntil) {
        // A heal-backfill Welcome landing after the wizard closed: keep the new device on the buddy list,
        // and slide the quiet window so a long paced heal keeps landing here instead of stealing nav.
        suppressAutoOpenUntil = Date.now() + POST_PROVISION_QUIET_MS;
        return;
      }
      stashTransientEditorForEvent(); // stash NOW (at event time), not inside the async resolve
      void controller.openChannel(p.conversationId).then((transmit) => {
        if (transmit.selfNote === true) {
          return; // the hidden self-group never auto-opens as a conversation
        }
        go({ kind: 'conversation', transmit });
      });
      return;
    }
    if (ev.event === 'outbound-appended') {
      // Something appended OUR OWN message to a conversation from the background (today: the away
      // auto reply). Repaint the open conversation so we see what our own account sent, and refresh
      // the channels list if we are on it. Never notifies: this is our own message.
      const p = ev.payload as { conversationId?: string };
      const ac = activeConv(view);
      if (ac !== null && ac.id === p.conversationId) {
        // NEVER rebuild over an on-screen burn-on-read message: its one permitted read is already
        // spent, so a rebuild would replace the plaintext with its tombstone. Away is exactly when
        // nobody is looking, so the reply waits for the next natural rebuild (a send, an arrival, a
        // re-open) in that rare case, matching the pre-existing 'erased' handler's caution.
        const unspentBurn = ac.transmit.log.some((e) => e.kind === 'message' && e.lifetime.kind === 'burn-on-read');
        if (!unspentBurn) {
          const id = ac.id;
          void controller.openChannel(id).then((transmit) => {
            // Re-check at resolve time: the user may have closed, minimized, or navigated away while
            // this read was in flight, and a late repaint must never raise a dismissed window.
            const cur = activeConv(view);
            if (cur !== null && cur.id === id) {
              goToActive(transmit);
            }
          });
        }
      } else if (view.kind === 'channels') {
        void controller.listChannels().then((channels) => {
          if (view.kind !== 'channels') {
            return;
          }
          const cur = view;
          let active = cur.active;
          if (active !== undefined) {
            // Harvest the live compose draft: it lives only in the DOM, so repainting from the stored
            // view would roll back whatever is half-typed in the two-pane's chat.
            const liveCompose = root.querySelector('#dd-compose-input');
            active = { ...active, compose: liveCompose instanceof HTMLElement ? serializeRichText(liveCompose) : '' };
          }
          go({
            kind: 'channels',
            channels,
            ...(active !== undefined ? { active } : {}),
            ...(cur.selectedId !== undefined ? { selectedId: cur.selectedId } : {}),
          });
        });
      }
      return;
    }
    if (ev.event === 'inbound-message') {
      const p = ev.payload as { conversationId: string };
      const ac = activeConv(view);
      if (ac !== null && ac.id === p.conversationId) {
        // We are looking at it (standalone OR the embedded Channels pane): re-render in place, which marks
        // the new message seen and starts its timer.
        void controller.openChannel(p.conversationId).then((transmit) => goToActive(transmit));
      } else {
        // Not the open conversation. Two independent needs, split so a background message never pays the
        // FULL channel sweep (decrypt every row) just to name one sender:
        //  - a notification wants ONE peer name: an O(1) single-row lookup (peerFor);
        //  - the Channels pane, if we are on it, wants the refreshed list (badges + previews).
        // AIM behavior: an arriving message OPENS ITS WINDOW IN FRONT so you can answer it, rather than
        // only announcing itself. Two cases:
        //  - the conversation is DOCKED (minimized): respect that deliberate choice, leave it docked, and
        //    mark its chip unread so the user sees something is waiting (handled below).
        //  - otherwise: pop the conversation window to the front. This also arms the message's burn
        //    countdown, because viewing is what starts an inbound timer (hold-until-seen) — a message that
        //    only raised a toast sat unseen and its countdown never began.
        // Never steal focus during the pairing wizard, a modal/guided flow, or a transient editor holding
        // an unsaved draft: those windows own the screen and yanking the user out loses work.
        const dockedKey = `conv:${p.conversationId}`;
        const isDocked = minimizedWins.some((m) => m.key === dockedKey);
        const popOk =
          !isDocked &&
          !joiningNewDevice &&
          view.kind !== 'provisioning' &&
          Date.now() >= suppressAutoOpenUntil &&
          isPrimaryWindow(view); // a primary window (buddy list / channels / another chat) may be superseded
        if (isDocked) {
          // Keep it docked, but make the dock say so.
          minimizedWins = minimizedWins.map((m) => (m.key === dockedKey ? { ...m, unread: (m.unread ?? 0) + 1 } : m));
          render();
        } else if (popOk) {
          void controller.openChannel(p.conversationId).then((transmit) => {
            // Re-check at resolve time: the user may have navigated somewhere focus-sensitive while the
            // decrypt was in flight.
            if (joiningNewDevice || view.kind === 'provisioning' || !isPrimaryWindow(view)) {
              return;
            }
            go({ kind: 'conversation', transmit });
          });
        }
        if (notifyEnabled) {
          const nameLookup = controller.peerFor !== undefined ? controller.peerFor(p.conversationId) : Promise.resolve('');
          void nameLookup.then(
            (from) => notify(from !== '' ? `Message from ${from}` : 'New message', '', 660),
            () => notify('New message', '', 660), // the lookup failed: still alert, just unnamed
          );
        }
        if (view.kind === 'channels') {
          // Refresh the list (unread badges + previews) but KEEP the current chat pane. Re-derive from the
          // LIVE view at resolve time (a message for the active channel, a send, or a revoke may have landed
          // in the pane while this list fetch was in flight — reverting to a dispatch-time snapshot would
          // hide it, and a burn-on-read message could be crypto-erased yet never seen). Harvest the live
          // compose draft too, so refreshing the badges never wipes what was typed. Bail if we left the pane.
          void controller.listChannels().then((channels) => {
            if (view.kind !== 'channels') {
              return;
            }
            const cur = view;
            let active = cur.active;
            if (active !== undefined) {
              const liveCompose = root.querySelector('#dd-compose-input');
              active = { ...active, compose: liveCompose instanceof HTMLElement ? serializeRichText(liveCompose) : '' };
            }
            go({ kind: 'channels', channels, ...(active !== undefined ? { active } : {}), ...(cur.selectedId !== undefined ? { selectedId: cur.selectedId } : {}) });
          });
        }
        // Otherwise the message stays stored and unseen until the user opens the conversation.
      }
      return;
    }
    if (ev.event === 'erased') {
      // The stored copy was crypto-erased. For expiry and revoke IN THE OPEN CONVERSATION, re-render
      // so the rendered copy drops too; an erasure in any other conversation must not touch this view
      // (a rebuild here would consume or tombstone an on-screen burn message over an unrelated event).
      // A BURN erase never re-renders: it fires DURING the view rebuild that performed the read (the
      // key dies before the plaintext is returned), so re-rendering would replace the one permitted
      // view with its tombstone before the user could read it. The rendered burn copy stays until the
      // next rebuild of its own conversation (a send, an arrival, a re-open, or another erasure
      // there), which finds the latch and shows the destroyed marker.
      const p = ev.payload as { reason?: string; conversationId?: string; selfCopy?: boolean };
      const acEr = activeConv(view);
      // An open Note to Self renders the UNION of every self-classified history, so an erasure in a
      // superseded self-copy (selfCopy, a different id) must ALSO drop the rendered copy here: without
      // this the crypto-erased plaintext stays painted until an unrelated rebuild. Erasures in other
      // PEER conversations still never rebuild this view.
      const hitsSelfUnion = p.selfCopy === true && acEr !== null && acEr.transmit.selfNote === true;
      if (p.reason !== 'burn' && acEr !== null && (acEr.id === p.conversationId || hitsSelfUnion)) {
        void controller.openChannel(acEr.id).then((transmit) => goToActive(transmit));
      }
      return;
    }
    if (ev.event === 'identity-updated') {
      // Another of your devices changed the buddy icon, profile, or away config and it was adopted here
      // (most recent change wins). Only refresh a READ-ONLY view that shows the card: the buddy list. The
      // Profile and Away screens are live editors holding an UNSAVED draft, so reloading them the moment a
      // sibling syncs would wipe what you are mid-typing, drop your caret, and cost a getIdentity round-trip
      // each time. Like Buddy List Setup, they keep your draft and your Save merges last-writer-wins. (This
      // reload was what made the Away editor feel unusable: a self-group sync kept re-rendering it out from
      // under you, so text and applied colors vanished as you typed.)
      if (view.kind === 'buddies') {
        // A reveal-hydrate (focusParkedWindow / revealNextWindow) may be in flight holding the
        // PRE-adoption card, and openBuddies only guards on navGen, so the first loader to resolve
        // wins: without painting here the STALE read could land last and undo this very fix. Paint the
        // carried card now (this go() bumps navGen, so the stale loader self-aborts), then refresh.
        const live = (ev.payload as { profile?: IdentityProfile }).profile;
        if (live !== undefined) {
          go(patchBuddyView(live)(view));
        }
        void openBuddies();
        return;
      }
      // NOT the focused window. The buddy list is usually PARKED behind a chat or an editor (still
      // painted on the desktop, from a FROZEN snapshot) or stashed in the tray, and it is the only
      // surface showing your own away bubble, status diamond, and row. Dropping the event here left a
      // sibling's away change stale INDEFINITELY: no flag, no retry, and both ways back to a parked
      // window re-render the snapshot verbatim. Patch the stored snapshots in place instead: no worker
      // round trip, no navigation, and a live editor's unsaved draft is never touched.
      const adopted = (ev.payload as { profile?: IdentityProfile }).profile;
      if (adopted !== undefined) {
        patchBuddySnapshots(adopted);
      }
      return;
    }
    if (ev.event === 'buddies-updated') {
      // Another of your devices changed the buddy list and it was adopted here (per-buddy last-writer-wins).
      // The stored list is already merged; re-render the read-only list if you are looking at it. Setup is
      // deliberately NOT reloaded: it holds an unsaved draft, and Save's per-item diff merges cleanly with
      // whatever the sibling wrote (LWW downstream).
      if (view.kind === 'buddies') {
        void openBuddies();
      }
      return;
    }
    if (ev.event === 'groups-updated') {
      // Same as buddies-updated: refresh the read-only list, never clobber an open Setup draft.
      if (view.kind === 'buddies') {
        void openBuddies();
      }
      return;
    }
    // Device provisioning (model b). Both devices show six words; the user compares them out of band.
    if (ev.event === 'show-code' || ev.event === 'confirm-device') {
      const words = (ev.payload as { words?: string }).words;
      const role: ProvisioningView['role'] =
        view.kind === 'provisioning' ? view.state.role : ev.event === 'confirm-device' ? 'seedholder' : 'newdevice';
      go({ kind: 'provisioning', state: { role, step: 'compare', ...(words !== undefined ? { words } : {}) } });
      return;
    }
    if (ev.event === 'provisioning-authorized') {
      // This device just adopted its certificate. Enroll it now (the reorder deferred enrollment to here),
      // publish authorized key packages so peers can add it, then show the success screen.
      void finishWizardEnrollment();
      return;
    }
    if (ev.event === 'device-added') {
      // The seed-holder just authorized a new sibling. It is online and in the open conversation, so
      // heal it into the group now (H1): the new device receives going forward. No-op if no conversation.
      void reconcileRemovals();
      void reconcileSiblings();
      selfMintFailures = 0; // real news about the roster: retry even if we had parked
      void ensureSelfGroup(); // and bring the new device into the buddy-list self-group
      // The new device publishes its key package AFTER this event, so the calls above find nothing
      // claimable yet. Poll (by the device's own key) until it publishes, then heal it into the self-group
      // even when we are not the lowest-keyed adder (else it would sit on SECURING forever).
      healNewSibling((ev.payload as { deviceKey?: string }).deviceKey ?? '');
      go({ kind: 'provisioning', state: { role: 'seedholder', step: 'done' } });
      return;
    }
    if (ev.event === 'provisioning-window-closed') {
      if (view.kind === 'provisioning' && view.state.role === 'seedholder' && view.state.step !== 'done') {
        void openSettings(); // the window timed out or was dismissed
      }
      return;
    }
    if (ev.event === 'provisioning-expired') {
      // The shown QR expired (Fix 3). Surface the expired state so the user can request a fresh code; if we
      // have already moved off the showqr step, the machine has reset and this is a no-op.
      if (view.kind === 'provisioning' && view.state.step === 'showqr') {
        go({ kind: 'provisioning', state: { ...view.state, step: 'qrexpired' } }); // qrexpired render ignores the stale qr
      }
      return;
    }
    if (ev.event === 'roster-changed') {
      const p = ev.payload as { conversationId?: string };
      // Drive the forward-heal loop: a successful add fires this, so re-run reconcile to admit the next
      // missing sibling (one staged add is in flight at a time). No-op once every device is in.
      // DEBOUNCED: a revoke cascade fires one roster-changed per conversation over seconds, and each
      // reconcile pass does a device-list fetch plus heavy MLS worker ops on the SINGLE serialized worker
      // chain. Running the trio per event floods that chain, and every other worker call (notably the
      // Back button's buddy-list reads) queues behind it for seconds; one trailing pass per burst heals
      // everything the burst changed just as well.
      if (reconcileTimer !== null) {
        clearTimeout(reconcileTimer);
      }
      reconcileTimer = setTimeout(() => {
        reconcileTimer = null;
        void reconcileRemovals();
        void reconcileSiblings();
        selfMintFailures = 0; // the roster genuinely changed: a parked mint deserves another attempt
        void ensureSelfGroup(); // a newly learned sibling may mean the self-group still needs creating
      }, RECONCILE_DEBOUNCE_MS);

      const acRoster = activeConv(view);
      if (view.kind === 'settings') {
        // Debounced background refresh: a revoke fires one roster-changed per conversation over seconds;
        // refresh once after the burst settles rather than rebuilding (and eating taps) per event.
        if (settingsRefreshTimer !== null) {
          clearTimeout(settingsRefreshTimer);
        }
        settingsRefreshTimer = setTimeout(() => {
          settingsRefreshTimer = null;
          void openSettings(undefined, true);
        }, SETTINGS_REFRESH_DEBOUNCE_MS);
      } else if (acRoster !== null && acRoster.id === p.conversationId) {
        // Someone was added or removed: refresh so the participant label updates to GROUP.
        void controller.openChannel(acRoster.id).then((transmit) => goToActive(transmit));
      }
      return;
    }
    if (ev.event === 'sibling-add-rejected') {
      // The adder-side gate refused a sibling's key package (deterministic for that package). Count it
      // so the heal poll stops claiming fresh packages for a device whose directory only serves
      // rejected ones (two strikes abort the poll with a toast).
      const p = ev.payload as { deviceKey?: string; detail?: string };
      if (typeof p.deviceKey === 'string' && p.deviceKey !== '') {
        siblingAddRejections.set(p.deviceKey, (siblingAddRejections.get(p.deviceKey) ?? 0) + 1);
        // Keep the REASON, not just the count. The crypto layer's message names the leaf's epoch, this
        // conversation's floor, and this device's global floor, and until now it existed only in a
        // console.warn: diagnosing a stuck pairing meant guessing at three numbers that were sitting
        // right there. They are counters, not secrets.
        if (typeof p.detail === 'string' && p.detail !== '') {
          siblingAddRejectReasons.set(p.deviceKey, p.detail);
        }
      }
      return;
    }
    if (ev.event === 'provisioning-error') {
      // The provisioning machine's OWN failures (already friendly copy). Surface only while the wizard
      // is still in progress: a straggler after DONE must not repaint the success screen.
      const p = ev.payload as { detail?: string };
      if (view.kind === 'provisioning' && view.state.step !== 'done') {
        go({ kind: 'provisioning', state: { role: view.state.role, step: 'error', error: p.detail ?? 'something went wrong' } });
      }
      return;
    }
    if (ev.event === 'error') {
      // Background machinery only (gateway frames, transport decode, group receive/decrypt/persist).
      // Console-only, NEVER a view repaint: a re-flushed decrypt failure after a reconnect used to
      // hijack the open pairing wizard with raw MLS internals and tear down the camera mid-scan.
      const p = ev.payload as { code?: number; detail?: string };
      if (p.code !== 3) {
        console.warn('worker event error:', p.detail ?? 'unknown'); // 3 = RATE_LIMIT: the transport backs off and retransmits
      }
      return;
    }
  });

  // Close the DEAD DROP, buddy-list status, and connection-status dropdowns when a click lands outside
  // them (they re-render closed on navigation, so this only covers a click elsewhere without navigating).
  // Attached once; queries the menus fresh.
  document.addEventListener('click', (e) => {
    root.querySelectorAll('.dd-appmenu-pop, #dd-status-menu, #dd-conn-pop').forEach((menu) => {
      if (menu instanceof HTMLElement && !menu.hidden && !(e.target instanceof Node && menu.parentElement?.contains(e.target))) {
        menu.hidden = true;
      }
    });
  });

  // Keep the compose reachable above the mobile on-screen keyboard. Two platform behaviors meet here:
  // iOS ignores interactive-widget and OVERLAYS the keyboard (innerHeight stays put, only the visual
  // viewport shrinks and may PAN, gaining an offsetTop), so the desk is capped to the visible height and
  // translated to follow the pan; Android with interactive-widget=resizes-content resizes the LAYOUT
  // viewport itself (innerHeight tracks vv.height), so the 100dvh desk adapts natively and the cap stays
  // inert. A dragged window's absolute top is re-clamped on EVERY vv resize (both platforms need it:
  // max-height measures the whole stage, not the room below the window's top). Pinch-zoom also shrinks
  // vv.height, so the keyboard cap only engages at ~1:1 scale. CSSOM only (the strict CSP blocks style
  // attributes, never style properties).
  const vv = window.visualViewport;
  if (vv !== null && vv !== undefined && typeof vv.addEventListener === 'function') {
    let lastVvH = vv.height;
    vv.addEventListener('resize', () => {
      const zoomed = typeof vv.scale === 'number' && Math.abs(vv.scale - 1) > 0.05;
      const shrunk = !zoomed && window.innerHeight - vv.height > 80;
      root.style.height = shrunk ? `${Math.round(vv.height)}px` : '';
      root.style.transform = shrunk && vv.offsetTop > 0 ? `translateY(${Math.round(vv.offsetTop)}px)` : '';
      // Re-clamp a dragged window so its bottom (the compose) stays inside the now-smaller stage. Runs
      // on every resize: on Android the desk shrank natively without `shrunk` ever turning true.
      const win = root.querySelector('.dd-window');
      const stage = root.querySelector('.dd-stage');
      if (win instanceof HTMLElement && stage instanceof HTMLElement && win.style.position === 'absolute') {
        const top = parseFloat(win.style.top) || 0;
        win.style.top = `${Math.max(0, Math.min(top, stage.clientHeight - win.offsetHeight))}px`;
      }
      // The keyboard just opened (the visual viewport got shorter): bring the focused field into view.
      if (vv.height < lastVvH - 40) {
        const focused = document.activeElement;
        if (focused instanceof HTMLElement && root.contains(focused)) {
          focused.scrollIntoView({ block: 'nearest' });
        }
      }
      lastVvH = vv.height;
    });
  }

  render();
}

const DEMO_CHANNELS: readonly ChannelSummary[] = [
  { id: 'raven', peer: 'RAVEN', fingerprint: '5F·A2·91·C4', status: 'secure', preview: 'drop confirmed at the usual place', unread: 2 },
  { id: 'falcon', peer: 'FALCON', fingerprint: '0B·7D·3E·A1', status: 'pending', preview: 'awaiting your accept', unread: 0 },
  { id: 'wren', peer: 'WREN', fingerprint: 'C2·44·90·6F', status: 'blocked', preview: 'key changed, re-verify needed', unread: 0 },
];

/**
 * Demo controller for the preview: any non-empty passphrase unlocks, with sample channels. The
 * real controller wires `unlock` to the MSK vault and `listChannels`/`openChannel` to the worker.
 */
export class DemoController implements AppController {
  unlock(username: string, passphrase: string): Promise<{ ok: boolean; error?: string }> {
    if (username.trim().length === 0) {
      return Promise.resolve({ ok: false, error: 'enter a username' });
    }
    return Promise.resolve(passphrase.length > 0 ? { ok: true } : { ok: false, error: 'enter a passphrase' });
  }
  listChannels(): Promise<readonly ChannelSummary[]> {
    return Promise.resolve(DEMO_CHANNELS);
  }
  openChannel(id: string): Promise<TransmitModel> {
    const c = DEMO_CHANNELS.find((x) => x.id === id);
    const peer = c?.peer ?? 'UNKNOWN';
    return Promise.resolve({
      secure: c?.status === 'secure',
      peer,
      fingerprint: c?.fingerprint ?? null,
      log: [
        { kind: 'system', text: '» channel open · forward secrecy active' },
        { kind: 'message', sender: peer, text: 'drop confirmed at the usual place', lifetime: { kind: 'duration', seconds: 24 }, remainingSeconds: 24, expiresAtMs: Date.now() + 24_000 },
        { kind: 'message', sender: 'YOU', text: 'acknowledged', lifetime: { kind: 'until-revoked' }, remainingSeconds: null },
      ],
      compose: '',
      conversationId: id,
    });
  }
  openNoteToSelf(): Promise<TransmitModel> {
    return Promise.resolve({
      secure: true,
      peer: 'Note to Self',
      fingerprint: null,
      selfNote: true,
      log: [{ kind: 'system', text: '» channel open · forward secrecy active' }],
      compose: '',
      conversationId: 'note-to-self',
    });
  }
  startKeyExchange(): Promise<KeyExchangeState> {
    return Promise.resolve({ mode: 'start', conversationId: 'new', selfFingerprint: '9A·3C·71·EE', selfContact: 'deaddrop:1:demo:demo' });
  }
  channelKeyExchange(id: string): Promise<KeyExchangeState> {
    const c = DEMO_CHANNELS.find((x) => x.id === id);
    return Promise.resolve({
      mode: 'incoming',
      conversationId: id,
      selfFingerprint: '9A·3C·71·EE',
      peer: c?.peer ?? 'NEW CONTACT',
      peerFingerprint: c?.fingerprint ?? '',
    });
  }
  acceptKeyExchange(conversationId: string): Promise<TransmitModel> {
    const c = DEMO_CHANNELS.find((x) => x.id === conversationId);
    return Promise.resolve({
      secure: true,
      peer: c?.peer ?? 'NEW CONTACT',
      fingerprint: c?.fingerprint ?? '9A·3C·71·EE',
      log: [{ kind: 'system', text: '» channel established · forward secrecy active' }],
      compose: '',
      conversationId,
    });
  }
  connectGateway(): Promise<{ ok: boolean; selfContact: string; error?: string }> {
    return Promise.resolve({ ok: true, selfContact: 'deaddrop:1:demo:demo' });
  }
  startConversation(): Promise<TransmitModel> {
    return Promise.resolve({
      secure: true,
      peer: 'NEW CONTACT',
      fingerprint: '9A·3C·71·EE',
      log: [{ kind: 'system', text: '» channel established · forward secrecy active' }],
      compose: '',
      conversationId: 'demo',
    });
  }
  sendMessage(_conversationId: string, text: string, lifetime?: Lifetime): Promise<TransmitModel> {
    // Echo the picked lifetime so the demo view matches the ⏳ trigger instead of contradicting it.
    const l: Lifetime = lifetime ?? { kind: 'duration', seconds: 24 };
    return Promise.resolve({
      secure: true,
      peer: 'NEW CONTACT',
      fingerprint: '9A·3C·71·EE',
      log: [
        { kind: 'system', text: '» channel established · forward secrecy active' },
        { kind: 'message', sender: 'YOU', text, lifetime: l, remainingSeconds: l.kind === 'duration' ? Math.min(l.seconds, 24) : null, expiresAtMs: l.kind === 'duration' ? Date.now() + Math.min(l.seconds, 24) * 1000 : null },
      ],
      compose: '',
      conversationId: 'demo',
    });
  }
  private demoIdentity: IdentityProfile = DEFAULT_IDENTITY;
  getIdentity(): Promise<IdentityProfile> {
    return Promise.resolve(this.demoIdentity);
  }
  setIdentity(profile: IdentityProfile): Promise<void> {
    this.demoIdentity = profile;
    return Promise.resolve();
  }
  getPeerIdentities(_conversationId: string): Promise<readonly PeerIdentity[]> {
    return Promise.resolve([
      { key: 'aabb', fingerprint: '5F·A2·91·C4', icon: { kind: 'emoji', value: '\u{1F985}', bg: '#1f9d6b' }, bio: 'drop confirmed at the usual place', away: ''  },
    ]);
  }
  tagConversationHandle(_conversationId: string, _username: string): Promise<void> {
    return Promise.resolve();
  }
  getBuddyInfo(username: string): Promise<readonly PeerIdentity[]> {
    // The demo pretends you have already chatted with raven, so Buddy Info shows a sample profile.
    if (username === 'raven') {
      return Promise.resolve([
        { key: 'aabb', fingerprint: '5F·A2·91·C4', icon: { kind: 'emoji', value: '\u{1F985}', bg: '#1f9d6b' }, bio: 'drop confirmed at the usual place', away: ''  },
      ]);
    }
    return Promise.resolve([]);
  }
  buddyIcons(usernames: readonly string[]): Promise<Record<string, BuddyIcon>> {
    // Matches getBuddyInfo: only raven has a cached icon; everyone else gets the placeholder.
    return Promise.resolve(usernames.includes('raven') ? { raven: { kind: 'emoji', value: '\u{1F985}', bg: '#1f9d6b' } } : {});
  }
  buddyAwayText(usernames: readonly string[]): Promise<Record<string, string>> {
    // Demo away messages (shown as the dim subtitle only when the buddy's presence reads 'away').
    const demo: Record<string, string> = { falcon: 'Girl 2 Girl Love? Type CRUSH to 25353', raven: 'brb — grabbing lunch, back at 1' };
    const out: Record<string, string> = {};
    for (const u of usernames) {
      if (demo[u] !== undefined) {
        out[u] = demo[u];
      }
    }
    return Promise.resolve(out);
  }
  private demoBuddies: Buddy[] = [
    { username: 'raven', addedAt: 0, group: 'Buddies' },
    { username: 'falcon', addedAt: 0, group: 'Buddies' },
    { username: 'talkingstan', addedAt: 0, group: 'Family' },
    { username: 'pianopaul97', addedAt: 0, group: 'Family' },
    { username: 'jitterbugsandy', addedAt: 0, group: 'Co-Workers' },
  ];
  listBuddies(): Promise<readonly Buddy[]> {
    return Promise.resolve(this.demoBuddies);
  }
  addBuddy(username: string, group?: string): Promise<readonly Buddy[]> {
    const u = username.trim().toLowerCase();
    if (u.length > 0 && !this.demoBuddies.some((b) => b.username === u)) {
      this.demoBuddies = [...this.demoBuddies, { username: u, addedAt: 0, group: group !== undefined && group.trim().length > 0 ? group.trim() : 'Buddies' }];
    }
    return Promise.resolve(this.demoBuddies);
  }
  setBuddyGroup(username: string, group: string): Promise<readonly Buddy[]> {
    const u = username.trim().toLowerCase();
    this.demoBuddies = this.demoBuddies.map((b) => (b.username === u ? { ...b, group: group.trim() || 'Buddies' } : b));
    return Promise.resolve(this.demoBuddies);
  }
  removeBuddy(username: string): Promise<readonly Buddy[]> {
    this.demoBuddies = this.demoBuddies.filter((b) => b.username !== username.trim().toLowerCase());
    return Promise.resolve(this.demoBuddies);
  }
  private demoGroups: GroupSummary[] = [{ name: 'Family' }, { name: 'Co-Workers' }];
  // The built-ins' current display labels (their internal keys never change; see GroupSummary.role).
  private demoDefaultName = 'Buddies';
  private demoBlockedName = 'Blocked';
  listGroups(): Promise<readonly GroupSummary[]> {
    return Promise.resolve([
      { name: this.demoDefaultName, role: 'default' as const },
      ...this.demoGroups,
      { name: this.demoBlockedName, role: 'blocked' as const },
    ]);
  }
  addGroup(name: string): Promise<readonly GroupSummary[]> {
    const g = name.trim();
    if (
      g.length > 0 &&
      g !== 'Buddies' &&
      g !== this.demoDefaultName &&
      g !== this.demoBlockedName &&
      !this.demoGroups.some((x) => x.name === g)
    ) {
      this.demoGroups = [...this.demoGroups, { name: g }];
    }
    return this.listGroups();
  }
  renameGroup(role: 'default' | 'blocked', name: string): Promise<readonly GroupSummary[]> {
    const g = name.trim();
    const other = role === 'default' ? this.demoBlockedName : this.demoDefaultName;
    if (g.length > 0 && g !== other && !this.demoGroups.some((x) => x.name === g)) {
      if (role === 'default') {
        this.demoDefaultName = g;
      } else {
        this.demoBlockedName = g;
      }
    }
    return this.listGroups();
  }
  deleteGroup(name: string): Promise<readonly GroupSummary[]> {
    const g = name.trim();
    if (g.length === 0 || g === 'Buddies') {
      return this.listGroups();
    }
    this.demoGroups = this.demoGroups.filter((x) => x.name !== g);
    this.demoBuddies = this.demoBuddies.map((b) => (b.group === g ? { ...b, group: 'Buddies' } : b));
    return this.listGroups();
  }
  private demoPresenceOn = false;
  getPresenceEnabled(): Promise<boolean> {
    return Promise.resolve(this.demoPresenceOn);
  }
  setPresenceEnabled(on: boolean): Promise<void> {
    this.demoPresenceOn = on;
    return Promise.resolve();
  }
  private demoNotifyOn = true;
  getNotifyEnabled(): Promise<boolean> {
    return Promise.resolve(this.demoNotifyOn);
  }
  setNotifyEnabled(on: boolean): Promise<void> {
    this.demoNotifyOn = on;
    return Promise.resolve();
  }
  private demoAppearance: Appearance = DEFAULT_APPEARANCE;
  getAppearance(): Promise<unknown> {
    return Promise.resolve(this.demoAppearance);
  }
  setAppearance(value: Appearance): Promise<void> {
    this.demoAppearance = value;
    return Promise.resolve();
  }
  sendFileSignal(_conversationId: string, _json: string): void {
    /* the demo has no live channel to carry signaling */
  }
  sendCallSignal(_conversationId: string, _json: string): void {
    /* the demo has no live channel to carry signaling */
  }
  private demoBlocked: BlockedContact[] = [];
  blockConversation(_conversationId: string): Promise<void> {
    this.demoBlocked = [...this.demoBlocked, { key: 'd'.repeat(64), fingerprint: 'DE·AD·BE·EF' }];
    return Promise.resolve();
  }
  listBlocked(): Promise<readonly BlockedContact[]> {
    return Promise.resolve(this.demoBlocked);
  }
  unblock(key: string): Promise<readonly BlockedContact[]> {
    this.demoBlocked = this.demoBlocked.filter((b) => b.key !== key);
    return Promise.resolve(this.demoBlocked);
  }
}
