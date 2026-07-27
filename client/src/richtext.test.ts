// @vitest-environment happy-dom
//
// Round-trip tests for the WYSIWYG rich-text pipeline: serializeRichText turns the editor's
// contenteditable DOM into the safe marker text the app stores/syncs, and formatMessageText renders that
// text back to CSP-safe HTML. The two must agree, and nothing outside the known grammar may survive.

import { describe, it, expect } from 'vitest';
import { serializeRichText, formatMessageText } from './app.js';

function ce(html: string): HTMLElement {
  const div = document.createElement('div');
  div.innerHTML = html;
  return div;
}

describe('rich text serializer round-trip', () => {
  it('serializes every supported format to its marker and renders back to CSP-safe HTML', () => {
    const div = ce(
      'plain <strong>bold</strong> <em>it</em> <u>un</u> <font size="5">big</font> <font size="2">sm</font> ' +
        '<span class="dd-c-rd">red</span> <span class="dd-hl-y">hi</span> <span class="dd-ft-m">mono</span>',
    );
    const markers = serializeRichText(div);
    expect(markers).toContain('*bold*');
    expect(markers).toContain('_it_');
    expect(markers).toContain('[u]un[/u]');
    expect(markers).toContain('[z:5]big[/z]'); // exact size level (font size 5), not just "large"
    expect(markers).toContain('[z:2]sm[/z]'); // exact size level (font size 2), not just "small"
    expect(markers).toContain('[c:rd]red[/c]');
    expect(markers).toContain('[h:y]hi[/h]');
    expect(markers).toContain('[f:m]mono[/f]');
    const html = formatMessageText(markers);
    expect(html).not.toContain('style='); // renders without inline styles (survives the strict CSP)
    expect(html).toContain('<span class="dd-c-rd">red</span>');
    expect(html).toContain('<font size="5">big</font>');
  });

  it('round-trips all three smaller and three larger size levels, treating size 4 as the baseline', () => {
    // 1-3 are the smaller steps, 5-7 the larger; each keeps its exact level through the round-trip.
    for (const n of [1, 2, 3, 5, 6, 7]) {
      expect(serializeRichText(ce(`<font size="${n}">x</font>`))).toBe(`[z:${n}]x[/z]`);
    }
    // Size 4 equals the surrounding text, so it carries no marker (round-trips to plain text).
    expect(serializeRichText(ce('<font size="4">x</font>'))).toBe('x');
    // Legacy s/l markers still render (onto the same scale) for messages saved before the seven levels.
    expect(formatMessageText('[z:s]x[/z]')).toContain('<font size="2">x</font>');
    expect(formatMessageText('[z:l]x[/z]')).toContain('<font size="5">x</font>');
  });

  it('strips the zero-width caret-holder that a no-selection color pick leaves in an empty run', () => {
    // Picking a color/highlight/font with nothing selected starts an empty styled span holding the caret
    // with a U+200B, so the NEXT typed text takes the style; the U+200B must never reach the markers.
    expect(serializeRichText(ce('<span class="dd-c-rd">\u200Bhello</span>'))).toBe('[c:rd]hello[/c]');
    expect(serializeRichText(ce('plain\u200B text'))).toBe('plain text');
  });

  it('drops an empty formatting run so an untouched B/I/U caret-holder cannot send a blank bubble', () => {
    // Clicking Bold/Italic/Underline with no selection opens an empty <b>\u200B</b> caret-holder; if the user
    // sends without typing, it must serialize to '' (not '**'), so the send-empty guard rejects it.
    expect(serializeRichText(ce('<b>\u200B</b>'))).toBe('');
    expect(serializeRichText(ce('<i>\u200B</i>'))).toBe('');
    expect(serializeRichText(ce('<u>\u200B</u>'))).toBe('');
    expect(serializeRichText(ce('<span class="dd-c-rd">\u200B</span>'))).toBe('');
    expect(serializeRichText(ce('<b></b>'))).toBe(''); // a genuinely empty tag carries nothing either
    // A holder with real text still serializes normally.
    expect(serializeRichText(ce('<b>\u200Bhi</b>'))).toBe('*hi*');
  });

  it('round-trips bold layered over font + italic + color (bold works after other formats already applied)', () => {
    // This nesting is exactly what the editor produces when you color, italicize, pick a font, then bold
    // a selection (requirement #6). All four formats must survive to the rendered output.
    const markers = serializeRichText(ce('<b><span class="dd-ft-h"><i><span class="dd-c-rd">hello</span></i></span></b>'));
    expect(markers).toBe('*[f:h]_[c:rd]hello[/c]_[/f]*');
    const html = formatMessageText(markers);
    expect(html).not.toContain('style='); // survives the strict CSP
    expect(html).toContain('<strong>');
    expect(html).toContain('<em>');
    expect(html).toContain('dd-ft-h');
    expect(html).toContain('dd-c-rd');
  });

  it('converts an rgb() <font color> (from paste/execCommand) into a legacy hex color marker', () => {
    const markers = serializeRichText(ce('<font color="rgb(255, 0, 0)">red</font>'));
    expect(markers).toBe('[c#ff0000]red[/c]');
    expect(formatMessageText(markers)).toContain('<font color="#ff0000">red</font>');
  });

  it('backslash-escapes literal marker characters so they survive the round-trip', () => {
    const div = document.createElement('div');
    div.textContent = 'use *asterisks* and [c:rd]brackets';
    const markers = serializeRichText(div);
    const html = formatMessageText(markers);
    expect(html).toContain('use *asterisks* and [c:rd]brackets');
    expect(html).not.toContain('<strong>'); // the literal * did not become bold
    expect(html).not.toContain('<span class="dd-c-rd"'); // the literal [c:rd] did not become a color
  });

  it('keeps only the text of unknown elements, so nothing outside the grammar reaches storage', () => {
    const markers = serializeRichText(ce('<a href="http://evil">link</a><b>x</b><table><tr><td>z</td></tr></table>'));
    expect(markers).not.toContain('<');
    expect(markers).toContain('*x*');
    expect(markers).toContain('link');
    expect(markers).toContain('z');
  });

  it('treats block elements as line breaks', () => {
    const markers = serializeRichText(ce('one<div>two</div><div>three</div>'));
    expect(markers).toBe('one\ntwo\nthree');
  });
});

describe('inline images ([img:] marker)', () => {
  const OK = 'data:image/webp;base64,AAAABBBBcccc0099++//==';

  it('serializes a trusted raster data-URL <img> to an [img:] marker and back to a bounded <img>', () => {
    const markers = serializeRichText(ce(`<img src="${OK}">`));
    expect(markers).toBe(`[img:${OK}]`);
    const html = formatMessageText(markers, { images: true });
    expect(html).toBe(`<img class="dd-img" src="${OK}" alt="shared image" decoding="async" />`);
    expect(html).not.toContain('style='); // CSP-safe: no inline style
  });

  it('preserves reading order of text around an image', () => {
    const html = formatMessageText(`hello [img:${OK}] world`, { images: true });
    expect(html).toBe(`hello <img class="dd-img" src="${OK}" alt="shared image" decoding="async" /> world`);
  });

  it('does NOT render images unless the caller opts in (profile/away stay literal text)', () => {
    const html = formatMessageText(`[img:${OK}]`); // default: images off
    expect(html).not.toContain('<img');
    expect(html).toContain('[img:'); // rendered as literal text
  });

  it('drops an external or non-data <img> src (a pasted tracker is never stored or sent)', () => {
    expect(serializeRichText(ce('<img src="https://evil.example/track.png">'))).toBe('');
    expect(serializeRichText(ce('<img src="data:text/html;base64,PHNjcmlwdD4=">'))).toBe(''); // not an image
    expect(serializeRichText(ce('<img src="data:image/svg+xml;base64,PHN2Zz4=">'))).toBe(''); // svg can carry script
  });

  it('refuses to render a crafted [img:] payload that tries to break out of the attribute or tag', () => {
    // A double-quote / bracket / angle bracket / colon-scheme is not in the base64 alphabet or the strict
    // data:image whitelist, so the marker regex never matches these — they stay literal, escaped text:
    // never an <img>, never a <script>, never an injected attribute or tag.
    const attacks = [
      '[img:data:image/png;base64,AA" onerror=alert(1)]', // " breaks the base64 run before the closing ]
      '[img:data:image/png;base64,AA><script>alert(1)</script>]', // > breaks the run
      '[img:data:image/svg+xml;base64,PHN2Zz48c2NyaXB0Pg==]', // svg is excluded (can carry script)
      '[img:javascript:alert(1)]', // not a data:image URL at all
    ];
    for (const a of attacks) {
      const html = formatMessageText(a, { images: true });
      expect(html).not.toContain('<img'); // stayed literal text, no image element
      expect(html).not.toContain('<script'); // any < is escaped to &lt;, so no tag is emitted
      expect(html).not.toMatch(/<[a-z]/i); // in fact NO real HTML tag at all (these payloads have no markers)
    }
  });

  it('terminates the image at the first closing bracket, escaping any trailing junk as text', () => {
    // The ] correctly ends the marker; the src captured is exactly the (valid) base64 up to it, and the
    // trailing `" onload=...` is inert escaped text OUTSIDE the well-formed <img>, not an injected attribute.
    const html = formatMessageText('[img:data:image/png;base64,AAAA]" onload="x', { images: true });
    expect(html).toContain('<img class="dd-img" src="data:image/png;base64,AAAA" alt="shared image" decoding="async" />');
    expect(html).not.toContain('onload="x"'); // the trailing bit never became a real attribute
    expect(html.match(/<img/g)?.length).toBe(1); // exactly one, well-formed image
  });

  it('refuses to render an image whose HEADER declares tab-crashing dimensions (decode-bomb guard)', () => {
    const b64 = (bytes: number[]): string => btoa(String.fromCharCode(...bytes));
    // GIF header: "GIF89a" then logical-screen width/height as little-endian uint16.
    const gif = (w: number, h: number): string =>
      'data:image/gif;base64,' + b64([0x47, 0x49, 0x46, 0x38, 0x39, 0x61, w & 0xff, (w >> 8) & 0xff, h & 0xff, (h >> 8) & 0xff]);
    // A modest image renders; a header claiming 16000x16000 (≈1 GB decoded) is blocked, not handed to <img>.
    const small = formatMessageText(`[img:${gif(64, 48)}]`, { images: true });
    expect(small).toContain('<img');
    const bomb = formatMessageText(`[img:${gif(16000, 16000)}]`, { images: true });
    expect(bomb).not.toContain('<img');
    expect(bomb).toContain('image too large');

    // PNG header (\x89PNG... IHDR width/height big-endian at bytes 16..23) declaring 20000x20000 is blocked.
    const pngBomb =
      'data:image/png;base64,' +
      b64([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 13, 0x49, 0x48, 0x44, 0x52, 0, 0, 0x4e, 0x20, 0, 0, 0x4e, 0x20]);
    expect(formatMessageText(`[img:${pngBomb}]`, { images: true })).not.toContain('<img');
  });

  it('round-trips an image together with formatted text', () => {
    const dom = ce(`<b>look</b> <img src="${OK}"> <em>at this</em>`);
    const markers = serializeRichText(dom);
    expect(markers).toBe(`*look* [img:${OK}] _at this_`);
    const html = formatMessageText(markers, { images: true });
    expect(html).toContain('<strong>look</strong>');
    expect(html).toContain(`<img class="dd-img" src="${OK}"`);
    expect(html).toContain('<em>at this</em>');
  });
});
