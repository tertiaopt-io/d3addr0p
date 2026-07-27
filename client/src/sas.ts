/**
 * Short Authentication String rendering for device provisioning (ADR-022 P4, model b).
 *
 * The provisioning verification code is the first 66 bits of the transcript-bound SAS digest
 * (crypto/src/authz.rs sas_digest, also exposed as the wasm `sasDigestHex`), rendered as SIX words
 * the user compares out of band across both devices. 66 bits of comparison entropy makes the offline
 * grind a relay would need to substitute a device key infeasible within the short add-a-device window
 * (the review found any decimal code grindable in under a second).
 *
 * The wordlist is 2048 distinct pronounceable syllable tokens (onset x vowel x coda = 16 x 8 x 16),
 * generated compactly so it is auditable at a glance, with 11 bits per token. Both devices share this
 * exact list, so the only requirement is that it has 2048 distinct entries; the entropy comes from the
 * digest, not the choice of words.
 */

const ONSETS = ['b', 'd', 'f', 'g', 'k', 'l', 'm', 'n', 'p', 'r', 's', 't', 'v', 'z', 'br', 'st'];
const VOWELS = ['a', 'e', 'i', 'o', 'u', 'ay', 'ee', 'oo'];
const CODAS = ['', 'b', 'd', 'k', 'l', 'm', 'n', 'p', 'r', 's', 't', 'x', 'ld', 'nd', 'rk', 'st'];

/** Map an 11-bit index (0..2047) to its token: 4 bits onset, 3 bits vowel, 4 bits coda. */
export function sasWord(index: number): string {
  const onset = ONSETS[(index >> 7) & 0xf] ?? '';
  const vowel = VOWELS[(index >> 4) & 0x7] ?? '';
  const coda = CODAS[index & 0xf] ?? '';
  return onset + vowel + coda;
}

/** Render the SAS digest (>=9 bytes) as six space-separated words from its first 66 bits. */
export function renderSas(digest: Uint8Array): string {
  if (digest.length < 9) {
    throw new Error('SAS digest too short');
  }
  const words: string[] = [];
  let bitpos = 0;
  for (let i = 0; i < 6; i++) {
    let value = 0;
    for (let b = 0; b < 11; b++) {
      const byte = digest[bitpos >> 3] ?? 0;
      const bit = (byte >> (7 - (bitpos & 7))) & 1;
      value = (value << 1) | bit;
      bitpos += 1;
    }
    words.push(sasWord(value));
  }
  return words.join(' ');
}

function hexToBytes(h: string): Uint8Array {
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/** Render a SAS digest given as hex (the form `sasDigestHex` returns). */
export function renderSasHex(digestHex: string): string {
  return renderSas(hexToBytes(digestHex));
}
