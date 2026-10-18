// Internal AES-256-GCM (NIST SP 800-38D) with 96-bit nonces and 128-bit tags.
// GHASH uses Shoup's 4-bit tables. Not constant-time (table lookups); educational use only.
import { Aes256 } from "./aes";

// Reduction constants for a 4-bit right shift: LAST4[n] = n's bits folded through x^128 + x^7 + x^2 + x + 1.
const LAST4 = new Uint32Array(16);
for (let n = 0; n < 16; n++) {
  let v = 0;
  for (let bit = 0; bit < 4; bit++) if (n & (1 << bit)) v ^= 0xe100 >>> (3 - bit);
  LAST4[n] = v;
}

class Ghash {
  private readonly table = new Uint32Array(16 * 4);
  private readonly y = new Uint8Array(16);

  constructor(h: Uint8Array) {
    const hv = new DataView(h.buffer, h.byteOffset, 16);
    let a0 = hv.getUint32(0), a1 = hv.getUint32(4), a2 = hv.getUint32(8), a3 = hv.getUint32(12);
    const t = this.table;
    t.set([a0, a1, a2, a3], 8 * 4);
    for (let i = 4; i > 0; i >>= 1) {
      const lsb = a3 & 1;
      a3 = ((a2 << 31) | (a3 >>> 1)) >>> 0;
      a2 = ((a1 << 31) | (a2 >>> 1)) >>> 0;
      a1 = ((a0 << 31) | (a1 >>> 1)) >>> 0;
      a0 = a0 >>> 1;
      if (lsb) a0 = (a0 ^ 0xe1000000) >>> 0;
      t.set([a0, a1, a2, a3], i * 4);
    }
    for (let i = 2; i <= 8; i *= 2) {
      for (let j = 1; j < i; j++) {
        for (let k = 0; k < 4; k++) t[(i + j) * 4 + k] = t[i * 4 + k] ^ t[j * 4 + k];
      }
    }
  }

  /** y = (y ^ block) * H */
  private mul(): void {
    const t = this.table;
    const x = this.y;
    let idx = (x[15] & 0xf) * 4;
    let z0 = t[idx], z1 = t[idx + 1], z2 = t[idx + 2], z3 = t[idx + 3];
    for (let i = 15; i >= 0; i--) {
      const lo = (x[i] & 0xf) * 4;
      const hi = ((x[i] >>> 4) & 0xf) * 4;
      if (i !== 15) {
        const rem = z3 & 0xf;
        z3 = ((z2 << 28) | (z3 >>> 4)) >>> 0;
        z2 = ((z1 << 28) | (z2 >>> 4)) >>> 0;
        z1 = ((z0 << 28) | (z1 >>> 4)) >>> 0;
        z0 = ((z0 >>> 4) ^ (LAST4[rem] << 16)) >>> 0;
        z0 ^= t[lo]; z1 ^= t[lo + 1]; z2 ^= t[lo + 2]; z3 ^= t[lo + 3];
      }
      const rem = z3 & 0xf;
      z3 = ((z2 << 28) | (z3 >>> 4)) >>> 0;
      z2 = ((z1 << 28) | (z2 >>> 4)) >>> 0;
      z1 = ((z0 << 28) | (z1 >>> 4)) >>> 0;
      z0 = ((z0 >>> 4) ^ (LAST4[rem] << 16)) >>> 0;
      z0 ^= t[hi]; z1 ^= t[hi + 1]; z2 ^= t[hi + 2]; z3 ^= t[hi + 3];
    }
    const yv = new DataView(x.buffer);
    yv.setUint32(0, z0 >>> 0); yv.setUint32(4, z1 >>> 0); yv.setUint32(8, z2 >>> 0); yv.setUint32(12, z3 >>> 0);
  }

  /** Absorb data, zero-padding the final partial block. */
  update(data: Uint8Array): void {
    const y = this.y;
    for (let off = 0; off < data.length; off += 16) {
      const n = Math.min(16, data.length - off);
      for (let i = 0; i < n; i++) y[i] ^= data[off + i];
      this.mul();
    }
  }

  digest(aadLen: number, ctLen: number): Uint8Array {
    const lens = new Uint8Array(16);
    const v = new DataView(lens.buffer);
    v.setUint32(0, Math.floor((aadLen * 8) / 0x100000000));
    v.setUint32(4, (aadLen * 8) >>> 0);
    v.setUint32(8, Math.floor((ctLen * 8) / 0x100000000));
    v.setUint32(12, (ctLen * 8) >>> 0);
    this.update(lens);
    return this.y.slice();
  }
}

function ctrCrypt(aes: Aes256, nonce: Uint8Array, input: Uint8Array): Uint8Array {
  const out = new Uint8Array(input.length);
  const nv = new DataView(nonce.buffer, nonce.byteOffset, 12);
  const c0 = nv.getUint32(0), c1 = nv.getUint32(4), c2 = nv.getUint32(8);
  const ks = new Uint32Array(4);
  let counter = 2; // J0 uses counter 1; data starts at inc32(J0)
  for (let off = 0; off < input.length; off += 16) {
    aes.encryptWords(c0, c1, c2, counter >>> 0, ks);
    counter = (counter + 1) >>> 0;
    const n = Math.min(16, input.length - off);
    for (let i = 0; i < n; i++) {
      out[off + i] = input[off + i] ^ (ks[i >>> 2] >>> (24 - 8 * (i & 3)));
    }
  }
  return out;
}

function computeTag(aes: Aes256, nonce: Uint8Array, aad: Uint8Array, ciphertext: Uint8Array): Uint8Array {
  const h = aes.encryptBlock(new Uint8Array(16));
  const ghash = new Ghash(h);
  ghash.update(aad);
  ghash.update(ciphertext);
  const s = ghash.digest(aad.length, ciphertext.length);
  const j0 = new Uint8Array(16);
  j0.set(nonce);
  j0[15] = 1;
  const ek = aes.encryptBlock(j0);
  for (let i = 0; i < 16; i++) s[i] ^= ek[i];
  return s;
}

export function gcmEncrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array = new Uint8Array(0)
): { ciphertext: Uint8Array; tag: Uint8Array } {
  if (nonce.length !== 12) throw new Error("AES-GCM nonce must be 12 bytes");
  const aes = new Aes256(key);
  const ciphertext = ctrCrypt(aes, nonce, plaintext);
  return { ciphertext, tag: computeTag(aes, nonce, aad, ciphertext) };
}

/** Returns the plaintext, or null if authentication fails. */
export function gcmDecrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  tag: Uint8Array,
  aad: Uint8Array = new Uint8Array(0)
): Uint8Array | null {
  if (nonce.length !== 12) throw new Error("AES-GCM nonce must be 12 bytes");
  const aes = new Aes256(key);
  const expected = computeTag(aes, nonce, aad, ciphertext);
  let diff = tag.length ^ expected.length;
  for (let i = 0; i < expected.length; i++) diff |= expected[i] ^ (tag[i] ?? 0);
  if (diff !== 0) return null;
  return ctrCrypt(aes, nonce, ciphertext);
}
