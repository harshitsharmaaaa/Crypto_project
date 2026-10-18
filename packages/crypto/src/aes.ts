// Internal AES-256 block cipher (FIPS 197), encryption direction only (all that CTR/GCM needs).
// Table-driven (T-tables) for reasonable speed in JS. Not constant-time.

const SBOX = new Uint8Array(256);
const TE0 = new Uint32Array(256);
const TE1 = new Uint32Array(256);
const TE2 = new Uint32Array(256);
const TE3 = new Uint32Array(256);

(function init() {
  // Build S-box from the GF(2^8) multiplicative inverse + affine transform.
  let p = 1;
  let q = 1;
  do {
    p = p ^ ((p << 1) & 0xff) ^ (p & 0x80 ? 0x1b : 0); // p *= 3
    q ^= q << 1; q ^= q << 2; q ^= q << 4; q &= 0xff;   // q /= 3
    if (q & 0x80) q ^= 0x09;
    const rot = (v: number, n: number) => ((v << n) | (v >>> (8 - n))) & 0xff;
    SBOX[p] = q ^ rot(q, 1) ^ rot(q, 2) ^ rot(q, 3) ^ rot(q, 4) ^ 0x63;
  } while (p !== 1);
  SBOX[0] = 0x63;

  for (let i = 0; i < 256; i++) {
    const s = SBOX[i];
    const s2 = (s << 1) ^ (s & 0x80 ? 0x11b : 0);
    const s3 = s2 ^ s;
    const w = ((s2 << 24) | (s << 16) | (s << 8) | s3) >>> 0;
    TE0[i] = w;
    TE1[i] = ((w >>> 8) | (w << 24)) >>> 0;
    TE2[i] = ((w >>> 16) | (w << 16)) >>> 0;
    TE3[i] = ((w >>> 24) | (w << 8)) >>> 0;
  }
})();

function subWord(w: number): number {
  return (
    ((SBOX[w >>> 24] << 24) | (SBOX[(w >>> 16) & 255] << 16) | (SBOX[(w >>> 8) & 255] << 8) | SBOX[w & 255]) >>> 0
  );
}

export const AES_BLOCK_SIZE = 16;

export class Aes256 {
  private readonly rk = new Uint32Array(60);

  constructor(key: Uint8Array) {
    if (key.length !== 32) throw new Error(`AES-256 requires a 32-byte key, got ${key.length}`);
    const rk = this.rk;
    for (let i = 0; i < 8; i++) {
      rk[i] = ((key[4 * i] << 24) | (key[4 * i + 1] << 16) | (key[4 * i + 2] << 8) | key[4 * i + 3]) >>> 0;
    }
    let rcon = 1;
    for (let i = 8; i < 60; i++) {
      let t = rk[i - 1];
      if (i % 8 === 0) {
        t = (subWord(((t << 8) | (t >>> 24)) >>> 0) ^ (rcon << 24)) >>> 0;
        rcon = (rcon << 1) ^ (rcon & 0x80 ? 0x11b : 0);
      } else if (i % 8 === 4) {
        t = subWord(t);
      }
      rk[i] = (rk[i - 8] ^ t) >>> 0;
    }
  }

  /** Encrypt one block given as four big-endian words; writes four words into `out`. */
  encryptWords(s0: number, s1: number, s2: number, s3: number, out: Uint32Array): void {
    const rk = this.rk;
    s0 ^= rk[0]; s1 ^= rk[1]; s2 ^= rk[2]; s3 ^= rk[3];
    let t0 = 0, t1 = 0, t2 = 0, t3 = 0;
    for (let r = 1; r < 14; r++) {
      const k = r * 4;
      t0 = TE0[s0 >>> 24] ^ TE1[(s1 >>> 16) & 255] ^ TE2[(s2 >>> 8) & 255] ^ TE3[s3 & 255] ^ rk[k];
      t1 = TE0[s1 >>> 24] ^ TE1[(s2 >>> 16) & 255] ^ TE2[(s3 >>> 8) & 255] ^ TE3[s0 & 255] ^ rk[k + 1];
      t2 = TE0[s2 >>> 24] ^ TE1[(s3 >>> 16) & 255] ^ TE2[(s0 >>> 8) & 255] ^ TE3[s1 & 255] ^ rk[k + 2];
      t3 = TE0[s3 >>> 24] ^ TE1[(s0 >>> 16) & 255] ^ TE2[(s1 >>> 8) & 255] ^ TE3[s2 & 255] ^ rk[k + 3];
      s0 = t0; s1 = t1; s2 = t2; s3 = t3;
    }
    out[0] = (((SBOX[s0 >>> 24] << 24) | (SBOX[(s1 >>> 16) & 255] << 16) | (SBOX[(s2 >>> 8) & 255] << 8) | SBOX[s3 & 255]) ^ rk[56]) >>> 0;
    out[1] = (((SBOX[s1 >>> 24] << 24) | (SBOX[(s2 >>> 16) & 255] << 16) | (SBOX[(s3 >>> 8) & 255] << 8) | SBOX[s0 & 255]) ^ rk[57]) >>> 0;
    out[2] = (((SBOX[s2 >>> 24] << 24) | (SBOX[(s3 >>> 16) & 255] << 16) | (SBOX[(s0 >>> 8) & 255] << 8) | SBOX[s1 & 255]) ^ rk[58]) >>> 0;
    out[3] = (((SBOX[s3 >>> 24] << 24) | (SBOX[(s0 >>> 16) & 255] << 16) | (SBOX[(s1 >>> 8) & 255] << 8) | SBOX[s2 & 255]) ^ rk[59]) >>> 0;
  }

  encryptBlock(block: Uint8Array): Uint8Array {
    const w = new Uint32Array(4);
    const v = new DataView(block.buffer, block.byteOffset, 16);
    this.encryptWords(v.getUint32(0), v.getUint32(4), v.getUint32(8), v.getUint32(12), w);
    const out = new Uint8Array(16);
    const ov = new DataView(out.buffer);
    for (let i = 0; i < 4; i++) ov.setUint32(i * 4, w[i], false);
    return out;
  }
}
