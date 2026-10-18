// Internal scrypt (RFC 7914) built on the internal PBKDF2-HMAC-SHA256.
import { pbkdf2Sha256 } from "./sha256";

export interface ScryptParams {
  N: number;
  r: number;
  p: number;
  maxmem: number;
}

const x = new Int32Array(16);

function rotl(v: number, n: number): number {
  return (v << n) | (v >>> (32 - n));
}

/** Salsa20/8 core. Reads 16 words from `b` at `bo`, writes the result back in place. */
function salsa8(b: Int32Array, bo: number): void {
  for (let i = 0; i < 16; i++) x[i] = b[bo + i];
  for (let i = 0; i < 8; i += 2) {
    x[4] ^= rotl((x[0] + x[12]) | 0, 7);  x[8] ^= rotl((x[4] + x[0]) | 0, 9);
    x[12] ^= rotl((x[8] + x[4]) | 0, 13); x[0] ^= rotl((x[12] + x[8]) | 0, 18);
    x[9] ^= rotl((x[5] + x[1]) | 0, 7);   x[13] ^= rotl((x[9] + x[5]) | 0, 9);
    x[1] ^= rotl((x[13] + x[9]) | 0, 13); x[5] ^= rotl((x[1] + x[13]) | 0, 18);
    x[14] ^= rotl((x[10] + x[6]) | 0, 7); x[2] ^= rotl((x[14] + x[10]) | 0, 9);
    x[6] ^= rotl((x[2] + x[14]) | 0, 13); x[10] ^= rotl((x[6] + x[2]) | 0, 18);
    x[3] ^= rotl((x[15] + x[11]) | 0, 7); x[7] ^= rotl((x[3] + x[15]) | 0, 9);
    x[11] ^= rotl((x[7] + x[3]) | 0, 13); x[15] ^= rotl((x[11] + x[7]) | 0, 18);

    x[1] ^= rotl((x[0] + x[3]) | 0, 7);   x[2] ^= rotl((x[1] + x[0]) | 0, 9);
    x[3] ^= rotl((x[2] + x[1]) | 0, 13);  x[0] ^= rotl((x[3] + x[2]) | 0, 18);
    x[6] ^= rotl((x[5] + x[4]) | 0, 7);   x[7] ^= rotl((x[6] + x[5]) | 0, 9);
    x[4] ^= rotl((x[7] + x[6]) | 0, 13);  x[5] ^= rotl((x[4] + x[7]) | 0, 18);
    x[11] ^= rotl((x[10] + x[9]) | 0, 7); x[8] ^= rotl((x[11] + x[10]) | 0, 9);
    x[9] ^= rotl((x[8] + x[11]) | 0, 13); x[10] ^= rotl((x[9] + x[8]) | 0, 18);
    x[12] ^= rotl((x[15] + x[14]) | 0, 7); x[13] ^= rotl((x[12] + x[15]) | 0, 9);
    x[14] ^= rotl((x[13] + x[12]) | 0, 13); x[15] ^= rotl((x[14] + x[13]) | 0, 18);
  }
  for (let i = 0; i < 16; i++) b[bo + i] = (b[bo + i] + x[i]) | 0;
}

/** scryptBlockMix: B (32*r words) -> B', using `y` (32*r words) as scratch. */
function blockMix(b: Int32Array, y: Int32Array, r: number): void {
  const t = new Int32Array(16);
  const last = (2 * r - 1) * 16;
  for (let i = 0; i < 16; i++) t[i] = b[last + i];
  for (let i = 0; i < 2 * r; i++) {
    for (let k = 0; k < 16; k++) t[k] ^= b[i * 16 + k];
    salsa8(t, 0);
    // even blocks go to the first half of the output, odd blocks to the second half
    const dst = ((i & 1) === 0 ? i / 2 : r + (i - 1) / 2) * 16;
    for (let k = 0; k < 16; k++) y[dst + k] = t[k];
  }
  b.set(y);
}

function roMix(block: Uint8Array, N: number, r: number): void {
  const words = 32 * r;
  const xw = new Int32Array(words);
  const view = new DataView(block.buffer, block.byteOffset, block.byteLength);
  for (let i = 0; i < words; i++) xw[i] = view.getInt32(i * 4, true);

  const v = new Int32Array(words * N);
  const y = new Int32Array(words);
  for (let i = 0; i < N; i++) {
    v.set(xw, i * words);
    blockMix(xw, y, r);
  }
  for (let i = 0; i < N; i++) {
    const j = (xw[(2 * r - 1) * 16] >>> 0) & (N - 1);
    const off = j * words;
    for (let k = 0; k < words; k++) xw[k] ^= v[off + k];
    blockMix(xw, y, r);
  }
  for (let i = 0; i < words; i++) view.setInt32(i * 4, xw[i], true);
}

export function scrypt(
  password: Uint8Array,
  salt: Uint8Array,
  keyLength: number,
  params: ScryptParams
): Uint8Array {
  const { N, r, p, maxmem } = params;
  if (!Number.isInteger(N) || N < 2 || (N & (N - 1)) !== 0 || N > 0x80000000) {
    throw new Error("Invalid scrypt parameter: N must be a power of 2 greater than 1");
  }
  if (!Number.isInteger(r) || r < 1 || !Number.isInteger(p) || p < 1) {
    throw new Error("Invalid scrypt parameter: r and p must be positive integers");
  }
  if (128 * N * r + 128 * r * p > maxmem) {
    throw new Error("Invalid scrypt parameter: memory limit exceeded");
  }
  const blockBytes = 128 * r;
  const b = pbkdf2Sha256(password, salt, 1, p * blockBytes);
  for (let i = 0; i < p; i++) {
    roMix(b.subarray(i * blockBytes, (i + 1) * blockBytes), N, r);
  }
  return pbkdf2Sha256(password, b, 1, keyLength);
}
