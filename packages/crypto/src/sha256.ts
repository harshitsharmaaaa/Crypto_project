// Internal SHA-256 / HMAC-SHA256 / PBKDF2-HMAC-SHA256 (FIPS 180-4, RFC 2104, RFC 8018).

const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

export const SHA256_BLOCK_SIZE = 64;
export const SHA256_DIGEST_SIZE = 32;

const W = new Uint32Array(64);

function compress(h: Uint32Array, block: Uint8Array, offset: number): void {
  for (let i = 0; i < 16; i++) {
    const j = offset + i * 4;
    W[i] = ((block[j] << 24) | (block[j + 1] << 16) | (block[j + 2] << 8) | block[j + 3]) >>> 0;
  }
  for (let i = 16; i < 64; i++) {
    const w15 = W[i - 15];
    const w2 = W[i - 2];
    const s0 = ((w15 >>> 7) | (w15 << 25)) ^ ((w15 >>> 18) | (w15 << 14)) ^ (w15 >>> 3);
    const s1 = ((w2 >>> 17) | (w2 << 15)) ^ ((w2 >>> 19) | (w2 << 13)) ^ (w2 >>> 10);
    W[i] = (W[i - 16] + s0 + W[i - 7] + s1) >>> 0;
  }
  let a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
  for (let i = 0; i < 64; i++) {
    const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
    const ch = (e & f) ^ (~e & g);
    const t1 = (hh + S1 + ch + K[i] + W[i]) >>> 0;
    const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
    const maj = (a & b) ^ (a & c) ^ (b & c);
    const t2 = (S0 + maj) >>> 0;
    hh = g; g = f; f = e;
    e = (d + t1) >>> 0;
    d = c; c = b; b = a;
    a = (t1 + t2) >>> 0;
  }
  h[0] = (h[0] + a) >>> 0; h[1] = (h[1] + b) >>> 0; h[2] = (h[2] + c) >>> 0; h[3] = (h[3] + d) >>> 0;
  h[4] = (h[4] + e) >>> 0; h[5] = (h[5] + f) >>> 0; h[6] = (h[6] + g) >>> 0; h[7] = (h[7] + hh) >>> 0;
}

export function sha256(data: Uint8Array): Uint8Array {
  const h = new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  ]);
  const fullBlocks = Math.floor(data.length / 64);
  for (let i = 0; i < fullBlocks; i++) compress(h, data, i * 64);

  const rem = data.length - fullBlocks * 64;
  const tailLen = rem < 56 ? 64 : 128;
  const tail = new Uint8Array(tailLen);
  tail.set(data.subarray(fullBlocks * 64));
  tail[rem] = 0x80;
  const bitLen = data.length * 8;
  const view = new DataView(tail.buffer);
  view.setUint32(tailLen - 8, Math.floor(bitLen / 0x100000000), false);
  view.setUint32(tailLen - 4, bitLen >>> 0, false);
  for (let i = 0; i < tailLen; i += 64) compress(h, tail, i);

  const out = new Uint8Array(32);
  const ov = new DataView(out.buffer);
  for (let i = 0; i < 8; i++) ov.setUint32(i * 4, h[i], false);
  return out;
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

export function hmacSha256(key: Uint8Array, message: Uint8Array): Uint8Array {
  let k = key.length > SHA256_BLOCK_SIZE ? sha256(key) : key;
  const ipad = new Uint8Array(SHA256_BLOCK_SIZE).fill(0x36);
  const opad = new Uint8Array(SHA256_BLOCK_SIZE).fill(0x5c);
  for (let i = 0; i < k.length; i++) {
    ipad[i] ^= k[i];
    opad[i] ^= k[i];
  }
  return sha256(concat(opad, sha256(concat(ipad, message))));
}

export function pbkdf2Sha256(
  password: Uint8Array,
  salt: Uint8Array,
  iterations: number,
  dkLen: number
): Uint8Array {
  if (!Number.isInteger(iterations) || iterations < 1) throw new Error("PBKDF2: invalid iteration count");
  const out = new Uint8Array(dkLen);
  const blocks = Math.ceil(dkLen / SHA256_DIGEST_SIZE);
  const saltBlock = new Uint8Array(salt.length + 4);
  saltBlock.set(salt);
  const sv = new DataView(saltBlock.buffer);
  for (let i = 1; i <= blocks; i++) {
    sv.setUint32(salt.length, i, false);
    let u = hmacSha256(password, saltBlock);
    const t = u.slice();
    for (let it = 1; it < iterations; it++) {
      u = hmacSha256(password, u);
      for (let j = 0; j < t.length; j++) t[j] ^= u[j];
    }
    const start = (i - 1) * SHA256_DIGEST_SIZE;
    out.set(t.subarray(0, Math.min(SHA256_DIGEST_SIZE, dkLen - start)), start);
  }
  return out;
}
