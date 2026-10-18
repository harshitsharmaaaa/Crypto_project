import { expect, test, describe } from "bun:test";
import { createCipheriv, createDecipheriv, scryptSync, pbkdf2Sync, createHmac, createHash, randomBytes } from "node:crypto";
import { gcmEncrypt, gcmDecrypt } from "./gcm";
import { scrypt } from "./scrypt";
import { sha256, hmacSha256, pbkdf2Sha256 } from "./sha256";
import { Aes256 } from "./aes";

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const fromHex = (s: string) => new Uint8Array(Buffer.from(s, "hex"));
const utf8 = (s: string) => new TextEncoder().encode(s);

describe("internal primitives: known-answer vectors", () => {
  test("AES-256 FIPS-197 C.3", () => {
    const key = fromHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    const pt = fromHex("00112233445566778899aabbccddeeff");
    expect(hex(new Aes256(key).encryptBlock(pt))).toBe("8ea2b7ca516745bfeafc49904b496089");
  });

  test("AES-256-GCM NIST test case 16 (with AAD)", () => {
    const key = fromHex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
    const nonce = fromHex("cafebabefacedbaddecaf888");
    const pt = fromHex(
      "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"
    );
    const aad = fromHex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
    const { ciphertext, tag } = gcmEncrypt(key, nonce, pt, aad);
    expect(hex(ciphertext)).toBe(
      "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662"
    );
    expect(hex(tag)).toBe("76fc6ece0f4e1768cddf8853bb2d551b");
    expect(hex(gcmDecrypt(key, nonce, ciphertext, tag, aad)!)).toBe(hex(pt));
  });

  test("SHA-256 / HMAC / PBKDF2", () => {
    expect(hex(sha256(utf8("abc")))).toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    expect(hex(hmacSha256(utf8("Jefe"), utf8("what do ya want for nothing?")))).toBe(
      "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    );
    expect(hex(pbkdf2Sha256(utf8("password"), utf8("salt"), 2, 32))).toBe(
      "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"
    );
  });

  test("scrypt RFC 7914 vectors", () => {
    expect(hex(scrypt(utf8(""), utf8(""), 64, { N: 16, r: 1, p: 1, maxmem: 1 << 26 }))).toBe(
      "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906"
    );
    expect(hex(scrypt(utf8("password"), utf8("NaCl"), 64, { N: 1024, r: 8, p: 16, maxmem: 1 << 26 }))).toBe(
      "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640"
    );
  });
});

describe("internal primitives: cross-check against node:crypto", () => {
  test("AES-256-GCM random inputs, both directions", () => {
    for (const len of [0, 1, 15, 16, 17, 31, 32, 100, 1000, 4097]) {
      for (const aadLen of [0, 5, 16, 33]) {
        const key = randomBytes(32), nonce = randomBytes(12), pt = randomBytes(len), aad = randomBytes(aadLen);
        const mine = gcmEncrypt(new Uint8Array(key), new Uint8Array(nonce), new Uint8Array(pt), new Uint8Array(aad));
        const c = createCipheriv("aes-256-gcm", key, nonce);
        if (aadLen) c.setAAD(aad);
        const ref = Buffer.concat([c.update(pt), c.final()]);
        expect(hex(mine.ciphertext)).toBe(ref.toString("hex"));
        expect(hex(mine.tag)).toBe(c.getAuthTag().toString("hex"));

        const d = createDecipheriv("aes-256-gcm", key, nonce);
        d.setAuthTag(Buffer.from(mine.tag));
        if (aadLen) d.setAAD(aad);
        expect(Buffer.concat([d.update(mine.ciphertext), d.final()]).equals(pt)).toBe(true);
      }
    }
  });

  test("GCM rejects tampering", () => {
    const key = new Uint8Array(randomBytes(32)), nonce = new Uint8Array(randomBytes(12));
    const { ciphertext, tag } = gcmEncrypt(key, nonce, utf8("hello world"), utf8("aad"));
    const bad = ciphertext.slice(); bad[0] ^= 1;
    expect(gcmDecrypt(key, nonce, bad, tag, utf8("aad"))).toBeNull();
    expect(gcmDecrypt(key, nonce, ciphertext, tag, utf8("AAD"))).toBeNull();
  });

  test("scrypt default params match node", () => {
    const salt = randomBytes(16);
    const ref = scryptSync("pässword", salt, 32, { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
    const t0 = performance.now();
    const mine = scrypt(utf8("pässword"), new Uint8Array(salt), 32, { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
    console.log(`internal scrypt N=32768 took ${(performance.now() - t0).toFixed(0)} ms`);
    expect(hex(mine)).toBe(ref.toString("hex"));
  });

  test("sha256 / hmac / pbkdf2 random inputs", () => {
    for (const len of [0, 1, 55, 56, 63, 64, 65, 119, 120, 1000]) {
      const d = randomBytes(len), k = randomBytes(len % 100);
      expect(hex(sha256(new Uint8Array(d)))).toBe(createHash("sha256").update(d).digest("hex"));
      expect(hex(hmacSha256(new Uint8Array(k), new Uint8Array(d)))).toBe(createHmac("sha256", k).update(d).digest("hex"));
    }
    const p = randomBytes(20), s = randomBytes(16);
    expect(hex(pbkdf2Sha256(new Uint8Array(p), new Uint8Array(s), 7, 70))).toBe(pbkdf2Sync(p, s, 7, 70, "sha256").toString("hex"));
  });
});
