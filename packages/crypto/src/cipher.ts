import { deriveKey, generateSalt, KEY_BYTE_LENGTH } from "./kdf";
import { gcmEncrypt, gcmDecrypt } from "./gcm";

export const NONCE_BYTE_LENGTH = 12; // 96 bits for GCM
export const TAG_BYTE_LENGTH = 16;   // 128-bit authentication tag

export interface EncryptionResult {
  ciphertext: Uint8Array;
  nonce: Uint8Array;
  tag: Uint8Array;
  salt?: Uint8Array;
}

export function generateNonce(length = NONCE_BYTE_LENGTH): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(length));
}

export function encryptPayload(
  plaintext: Uint8Array,
  key: Uint8Array,
  aad?: Uint8Array
): EncryptionResult {
  if (key.length !== KEY_BYTE_LENGTH) {
    throw new Error(`Invalid key length for AES-256-GCM: expected ${KEY_BYTE_LENGTH} bytes, got ${key.length}`);
  }

  const nonce = generateNonce();
  const { ciphertext, tag } = gcmEncrypt(key, nonce, plaintext, aad);
  return { ciphertext, nonce, tag };
}

export function decryptPayload(
  ciphertext: Uint8Array,
  key: Uint8Array,
  nonce: Uint8Array,
  tag: Uint8Array,
  aad?: Uint8Array
): Uint8Array {
  if (key.length !== KEY_BYTE_LENGTH) {
    throw new Error(`Invalid key length for AES-256-GCM: expected ${KEY_BYTE_LENGTH} bytes, got ${key.length}`);
  }
  if (nonce.length !== NONCE_BYTE_LENGTH) {
    throw new Error(`Invalid nonce length for AES-256-GCM: expected ${NONCE_BYTE_LENGTH} bytes, got ${nonce.length}`);
  }
  if (tag.length !== TAG_BYTE_LENGTH) {
    throw new Error(`Invalid authentication tag length: expected ${TAG_BYTE_LENGTH} bytes, got ${tag.length}`);
  }

  const plaintext = gcmDecrypt(key, nonce, ciphertext, tag, aad);
  if (!plaintext) {
    throw new Error("AES-GCM decryption / authentication failed. Incorrect password or tampered ciphertext/AAD.");
  }
  return plaintext;
}

export function encryptMessage(
  message: string | Uint8Array,
  password: string,
  aad?: Uint8Array
): EncryptionResult & { salt: Uint8Array } {
  const plaintext = typeof message === "string" ? new TextEncoder().encode(message) : message;
  const salt = generateSalt();
  const key = deriveKey(password, salt);
  
  const result = encryptPayload(plaintext, key, aad);
  return {
    ...result,
    salt,
  };
}

export function decryptMessage(
  ciphertext: Uint8Array,
  password: string,
  salt: Uint8Array,
  nonce: Uint8Array,
  tag: Uint8Array,
  aad?: Uint8Array
): Uint8Array {
  const key = deriveKey(password, salt);
  return decryptPayload(ciphertext, key, nonce, tag, aad);
}

export function encryptBytes(
  plaintext: Uint8Array,
  password: string,
  aad?: Uint8Array
): EncryptionResult & { salt: Uint8Array } {
  return encryptMessage(plaintext, password, aad);
}

export function decryptBytes(
  ciphertext: Uint8Array,
  password: string,
  salt: Uint8Array,
  nonce: Uint8Array,
  tag: Uint8Array,
  aad?: Uint8Array
): Uint8Array {
  return decryptMessage(ciphertext, password, salt, nonce, tag, aad);
}
