import { scrypt } from "./scrypt";

export const SALT_BYTE_LENGTH = 16;
export const KEY_BYTE_LENGTH = 32; // 256 bits

export interface ScryptOptions {
  N?: number; // CPU/memory cost factor (default 32768)
  r?: number; // Block size factor (default 8)
  p?: number; // Parallelization factor (default 1)
}

export function generateSalt(length = SALT_BYTE_LENGTH): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(length));
}

export function deriveKey(
  password: string | Uint8Array,
  salt: Uint8Array,
  keyLength = KEY_BYTE_LENGTH,
  options?: ScryptOptions
): Uint8Array {
  if (!password || (typeof password === "string" && password.length === 0)) {
    throw new Error("Password cannot be empty for key derivation");
  }
  if (!salt || salt.length === 0) {
    throw new Error("Salt must be provided for key derivation");
  }

  const N = options?.N ?? 32768; // 2^15
  const r = options?.r ?? 8;
  const p = options?.p ?? 1;

  const passwordBytes = typeof password === "string" ? new TextEncoder().encode(password) : password;
  return scrypt(passwordBytes, salt, keyLength, { N, r, p, maxmem: 64 * 1024 * 1024 });
}
