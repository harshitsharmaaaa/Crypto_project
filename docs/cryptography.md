# Cryptographic Design & Specifications

CryptoWave enforces strict cryptographic practices using Node/Bun `crypto` primitives.

## 1. Key Derivation Function (KDF)
- **Algorithm**: `scrypt` (RFC 7914, implemented in `packages/crypto/src/scrypt.ts`; AES-256-GCM in `gcm.ts`/`aes.ts`)
- **Parameters**:
  - CPU/Memory Cost ($N$): $32768$ ($2^{15}$)
  - Block Size ($r$): 8
  - Parallelization ($p$): 1
  - Derived Key Length: 32 bytes (256 bits)
  - Salt Length: 16 bytes (128 bits), randomly generated per encryption.

## 2. Authenticated Cipher
- **Algorithm**: `AES-256-GCM`
- **Key**: 32-byte derived key
- **IV / Nonce**: 12 bytes (96 bits), freshly generated random bytes per encryption.
- **Authentication Tag**: 16 bytes (128 bits).

## 3. Authenticated Additional Data (AAD)
To prevent packet tampering, cross-protocol replay, or format manipulation attacks, CryptoWave constructs 16 bytes of AAD containing protocol header fields:
- Magic bytes (`CWAV`)
- Protocol Version (`1`)
- KDF ID (`1` = scrypt)
- Cipher ID (`1` = AES-256-GCM)
- Sample Rate (uint32)
- Channel Count (uint8)
- Bits per Sample (uint8)
- LSB Depth (uint8)

If an attacker tampers with audio header metadata or packet bytes, AES-GCM authentication fails immediately during decryption.
