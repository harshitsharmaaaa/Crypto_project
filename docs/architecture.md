# CryptoWave System Architecture

CryptoWave is a backend-first TypeScript monorepo built with Bun and Turborepo, with an in-repo HTTP router (`packages/http`) and in-repo crypto primitives. It implements password-protected audio steganography using AES-256-GCM authenticated encryption and 1-bit / 2-bit LSB (Least Significant Bit) embedding in 16-bit PCM WAV audio.

## Package Architecture

```
cryptowave/
├── apps/
│   └── api/                  # REST API (in-repo router) (/health, /api/v1/encode, /api/v1/decode, /api/v1/analyze)
├── packages/
│   ├── crypto/               # AES-256-GCM + scrypt KDF + AAD
│   ├── protocol/             # CWAV Binary packet encoder/decoder & validation
│   └── audio/                # RIFF PCM WAV parser/writer + LSB engine + metrics
└── scripts/                  # CLI, E2E Demo, and Robustness tests
```

## Data Flow Pipeline

### Encoding Flow:
Plaintext Message + Password + Carrier WAV 
  ➔ KDF (scrypt, 16-byte random salt) ➔ 32-byte Key
  ➔ AES-256-GCM Encryption (12-byte random nonce, AAD header metadata) ➔ Ciphertext + Auth Tag
  ➔ Binary Protocol Encoding (`CWAV` Magic + Header + Salt + Nonce + Tag + Ciphertext)
  ➔ LSB Embedding into PCM 16-bit Int16Array
  ➔ WAV RIFF Serialization ➔ Stego WAV Output

### Decoding Flow:
Stego WAV Output + Password
  ➔ RIFF PCM Sample Extraction
  ➔ 32-byte Header LSB Extraction & CWAV Validation
  ➔ Total Packet Length Determination & Packet Unpacking
  ➔ KDF (scrypt with extracted Salt) ➔ 32-byte Key
  ➔ AAD Reconstruction & AES-256-GCM Authentication & Decryption
  ➔ Plaintext Message Recovery
