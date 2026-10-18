# 🌊 CryptoWave — Password-Protected Audio Steganography Laboratory

> Hide encrypted secrets inside WAV audio with **AES-256-GCM + scrypt** and **1/2-bit LSB steganography** — wrapped in a versioned `CWAV` binary protocol, a typed REST API on an in-repo HTTP router, and a Next.js security-console frontend.

![TypeScript](https://img.shields.io/badge/TypeScript-5.7-3178C6?logo=typescript&logoColor=white)
![Bun](https://img.shields.io/badge/Bun-1.3-black?logo=bun&logoColor=white)
![Turborepo](https://img.shields.io/badge/Turborepo-2.4-EF4444?logo=turborepo&logoColor=white)
![Next.js](https://img.shields.io/badge/Next.js-15-black?logo=next.js&logoColor=white)

---

## ✨ Why CryptoWave?

| Concern | How CryptoWave solves it |
|---------|--------------------------|
| **Confidentiality** | Every message is encrypted with `AES-256-GCM` — fresh 12-byte nonce + 16-byte tag per operation |
| **Password hardening** | Keys derived via `scrypt` (`N=32768, r=8, p=1`), 16-byte random salt per encryption |
| **Tamper evidence** | `CWAV` header fields (magic, version, KDF, cipher, sample-rate, channels, LSB depth) bound as AAD |
| **Imperceptibility** | 1-bit LSB → SNR > 100 dB; 2-bit LSB → 2× capacity at SNR > 90 dB |
| **Safety** | Strict capacity checks, magic/version validation, truncation guards |

---

## 🏗️ Monorepo Architecture

```text
cryptowave/
├── packages/
│   ├── protocol/   # CWAV v1 binary packet — encode / decode / validate
│   ├── crypto/     # in-repo scrypt KDF + AES-256-GCM (SHA-256, AES, GHASH implemented here)
│   ├── http/       # in-repo HTTP router, CORS and body validation (replaces Elysia)
│   └── audio/      # RIFF PCM WAV codec + LSB engine + SNR metrics
├── apps/
│   ├── api/        # REST API — /health, /api/v1/encode|decode|analyze
│   └── web/        # Next.js 15 laboratory — encode, decode, analyze, attack-lab
├── scripts/        # CLI, E2E demo, integration + robustness harnesses
├── docs/           # Architecture, protocol spec, cryptography, threat model
└── samples/        # Carrier WAV fixtures for local testing
```

**Encode pipeline:**

```text
message + password ──▶ scrypt ──▶ AES-256-GCM (+ AAD) ──▶ CWAV packet ──▶ LSB embed ──▶ stego.wav
audio carrier ────────────────────────────────────────────────────────────────────────────▲
```

**Decode pipeline:**

```text
stego.wav ──▶ LSB extract ──▶ CWAV validate ──▶ AES-256-GCM verify (+ AAD) ──▶ message
```

---

## 🚀 Quick Start

**Prerequisites:** [Bun](https://bun.sh) v1.0+

```bash
# 1. Install
bun install

# 2. Type-check
bun run check-types

# 3. Test (unit + API integration)
bun run test

# 4. E2E terminal demo
bun run demo

# 5. Run services (in two terminals)
bun --watch apps/api/src/server.ts   # API → http://localhost:3001
bun --cwd apps/web dev               # Web → http://localhost:3000
```

### Developer CLI

```bash
bun run cli encode    --in samples/carrier.wav --out samples/stego.wav --message "hello wave" --password "s3cret"
bun run cli decode    --in samples/stego.wav --password "s3cret"
bun run cli analyze   --original samples/carrier.wav --stego samples/stego.wav
```

---

## 📦 Packages

### `packages/protocol` — CWAV v1 packet

Versioned binary layout: `magic 'CWAV' (4B) | version | kdfId | cipherId | flags | sampleRate (u32) | channels | bitsPerSample | lsbDepth | reserved | saltLen | nonceLen | tagLen | payloadLen (u32) | salt | nonce | tag | ciphertext`.

- `encodePacket()` / `decodePacket()` with magic, version, and bounds validation
- `KdfAlgorithm.SCRYPT`, `CipherAlgorithm.AES_256_GCM`, `PROTOCOL_VERSION = 1`

### `packages/crypto` — Authenticated encryption

- `deriveKey(password, salt)` via the in-repo `scrypt` (RFC 7914)
- `encryptMessage(message, password, aad)` → `{ ciphertext, salt, nonce, tag }`
- `decryptMessage(...)` — wrong password / tampered AAD fails closed with auth error
- Full UTF-8 / Unicode support

### `packages/audio` — WAV + LSB

- `parseWav()` / `writeWav()` — strict 16-bit PCM RIFF handling, no Float32 resampling loss
- `embedLSB()` / `extractLSB()` — 1-bit (transparent) and 2-bit (high-capacity) modes
- `calculateCapacity()` + `calculateMetrics()` — RMS error, SNR (dB), changed samples/bits

---

## 🌐 API (`apps/api`)

| Method | Route | Description |
|--------|-------|-------------|
| `GET` | `/health` | Liveness probe |
| `POST` | `/api/v1/encode` | `multipart: audio, message, password, lsbDepth` → `audio/wav` + `X-CryptoWave-Metrics` |
| `POST` | `/api/v1/decode` | `multipart: audio, password` → `{ message, header }` |
| `POST` | `/api/v1/analyze` | `multipart: original?, stego` → `{ metrics, header? }` |

Capacity overflow, invalid WAV, and auth failures return typed `400/401` JSON errors.

---

## 🖥️ Web (`apps/web` — Next.js 15)

Dark engineering-console UI (`zinc-950`, mono accents) with five routes:

- `/encode` — upload carrier, set password, preview capacity, download stego + metrics
- `/decode` — upload stego, recover message + header inspector
- `/analyze` — waveform / spectrogram visualizers, SNR telemetry
- `/attack-lab` — wrong-password, bit-flip, and amplitude-scale robustness matrix
- `/docs` — in-app protocol + cryptography reference

---

## 🧪 Testing & Robustness

```bash
bun test                              # unit (crypto/protocol/audio) + API integration
bun run scripts/integration-test.ts   # full encode → decode round-trip
bun run scripts/robustness-test.ts    # tamper / wrong-password / scaling matrix
```

Covered: KDF determinism, GCM auth failure on wrong password, AAD binding, packet truncation, WAV round-trip, LSB 1/2-bit round-trip, capacity enforcement, HTTP encode/decode/analyze.

---

## 📚 Docs

| Document | Contents |
|----------|----------|
| `docs/architecture.md` | System + data-flow design |
| `docs/protocol.md` | CWAV byte layout spec |
| `docs/cryptography.md` | KDF / cipher / AAD parameters |
| `docs/audio-steganography.md` | LSB + SNR math |
| `docs/threat-model.md` | Guarantees & non-guarantees |
| `docs/testing.md` | Suite map |
| `docs/demo-guide.md` | E2E walkthrough |
| `docs/frontend-design.md` | Design-system tokens |
| `docs/research.md` | Technical decisions |

> ⚠️ **Scope note:** LSB steganography does not survive MP3/AAC compression, resampling, or amplitude scaling, and is not immune to statistical steganalysis. CryptoWave guarantees cryptographic confidentiality + tamper evidence, not undetectability.

---

## 🛠️ Tech Stack

**Runtime / Toolchain:** Bun 1.3 · TypeScript 5.7 (strict) · Turborepo 2.4
**Backend:** no third-party runtime dependencies — `@cryptowave/http` (router/CORS/validation) and `@cryptowave/crypto` (AES-256-GCM, scrypt, SHA-256) are implemented in this repo

> **Security note:** the cryptographic primitives are hand-written for educational purposes. They are verified against NIST/RFC test vectors and `node:crypto` (see `packages/crypto/src/internal-vs-node.test.ts`), but are not constant-time or audited. Do not use them to protect real secrets.
**Frontend:** Next.js 15 · React 19 · Tailwind CSS · lucide-react · `clsx` + `tailwind-merge`

---

## 📄 License

MIT — built for learning, security experimentation, and demonstration purposes.

<p align="center">Made with 🌊 by <b>harshitsharmaaaa</b> · <code>CWAV v1</code></p>
