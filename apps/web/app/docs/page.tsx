import { BookOpen, ShieldCheck, Lock, Radio, Cpu, FileText, Terminal } from "lucide-react";

export default function DocsPage() {
  return (
    <div className="mx-auto max-w-7xl px-4 py-8 sm:px-6 space-y-8 font-mono">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-zinc-800 pb-4">
        <div>
          <h1 className="flex items-center gap-2 text-xl font-bold text-zinc-100">
            <BookOpen className="h-5 w-5 text-emerald-400" /> CryptoWave System & Technical Documentation
          </h1>
          <p className="mt-1 font-sans text-xs text-zinc-400">
            In-depth architecture specification, cryptographic parameters, binary packet format, audio steganography algorithms, and threat model.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
        {/* Main Content Area (8 Cols) */}
        <div className="lg:col-span-8 space-y-8">
          {/* Section 1: Architecture */}
          <section className="rounded-lg border border-zinc-800 bg-zinc-900 p-6 space-y-4">
            <h2 className="flex items-center gap-2 text-sm font-semibold text-emerald-400">
              <Cpu className="h-4 w-4" /> 1. SYSTEM ARCHITECTURE
            </h2>
            <p className="font-sans text-xs text-zinc-300 leading-relaxed">
              CryptoWave is structured as a Bun/TypeScript monorepo using Turborepo. It cleanly decouples cryptographic operations (`@cryptowave/crypto`), binary protocol packing (`@cryptowave/protocol`), audio sample processing (`@cryptowave/audio`), and REST endpoints (`apps/api`).
            </p>
            <div className="rounded border border-zinc-800 bg-zinc-950 p-4 text-[11px] text-zinc-300 font-mono">
              cryptowave/ <br />
              ├── apps/ <br />
              │ ├── api/ # REST API (/encode, /decode, /analyze) <br />
              │ └── web/ # Next.js 15 App Router Security Console <br />
              ├── packages/ <br />
              │ ├── crypto/ # AES-256-GCM + scrypt KDF + AAD <br />
              │ ├── protocol/ # CWAV binary packet encoder/decoder <br />
              │ └── audio/ # RIFF PCM-16 WAV parser/writer + LSB engine <br />
            </div>
          </section>

          {/* Section 2: Cryptography */}
          <section className="rounded-lg border border-zinc-800 bg-zinc-900 p-6 space-y-4">
            <h2 className="flex items-center gap-2 text-sm font-semibold text-cyan-400">
              <Lock className="h-4 w-4" /> 2. CRYPTOGRAPHIC SPECIFICATION
            </h2>
            <div className="space-y-3 text-xs text-zinc-300 font-sans leading-relaxed">
              <div>
                <strong className="font-mono text-emerald-400 font-semibold">Key Derivation (scrypt KDF):</strong>
                <p className="mt-0.5 text-zinc-400">
                  Password key derivation uses scrypt with cost parameters N=32768 (2^15), r=8, p=1, producing a 32-byte (256-bit) AES key with a fresh 16-byte random salt per operation.
                </p>
              </div>

              <div>
                <strong className="font-mono text-emerald-400 font-semibold">Cipher (AES-256-GCM):</strong>
                <p className="mt-0.5 text-zinc-400">
                  Authenticated encryption using AES-256 in Galois/Counter Mode (GCM). Generates a fresh 12-byte random IV/nonce per encryption and a 16-byte authentication tag.
                </p>
              </div>

              <div>
                <strong className="font-mono text-emerald-400 font-semibold">Authenticated Additional Data (AAD):</strong>
                <p className="mt-0.5 text-zinc-400">
                  16 bytes of header metadata (Magic 'CWAV', protocol version, KDF ID, cipher ID, sample rate, channels, bit depth) are bound into GCM authentication. Tampering with header fields causes decryption failure.
                </p>
              </div>
            </div>
          </section>

          {/* Section 3: CWAV Packet Specification */}
          <section className="rounded-lg border border-zinc-800 bg-zinc-900 p-6 space-y-4">
            <h2 className="flex items-center gap-2 text-sm font-semibold text-purple-400">
              <FileText className="h-4 w-4" /> 3. CWAV BINARY PACKET LAYOUT
            </h2>
            <p className="font-sans text-xs text-zinc-300 leading-relaxed">
              The embedded payload is structured into a versioned binary format starting with a fixed 32-byte header:
            </p>

            <div className="rounded border border-zinc-800 bg-zinc-950 p-4 text-[11px] font-mono text-zinc-300 space-y-1">
              <div>00..03: Magic Bytes ('C' 'W' 'A' 'V')</div>
              <div>04: Protocol Version (1)</div>
              <div>05: KDF Algorithm ID (1 = scrypt)</div>
              <div>06: Cipher Algorithm ID (1 = AES-256-GCM)</div>
              <div>08..11: Sample Rate (uint32 BE)</div>
              <div>12: Channels (1=mono, 2=stereo)</div>
              <div>13: Bits per Sample (16)</div>
              <div>14: LSB Depth (1 or 2)</div>
              <div>16..19: Salt Length (uint32 BE = 16)</div>
              <div>20..23: Nonce Length (uint32 BE = 12)</div>
              <div>24..27: Tag Length (uint32 BE = 16)</div>
              <div>28..31: Encrypted Payload Length (uint32 BE)</div>
              <div>32..47: Salt Bytes (16B)</div>
              <div>48..59: Nonce Bytes (12B)</div>
              <div>60..75: Auth Tag Bytes (16B)</div>
              <div>76..N : Encrypted Ciphertext Payload</div>
            </div>
          </section>
        </div>

        {/* Sidebar Summary (4 Cols) */}
        <div className="lg:col-span-4 space-y-6">
          <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-5 space-y-4">
            <h3 className="flex items-center gap-2 text-xs font-semibold text-zinc-200">
              <ShieldCheck className="h-4 w-4 text-emerald-400" /> THREAT MODEL SUMMARY
            </h3>

            <div className="space-y-3 text-xs font-sans text-zinc-300">
              <div className="space-y-1">
                <span className="font-mono text-emerald-400 font-semibold text-[11px]">PROTECTED:</span>
                <p className="text-[11px] text-zinc-400">
                  Confidentiality of message payload without password. Detection of ciphertext or sample tampering via GCM auth tag.
                </p>
              </div>

              <div className="space-y-1 border-t border-zinc-800 pt-2">
                <span className="font-mono text-rose-400 font-semibold text-[11px]">NOT GUARANTEED:</span>
                <p className="text-[11px] text-zinc-400">
                  Immunity against high-order statistical steganalysis or lossy audio compression (MP3/AAC). Requires lossless WAV transmission.
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
