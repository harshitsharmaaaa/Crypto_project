import { Router, t } from "@cryptowave/http";
import { extractRecoveryChunk, buildRecoveryAad } from "@cryptowave/audio";
import { decryptBytes } from "@cryptowave/crypto";

// Bounded upload ceiling for the restore endpoint, matching the encode route.
const MAX_RESTORE_UPLOAD_SIZE = 160 * 1024 * 1024; // 160 MB

export const restoreRoute = new Router().post(
  "/api/v1/restore",
  async ({ body, set }) => {
    const { stegoAudio, password } = body;

    if (!password || password.length === 0) {
      set.status = 400;
      return { error: "Password cannot be empty" };
    }

    const audioArrayBuffer = await stegoAudio.arrayBuffer();
    const audioBytes = new Uint8Array(audioArrayBuffer);

    if (audioBytes.length > MAX_RESTORE_UPLOAD_SIZE) {
      set.status = 413;
      return {
        error: `Upload size (${audioBytes.length} bytes) exceeds the maximum allowed limit of ${MAX_RESTORE_UPLOAD_SIZE} bytes.`,
      };
    }

    let recovery;
    try {
      recovery = extractRecoveryChunk(audioBytes);
    } catch (err: any) {
      if (err.code === "RECOVERY_CHUNK_NOT_FOUND") {
        set.status = 400;
        set.headers["X-CryptoWave-Error-Code"] = "RECOVERY_CHUNK_NOT_FOUND";
        return {
          error:
            "Original audio recovery is unavailable: this stego WAV does not contain a recovery chunk (legacy file created before recovery support, or not produced by CryptoWave).",
        };
      }
      set.status = 400;
      set.headers["X-CryptoWave-Error-Code"] = "RECOVERY_FORMAT_INVALID";
      return { error: `Invalid recovery chunk: ${err.message}` };
    }

    const recoveryAad = buildRecoveryAad(recovery.originalLength);

    let originalBytes: Uint8Array;
    try {
      originalBytes = decryptBytes(
        recovery.ciphertext,
        password,
        recovery.salt,
        recovery.nonce,
        recovery.tag,
        recoveryAad
      );
    } catch {
      set.status = 401;
      set.headers["X-CryptoWave-Error-Code"] = "RECOVERY_AUTH_FAILED";
      return {
        error:
          "Authentication failed. Incorrect password or tampered recovery data. The original WAV could not be restored.",
      };
    }

    // Sanity check: the decrypted bytes must be a valid WAV container. Because
    // the recovery payload was authenticated with AES-GCM, this is a defense-
    // in-depth check rather than a security boundary.
    if (
      originalBytes.length < 12 ||
      String.fromCharCode(originalBytes[0], originalBytes[1], originalBytes[2], originalBytes[3]) !== "RIFF" ||
      String.fromCharCode(originalBytes[8], originalBytes[9], originalBytes[10], originalBytes[11]) !== "WAVE"
    ) {
      set.status = 422;
      set.headers["X-CryptoWave-Error-Code"] = "RECOVERY_PAYLOAD_INVALID";
      return {
        error:
          "Recovered bytes are not a valid WAV container. The recovery data may be corrupted or not produced by CryptoWave.",
      };
    }

    set.headers["Content-Type"] = "audio/wav";
    set.headers["Content-Disposition"] = 'attachment; filename="original.wav"';

    return new Response(Buffer.from(originalBytes), {
      headers: {
        "Content-Type": "audio/wav",
        "Content-Disposition": 'attachment; filename="original.wav"',
      },
    });
  },
  {
    body: t.Object({
      stegoAudio: t.File(),
      password: t.String(),
    }),
  }
);