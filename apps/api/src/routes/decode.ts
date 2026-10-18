import { Router, t } from "@cryptowave/http";
import { parseWav, extractLSB, extractLSBHeader, extractRecoveryChunk } from "@cryptowave/audio";
import { decryptMessage } from "@cryptowave/crypto";
import {
  decodeHeader,
  decodePacket,
  KdfAlgorithm,
  CipherAlgorithm,
  PROTOCOL_VERSION,
  HEADER_SIZE,
} from "@cryptowave/protocol";

export const decodeRoute = new Router().post(
  "/api/v1/decode",
  async ({ body, set }) => {
    const { stegoAudio, password, lsbDepth: rawLsbDepth } = body;

    const lsbDepth = rawLsbDepth ? (Number(rawLsbDepth) as 1 | 2) : 1;
    if (lsbDepth !== 1 && lsbDepth !== 2) {
      set.status = 400;
      return { error: "Invalid lsbDepth. Only 1 or 2 supported." };
    }

    if (!password || password.length === 0) {
      set.status = 400;
      return { error: "Password cannot be empty" };
    }

    const audioArrayBuffer = await stegoAudio.arrayBuffer();
    const audioBytes = new Uint8Array(audioArrayBuffer);

    let wavAudio;
    try {
      wavAudio = parseWav(audioBytes);
    } catch (err: any) {
      set.status = 400;
      return { error: `Invalid stego audio file: ${err.message}` };
    }

    // Probe for the original-audio recovery chunk. This is additive: legacy
    // stego WAVs without a recovery chunk still decode their messages, but the
    // caller is told that original-audio restoration is unavailable.
    let recoveryAvailable = false;
    try {
      extractRecoveryChunk(audioBytes);
      recoveryAvailable = true;
    } catch {
      recoveryAvailable = false;
    }

    
    let headerBytes;
    try {
      headerBytes = extractLSBHeader(wavAudio.samples, lsbDepth);
    } catch (err: any) {
      set.status = 400;
      return { error: `Failed to extract header bits: ${err.message}` };
    }

    
    let header;
    try {
      header = decodeHeader(headerBytes);
    } catch (err: any) {
      set.status = 400;
      return { error: `Invalid steganographic packet header: ${err.message}` };
    }

    // Step 3: Calculate total packet size and extract full packet
    const totalPacketSize =
      HEADER_SIZE +
      header.saltLength +
      header.nonceLength +
      header.tagLength +
      header.payloadLength;

    let fullPacketBytes;
    try {
      fullPacketBytes = extractLSB(wavAudio.samples, totalPacketSize, lsbDepth);
    } catch (err: any) {
      set.status = 400;
      return { error: `Failed to extract embedded packet bits: ${err.message}` };
    }

    // Step 4: Unpack packet
    const packet = decodePacket(fullPacketBytes);

    // Step 5: Reconstruct AAD
    const aadBuffer = new Uint8Array(16);
    const aadView = new DataView(aadBuffer.buffer);
    aadBuffer.set([0x43, 0x57, 0x41, 0x56], 0);
    aadView.setUint8(4, header.version);
    aadView.setUint8(5, header.kdfId);
    aadView.setUint8(6, header.cipherId);
    aadView.setUint8(7, header.flags);
    aadView.setUint32(8, wavAudio.sampleRate, false);
    aadView.setUint8(12, wavAudio.channels);
    aadView.setUint8(13, wavAudio.bitsPerSample);
    aadView.setUint8(14, lsbDepth);
    aadView.setUint8(15, 0);

    // Step 6: Decrypt payload
    try {
      const plaintextBytes = decryptMessage(
        packet.encryptedPayload,
        password,
        packet.salt,
        packet.nonce,
        packet.tag,
        aadBuffer
      );
      const message = new TextDecoder("utf-8").decode(plaintextBytes);

      return {
        success: true,
        message,
        recoveryAvailable,
        packetInfo: {
          version: header.version,
          kdf: KdfAlgorithm[header.kdfId] || header.kdfId,
          cipher: CipherAlgorithm[header.cipherId] || header.cipherId,
          payloadSize: header.payloadLength,
          sampleRate: wavAudio.sampleRate,
          channels: wavAudio.channels,
          lsbDepth,
        },
      };
    } catch (err: any) {
      set.status = 401; // Unauthorized / Decryption failure
      return {
        error: "Authentication failed. Incorrect password or tampered stego payload.",
      };
    }
  },
  {
    body: t.Object({
      stegoAudio: t.File(),
      password: t.String(),
      lsbDepth: t.Optional(t.Union([t.String(), t.Number()])),
    }),
  }
);
