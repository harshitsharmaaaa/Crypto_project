import { Router, t } from "@cryptowave/http";
import { parseWav, extractLSBHeader, calculateMetrics } from "@cryptowave/audio";
import { decodeHeader } from "@cryptowave/protocol";

export const analyzeRoute = new Router().post(
  "/api/v1/analyze",
  async ({ body, set }) => {
    const { originalAudio, stegoAudio, lsbDepth: rawLsbDepth } = body;

    const lsbDepth = rawLsbDepth ? (Number(rawLsbDepth) as 1 | 2) : 1;
    if (lsbDepth !== 1 && lsbDepth !== 2) {
      set.status = 400;
      return { error: "Invalid lsbDepth. Only 1 or 2 supported." };
    }

    const origBuffer = await originalAudio.arrayBuffer();
    const stegoBuffer = await stegoAudio.arrayBuffer();

    let origWav, stegoWav;
    try {
      origWav = parseWav(new Uint8Array(origBuffer));
    } catch (err: any) {
      set.status = 400;
      return { error: `Invalid original WAV audio: ${err.message}` };
    }

    try {
      stegoWav = parseWav(new Uint8Array(stegoBuffer));
    } catch (err: any) {
      set.status = 400;
      return { error: `Invalid stego WAV audio: ${err.message}` };
    }

    if (origWav.samples.length !== stegoWav.samples.length) {
      set.status = 400;
      return {
        error: "Audio length mismatch: original and stego WAV files must have identical sample counts.",
      };
    }

    let detectedPayloadSize = 0;
    try {
      const headerBytes = extractLSBHeader(stegoWav.samples, lsbDepth);
      const header = decodeHeader(headerBytes);
      detectedPayloadSize = header.payloadLength + 32 + header.saltLength + header.nonceLength + header.tagLength;
    } catch {
      // Stego header could not be extracted; payload size defaults to 0
    }

    const metrics = calculateMetrics(
      origWav.samples,
      stegoWav.samples,
      detectedPayloadSize,
      lsbDepth
    );

    return {
      success: true,
      audioProperties: {
        sampleRate: origWav.sampleRate,
        channels: origWav.channels,
        bitsPerSample: origWav.bitsPerSample,
        lsbDepth,
      },
      metrics,
    };
  },
  {
    body: t.Object({
      originalAudio: t.File(),
      stegoAudio: t.File(),
      lsbDepth: t.Optional(t.Union([t.String(), t.Number()])),
    }),
  }
);
