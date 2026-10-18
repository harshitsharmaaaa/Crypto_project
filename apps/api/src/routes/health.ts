import { Router } from "@cryptowave/http";

export const healthRoute = new Router().get("/health", () => ({
  status: "ok",
  timestamp: new Date().toISOString(),
  service: "CryptoWave API",
  version: "1.0.0",
}));
