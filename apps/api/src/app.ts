import { Router, cors } from "@cryptowave/http";
import { healthRoute } from "./routes/health";
import { encodeRoute } from "./routes/encode";
import { decodeRoute } from "./routes/decode";
import { analyzeRoute } from "./routes/analyze";
import { restoreRoute } from "./routes/restore";

export const app = new Router()
  .use(
    cors({
      origin: true, // Allow any origin in dev or specify client port
      allowedHeaders: ["Content-Type", "Authorization", "Accept"],
      exposeHeaders: ["Content-Disposition", "X-CryptoWave-Metrics", "X-CryptoWave-Error-Code"],
    })
  )
  .use(healthRoute)
  .use(encodeRoute)
  .use(decodeRoute)
  .use(analyzeRoute)
  .use(restoreRoute)
  .onError(({ code, error, set }) => {
    if (code === "NOT_FOUND") {
      set.status = 404;
      return { error: "Route not found" };
    }
    set.status = 500;
    const errorMessage = error instanceof Error ? error.message : "Internal server error";
    return { error: errorMessage };
  });
