import { Router } from "./router";

export interface CorsOptions {
  /** `true` allows any origin; a string or list restricts to those origins. */
  origin?: true | string | string[];
  methods?: string[];
  allowedHeaders?: string[];
  exposeHeaders?: string[];
  maxAge?: number;
}

export function cors(options: CorsOptions = {}): Router {
  const origin = options.origin ?? true;
  const methods = (options.methods ?? ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]).join(", ");

  function allowOrigin(request: Request): string | null {
    const reqOrigin = request.headers.get("origin");
    if (origin === true) return reqOrigin ?? "*"; // reflect the caller's origin
    const list = Array.isArray(origin) ? origin : [origin];
    return reqOrigin && list.includes(reqOrigin) ? reqOrigin : null;
  }

  function apply(request: Request, headers: Headers): void {
    const o = allowOrigin(request);
    if (!o) return;
    headers.set("Access-Control-Allow-Origin", o);
    if (o !== "*") headers.append("Vary", "Origin");
    if (options.exposeHeaders?.length) headers.set("Access-Control-Expose-Headers", options.exposeHeaders.join(", "));
  }

  return new Router()
    .onRequest((request) => {
      if (request.method !== "OPTIONS") return;
      const headers = new Headers();
      apply(request, headers);
      headers.set("Access-Control-Allow-Methods", methods);
      const allowed = options.allowedHeaders?.join(", ") ?? request.headers.get("access-control-request-headers");
      if (allowed) headers.set("Access-Control-Allow-Headers", allowed);
      if (options.maxAge !== undefined) headers.set("Access-Control-Max-Age", String(options.maxAge));
      return new Response(null, { status: 204, headers });
    })
    .onAfterHandle((request, response) => apply(request, response.headers));
}
