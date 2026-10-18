import type { Schema } from "./schema";

export type HttpMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";

export interface MutableResponseState {
  status: number;
  headers: Record<string, string>;
}

export interface Context<B = any> {
  request: Request;
  body: B;
  set: MutableResponseState;
}

type Handler<B> = (ctx: Context<B>) => unknown | Promise<unknown>;

export interface RouteHooks<B> {
  body?: Schema<B>;
}

export type ErrorCode = "NOT_FOUND" | "VALIDATION" | "PARSE" | "UNKNOWN";
export type ErrorHandler = (ctx: { code: ErrorCode; error: unknown; set: MutableResponseState; request: Request }) => unknown;

interface Route {
  method: HttpMethod;
  path: string;
  handler: Handler<any>;
  hooks: RouteHooks<any>;
}

type RequestHook = (request: Request) => Response | void | Promise<Response | void>;
type AfterHook = (request: Request, response: Response) => void;

class HttpError extends Error {
  constructor(public code: ErrorCode, message: string) {
    super(message);
  }
}

// Large enough for the 160 MB upload ceiling enforced by the encode/restore routes plus multipart overhead.
const MAX_REQUEST_BODY_SIZE = 200 * 1024 * 1024;

export class Router {
  private routes: Route[] = [];
  private requestHooks: RequestHook[] = [];
  private afterHooks: AfterHook[] = [];
  private errorHandler: ErrorHandler | null = null;

  get<B = unknown>(path: string, handler: Handler<B>, hooks: RouteHooks<B> = {}): this {
    return this.add("GET", path, handler, hooks);
  }

  post<B = unknown>(path: string, handler: Handler<B>, hooks: RouteHooks<B> = {}): this {
    return this.add("POST", path, handler, hooks);
  }

  private add(method: HttpMethod, path: string, handler: Handler<any>, hooks: RouteHooks<any>): this {
    this.routes.push({ method, path, handler, hooks });
    return this;
  }

  /** Runs before routing; returning a Response short-circuits the request. */
  onRequest(hook: RequestHook): this {
    this.requestHooks.push(hook);
    return this;
  }

  /** Runs on every outgoing response (including errors and 404s). */
  onAfterHandle(hook: AfterHook): this {
    this.afterHooks.push(hook);
    return this;
  }

  onError(handler: ErrorHandler): this {
    this.errorHandler = handler;
    return this;
  }

  /** Merge another router's routes and hooks into this one. */
  use(other: Router): this {
    this.routes.push(...other.routes);
    this.requestHooks.push(...other.requestHooks);
    this.afterHooks.push(...other.afterHooks);
    if (other.errorHandler) this.errorHandler = other.errorHandler;
    return this;
  }

  async handle(request: Request): Promise<Response> {
    let response: Response;
    try {
      response = await this.dispatch(request);
    } catch (error) {
      response = await this.fail(request, error);
    }
    for (const hook of this.afterHooks) {
      try {
        hook(request, response);
      } catch {
        response = new Response(response.body, response); // headers were immutable; copy and retry
        hook(request, response);
      }
    }
    return response;
  }

  listen(port: number, onListen?: () => void): ReturnType<typeof Bun.serve> {
    const server = Bun.serve({
      port,
      maxRequestBodySize: MAX_REQUEST_BODY_SIZE,
      fetch: (req) => this.handle(req),
    });
    onListen?.();
    return server;
  }

  private async dispatch(request: Request): Promise<Response> {
    for (const hook of this.requestHooks) {
      const early = await hook(request);
      if (early) return early;
    }

    const path = new URL(request.url).pathname;
    const route = this.routes.find((r) => r.method === request.method && r.path === path);
    if (!route) throw new HttpError("NOT_FOUND", "NOT_FOUND");

    const body = request.method === "GET" ? undefined : await parseBody(request);
    if (route.hooks.body) {
      const err = route.hooks.body.validate(body);
      if (err) throw new HttpError("VALIDATION", err);
    }

    const set: MutableResponseState = { status: 200, headers: {} };
    const result = await route.handler({ request, body, set });
    return toResponse(result, set);
  }

  private async fail(request: Request, error: unknown): Promise<Response> {
    const set: MutableResponseState = { status: 500, headers: {} };
    const code: ErrorCode = error instanceof HttpError ? error.code : "UNKNOWN";
    if (code === "NOT_FOUND") set.status = 404;
    else if (code === "VALIDATION" || code === "PARSE") set.status = 400;

    if (this.errorHandler) {
      try {
        return toResponse(await this.errorHandler({ code, error, set, request }), set);
      } catch {
        /* fall through to the default response */
      }
    }
    const message = error instanceof Error ? error.message : "Internal server error";
    return toResponse({ error: message }, set);
  }
}

async function parseBody(request: Request): Promise<unknown> {
  const type = request.headers.get("content-type") ?? "";
  try {
    if (type.includes("multipart/form-data") || type.includes("application/x-www-form-urlencoded")) {
      const form = await request.formData();
      const out: Record<string, FormDataEntryValue> = {};
      for (const [key, value] of form.entries()) out[key] = value;
      return out;
    }
    if (type.includes("application/json")) return await request.json();
  } catch (err) {
    throw new HttpError("PARSE", `Malformed request body: ${err instanceof Error ? err.message : String(err)}`);
  }
  return undefined;
}

function toResponse(result: unknown, set: MutableResponseState): Response {
  if (result instanceof Response) {
    for (const [k, v] of Object.entries(set.headers)) if (!result.headers.has(k)) result.headers.set(k, v);
    return result;
  }
  const headers = new Headers(set.headers);
  if (result === undefined || result === null) return new Response(null, { status: set.status, headers });
  if (typeof result === "string") {
    if (!headers.has("content-type")) headers.set("content-type", "text/plain;charset=utf-8");
    return new Response(result, { status: set.status, headers });
  }
  if (!headers.has("content-type")) headers.set("content-type", "application/json");
  return new Response(JSON.stringify(result), { status: set.status, headers });
}
