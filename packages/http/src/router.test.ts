import { expect, test, describe } from "bun:test";
import { Router, cors, t } from "./index";

const app = new Router()
  .use(cors({ origin: true, allowedHeaders: ["Content-Type"], exposeHeaders: ["X-Test"] }))
  .get("/ping", () => ({ ok: true }))
  .post(
    "/echo",
    async ({ body, set }) => {
      if (body.message === "bad") {
        set.status = 418;
        set.headers["X-Test"] = "1";
        return { error: "teapot" };
      }
      return new Response(`${body.message}:${(await body.file.arrayBuffer()).byteLength}:${body.depth ?? "-"}`);
    },
    { body: t.Object({ message: t.String(), file: t.File(), depth: t.Optional(t.Union([t.String(), t.Number()])) }) }
  )
  .get("/boom", () => {
    throw new Error("kaboom");
  })
  .onError(({ code, error, set }) => {
    if (code === "NOT_FOUND") {
      set.status = 404;
      return { error: "Route not found" };
    }
    if (code !== "VALIDATION") set.status = 500;
    return { error: error instanceof Error ? error.message : "Internal server error" };
  });

function form(fields: Record<string, string | Blob>): FormData {
  const f = new FormData();
  for (const [k, v] of Object.entries(fields)) f.append(k, v);
  return f;
}

describe("Router", () => {
  test("GET returns JSON", async () => {
    const res = await app.handle(new Request("http://x/ping"));
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("application/json");
    expect(await res.json()).toEqual({ ok: true });
  });

  test("multipart body is parsed and validated", async () => {
    const res = await app.handle(
      new Request("http://x/echo", { method: "POST", body: form({ message: "hi", file: new File([new Uint8Array([1, 2, 3, 4, 5])], "a.bin"), depth: "2" }) })
    );
    expect(await res.text()).toBe("hi:5:2");
  });

  test("missing field -> 400", async () => {
    const res = await app.handle(new Request("http://x/echo", { method: "POST", body: form({ message: "hi" }) }));
    expect(res.status).toBe(400);
    expect((await res.json()).error).toContain("file");
  });

  test("set.status / set.headers apply to plain-object results", async () => {
    const res = await app.handle(
      new Request("http://x/echo", { method: "POST", body: form({ message: "bad", file: new File(["a"], "a.txt") }) })
    );
    expect(res.status).toBe(418);
    expect(res.headers.get("X-Test")).toBe("1");
  });

  test("404 and 500 go through onError", async () => {
    const nf = await app.handle(new Request("http://x/nope"));
    expect(nf.status).toBe(404);
    expect(await nf.json()).toEqual({ error: "Route not found" });
    const boom = await app.handle(new Request("http://x/boom"));
    expect(boom.status).toBe(500);
    expect(await boom.json()).toEqual({ error: "kaboom" });
  });

  test("CORS headers on responses and preflight", async () => {
    const res = await app.handle(new Request("http://x/ping", { headers: { origin: "http://a" } }));
    expect(res.headers.get("access-control-allow-origin")).toBe("http://a");
    expect(res.headers.get("access-control-expose-headers")).toBe("X-Test");
    const pre = await app.handle(new Request("http://x/echo", { method: "OPTIONS", headers: { origin: "http://a" } }));
    expect(pre.status).toBe(204);
    expect(pre.headers.get("access-control-allow-headers")).toBe("Content-Type");
  });
});
