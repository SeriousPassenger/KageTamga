import { createHash, webcrypto } from "node:crypto";
import { readFile } from "node:fs/promises";
import vm from "node:vm";
import { describe, expect, it, vi } from "vitest";

function digest(body: string): string {
  return createHash("sha256").update(body).digest("base64url");
}

function response(body: string, url: string, contentType: string): Response {
  const value = new Response(body, {
    status: 200,
    headers: { "Content-Type": contentType },
  });
  Object.defineProperty(value, "url", { value: url });
  return value;
}

describe("integrity Service Worker installation", () => {
  it("pins the canonical root response without following /index.html redirects", async () => {
    const origin = "https://chat.example";
    const shellDigest = "S".repeat(43);
    const bodies: Record<string, string> = {
      "/": "<!doctype html><title>QuietWire</title>",
      "/assets/app.js": "globalThis.quietwire = true;",
      "/integrity-worker.js": "// generated integrity worker",
    };
    const manifest = {
      version: 1,
      algorithm: "SHA-256",
      shellDigest,
      buildDigest: "B".repeat(43),
      assets: {
        "/assets/app.js": digest(bodies["/assets/app.js"]!),
        "/index.html": digest(bodies["/"]!),
        "/integrity-worker.js": digest(bodies["/integrity-worker.js"]!),
      },
    };
    const fetchMock = vi.fn(async (input: string, init?: RequestInit) => {
      const path = new URL(input, origin).pathname;
      expect(init?.redirect).toBe("error");
      if (path === "/integrity-manifest.json") {
        return response(JSON.stringify(manifest), `${origin}${path}`, "application/json");
      }
      const body = bodies[path];
      if (body === undefined) throw new Error(`Unexpected fetch: ${path}`);
      return response(body, `${origin}${path}`, "application/octet-stream");
    });
    const put = vi.fn(async (_path: string, _response: Response) => undefined);
    const listeners = new Map<string, (event: { waitUntil(value: Promise<unknown>): void }) => void>();
    const workerSource = (
      await readFile(new URL("../../public/integrity-worker.js", import.meta.url), "utf8")
    ).replace('"__QUIETWIRE_BUILD_STAMP__"', JSON.stringify(shellDigest));

    vm.runInNewContext(workerSource, {
      URL,
      Response,
      TextEncoder,
      btoa,
      console,
      crypto: webcrypto,
      fetch: fetchMock,
      caches: {
        open: async () => ({ put }),
        keys: async () => [],
        delete: async () => true,
      },
      self: {
        location: { origin },
        clients: { claim: async () => undefined },
        addEventListener(
          type: string,
          listener: (event: { waitUntil(value: Promise<unknown>): void }) => void,
        ) {
          listeners.set(type, listener);
        },
      },
    });

    let installation: Promise<unknown> | undefined;
    listeners.get("install")?.({
      waitUntil(value) {
        installation = value;
      },
    });
    await installation;

    const fetchedPaths = fetchMock.mock.calls.map(([input]) => new URL(input, origin).pathname);
    expect(fetchedPaths).toEqual([
      "/integrity-manifest.json",
      "/assets/app.js",
      "/",
      "/integrity-worker.js",
    ]);
    expect(fetchedPaths).not.toContain("/index.html");
    expect(put.mock.calls.map(([path]) => path)).toEqual([
      "/integrity-manifest.json",
      "/assets/app.js",
      "/index.html",
      "/integrity-worker.js",
    ]);
  });
});
