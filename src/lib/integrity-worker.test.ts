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
  it("pins a canonical static-host subpath without fetching a redirected index URL", async () => {
    const origin = "https://chat.example";
    const scope = `${origin}/projects/kagetamga/`;
    const shellDigest = "S".repeat(43);
    const bodies: Record<string, string> = {
      "/projects/kagetamga/": "<!doctype html><title>KageTamga</title>",
      "/projects/kagetamga/assets/app.js": "globalThis.kagetamga = true;",
      "/projects/kagetamga/integrity-worker.js": "// generated integrity worker",
    };
    const manifest = {
      version: 1,
      algorithm: "SHA-256",
      shellDigest,
      buildDigest: "B".repeat(43),
      assets: {
        "/assets/app.js": digest(bodies["/projects/kagetamga/assets/app.js"]!),
        "/index.html": digest(bodies["/projects/kagetamga/"]!),
        "/integrity-worker.js": digest(bodies["/projects/kagetamga/integrity-worker.js"]!),
      },
    };
    const fetchMock = vi.fn(async (input: string, init?: RequestInit) => {
      const path = new URL(input, origin).pathname;
      expect(init?.redirect).toBe("error");
      if (path === "/projects/kagetamga/integrity-manifest.json") {
        return response(JSON.stringify(manifest), `${origin}${path}`, "application/json");
      }
      const body = bodies[path];
      if (body === undefined) throw new Error(`Unexpected fetch: ${path}`);
      return response(body, `${origin}${path}`, "application/octet-stream");
    });
    const cached = new Map<string, Response>();
    const put = vi.fn(async (path: string, value: Response) => {
      cached.set(path, value.clone());
    });
    const cache = {
      put,
      match: async (path: string) => cached.get(path)?.clone(),
    };
    const listeners = new Map<string, (event: any) => void>();
    const workerSource = (
      await readFile(new URL("../../public/integrity-worker.js", import.meta.url), "utf8")
    ).replace('"__KAGETAMGA_BUILD_STAMP__"', JSON.stringify(shellDigest));

    vm.runInNewContext(workerSource, {
      URL,
      Headers,
      Response,
      TextEncoder,
      btoa,
      console,
      crypto: webcrypto,
      fetch: fetchMock,
      caches: {
        open: async () => cache,
        keys: async () => [],
        delete: async () => true,
      },
      self: {
        location: { origin },
        registration: { scope },
        clients: { claim: async () => undefined },
        addEventListener(
          type: string,
          listener: (event: any) => void,
        ) {
          listeners.set(type, listener);
        },
      },
    });

    let installation: Promise<unknown> | undefined;
    listeners.get("install")?.({
      waitUntil(value: Promise<unknown>) {
        installation = value;
      },
    });
    await installation;

    const fetchedPaths = fetchMock.mock.calls.map(([input]) => new URL(input, origin).pathname);
    expect(fetchedPaths).toEqual([
      "/projects/kagetamga/integrity-manifest.json",
      "/projects/kagetamga/assets/app.js",
      "/projects/kagetamga/",
      "/projects/kagetamga/integrity-worker.js",
    ]);
    expect(fetchedPaths).not.toContain("/projects/kagetamga/index.html");
    expect(put.mock.calls.map(([path]) => path)).toEqual([
      "/integrity-manifest.json",
      "/assets/app.js",
      "/index.html",
      "/integrity-worker.js",
    ]);

    let served: Promise<Response> | undefined;
    listeners.get("fetch")?.({
      request: {
        url: scope,
        method: "GET",
        mode: "navigate",
        destination: "document",
      },
      respondWith(value: Promise<Response>) {
        served = value;
      },
    });
    const controlledNavigation = await served;
    expect(await controlledNavigation?.text()).toContain("KageTamga");
    expect(controlledNavigation?.headers.get("Cross-Origin-Opener-Policy")).toBe("same-origin");
    expect(controlledNavigation?.headers.get("Cross-Origin-Embedder-Policy")).toBe("require-corp");
    expect(controlledNavigation?.headers.get("Content-Security-Policy")).toContain(
      "require-trusted-types-for 'script'",
    );
  });
});
