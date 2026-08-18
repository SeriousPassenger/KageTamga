/*
 * KageTamga integrity Service Worker.
 * Trust model: trust on first use. The origin is trusted during installation.
 * This cannot defend against a malicious origin changing the Service Worker update response.
 */
const BUILD_STAMP = "__KAGETAMGA_BUILD_STAMP__";
const CACHE_NAME = `kagetamga-pinned-shell-${BUILD_STAMP}`;
const APPLICATION_SCOPE = new URL(self.registration.scope);
const MANIFEST_URL = new URL("integrity-manifest.json", APPLICATION_SCOPE).href;
const MANIFEST_CACHE_KEY = "/integrity-manifest.json";
const SECURITY_HEADERS = {
  "Cache-Control": "no-store, no-transform",
  "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; connect-src 'self'; font-src 'self'; worker-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; manifest-src 'self'; require-trusted-types-for 'script'; trusted-types kagetamga",
  "Cross-Origin-Embedder-Policy": "require-corp",
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Resource-Policy": "same-origin",
  "Origin-Agent-Cluster": "?1",
  "Permissions-Policy": "accelerometer=(), camera=(), display-capture=(), geolocation=(), gyroscope=(), microphone=(), payment=(), usb=()",
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "X-Robots-Tag": "noindex, nofollow, noarchive",
};

self.addEventListener("install", (event) => {
  event.waitUntil(installPinnedShell());
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    Promise.all([
      self.clients.claim(),
      caches.keys().then((names) =>
        Promise.all(
          names
            .filter((name) => name.startsWith("kagetamga-pinned-shell-") && name !== CACHE_NAME)
            .map((name) => caches.delete(name)),
        ),
      ),
    ]),
  );
});

self.addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);
  if (url.origin !== self.location.origin || !url.href.startsWith(APPLICATION_SCOPE.href)) return;
  event.respondWith(
    event.request.method === "GET"
      ? servePinned(event.request)
      : Promise.resolve(blockedResponse()),
  );
});

self.addEventListener("message", (event) => {
  if (event.data?.type !== "VERIFY_PINNED_SHELL" || !event.ports[0]) return;
  event.waitUntil(
    verifyPinnedShell()
      .then((buildDigest) => event.ports[0].postMessage({ ok: true, buildDigest }))
      .catch((error) =>
        event.ports[0].postMessage({
          ok: false,
          error: error instanceof Error ? error.message : "Integrity verification failed",
        }),
      ),
  );
});

async function installPinnedShell() {
  const manifestResponse = await fetch(MANIFEST_URL, {
    cache: "no-store",
    credentials: "omit",
    redirect: "error",
  });
  if (!manifestResponse.ok) throw new Error("Integrity manifest unavailable");
  if (manifestResponse.url !== MANIFEST_URL) {
    throw new Error("Integrity manifest resolved to an unexpected URL");
  }
  const manifest = await manifestResponse.clone().json();
  validateManifest(manifest);
  const cache = await caches.open(CACHE_NAME);
  await cache.put(MANIFEST_CACHE_KEY, manifestResponse);
  for (const [path, expected] of Object.entries(manifest.assets)) {
    const sourceUrl = path === "/index.html"
      ? APPLICATION_SCOPE.href
      : new URL(path.slice(1), APPLICATION_SCOPE).href;
    const response = await fetch(sourceUrl, {
      cache: "no-store",
      credentials: "omit",
      redirect: "error",
    });
    if (!response.ok) throw new Error(`Pinned asset unavailable: ${path}`);
    if (response.url !== sourceUrl) {
      throw new Error(`Pinned asset resolved to an unexpected URL: ${path}`);
    }
    await assertDigest(response.clone(), expected, path);
    await cache.put(path, response);
  }
}

async function servePinned(request) {
  const cache = await caches.open(CACHE_NAME);
  const url = new URL(request.url);
  const relativePath = url.pathname.slice(APPLICATION_SCOPE.pathname.length);
  const cacheKey = request.mode === "navigate" ? "/index.html" : `/${relativePath}`;
  const pinned = await cache.match(cacheKey);
  if (pinned) return withSecurityHeaders(pinned);
  return blockedResponse();
}

async function verifyPinnedShell() {
  const cache = await caches.open(CACHE_NAME);
  const manifestResponse = await cache.match(MANIFEST_CACHE_KEY);
  if (!manifestResponse) throw new Error("Pinned integrity manifest is missing");
  const manifest = await manifestResponse.json();
  validateManifest(manifest);
  const computedBuildDigest = toBase64Url(
    new Uint8Array(
      await crypto.subtle.digest("SHA-256", new TextEncoder().encode(JSON.stringify(manifest.assets))),
    ),
  );
  if (computedBuildDigest !== manifest.buildDigest) {
    throw new Error("Pinned build digest does not match the asset manifest");
  }
  const shellAssets = Object.fromEntries(
    Object.entries(manifest.assets).filter(([path]) => path !== "/integrity-worker.js"),
  );
  const computedShellDigest = toBase64Url(
    new Uint8Array(
      await crypto.subtle.digest("SHA-256", new TextEncoder().encode(JSON.stringify(shellAssets))),
    ),
  );
  if (computedShellDigest !== manifest.shellDigest) {
    throw new Error("Pinned shell digest does not match the integrity worker build stamp");
  }
  for (const [path, expected] of Object.entries(manifest.assets)) {
    const response = await cache.match(path);
    if (!response) throw new Error(`Pinned asset is missing: ${path}`);
    await assertDigest(response, expected, path);
  }
  return computedBuildDigest;
}

function withSecurityHeaders(response) {
  const headers = new Headers(response.headers);
  headers.delete("Content-Encoding");
  headers.delete("Content-Length");
  for (const [name, value] of Object.entries(SECURITY_HEADERS)) headers.set(name, value);
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

function withSecurityHeaderValues(initial) {
  return { ...initial, ...SECURITY_HEADERS };
}

function blockedResponse() {
  return new Response("Blocked: request is not in the pinned static application.", {
    status: 503,
    headers: withSecurityHeaderValues({ "Content-Type": "text/plain; charset=utf-8" }),
  });
}

function validateManifest(value) {
  const keys = value && typeof value === "object" && !Array.isArray(value)
    ? Object.keys(value).sort()
    : [];
  if (
    !value ||
    keys.length !== 5 ||
    keys[0] !== "algorithm" ||
    keys[1] !== "assets" ||
    keys[2] !== "buildDigest" ||
    keys[3] !== "shellDigest" ||
    keys[4] !== "version" ||
    value.version !== 1 ||
    value.algorithm !== "SHA-256" ||
    typeof value.buildDigest !== "string" ||
    typeof value.shellDigest !== "string" ||
    value.shellDigest !== BUILD_STAMP ||
    !value.assets ||
    typeof value.assets !== "object" ||
    Array.isArray(value.assets)
  ) {
    throw new Error("Malformed integrity manifest");
  }
  if (!value.assets["/index.html"] || !value.assets["/integrity-worker.js"]) {
    throw new Error("Integrity manifest omits a required trust anchor");
  }
  for (const [path, digest] of Object.entries(value.assets)) {
    if (!/^\/[A-Za-z0-9_./-]+$/u.test(path) || path.includes("..") || !/^[A-Za-z0-9_-]{43}$/u.test(digest)) {
      throw new Error("Malformed pinned asset entry");
    }
  }
}

async function assertDigest(response, expected, path) {
  const actual = toBase64Url(new Uint8Array(await crypto.subtle.digest("SHA-256", await response.arrayBuffer())));
  if (actual !== expected) throw new Error(`Pinned asset digest mismatch: ${path}`);
}

function toBase64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}
