import * as openpgp from "openpgp";
import {
  generateHybridKeyPair,
  unwrapCiphertext,
  wrapCiphertext,
} from "./hybrid-crypto";
import { randomId, utf8 } from "./encoding";
import { assertSupportedOpenPgpKey } from "./pgp-policy";

export type PreflightCheckId =
  | "secure-context"
  | "browser-crypto"
  | "openpgp"
  | "mlkem"
  | "local-storage"
  | "p2p"
  | "resource-isolation"
  | "signaling";

export type PreflightStatus = "waiting" | "running" | "passed" | "failed";

export interface PreflightResult {
  id: PreflightCheckId;
  status: PreflightStatus;
  detail?: string;
}

export const PREFLIGHT_CHECKS: readonly PreflightCheckId[] = [
  "secure-context",
  "resource-isolation",
  "browser-crypto",
  "openpgp",
  "mlkem",
  "local-storage",
  "p2p",
  "signaling",
];

// A controller acquired later through clients.claim() cannot retroactively vouch for
// the HTML and modules that already executed during this navigation. First-time
// installs therefore reload once and only let the pinned Service Worker serve the
// application on the following navigation.
const integrityControlledAtStartup = Boolean(navigator.serviceWorker?.controller);

async function withTimeout<T>(promise: Promise<T>, timeoutMs: number, message: string): Promise<T> {
  let timeout: number | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_, reject) => {
        timeout = window.setTimeout(() => reject(new Error(message)), timeoutMs);
      }),
    ]);
  } finally {
    if (timeout !== undefined) window.clearTimeout(timeout);
  }
}

export async function runPreflight(
  onUpdate: (result: PreflightResult) => void,
): Promise<boolean> {
  let ephemeralPgpCiphertext = "";
  let ephemeralFingerprint = "";

  const checks: Array<[PreflightCheckId, () => Promise<void>]> = [
    ["secure-context", checkSecureContext],
    ["resource-isolation", checkResourceIsolation],
    ["browser-crypto", checkBrowserCrypto],
    [
      "openpgp",
      async () => {
        const result = await checkOpenPgp();
        ephemeralPgpCiphertext = result.ciphertext;
        ephemeralFingerprint = result.fingerprint;
      },
    ],
    [
      "mlkem",
      async () => checkMlKem(ephemeralPgpCiphertext, ephemeralFingerprint),
    ],
    ["local-storage", checkIndexedDb],
    ["p2p", checkPeerToPeerApis],
    ["signaling", checkSignalingService],
  ];

  for (const [id, check] of checks) {
    onUpdate({ id, status: "running" });
    try {
      await check();
      onUpdate({ id, status: "passed" });
    } catch (error) {
      const detail = error instanceof Error ? error.message : "Unknown preflight failure";
      onUpdate({ id, status: "failed", detail });
      return false;
    }
  }
  return true;
}

async function checkSecureContext(): Promise<void> {
  if (!window.isSecureContext) throw new Error("Open this application over HTTPS.");
  if (location.protocol !== "https:" && location.hostname !== "localhost") {
    throw new Error("The page was not delivered through HTTPS.");
  }
  if (!window.crossOriginIsolated) {
    throw new Error("Required cross-origin isolation headers are missing.");
  }
}

async function checkBrowserCrypto(): Promise<void> {
  if (!globalThis.crypto?.getRandomValues || !globalThis.crypto.subtle) {
    throw new Error("This browser does not provide the required WebCrypto APIs.");
  }
  const first = crypto.getRandomValues(new Uint8Array(32));
  const second = crypto.getRandomValues(new Uint8Array(32));
  if (first.every((byte) => byte === 0) || first.every((byte, index) => byte === second[index])) {
    throw new Error("The browser CSPRNG failed its startup check.");
  }

  const keyBytes = crypto.getRandomValues(new Uint8Array(32));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, [
    "encrypt",
    "decrypt",
  ]);
  const expected = utf8("quietwire-webcrypto-self-test");
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, expected);
  const plaintext = new Uint8Array(
    await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext),
  );
  if (plaintext.length !== expected.length || !plaintext.every((byte, index) => byte === expected[index])) {
    throw new Error("AES-GCM encryption self-test failed.");
  }
  first.fill(0);
  second.fill(0);
  keyBytes.fill(0);
  plaintext.fill(0);
}

async function checkOpenPgp(): Promise<{ ciphertext: string; fingerprint: string }> {
  const generated = await openpgp.generateKey({
    type: "curve25519",
    userIDs: [{ name: "QuietWire startup self-test" }],
    format: "armored",
  });
  const privateKey = await openpgp.readPrivateKey({ armoredKey: generated.privateKey });
  const publicKey = await openpgp.readKey({ armoredKey: generated.publicKey });
  await assertSupportedOpenPgpKey(publicKey);
  const ciphertext = await openpgp.encrypt({
    message: await openpgp.createMessage({ text: "quietwire-openpgp-self-test" }),
    encryptionKeys: publicKey,
    signingKeys: privateKey,
    format: "armored",
  });
  const decrypted = await openpgp.decrypt({
    message: await openpgp.readMessage({ armoredMessage: ciphertext }),
    decryptionKeys: privateKey,
    verificationKeys: publicKey,
    format: "utf8",
  });
  if (decrypted.data !== "quietwire-openpgp-self-test" || !decrypted.signatures[0]) {
    throw new Error("OpenPGP round-trip self-test failed.");
  }
  await decrypted.signatures[0].verified;
  return { ciphertext, fingerprint: publicKey.getFingerprint().toUpperCase() };
}

async function checkMlKem(pgpCiphertext: string, fingerprint: string): Promise<void> {
  if (!pgpCiphertext || !fingerprint) throw new Error("OpenPGP prerequisite did not complete.");
  const pair = generateHybridKeyPair();
  try {
    const messageId = randomId();
    const envelope = await wrapCiphertext(messageId, pgpCiphertext, [
      { fingerprint, publicKey: pair.publicKey },
    ]);
    const recovered = await unwrapCiphertext(envelope, fingerprint, pair.secretKey);
    if (recovered !== pgpCiphertext) throw new Error("ML-KEM hybrid round-trip did not match.");
  } finally {
    pair.secretKey.fill(0);
  }
}

async function checkIndexedDb(): Promise<void> {
  if (!globalThis.indexedDB) throw new Error("IndexedDB is unavailable.");
  const name = `quietwire-preflight-${randomId(8)}`;
  const db = await new Promise<IDBDatabase>((resolve, reject) => {
    const request = indexedDB.open(name, 1);
    request.onupgradeneeded = () => request.result.createObjectStore("check");
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("IndexedDB could not be opened."));
  });
  try {
    const transaction = db.transaction("check", "readwrite");
    transaction.objectStore("check").put("ok", "status");
    await new Promise<void>((resolve, reject) => {
      transaction.oncomplete = () => resolve();
      transaction.onerror = () => reject(transaction.error ?? new Error("IndexedDB write failed."));
    });
    const read = db.transaction("check", "readonly").objectStore("check").get("status");
    const value = await new Promise<unknown>((resolve, reject) => {
      read.onsuccess = () => resolve(read.result);
      read.onerror = () => reject(read.error ?? new Error("IndexedDB read failed."));
    });
    if (value !== "ok") throw new Error("IndexedDB verification value did not match.");
  } finally {
    db.close();
    indexedDB.deleteDatabase(name);
  }
}

async function checkPeerToPeerApis(): Promise<void> {
  if (!globalThis.RTCPeerConnection || !globalThis.WebSocket) {
    throw new Error("WebRTC or WebSocket is unavailable in this browser.");
  }
  const connection = new RTCPeerConnection();
  try {
    const channel = connection.createDataChannel("quietwire-preflight");
    channel.close();
  } finally {
    connection.close();
  }
}

async function checkResourceIsolation(): Promise<void> {
  const urls = [
    ...[...document.querySelectorAll<HTMLScriptElement>("script[src]")].map((node) => node.src),
    ...[...document.querySelectorAll<HTMLLinkElement>("link[href]")].map((node) => node.href),
  ];
  const external = urls.find((value) => {
    const url = new URL(value, location.href);
    return !["data:", "blob:"].includes(url.protocol) && url.origin !== location.origin;
  });
  if (external) throw new Error(`External runtime resource detected: ${new URL(external).origin}`);

  const markerText = document.documentElement.innerHTML.toLowerCase();
  const forbiddenMarkers = ["moc.sthgisnieralfduolc", "sj.nim.nocaeb", "mur/igc-ndc/"]
    .map((marker) => [...marker].reverse().join(""));
  if (forbiddenMarkers.some((marker) => markerText.includes(marker))) {
    throw new Error("Cloudflare Browser Insights/RUM injection was detected.");
  }

  await verifyIntegrityWorker();
}

export async function verifyIntegrityWorker(): Promise<string> {
  if (!("serviceWorker" in navigator)) {
    throw new Error("This browser cannot install the integrity Service Worker.");
  }
  const expectedScript = new URL("/integrity-worker.js", location.origin).href;
  const expectedScope = new URL("/", location.origin).href;
  const registrations = await navigator.serviceWorker.getRegistrations();
  const foreign = registrations.find((registration) => {
    const scripts = [
      registration.active?.scriptURL,
      registration.installing?.scriptURL,
      registration.waiting?.scriptURL,
    ].filter((script): script is string => Boolean(script));
    return registration.scope !== expectedScope || scripts.some((script) => script !== expectedScript);
  });
  if (foreign || registrations.length > 1) {
    throw new Error("An unknown Service Worker is registered for this origin.");
  }

  let registration = registrations.find(
    (candidate) => candidate.active?.scriptURL === expectedScript,
  );
  registration ??= await navigator.serviceWorker.register(expectedScript, {
    scope: "/",
    updateViaCache: "none",
  });
  await withTimeout(
    navigator.serviceWorker.ready,
    30_000,
    "The integrity Service Worker did not become ready.",
  );
  if (!integrityControlledAtStartup) {
    location.reload();
    throw new Error("Reloading through the pinned application shell.");
  }
  if (registration.scope !== expectedScope) {
    throw new Error("The integrity Service Worker does not control the complete origin scope.");
  }
  if (registration.waiting) {
    throw new Error("An application update is waiting. Close every app tab, reopen, and verify again.");
  }
  const worker = registration.active ?? navigator.serviceWorker.controller;
  if (!worker) throw new Error("The integrity Service Worker did not activate.");

  const result = await new Promise<{ ok?: boolean; error?: string; buildDigest?: string }>((resolve, reject) => {
    const channel = new MessageChannel();
    const timeout = window.setTimeout(
      () => reject(new Error("The integrity Service Worker did not respond.")),
      20_000,
    );
    channel.port1.onmessage = (event: MessageEvent<{ ok?: boolean; error?: string; buildDigest?: string }>) => {
      window.clearTimeout(timeout);
      resolve(event.data);
    };
    worker.postMessage({ type: "VERIFY_PINNED_SHELL" }, [channel.port2]);
  });
  if (!result.ok) throw new Error(result.error ?? "Pinned application assets failed verification.");
  if (!result.buildDigest || !/^[A-Za-z0-9_-]{43}$/u.test(result.buildDigest)) {
    throw new Error("The integrity Service Worker returned an invalid build digest.");
  }
  return result.buildDigest;
}

async function checkSignalingService(): Promise<void> {
  const response = await fetch("/api/health", { cache: "no-store", credentials: "omit" });
  if (!response.ok) throw new Error("The signaling Worker health check failed.");
  const body = (await response.json()) as { ok?: boolean; storage?: string; signaling?: string };
  if (body.ok !== true || body.storage !== "none" || body.signaling !== "ephemeral") {
    throw new Error("The signaling Worker did not confirm its storage-free mode.");
  }
  const csp = response.headers.get("Content-Security-Policy") ?? "";
  if (
    !csp.includes("default-src 'self'") ||
    !csp.includes("script-src 'self'") ||
    !csp.includes("connect-src 'self'") ||
    !csp.includes("object-src 'none'")
  ) {
    throw new Error("Required Content Security Policy headers are missing.");
  }

  const shell = await fetch("/", { cache: "no-store", credentials: "omit" });
  if (!shell.ok) throw new Error("The secured application shell could not be fetched.");
  const shellCsp = shell.headers.get("Content-Security-Policy") ?? "";
  if (
    !shellCsp.includes("require-trusted-types-for 'script'") ||
    shell.headers.get("Cross-Origin-Opener-Policy") !== "same-origin" ||
    shell.headers.get("Cross-Origin-Embedder-Policy") !== "require-corp" ||
    !shell.headers.get("Permissions-Policy")
  ) {
    throw new Error("The application shell is missing mandatory isolation headers.");
  }

  await checkDisposableSignalingSocket();
}

async function checkDisposableSignalingSocket(): Promise<void> {
  const protocol = location.protocol === "https:" ? "wss:" : "ws:";
  const url = new URL(`${protocol}//${location.host}/api/signal/${randomId(32)}`);
  url.searchParams.set("peer", randomId());

  await new Promise<void>((resolve, reject) => {
    const socket = new WebSocket(url);
    const timeout = window.setTimeout(() => {
      socket.close();
      reject(new Error("The disposable signaling WebSocket timed out."));
    }, 12_000);
    let settled = false;
    const finish = (error?: Error) => {
      if (settled) return;
      settled = true;
      window.clearTimeout(timeout);
      socket.close(1000, "Preflight complete");
      if (error) reject(error);
      else resolve();
    };
    socket.onerror = () => finish(new Error("The signaling Durable Object could not be reached."));
    socket.onmessage = (event) => {
      try {
        const message = JSON.parse(String(event.data)) as { type?: unknown; peerIds?: unknown };
        if (
          message.type !== "roster" ||
          !Array.isArray(message.peerIds) ||
          message.peerIds.length !== 0
        ) {
          throw new Error("The signaling Durable Object returned an invalid roster.");
        }
        finish();
      } catch (error) {
        finish(error instanceof Error ? error : new Error("Invalid signaling response."));
      }
    };
  });
}
