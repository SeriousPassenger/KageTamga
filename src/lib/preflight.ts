import * as openpgp from "openpgp";
import {
  generateHybridKeyPair,
  unwrapCiphertext,
  wrapCiphertext,
} from "./hybrid-crypto";
import { randomId, utf8 } from "./encoding";
import { assertSupportedOpenPgpKey } from "./pgp-policy";
import { createRoomSecret, deriveSignalingKey } from "./room";
import {
  integrityBootstrapAction,
  waitForExpectedController,
} from "./service-worker-bootstrap";
import { decryptSignal, encryptSignal } from "./signaling-crypto";
import { integrityWorkerRegistrationUrl } from "./trusted-types";

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
  "resource-isolation",
  "secure-context",
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
const INTEGRITY_RELOAD_KEY = "kagetamga.integrity-reload-attempt.v1";

function integrityReloadAlreadyAttempted(): boolean {
  try {
    return sessionStorage.getItem(INTEGRITY_RELOAD_KEY) !== null;
  } catch {
    throw new Error("Origin-scoped session storage is required to guard the integrity reload.");
  }
}

function setIntegrityReloadAttempted(): void {
  try {
    sessionStorage.setItem(INTEGRITY_RELOAD_KEY, "1");
  } catch {
    throw new Error("Origin-scoped session storage is required to guard the integrity reload.");
  }
}

function clearIntegrityReloadAttempt(): void {
  try {
    sessionStorage.removeItem(INTEGRITY_RELOAD_KEY);
  } catch {
    throw new Error("Origin-scoped session storage is required to guard the integrity reload.");
  }
}

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
  const loopback = location.hostname === "localhost" ||
    location.hostname === "127.0.0.1" ||
    location.hostname === "[::1]" ||
    location.hostname === "::1";
  if (location.protocol !== "https:" && !loopback) {
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
  const expected = utf8("kagetamga-webcrypto-self-test");
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
    userIDs: [{ name: "KageTamga startup self-test" }],
    format: "armored",
  });
  const privateKey = await openpgp.readPrivateKey({ armoredKey: generated.privateKey });
  const publicKey = await openpgp.readKey({ armoredKey: generated.publicKey });
  await assertSupportedOpenPgpKey(publicKey);
  const ciphertext = await openpgp.encrypt({
    message: await openpgp.createMessage({ text: "kagetamga-openpgp-self-test" }),
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
  if (decrypted.data !== "kagetamga-openpgp-self-test" || !decrypted.signatures[0]) {
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
  const name = `kagetamga-preflight-${randomId(8)}`;
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
  if (!globalThis.RTCPeerConnection) {
    throw new Error("WebRTC is unavailable in this browser.");
  }
  const connection = new RTCPeerConnection();
  try {
    const channel = connection.createDataChannel("kagetamga-preflight");
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
  const forbiddenMarkers = ["sj.nim.nocaeb", "reganamgatelgoog", "scitylana-elgoog", "gohtsop"]
    .map((marker) => [...marker].reverse().join(""));
  if (forbiddenMarkers.some((marker) => markerText.includes(marker))) {
    throw new Error("Unexpected analytics or telemetry injection was detected.");
  }

  await verifyIntegrityWorker();
}

export async function verifyIntegrityWorker(): Promise<string> {
  if (!("serviceWorker" in navigator)) {
    throw new Error("This browser cannot install the integrity Service Worker.");
  }
  const expectedScope = new URL("./", document.baseURI).href;
  const expectedScript = new URL("integrity-worker.js", expectedScope).href;
  const registrations = await navigator.serviceWorker.getRegistrations();
  const relevantRegistrations = registrations.filter((registration) =>
    location.href.startsWith(registration.scope) || registration.scope === expectedScope);
  const foreign = relevantRegistrations.find((registration) => {
    const scripts = [
      registration.active?.scriptURL,
      registration.installing?.scriptURL,
      registration.waiting?.scriptURL,
    ].filter((script): script is string => Boolean(script));
    return registration.scope !== expectedScope || scripts.some((script) => script !== expectedScript);
  });
  if (foreign || relevantRegistrations.length > 1) {
    throw new Error("An unknown Service Worker can control this application path.");
  }

  let registration = registrations.find(
    (candidate) => candidate.active?.scriptURL === expectedScript,
  );
  registration ??= await navigator.serviceWorker.register(
    integrityWorkerRegistrationUrl(expectedScript),
    {
      scope: new URL(expectedScope).pathname,
      updateViaCache: "none",
    },
  );
  const readyRegistration = await withTimeout(
    navigator.serviceWorker.ready,
    30_000,
    "The integrity Service Worker did not become ready.",
  );
  registration = readyRegistration;
  if (registration.scope !== expectedScope) {
    throw new Error("The integrity Service Worker does not control the complete application scope.");
  }
  if (registration.waiting) {
    throw new Error("An application update is waiting. Close every app tab, reopen, and verify again.");
  }
  const action = integrityBootstrapAction(
    integrityControlledAtStartup,
    integrityReloadAlreadyAttempted(),
  );
  if (action === "stop") {
    clearIntegrityReloadAttempt();
    throw new Error(
      "The integrity Service Worker did not control the page after one guarded reload. Retry once; if it persists, clear this origin's site data.",
    );
  }

  if (action === "reload") {
    const activeWorker = registration.active;
    if (!activeWorker) throw new Error("The integrity Service Worker did not activate.");
    await requestPinnedShellVerification(activeWorker);
    await waitForExpectedController(navigator.serviceWorker, expectedScript);
    setIntegrityReloadAttempted();
    location.reload();
    throw new Error("Reloading once through the verified pinned application shell.");
  }

  const worker = navigator.serviceWorker.controller;
  if (!worker || worker.scriptURL !== expectedScript) {
    throw new Error("The verified integrity Service Worker does not control this page.");
  }
  const buildDigest = await requestPinnedShellVerification(worker);
  clearIntegrityReloadAttempt();
  return buildDigest;
}

async function requestPinnedShellVerification(worker: ServiceWorker): Promise<string> {
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
  const roomSecret = createRoomSecret();
  const key = await deriveSignalingKey(roomSecret);
  const expected = {
    mode: "manual-offer-answer",
    relayPolicy: "persistent-trusted-fingerprint-only",
    nonce: randomId(),
  };
  const encrypted = await encryptSignal(key, expected);
  const recovered = await decryptSignal<typeof expected>(key, encrypted);
  if (
    recovered.mode !== expected.mode ||
    recovered.relayPolicy !== expected.relayPolicy ||
    recovered.nonce !== expected.nonce
  ) {
    throw new Error("Backend-free encrypted peer setup self-test failed.");
  }
}
