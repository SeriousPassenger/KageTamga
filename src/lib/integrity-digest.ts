import { fromBase64Url, toBase64Url } from "./encoding";

export interface IntegrityDigestEncodings {
  algorithm: "SHA-256";
  base64Url: string;
  hex: string;
}

export function sha256DigestEncodings(base64Url: string): IntegrityDigestEncodings {
  if (!/^[A-Za-z0-9_-]{43}$/u.test(base64Url)) {
    throw new Error("The build digest is not a canonical unpadded SHA-256 Base64URL value.");
  }

  const bytes = fromBase64Url(base64Url);
  if (bytes.length !== 32 || toBase64Url(bytes) !== base64Url) {
    throw new Error("The build digest is not a canonical 32-byte SHA-256 value.");
  }

  return Object.freeze({
    algorithm: "SHA-256",
    base64Url,
    hex: Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(""),
  });
}

export const INTEGRITY_CONSOLE_COMMAND = `await (async () => {
  const registration = await navigator.serviceWorker.ready;
  const worker = navigator.serviceWorker.controller;
  const expectedWorkerUrl = new URL("/integrity-worker.js", location.origin).href;
  if (!worker || worker.scriptURL !== expectedWorkerUrl) {
    throw new Error("The expected QuietWire integrity worker does not control this page.");
  }
  if (registration.waiting) {
    throw new Error("A waiting integrity-worker update must be resolved before comparison.");
  }

  const channel = new MessageChannel();
  const result = await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error("Integrity verification timed out.")), 10000);
    channel.port1.onmessage = ({ data }) => {
      clearTimeout(timeout);
      if (data?.ok && typeof data.buildDigest === "string") resolve(data.buildDigest);
      else reject(new Error(data?.error || "Integrity verification failed."));
    };
    worker.postMessage({ type: "VERIFY_PINNED_SHELL" }, [channel.port2]);
  });

  if (!/^[A-Za-z0-9_-]{43}$/.test(result)) {
    throw new Error("The worker returned a non-canonical SHA-256 digest.");
  }
  const padded = result.replaceAll("-", "+").replaceAll("_", "/").padEnd(44, "=");
  const binary = atob(padded);
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  const canonical = btoa(String.fromCharCode(...bytes))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/, "");
  if (bytes.length !== 32 || canonical !== result) {
    throw new Error("The worker returned a non-canonical SHA-256 digest.");
  }

  const output = Object.freeze({
    algorithm: "SHA-256",
    base64Url: result,
    hex: Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(""),
  });
  console.log("QuietWire build digest (SHA-256, Base64URL unpadded):", output.base64Url);
  console.log("QuietWire build digest (SHA-256, lowercase hex):", output.hex);
  return output;
})()`;
