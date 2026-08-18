import { fromBase64Url, toBase64Url, utf8 } from "./encoding";

const ROOM_SECRET_BYTES = 32;
const ROOM_FRAGMENT_PREFIX = "#room=";

export function createRoomSecret(): string {
  return toBase64Url(crypto.getRandomValues(new Uint8Array(ROOM_SECRET_BYTES)));
}

export function normalizeRoomSecret(value: string): string | null {
  const trimmed = value.trim();
  let candidate = trimmed;

  try {
    if (trimmed.startsWith("#")) {
      candidate = trimmed.slice(1);
    } else if (trimmed.includes("#")) {
      candidate = new URL(trimmed, "https://kagetamga.invalid/").hash.slice(1);
    }
  } catch {
    return null;
  }

  candidate = candidate.replace(/^#?room=/u, "").replace(/^#?\/room\//u, "");
  try {
    const bytes = fromBase64Url(candidate);
    return bytes.byteLength === ROOM_SECRET_BYTES &&
      /^[A-Za-z0-9_-]{43}$/u.test(candidate) &&
      toBase64Url(bytes) === candidate
      ? candidate
      : null;
  } catch {
    return null;
  }
}

export function roomSecretFromHash(hash: string): string | null {
  return normalizeRoomSecret(hash);
}

export function roomLink(secret: string): string {
  const url = new URL(window.location.href);
  url.search = "";
  url.hash = `${ROOM_FRAGMENT_PREFIX}${secret}`;
  return url.toString();
}

export async function deriveRoomId(secret: string): Promise<string> {
  const secretBytes = fromBase64Url(secret);
  const context = utf8("kagetamga:room-id:v1:");
  const material = new Uint8Array(context.length + secretBytes.length);
  material.set(context);
  material.set(secretBytes, context.length);
  return toBase64Url(new Uint8Array(await crypto.subtle.digest("SHA-256", material)));
}

export async function deriveSignalingKey(secret: string): Promise<CryptoKey> {
  const material = await crypto.subtle.importKey(
    "raw",
    fromBase64Url(secret),
    "HKDF",
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: utf8("kagetamga:signaling-salt:v1"),
      info: utf8("kagetamga:signaling-key:v1"),
    },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}
