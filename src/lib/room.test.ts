import { describe, expect, it } from "vitest";
import { decryptSignal, encryptSignal } from "./signaling-crypto";
import {
  createRoomSecret,
  deriveRoomId,
  deriveSignalingKey,
  normalizeRoomSecret,
  roomSecretFromHash,
} from "./room";

describe("room secrets", () => {
  it("creates 256-bit base64url secrets and derives stable opaque room ids", async () => {
    const secret = createRoomSecret();
    expect(secret).toMatch(/^[A-Za-z0-9_-]{43}$/u);
    const first = await deriveRoomId(secret);
    const second = await deriveRoomId(secret);
    expect(first).toBe(second);
    expect(first).toMatch(/^[A-Za-z0-9_-]{43}$/u);
    expect(first).not.toBe(secret);
  });

  it("accepts raw, fragment, and invite-link forms without weakening validation", () => {
    const secret = createRoomSecret();
    expect(normalizeRoomSecret(secret)).toBe(secret);
    expect(roomSecretFromHash(`#room=${secret}`)).toBe(secret);
    expect(normalizeRoomSecret(`https://chat.example/#room=${secret}`)).toBe(secret);
    expect(normalizeRoomSecret("too-short")).toBeNull();
    expect(normalizeRoomSecret(`${secret}=`)).toBeNull();
    expect(normalizeRoomSecret(secret.slice(0, -1) + "+")).toBeNull();
  });

  it("encrypts signaling payloads with the room-derived key", async () => {
    const key = await deriveSignalingKey(createRoomSecret());
    const encrypted = await encryptSignal(key, { kind: "candidate", value: "private" });
    expect(JSON.stringify(encrypted)).not.toContain("private");
    await expect(decryptSignal(key, encrypted)).resolves.toEqual({
      kind: "candidate",
      value: "private",
    });
  });
});
