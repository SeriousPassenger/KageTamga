import { afterEach, describe, expect, it } from "vitest";
import {
  HYBRID_ALGORITHM,
  deriveHybridPublicKey,
  generateHybridKeyPair,
  protectHybridSecretKey,
  unprotectHybridSecretKey,
  unwrapCiphertext,
  wrapCiphertext,
  type HybridEnvelope,
} from "./hybrid-crypto";

const MESSAGE_ID = "A_secure_message_id_2026";
const ALICE_FINGERPRINT = "A1B2C3D4E5F60718293A4B5C6D7E8F9012345678";
const BOB_FINGERPRINT = "1029384756AABBCCDDEEFF001122334455667788";
const ARMORED_MESSAGE = [
  "-----BEGIN PGP MESSAGE-----",
  "",
  "dGVzdC1jaXBoZXJ0ZXh0",
  "-----END PGP MESSAGE-----",
].join("\n");

const secrets: Uint8Array[] = [];

afterEach(() => {
  for (const secret of secrets) secret.fill(0);
  secrets.length = 0;
});

function keyPair() {
  const pair = generateHybridKeyPair();
  secrets.push(pair.secretKey);
  return pair;
}

function mutateBase64Url(value: string): string {
  const index = Math.floor(value.length / 2);
  const replacement = value[index] === "A" ? "B" : "A";
  return `${value.slice(0, index)}${replacement}${value.slice(index + 1)}`;
}

describe("hybrid key lifecycle", () => {
  it("generates an ML-KEM-768 keypair and derives the same public key", () => {
    const pair = keyPair();

    expect(pair.version).toBe(1);
    expect(pair.algorithm).toBe(HYBRID_ALGORITHM);
    expect(pair.secretKey).toHaveLength(2400);
    expect(deriveHybridPublicKey(pair.secretKey)).toBe(pair.publicKey);
  });

  it("protects the secret key with a passphrase and rejects wrong or tampered input", async () => {
    const pair = keyPair();
    const protectedKey = await protectHybridSecretKey(
      pair.secretKey,
      "correct horse battery staple",
    );

    expect(JSON.stringify(protectedKey)).not.toContain(pair.publicKey);
    const unlocked = await unprotectHybridSecretKey(
      protectedKey,
      "correct horse battery staple",
    );
    secrets.push(unlocked);
    expect(deriveHybridPublicKey(unlocked)).toBe(pair.publicKey);

    await expect(
      unprotectHybridSecretKey(protectedKey, "wrong battery staple passphrase"),
    ).rejects.toThrow("Unable to unlock");

    const tampered = structuredClone(protectedKey);
    tampered.cipher.ciphertext = mutateBase64Url(tampered.cipher.ciphertext);
    await expect(
      unprotectHybridSecretKey(tampered, "correct horse battery staple"),
    ).rejects.toThrow("Unable to unlock");
  });
});

describe("hybrid message envelope", () => {
  it("outer-encrypts one OpenPGP ciphertext for multiple recipients", async () => {
    const alice = keyPair();
    const bob = keyPair();
    const envelope = await wrapCiphertext(MESSAGE_ID, ARMORED_MESSAGE, [
      { fingerprint: BOB_FINGERPRINT, publicKey: bob.publicKey },
      { fingerprint: ALICE_FINGERPRINT.toLowerCase(), publicKey: alice.publicKey },
    ]);

    expect(envelope.algorithm).toBe(HYBRID_ALGORITHM);
    expect(envelope.recipients.map((entry) => entry.fingerprint)).toEqual([
      BOB_FINGERPRINT,
      ALICE_FINGERPRINT,
    ].sort());
    expect(JSON.stringify(envelope)).not.toContain(ARMORED_MESSAGE);
    expect(JSON.stringify(envelope)).not.toContain(alice.publicKey);
    expect(JSON.stringify(envelope)).not.toContain(bob.publicKey);

    await expect(
      unwrapCiphertext(envelope, ALICE_FINGERPRINT, alice.secretKey),
    ).resolves.toBe(ARMORED_MESSAGE);
    await expect(
      unwrapCiphertext(envelope, BOB_FINGERPRINT, bob.secretKey),
    ).resolves.toBe(ARMORED_MESSAGE);
  });

  it("binds the algorithm, message ID, and recipient fingerprint with authenticated data", async () => {
    const alice = keyPair();
    const envelope = await wrapCiphertext(MESSAGE_ID, ARMORED_MESSAGE, [
      { fingerprint: ALICE_FINGERPRINT, publicKey: alice.publicKey },
    ]);

    const changedMessageId = structuredClone(envelope);
    changedMessageId.messageId = "B_secure_message_id_2026";
    await expect(
      unwrapCiphertext(changedMessageId, ALICE_FINGERPRINT, alice.secretKey),
    ).rejects.toThrow("Unable to decrypt");

    const changedFingerprint = structuredClone(envelope);
    changedFingerprint.recipients[0]!.fingerprint = BOB_FINGERPRINT;
    await expect(
      unwrapCiphertext(changedFingerprint, BOB_FINGERPRINT, alice.secretKey),
    ).rejects.toThrow("Unable to decrypt");

    const changedContent = structuredClone(envelope);
    changedContent.content.ciphertext = mutateBase64Url(changedContent.content.ciphertext);
    await expect(
      unwrapCiphertext(changedContent, ALICE_FINGERPRINT, alice.secretKey),
    ).rejects.toThrow("Unable to decrypt");
  });

  it("rejects wrong keys, duplicate recipients, non-PGP payloads, and extra fields", async () => {
    const alice = keyPair();
    const mallory = keyPair();
    const envelope = await wrapCiphertext(MESSAGE_ID, ARMORED_MESSAGE, [
      { fingerprint: ALICE_FINGERPRINT, publicKey: alice.publicKey },
    ]);

    await expect(
      unwrapCiphertext(envelope, ALICE_FINGERPRINT, mallory.secretKey),
    ).rejects.toThrow("Unable to decrypt");
    await expect(
      wrapCiphertext(MESSAGE_ID, ARMORED_MESSAGE, [
        { fingerprint: ALICE_FINGERPRINT, publicKey: alice.publicKey },
        { fingerprint: ALICE_FINGERPRINT, publicKey: alice.publicKey },
      ]),
    ).rejects.toThrow("Duplicate");
    await expect(
      wrapCiphertext(MESSAGE_ID, "plaintext", [
        { fingerprint: ALICE_FINGERPRINT, publicKey: alice.publicKey },
      ]),
    ).rejects.toThrow("armored OpenPGP");

    const withExtraField = {
      ...envelope,
      plaintext: "must never be accepted",
    } as unknown as HybridEnvelope;
    await expect(
      unwrapCiphertext(withExtraField, ALICE_FINGERPRINT, alice.secretKey),
    ).rejects.toThrow("unexpected or missing fields");
  });
});
