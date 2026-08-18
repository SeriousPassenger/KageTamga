import * as openpgp from "openpgp";
import type { PrivateKey } from "openpgp";
import { beforeAll, describe, expect, it } from "vitest";
import { randomId } from "./encoding";
import {
  generateHybridKeyPair,
  wrapCiphertext,
  type HybridEnvelope,
} from "./hybrid-crypto";
import {
  signDeliveryManifest,
  signTrustAnnouncement,
  verifyDeliveryManifest,
  verifyTrustAnnouncement,
  type DeliveryManifestFields,
  type TrustAnnouncementFields,
} from "./room-events";

interface TestIdentity {
  privateKey: PrivateKey;
  publicKeyArmored: string;
  fingerprint: string;
}

const ARMORED_MESSAGE = [
  "-----BEGIN PGP MESSAGE-----",
  "",
  "cm9vbS1ldmVudC10ZXN0",
  "-----END PGP MESSAGE-----",
].join("\n");

let alice: TestIdentity;
let bob: TestIdentity;
let mallory: TestIdentity;

beforeAll(async () => {
  [alice, bob, mallory] = await Promise.all([
    testIdentity("Alice"),
    testIdentity("Bob"),
    testIdentity("Mallory"),
  ]);
});

async function testIdentity(name: string): Promise<TestIdentity> {
  const generated = await openpgp.generateKey({
    type: "ecc",
    curve: "curve25519Legacy",
    userIDs: [{ name }],
    format: "armored",
  });
  const privateKey = await openpgp.readPrivateKey({ armoredKey: generated.privateKey });
  const publicKey = await openpgp.readKey({ armoredKey: generated.publicKey });
  return {
    privateKey,
    publicKeyArmored: generated.publicKey,
    fingerprint: publicKey.getFingerprint().toUpperCase(),
  };
}

async function testEnvelope(messageId = randomId()): Promise<HybridEnvelope> {
  const aliceKem = generateHybridKeyPair();
  const bobKem = generateHybridKeyPair();
  try {
    return await wrapCiphertext(messageId, ARMORED_MESSAGE, [
      { fingerprint: alice.fingerprint, publicKey: aliceKem.publicKey },
      { fingerprint: bob.fingerprint, publicKey: bobKem.publicKey },
    ]);
  } finally {
    aliceKem.secretKey.fill(0);
    bobKem.secretKey.fill(0);
  }
}

function deliveryFields(roomId: string, senderPeerId: string): DeliveryManifestFields {
  return {
    version: 1,
    roomId,
    senderPeerId,
    senderName: "Alice",
    senderFingerprint: alice.fingerprint,
    sentAt: "2020-01-02T03:04:05.000Z",
  };
}

function mutateBase64Url(value: string): string {
  const index = Math.floor(value.length / 2);
  return `${value.slice(0, index)}${value[index] === "A" ? "B" : "A"}${value.slice(index + 1)}`;
}

describe("signed delivery manifests", () => {
  it("round-trips and binds a historical delivery to canonical envelope bytes", async () => {
    const roomId = randomId(32);
    const senderPeerId = randomId();
    const envelope = await testEnvelope();
    const manifest = await signDeliveryManifest(
      deliveryFields(roomId, senderPeerId),
      envelope,
      alice.privateKey,
    );

    expect(manifest.messageId).toBe(envelope.messageId);
    expect(manifest.envelopeDigest).toMatch(/^[A-Za-z0-9_-]{43}$/u);
    expect(manifest.recipientFingerprints).toEqual(
      [alice.fingerprint, bob.fingerprint].sort(),
    );
    await expect(
      verifyDeliveryManifest(
        manifest,
        envelope,
        alice.publicKeyArmored,
        roomId,
        senderPeerId,
        alice.fingerprint,
      ),
    ).resolves.toEqual(manifest);
  });

  it("rejects tampered envelope bytes and recipient bindings", async () => {
    const roomId = randomId(32);
    const senderPeerId = randomId();
    const envelope = await testEnvelope();
    const manifest = await signDeliveryManifest(
      deliveryFields(roomId, senderPeerId),
      envelope,
      alice.privateKey,
    );

    const changedEnvelope = structuredClone(envelope);
    changedEnvelope.content.ciphertext = mutateBase64Url(
      changedEnvelope.content.ciphertext,
    );
    await expect(
      verifyDeliveryManifest(
        manifest,
        changedEnvelope,
        alice.publicKeyArmored,
        roomId,
        senderPeerId,
        alice.fingerprint,
      ),
    ).rejects.toThrow("does not match");

    const changedRecipients = structuredClone(manifest);
    changedRecipients.recipientFingerprints = [
      ...new Set(["0000000000000000000000000000000000000000", bob.fingerprint]),
    ].sort();
    await expect(
      verifyDeliveryManifest(
        changedRecipients,
        envelope,
        alice.publicKeyArmored,
        roomId,
        senderPeerId,
        alice.fingerprint,
      ),
    ).rejects.toThrow("does not match");
  });

  it("rejects the wrong signer, room, and extra event fields", async () => {
    const roomId = randomId(32);
    const senderPeerId = randomId();
    const envelope = await testEnvelope();
    const manifest = await signDeliveryManifest(
      deliveryFields(roomId, senderPeerId),
      envelope,
      alice.privateKey,
    );

    await expect(
      verifyDeliveryManifest(
        manifest,
        envelope,
        mallory.publicKeyArmored,
        roomId,
        senderPeerId,
        alice.fingerprint,
      ),
    ).rejects.toThrow("does not match");
    await expect(
      verifyDeliveryManifest(
        manifest,
        envelope,
        alice.publicKeyArmored,
        randomId(32),
        senderPeerId,
        alice.fingerprint,
      ),
    ).rejects.toThrow("context");
    await expect(
      verifyDeliveryManifest(
        { ...manifest, trusted: true },
        envelope,
        alice.publicKeyArmored,
        roomId,
        senderPeerId,
        alice.fingerprint,
      ),
    ).rejects.toThrow("unexpected or missing fields");
  });
});

describe("directional trust announcements", () => {
  it("authenticates only the expected initiator's room-bound statement", async () => {
    const roomId = randomId(32);
    const alicePeerId = randomId();
    const fields: TrustAnnouncementFields = {
      version: 1,
      roomId,
      initiatorPeerId: alicePeerId,
      initiatorFingerprint: alice.fingerprint,
      subjectFingerprint: bob.fingerprint,
      issuedAt: new Date().toISOString(),
      nonce: randomId(),
      state: "trusted",
    };
    const announcement = await signTrustAnnouncement(fields, alice.privateKey);

    await expect(
      verifyTrustAnnouncement(
        announcement,
        alice.publicKeyArmored,
        roomId,
        alicePeerId,
        alice.fingerprint,
      ),
    ).resolves.toEqual(announcement);

    // Alice -> Bob cannot be reinterpreted as Bob -> Alice.
    await expect(
      verifyTrustAnnouncement(
        announcement,
        bob.publicKeyArmored,
        roomId,
        alicePeerId,
        bob.fingerprint,
      ),
    ).rejects.toThrow("context");
    await expect(
      verifyTrustAnnouncement(
        announcement,
        alice.publicKeyArmored,
        roomId,
        randomId(),
        alice.fingerprint,
      ),
    ).rejects.toThrow("context");

    const changedSubject = {
      ...announcement,
      subjectFingerprint: mallory.fingerprint,
    };
    await expect(
      verifyTrustAnnouncement(
        changedSubject,
        alice.publicKeyArmored,
        roomId,
        alicePeerId,
        alice.fingerprint,
      ),
    ).rejects.toThrow();
  });

  it("rejects stale announcements outside the ten-minute window", async () => {
    const now = Date.now();
    const roomId = randomId(32);
    const alicePeerId = randomId();
    const announcement = await signTrustAnnouncement(
      {
        version: 1,
        roomId,
        initiatorPeerId: alicePeerId,
        initiatorFingerprint: alice.fingerprint,
        subjectFingerprint: bob.fingerprint,
        issuedAt: new Date(now).toISOString(),
        nonce: randomId(),
        state: "trusted",
      },
      alice.privateKey,
    );

    await expect(
      verifyTrustAnnouncement(
        announcement,
        alice.publicKeyArmored,
        roomId,
        alicePeerId,
        alice.fingerprint,
        now + 10 * 60 * 1000 + 1,
      ),
    ).rejects.toThrow("ten-minute");
  });
});
