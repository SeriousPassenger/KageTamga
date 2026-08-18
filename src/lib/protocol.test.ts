import * as openpgp from "openpgp";
import { describe, expect, it } from "vitest";
import { randomId } from "./encoding";
import {
  PROTOCOL_VERSION,
  signIdentityAssertion,
  verifyIdentityAssertion,
} from "./protocol";

describe("signed identity assertions", () => {
  it("binds the username and KEM key to the room, peer id, and PGP key", async () => {
    const generated = await openpgp.generateKey({
      type: "ecc",
      curve: "curve25519Legacy",
      userIDs: [{ name: "Alice" }],
      format: "armored",
    });
    const privateKey = await openpgp.readPrivateKey({ armoredKey: generated.privateKey });
    const publicKey = await openpgp.readKey({ armoredKey: generated.publicKey });
    const peerId = randomId();
    const roomId = randomId(32);
    const assertion = await signIdentityAssertion(
      {
        version: PROTOCOL_VERSION,
        peerId,
        roomId,
        displayName: "Alice",
        pgpFingerprint: publicKey.getFingerprint().toUpperCase(),
        pgpPublicKey: generated.publicKey,
        kemAlgorithm: "ML-KEM-768",
        kemPublicKey: "A".repeat(1579),
        issuedAt: new Date().toISOString(),
        sessionNonce: randomId(),
      },
      privateKey,
    );
    await expect(verifyIdentityAssertion(assertion, peerId, roomId)).resolves.toMatchObject({
      displayName: "Alice",
      peerId,
      roomId,
    });

    await expect(
      verifyIdentityAssertion({ ...assertion, displayName: "Mallory" }, peerId, roomId),
    ).rejects.toThrow();
    await expect(
      verifyIdentityAssertion({ ...assertion, displayName: "Alice\u202E" }, peerId, roomId),
    ).rejects.toThrow("Malformed identity assertion");
  });
});
