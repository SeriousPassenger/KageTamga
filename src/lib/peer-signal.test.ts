import * as openpgp from "openpgp";
import { describe, expect, it } from "vitest";
import { generateHybridKeyPair } from "./hybrid-crypto";
import { signPeerSignal, verifyPeerSignal } from "./peer-signal";
import { signIdentityAssertion } from "./protocol";

describe("signed peer-assisted WebRTC setup", () => {
  it("binds the identity, room, target and complete SDP against relay tampering", async () => {
    const generated = await openpgp.generateKey({
      type: "curve25519",
      userIDs: [{ name: "Introduced peer" }],
      format: "armored",
    });
    const privateKey = await openpgp.readPrivateKey({ armoredKey: generated.privateKey });
    const publicKey = await openpgp.readKey({ armoredKey: generated.publicKey });
    const kem = generateHybridKeyPair();
    const roomId = "R".repeat(43);
    const fromPeerId = "A".repeat(24);
    const toPeerId = "B".repeat(24);
    try {
      const identity = await signIdentityAssertion({
        version: 1,
        peerId: fromPeerId,
        roomId,
        displayName: "Introduced peer",
        pgpFingerprint: publicKey.getFingerprint().toUpperCase(),
        pgpPublicKey: generated.publicKey,
        kemAlgorithm: "ML-KEM-768",
        kemPublicKey: kem.publicKey,
        issuedAt: new Date().toISOString(),
        sessionNonce: "N".repeat(24),
      }, privateKey);
      const signed = await signPeerSignal({
        version: 1,
        roomId,
        fromPeerId,
        toPeerId,
        exchangeId: "E".repeat(24),
        issuedAt: new Date().toISOString(),
        nonce: "S".repeat(24),
        description: { type: "offer", sdp: "v=0\r\n" },
        identity,
      }, privateKey);

      await expect(verifyPeerSignal(signed, roomId, toPeerId)).resolves.toEqual(signed);
      await expect(verifyPeerSignal(
        { ...signed, description: { ...signed.description, sdp: "v=0\r\na=altered\r\n" } },
        roomId,
        toPeerId,
      )).rejects.toThrow();
      await expect(verifyPeerSignal(signed, roomId, "C".repeat(24))).rejects.toThrow();
    } finally {
      kem.secretKey.fill(0);
    }
  });
});
