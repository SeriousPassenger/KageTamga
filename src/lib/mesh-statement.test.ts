import * as openpgp from "openpgp";
import { describe, expect, it } from "vitest";
import { generateHybridKeyPair } from "./hybrid-crypto";
import { signMeshStatement, verifyMeshStatement } from "./mesh-statement";
import { signIdentityAssertion } from "./protocol";

describe("dual-signed peer introductions", () => {
  it("binds the trusted relayer and the newcomer's independently signed identity", async () => {
    const relayerGenerated = await openpgp.generateKey({
      type: "curve25519",
      userIDs: [{ name: "Trusted relayer" }],
      format: "armored",
    });
    const newcomerGenerated = await openpgp.generateKey({
      type: "curve25519",
      userIDs: [{ name: "Newcomer" }],
      format: "armored",
    });
    const relayerPrivateKey = await openpgp.readPrivateKey({ armoredKey: relayerGenerated.privateKey });
    const relayerPublicKey = await openpgp.readKey({ armoredKey: relayerGenerated.publicKey });
    const newcomerPrivateKey = await openpgp.readPrivateKey({ armoredKey: newcomerGenerated.privateKey });
    const newcomerPublicKey = await openpgp.readKey({ armoredKey: newcomerGenerated.publicKey });
    const kem = generateHybridKeyPair();
    const roomId = "R".repeat(43);
    const relayerPeerId = "A".repeat(24);
    const receiverPeerId = "B".repeat(24);
    const newcomerPeerId = "C".repeat(24);
    const relayerFingerprint = relayerPublicKey.getFingerprint().toUpperCase();

    try {
      const newcomerIdentity = await signIdentityAssertion({
        version: 1,
        peerId: newcomerPeerId,
        roomId,
        displayName: "Newcomer",
        pgpFingerprint: newcomerPublicKey.getFingerprint().toUpperCase(),
        pgpPublicKey: newcomerGenerated.publicKey,
        kemAlgorithm: "ML-KEM-768",
        kemPublicKey: kem.publicKey,
        issuedAt: new Date().toISOString(),
        sessionNonce: "I".repeat(24),
      }, newcomerPrivateKey);
      const signed = await signMeshStatement({
        version: 1,
        roomId,
        relayerPeerId,
        relayerFingerprint,
        targetPeerId: receiverPeerId,
        hops: 0,
        issuedAt: new Date().toISOString(),
        nonce: "M".repeat(24),
        payload: { type: "introduction", identity: newcomerIdentity },
      }, relayerPrivateKey);

      await expect(verifyMeshStatement(
        signed,
        relayerGenerated.publicKey,
        roomId,
        relayerPeerId,
        relayerFingerprint,
      )).resolves.toEqual(signed);

      await expect(verifyMeshStatement(
        { ...signed, targetPeerId: "D".repeat(24) },
        relayerGenerated.publicKey,
        roomId,
        relayerPeerId,
        relayerFingerprint,
      )).rejects.toThrow();

      await expect(verifyMeshStatement(
        {
          ...signed,
          payload: {
            type: "introduction",
            identity: { ...newcomerIdentity, displayName: "Forged name" },
          },
        },
        relayerGenerated.publicKey,
        roomId,
        relayerPeerId,
        relayerFingerprint,
      )).rejects.toThrow();

      await expect(verifyMeshStatement(
        signed,
        newcomerGenerated.publicKey,
        roomId,
        relayerPeerId,
        relayerFingerprint,
      )).rejects.toThrow();
    } finally {
      kem.secretKey.fill(0);
    }
  });
});
