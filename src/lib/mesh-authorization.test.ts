import * as openpgp from "openpgp";
import { describe, expect, it, vi } from "vitest";
import { generateHybridKeyPair } from "./hybrid-crypto";
import { MeshNetwork, type MeshSecurityEvent } from "./mesh";
import { signMeshStatement, type SignedMeshStatement } from "./mesh-statement";
import { signPeerSignal } from "./peer-signal";
import { signIdentityAssertion, type SignedIdentityAssertion } from "./protocol";
import { createRoomSecret } from "./room";

describe("persistent relay authorization", () => {
  it("drops valid dual-signed setup until both direct relayer and origin fingerprints are locally trusted", async () => {
    const relayerKeys = await openpgp.generateKey({
      type: "curve25519",
      userIDs: [{ name: "Relayer" }],
      format: "armored",
    });
    const newcomerKeys = await openpgp.generateKey({
      type: "curve25519",
      userIDs: [{ name: "Newcomer" }],
      format: "armored",
    });
    const relayerPrivate = await openpgp.readPrivateKey({ armoredKey: relayerKeys.privateKey });
    const relayerPublic = await openpgp.readKey({ armoredKey: relayerKeys.publicKey });
    const newcomerPrivate = await openpgp.readPrivateKey({ armoredKey: newcomerKeys.privateKey });
    const newcomerPublic = await openpgp.readKey({ armoredKey: newcomerKeys.publicKey });
    const relayerKem = generateHybridKeyPair();
    const newcomerKem = generateHybridKeyPair();
    const securityEvents: MeshSecurityEvent[] = [];
    const trustedOrigins = new Set<string>();
    const onData = vi.fn();
    const mesh = new MeshNetwork(createRoomSecret(), {
      onData,
      onPeerState: vi.fn(),
      onError: vi.fn(),
      onSecurityEvent: (event) => securityEvents.push(event),
      isPersistentFingerprintTrusted: async (assertion) =>
        trustedOrigins.has(assertion.pgpFingerprint),
    }, []);

    try {
      const roomId = await mesh.connect();
      const relayerPeerId = "R".repeat(24);
      const newcomerPeerId = "N".repeat(24);
      const targetPeerId = "T".repeat(24);
      const relayerFingerprint = relayerPublic.getFingerprint().toUpperCase();
      const relayerIdentity = await signIdentityAssertion({
        version: 1,
        peerId: relayerPeerId,
        roomId,
        displayName: "Relayer",
        pgpFingerprint: relayerFingerprint,
        pgpPublicKey: relayerKeys.publicKey,
        kemAlgorithm: "ML-KEM-768",
        kemPublicKey: relayerKem.publicKey,
        issuedAt: new Date().toISOString(),
        sessionNonce: "A".repeat(24),
      }, relayerPrivate);
      const newcomerIdentity = await signIdentityAssertion({
        version: 1,
        peerId: newcomerPeerId,
        roomId,
        displayName: "Newcomer",
        pgpFingerprint: newcomerPublic.getFingerprint().toUpperCase(),
        pgpPublicKey: newcomerKeys.publicKey,
        kemAlgorithm: "ML-KEM-768",
        kemPublicKey: newcomerKem.publicKey,
        issuedAt: new Date().toISOString(),
        sessionNonce: "B".repeat(24),
      }, newcomerPrivate);
      const originSignal = await signPeerSignal({
        version: 1,
        roomId,
        fromPeerId: newcomerPeerId,
        toPeerId: targetPeerId,
        exchangeId: "E".repeat(24),
        issuedAt: new Date().toISOString(),
        nonce: "S".repeat(24),
        description: { type: "offer", sdp: "v=0\r\n" },
        identity: newcomerIdentity,
      }, newcomerPrivate);
      const statement = await signMeshStatement({
        version: 1,
        roomId,
        relayerPeerId,
        relayerFingerprint,
        targetPeerId,
        hops: 0,
        issuedAt: new Date().toISOString(),
        nonce: "M".repeat(24),
        payload: { type: "relay-signal", signal: originSignal },
      }, relayerPrivate);

      await mesh.observePeerIdentity(relayerPeerId, relayerIdentity);
      const internals = mesh as unknown as {
        authorizedIdentities: Map<string, SignedIdentityAssertion>;
        handleStatement(peerId: string, value: SignedMeshStatement): Promise<void>;
      };

      await internals.handleStatement(relayerPeerId, statement);
      expect(securityEvents).toEqual([{
        type: "untrusted-relay",
        peerId: relayerPeerId,
        fingerprint: relayerFingerprint,
      }]);
      expect(onData).not.toHaveBeenCalled();

      securityEvents.length = 0;
      internals.authorizedIdentities.set(relayerPeerId, relayerIdentity);
      await internals.handleStatement(relayerPeerId, statement);
      expect(securityEvents).toEqual([{
        type: "untrusted-origin",
        peerId: newcomerPeerId,
        fingerprint: newcomerIdentity.pgpFingerprint,
      }]);
      expect(onData).not.toHaveBeenCalled();

      securityEvents.length = 0;
      trustedOrigins.add(newcomerIdentity.pgpFingerprint);
      const retriedStatement = await signMeshStatement({
        version: 1,
        roomId,
        relayerPeerId,
        relayerFingerprint,
        targetPeerId,
        hops: 0,
        issuedAt: new Date().toISOString(),
        nonce: "Q".repeat(24),
        payload: { type: "relay-signal", signal: originSignal },
      }, relayerPrivate);
      await internals.handleStatement(relayerPeerId, retriedStatement);
      expect(securityEvents).toEqual([]);
      expect(onData).not.toHaveBeenCalled();
    } finally {
      relayerKem.secretKey.fill(0);
      newcomerKem.secretKey.fill(0);
      mesh.close();
    }
  }, 30_000);
});
