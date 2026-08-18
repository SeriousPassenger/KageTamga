import { describe, expect, it } from "vitest";
import * as openpgp from "openpgp";
import { assertSupportedOpenPgpKey } from "./pgp-policy";

describe("OpenPGP identity policy", () => {
  it("accepts a v4 Ed25519/X25519 identity", async () => {
    const { publicKey } = await openpgp.generateKey({
      type: "curve25519",
      userIDs: [{ name: "Policy test" }],
      format: "object",
    });
    await expect(assertSupportedOpenPgpKey(publicKey)).resolves.toBeUndefined();
    expect(publicKey.getFingerprint()).toHaveLength(40);
  });

  it("accepts the explicitly supported legacy Ed25519/Curve25519 encoding", async () => {
    const { publicKey } = await openpgp.generateKey({
      type: "ecc",
      curve: "ed25519Legacy",
      userIDs: [{ name: "Legacy policy test" }],
      format: "object",
    });
    await expect(assertSupportedOpenPgpKey(publicKey)).resolves.toBeUndefined();
    expect(publicKey.getAlgorithmInfo()).toMatchObject({
      algorithm: "eddsaLegacy",
      curve: "ed25519Legacy",
    });
    expect((await publicKey.getEncryptionKey()).getAlgorithmInfo()).toMatchObject({
      algorithm: "ecdh",
      curve: "curve25519Legacy",
    });
  });

  it("rejects an imported non-Curve25519 identity", async () => {
    const { publicKey } = await openpgp.generateKey({
      type: "ecc",
      curve: "nistP256",
      userIDs: [{ name: "Policy test" }],
      format: "object",
    });
    await expect(assertSupportedOpenPgpKey(publicKey)).rejects.toThrow(
      "Only OpenPGP Ed25519/X25519 identities are supported.",
    );
  });

  it("rejects an RSA primary even when its selected subkeys are Ed25519/X25519", async () => {
    const { publicKey } = await openpgp.generateKey({
      type: "rsa",
      rsaBits: 2_048,
      userIDs: [{ name: "Mixed primary policy test" }],
      subkeys: [
        { type: "curve25519", sign: true },
        { type: "curve25519" },
      ],
      format: "object",
    });

    expect(publicKey.getAlgorithmInfo().algorithm).toBe("rsaEncryptSign");
    expect((await publicKey.getSigningKey()).getAlgorithmInfo().algorithm).toBe("ed25519");
    expect((await publicKey.getEncryptionKey()).getAlgorithmInfo().algorithm).toBe("x25519");
    await expect(assertSupportedOpenPgpKey(publicKey)).rejects.toThrow(
      "Only OpenPGP Ed25519/X25519 identities are supported.",
    );
  });

  it("rejects an otherwise supported certificate carrying an RSA signing subkey", async () => {
    const base = new Date("2025-01-01T00:00:00.000Z");
    const { privateKey, publicKey } = await openpgp.generateKey({
      type: "curve25519",
      date: base,
      userIDs: [{ name: "Mixed subkey policy test" }],
      subkeys: [
        { type: "rsa", rsaBits: 2_048, sign: true, date: new Date(base.getTime() + 1_000) },
        { type: "curve25519", sign: true, date: new Date(base.getTime() + 2_000) },
        { type: "curve25519", date: new Date(base.getTime() + 3_000) },
      ],
      format: "object",
    });
    const rsaSigningSubkey = privateKey.subkeys.find(
      (subkey) => subkey.getAlgorithmInfo().algorithm === "rsaEncryptSign",
    );
    expect(rsaSigningSubkey).toBeDefined();
    expect((await publicKey.getSigningKey()).getAlgorithmInfo().algorithm).toBe("ed25519");
    expect((await publicKey.getEncryptionKey()).getAlgorithmInfo().algorithm).toBe("x25519");

    const message = await openpgp.createMessage({ text: "mixed-certificate signature" });
    const signature = await openpgp.sign({
      message,
      signingKeys: privateKey,
      signingKeyIDs: rsaSigningSubkey!.getKeyID(),
      detached: true,
      format: "armored",
    });
    const verification = await openpgp.verify({
      message,
      signature: await openpgp.readSignature({ armoredSignature: signature }),
      verificationKeys: publicKey,
    });
    await expect(verification.signatures[0]!.verified).resolves.toBe(true);

    await expect(assertSupportedOpenPgpKey(publicKey)).rejects.toThrow(
      "Only OpenPGP Ed25519/X25519 identities are supported.",
    );
  });
});
