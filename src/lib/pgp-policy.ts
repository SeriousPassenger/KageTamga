import type { AlgorithmInfo, Key } from "openpgp";

function isSupportedSigningAlgorithm(info: AlgorithmInfo): boolean {
  return (
    info.algorithm === "ed25519" ||
    (info.algorithm === "eddsaLegacy" && info.curve === "ed25519Legacy")
  );
}

function isSupportedEncryptionAlgorithm(info: AlgorithmInfo): boolean {
  return (
    info.algorithm === "x25519" ||
    (info.algorithm === "ecdh" && info.curve === "curve25519Legacy")
  );
}

/**
 * QuietWire deliberately accepts only Curve25519 OpenPGP identities. This
 * keeps the security label accurate and prevents an imported legacy key from
 * silently weakening the signature or encryption layer.
 */
export async function assertSupportedOpenPgpKey(key: Key): Promise<void> {
  if (!/^[A-Fa-f0-9]{40}$/u.test(key.getFingerprint())) {
    throw new Error("Only OpenPGP v4 keys with 40-digit fingerprints are supported.");
  }
  await key.verifyPrimaryKey();
  if (await key.isRevoked()) throw new Error("The OpenPGP key is revoked.");

  const expiration = await key.getExpirationTime();
  if (expiration instanceof Date && expiration.getTime() <= Date.now()) {
    throw new Error("The OpenPGP key is expired.");
  }

  const primary = key.getAlgorithmInfo();
  const [signingKey, encryptionKey] = await Promise.all([
    key.getSigningKey(),
    key.getEncryptionKey(),
  ]);
  const signing = signingKey.getAlgorithmInfo();
  const encryption = encryptionKey.getAlgorithmInfo();
  const hasUnsupportedSubkey = key.subkeys.some((subkey) => {
    const info = subkey.getAlgorithmInfo();
    return !isSupportedSigningAlgorithm(info) && !isSupportedEncryptionAlgorithm(info);
  });

  if (
    !isSupportedSigningAlgorithm(primary) ||
    !isSupportedSigningAlgorithm(signing) ||
    encryptionKey === key ||
    !isSupportedEncryptionAlgorithm(encryption) ||
    hasUnsupportedSubkey
  ) {
    throw new Error("Only OpenPGP Ed25519/X25519 identities are supported.");
  }
}
