import * as openpgp from "openpgp";
import type { PrivateKey } from "openpgp";
import type { StoredIdentity } from "./db";
import {
  deriveHybridPublicKey,
  generateHybridKeyPair,
  protectHybridSecretKey,
  unprotectHybridSecretKey,
} from "./hybrid-crypto";
import { assertSupportedOpenPgpKey } from "./pgp-policy";

export interface IdentityBundle {
  stored: StoredIdentity;
  unlocked: UnlockedIdentity;
}

export interface UnlockedIdentity {
  pgpPrivateKey: PrivateKey;
  hybridSecretKey: Uint8Array<ArrayBuffer>;
}

export interface KeyDetails {
  fingerprint: string;
  createdAt: string;
  expiresAt: string | null;
  algorithm: string;
  userIds: string[];
}

export async function generateIdentity(
  displayName: string,
  passphrase: string,
): Promise<IdentityBundle> {
  const normalizedDisplayName = normalizeDisplayName(displayName);
  const generated = await openpgp.generateKey({
    // OpenPGP.js' dedicated Curve25519 mode uses the standardized Ed25519
    // signing and X25519 encryption algorithms. Keep v4 fingerprints for the
    // explicit 40-hex-digit comparison flow and broad key interoperability.
    type: "curve25519",
    userIDs: [{ name: normalizedDisplayName }],
    passphrase,
    format: "armored",
  });
  const publicKey = await openpgp.readKey({ armoredKey: generated.publicKey });
  await assertSupportedOpenPgpKey(publicKey);
  const privateKey = await openpgp.readPrivateKey({ armoredKey: generated.privateKey });
  const pgpPrivateKey = await openpgp.decryptKey({ privateKey, passphrase });
  const hybrid = generateHybridKeyPair();
  const protectedHybridSecretKey = await protectHybridSecretKey(hybrid.secretKey, passphrase);

  return {
    stored: {
      id: "default",
      displayName: normalizedDisplayName,
      publicKeyArmored: generated.publicKey,
      privateKeyArmored: generated.privateKey,
      revocationCertificate: generated.revocationCertificate,
      fingerprint: publicKey.getFingerprint().toUpperCase(),
      createdAt: new Date().toISOString(),
      hybridPublicKey: hybrid.publicKey,
      protectedHybridSecretKey,
    },
    unlocked: { pgpPrivateKey, hybridSecretKey: hybrid.secretKey },
  };
}

export async function importIdentity(
  displayName: string,
  armoredPrivateKey: string,
  passphrase: string,
): Promise<IdentityBundle> {
  const input = armoredPrivateKey.trim();
  if (input.startsWith("{")) {
    return importIdentityBackup(input, passphrase);
  }
  const normalizedDisplayName = normalizeDisplayName(displayName);

  const parsed = await openpgp.readPrivateKey({ armoredKey: input });
  let unlockedKey: PrivateKey;
  try {
    unlockedKey = await openpgp.decryptKey({ privateKey: parsed, passphrase });
  } catch {
    if (!parsed.isDecrypted()) throw new Error("The private-key passphrase is incorrect.");
    unlockedKey = parsed;
  }

  const protectedKey = parsed.isDecrypted()
    ? await openpgp.encryptKey({ privateKey: parsed, passphrase })
    : parsed;
  const publicKey = protectedKey.toPublic();
  await assertSupportedOpenPgpKey(publicKey);
  const hybrid = generateHybridKeyPair();
  const protectedHybridSecretKey = await protectHybridSecretKey(hybrid.secretKey, passphrase);

  return {
    stored: {
      id: "default",
      displayName: normalizedDisplayName,
      publicKeyArmored: publicKey.armor(),
      privateKeyArmored: protectedKey.armor(),
      fingerprint: publicKey.getFingerprint().toUpperCase(),
      createdAt: new Date().toISOString(),
      hybridPublicKey: hybrid.publicKey,
      protectedHybridSecretKey,
    },
    unlocked: { pgpPrivateKey: unlockedKey, hybridSecretKey: hybrid.secretKey },
  };
}

export async function unlockIdentity(
  identity: StoredIdentity,
  passphrase: string,
): Promise<UnlockedIdentity> {
  const privateKey = await openpgp.readPrivateKey({ armoredKey: identity.privateKeyArmored });
  const derivedPublicKey = privateKey.toPublic();
  const storedPublicKey = await openpgp.readKey({ armoredKey: identity.publicKeyArmored });
  await Promise.all([
    assertSupportedOpenPgpKey(derivedPublicKey),
    assertSupportedOpenPgpKey(storedPublicKey),
  ]);
  const normalizedDerivedPublicKey = derivedPublicKey.armor().replaceAll("\r\n", "\n").trim();
  const normalizedStoredPublicKey = identity.publicKeyArmored.replaceAll("\r\n", "\n").trim();
  if (
    derivedPublicKey.getFingerprint().toUpperCase() !== identity.fingerprint.toUpperCase() ||
    storedPublicKey.getFingerprint().toUpperCase() !== identity.fingerprint.toUpperCase() ||
    normalizedDerivedPublicKey !== normalizedStoredPublicKey
  ) {
    throw new Error("The stored OpenPGP identity components do not match.");
  }
  try {
    const [pgpPrivateKey, hybridSecretKey] = await Promise.all([
      openpgp.decryptKey({ privateKey, passphrase }),
      unprotectHybridSecretKey(identity.protectedHybridSecretKey, passphrase),
    ]);
    if (deriveHybridPublicKey(hybridSecretKey) !== identity.hybridPublicKey) {
      hybridSecretKey.fill(0);
      throw new Error("The post-quantum key backup does not match its public key.");
    }
    return { pgpPrivateKey, hybridSecretKey };
  } catch {
    throw new Error("The passphrase is incorrect.");
  }
}

interface IdentityBackup {
  format: "quietwire-identity-backup";
  version: 1;
  exportedAt: string;
  identity: StoredIdentity;
}

export function exportIdentityBackup(identity: StoredIdentity): string {
  const backup: IdentityBackup = {
    format: "quietwire-identity-backup",
    version: 1,
    exportedAt: new Date().toISOString(),
    identity,
  };
  return `${JSON.stringify(backup, null, 2)}\n`;
}

export async function importIdentityBackup(
  contents: string,
  passphrase: string,
): Promise<IdentityBundle> {
  const parsed = JSON.parse(contents) as Partial<IdentityBackup>;
  const backupKeys = parsed && typeof parsed === "object" ? Object.keys(parsed).sort() : [];
  if (
    backupKeys.join(",") !== "exportedAt,format,identity,version" ||
    parsed.format !== "quietwire-identity-backup" ||
    parsed.version !== 1 ||
    typeof parsed.exportedAt !== "string" ||
    new Date(parsed.exportedAt).toISOString() !== parsed.exportedAt ||
    !parsed.identity ||
    typeof parsed.identity !== "object"
  ) {
    throw new Error("This is not a supported QuietWire identity backup.");
  }
  const identity = parsed.identity as StoredIdentity;
  assertStoredIdentity(identity);
  const unlocked = await unlockIdentity(identity, passphrase);
  const privatePublicKey = unlocked.pgpPrivateKey.toPublic();
  await assertSupportedOpenPgpKey(privatePublicKey);
  if (
    privatePublicKey.getFingerprint().toUpperCase() !== identity.fingerprint.toUpperCase() ||
    privatePublicKey.armor().replaceAll("\r\n", "\n").trim() !==
      identity.publicKeyArmored.replaceAll("\r\n", "\n").trim()
  ) {
    unlocked.hybridSecretKey.fill(0);
    throw new Error("The backup's public and private OpenPGP keys do not match.");
  }
  return { stored: identity, unlocked };
}

function assertStoredIdentity(identity: StoredIdentity): void {
  const keys = Object.keys(identity).sort();
  const expectedWithoutRevocation = [
    "createdAt",
    "displayName",
    "fingerprint",
    "hybridPublicKey",
    "id",
    "privateKeyArmored",
    "protectedHybridSecretKey",
    "publicKeyArmored",
  ];
  const expectedWithRevocation = [...expectedWithoutRevocation, "revocationCertificate"].sort();
  const exactShape = [expectedWithoutRevocation, expectedWithRevocation].some((expected) =>
    keys.length === expected.length && keys.every((key, index) => key === expected[index]));
  if (
    !exactShape ||
    identity.id !== "default" ||
    typeof identity.displayName !== "string" ||
    identity.displayName.length < 1 ||
    identity.displayName.length > 64 ||
    identity.displayName !== identity.displayName.normalize("NFKC").trim() ||
    /[\p{Cc}\p{Cf}\p{Cs}\p{Zl}\p{Zp}]/u.test(identity.displayName) ||
    typeof identity.publicKeyArmored !== "string" ||
    identity.publicKeyArmored.length > 100_000 ||
    typeof identity.privateKeyArmored !== "string" ||
    identity.privateKeyArmored.length > 200_000 ||
    (identity.revocationCertificate !== undefined &&
      (typeof identity.revocationCertificate !== "string" ||
        identity.revocationCertificate.length > 50_000)) ||
    typeof identity.fingerprint !== "string" ||
    !/^[A-Fa-f0-9]{40}$/u.test(identity.fingerprint) ||
    typeof identity.createdAt !== "string" ||
    identity.createdAt.length !== 24 ||
    new Date(identity.createdAt).toISOString() !== identity.createdAt ||
    typeof identity.hybridPublicKey !== "string" ||
    !identity.protectedHybridSecretKey ||
    typeof identity.protectedHybridSecretKey !== "object"
  ) {
    throw new Error("The identity backup is malformed.");
  }
}

function normalizeDisplayName(value: string): string {
  const normalized = value.normalize("NFKC").trim();
  if (
    normalized.length < 1 ||
    normalized.length > 64 ||
    /[\p{Cc}\p{Cf}\p{Cs}\p{Zl}\p{Zp}]/u.test(normalized)
  ) {
    throw new Error("The display name is malformed.");
  }
  return normalized;
}

export async function publicKeyDetails(armoredKey: string): Promise<KeyDetails> {
  const key = await openpgp.readKey({ armoredKey });
  const expiration = await key.getExpirationTime();
  return {
    fingerprint: key.getFingerprint().toUpperCase(),
    createdAt: key.getCreationTime().toISOString(),
    expiresAt: expiration instanceof Date ? expiration.toISOString() : null,
    algorithm: key.getAlgorithmInfo().algorithm,
    userIds: key.getUserIDs(),
  };
}

export function groupedFingerprint(fingerprint: string): string {
  return fingerprint.replace(/\s/gu, "").match(/.{1,4}/gu)?.join(" ") ?? fingerprint;
}

export function downloadText(filename: string, text: string): void {
  const url = URL.createObjectURL(new Blob([text], { type: "text/plain;charset=utf-8" }));
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}
