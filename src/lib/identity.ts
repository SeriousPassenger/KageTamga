import * as openpgp from "openpgp";
import type { PrivateKey } from "openpgp";
import type { StoredContact, StoredIdentity } from "./db";
import { decodeUtf8, fromBase64Url, toBase64Url, utf8 } from "./encoding";
import {
  deriveHybridPublicKey,
  generateHybridKeyPair,
  protectHybridSecretKey,
  unprotectHybridSecretKey,
} from "./hybrid-crypto";
import { assertSupportedOpenPgpKey } from "./pgp-policy";
import { verifyTrustedContact } from "./trust";

export interface IdentityBundle {
  stored: StoredIdentity;
  unlocked: UnlockedIdentity;
  contacts: StoredContact[];
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
    contacts: [],
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
    contacts: [],
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

interface EncryptedIdentityBackup {
  format: "kagetamga-encrypted-backup";
  version: 2;
  exportedAt: string;
  keyProtection: StoredIdentity["protectedHybridSecretKey"];
  encryption: {
    algorithm: "ML-KEM-768-secret/HKDF-SHA-512/AES-256-GCM-v1";
    salt: string;
    iv: string;
    ciphertext: string;
  };
}

interface BackupPayload {
  version: 1;
  identity: StoredIdentity;
  trustedContacts: StoredContact[];
}

const BACKUP_ALGORITHM = "ML-KEM-768-secret/HKDF-SHA-512/AES-256-GCM-v1" as const;
const MAX_BACKUP_CONTACTS = 64;

export async function exportIdentityBackup(
  identity: StoredIdentity,
  unlocked: UnlockedIdentity,
  contacts: readonly StoredContact[],
): Promise<string> {
  assertStoredIdentity(identity);
  if (deriveHybridPublicKey(unlocked.hybridSecretKey) !== identity.hybridPublicKey) {
    throw new Error("The unlocked post-quantum key does not match this identity.");
  }
  const trustedContacts = await validateBackupContacts(contacts, identity);
  const exportedAt = new Date().toISOString();
  const salt = crypto.getRandomValues(new Uint8Array(32));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveBackupEncryptionKey(unlocked.hybridSecretKey, salt);
  const keyProtection = identity.protectedHybridSecretKey;
  const payload: BackupPayload = { version: 1, identity, trustedContacts };
  const ciphertext = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv,
      additionalData: backupAdditionalData(exportedAt, keyProtection),
    },
    key,
    utf8(JSON.stringify(payload)),
  );
  const backup: EncryptedIdentityBackup = {
    format: "kagetamga-encrypted-backup",
    version: 2,
    exportedAt,
    keyProtection,
    encryption: {
      algorithm: BACKUP_ALGORITHM,
      salt: toBase64Url(salt),
      iv: toBase64Url(iv),
      ciphertext: toBase64Url(new Uint8Array(ciphertext)),
    },
  };
  return `${JSON.stringify(backup, null, 2)}\n`;
}

export async function importIdentityBackup(
  contents: string,
  passphrase: string,
): Promise<IdentityBundle> {
  const parsed = JSON.parse(contents) as Partial<EncryptedIdentityBackup>;
  const backupKeys = parsed && typeof parsed === "object" ? Object.keys(parsed).sort() : [];
  if (
    backupKeys.join(",") !== "encryption,exportedAt,format,keyProtection,version" ||
    parsed.format !== "kagetamga-encrypted-backup" ||
    parsed.version !== 2 ||
    typeof parsed.exportedAt !== "string" ||
    new Date(parsed.exportedAt).toISOString() !== parsed.exportedAt ||
    !parsed.keyProtection ||
    typeof parsed.keyProtection !== "object" ||
    !parsed.encryption ||
    typeof parsed.encryption !== "object" ||
    Object.keys(parsed.encryption).sort().join(",") !== "algorithm,ciphertext,iv,salt" ||
    parsed.encryption.algorithm !== BACKUP_ALGORITHM ||
    !isCanonicalBase64Url(parsed.encryption.salt, 32) ||
    !isCanonicalBase64Url(parsed.encryption.iv, 12) ||
    typeof parsed.encryption.ciphertext !== "string" ||
    parsed.encryption.ciphertext.length < 24 ||
    parsed.encryption.ciphertext.length > 4 * 1024 * 1024 ||
    !isCanonicalBase64Url(parsed.encryption.ciphertext)
  ) {
    throw new Error("This is not a supported encrypted KageTamga backup.");
  }
  const hybridSecretKey = await unprotectHybridSecretKey(parsed.keyProtection, passphrase);
  let payload: BackupPayload;
  try {
    const key = await deriveBackupEncryptionKey(
      hybridSecretKey,
      fromBase64Url(parsed.encryption.salt),
    );
    const plaintext = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: fromBase64Url(parsed.encryption.iv),
        additionalData: backupAdditionalData(parsed.exportedAt, parsed.keyProtection),
      },
      key,
      fromBase64Url(parsed.encryption.ciphertext),
    );
    const value = JSON.parse(decodeUtf8(plaintext)) as Partial<BackupPayload>;
    if (
      !value ||
      typeof value !== "object" ||
      Object.keys(value).sort().join(",") !== "identity,trustedContacts,version" ||
      value.version !== 1 ||
      !value.identity ||
      typeof value.identity !== "object" ||
      !Array.isArray(value.trustedContacts)
    ) {
      throw new Error("The decrypted backup payload is malformed.");
    }
    payload = value as BackupPayload;
  } finally {
    hybridSecretKey.fill(0);
  }
  const identity = payload.identity;
  assertStoredIdentity(identity);
  if (JSON.stringify(identity.protectedHybridSecretKey) !== JSON.stringify(parsed.keyProtection)) {
    throw new Error("The encrypted backup key header does not match its identity payload.");
  }
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
  const contacts = await validateBackupContacts(payload.trustedContacts, identity);
  return { stored: identity, unlocked, contacts };
}

async function deriveBackupEncryptionKey(
  hybridSecretKey: Uint8Array<ArrayBuffer>,
  salt: Uint8Array<ArrayBuffer>,
): Promise<CryptoKey> {
  const material = await crypto.subtle.importKey(
    "raw",
    hybridSecretKey,
    "HKDF",
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-512",
      salt,
      info: utf8("kagetamga:encrypted-identity-backup:v2"),
    },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

function backupAdditionalData(
  exportedAt: string,
  keyProtection: StoredIdentity["protectedHybridSecretKey"],
): Uint8Array<ArrayBuffer> {
  return utf8(JSON.stringify({
    format: "kagetamga-encrypted-backup",
    version: 2,
    exportedAt,
    algorithm: BACKUP_ALGORITHM,
    keyProtection,
  }));
}

async function validateBackupContacts(
  contacts: readonly StoredContact[],
  identity: StoredIdentity,
): Promise<StoredContact[]> {
  if (contacts.length > MAX_BACKUP_CONTACTS) throw new Error("The trusted fingerprint list is too large.");
  const names = new Set<string>();
  const validated: StoredContact[] = [];
  for (const contact of contacts) {
    assertStoredContact(contact);
    if (names.has(contact.name)) throw new Error("The trusted fingerprint list contains duplicate names.");
    names.add(contact.name);
    if (!await verifyTrustedContact(contact, identity.publicKeyArmored, identity.fingerprint)) {
      throw new Error("A trusted fingerprint record has an invalid owner signature.");
    }
    validated.push(contact);
  }
  return validated.sort((left, right) => left.name.localeCompare(right.name));
}

function assertStoredContact(contact: StoredContact): void {
  if (
    !contact ||
    typeof contact !== "object" ||
    Object.keys(contact).sort().join(",") !==
      "fingerprint,name,ownerFingerprint,publicKeyArmored,signature,verifiedAt,version" ||
    contact.version !== 1 ||
    typeof contact.name !== "string" ||
    contact.name.length < 1 ||
    contact.name.length > 64 ||
    contact.name !== contact.name.normalize("NFKC").trim() ||
    typeof contact.fingerprint !== "string" ||
    !/^[A-F0-9]{40}$/u.test(contact.fingerprint) ||
    typeof contact.ownerFingerprint !== "string" ||
    !/^[A-F0-9]{40}$/u.test(contact.ownerFingerprint) ||
    typeof contact.publicKeyArmored !== "string" ||
    contact.publicKeyArmored.length < 1 ||
    contact.publicKeyArmored.length > 100_000 ||
    typeof contact.verifiedAt !== "string" ||
    contact.verifiedAt.length !== 24 ||
    new Date(contact.verifiedAt).toISOString() !== contact.verifiedAt ||
    typeof contact.signature !== "string" ||
    contact.signature.length < 1 ||
    contact.signature.length > 20_000
  ) {
    throw new Error("A trusted fingerprint record in the backup is malformed.");
  }
}

function isCanonicalBase64Url(value: string, expectedBytes?: number): boolean {
  try {
    const decoded = fromBase64Url(value);
    return (expectedBytes === undefined || decoded.byteLength === expectedBytes) &&
      toBase64Url(decoded) === value;
  } catch {
    return false;
  }
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

export function safeBackupBaseName(value: string): string {
  return value.normalize("NFKD").replace(/[^A-Za-z0-9_-]+/gu, "-").replace(/^-|-$/gu, "") || "identity";
}

export function downloadText(filename: string, text: string): void {
  const url = URL.createObjectURL(new Blob([text], { type: "text/plain;charset=utf-8" }));
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}
