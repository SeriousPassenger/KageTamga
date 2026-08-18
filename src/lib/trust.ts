import * as openpgp from "openpgp";
import type { PrivateKey } from "openpgp";
import type { StoredContact } from "./db";
import { assertSupportedOpenPgpKey } from "./pgp-policy";

interface TrustFields {
  version: 1;
  name: string;
  fingerprint: string;
  publicKeyArmored: string;
  verifiedAt: string;
  ownerFingerprint: string;
}

export type ContactTrustDecision = "unrelated" | "verified" | "changed";

/** Canonical key used for the one-current-fingerprint-per-display-name contact policy. */
export function normalizeContactName(name: string): string {
  return name.normalize("NFKC").trim().toLocaleLowerCase("en-US");
}

/**
 * Reconcile a signed identity against the current contact occupying its normalized name.
 * A replacement fingerprint therefore invalidates every older same-name identity at once.
 */
export function decideContactTrust(
  displayName: string,
  fingerprint: string,
  contactName: string,
  contactFingerprint: string,
): ContactTrustDecision {
  if (normalizeContactName(displayName) !== normalizeContactName(contactName)) {
    return "unrelated";
  }
  return fingerprint.toUpperCase() === contactFingerprint.toUpperCase()
    ? "verified"
    : "changed";
}

function trustText(fields: TrustFields): string {
  return JSON.stringify({
    version: fields.version,
    name: fields.name,
    fingerprint: fields.fingerprint,
    publicKeyArmored: fields.publicKeyArmored,
    verifiedAt: fields.verifiedAt,
    ownerFingerprint: fields.ownerFingerprint,
  });
}

export async function createTrustedContact(
  name: string,
  fingerprint: string,
  publicKeyArmored: string,
  ownerFingerprint: string,
  ownerPrivateKey: PrivateKey,
): Promise<StoredContact> {
  const contactKey = await openpgp.readKey({ armoredKey: publicKeyArmored });
  await assertSupportedOpenPgpKey(contactKey);
  const canonicalFingerprint = fingerprint.toUpperCase();
  if (contactKey.getFingerprint().toUpperCase() !== canonicalFingerprint) {
    throw new Error("The trusted public key does not match the compared fingerprint.");
  }
  const fields: TrustFields = {
    version: 1,
    name,
    fingerprint: canonicalFingerprint,
    publicKeyArmored: contactKey.armor(),
    verifiedAt: new Date().toISOString(),
    ownerFingerprint: ownerFingerprint.toUpperCase(),
  };
  const signature = await openpgp.sign({
    message: await openpgp.createMessage({ text: trustText(fields) }),
    signingKeys: ownerPrivateKey,
    detached: true,
    format: "armored",
  });
  return { ...fields, signature };
}

export async function verifyTrustedContact(
  contact: StoredContact,
  ownerPublicKeyArmored: string,
  expectedOwnerFingerprint: string,
): Promise<boolean> {
  try {
    const ownerKey = await openpgp.readKey({ armoredKey: ownerPublicKeyArmored });
    if (
      ownerKey.getFingerprint().toUpperCase() !== expectedOwnerFingerprint.toUpperCase() ||
      contact.ownerFingerprint.toUpperCase() !== expectedOwnerFingerprint.toUpperCase()
    ) {
      return false;
    }
    const contactKey = await openpgp.readKey({ armoredKey: contact.publicKeyArmored });
    if (contactKey.getFingerprint().toUpperCase() !== contact.fingerprint.toUpperCase()) return false;
    const fields: TrustFields = {
      version: 1,
      name: contact.name,
      fingerprint: contact.fingerprint,
      publicKeyArmored: contact.publicKeyArmored,
      verifiedAt: contact.verifiedAt,
      ownerFingerprint: contact.ownerFingerprint,
    };
    const verification = await openpgp.verify({
      message: await openpgp.createMessage({ text: trustText(fields) }),
      signature: await openpgp.readSignature({ armoredSignature: contact.signature }),
      verificationKeys: ownerKey,
    });
    if (!verification.signatures[0]) return false;
    await verification.signatures[0].verified;
    return true;
  } catch {
    return false;
  }
}
