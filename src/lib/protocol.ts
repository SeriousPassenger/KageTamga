import * as openpgp from "openpgp";
import type { PrivateKey } from "openpgp";
import { assertHybridPublicKey } from "./hybrid-crypto";
import { assertSupportedOpenPgpKey } from "./pgp-policy";

export const PROTOCOL_VERSION = 1 as const;
const ASSERTION_MAX_CLOCK_SKEW_MS = 10 * 60 * 1000;

export interface IdentityAssertionFields {
  version: typeof PROTOCOL_VERSION;
  peerId: string;
  roomId: string;
  displayName: string;
  pgpFingerprint: string;
  pgpPublicKey: string;
  kemAlgorithm: "ML-KEM-768";
  kemPublicKey: string;
  issuedAt: string;
  sessionNonce: string;
}

export interface SignedIdentityAssertion extends IdentityAssertionFields {
  kind: "identity-assertion";
  signature: string;
}

function signedText(fields: IdentityAssertionFields): string {
  return JSON.stringify({
    version: fields.version,
    peerId: fields.peerId,
    roomId: fields.roomId,
    displayName: fields.displayName,
    pgpFingerprint: fields.pgpFingerprint,
    pgpPublicKey: fields.pgpPublicKey,
    kemAlgorithm: fields.kemAlgorithm,
    kemPublicKey: fields.kemPublicKey,
    issuedAt: fields.issuedAt,
    sessionNonce: fields.sessionNonce,
  });
}

export async function signIdentityAssertion(
  fields: IdentityAssertionFields,
  privateKey: PrivateKey,
): Promise<SignedIdentityAssertion> {
  const signature = await openpgp.sign({
    message: await openpgp.createMessage({ text: signedText(fields) }),
    signingKeys: privateKey,
    detached: true,
    format: "armored",
  });
  return { kind: "identity-assertion", ...fields, signature };
}

export async function verifyIdentityAssertion(
  value: unknown,
  expectedPeerId: string,
  expectedRoomId: string,
  now = Date.now(),
): Promise<SignedIdentityAssertion> {
  if (!value || typeof value !== "object") throw new Error("Missing identity assertion");
  const assertion = value as Partial<SignedIdentityAssertion>;
  const keys = Object.keys(assertion).sort();
  const expectedKeys = [
    "displayName",
    "issuedAt",
    "kemAlgorithm",
    "kemPublicKey",
    "kind",
    "peerId",
    "pgpFingerprint",
    "pgpPublicKey",
    "roomId",
    "sessionNonce",
    "signature",
    "version",
  ];
  if (
    !Number.isFinite(now) ||
    keys.length !== expectedKeys.length ||
    keys.some((key, index) => key !== expectedKeys[index]) ||
    assertion.kind !== "identity-assertion" ||
    assertion.version !== PROTOCOL_VERSION ||
    assertion.peerId !== expectedPeerId ||
    !/^[A-Za-z0-9_-]{16,64}$/u.test(assertion.peerId) ||
    assertion.roomId !== expectedRoomId ||
    !/^[A-Za-z0-9_-]{43}$/u.test(assertion.roomId) ||
    typeof assertion.displayName !== "string" ||
    assertion.displayName.length < 1 ||
    assertion.displayName.length > 64 ||
    assertion.displayName !== assertion.displayName.normalize("NFKC").trim() ||
    /[\p{Cc}\p{Cf}\p{Cs}\p{Zl}\p{Zp}]/u.test(assertion.displayName) ||
    typeof assertion.pgpFingerprint !== "string" ||
    !/^[A-Fa-f0-9]{40}$/u.test(assertion.pgpFingerprint) ||
    typeof assertion.pgpPublicKey !== "string" ||
    assertion.pgpPublicKey.length > 100_000 ||
    assertion.kemAlgorithm !== "ML-KEM-768" ||
    typeof assertion.kemPublicKey !== "string" ||
    assertion.kemPublicKey.length > 4_000 ||
    typeof assertion.issuedAt !== "string" ||
    assertion.issuedAt.length !== 24 ||
    !Number.isFinite(Date.parse(assertion.issuedAt)) ||
    new Date(Date.parse(assertion.issuedAt)).toISOString() !== assertion.issuedAt ||
    Math.abs(Date.parse(assertion.issuedAt) - now) > ASSERTION_MAX_CLOCK_SKEW_MS ||
    typeof assertion.sessionNonce !== "string" ||
    !/^[A-Za-z0-9_-]{22,64}$/u.test(assertion.sessionNonce) ||
    typeof assertion.signature !== "string" ||
    assertion.signature.length > 20_000
  ) {
    throw new Error("Malformed identity assertion");
  }
  assertHybridPublicKey(assertion.kemPublicKey);

  const publicKey = await openpgp.readKey({ armoredKey: assertion.pgpPublicKey });
  await assertSupportedOpenPgpKey(publicKey);
  const actualFingerprint = publicKey.getFingerprint().toUpperCase();
  if (actualFingerprint !== assertion.pgpFingerprint.toUpperCase()) {
    throw new Error("Public-key fingerprint mismatch");
  }

  const fields: IdentityAssertionFields = {
    version: PROTOCOL_VERSION,
    peerId: assertion.peerId,
    roomId: assertion.roomId,
    displayName: assertion.displayName,
    pgpFingerprint: actualFingerprint,
    pgpPublicKey: assertion.pgpPublicKey,
    kemAlgorithm: "ML-KEM-768",
    kemPublicKey: assertion.kemPublicKey,
    issuedAt: assertion.issuedAt,
    sessionNonce: assertion.sessionNonce,
  };
  const verification = await openpgp.verify({
    message: await openpgp.createMessage({ text: signedText(fields) }),
    signature: await openpgp.readSignature({ armoredSignature: assertion.signature }),
    verificationKeys: publicKey,
  });
  const signature = verification.signatures[0];
  if (verification.signatures.length !== 1 || !signature) {
    throw new Error("Identity assertion must contain exactly one signature");
  }
  await signature.verified;

  return { kind: "identity-assertion", ...fields, signature: assertion.signature };
}

export function normalizeFingerprint(value: string): string {
  return value.replace(/[^A-Fa-f0-9]/gu, "").toUpperCase();
}
