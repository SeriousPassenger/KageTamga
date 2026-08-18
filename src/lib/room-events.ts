import * as openpgp from "openpgp";
import type { PrivateKey } from "openpgp";
import { toBase64Url, utf8 } from "./encoding";
import {
  inspectHybridEnvelope,
  type HybridEnvelope,
} from "./hybrid-crypto";
import { assertSupportedOpenPgpKey } from "./pgp-policy";

const VERSION = 1 as const;
const SIGNATURE_DOMAIN = "kagetamga-room-event:v1";
const TRUST_MAX_CLOCK_SKEW_MS = 10 * 60 * 1000;
const MAX_SIGNATURE_CHARACTERS = 20_000;
const MAX_PUBLIC_KEY_CHARACTERS = 100_000;
const MAX_RECIPIENTS = 32;
const ROOM_ID_PATTERN = /^[A-Za-z0-9_-]{43}$/u;
const PEER_ID_PATTERN = /^[A-Za-z0-9_-]{16,64}$/u;
const MESSAGE_ID_PATTERN = /^[A-Za-z0-9_-]{16,128}$/u;
const NONCE_PATTERN = /^[A-Za-z0-9_-]{22,64}$/u;
const DIGEST_PATTERN = /^[A-Za-z0-9_-]{43}$/u;
const FINGERPRINT_PATTERN = /^[A-F0-9]{40}$/u;
const UNSAFE_NAME_CHARACTER_PATTERN = /[\p{Cc}\p{Cf}\p{Cs}\p{Zl}\p{Zp}]/u;

export interface TrustAnnouncementFields {
  version: typeof VERSION;
  roomId: string;
  initiatorPeerId: string;
  initiatorFingerprint: string;
  subjectFingerprint: string;
  issuedAt: string;
  nonce: string;
  state: "trusted";
}

/**
 * A direct statement by one initiator about one subject. Verification proves
 * only that directional statement; it never authenticates the subject's trust
 * in the initiator and must never be extended transitively to a third party.
 */
export interface SignedTrustAnnouncement extends TrustAnnouncementFields {
  kind: "trust-announcement";
  signature: string;
}

export interface DeliveryManifestFields {
  version: typeof VERSION;
  roomId: string;
  senderPeerId: string;
  senderName: string;
  senderFingerprint: string;
  sentAt: string;
}

export interface SignedDeliveryManifest extends DeliveryManifestFields {
  kind: "delivery-manifest";
  messageId: string;
  envelopeDigest: string;
  recipientFingerprints: string[];
  signature: string;
}

interface EnvelopeBinding {
  messageId: string;
  envelopeDigest: string;
  recipientFingerprints: string[];
}

/** Sign one fresh, room-bound and explicitly directional trust statement. */
export async function signTrustAnnouncement(
  fields: TrustAnnouncementFields,
  initiatorPrivateKey: PrivateKey,
): Promise<SignedTrustAnnouncement> {
  assertPlainRecord(fields, "Trust announcement fields");
  assertExactKeys(
    fields,
    [
      "version",
      "roomId",
      "initiatorPeerId",
      "initiatorFingerprint",
      "subjectFingerprint",
      "issuedAt",
      "nonce",
      "state",
    ],
    "Trust announcement fields",
  );
  validateTrustFields(fields, Date.now());
  await assertPrivateKeyFingerprint(
    initiatorPrivateKey,
    fields.initiatorFingerprint,
    "Trust announcement initiator",
  );

  const signature = await detachedSign(trustSignedText(fields), initiatorPrivateKey);
  return { kind: "trust-announcement", ...fields, signature };
}

/**
 * Verify only the named initiator's direct statement about the named subject.
 * The caller remains responsible for nonce replay tracking and MUST NOT infer
 * that the subject trusts the initiator or that either party trusts anyone else.
 */
export async function verifyTrustAnnouncement(
  value: unknown,
  initiatorPublicKeyArmored: string,
  expectedRoomId: string,
  expectedInitiatorPeerId: string,
  expectedInitiatorFingerprint: string,
  now = Date.now(),
): Promise<SignedTrustAnnouncement> {
  validateRoomId(expectedRoomId, "Expected room ID");
  validatePeerId(expectedInitiatorPeerId, "Expected initiator peer ID");
  validateCanonicalFingerprint(
    expectedInitiatorFingerprint,
    "Expected initiator fingerprint",
  );
  if (!Number.isFinite(now)) throw new Error("Trust verification time must be finite.");

  assertPlainRecord(value, "Trust announcement");
  assertExactKeys(
    value,
    [
      "kind",
      "version",
      "roomId",
      "initiatorPeerId",
      "initiatorFingerprint",
      "subjectFingerprint",
      "issuedAt",
      "nonce",
      "state",
      "signature",
    ],
    "Trust announcement",
  );
  if (value.kind !== "trust-announcement") {
    throw new Error("Unsupported trust announcement kind.");
  }

  const announcement = value as unknown as SignedTrustAnnouncement;
  validateTrustFields(announcement, now);
  validateSignature(announcement.signature);
  if (
    announcement.roomId !== expectedRoomId ||
    announcement.initiatorPeerId !== expectedInitiatorPeerId ||
    announcement.initiatorFingerprint !== expectedInitiatorFingerprint
  ) {
    throw new Error("Trust announcement context does not match the expected initiator.");
  }

  const publicKey = await readBoundPublicKey(
    initiatorPublicKeyArmored,
    expectedInitiatorFingerprint,
    "Trust announcement initiator",
  );
  await verifyDetachedSignature(
    trustSignedText(announcement),
    announcement.signature,
    publicKey,
  );
  return announcement;
}

/** Sign a manifest bound to the exact strict canonical hybrid envelope. */
export async function signDeliveryManifest(
  fields: DeliveryManifestFields,
  envelope: HybridEnvelope,
  senderPrivateKey: PrivateKey,
): Promise<SignedDeliveryManifest> {
  assertPlainRecord(fields, "Delivery manifest fields");
  assertExactKeys(
    fields,
    ["version", "roomId", "senderPeerId", "senderName", "senderFingerprint", "sentAt"],
    "Delivery manifest fields",
  );
  validateDeliveryFields(fields);
  await assertPrivateKeyFingerprint(
    senderPrivateKey,
    fields.senderFingerprint,
    "Delivery manifest sender",
  );
  const binding = await bindEnvelope(envelope);
  const unsigned: Omit<SignedDeliveryManifest, "kind" | "signature"> = {
    ...fields,
    messageId: binding.messageId,
    envelopeDigest: binding.envelopeDigest,
    recipientFingerprints: binding.recipientFingerprints,
  };
  const signature = await detachedSign(deliverySignedText(unsigned), senderPrivateKey);
  return { kind: "delivery-manifest", ...unsigned, signature };
}

/** Verify sender identity, manifest fields and exact envelope binding. */
export async function verifyDeliveryManifest(
  value: unknown,
  envelope: HybridEnvelope,
  senderPublicKeyArmored: string,
  expectedRoomId: string,
  expectedSenderPeerId: string,
  expectedSenderFingerprint: string,
): Promise<SignedDeliveryManifest> {
  validateRoomId(expectedRoomId, "Expected room ID");
  validatePeerId(expectedSenderPeerId, "Expected sender peer ID");
  validateCanonicalFingerprint(expectedSenderFingerprint, "Expected sender fingerprint");

  assertPlainRecord(value, "Delivery manifest");
  assertExactKeys(
    value,
    [
      "kind",
      "version",
      "roomId",
      "messageId",
      "senderPeerId",
      "senderName",
      "senderFingerprint",
      "sentAt",
      "envelopeDigest",
      "recipientFingerprints",
      "signature",
    ],
    "Delivery manifest",
  );
  if (value.kind !== "delivery-manifest") {
    throw new Error("Unsupported delivery manifest kind.");
  }

  const manifest = value as unknown as SignedDeliveryManifest;
  validateDeliveryManifestFields(manifest);
  validateSignature(manifest.signature);
  if (
    manifest.roomId !== expectedRoomId ||
    manifest.senderPeerId !== expectedSenderPeerId ||
    manifest.senderFingerprint !== expectedSenderFingerprint
  ) {
    throw new Error("Delivery manifest context does not match the expected sender.");
  }

  const binding = await bindEnvelope(envelope);
  if (
    manifest.messageId !== binding.messageId ||
    manifest.envelopeDigest !== binding.envelopeDigest ||
    !equalStrings(manifest.recipientFingerprints, binding.recipientFingerprints)
  ) {
    throw new Error("Delivery manifest does not match the hybrid envelope.");
  }

  const publicKey = await readBoundPublicKey(
    senderPublicKeyArmored,
    expectedSenderFingerprint,
    "Delivery manifest sender",
  );
  await verifyDetachedSignature(
    deliverySignedText(manifest),
    manifest.signature,
    publicKey,
  );
  return manifest;
}

function trustSignedText(fields: TrustAnnouncementFields): string {
  return JSON.stringify({
    domain: SIGNATURE_DOMAIN,
    kind: "trust-announcement",
    version: fields.version,
    roomId: fields.roomId,
    initiatorPeerId: fields.initiatorPeerId,
    initiatorFingerprint: fields.initiatorFingerprint,
    subjectFingerprint: fields.subjectFingerprint,
    issuedAt: fields.issuedAt,
    nonce: fields.nonce,
    state: fields.state,
  });
}

function deliverySignedText(
  fields: Omit<SignedDeliveryManifest, "kind" | "signature">,
): string {
  return JSON.stringify({
    domain: SIGNATURE_DOMAIN,
    kind: "delivery-manifest",
    version: fields.version,
    roomId: fields.roomId,
    messageId: fields.messageId,
    senderPeerId: fields.senderPeerId,
    senderName: fields.senderName,
    senderFingerprint: fields.senderFingerprint,
    sentAt: fields.sentAt,
    envelopeDigest: fields.envelopeDigest,
    recipientFingerprints: fields.recipientFingerprints,
  });
}

function validateTrustFields(fields: TrustAnnouncementFields, now: number): void {
  if (fields.version !== VERSION || fields.state !== "trusted") {
    throw new Error("Unsupported trust announcement version or state.");
  }
  validateRoomId(fields.roomId, "Trust announcement room ID");
  validatePeerId(fields.initiatorPeerId, "Trust announcement initiator peer ID");
  validateCanonicalFingerprint(
    fields.initiatorFingerprint,
    "Trust announcement initiator fingerprint",
  );
  validateCanonicalFingerprint(
    fields.subjectFingerprint,
    "Trust announcement subject fingerprint",
  );
  if (fields.initiatorFingerprint === fields.subjectFingerprint) {
    throw new Error("A trust announcement subject must differ from its initiator.");
  }
  const issuedAt = validateTimestamp(fields.issuedAt, "Trust announcement issue time");
  if (Math.abs(issuedAt - now) > TRUST_MAX_CLOCK_SKEW_MS) {
    throw new Error("Trust announcement is outside the allowed ten-minute window.");
  }
  if (typeof fields.nonce !== "string" || !NONCE_PATTERN.test(fields.nonce)) {
    throw new Error("Trust announcement nonce must be canonical base64url.");
  }
}

function validateDeliveryFields(fields: DeliveryManifestFields): void {
  if (fields.version !== VERSION) throw new Error("Unsupported delivery manifest version.");
  validateRoomId(fields.roomId, "Delivery manifest room ID");
  validatePeerId(fields.senderPeerId, "Delivery manifest sender peer ID");
  validateSenderName(fields.senderName);
  validateCanonicalFingerprint(fields.senderFingerprint, "Delivery manifest sender fingerprint");
  validateTimestamp(fields.sentAt, "Delivery manifest send time");
}

function validateDeliveryManifestFields(manifest: SignedDeliveryManifest): void {
  validateDeliveryFields(manifest);
  if (typeof manifest.messageId !== "string" || !MESSAGE_ID_PATTERN.test(manifest.messageId)) {
    throw new Error("Delivery manifest message ID is malformed.");
  }
  if (
    typeof manifest.envelopeDigest !== "string" ||
    !DIGEST_PATTERN.test(manifest.envelopeDigest)
  ) {
    throw new Error("Delivery manifest envelope digest is malformed.");
  }
  validateRecipientFingerprints(manifest.recipientFingerprints);
}

async function bindEnvelope(envelope: HybridEnvelope): Promise<EnvelopeBinding> {
  if (!globalThis.crypto?.subtle) {
    throw new Error("Web Crypto is unavailable; use this application in a secure context.");
  }
  const inspection = inspectHybridEnvelope(envelope);
  const recipientFingerprints = [...inspection.recipientFingerprints].sort();
  validateRecipientFingerprints(recipientFingerprints);
  const digest = await crypto.subtle.digest("SHA-256", utf8(inspection.canonical));
  return {
    messageId: inspection.messageId,
    envelopeDigest: toBase64Url(new Uint8Array(digest)),
    recipientFingerprints,
  };
}

async function assertPrivateKeyFingerprint(
  privateKey: PrivateKey,
  expectedFingerprint: string,
  label: string,
): Promise<void> {
  const publicKey = privateKey.toPublic();
  await assertSupportedOpenPgpKey(publicKey);
  if (publicKey.getFingerprint().toUpperCase() !== expectedFingerprint) {
    throw new Error(`${label} private key does not match its fingerprint.`);
  }
}

async function readBoundPublicKey(
  armoredKey: string,
  expectedFingerprint: string,
  label: string,
) {
  if (
    typeof armoredKey !== "string" ||
    armoredKey.length === 0 ||
    armoredKey.length > MAX_PUBLIC_KEY_CHARACTERS
  ) {
    throw new Error(`${label} public key is malformed.`);
  }
  const publicKey = await openpgp.readKey({ armoredKey });
  await assertSupportedOpenPgpKey(publicKey);
  if (publicKey.getFingerprint().toUpperCase() !== expectedFingerprint) {
    throw new Error(`${label} public key does not match the expected fingerprint.`);
  }
  return publicKey;
}

async function detachedSign(text: string, privateKey: PrivateKey): Promise<string> {
  const signature = await openpgp.sign({
    message: await openpgp.createMessage({ text }),
    signingKeys: privateKey,
    detached: true,
    format: "armored",
  });
  validateSignature(signature);
  return signature;
}

async function verifyDetachedSignature(
  text: string,
  armoredSignature: string,
  publicKey: Awaited<ReturnType<typeof openpgp.readKey>>,
): Promise<void> {
  const verification = await openpgp.verify({
    message: await openpgp.createMessage({ text }),
    signature: await openpgp.readSignature({ armoredSignature }),
    verificationKeys: publicKey,
  });
  if (verification.signatures.length !== 1 || !verification.signatures[0]) {
    throw new Error("Room event must contain exactly one signature.");
  }
  await verification.signatures[0].verified;
}

function validateSignature(value: string): void {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > MAX_SIGNATURE_CHARACTERS ||
    !value.trim().startsWith("-----BEGIN PGP SIGNATURE-----") ||
    !value.trim().endsWith("-----END PGP SIGNATURE-----")
  ) {
    throw new Error("Room event signature is malformed.");
  }
}

function validateRoomId(value: string, label: string): void {
  if (typeof value !== "string" || !ROOM_ID_PATTERN.test(value)) {
    throw new Error(`${label} must be a 32-byte base64url identifier.`);
  }
}

function validatePeerId(value: string, label: string): void {
  if (typeof value !== "string" || !PEER_ID_PATTERN.test(value)) {
    throw new Error(`${label} must be canonical base64url.`);
  }
}

function validateCanonicalFingerprint(value: string, label: string): void {
  if (typeof value !== "string" || !FINGERPRINT_PATTERN.test(value)) {
    throw new Error(`${label} must be 40 uppercase hexadecimal characters.`);
  }
}

function validateSenderName(value: string): void {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > 64 ||
    value !== value.normalize("NFKC").trim() ||
    UNSAFE_NAME_CHARACTER_PATTERN.test(value)
  ) {
    throw new Error("Delivery manifest sender name is malformed.");
  }
}

function validateTimestamp(value: string, label: string): number {
  if (typeof value !== "string" || value.length !== 24) {
    throw new Error(`${label} must be a canonical ISO timestamp.`);
  }
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== value) {
    throw new Error(`${label} must be a canonical ISO timestamp.`);
  }
  return milliseconds;
}

function validateRecipientFingerprints(value: string[]): void {
  if (!Array.isArray(value) || value.length === 0 || value.length > MAX_RECIPIENTS) {
    throw new Error("Delivery manifest recipient fingerprints are malformed.");
  }
  for (let index = 0; index < value.length; index += 1) {
    const fingerprint = value[index];
    if (typeof fingerprint !== "string") {
      throw new Error("Delivery manifest recipient fingerprint must be a string.");
    }
    validateCanonicalFingerprint(fingerprint, "Delivery manifest recipient fingerprint");
    if (index > 0 && value[index - 1]! >= fingerprint) {
      throw new Error("Delivery manifest recipient fingerprints must be sorted and unique.");
    }
  }
}

function equalStrings(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function assertPlainRecord(
  value: unknown,
  label: string,
): asserts value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new TypeError(`${label} must be a plain object.`);
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new TypeError(`${label} must be a plain object.`);
  }
}

function assertExactKeys(
  value: Record<string, unknown>,
  expectedKeys: readonly string[],
  label: string,
): void {
  const actual = Object.keys(value).sort();
  const expected = [...expectedKeys].sort();
  if (
    actual.length !== expected.length ||
    actual.some((key, index) => key !== expected[index])
  ) {
    throw new Error(`${label} contains unexpected or missing fields.`);
  }
}
