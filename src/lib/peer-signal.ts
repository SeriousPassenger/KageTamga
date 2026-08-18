import * as openpgp from "openpgp";
import type { PrivateKey } from "openpgp";
import { assertSupportedOpenPgpKey } from "./pgp-policy";
import { verifyIdentityAssertion, type SignedIdentityAssertion } from "./protocol";

const SIGNATURE_DOMAIN = "kagetamga-peer-signal:v1";
const MAX_CLOCK_SKEW_MS = 10 * 60 * 1000;
const MAX_SDP_CHARACTERS = 64 * 1024;
const MAX_SIGNATURE_CHARACTERS = 20_000;
const PEER_ID_PATTERN = /^[A-Za-z0-9_-]{24}$/u;
const ROOM_ID_PATTERN = /^[A-Za-z0-9_-]{43}$/u;
const NONCE_PATTERN = /^[A-Za-z0-9_-]{22,64}$/u;

export interface PeerSignalDescription {
  type: "offer" | "answer";
  sdp: string;
}

export interface PeerSignalFields {
  version: 1;
  roomId: string;
  fromPeerId: string;
  toPeerId: string;
  exchangeId: string;
  issuedAt: string;
  nonce: string;
  description: PeerSignalDescription;
  identity: SignedIdentityAssertion;
}

export interface SignedPeerSignal extends PeerSignalFields {
  kind: "peer-signal";
  signature: string;
}

export async function signPeerSignal(
  fields: PeerSignalFields,
  privateKey: PrivateKey,
): Promise<SignedPeerSignal> {
  assertPlainObject(fields, "Peer signal fields");
  assertExactKeys(fields, [
    "description",
    "exchangeId",
    "fromPeerId",
    "identity",
    "issuedAt",
    "nonce",
    "roomId",
    "toPeerId",
    "version",
  ], "Peer signal fields");
  validateFields(fields, Date.now());
  const identity = await verifyIdentityAssertion(fields.identity, fields.fromPeerId, fields.roomId);
  const publicKey = privateKey.toPublic();
  await assertSupportedOpenPgpKey(publicKey);
  if (publicKey.getFingerprint().toUpperCase() !== identity.pgpFingerprint) {
    throw new Error("Peer signal private key does not match the signed identity assertion.");
  }
  const signature = await openpgp.sign({
    message: await openpgp.createMessage({ text: signedText(fields) }),
    signingKeys: privateKey,
    detached: true,
    format: "armored",
  });
  validateSignature(signature);
  return { kind: "peer-signal", ...fields, identity, signature };
}

export async function verifyPeerSignal(
  value: unknown,
  expectedRoomId: string,
  expectedToPeerId: string,
  now = Date.now(),
): Promise<SignedPeerSignal> {
  assertPlainObject(value, "Peer signal");
  assertExactKeys(value, [
    "description",
    "exchangeId",
    "fromPeerId",
    "identity",
    "issuedAt",
    "kind",
    "nonce",
    "roomId",
    "signature",
    "toPeerId",
    "version",
  ], "Peer signal");
  if (value.kind !== "peer-signal") throw new Error("Unsupported peer signal kind.");
  const signal = value as unknown as SignedPeerSignal;
  validateFields(signal, now);
  validateSignature(signal.signature);
  if (signal.roomId !== expectedRoomId || signal.toPeerId !== expectedToPeerId) {
    throw new Error("Peer signal room or target does not match this browser.");
  }
  const identity = await verifyIdentityAssertion(
    signal.identity,
    signal.fromPeerId,
    signal.roomId,
    now,
  );
  const publicKey = await openpgp.readKey({ armoredKey: identity.pgpPublicKey });
  await assertSupportedOpenPgpKey(publicKey);
  const verification = await openpgp.verify({
    message: await openpgp.createMessage({ text: signedText({ ...signal, identity }) }),
    signature: await openpgp.readSignature({ armoredSignature: signal.signature }),
    verificationKeys: publicKey,
  });
  if (verification.signatures.length !== 1 || !verification.signatures[0]) {
    throw new Error("Peer signal must contain exactly one signature.");
  }
  await verification.signatures[0].verified;
  return { ...signal, identity };
}

function signedText(fields: PeerSignalFields): string {
  return JSON.stringify({
    domain: SIGNATURE_DOMAIN,
    version: fields.version,
    roomId: fields.roomId,
    fromPeerId: fields.fromPeerId,
    toPeerId: fields.toPeerId,
    exchangeId: fields.exchangeId,
    issuedAt: fields.issuedAt,
    nonce: fields.nonce,
    description: {
      type: fields.description.type,
      sdp: fields.description.sdp,
    },
    identity: {
      kind: fields.identity.kind,
      version: fields.identity.version,
      peerId: fields.identity.peerId,
      roomId: fields.identity.roomId,
      displayName: fields.identity.displayName,
      pgpFingerprint: fields.identity.pgpFingerprint,
      pgpPublicKey: fields.identity.pgpPublicKey,
      kemAlgorithm: fields.identity.kemAlgorithm,
      kemPublicKey: fields.identity.kemPublicKey,
      issuedAt: fields.identity.issuedAt,
      sessionNonce: fields.identity.sessionNonce,
      signature: fields.identity.signature,
    },
  });
}

function validateFields(fields: PeerSignalFields, now: number): void {
  if (
    fields.version !== 1 ||
    typeof fields.roomId !== "string" ||
    !ROOM_ID_PATTERN.test(fields.roomId) ||
    typeof fields.fromPeerId !== "string" ||
    !PEER_ID_PATTERN.test(fields.fromPeerId) ||
    typeof fields.toPeerId !== "string" ||
    !PEER_ID_PATTERN.test(fields.toPeerId) ||
    fields.fromPeerId === fields.toPeerId ||
    typeof fields.exchangeId !== "string" ||
    !NONCE_PATTERN.test(fields.exchangeId) ||
    typeof fields.nonce !== "string" ||
    !NONCE_PATTERN.test(fields.nonce) ||
    !Number.isFinite(now)
  ) {
    throw new Error("Peer signal context is malformed.");
  }
  if (
    typeof fields.issuedAt !== "string" ||
    fields.issuedAt.length !== 24 ||
    !Number.isFinite(Date.parse(fields.issuedAt)) ||
    new Date(Date.parse(fields.issuedAt)).toISOString() !== fields.issuedAt ||
    Math.abs(Date.parse(fields.issuedAt) - now) > MAX_CLOCK_SKEW_MS
  ) {
    throw new Error("Peer signal timestamp is stale or malformed.");
  }
  assertPlainObject(fields.description, "Peer signal description");
  assertExactKeys(fields.description, ["sdp", "type"], "Peer signal description");
  if (
    !["offer", "answer"].includes(fields.description.type) ||
    typeof fields.description.sdp !== "string" ||
    fields.description.sdp.length < 1 ||
    fields.description.sdp.length > MAX_SDP_CHARACTERS
  ) {
    throw new Error("Peer signal WebRTC description is malformed.");
  }
}

function validateSignature(value: string): void {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > MAX_SIGNATURE_CHARACTERS ||
    !value.trim().startsWith("-----BEGIN PGP SIGNATURE-----") ||
    !value.trim().endsWith("-----END PGP SIGNATURE-----")
  ) {
    throw new Error("Peer signal signature is malformed.");
  }
}

function assertPlainObject(value: unknown, label: string): asserts value is Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be a plain object.`);
  }
}

function assertExactKeys(
  value: Record<string, unknown>,
  expected: readonly string[],
  label: string,
): void {
  const actual = Object.keys(value).sort();
  const sortedExpected = [...expected].sort();
  if (actual.length !== sortedExpected.length || actual.some((key, index) => key !== sortedExpected[index])) {
    throw new Error(`${label} contains missing or unexpected fields.`);
  }
}
