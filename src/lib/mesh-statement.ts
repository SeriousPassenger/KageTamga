import * as openpgp from "openpgp";
import type { PrivateKey } from "openpgp";
import { assertSupportedOpenPgpKey } from "./pgp-policy";
import { verifyPeerSignal, type SignedPeerSignal } from "./peer-signal";
import { verifyIdentityAssertion, type SignedIdentityAssertion } from "./protocol";

const SIGNATURE_DOMAIN = "kagetamga-mesh-statement:v1";
const MAX_CLOCK_SKEW_MS = 10 * 60 * 1000;
const MAX_SIGNATURE_CHARACTERS = 20_000;
const ROOM_ID_PATTERN = /^[A-Za-z0-9_-]{43}$/u;
const PEER_ID_PATTERN = /^[A-Za-z0-9_-]{24}$/u;
const FINGERPRINT_PATTERN = /^[A-F0-9]{40}$/u;
const NONCE_PATTERN = /^[A-Za-z0-9_-]{22,64}$/u;

export type MeshStatementPayload =
  | { type: "topology-request" }
  | { type: "introduction"; identity: SignedIdentityAssertion }
  | { type: "relay-signal"; signal: SignedPeerSignal };

export interface MeshStatementFields {
  version: 1;
  roomId: string;
  relayerPeerId: string;
  relayerFingerprint: string;
  targetPeerId: string;
  hops: number;
  issuedAt: string;
  nonce: string;
  payload: MeshStatementPayload;
}

export interface SignedMeshStatement extends MeshStatementFields {
  kind: "mesh-statement";
  signature: string;
}

export async function signMeshStatement(
  fields: MeshStatementFields,
  privateKey: PrivateKey,
): Promise<SignedMeshStatement> {
  assertPlainObject(fields, "Mesh statement fields");
  assertExactKeys(fields, [
    "issuedAt",
    "hops",
    "nonce",
    "payload",
    "relayerFingerprint",
    "relayerPeerId",
    "roomId",
    "targetPeerId",
    "version",
  ], "Mesh statement fields");
  const payload = await validatePayload(fields.payload, fields.roomId, fields.targetPeerId);
  validateFields(fields, Date.now());
  const publicKey = privateKey.toPublic();
  await assertSupportedOpenPgpKey(publicKey);
  if (publicKey.getFingerprint().toUpperCase() !== fields.relayerFingerprint) {
    throw new Error("Mesh statement private key does not match the relayer fingerprint.");
  }
  const normalized = { ...fields, payload };
  const signature = await openpgp.sign({
    message: await openpgp.createMessage({ text: signedText(normalized) }),
    signingKeys: privateKey,
    detached: true,
    format: "armored",
  });
  validateSignature(signature);
  return { kind: "mesh-statement", ...normalized, signature };
}

export async function verifyMeshStatement(
  value: unknown,
  relayerPublicKeyArmored: string,
  expectedRoomId: string,
  expectedRelayerPeerId: string,
  expectedRelayerFingerprint: string,
  now = Date.now(),
): Promise<SignedMeshStatement> {
  assertPlainObject(value, "Mesh statement");
  assertExactKeys(value, [
    "issuedAt",
    "hops",
    "kind",
    "nonce",
    "payload",
    "relayerFingerprint",
    "relayerPeerId",
    "roomId",
    "signature",
    "targetPeerId",
    "version",
  ], "Mesh statement");
  if (value.kind !== "mesh-statement") throw new Error("Unsupported mesh statement kind.");
  const statement = value as unknown as SignedMeshStatement;
  validateFields(statement, now);
  validateSignature(statement.signature);
  if (
    statement.roomId !== expectedRoomId ||
    statement.relayerPeerId !== expectedRelayerPeerId ||
    statement.relayerFingerprint !== expectedRelayerFingerprint
  ) {
    throw new Error("Mesh statement relayer context does not match the trusted connection.");
  }
  const payload = await validatePayload(statement.payload, statement.roomId, statement.targetPeerId, now);
  const publicKey = await openpgp.readKey({ armoredKey: relayerPublicKeyArmored });
  await assertSupportedOpenPgpKey(publicKey);
  if (publicKey.getFingerprint().toUpperCase() !== expectedRelayerFingerprint) {
    throw new Error("Mesh statement relayer public key does not match its trusted fingerprint.");
  }
  const normalized = { ...statement, payload };
  const verification = await openpgp.verify({
    message: await openpgp.createMessage({ text: signedText({
      version: statement.version,
      roomId: statement.roomId,
      relayerPeerId: statement.relayerPeerId,
      relayerFingerprint: statement.relayerFingerprint,
      targetPeerId: statement.targetPeerId,
      hops: statement.hops,
      issuedAt: statement.issuedAt,
      nonce: statement.nonce,
      payload,
    }) }),
    signature: await openpgp.readSignature({ armoredSignature: statement.signature }),
    verificationKeys: publicKey,
  });
  if (verification.signatures.length !== 1 || !verification.signatures[0]) {
    throw new Error("Mesh statement must contain exactly one relayer signature.");
  }
  await verification.signatures[0].verified;
  return normalized;
}

function signedText(fields: MeshStatementFields): string {
  return canonicalJson({ domain: SIGNATURE_DOMAIN, ...fields });
}

async function validatePayload(
  value: unknown,
  roomId: string,
  targetPeerId: string,
  now = Date.now(),
): Promise<MeshStatementPayload> {
  assertPlainObject(value, "Mesh statement payload");
  if (value.type === "topology-request") {
    assertExactKeys(value, ["type"], "Topology request");
    return { type: "topology-request" };
  }
  if (value.type === "introduction") {
    assertExactKeys(value, ["identity", "type"], "Peer introduction");
    const claimedPeerId = isPlainObject(value.identity) && typeof value.identity.peerId === "string"
      ? value.identity.peerId
      : "";
    if (!PEER_ID_PATTERN.test(claimedPeerId)) throw new Error("Introduced peer ID is malformed.");
    const identity = await verifyIdentityAssertion(value.identity, claimedPeerId, roomId, now);
    if (identity.peerId === targetPeerId) {
      throw new Error("An introduction cannot introduce its receiving peer to itself.");
    }
    return { type: "introduction", identity };
  }
  if (value.type === "relay-signal") {
    assertExactKeys(value, ["signal", "type"], "Relayed signal payload");
    const signal = await verifyPeerSignal(value.signal, roomId, targetPeerId, now);
    return { type: "relay-signal", signal };
  }
  throw new Error("Unsupported signed mesh statement payload.");
}

function validateFields(fields: MeshStatementFields, now: number): void {
  if (
    fields.version !== 1 ||
    typeof fields.roomId !== "string" ||
    !ROOM_ID_PATTERN.test(fields.roomId) ||
    typeof fields.relayerPeerId !== "string" ||
    !PEER_ID_PATTERN.test(fields.relayerPeerId) ||
    typeof fields.relayerFingerprint !== "string" ||
    !FINGERPRINT_PATTERN.test(fields.relayerFingerprint) ||
    typeof fields.targetPeerId !== "string" ||
    !PEER_ID_PATTERN.test(fields.targetPeerId) ||
    typeof fields.hops !== "number" ||
    !Number.isInteger(fields.hops) ||
    fields.hops < 0 ||
    fields.hops > 3 ||
    typeof fields.nonce !== "string" ||
    !NONCE_PATTERN.test(fields.nonce) ||
    !Number.isFinite(now)
  ) {
    throw new Error("Mesh statement context is malformed.");
  }
  if (
    typeof fields.issuedAt !== "string" ||
    fields.issuedAt.length !== 24 ||
    !Number.isFinite(Date.parse(fields.issuedAt)) ||
    new Date(Date.parse(fields.issuedAt)).toISOString() !== fields.issuedAt ||
    Math.abs(Date.parse(fields.issuedAt) - now) > MAX_CLOCK_SKEW_MS
  ) {
    throw new Error("Mesh statement timestamp is stale or malformed.");
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
    throw new Error("Mesh statement signature is malformed.");
  }
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value === "string" || typeof value === "boolean") {
    return JSON.stringify(value);
  }
  if (typeof value === "number" && Number.isFinite(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (isPlainObject(value)) {
    return `{${Object.keys(value).sort().map((key) =>
      `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  }
  throw new Error("A signed mesh statement contains a non-canonical value.");
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function assertPlainObject(value: unknown, label: string): asserts value is Record<string, unknown> {
  if (!isPlainObject(value)) throw new Error(`${label} must be a plain object.`);
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
