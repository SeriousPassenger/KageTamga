import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { toBase64Url, utf8 } from "./encoding";

/**
 * Application profile for nested, hybrid confidentiality.
 *
 * The signed OpenPGP Curve25519 message remains the inner ciphertext. ML-KEM-768
 * protects an independent AES-256 key which encrypts that ciphertext again. This
 * is deliberately not a custom KEM combiner: either complete encryption layer
 * must be defeated before the chat plaintext is exposed.
 */
export const HYBRID_ALGORITHM =
  "OpenPGP-Curve25519+ML-KEM-768/AES-256-GCM-v1" as const;

export const HYBRID_KEY_PROTECTION = "PBKDF2-SHA-512/AES-256-GCM-v1" as const;

const VERSION = 1 as const;
const CONTENT_KEY_BYTES = 32;
const GCM_IV_BYTES = 12;
const GCM_TAG_BYTES = 16;
const HKDF_SALT_BYTES = 32;
const PBKDF2_SALT_BYTES = 32;
const PBKDF2_ITERATIONS = 600_000;
const MIN_PASSPHRASE_CHARACTERS = 12;
const MAX_PASSPHRASE_BYTES = 1_024;
const MAX_RECIPIENTS = 32;
const MAX_ARMORED_MESSAGE_BYTES = 1024 * 1024;
const MIN_MESSAGE_ID_CHARACTERS = 16;
const MAX_MESSAGE_ID_CHARACTERS = 128;
const MESSAGE_ID_PATTERN = /^[A-Za-z0-9_-]+$/u;
const FINGERPRINT_PATTERN = /^(?:[A-F0-9]{40}|[A-F0-9]{64})$/u;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/u;
const decoder = new TextDecoder("utf-8", { fatal: true });

type ByteInput = Uint8Array<ArrayBufferLike>;
type OwnedBytes = Uint8Array<ArrayBuffer>;

const PUBLIC_KEY_BYTES = requiredLength(ml_kem768.lengths.publicKey, "public key");
const SECRET_KEY_BYTES = requiredLength(ml_kem768.lengths.secretKey, "secret key");
const KEM_CIPHERTEXT_BYTES = requiredLength(
  ml_kem768.lengths.cipherText,
  "KEM ciphertext",
);

export interface HybridKeyPair {
  version: typeof VERSION;
  algorithm: typeof HYBRID_ALGORITHM;
  /** Base64url ML-KEM-768 public key, safe to share. */
  publicKey: string;
  /** Mutable secret bytes. Protect promptly and wipe with `.fill(0)`. */
  secretKey: OwnedBytes;
}

export interface HybridRecipientPublicKey {
  /** OpenPGP fingerprint to which this ML-KEM public key is authenticated. */
  fingerprint: string;
  /** Base64url ML-KEM-768 public key. */
  publicKey: string;
}

export interface HybridRecipientEntry {
  fingerprint: string;
  kemCiphertext: string;
  kdfSalt: string;
  wrapIv: string;
  wrappedContentKey: string;
}

export interface HybridEnvelope {
  version: typeof VERSION;
  algorithm: typeof HYBRID_ALGORITHM;
  messageId: string;
  content: {
    iv: string;
    ciphertext: string;
  };
  recipients: HybridRecipientEntry[];
}

export interface HybridEnvelopeInspection {
  canonical: string;
  messageId: string;
  recipientFingerprints: string[];
  contentCiphertextBytes: number;
  kemCiphertextBytes: number[];
}

export interface ProtectedHybridSecretKey {
  version: typeof VERSION;
  algorithm: typeof HYBRID_ALGORITHM;
  protection: typeof HYBRID_KEY_PROTECTION;
  kdf: {
    name: "PBKDF2-SHA-512";
    iterations: typeof PBKDF2_ITERATIONS;
    salt: string;
  };
  cipher: {
    name: "AES-256-GCM";
    iv: string;
    ciphertext: string;
  };
}

interface ParsedRecipientEntry {
  fingerprint: string;
  kemCiphertext: OwnedBytes;
  kdfSalt: OwnedBytes;
  wrapIv: OwnedBytes;
  wrappedContentKey: OwnedBytes;
}

interface ParsedEnvelope {
  messageId: string;
  contentIv: OwnedBytes;
  contentCiphertext: OwnedBytes;
  recipients: ParsedRecipientEntry[];
}

/** Generate a local FIPS-203 ML-KEM-768 keypair. */
export function generateHybridKeyPair(): HybridKeyPair {
  assertWebCrypto();
  const generated = ml_kem768.keygen();
  return {
    version: VERSION,
    algorithm: HYBRID_ALGORITHM,
    publicKey: toBase64Url(generated.publicKey),
    secretKey: generated.secretKey,
  };
}

/** Hard-fail unless a public key is canonical, exact-length FIPS-203 ML-KEM-768. */
export function assertHybridPublicKey(publicKey: string): void {
  const bytes = decodeBase64Url(publicKey, "ML-KEM-768 public key", PUBLIC_KEY_BYTES);
  bytes.fill(0);
}

/** Derive the shareable ML-KEM public key from an unlocked secret key. */
export function deriveHybridPublicKey(secretKey: ByteInput | string): string {
  const secretBytes = copySecretKey(secretKey);
  try {
    return toBase64Url(ml_kem768.getPublicKey(secretBytes));
  } finally {
    secretBytes.fill(0);
  }
}

/**
 * Encrypt an ML-KEM secret key for storage. The returned object contains no
 * plaintext secret-key bytes or verifier which could confirm guesses offline
 * more cheaply than attempting authenticated decryption.
 */
export async function protectHybridSecretKey(
  secretKey: ByteInput | string,
  passphrase: string,
): Promise<ProtectedHybridSecretKey> {
  assertWebCrypto();
  const secretBytes = copySecretKey(secretKey);
  const passphraseBytes = validatePassphrase(passphrase);
  const salt = randomBytes(PBKDF2_SALT_BYTES);
  const iv = randomBytes(GCM_IV_BYTES);

  try {
    const key = await derivePassphraseKey(passphraseBytes, salt);
    const ciphertext = await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv,
        additionalData: secretProtectionAad(),
        tagLength: 128,
      },
      key,
      secretBytes,
    );

    return {
      version: VERSION,
      algorithm: HYBRID_ALGORITHM,
      protection: HYBRID_KEY_PROTECTION,
      kdf: {
        name: "PBKDF2-SHA-512",
        iterations: PBKDF2_ITERATIONS,
        salt: toBase64Url(salt),
      },
      cipher: {
        name: "AES-256-GCM",
        iv: toBase64Url(iv),
        ciphertext: toBase64Url(new Uint8Array(ciphertext)),
      },
    };
  } finally {
    secretBytes.fill(0);
    passphraseBytes.fill(0);
  }
}

/** Unlock a protected ML-KEM secret key. Wipe the returned bytes after use. */
export async function unprotectHybridSecretKey(
  protectedKey: ProtectedHybridSecretKey,
  passphrase: string,
): Promise<OwnedBytes> {
  assertWebCrypto();
  const parsed = parseProtectedSecretKey(protectedKey);
  const passphraseBytes = validatePassphrase(passphrase);

  try {
    const key = await derivePassphraseKey(passphraseBytes, parsed.salt);
    let plaintext: ArrayBuffer;
    try {
      plaintext = await crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: parsed.iv,
          additionalData: secretProtectionAad(),
          tagLength: 128,
        },
        key,
        parsed.ciphertext,
      );
    } catch {
      throw new Error("Unable to unlock the hybrid secret key.");
    }

    const secretKey = new Uint8Array(plaintext);
    if (secretKey.byteLength !== SECRET_KEY_BYTES) {
      secretKey.fill(0);
      throw new Error("The protected hybrid secret key has an invalid length.");
    }
    return secretKey;
  } finally {
    passphraseBytes.fill(0);
  }
}

/**
 * Outer-encrypt an already signed/encrypted OpenPGP message for every recipient.
 * The same random AES content key is independently KEM-wrapped for each verified
 * recipient fingerprint.
 */
export async function wrapCiphertext(
  messageId: string,
  armoredCiphertext: string,
  recipients: readonly HybridRecipientPublicKey[],
): Promise<HybridEnvelope> {
  assertWebCrypto();
  validateMessageId(messageId);
  const plaintext = validateArmoredCiphertext(armoredCiphertext);
  const validatedRecipients = validateRecipientPublicKeys(recipients);
  const contentKey = randomBytes(CONTENT_KEY_BYTES);
  const contentIv = randomBytes(GCM_IV_BYTES);

  try {
    const contentCiphertext = await encryptWithRawAesKey(
      contentKey,
      contentIv,
      plaintext,
      contextBytes("content-aad", messageId),
    );

    const entries: HybridRecipientEntry[] = [];
    for (const recipient of validatedRecipients) {
      let sharedSecret: OwnedBytes | undefined;
      try {
        const encapsulated = ml_kem768.encapsulate(recipient.publicKey);
        sharedSecret = encapsulated.sharedSecret;
        const kdfSalt = randomBytes(HKDF_SALT_BYTES);
        const wrapIv = randomBytes(GCM_IV_BYTES);
        const wrapKey = await deriveWrapKey(
          sharedSecret,
          kdfSalt,
          contextBytes("recipient-wrap-key", messageId, recipient.fingerprint),
        );
        const wrappedContentKey = await crypto.subtle.encrypt(
          {
            name: "AES-GCM",
            iv: wrapIv,
            additionalData: contextBytes(
              "recipient-wrap-aad",
              messageId,
              recipient.fingerprint,
            ),
            tagLength: 128,
          },
          wrapKey,
          contentKey,
        );

        entries.push({
          fingerprint: recipient.fingerprint,
          kemCiphertext: toBase64Url(encapsulated.cipherText),
          kdfSalt: toBase64Url(kdfSalt),
          wrapIv: toBase64Url(wrapIv),
          wrappedContentKey: toBase64Url(new Uint8Array(wrappedContentKey)),
        });
      } finally {
        sharedSecret?.fill(0);
      }
    }

    return {
      version: VERSION,
      algorithm: HYBRID_ALGORITHM,
      messageId,
      content: {
        iv: toBase64Url(contentIv),
        ciphertext: toBase64Url(contentCiphertext),
      },
      recipients: entries,
    };
  } finally {
    contentKey.fill(0);
    plaintext.fill(0);
  }
}

/**
 * Strictly validate an envelope without decrypting it and return a canonical
 * serialization suitable for hashing/signing an outer delivery manifest.
 */
export function inspectHybridEnvelope(envelope: HybridEnvelope): HybridEnvelopeInspection {
  const parsed = parseEnvelope(envelope);
  try {
    return {
      canonical: JSON.stringify({
        version: envelope.version,
        algorithm: envelope.algorithm,
        messageId: envelope.messageId,
        content: {
          iv: envelope.content.iv,
          ciphertext: envelope.content.ciphertext,
        },
        recipients: envelope.recipients.map((entry) => ({
          fingerprint: entry.fingerprint,
          kemCiphertext: entry.kemCiphertext,
          kdfSalt: entry.kdfSalt,
          wrapIv: entry.wrapIv,
          wrappedContentKey: entry.wrappedContentKey,
        })),
      }),
      messageId: parsed.messageId,
      recipientFingerprints: parsed.recipients.map((entry) => entry.fingerprint),
      contentCiphertextBytes: parsed.contentCiphertext.byteLength,
      kemCiphertextBytes: parsed.recipients.map((entry) => entry.kemCiphertext.byteLength),
    };
  } finally {
    parsed.contentIv.fill(0);
    parsed.contentCiphertext.fill(0);
    for (const recipient of parsed.recipients) {
      recipient.kemCiphertext.fill(0);
      recipient.kdfSalt.fill(0);
      recipient.wrapIv.fill(0);
      recipient.wrappedContentKey.fill(0);
    }
  }
}

/** Recover the inner armored OpenPGP ciphertext for one recipient. */
export async function unwrapCiphertext(
  envelope: HybridEnvelope,
  selfFingerprint: string,
  secretKey: ByteInput | string,
): Promise<string> {
  assertWebCrypto();
  const parsed = parseEnvelope(envelope);
  const fingerprint = normalizeFingerprint(selfFingerprint);
  const recipient = parsed.recipients.find((entry) => entry.fingerprint === fingerprint);
  if (!recipient) {
    throw new Error("This fingerprint is not a recipient of the hybrid envelope.");
  }

  const secretBytes = copySecretKey(secretKey);
  let sharedSecret: OwnedBytes | undefined;
  let contentKey: OwnedBytes | undefined;

  try {
    let unwrappedKey: ArrayBuffer;
    try {
      sharedSecret = ml_kem768.decapsulate(recipient.kemCiphertext, secretBytes);
      const wrapKey = await deriveWrapKey(
        sharedSecret,
        recipient.kdfSalt,
        contextBytes("recipient-wrap-key", parsed.messageId, fingerprint),
      );
      unwrappedKey = await crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: recipient.wrapIv,
          additionalData: contextBytes(
            "recipient-wrap-aad",
            parsed.messageId,
            fingerprint,
          ),
          tagLength: 128,
        },
        wrapKey,
        recipient.wrappedContentKey,
      );
    } catch {
      throw new Error("Unable to decrypt the hybrid envelope.");
    }

    contentKey = new Uint8Array(unwrappedKey);
    if (contentKey.byteLength !== CONTENT_KEY_BYTES) {
      throw new Error("Unable to decrypt the hybrid envelope.");
    }

    let plaintext: ArrayBuffer;
    try {
      plaintext = await decryptWithRawAesKey(
        contentKey,
        parsed.contentIv,
        parsed.contentCiphertext,
        contextBytes("content-aad", parsed.messageId),
      );
    } catch {
      throw new Error("Unable to decrypt the hybrid envelope.");
    }

    const plaintextBytes = new Uint8Array(plaintext);
    let armored: string;
    try {
      armored = decoder.decode(plaintextBytes);
    } catch {
      throw new Error("The decrypted hybrid payload is not valid UTF-8.");
    } finally {
      plaintextBytes.fill(0);
    }
    validateArmoredCiphertext(armored).fill(0);
    return armored;
  } finally {
    secretBytes.fill(0);
    sharedSecret?.fill(0);
    contentKey?.fill(0);
  }
}

function requiredLength(value: number | undefined, label: string): number {
  if (!Number.isSafeInteger(value) || value === undefined || value <= 0) {
    throw new Error(`ML-KEM-768 did not expose a valid ${label} length.`);
  }
  return value;
}

function assertWebCrypto(): void {
  if (
    typeof crypto !== "object" ||
    typeof crypto.getRandomValues !== "function" ||
    typeof crypto.subtle !== "object"
  ) {
    throw new Error("Web Crypto is unavailable; use this application in a secure context.");
  }
}

function ownedBytes(value: ByteInput): OwnedBytes {
  return Uint8Array.from(value);
}

function randomBytes(length: number): OwnedBytes {
  return crypto.getRandomValues(new Uint8Array(length));
}

function normalizeFingerprint(value: string): string {
  if (typeof value !== "string") throw new TypeError("Fingerprint must be a string.");
  const normalized = value.replaceAll(" ", "").toUpperCase();
  if (!FINGERPRINT_PATTERN.test(normalized)) {
    throw new Error("Fingerprint must contain 40 or 64 hexadecimal characters.");
  }
  return normalized;
}

function validateMessageId(value: string): void {
  if (
    typeof value !== "string" ||
    value.length < MIN_MESSAGE_ID_CHARACTERS ||
    value.length > MAX_MESSAGE_ID_CHARACTERS ||
    !MESSAGE_ID_PATTERN.test(value)
  ) {
    throw new Error(
      `Message ID must be ${MIN_MESSAGE_ID_CHARACTERS}-${MAX_MESSAGE_ID_CHARACTERS} base64url characters.`,
    );
  }
}

function validateArmoredCiphertext(value: string): OwnedBytes {
  if (typeof value !== "string") {
    throw new TypeError("OpenPGP ciphertext must be a string.");
  }
  const trimmed = value.trim();
  if (
    !trimmed.startsWith("-----BEGIN PGP MESSAGE-----") ||
    !trimmed.endsWith("-----END PGP MESSAGE-----") ||
    value.includes("\0")
  ) {
    throw new Error("Expected an armored OpenPGP message ciphertext.");
  }
  const bytes = ownedBytes(utf8(value));
  if (bytes.byteLength > MAX_ARMORED_MESSAGE_BYTES) {
    bytes.fill(0);
    throw new Error("The armored OpenPGP ciphertext exceeds the 1 MiB limit.");
  }
  return bytes;
}

function validateRecipientPublicKeys(
  recipients: readonly HybridRecipientPublicKey[],
): Array<{ fingerprint: string; publicKey: OwnedBytes }> {
  if (!Array.isArray(recipients) || recipients.length === 0) {
    throw new Error("At least one hybrid recipient is required.");
  }
  if (recipients.length > MAX_RECIPIENTS) {
    throw new Error(`A hybrid envelope supports at most ${MAX_RECIPIENTS} recipients.`);
  }

  const fingerprints = new Set<string>();
  const validated = recipients.map((recipient, index) => {
    assertPlainRecord(recipient, `Recipient ${index + 1}`);
    assertExactKeys(recipient, ["fingerprint", "publicKey"], `Recipient ${index + 1}`);
    if (typeof recipient.fingerprint !== "string" || typeof recipient.publicKey !== "string") {
      throw new TypeError(`Recipient ${index + 1} key fields must be strings.`);
    }
    const fingerprint = normalizeFingerprint(recipient.fingerprint);
    if (fingerprints.has(fingerprint)) {
      throw new Error(`Duplicate hybrid recipient fingerprint: ${fingerprint}`);
    }
    fingerprints.add(fingerprint);
    return {
      fingerprint,
      publicKey: decodeBase64Url(
        recipient.publicKey,
        `Recipient ${fingerprint} public key`,
        PUBLIC_KEY_BYTES,
      ),
    };
  });

  return validated.sort((left, right) => left.fingerprint.localeCompare(right.fingerprint));
}

function parseEnvelope(value: HybridEnvelope): ParsedEnvelope {
  assertPlainRecord(value, "Hybrid envelope");
  assertExactKeys(
    value,
    ["version", "algorithm", "messageId", "content", "recipients"],
    "Hybrid envelope",
  );
  if (value.version !== VERSION || value.algorithm !== HYBRID_ALGORITHM) {
    throw new Error("Unsupported hybrid envelope version or algorithm.");
  }
  validateMessageId(value.messageId);

  assertPlainRecord(value.content, "Hybrid envelope content");
  assertExactKeys(value.content, ["iv", "ciphertext"], "Hybrid envelope content");
  const contentIv = decodeBase64Url(
    value.content.iv,
    "Hybrid envelope content IV",
    GCM_IV_BYTES,
  );
  const contentCiphertext = decodeBase64UrlRange(
    value.content.ciphertext,
    "Hybrid envelope content ciphertext",
    GCM_TAG_BYTES + 1,
    MAX_ARMORED_MESSAGE_BYTES + GCM_TAG_BYTES,
  );

  if (!Array.isArray(value.recipients) || value.recipients.length === 0) {
    throw new Error("Hybrid envelope must contain at least one recipient.");
  }
  if (value.recipients.length > MAX_RECIPIENTS) {
    throw new Error(`Hybrid envelope has more than ${MAX_RECIPIENTS} recipients.`);
  }

  const fingerprints = new Set<string>();
  const recipients = value.recipients.map((entry, index): ParsedRecipientEntry => {
    assertPlainRecord(entry, `Hybrid recipient entry ${index + 1}`);
    assertExactKeys(
      entry,
      ["fingerprint", "kemCiphertext", "kdfSalt", "wrapIv", "wrappedContentKey"],
      `Hybrid recipient entry ${index + 1}`,
    );
    const fingerprint = normalizeFingerprint(entry.fingerprint);
    if (entry.fingerprint !== fingerprint) {
      throw new Error("Hybrid envelope fingerprints must use canonical uppercase hexadecimal.");
    }
    if (fingerprints.has(fingerprint)) {
      throw new Error(`Duplicate hybrid recipient fingerprint: ${fingerprint}`);
    }
    fingerprints.add(fingerprint);

    return {
      fingerprint,
      kemCiphertext: decodeBase64Url(
        entry.kemCiphertext,
        `Recipient ${fingerprint} KEM ciphertext`,
        KEM_CIPHERTEXT_BYTES,
      ),
      kdfSalt: decodeBase64Url(
        entry.kdfSalt,
        `Recipient ${fingerprint} KDF salt`,
        HKDF_SALT_BYTES,
      ),
      wrapIv: decodeBase64Url(
        entry.wrapIv,
        `Recipient ${fingerprint} wrap IV`,
        GCM_IV_BYTES,
      ),
      wrappedContentKey: decodeBase64Url(
        entry.wrappedContentKey,
        `Recipient ${fingerprint} wrapped key`,
        CONTENT_KEY_BYTES + GCM_TAG_BYTES,
      ),
    };
  });

  return {
    messageId: value.messageId,
    contentIv,
    contentCiphertext,
    recipients,
  };
}

function parseProtectedSecretKey(value: ProtectedHybridSecretKey): {
  salt: OwnedBytes;
  iv: OwnedBytes;
  ciphertext: OwnedBytes;
} {
  assertPlainRecord(value, "Protected hybrid secret key");
  assertExactKeys(
    value,
    ["version", "algorithm", "protection", "kdf", "cipher"],
    "Protected hybrid secret key",
  );
  if (
    value.version !== VERSION ||
    value.algorithm !== HYBRID_ALGORITHM ||
    value.protection !== HYBRID_KEY_PROTECTION
  ) {
    throw new Error("Unsupported hybrid secret-key protection format.");
  }

  assertPlainRecord(value.kdf, "Hybrid secret-key KDF");
  assertExactKeys(value.kdf, ["name", "iterations", "salt"], "Hybrid secret-key KDF");
  if (
    value.kdf.name !== "PBKDF2-SHA-512" ||
    value.kdf.iterations !== PBKDF2_ITERATIONS
  ) {
    throw new Error("Unsupported hybrid secret-key KDF parameters.");
  }

  assertPlainRecord(value.cipher, "Hybrid secret-key cipher");
  assertExactKeys(value.cipher, ["name", "iv", "ciphertext"], "Hybrid secret-key cipher");
  if (value.cipher.name !== "AES-256-GCM") {
    throw new Error("Unsupported hybrid secret-key cipher.");
  }

  return {
    salt: decodeBase64Url(value.kdf.salt, "Hybrid secret-key KDF salt", PBKDF2_SALT_BYTES),
    iv: decodeBase64Url(value.cipher.iv, "Hybrid secret-key IV", GCM_IV_BYTES),
    ciphertext: decodeBase64Url(
      value.cipher.ciphertext,
      "Protected hybrid secret key ciphertext",
      SECRET_KEY_BYTES + GCM_TAG_BYTES,
    ),
  };
}

function copySecretKey(value: ByteInput | string): OwnedBytes {
  if (typeof value === "string") {
    return decodeBase64Url(value, "Hybrid secret key", SECRET_KEY_BYTES);
  }
  if (!(value instanceof Uint8Array) || value.byteLength !== SECRET_KEY_BYTES) {
    throw new Error(`Hybrid secret key must be ${SECRET_KEY_BYTES} bytes.`);
  }
  return ownedBytes(value);
}

function validatePassphrase(value: string): OwnedBytes {
  if (typeof value !== "string") throw new TypeError("Passphrase must be a string.");
  if ([...value].length < MIN_PASSPHRASE_CHARACTERS) {
    throw new Error(
      `Hybrid-key passphrase must contain at least ${MIN_PASSPHRASE_CHARACTERS} characters.`,
    );
  }
  const bytes = ownedBytes(utf8(value));
  if (bytes.byteLength > MAX_PASSPHRASE_BYTES) {
    bytes.fill(0);
    throw new Error("Hybrid-key passphrase is too long.");
  }
  return bytes;
}

async function derivePassphraseKey(
  passphraseBytes: OwnedBytes,
  salt: OwnedBytes,
): Promise<CryptoKey> {
  const material = await crypto.subtle.importKey(
    "raw",
    passphraseBytes,
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      hash: "SHA-512",
      salt,
      iterations: PBKDF2_ITERATIONS,
    },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

async function deriveWrapKey(
  sharedSecret: OwnedBytes,
  salt: OwnedBytes,
  info: OwnedBytes,
): Promise<CryptoKey> {
  const material = await crypto.subtle.importKey("raw", sharedSecret, "HKDF", false, [
    "deriveKey",
  ]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-512", salt, info },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

async function encryptWithRawAesKey(
  keyBytes: OwnedBytes,
  iv: OwnedBytes,
  plaintext: OwnedBytes,
  additionalData: OwnedBytes,
): Promise<OwnedBytes> {
  const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["encrypt"]);
  return new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData, tagLength: 128 },
      key,
      plaintext,
    ),
  );
}

async function decryptWithRawAesKey(
  keyBytes: OwnedBytes,
  iv: OwnedBytes,
  ciphertext: OwnedBytes,
  additionalData: OwnedBytes,
): Promise<ArrayBuffer> {
  const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["decrypt"]);
  return crypto.subtle.decrypt(
    { name: "AES-GCM", iv, additionalData, tagLength: 128 },
    key,
    ciphertext,
  );
}

function secretProtectionAad(): OwnedBytes {
  return contextBytes("secret-key-protection", HYBRID_KEY_PROTECTION, String(PBKDF2_ITERATIONS));
}

/** Length-prefix every field to make domain separation unambiguous. */
function contextBytes(purpose: string, ...fields: string[]): OwnedBytes {
  const values = ["kagetamga-hybrid-crypto", "v1", HYBRID_ALGORITHM, purpose, ...fields];
  return ownedBytes(utf8(values.map((value) => `${utf8(value).byteLength}:${value}`).join("|")));
}

function decodeBase64Url(value: string, label: string, expectedBytes: number): OwnedBytes {
  const decoded = decodeBase64UrlRange(value, label, expectedBytes, expectedBytes);
  if (decoded.byteLength !== expectedBytes) {
    throw new Error(`${label} must decode to ${expectedBytes} bytes.`);
  }
  return decoded;
}

function decodeBase64UrlRange(
  value: string,
  label: string,
  minimumBytes: number,
  maximumBytes: number,
): OwnedBytes {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > Math.ceil((maximumBytes * 4) / 3) + 2 ||
    value.length % 4 === 1 ||
    !BASE64URL_PATTERN.test(value)
  ) {
    throw new Error(`${label} is not canonical unpadded base64url.`);
  }

  let decoded: OwnedBytes;
  try {
    const padded = value
      .replaceAll("-", "+")
      .replaceAll("_", "/")
      .padEnd(Math.ceil(value.length / 4) * 4, "=");
    const binary = atob(padded);
    decoded = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  } catch {
    throw new Error(`${label} is not valid base64url.`);
  }

  if (
    decoded.byteLength < minimumBytes ||
    decoded.byteLength > maximumBytes ||
    toBase64Url(decoded) !== value
  ) {
    decoded.fill(0);
    throw new Error(`${label} has an invalid encoding or length.`);
  }
  return decoded;
}

function assertPlainRecord(value: unknown, label: string): asserts value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new TypeError(`${label} must be an object.`);
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
