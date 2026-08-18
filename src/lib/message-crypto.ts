import * as openpgp from "openpgp";
import type { PrivateKey } from "openpgp";

export interface ChatPayload {
  version: 1;
  id: string;
  roomId: string;
  senderName: string;
  senderFingerprint: string;
  sentAt: string;
  body: string;
}

export interface DecryptedChat {
  payload: ChatPayload;
  verified: boolean;
  signerFingerprint: string;
}

export async function encryptChat(
  payload: ChatPayload,
  signingKey: PrivateKey,
  recipientKeys: string[],
): Promise<string> {
  const keys = await Promise.all(
    recipientKeys.map((armoredKey) => openpgp.readKey({ armoredKey })),
  );
  return openpgp.encrypt({
    message: await openpgp.createMessage({ text: JSON.stringify(payload) }),
    encryptionKeys: keys,
    signingKeys: signingKey,
    format: "armored",
  });
}

export async function decryptChat(
  ciphertext: string,
  decryptionKey: PrivateKey,
  senderPublicKey: string,
): Promise<DecryptedChat> {
  const message = await openpgp.readMessage({ armoredMessage: ciphertext });
  const verificationKey = await openpgp.readKey({ armoredKey: senderPublicKey });
  const result = await openpgp.decrypt({
    message,
    decryptionKeys: decryptionKey,
    verificationKeys: verificationKey,
    expectSigned: true,
    format: "utf8",
    config: { maxDecompressedMessageSize: 64 * 1024 },
  });

  let verified = false;
  if (result.signatures.length === 1 && result.signatures[0]) {
    try {
      await result.signatures[0].verified;
      verified = true;
    } catch {
      verified = false;
    }
  }

  if (result.data.length > 16_384) throw new Error("Decrypted message metadata is too large");
  const payload = JSON.parse(result.data) as ChatPayload;
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw new Error("Unsupported message format");
  }
  const keys = Object.keys(payload).sort();
  const expectedKeys = [
    "body",
    "id",
    "roomId",
    "senderFingerprint",
    "senderName",
    "sentAt",
    "version",
  ];
  if (
    keys.length !== expectedKeys.length ||
    keys.some((key, index) => key !== expectedKeys[index]) ||
    payload.version !== 1 ||
    typeof payload.body !== "string"
  ) {
    throw new Error("Unsupported message format");
  }
  return {
    payload,
    verified,
    signerFingerprint: verificationKey.getFingerprint().toUpperCase(),
  };
}
