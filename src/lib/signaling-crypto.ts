import { decodeUtf8, fromBase64Url, toBase64Url, utf8 } from "./encoding";

export interface EncryptedSignal {
  iv: string;
  ciphertext: string;
}

export async function encryptSignal(
  key: CryptoKey,
  payload: unknown,
): Promise<EncryptedSignal> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    utf8(JSON.stringify(payload)),
  );
  return {
    iv: toBase64Url(iv),
    ciphertext: toBase64Url(new Uint8Array(ciphertext)),
  };
}

export async function decryptSignal<T>(
  key: CryptoKey,
  envelope: EncryptedSignal,
): Promise<T> {
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: fromBase64Url(envelope.iv) },
    key,
    fromBase64Url(envelope.ciphertext),
  );
  return JSON.parse(decodeUtf8(plaintext)) as T;
}
