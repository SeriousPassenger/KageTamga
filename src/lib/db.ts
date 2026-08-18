import type { ProtectedHybridSecretKey } from "./hybrid-crypto";
import type { SignedDeliveryManifest } from "./room-events";

export interface StoredIdentity {
  id: "default";
  displayName: string;
  publicKeyArmored: string;
  privateKeyArmored: string;
  revocationCertificate?: string;
  fingerprint: string;
  createdAt: string;
  hybridPublicKey: string;
  protectedHybridSecretKey: ProtectedHybridSecretKey;
}

export interface StoredMessage {
  key: string;
  roomId: string;
  id: string;
  sentAt: string;
  senderFingerprint: string;
  senderPublicKey: string;
  ciphertext: string;
  delivery: SignedDeliveryManifest;
}

export interface StoredContact {
  name: string;
  fingerprint: string;
  publicKeyArmored: string;
  verifiedAt: string;
  ownerFingerprint: string;
  signature: string;
}

const DATABASE_NAME = "quietwire-private-data";
const DATABASE_VERSION = 1;

function requestResult<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("IndexedDB request failed"));
  });
}

function transactionDone(transaction: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(transaction.error ?? new Error("IndexedDB transaction failed"));
    transaction.onabort = () => reject(transaction.error ?? new Error("IndexedDB transaction aborted"));
  });
}

async function database(): Promise<IDBDatabase> {
  const request = indexedDB.open(DATABASE_NAME, DATABASE_VERSION);
  request.onupgradeneeded = () => {
    const db = request.result;
    if (!db.objectStoreNames.contains("identity")) {
      db.createObjectStore("identity", { keyPath: "id" });
    }
    if (!db.objectStoreNames.contains("messages")) {
      const messages = db.createObjectStore("messages", { keyPath: "key" });
      messages.createIndex("roomId", "roomId", { unique: false });
    }
    if (!db.objectStoreNames.contains("contacts")) {
      db.createObjectStore("contacts", { keyPath: "name" });
    }
  };
  return requestResult(request);
}

export async function getIdentity(): Promise<StoredIdentity | undefined> {
  const db = await database();
  try {
    return await requestResult(
      db.transaction("identity", "readonly").objectStore("identity").get("default"),
    );
  } finally {
    db.close();
  }
}

export async function saveIdentity(identity: StoredIdentity): Promise<void> {
  const db = await database();
  try {
    const transaction = db.transaction("identity", "readwrite");
    transaction.objectStore("identity").put(identity);
    await transactionDone(transaction);
  } finally {
    db.close();
  }
}

export async function saveMessage(message: StoredMessage): Promise<void> {
  const expectedKey = `${message.roomId}:${message.senderFingerprint}:${message.id}`;
  if (message.key !== expectedKey) throw new Error("The local message key is malformed.");
  const db = await database();
  try {
    const transaction = db.transaction("messages", "readwrite");
    const store = transaction.objectStore("messages");
    const existing = await requestResult(store.get(message.key)) as StoredMessage | undefined;
    if (existing) {
      if (
        existing.ciphertext !== message.ciphertext ||
        JSON.stringify(existing.delivery) !== JSON.stringify(message.delivery)
      ) {
        transaction.abort();
        throw new Error("A conflicting authenticated message replay was rejected.");
      }
    } else {
      store.add(message);
    }
    await transactionDone(transaction);
  } finally {
    db.close();
  }
}

export async function listMessages(roomId: string): Promise<StoredMessage[]> {
  const db = await database();
  try {
    const transaction = db.transaction("messages", "readonly");
    const index = transaction.objectStore("messages").index("roomId");
    const messages = await requestResult(index.getAll(IDBKeyRange.only(roomId)));
    return messages.sort((left, right) => left.sentAt.localeCompare(right.sentAt));
  } finally {
    db.close();
  }
}

export async function deleteMessage(key: string): Promise<void> {
  const db = await database();
  try {
    const transaction = db.transaction("messages", "readwrite");
    transaction.objectStore("messages").delete(key);
    await transactionDone(transaction);
  } finally {
    db.close();
  }
}

export async function purgeRoom(roomId: string): Promise<void> {
  const db = await database();
  try {
    const transaction = db.transaction("messages", "readwrite");
    const store = transaction.objectStore("messages");
    const keys = await requestResult(store.index("roomId").getAllKeys(IDBKeyRange.only(roomId)));
    for (const key of keys) store.delete(key);
    await transactionDone(transaction);
  } finally {
    db.close();
  }
}

export async function getContact(name: string): Promise<StoredContact | undefined> {
  const db = await database();
  try {
    return await requestResult(
      db.transaction("contacts", "readonly").objectStore("contacts").get(name),
    );
  } finally {
    db.close();
  }
}

export async function saveContact(contact: StoredContact): Promise<void> {
  const db = await database();
  try {
    const transaction = db.transaction("contacts", "readwrite");
    transaction.objectStore("contacts").put(contact);
    await transactionDone(transaction);
  } finally {
    db.close();
  }
}

export async function purgeIdentity(): Promise<void> {
  const db = await database();
  try {
    const transaction = db.transaction(["identity", "contacts"], "readwrite");
    transaction.objectStore("identity").delete("default");
    // Trust records are signed by the local identity. Keeping them after the
    // owner key is deleted would make them unverifiable and could permanently
    // block the same contact name under a replacement identity.
    transaction.objectStore("contacts").clear();
    await transactionDone(transaction);
  } finally {
    db.close();
  }
}

export async function purgeEverything(): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    const request = indexedDB.deleteDatabase(DATABASE_NAME);
    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error ?? new Error("Could not delete local data"));
    request.onblocked = () => reject(new Error("Close other tabs before deleting local data"));
  });
  localStorage.clear();
  sessionStorage.clear();
  if ("caches" in globalThis) {
    const names = await caches.keys();
    await Promise.all(names.map((name) => caches.delete(name)));
  }
  if ("serviceWorker" in navigator) {
    const registrations = await navigator.serviceWorker.getRegistrations();
    await Promise.all(registrations.map((registration) => registration.unregister()));
  }
}
