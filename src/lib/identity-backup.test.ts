import * as openpgp from "openpgp";
import { describe, expect, it } from "vitest";
import {
  exportIdentityBackup,
  generateIdentity,
  importIdentityBackup,
} from "./identity";
import { createTrustedContact } from "./trust";

describe("encrypted identity backups", () => {
  it("encrypts the identity and owner-signed persistent trust list as one authenticated payload", async () => {
    const passphrase = "correct horse battery staple for the backup";
    const identity = await generateIdentity("Backup Owner", passphrase);
    const peer = await openpgp.generateKey({
      type: "curve25519",
      userIDs: [{ name: "Trusted Peer" }],
      format: "armored",
    });
    const peerKey = await openpgp.readKey({ armoredKey: peer.publicKey });
    const contact = await createTrustedContact(
      "Trusted Peer",
      peerKey.getFingerprint().toUpperCase(),
      peer.publicKey,
      identity.stored.fingerprint,
      identity.unlocked.pgpPrivateKey,
    );

    try {
      const serialized = await exportIdentityBackup(identity.stored, identity.unlocked, [contact]);
      expect(serialized).toContain('"format": "kagetamga-encrypted-backup"');
      expect(serialized).not.toContain("Backup Owner");
      expect(serialized).not.toContain("Trusted Peer");
      expect(serialized).not.toContain(contact.fingerprint);

      const restored = await importIdentityBackup(serialized, passphrase);
      try {
        expect(restored.stored.fingerprint).toBe(identity.stored.fingerprint);
        expect(restored.contacts).toEqual([contact]);
      } finally {
        restored.unlocked.hybridSecretKey.fill(0);
      }

      await expect(importIdentityBackup(serialized, "wrong passphrase")).rejects.toThrow();

      const tampered = JSON.parse(serialized) as {
        encryption: { ciphertext: string };
      };
      tampered.encryption.ciphertext = `${tampered.encryption.ciphertext.startsWith("A") ? "B" : "A"}${tampered.encryption.ciphertext.slice(1)}`;
      await expect(importIdentityBackup(JSON.stringify(tampered), passphrase)).rejects.toThrow();
    } finally {
      identity.unlocked.hybridSecretKey.fill(0);
    }
  }, 30_000);
});
