import { useEffect, useState, type FormEvent } from "react";
import {
  deleteContact,
  listContacts,
  saveContact,
  type StoredContact,
  type StoredIdentity,
} from "../lib/db";
import { groupedFingerprint, type UnlockedIdentity } from "../lib/identity";
import { iceServersFromSettings, type IceSettings } from "../lib/ice-config";
import type { Translator } from "../lib/i18n";
import { normalizeFingerprint } from "../lib/protocol";
import { createRoomSecret, normalizeRoomSecret, roomSecretFromHash } from "../lib/room";
import { createTrustedContact, normalizeContactName } from "../lib/trust";

interface RoomLobbyProps {
  t: Translator;
  identity: StoredIdentity;
  unlocked: UnlockedIdentity;
  iceSettings: IceSettings;
  onIceSettingsChange(settings: IceSettings): void;
  onJoin(secret: string, iceServers: RTCIceServer[]): void;
  onDownloadBackup(): Promise<void>;
  onLock(): void;
  onPurgeEverything(): Promise<void>;
}

export function RoomLobby({
  t,
  identity,
  unlocked,
  iceSettings,
  onIceSettingsChange,
  onJoin,
  onDownloadBackup,
  onLock,
  onPurgeEverything,
}: RoomLobbyProps) {
  const [invite, setInvite] = useState(() => roomSecretFromHash(location.hash) ?? "");
  const [error, setError] = useState<string>();
  const [contacts, setContacts] = useState<StoredContact[]>([]);
  const [contactName, setContactName] = useState("");
  const [contactFingerprint, setContactFingerprint] = useState("");
  const [contactPublicKey, setContactPublicKey] = useState("");
  const [contactCompared, setContactCompared] = useState(false);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    void listContacts().then(setContacts).catch(() => setError(t("operationFailed")));
  }, [t]);

  function joinWithIce(secret: string) {
    try {
      onJoin(secret, iceServersFromSettings(iceSettings));
    } catch {
      setError(t("invalidIceConfiguration"));
    }
  }

  function join(event: FormEvent) {
    event.preventDefault();
    const secret = normalizeRoomSecret(invite);
    if (!secret) {
      setError(t("invalidInvite"));
      return;
    }
    joinWithIce(secret);
  }

  async function addTrustedFingerprint(event: FormEvent) {
    event.preventDefault();
    const fingerprint = normalizeFingerprint(contactFingerprint);
    if (!contactCompared || fingerprint.length !== 40 || !contactName.trim() || !contactPublicKey.trim()) {
      setError(t("invalidTrustedContact"));
      return;
    }
    setBusy(true);
    setError(undefined);
    try {
      const contact = await createTrustedContact(
        normalizeContactName(contactName),
        fingerprint,
        contactPublicKey.trim(),
        identity.fingerprint,
        unlocked.pgpPrivateKey,
      );
      await saveContact(contact);
      setContacts(await listContacts());
      setContactName("");
      setContactFingerprint("");
      setContactPublicKey("");
      setContactCompared(false);
    } catch {
      setError(t("invalidTrustedContact"));
    } finally {
      setBusy(false);
    }
  }

  async function removeTrustedFingerprint(contact: StoredContact) {
    if (!confirm(t("removeTrustedContactConfirm", { fingerprint: contact.fingerprint }))) return;
    await deleteContact(contact.name);
    setContacts(await listContacts());
  }

  async function purgeAll() {
    if (!confirm(t("purgeEverythingConfirm"))) return;
    await onPurgeEverything();
  }

  return (
    <main className="lobby-shell">
      <section className="lobby-hero">
        <div className="eyebrow">{t("tagline")}</div>
        <h1>{t("roomsTitle")}</h1>
        <p className="lede">{t("smallGroupNote")}</p>
      </section>

      {error && <div className="alert danger lobby-error" role="alert">{error}</div>}

      <section className="panel trusted-contacts-panel">
        <div className="section-heading-row">
          <div>
            <div className="eyebrow">{t("persistentTrustTitle")}</div>
            <h2>{t("trustedFingerprintList")}</h2>
          </div>
          <button className="button secondary" type="button" onClick={() => void onDownloadBackup()}>
            {t("downloadIdentityBackup")}
          </button>
        </div>
        <p>{t("trustedFingerprintExplain")}</p>
        {contacts.length === 0 ? (
          <div className="alert warning">{t("trustedFingerprintEmpty")}</div>
        ) : (
          <ul className="trusted-contact-list">
            {contacts.map((contact) => (
              <li key={contact.name}>
                <div>
                  <strong>{contact.name}</strong>
                  <code>{groupedFingerprint(contact.fingerprint)}</code>
                </div>
                <button
                  className="text-button danger-text"
                  type="button"
                  onClick={() => void removeTrustedFingerprint(contact)}
                >
                  {t("removeTrustedContact")}
                </button>
              </li>
            ))}
          </ul>
        )}
        <details className="add-trusted-contact">
          <summary>{t("addTrustedContact")}</summary>
          <p>{t("addTrustedContactExplain")}</p>
          <form className="stack" onSubmit={(event) => void addTrustedFingerprint(event)}>
            <label>
              <span>{t("displayName")}</span>
              <input
                type="text"
                maxLength={64}
                autoComplete="off"
                value={contactName}
                onChange={(event) => setContactName(event.target.value)}
              />
            </label>
            <label>
              <span>{t("fullFingerprint")}</span>
              <input
                type="text"
                autoComplete="off"
                spellCheck={false}
                value={contactFingerprint}
                onChange={(event) => setContactFingerprint(event.target.value)}
              />
            </label>
            <label>
              <span>{t("publicKey")}</span>
              <textarea
                rows={6}
                spellCheck={false}
                value={contactPublicKey}
                onChange={(event) => setContactPublicKey(event.target.value)}
              />
            </label>
            <label className="checkbox-label light-checkbox">
              <input
                type="checkbox"
                checked={contactCompared}
                onChange={(event) => setContactCompared(event.target.checked)}
              />
              <span>{t("comparisonSteps")}</span>
            </label>
            <button className="button primary" type="submit" disabled={busy || !contactCompared}>
              {t("addTrustedContact")}
            </button>
          </form>
        </details>
      </section>

      <details className="panel ice-settings-panel">
        <summary>{t("iceSettingsTitle")}</summary>
        <p>{t("iceSettingsExplain")}</p>
        <div className="alert warning">{t("icePrivacyWarning")}</div>
        <div className="stack">
          <label>
            <span>{t("iceUrls")}</span>
            <textarea
              rows={4}
              spellCheck={false}
              value={iceSettings.urlsText}
              onChange={(event) => onIceSettingsChange({ ...iceSettings, urlsText: event.target.value })}
            />
            <small>{t("iceUrlsHint")}</small>
          </label>
          <label>
            <span>{t("turnUsername")}</span>
            <input
              type="text"
              autoComplete="off"
              value={iceSettings.username}
              onChange={(event) => onIceSettingsChange({ ...iceSettings, username: event.target.value })}
            />
          </label>
          <label>
            <span>{t("turnCredential")}</span>
            <input
              type="password"
              autoComplete="off"
              value={iceSettings.credential}
              onChange={(event) => onIceSettingsChange({ ...iceSettings, credential: event.target.value })}
            />
            <small>{t("iceMemoryOnly")}</small>
          </label>
        </div>
      </details>

      <section className="room-actions">
        <article className="panel action-card">
          <span className="card-number">01</span>
          <h2>{t("createRoom")}</h2>
          <p>{t("inviteWarning")}</p>
          <p className="muted">{t("roomCapability256")}</p>
          <button className="button primary" type="button" onClick={() => joinWithIce(createRoomSecret())}>
            {t("createRoom")}
          </button>
        </article>
        <article className="panel action-card">
          <span className="card-number">02</span>
          <h2>{t("joinRoom")}</h2>
          <form className="stack" onSubmit={join}>
            <label>
              <span>{t("roomSecret")}</span>
              <input
                type="text"
                autoComplete="off"
                spellCheck={false}
                value={invite}
                onChange={(event) => setInvite(event.target.value)}
              />
              <small>{t("fragmentSafety")}</small>
            </label>
            <button className="button primary" type="submit">
              {t("join")}
            </button>
          </form>
        </article>
      </section>

      <section className="privacy-strip">
        <div><strong>01</strong><span>{t("privacyP2p")}</span></div>
        <div><strong>02</strong><span>{t("privateKeyNeverLeaves")}</span></div>
        <div><strong>03</strong><span>{t("noOfflineWarning")}</span></div>
        <div><strong>04</strong><span>{t("peerIpWarning")}</span></div>
      </section>

      <details className="panel identity-summary">
        <summary>{identity.displayName} · {t("keyDetails")}</summary>
        <div className="fingerprint-inline">
          <span>{t("fullFingerprint")}</span>
          <code>{groupedFingerprint(identity.fingerprint)}</code>
        </div>
        <div className="button-row">
          <button className="button ghost" type="button" onClick={onLock}>{t("lockIdentity")}</button>
          <button className="button ghost danger-text" type="button" onClick={() => void purgeAll()}>
            {t("purgeEverything")}
          </button>
        </div>
      </details>
    </main>
  );
}
