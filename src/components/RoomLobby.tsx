import { useState, type FormEvent } from "react";
import type { StoredIdentity } from "../lib/db";
import { groupedFingerprint } from "../lib/identity";
import type { Translator } from "../lib/i18n";
import { createRoomSecret, normalizeRoomSecret } from "../lib/room";

interface RoomLobbyProps {
  t: Translator;
  identity: StoredIdentity;
  onJoin(secret: string): void;
  onLock(): void;
  onPurgeEverything(): Promise<void>;
}

export function RoomLobby({ t, identity, onJoin, onLock, onPurgeEverything }: RoomLobbyProps) {
  const [invite, setInvite] = useState("");
  const [error, setError] = useState<string>();

  function join(event: FormEvent) {
    event.preventDefault();
    const secret = normalizeRoomSecret(invite);
    if (!secret) {
      setError(t("invalidInvite"));
      return;
    }
    onJoin(secret);
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

      <section className="room-actions">
        <article className="panel action-card">
          <span className="card-number">01</span>
          <h2>{t("createRoom")}</h2>
          <p>{t("inviteWarning")}</p>
          <p className="muted">{t("roomCapability256")}</p>
          <button className="button primary" type="button" onClick={() => onJoin(createRoomSecret())}>
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
            {error && <div className="alert danger">{error}</div>}
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
