import { useEffect, useMemo, useState } from "react";
import { ChatRoom } from "./components/ChatRoom";
import { IdentityGate } from "./components/IdentityGate";
import { PreflightGate } from "./components/PreflightGate";
import { RoomLobby } from "./components/RoomLobby";
import { getIdentity, listContacts, purgeEverything, type StoredIdentity } from "./lib/db";
import {
  downloadText,
  exportIdentityBackup,
  safeBackupBaseName,
  type UnlockedIdentity,
} from "./lib/identity";
import { DEFAULT_ICE_SETTINGS, iceServersFromSettings, type IceSettings } from "./lib/ice-config";
import {
  createTranslator,
  detectLocale,
  LOCALE_LABELS,
  setSavedLocale,
  SUPPORTED_LOCALES,
  type Locale,
} from "./lib/i18n";
import { sha256DigestEncodings } from "./lib/integrity-digest";
import { verifyIntegrityWorker } from "./lib/preflight";

export default function App() {
  const [locale, setLocale] = useState<Locale>(() => detectLocale());
  const [preflightPassed, setPreflightPassed] = useState(false);
  const [loadingIdentity, setLoadingIdentity] = useState(true);
  const [identity, setIdentity] = useState<StoredIdentity>();
  const [unlocked, setUnlocked] = useState<UnlockedIdentity>();
  const [roomSecret, setRoomSecret] = useState<string>();
  const [iceSettings, setIceSettings] = useState<IceSettings>(DEFAULT_ICE_SETTINGS);
  const [activeIceServers, setActiveIceServers] = useState<RTCIceServer[]>(() =>
    iceServersFromSettings(DEFAULT_ICE_SETTINGS));
  const [developerMode, setDeveloperMode] = useState(false);
  const [buildDigest, setBuildDigest] = useState<string>();
  const [backupBusy, setBackupBusy] = useState(false);
  const [backupError, setBackupError] = useState(false);
  const t = useMemo(() => createTranslator(locale), [locale]);
  const buildDigestEncodings = useMemo(
    () => buildDigest ? sha256DigestEncodings(buildDigest) : undefined,
    [buildDigest],
  );

  useEffect(() => {
    document.documentElement.lang = locale;
    document.documentElement.dir = "ltr";
  }, [locale]);

  useEffect(() => {
    if (!preflightPassed) return;
    setLoadingIdentity(true);
    void getIdentity()
      .then(setIdentity)
      .finally(() => setLoadingIdentity(false));
  }, [preflightPassed]);

  useEffect(
    () => () => {
      unlocked?.hybridSecretKey.fill(0);
    },
    [unlocked],
  );

  useEffect(() => {
    if (!developerMode || !preflightPassed) return;
    void verifyIntegrityWorker().then(setBuildDigest).catch(() => setBuildDigest(undefined));
  }, [developerMode, preflightPassed]);

  function chooseLanguage(value: string) {
    if (value === "auto") {
      setSavedLocale(null);
      setLocale(detectLocale({ saved: null }));
      return;
    }
    const selected = value as Locale;
    setSavedLocale(selected);
    setLocale(selected);
  }

  function lockIdentity() {
    unlocked?.hybridSecretKey.fill(0);
    leaveRoom();
    setUnlocked(undefined);
  }

  function leaveRoom() {
    history.replaceState(null, "", `${location.pathname}${location.search}`);
    setRoomSecret(undefined);
  }

  async function purgeAll() {
    unlocked?.hybridSecretKey.fill(0);
    history.replaceState(null, "", `${location.pathname}${location.search}`);
    await purgeEverything();
    location.reload();
  }

  function enterRoom(secret: string, iceServers: RTCIceServer[]) {
    setActiveIceServers(iceServers);
    setRoomSecret(secret);
  }

  async function downloadBackup() {
    if (!identity || !unlocked || backupBusy) return;
    setBackupBusy(true);
    setBackupError(false);
    try {
      const contents = await exportIdentityBackup(identity, unlocked, await listContacts());
      downloadText(`${safeBackupBaseName(identity.displayName)}.kagetamga.json`, contents);
    } catch {
      setBackupError(true);
    } finally {
      setBackupBusy(false);
    }
  }

  return (
    <div className="app-frame">
      <header className="site-header">
        <button
          className="brand"
          type="button"
          onClick={() => {
            if (roomSecret) leaveRoom();
          }}
          aria-label={t("appName")}
        >
          <span className="brand-mark" aria-hidden="true">K</span>
          <span>
            <strong>{t("appName")}</strong>
            <small>browser-to-browser</small>
          </span>
        </button>
        <label className="language-select">
          <span>{t("language")}</span>
          <select value={locale} onChange={(event) => chooseLanguage(event.target.value)}>
            <option value="auto">{t("autoLanguage")}</option>
            {SUPPORTED_LOCALES.map((option) => (
              <option key={option} value={option}>{LOCALE_LABELS[option]}</option>
            ))}
          </select>
        </label>
        {identity && unlocked && (
          <button
            className="button secondary header-backup"
            type="button"
            disabled={backupBusy}
            onClick={() => void downloadBackup()}
          >
            {backupBusy ? t("loading") : t("downloadIdentityBackup")}
          </button>
        )}
        <label className="developer-toggle">
          <input
            type="checkbox"
            checked={developerMode}
            onChange={(event) => setDeveloperMode(event.target.checked)}
          />
          <span>{t("developerMode")}</span>
        </label>
      </header>

      {!preflightPassed ? (
        <PreflightGate t={t} onContinue={() => setPreflightPassed(true)} />
      ) : loadingIdentity ? (
        <main className="gate-shell"><div className="panel">{t("loading")}</div></main>
      ) : !identity || !unlocked ? (
        <IdentityGate
          t={t}
          identity={identity}
          onUnlocked={(nextIdentity, nextUnlocked) => {
            setIdentity(nextIdentity);
            setUnlocked(nextUnlocked);
          }}
          onIdentityRemoved={() => {
            setIdentity(undefined);
            setUnlocked(undefined);
          }}
        />
      ) : roomSecret ? (
        <ChatRoom
          t={t}
          locale={locale}
          identity={identity}
          unlocked={unlocked}
          roomSecret={roomSecret}
          iceServers={activeIceServers}
          developerMode={developerMode}
          onLeave={leaveRoom}
          onLockIdentity={lockIdentity}
        />
      ) : (
        <RoomLobby
          t={t}
          identity={identity}
          unlocked={unlocked}
          iceSettings={iceSettings}
          onIceSettingsChange={setIceSettings}
          onJoin={enterRoom}
          onDownloadBackup={downloadBackup}
          onLock={lockIdentity}
          onPurgeEverything={purgeAll}
        />
      )}

      {backupError && <div className="alert danger global-alert">{t("backupFailed")}</div>}

      {developerMode && (
        <details className="debug-panel app-debug">
          <summary>{t("debugApp")} · {t("debugRedacted")}</summary>
          <pre>{JSON.stringify({
            app: { name: "KageTamga", version: "0.1.0", protocolVersion: 1, locale },
            build: {
              digestAlgorithm: "SHA-256",
              digestBase64Url: buildDigestEncodings?.base64Url ?? null,
              digestHex: buildDigestEncodings?.hex ?? null,
            },
            runtime: {
              secureContext: window.isSecureContext,
              crossOriginIsolated: window.crossOriginIsolated,
              serviceWorkerControlled: Boolean(navigator.serviceWorker?.controller),
              webCrypto: Boolean(globalThis.crypto?.subtle),
              indexedDb: Boolean(globalThis.indexedDB),
              webRtc: Boolean(globalThis.RTCPeerConnection),
            },
            privacy: {
              applicationBackend: "none",
              serverMessageStorage: "none",
              participantDiscovery: "manual encrypted offer/answer; persistent-trust-gated peer introductions",
              runtimeThirdPartyScripts: "blocked by CSP and build verification",
              browserStorage: "origin-scoped IndexedDB; encrypted key and message records",
              redactedFields: ["passphrase", "private keys", "room secret", "message plaintext"],
              rawCiphertextDisclosure: "opt-in, per-message, collapsed; encrypted transport JSON only",
            },
            identity: identity ? { displayName: identity.displayName, pgpFingerprint: identity.fingerprint } : null,
            room: { active: Boolean(roomSecret), secret: "[REDACTED]" },
          }, null, 2)}</pre>
        </details>
      )}

      <footer className="site-footer">
        <span>{t("noAnalytics")}</span>
        <a href="https://github.com/SeriousPassenger/KageTamga" target="_blank" rel="noopener noreferrer">
          Source ↗
        </a>
        <span>MIT · 2026 SeriousPassenger</span>
      </footer>
    </div>
  );
}
