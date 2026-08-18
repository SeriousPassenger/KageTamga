import { useEffect, useState, type ChangeEvent, type FormEvent } from "react";
import QRCode from "qrcode";
import type { StoredIdentity } from "../lib/db";
import { purgeIdentity, saveIdentityWithContacts } from "../lib/db";
import {
  downloadText,
  exportIdentityBackup,
  generateIdentity,
  groupedFingerprint,
  importIdentity,
  importIdentityBackup,
  safeBackupBaseName,
  unlockIdentity,
  type IdentityBundle,
  type UnlockedIdentity,
} from "../lib/identity";
import type { Translator } from "../lib/i18n";

interface IdentityGateProps {
  t: Translator;
  identity?: StoredIdentity;
  onUnlocked(identity: StoredIdentity, unlocked: UnlockedIdentity): void;
  onIdentityRemoved(): void;
}

type CreateMode = "create" | "import";

export function IdentityGate({
  t,
  identity,
  onUnlocked,
  onIdentityRemoved,
}: IdentityGateProps) {
  const [mode, setMode] = useState<CreateMode>("create");
  const [displayName, setDisplayName] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [importText, setImportText] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const [pendingBundle, setPendingBundle] = useState<IdentityBundle>();
  const [backupPassphrase, setBackupPassphrase] = useState("");
  const [backupVerified, setBackupVerified] = useState(false);
  const [qrCode, setQrCode] = useState<string>();

  useEffect(() => {
    if (!pendingBundle) return;
    void QRCode.toDataURL(`openpgp4fpr:${pendingBundle.stored.fingerprint}`, {
      errorCorrectionLevel: "M",
      margin: 1,
      width: 220,
      color: { dark: "#10231d", light: "#f5f0e6" },
    }).then(setQrCode);
  }, [pendingBundle]);

  async function submitCreate(event: FormEvent) {
    event.preventDefault();
    setError(undefined);
    const name = displayName.trim();
    if (!name || name.length > 64 || /[\p{Cc}\p{Cf}\p{Cs}\p{Zl}\p{Zp}]/u.test(name)) {
      setError(t("operationFailed"));
      return;
    }
    if (passphrase.length < 12) {
      setError(t("passphraseHint"));
      return;
    }
    if (passphrase !== confirmation) {
      setError(t("passphraseMismatch"));
      return;
    }
    setBusy(true);
    try {
      const bundle = await generateIdentity(name, passphrase);
      setPendingBundle(bundle);
      setBackupPassphrase("");
      setBackupVerified(false);
    } catch {
      setError(t("operationFailed"));
    } finally {
      setBusy(false);
    }
  }

  async function submitImport(event: FormEvent) {
    event.preventDefault();
    setError(undefined);
    const input = importText.trim();
    const completeBackup = input.startsWith("{");
    if ((!completeBackup && !displayName.trim()) || passphrase.length < 12 || !input) {
      setError(t("importFailed"));
      return;
    }
    setBusy(true);
    try {
      const bundle = await importIdentity(displayName.trim(), input, passphrase);
      setPendingBundle(bundle);
      setBackupPassphrase("");
      setBackupVerified(false);
    } catch {
      setError(t("importFailed"));
    } finally {
      setBusy(false);
    }
  }

  async function submitUnlock(event: FormEvent) {
    event.preventDefault();
    if (!identity) return;
    setBusy(true);
    setError(undefined);
    try {
      onUnlocked(identity, await unlockIdentity(identity, passphrase));
      setPassphrase("");
    } catch {
      setError(t("wrongPassphrase"));
    } finally {
      setBusy(false);
    }
  }

  async function loadImportFile(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    if (!file) return;
    if (file.size > 4 * 1024 * 1024) {
      setError(t("importFailed"));
      return;
    }
    setImportText(await file.text());
  }

  async function verifyBackupFile(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    if (!file || !pendingBundle || backupPassphrase.length < 12) return;
    setBusy(true);
    setError(undefined);
    try {
      const imported = await importIdentityBackup(await file.text(), backupPassphrase);
      const matches =
        imported.stored.fingerprint === pendingBundle.stored.fingerprint &&
        imported.stored.hybridPublicKey === pendingBundle.stored.hybridPublicKey &&
        JSON.stringify(imported.contacts) === JSON.stringify(pendingBundle.contacts);
      imported.unlocked.hybridSecretKey.fill(0);
      if (!matches) throw new Error(t("backupFailed"));
      setBackupVerified(true);
    } catch {
      setBackupVerified(false);
      setError(t("backupFailed"));
    } finally {
      setBusy(false);
      event.target.value = "";
    }
  }

  async function removeIdentity() {
    if (!confirm(t("purgeIdentityConfirm"))) return;
    await purgeIdentity();
    onIdentityRemoved();
  }

  async function completePendingIdentity() {
    if (!pendingBundle || !backupVerified) return;
    setBusy(true);
    setError(undefined);
    try {
      await saveIdentityWithContacts(pendingBundle.stored, pendingBundle.contacts);
      onUnlocked(pendingBundle.stored, pendingBundle.unlocked);
    } catch {
      setError(t("operationFailed"));
    } finally {
      setBusy(false);
    }
  }

  async function downloadPendingBackup(filename: string) {
    if (!pendingBundle) return;
    setBusy(true);
    setError(undefined);
    try {
      downloadText(
        `${filename}.kagetamga.json`,
        await exportIdentityBackup(
          pendingBundle.stored,
          pendingBundle.unlocked,
          pendingBundle.contacts,
        ),
      );
    } catch {
      setError(t("backupFailed"));
    } finally {
      setBusy(false);
    }
  }

  if (pendingBundle) {
    const stored = pendingBundle.stored;
    const filename = safeBackupBaseName(stored.displayName);
    return (
      <main className="gate-shell">
        <section className="panel wide-panel">
          <div className="eyebrow">{t("identityReady")}</div>
          <h1>{t("backupTitle")}</h1>
          <p className="lede">{t("backupExplain")}</p>
          <div className="alert warning">{t("backupRequired")}</div>
          <div className="backup-grid">
            <div className="fingerprint-card">
              {qrCode && <img src={qrCode} alt="OpenPGP fingerprint QR code" width="220" height="220" />}
              <span>{t("fullFingerprint")}</span>
              <code>{groupedFingerprint(stored.fingerprint)}</code>
            </div>
            <div className="stack">
              <button
                className="button primary"
                type="button"
                onClick={() => void downloadPendingBackup(filename)}
              >
                {t("downloadIdentityBackup")} (.json)
              </button>
              <button
                className="button secondary"
                type="button"
                onClick={() => downloadText(`${filename}.private.asc`, stored.privateKeyArmored)}
              >
                {t("downloadPrivateKey")}
              </button>
              <button
                className="button secondary"
                type="button"
                onClick={() => downloadText(`${filename}.public.asc`, stored.publicKeyArmored)}
              >
                {t("downloadPublicKey")}
              </button>
              {stored.revocationCertificate && (
                <button
                  className="button secondary"
                  type="button"
                  onClick={() =>
                    downloadText(`${filename}.revocation.asc`, stored.revocationCertificate ?? "")
                  }
                >
                  {t("downloadRevocation")}
                </button>
              )}
            </div>
          </div>
          <div className="alert danger">{t("privateKeyWarning")}</div>
          <div className="verify-backup">
            <h2>{t("verifyBackup")}</h2>
            <p>{t("verifyBackupExplain")}</p>
            <label>
              <span>{t("passphrase")}</span>
              <input
                type="password"
                autoComplete="off"
                value={backupPassphrase}
                onChange={(event) => setBackupPassphrase(event.target.value)}
              />
            </label>
            <label className={`file-button ${backupPassphrase.length < 12 ? "disabled" : ""}`}>
              {t("selectBackup")}
              <input
                type="file"
                accept=".json,application/json"
                disabled={backupPassphrase.length < 12 || busy}
                onChange={(event) => void verifyBackupFile(event)}
              />
            </label>
            {backupVerified && <div className="alert success">{t("backupVerified")}</div>}
          </div>
          {error && <div className="alert danger">{error}</div>}
          <div className="button-row end">
            <button
              className="button primary"
              type="button"
              disabled={!backupVerified || busy}
              onClick={() => void completePendingIdentity()}
            >
              {t("continue")}
            </button>
          </div>
        </section>
      </main>
    );
  }

  if (identity) {
    return (
      <main className="gate-shell">
        <section className="panel identity-panel">
          <div className="eyebrow">{t("identityTitle")}</div>
          <h1>{identity.displayName}</h1>
          <div className="fingerprint-inline">
            <span>{t("fullFingerprint")}</span>
            <code>{groupedFingerprint(identity.fingerprint)}</code>
          </div>
          <form onSubmit={(event) => void submitUnlock(event)} className="stack">
            <label>
              <span>{t("passphrase")}</span>
              <input
                autoFocus
                type="password"
                autoComplete="current-password"
                value={passphrase}
                onChange={(event) => setPassphrase(event.target.value)}
              />
            </label>
            {error && <div className="alert danger">{error}</div>}
            <button className="button primary" type="submit" disabled={busy || !passphrase}>
              {busy ? t("unlocking") : t("unlock")}
            </button>
          </form>
          <button className="text-button danger-text" type="button" onClick={() => void removeIdentity()}>
            {t("purgeIdentity")}
          </button>
        </section>
      </main>
    );
  }

  return (
    <main className="gate-shell">
      <section className="panel wide-panel">
        <div className="eyebrow">{t("welcomeTitle")}</div>
        <h1>{t("identityTitle")}</h1>
        <p className="lede">{t("identityIntro")}</p>
        <div className="segmented" role="tablist">
          <button
            className={mode === "create" ? "active" : ""}
            type="button"
            onClick={() => setMode("create")}
          >
            {t("createIdentity")}
          </button>
          <button
            className={mode === "import" ? "active" : ""}
            type="button"
            onClick={() => setMode("import")}
          >
            {t("importIdentity")}
          </button>
        </div>

        <form
          className="identity-form stack"
          onSubmit={(event) => void (mode === "create" ? submitCreate(event) : submitImport(event))}
        >
          <label>
            <span>{t("displayName")}</span>
            <input
              type="text"
              autoComplete="nickname"
              maxLength={64}
              placeholder={t("displayNamePlaceholder")}
              value={displayName}
              onChange={(event) => setDisplayName(event.target.value)}
            />
          </label>
          {mode === "import" && (
            <>
              <label className="file-button">
                {t("privateKeyFile")} / KageTamga backup
                <input type="file" accept=".asc,.pgp,.json,text/plain,application/json" onChange={(event) => void loadImportFile(event)} />
              </label>
              <label>
                <span>{t("pastePrivateKey")}</span>
                <textarea
                  rows={8}
                  spellCheck={false}
                  value={importText}
                  onChange={(event) => setImportText(event.target.value)}
                />
              </label>
            </>
          )}
          <label>
            <span>{t("passphrase")}</span>
            <input
              type="password"
              autoComplete="new-password"
              value={passphrase}
              onChange={(event) => setPassphrase(event.target.value)}
            />
            <small>{t("passphraseHint")}</small>
          </label>
          {mode === "create" && (
            <label>
              <span>{t("confirmPassphrase")}</span>
              <input
                type="password"
                autoComplete="new-password"
                value={confirmation}
                onChange={(event) => setConfirmation(event.target.value)}
              />
            </label>
          )}
          {error && <div className="alert danger">{error}</div>}
          <button className="button primary" type="submit" disabled={busy}>
            {busy
              ? mode === "create"
                ? t("generatingKey")
                : t("importingKey")
              : mode === "create"
                ? t("generateKey")
                : t("importIdentity")}
          </button>
        </form>

        <div className="security-notes">
          <p>✓ {t("privateKeyNeverLeaves")}</p>
          <p>✓ {t("noRecoveryWarning")}</p>
          <p>✓ {t("pqHybridLabel")}</p>
        </div>
      </section>
    </main>
  );
}
