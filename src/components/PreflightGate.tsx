import { useEffect, useMemo, useState } from "react";
import type { TranslationKey, Translator } from "../lib/i18n";
import {
  PREFLIGHT_CHECKS,
  runPreflight,
  verifyIntegrityWorker,
  type PreflightCheckId,
  type PreflightResult,
} from "../lib/preflight";

interface PreflightGateProps {
  t: Translator;
  onContinue(): void;
}

const labelKeys: Record<PreflightCheckId, TranslationKey> = {
  "secure-context": "checkSecureTransport",
  "browser-crypto": "checkBrowserRandomness",
  openpgp: "checkOpenPgp",
  mlkem: "checkMlKem",
  "local-storage": "checkLocalDatabase",
  p2p: "checkP2pApis",
  "resource-isolation": "checkRuntimeResources",
  signaling: "checkSignalingService",
};

const consoleCommand =
  "await (async()=>{const r=await navigator.serviceWorker.ready,w=r.active||navigator.serviceWorker.controller,c=new MessageChannel(),p=new Promise((ok,fail)=>{c.port1.onmessage=e=>e.data.ok?ok(e.data.buildDigest):fail(Error(e.data.error))});w.postMessage({type:'VERIFY_PINNED_SHELL'},[c.port2]);const d=await p;console.log('QuietWire build digest:',d);return d})()";

function initialResults(): Record<PreflightCheckId, PreflightResult> {
  return Object.fromEntries(
    PREFLIGHT_CHECKS.map((id) => [id, { id, status: "waiting" }]),
  ) as Record<PreflightCheckId, PreflightResult>;
}

export function PreflightGate({ t, onContinue }: PreflightGateProps) {
  const [attempt, setAttempt] = useState(0);
  const [results, setResults] = useState(initialResults);
  const [complete, setComplete] = useState(false);
  const [digest, setDigest] = useState<string>();
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    let current = true;
    setResults(initialResults());
    setComplete(false);
    setDigest(undefined);
    void runPreflight((result) => {
      if (current) setResults((previous) => ({ ...previous, [result.id]: result }));
    }).then(async (passed) => {
      if (!current) return;
      if (passed) {
        try {
          const verifiedDigest = await verifyIntegrityWorker();
          if (!current) return;
          setDigest(verifiedDigest);
          setComplete(true);
        } catch (error) {
          if (!current) return;
          setDigest(undefined);
          setResults((previous) => ({
            ...previous,
            "resource-isolation": {
              id: "resource-isolation",
              status: "failed",
              detail: error instanceof Error ? error.message : "Integrity verification failed",
            },
          }));
          setComplete(false);
        }
        return;
      }
      setComplete(false);
    });
    return () => {
      current = false;
    };
  }, [attempt]);

  const failed = useMemo(
    () => PREFLIGHT_CHECKS.map((id) => results[id]).find((result) => result.status === "failed"),
    [results],
  );

  async function copyCommand() {
    await navigator.clipboard.writeText(consoleCommand);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1_500);
  }

  return (
    <main className="gate-shell">
      <section className="panel preflight-panel" aria-labelledby="preflight-title">
        <div className="eyebrow">{t("privacyTitle")}</div>
        <h1 id="preflight-title">{t("preflightTitle")}</h1>
        <p className="lede">{t("preflightBody")}</p>

        <ol className="check-list" aria-live="polite">
          {PREFLIGHT_CHECKS.map((id) => {
            const result = results[id];
            return (
              <li key={id} className={`check-row check-${result.status}`}>
                <span className="check-mark" aria-hidden="true">
                  {result.status === "passed"
                    ? "✓"
                    : result.status === "failed"
                      ? "!"
                      : result.status === "running"
                        ? "·"
                        : ""}
                </span>
                <span>
                  <strong>{t(labelKeys[id])}</strong>
                  {result.status === "failed" && (
                    <small>{result.detail ?? t("browserUnsupported")}</small>
                  )}
                </span>
              </li>
            );
          })}
        </ol>

        {complete && digest && (
          <details className="integrity-box">
            <summary>{t("integrityTitle")}: SHA-256</summary>
            <p>{t("integrityCompare")}</p>
            <code className="digest">{digest}</code>
            <div className="button-row">
              <button className="button secondary" type="button" onClick={() => void copyCommand()}>
                {copied ? t("copied") : t("copyConsoleCommand")}
              </button>
              <a
                className="button ghost"
                href="https://github.com/SeriousPassenger/cloudflare-p2p-e2ee-chat/actions"
                target="_blank"
                rel="noopener noreferrer"
              >
                GitHub Actions ↗
              </a>
            </div>
          </details>
        )}

        {failed && <div className="alert danger">{t("browserUnsupported")}</div>}
        <div className="button-row end">
          {failed ? (
            <button className="button primary" type="button" onClick={() => setAttempt((value) => value + 1)}>
              {t("retry")}
            </button>
          ) : (
            <button className="button primary" type="button" disabled={!complete} onClick={onContinue}>
              {complete ? t("continue") : t("loading")}
            </button>
          )}
        </div>
      </section>
    </main>
  );
}
