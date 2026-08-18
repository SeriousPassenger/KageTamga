export interface IceSettings {
  urlsText: string;
  username: string;
  credential: string;
}

export const DEFAULT_ICE_URLS = [
  "stun:stun.l.google.com:19302",
  "stun:stun1.l.google.com:19302",
] as const;

export const DEFAULT_ICE_SETTINGS: IceSettings = {
  urlsText: DEFAULT_ICE_URLS.join("\n"),
  username: "",
  credential: "",
};

const ICE_URL_PATTERN = /^(stun|stuns|turn|turns):([A-Za-z0-9.-]+|\[[A-Fa-f0-9:]+\])(?::([0-9]{1,5}))?(?:\?transport=(udp|tcp))?$/u;
const MAX_ICE_URLS = 8;
const MAX_CREDENTIAL_CHARACTERS = 256;

export function iceServersFromSettings(settings: IceSettings): RTCIceServer[] {
  if (!isSafeCredential(settings.username) || !isSafeCredential(settings.credential)) {
    throw new Error("ICE credentials are malformed or too long.");
  }
  const urls = [...new Set(
    settings.urlsText
      .split(/\r?\n/gu)
      .map((value) => value.trim())
      .filter(Boolean),
  )];
  if (urls.length > MAX_ICE_URLS) throw new Error("At most eight ICE endpoints are allowed.");

  const stunUrls: string[] = [];
  const turnUrls: string[] = [];
  for (const value of urls) {
    const match = ICE_URL_PATTERN.exec(value);
    if (!match) throw new Error("An ICE endpoint is malformed.");
    const portText = match[3];
    if (portText) {
      const port = Number(portText);
      if (!Number.isInteger(port) || port < 1 || port > 65_535) {
        throw new Error("An ICE endpoint port is outside the valid range.");
      }
    }
    if (match[1] === "turn" || match[1] === "turns") turnUrls.push(value);
    else stunUrls.push(value);
  }

  if (turnUrls.length > 0 && (!settings.username || !settings.credential)) {
    throw new Error("TURN endpoints require both a username and credential.");
  }
  if (turnUrls.length === 0 && (settings.username || settings.credential)) {
    throw new Error("TURN credentials were supplied without a TURN endpoint.");
  }

  const servers: RTCIceServer[] = [];
  if (stunUrls.length > 0) servers.push({ urls: stunUrls });
  if (turnUrls.length > 0) {
    servers.push({
      urls: turnUrls,
      username: settings.username,
      credential: settings.credential,
    });
  }
  return servers;
}

function isSafeCredential(value: string): boolean {
  return typeof value === "string" &&
    value.length <= MAX_CREDENTIAL_CHARACTERS &&
    !/[\p{Cc}\p{Cs}\p{Zl}\p{Zp}]/u.test(value);
}
