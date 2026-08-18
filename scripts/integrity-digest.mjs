import { readFile } from "node:fs/promises";

export async function readIntegrityBuildDigest(
  manifestUrl = new URL("../dist/integrity-manifest.json", import.meta.url),
) {
  const manifest = JSON.parse(await readFile(manifestUrl, "utf8"));
  const base64Url = manifest?.buildDigest;
  if (typeof base64Url !== "string" || !/^[A-Za-z0-9_-]{43}$/u.test(base64Url)) {
    throw new Error("The integrity manifest has no canonical SHA-256 Base64URL build digest.");
  }

  const bytes = Buffer.from(base64Url, "base64url");
  if (bytes.length !== 32 || bytes.toString("base64url") !== base64Url) {
    throw new Error("The integrity manifest build digest is not a canonical 32-byte value.");
  }

  return Object.freeze({
    algorithm: "SHA-256",
    base64Url,
    hex: bytes.toString("hex"),
  });
}
