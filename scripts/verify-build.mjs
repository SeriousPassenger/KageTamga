import { createHash } from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import { extname, join } from "node:path";

const forbidden = [
  /beacon\.min\.js/iu,
  /\/cdn-cgi\/rum/iu,
  /googletagmanager/iu,
  /google-analytics/iu,
  /segment\.com/iu,
  /posthog/iu,
];

async function files(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const nested = await Promise.all(
    entries.map((entry) => {
      const path = join(directory, entry.name);
      return entry.isDirectory() ? files(path) : [path];
    }),
  );
  return nested.flat();
}

function sha256Base64Url(contents) {
  return createHash("sha256").update(contents).digest("base64url");
}

function canonicalDigest(entries) {
  return sha256Base64Url(
    JSON.stringify(
      Object.fromEntries(
        entries.sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0)),
      ),
    ),
  );
}

const builtFiles = await files("dist");
for (const path of builtFiles) {
  if (![".html", ".js", ".css", ".json"].includes(extname(path))) continue;
  const contents = await readFile(path, "utf8");
  for (const pattern of forbidden) {
    if (pattern.test(contents)) {
      throw new Error(`Security verification failed: ${pattern} found in ${path}`);
    }
  }
  if (
    extname(path) === ".html" &&
    /<(?:script|link)\b[^>]*(?:src|href)=["'](?:https?:)?\/\//iu.test(contents)
  ) {
    throw new Error(`Security verification failed: external runtime asset found in ${path}`);
  }
}

const manifest = JSON.parse(await readFile("dist/integrity-manifest.json", "utf8"));
const manifestKeys =
  manifest !== null && typeof manifest === "object" && !Array.isArray(manifest)
    ? Object.keys(manifest).sort()
    : [];
if (
  manifest === null ||
  typeof manifest !== "object" ||
  Array.isArray(manifest) ||
  manifestKeys.join(",") !== "algorithm,assets,buildDigest,shellDigest,version" ||
  manifest.version !== 1 ||
  manifest.algorithm !== "SHA-256" ||
  typeof manifest.shellDigest !== "string" ||
  typeof manifest.buildDigest !== "string" ||
  !/^[A-Za-z0-9_-]{43}$/u.test(manifest.shellDigest) ||
  !/^[A-Za-z0-9_-]{43}$/u.test(manifest.buildDigest) ||
  manifest.assets === null ||
  typeof manifest.assets !== "object" ||
  Array.isArray(manifest.assets)
) {
  throw new Error("Security verification failed: malformed integrity manifest");
}

const assetEntries = Object.entries(manifest.assets);
if (assetEntries.length === 0) {
  throw new Error("Security verification failed: integrity manifest has no assets");
}
if (!("/index.html" in manifest.assets) || !("/integrity-worker.js" in manifest.assets)) {
  throw new Error("Security verification failed: integrity manifest omits a trust anchor");
}

for (const [assetPath, expectedDigest] of assetEntries) {
  if (
    !/^\/(?:assets\/[A-Za-z0-9._-]+|index\.html|integrity-worker\.js)$/u.test(assetPath) ||
    typeof expectedDigest !== "string" ||
    !/^[A-Za-z0-9_-]{43}$/u.test(expectedDigest)
  ) {
    throw new Error(`Security verification failed: invalid manifest entry ${assetPath}`);
  }
  const actualDigest = sha256Base64Url(await readFile(join("dist", assetPath.slice(1))));
  if (actualDigest !== expectedDigest) {
    throw new Error(`Security verification failed: digest mismatch for ${assetPath}`);
  }
}

const shellEntries = assetEntries.filter(([assetPath]) => assetPath !== "/integrity-worker.js");
if (canonicalDigest(shellEntries) !== manifest.shellDigest) {
  throw new Error("Security verification failed: shell digest does not match its assets");
}
if (canonicalDigest(assetEntries) !== manifest.buildDigest) {
  throw new Error("Security verification failed: build digest does not match its assets");
}

const integrityWorker = await readFile("dist/integrity-worker.js", "utf8");
if (!integrityWorker.includes(`const BUILD_STAMP = "${manifest.shellDigest}";`)) {
  throw new Error("Security verification failed: integrity worker is not bound to the shell digest");
}

console.log(
  `Security verification passed for ${builtFiles.length} build files; ` +
    `${assetEntries.length} integrity-pinned assets; build ${manifest.buildDigest}.`,
);
