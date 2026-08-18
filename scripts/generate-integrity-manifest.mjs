import { createHash } from "node:crypto";
import { readFile, readdir, writeFile } from "node:fs/promises";
import { extname, relative, sep } from "node:path";

async function walk(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const nested = await Promise.all(
    entries.map(async (entry) => {
      const path = `${directory}/${entry.name}`;
      return entry.isDirectory() ? walk(path) : [path];
    }),
  );
  return nested.flat();
}

const candidates = (await walk("dist"))
  .filter((path) => [".html", ".js", ".css"].includes(extname(path)))
  .sort();
const assets = {};
for (const path of candidates) {
  const bytes = await readFile(path);
  const url = `/${relative("dist", path).split(sep).join("/")}`;
  assets[url] = createHash("sha256").update(bytes).digest("base64url");
}
const shellAssets = Object.fromEntries(
  Object.entries(assets).filter(([path]) => path !== "/integrity-worker.js"),
);
const shellDigest = createHash("sha256")
  .update(JSON.stringify(shellAssets))
  .digest("base64url");
const buildDigest = createHash("sha256")
  .update(JSON.stringify(assets))
  .digest("base64url");
await writeFile(
  "dist/integrity-manifest.json",
  `${JSON.stringify({ version: 1, algorithm: "SHA-256", shellDigest, buildDigest, assets }, null, 2)}\n`,
  "utf8",
);
console.log(`Pinned ${candidates.length} application assets (${buildDigest}).`);
