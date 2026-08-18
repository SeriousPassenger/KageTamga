import { createHash } from "node:crypto";
import { readFile, readdir, writeFile } from "node:fs/promises";
import { extname, relative, sep } from "node:path";

async function walk(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  return (await Promise.all(entries.map((entry) => {
    const path = `${directory}/${entry.name}`;
    return entry.isDirectory() ? walk(path) : [path];
  }))).flat();
}

const assets = {};
for (const path of (await walk("dist"))
  .filter((candidate) => [".html", ".js", ".css"].includes(extname(candidate)))
  .filter((candidate) => !candidate.endsWith("/integrity-worker.js"))
  .sort()) {
  const url = `/${relative("dist", path).split(sep).join("/")}`;
  assets[url] = createHash("sha256").update(await readFile(path)).digest("base64url");
}

const shellDigest = createHash("sha256").update(JSON.stringify(assets)).digest("base64url");
const workerPath = "dist/integrity-worker.js";
const worker = await readFile(workerPath, "utf8");
const placeholder = "__KAGETAMGA_BUILD_STAMP__";
if (!worker.includes(placeholder)) throw new Error("Integrity Worker build-stamp placeholder is missing.");
await writeFile(workerPath, worker.replaceAll(placeholder, shellDigest), "utf8");
console.log(`Stamped integrity worker for shell ${shellDigest}.`);
