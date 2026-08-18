import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

const START_MARKER = "<!-- kagetamga-integrity-console:start -->";
const END_MARKER = "<!-- kagetamga-integrity-console:end -->";
const DIGEST_CARD = "[![Current KageTamga SHA-256 build digest in hexadecimal and Base64URL](docs/build-digest.svg)](https://github.com/SeriousPassenger/KageTamga)";
const checkOnly = process.argv.includes("--check");
const positional = process.argv.slice(2).filter((argument) => argument !== "--check");
if (positional.length > 1) throw new Error("Usage: sync-readme-integrity-command.mjs [--check] [README-path]");

const readmePaths = positional[0]
  ? [resolve(positional[0])]
  : [resolve("README.md"), resolve("README.tr.md")];
const source = await readFile(new URL("../src/lib/integrity-digest.ts", import.meta.url), "utf8");
const commandMatch = source.match(/export const INTEGRITY_CONSOLE_COMMAND = `([\s\S]*?)`;\n/u);
if (!commandMatch?.[1] || commandMatch[1].includes("```")) {
  throw new Error("Could not safely extract INTEGRITY_CONSOLE_COMMAND.");
}

for (const readmePath of readmePaths) {
  const turkish = readmePath.endsWith("README.tr.md");
  const generatedBlock = [
    START_MARKER,
    turkish
      ? "#### Dağıtılan derlemeyi tarayıcıda doğrulayın"
      : "#### Verify the deployed build in your browser",
    "",
    turkish
      ? "KageTamga zorunlu ön denetimleri geçtikten sonra dağıtılan uygulamanın geliştirici konsolunu açın ve bu komutun tamamını yapıştırın:"
      : "After KageTamga passes mandatory preflight, open the deployed app's browser developer console and paste this complete command:",
    "",
    "```js",
    commandMatch[1],
    "```",
    "",
    turkish
      ? "Komut, geçerli uygulama yolunun tam `integrity-worker.js` denetleyicisini zorunlu kılar; Service Worker'dan sabitlenmiş manifesti ve önbelleği yeniden doğrulamasını ister; dönen 32 baytlık SHA-256 değerini denetler ve hem küçük harfli onaltılık hem de dolgusuz Base64URL gösterimlerini yazdırıp döndürür. Tam değerlerden birini, deponun ana kaynak sayfasını ayrı bir yoldan açarak yukarıdaki statik özet kartıyla karşılaştırın."
      : "It requires the exact application-path-scoped `integrity-worker.js` controller, asks that Service Worker to reverify its pinned manifest and cache, validates the returned 32-byte SHA-256 value, and prints and returns both lowercase hexadecimal and unpadded Base64URL encodings. Compare either complete value with the static digest card above through a separate view of the repository's main source page.",
    "",
    turkish
      ? "> Bu, yerel sabitlenmiş uygulama kabuğu tutarlılık denetimidir; bağımsız ve güven gerektirmeyen bir kanıt değildir. İlk teslim, sonraki Service Worker güncellemeleri, GitHub, derleme ortamı, tarayıcı ve uç cihaz güven sınırı olmaya devam eder."
      : "> This is a local pinned-shell consistency check, not a trustless proof. First-use delivery, later Service Worker updates, GitHub, the build environment, the browser, and the endpoint remain trust boundaries.",
    END_MARKER,
  ].join("\n");

  const original = await readFile(readmePath, "utf8");
  let updated = original.replace(
    /^\[!\[Current KageTamga SHA-256 build digest in hexadecimal and Base64URL\]\(docs\/build-digest\.svg\)\]\([^\n]+\)$/mu,
    DIGEST_CARD,
  );
  const startIndex = updated.indexOf(START_MARKER);
  const endIndex = updated.indexOf(END_MARKER);
  if ((startIndex === -1) !== (endIndex === -1)) {
    throw new Error(`${readmePath} has only one integrity-console generation marker.`);
  }
  if (startIndex !== -1) {
    if (
      updated.indexOf(START_MARKER, startIndex + 1) !== -1 ||
      updated.indexOf(END_MARKER, endIndex + 1) !== -1
    ) {
      throw new Error(`${readmePath} has duplicate integrity-console generation markers.`);
    }
    updated = `${updated.slice(0, startIndex)}${generatedBlock}${updated.slice(endIndex + END_MARKER.length)}`;
  } else {
    const cardIndex = updated.indexOf(DIGEST_CARD);
    if (cardIndex === -1) throw new Error(`${readmePath} digest card was not found.`);
    const insertionPoint = cardIndex + DIGEST_CARD.length;
    updated = `${updated.slice(0, insertionPoint)}\n\n${generatedBlock}${updated.slice(insertionPoint)}`;
  }

  if (updated === original) {
    console.log(`${readmePath} browser-console verifier is current.`);
  } else if (checkOnly) {
    throw new Error(`${readmePath} browser-console verifier is stale; run npm run integrity:readme.`);
  } else {
    await writeFile(readmePath, updated, "utf8");
    console.log(`Updated ${readmePath}.`);
  }
}
