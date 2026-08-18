import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { basename, join } from "node:path";

const lock = JSON.parse(await readFile("package-lock.json", "utf8"));
const productionPackages = Object.entries(lock.packages)
  .filter(([path, metadata]) => path.startsWith("node_modules/") && !metadata.dev)
  .sort(([left], [right]) => left.localeCompare(right));
const kageTamgaLicense = (await readFile("LICENSE", "utf8")).trim();

const sections = [];
for (const [path, metadata] of productionPackages) {
  const packageDirectory = join(process.cwd(), path);
  const packageJson = JSON.parse(await readFile(join(packageDirectory, "package.json"), "utf8"));
  const filenames = await readdir(packageDirectory);
  const licenseFilename = filenames.find((name) =>
    /^(?:licen[cs]e|copying)(?:[._-].*)?$/iu.test(name));
  if (!licenseFilename) {
    throw new Error(
      `${packageJson.name ?? path} does not ship a recognizable license file; ` +
        "add a reviewed notice before releasing it.",
    );
  }
  const licenseText = await readFile(join(packageDirectory, licenseFilename), "utf8");
  const repository =
    typeof packageJson.repository === "string"
      ? packageJson.repository
      : packageJson.repository?.url ?? "not specified";
  sections.push(
    [
      "=".repeat(78),
      `${packageJson.name ?? basename(path)} ${packageJson.version ?? metadata.version ?? "unknown"}`,
      `Declared license: ${packageJson.license ?? metadata.license ?? "unknown"}`,
      `Source: ${repository}`,
      "-".repeat(78),
      licenseText.trim(),
    ].join("\n"),
  );
}

await mkdir("dist", { recursive: true });
await writeFile(
  "dist/THIRD_PARTY_LICENSES.txt",
  [
    "KageTamga third-party software notices",
    "Generated from the exact production dependency graph in package-lock.json.",
    "The application's own MIT License text is included first.",
    "",
    "=".repeat(78),
    "KageTamga 0.1.0",
    "Declared license: MIT",
    "Source: https://github.com/SeriousPassenger/KageTamga",
    "-".repeat(78),
    kageTamgaLicense,
    "",
    ...sections,
    "",
  ].join("\n"),
  "utf8",
);

console.log(`Wrote licenses for ${productionPackages.length} production packages.`);
