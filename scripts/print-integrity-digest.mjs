import { appendFile } from "node:fs/promises";
import { readIntegrityBuildDigest } from "./integrity-digest.mjs";

const digest = await readIntegrityBuildDigest();

console.log(`KageTamga build digest (SHA-256, Base64URL unpadded): ${digest.base64Url}`);
console.log(`KageTamga build digest (SHA-256, lowercase hex): ${digest.hex}`);
console.log(`KageTamga integrity artifact name: ${digest.hex}`);

if (process.env.GITHUB_OUTPUT) {
  await appendFile(
    process.env.GITHUB_OUTPUT,
    `base64url=${digest.base64Url}\nsha256_hex=${digest.hex}\nartifact_name=${digest.hex}\n`,
    "utf8",
  );
}

if (process.env.GITHUB_STEP_SUMMARY) {
  await appendFile(
    process.env.GITHUB_STEP_SUMMARY,
    [
      "## KageTamga build digest",
      "",
      "| Encoding | Value |",
      "| --- | --- |",
      `| SHA-256 · Base64URL (unpadded) | \`${digest.base64Url}\` |`,
      `| SHA-256 · lowercase hex | \`${digest.hex}\` |`,
      `| Artifact name | \`${digest.hex}\` |`,
      "",
      "> GitHub's separate artifact digest hashes the downloadable ZIP. The values above hash KageTamga's canonical pinned-shell asset map.",
      "",
    ].join("\n"),
    "utf8",
  );
}
