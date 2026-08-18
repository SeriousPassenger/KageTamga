import { describe, expect, it, vi } from "vitest";
import { INTEGRITY_CONSOLE_COMMAND, sha256DigestEncodings } from "./integrity-digest";

const EMPTY_SHA256_BASE64URL = "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU";
const EMPTY_SHA256_HEX = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

describe("integrity digest encodings", () => {
  it("converts the canonical unpadded Base64URL digest to lowercase hex", () => {
    expect(sha256DigestEncodings(EMPTY_SHA256_BASE64URL)).toEqual({
      algorithm: "SHA-256",
      base64Url: EMPTY_SHA256_BASE64URL,
      hex: EMPTY_SHA256_HEX,
    });
  });

  it.each([
    "",
    "A".repeat(42),
    "A".repeat(44),
    `${"A".repeat(42)}=`,
    `${"A".repeat(42)}+`,
  ])("rejects a malformed digest: %s", (value) => {
    expect(() => sha256DigestEncodings(value)).toThrow(/canonical/u);
  });

  it("makes the copied console verifier return and print both encodings", async () => {
    class TestMessageChannel {
      port1: { onmessage?: (event: { data: unknown }) => void } = {};
      port2 = {
        postMessage: (data: unknown) => this.port1.onmessage?.({ data }),
      };
    }

    const worker = {
      scriptURL: "https://kagetamga.example/integrity-worker.js",
      postMessage: (_message: unknown, ports: Array<{ postMessage(data: unknown): void }>) => {
        ports[0]?.postMessage({ ok: true, buildDigest: EMPTY_SHA256_BASE64URL });
      },
    };
    vi.stubGlobal("location", {
      href: "https://kagetamga.example/",
      origin: "https://kagetamga.example",
    });
    vi.stubGlobal("navigator", {
      serviceWorker: {
        controller: worker,
        ready: Promise.resolve({ scope: "https://kagetamga.example/", waiting: null }),
      },
    });
    vi.stubGlobal("MessageChannel", TestMessageChannel);
    const log = vi.spyOn(console, "log").mockImplementation(() => undefined);

    try {
      const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor as new (
        body: string,
      ) => () => Promise<unknown>;
      const execute = new AsyncFunction(`return ${INTEGRITY_CONSOLE_COMMAND}`);
      await expect(execute()).resolves.toEqual({
        algorithm: "SHA-256",
        base64Url: EMPTY_SHA256_BASE64URL,
        hex: EMPTY_SHA256_HEX,
      });
      expect(log).toHaveBeenCalledWith(
        "KageTamga build digest (SHA-256, Base64URL unpadded):",
        EMPTY_SHA256_BASE64URL,
      );
      expect(log).toHaveBeenCalledWith(
        "KageTamga build digest (SHA-256, lowercase hex):",
        EMPTY_SHA256_HEX,
      );
    } finally {
      log.mockRestore();
      vi.unstubAllGlobals();
    }
  });
});
