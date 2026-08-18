import { afterEach, describe, expect, it, vi } from "vitest";

afterEach(() => {
  vi.unstubAllGlobals();
  vi.resetModules();
});

describe("integrityWorkerRegistrationUrl", () => {
  it("returns the exact same-origin worker URL when Trusted Types are unavailable", async () => {
    vi.stubGlobal("location", new URL("https://chat.example/room"));
    const { integrityWorkerRegistrationUrl } = await import("./trusted-types");

    expect(integrityWorkerRegistrationUrl("/integrity-worker.js")).toBe(
      "https://chat.example/integrity-worker.js",
    );
    expect(() => integrityWorkerRegistrationUrl("https://attacker.example/worker.js")).toThrow(
      "Only the same-origin KageTamga integrity worker may be registered.",
    );
  });

  it("pins the worker to the current static application subpath", async () => {
    vi.stubGlobal("location", new URL("https://pages.example/projects/KageTamga/"));
    const { integrityWorkerRegistrationUrl } = await import("./trusted-types");

    expect(integrityWorkerRegistrationUrl("./integrity-worker.js")).toBe(
      "https://pages.example/projects/KageTamga/integrity-worker.js",
    );
    expect(() => integrityWorkerRegistrationUrl("/integrity-worker.js")).toThrow(
      "Only the same-origin KageTamga integrity worker may be registered.",
    );
  });

  it("uses one narrowly scoped named policy for the registration sink", async () => {
    vi.stubGlobal("location", new URL("https://chat.example/"));
    let policyRules: { createScriptURL(input: string): string } | undefined;
    const trustedUrl = { kind: "TrustedScriptURL" };
    const createPolicy = vi.fn(
      (name: string, rules: { createScriptURL(input: string): string }) => {
        expect(name).toBe("kagetamga");
        policyRules = rules;
        return {
          createScriptURL(input: string) {
            expect(rules.createScriptURL(input)).toBe(
              "https://chat.example/integrity-worker.js",
            );
            return trustedUrl;
          },
        };
      },
    );
    vi.stubGlobal("trustedTypes", { createPolicy });
    const { integrityWorkerRegistrationUrl } = await import("./trusted-types");

    expect(integrityWorkerRegistrationUrl("/integrity-worker.js")).toBe(trustedUrl);
    expect(integrityWorkerRegistrationUrl("/integrity-worker.js")).toBe(trustedUrl);
    expect(createPolicy).toHaveBeenCalledTimes(1);
    expect(() => policyRules?.createScriptURL("/another-worker.js")).toThrow(
      "Only the same-origin KageTamga integrity worker may be registered.",
    );
  });
});
