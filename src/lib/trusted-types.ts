interface QuietWireTrustedTypePolicy {
  createScriptURL(input: string): unknown;
}

interface QuietWireTrustedTypePolicyFactory {
  createPolicy(
    name: string,
    rules: { createScriptURL(input: string): string },
  ): QuietWireTrustedTypePolicy;
}

let integrityWorkerPolicy: QuietWireTrustedTypePolicy | undefined;

function exactIntegrityWorkerUrl(input: string): string {
  const expected = new URL("/integrity-worker.js", location.origin).href;
  const candidate = new URL(input, location.origin).href;
  if (candidate !== expected) {
    throw new TypeError("Only the same-origin QuietWire integrity worker may be registered.");
  }
  return expected;
}

/**
 * Returns the sole script URL allowed through QuietWire's Trusted Types policy.
 * Browsers that do not implement Trusted Types receive the same validated string.
 */
export function integrityWorkerRegistrationUrl(input: string): string {
  const exactUrl = exactIntegrityWorkerUrl(input);
  const trustedTypes = (
    globalThis as typeof globalThis & { trustedTypes?: QuietWireTrustedTypePolicyFactory }
  ).trustedTypes;
  if (!trustedTypes) return exactUrl;

  integrityWorkerPolicy ??= trustedTypes.createPolicy("quietwire", {
    createScriptURL: exactIntegrityWorkerUrl,
  });
  return integrityWorkerPolicy.createScriptURL(exactUrl) as string;
}
