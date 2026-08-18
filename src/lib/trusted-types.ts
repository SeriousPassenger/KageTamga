interface KageTamgaTrustedTypePolicy {
  createScriptURL(input: string): unknown;
}

interface KageTamgaTrustedTypePolicyFactory {
  createPolicy(
    name: string,
    rules: { createScriptURL(input: string): string },
  ): KageTamgaTrustedTypePolicy;
}

let integrityWorkerPolicy: KageTamgaTrustedTypePolicy | undefined;

function exactIntegrityWorkerUrl(input: string): string {
  const expected = new URL("integrity-worker.js", new URL(".", location.href)).href;
  const candidate = new URL(input, location.href).href;
  if (candidate !== expected) {
    throw new TypeError("Only the same-origin KageTamga integrity worker may be registered.");
  }
  return expected;
}

/**
 * Returns the sole script URL allowed through KageTamga's Trusted Types policy.
 * Browsers that do not implement Trusted Types receive the same validated string.
 */
export function integrityWorkerRegistrationUrl(input: string): string {
  const exactUrl = exactIntegrityWorkerUrl(input);
  const trustedTypes = (
    globalThis as typeof globalThis & { trustedTypes?: KageTamgaTrustedTypePolicyFactory }
  ).trustedTypes;
  if (!trustedTypes) return exactUrl;

  integrityWorkerPolicy ??= trustedTypes.createPolicy("kagetamga", {
    createScriptURL: exactIntegrityWorkerUrl,
  });
  return integrityWorkerPolicy.createScriptURL(exactUrl) as string;
}
