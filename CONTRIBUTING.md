# Contributing

Contributions are welcome, especially security review, tests, accessibility improvements, and corrections to translations or documentation. QuietWire is security-sensitive: a small UI, storage, or dependency change can silently weaken its promises.

## Before opening a pull request

For vulnerabilities, follow [SECURITY.md](SECURITY.md) instead of opening a public issue.

For ordinary changes:

```bash
npm ci
npm run check
```

Use Node.js 22 or newer. Keep commits focused and explain the user-visible and security impact in the pull request.

## Non-negotiable privacy constraints

A normal contribution must not add:

- analytics, telemetry, browser RUM, advertising, fingerprints, or trackers;
- third-party runtime scripts, styles, fonts, images, CDNs, tag managers, or remote code;
- plaintext logging of room URLs/IDs, peer IDs, SDP, ICE, identities, keys, passphrases, messages, or cryptographic errors containing sensitive values;
- server-side messages, identity keys, contact graphs, or signaling-payload persistence;
- D1, KV, R2, Queues, Analytics Engine, Logpush, crash reporting, or an external monitoring service;
- additional/unreviewed Service Workers, caching of user or `/api` data, network fallback for executable resources, or application-shell caching outside the integrity manifest;
- a weaker CSP, Permissions Policy, origin boundary, cache directive, or observability setting merely to make a feature easier; or
- misleading claims of anonymity, audited security, quantum safety, forward secrecy, remote erasure, or identity authentication without fingerprint verification.

A proposal that genuinely requires one of these must include a new threat analysis, explicit user disclosure/consent, data-flow documentation, retention controls, and a maintainer decision before implementation.

## Cryptographic and protocol changes

Do not invent, silently downgrade, or relabel cryptography. A cryptographic pull request should include:

- the exact algorithm and wire-format/version change;
- test vectors or cross-implementation evidence where available;
- negative tests for tampering, wrong recipient, wrong key, malformed length, replay/duplicate handling, and downgrade/substitution;
- a migration/backward-compatibility plan;
- key lifecycle, nonce generation, domain separation, and deletion analysis;
- an update to [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md); and
- prominent disclosure when a component or composition is experimental or unaudited.

The current PQ envelope is an application-specific nesting of inner OpenPGP X25519-encrypted/Ed25519-signed data with outer FIPS 203 ML-KEM-768/AES-256-GCM recipient protection. It is not X-Wing wire compatibility and must not be described that way. ML-KEM key material must stay bound to the signed OpenPGP identity, and a human-verified full OpenPGP fingerprint remains the authentication root.

Pure-JavaScript post-quantum code does not provide strong constant-time guarantees. Do not convert “defense in depth” into a security certification claim.

Generated and imported OpenPGP identities are deliberately restricted to v4, 40-hex fingerprints, Ed25519 signatures, and X25519 encryption; legacy OpenPGP Curve25519 encodings are accepted. Every usable peer and local identity must also have an exact, internally consistent ML-KEM-768 key. The combined profile hard-fails if either half is missing, malformed, mismatched, or uses another algorithm; do not add a classical-only or PQ downgrade path. Do not broaden the OpenPGP policy to RSA, P-curves, v6, revoked, expired, or invalid keys without changing the protocol/UI labels, fingerprint workflow, tests, migration plan, and threat model.

The complete `.quietwire.json` backup is the one complete combined-identity recovery artifact and a versioned protocol surface. Changes to stored OpenPGP/ML-KEM fields, protection parameters, validation, import, or export require round-trip and wrong-key tests plus migration/recovery documentation. A raw OpenPGP `.asc` import intentionally creates a fresh required ML-KEM-768 key and must not be presented as a complete restore or classical-only operating mode.

Each message must use a fresh random AES-256 content key. There is no shared room key or join/leave group-key rotation. The sender's own locally verified contacts determine the exact recipients independently for every message. Preserve these trust and delivery invariants:

- trust is directional, local, and non-transitive;
- a signed room-scoped trust announcement is independently verified and displayed as information, but never mutates or inherits local trust;
- the signed delivery manifest binds the canonical envelope digest and exact sorted recipient fingerprints;
- an excluded peer receives only the authenticated not-shared state and encrypted transport, never plaintext;
- a recipient who can decrypt but has not locally verified the sender remains visibly untrusted; and
- a local data-channel send is not represented as a delivery or read receipt.

## Frontend changes

- Keep all runtime resources local and bundled.
- Never render untrusted peer data as HTML. Preserve React text escaping and Trusted Types.
- Make security state explicit: unverified vs. verified, key changed, direct vs. relay, connecting vs. offline.
- Use complete 40-hex v4 fingerprints for verification; short identifiers are display aids only.
- Do not expose secrets in query strings, document titles, analytics, errors, clipboard operations the user did not request, or referrers.
- Keep application, room, and message metadata JSON explicitly allowlisted and redacted. Fingerprints, peer IDs, message IDs, sizes, counts, trust state, and delivery-recipient sets are still metadata. The separate nested per-message raw transport panel is deliberately opt-in and may show the exact encrypted delivery manifest/envelope, including ciphertext; it must remain collapsed and must never contain room secrets, passphrases, private keys, or plaintext.
- Preserve accessible keyboard interaction, focus, labels, warnings, and color-independent state cues.
- Treat the clipboard and downloaded files as explicit user actions with clear private/public labeling.

## Translations

Security warnings must not fall back to ambiguous or softer wording. When adding or changing a string:

- update English, German, Japanese, Turkish, Spanish, French, Simplified Chinese, and Traditional Chinese;
- preserve the distinction between public key/fingerprint and private key/passphrase;
- preserve “verified” versus merely “encrypted”;
- preserve warnings about IP exposure, peer retention, unrecoverable key loss, and key changes; and
- have a fluent speaker review high-impact security language when possible.

Do not infer a user's identity or location from language choice. Language detection and the saved preference remain local.

## Integrity Service Worker

The one expected Service Worker is a trust-on-first-use shell-integrity control, not an offline application or an origin-independent signature system. Keep these properties:

- only same-origin, manifest-listed HTML/JavaScript/CSS and the build-stamped `/integrity-worker.js` are pinned;
- `/api` requests and user data are never cached;
- unlisted document/script/style/worker requests fail closed after control;
- the build first stamps the integrity worker with the digest of that shell, then the manifest/build digest covers the stamped worker as well as the other canonical assets;
- cache names are build-specific, stale build caches are removed on activation, and a first install forces a reload through the new controller before the app continues;
- a foreign Service Worker registration fails preflight;
- full local purge deletes Cache Storage and unregisters Service Workers; and
- documentation continues to disclose first-load and malicious-update limitations.

Changes to the manifest generator, `integrity-worker.js`, Cache Storage behavior, preflight, or CI artifact require adversarial cache/update tests and an update to the threat model.

Keep every third-party GitHub Action pinned to a reviewed full commit SHA. CI must recompute and compare every manifest-listed file digest, the non-worker `shellDigest`, the complete `buildDigest`, and the integrity worker's embedded stamp; uploading or printing the manifest alone is not integrity verification.

## Cloudflare changes

Keep `observability.enabled` false and keep `assets.run_worker_first: true` globally. Every network asset request must pass through the Worker so the first HTTP visit is redirected and every Worker/static response receives the authoritative security headers. The integrity Service Worker's build-specific pinned cache minimizes repeat edge requests after it controls the page, but contributors must not claim that uncached static requests bypass Worker code. Durable Object changes must preserve ephemeral-only signaling and avoid `ctx.storage` calls.

Keep the room capability 256-bit and in the URL fragment, the derived routing ID opaque, the WebSocket `Origin` check exact and same-origin, the eight-peer server/client room cap, the per-socket signaling rate limit, and the client unique-peer safety cap. These are bounded-resource controls, not user authentication or complete abuse protection. Preserve room-local ignore by fingerprint: it closes/suppresses that local P2P relationship for the session, but must not be described as a persistent/server-side block or invite revocation. Operators still need appropriate edge IP/rate controls.

The “lock signaling” action is local and one-way for the current tab/room session: it closes only that client's signaling WebSocket while established data channels continue. Do not describe it as a server room lock, invite revocation, or global admission control. If TURN support is proposed, it needs short-lived credentials, abuse/cost controls, provider disclosure, and explicit direct/auto/relay behavior; a long-lived TURN secret must never be shipped to the browser.

After deployment, use [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) to check headers, Network activity, source injection, and opaque signaling frames.

## License

By contributing, you agree that your contribution is provided under the repository's [MIT License](LICENSE).
