# Contributing

Contributions are welcome, especially security review, tests, accessibility improvements, and corrections to translations or documentation. KageTamga is security-sensitive: a small UI, storage, or dependency change can silently weaken its promises.

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
- an application backend, hosted room discovery/signaling, server-side messages, identity keys, contact graphs, or signaling persistence;
- remote storage, queues, hosted analytics, crash reporting, request-body inspection, or an external monitoring service;
- additional/unreviewed Service Workers, caching of user or arbitrary network data, network fallback for executable resources, or application-shell caching outside the integrity manifest;
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

The complete `.kagetamga.json` backup is the one complete combined-identity and persistent-trust recovery artifact and a versioned protocol surface. Its identity/contact payload remains authenticated ciphertext under a key derived from the unlocked ML-KEM secret, while the ML-KEM secret remains passphrase protected. Changes to stored OpenPGP/ML-KEM/contact fields, protection parameters, validation, import, or export require round-trip, tamper, wrong-key, wrong-passphrase, and owner-signature tests plus migration/recovery documentation. A raw OpenPGP `.asc` import intentionally creates a fresh required ML-KEM-768 key and must not be presented as a complete restore or classical-only operating mode.

Each message must use a fresh random AES-256 content key. There is no shared room key or join/leave group-key rotation. The sender's own locally verified contacts determine the exact recipients independently for every message. Preserve these trust and delivery invariants:

- trust is directional, local, and non-transitive;
- a signed room-scoped trust announcement is independently verified and displayed as information, but never mutates or inherits local trust;
- the signed delivery manifest binds the canonical envelope digest and exact sorted recipient fingerprints;
- an excluded peer receives only the authenticated not-shared state and encrypted transport, never plaintext;
- a recipient who can decrypt but has not locally verified the sender remains visibly untrusted; and
- a local data-channel send is not represented as a delivery or read receipt.

Peer-assisted WebRTC setup also preserves these invariants:

- the newcomer signs its exact identity and every targeted offer/answer SDP;
- every direct relayer signs a fresh room/target/hop/time/nonce-bound outer statement;
- the receiving browser requires the direct relayer fingerprint in its own persistent owner-signed trust list before nested payload processing;
- after signature verification, the receiving browser separately requires the embedded origin fingerprint in its own persistent owner-signed trust list;
- an intermediate forward requires a locally trusted direct next hop;
- unknown, unsigned, invalid, stale, replayed, wrong-target, or over-hop relays are dropped and visibly reported;
- a denied known relayer fingerprint appears in a red chat security event; and
- a valid introduction never grants chat or relay trust to the newcomer automatically.

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

- only same-origin, manifest-listed HTML/JavaScript/CSS and the application-path build-stamped `integrity-worker.js` are pinned;
- user data and arbitrary network responses are never cached;
- every unlisted request within the controlled application path fails closed;
- the build first stamps the integrity worker with the digest of that shell, then the manifest/build digest covers the stamped worker as well as the other canonical assets;
- cache names are build-specific, stale build caches are removed on activation, and a first install forces a reload through the new controller before the app continues;
- a foreign Service Worker capable of controlling the application path fails preflight;
- full local purge deletes Cache Storage and unregisters Service Workers; and
- documentation continues to disclose first-load and malicious-update limitations.

Changes to the manifest generator, `integrity-worker.js`, Cache Storage behavior, preflight, or CI artifact require adversarial cache/update tests and an update to the threat model.

Keep every third-party GitHub Action pinned to a reviewed full commit SHA. CI must recompute and compare every manifest-listed file digest, the non-worker `shellDigest`, the complete `buildDigest`, and the integrity worker's embedded stamp; uploading or printing the manifest alone is not integrity verification.

## Static delivery, manual signaling, and ICE

KageTamga has no application backend. Do not add a hosted Worker/function, WebSocket rendezvous, database, account, mailbox, room-presence endpoint, or implicit network discovery while describing the result as the same architecture. A proposal for hosted signaling requires a new protocol version, threat model, data-flow/retention disclosure, opt-in design, abuse plan, and maintainer decision.

Keep the room capability 256-bit and in the URL fragment. Manual offer/answer codes remain room-key-encrypted, origin-signed, canonical, bounded, fresh, target-bound, replay-tracked, and tied to in-tab pending exchanges. The existing trusted-peer mesh may forward only the dual-signed protocol described above.

Preserve the eight-peer active cap, cumulative-peer cap, pending-offer cap, buffer/message/control bounds, negotiation/ICE timeouts, replay-cache limits, and maximum relay hops. These contain local resources; they do not provide complete denial-of-service protection.

ICE URLs stay user-configurable before entering a room and tab-memory-only. STUN and TURN must never be described as signaling or member discovery. TURN credentials must not enter source, IndexedDB, backups, logs, debug JSON, or exported transport JSON. Any default endpoint change requires privacy/availability review and documentation of operator metadata exposure.

The production build stays subpath-safe with relative assets and application-path Service Worker scope. Changes must be tested at both `/` and a project-style `/KageTamga/` path. After deployment, use [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) to check headers, MIME types, guarded reload, Service Worker scope, network activity, source injection, digest comparison, manual connection, and relay denial.

## License

By contributing, you agree that your contribution is provided under the repository's [MIT License](LICENSE).
