# Security policy

KageTamga handles cryptographic keys and private conversations, so responsible reports are appreciated. This repository is an **initial, unaudited MVP**. It has no certification, formal verification, bug bounty, or claim of fitness for high-risk use.

## Report a vulnerability

Report privately to **seriouspassenger@proton.me** with subject `KageTamga security report`.

Include when possible:

- affected commit or deployed version;
- impact and threat scenario;
- reproduction steps or a minimal disposable proof of concept;
- affected browsers and operating systems;
- suggested remediation.

Do not send real private keys, passphrases, room links, messages, personal data, TURN credentials, or backups. Generate disposable identities and rooms. Do not open a public issue for an unpatched vulnerability that could expose users. Receipt, remediation, and coordinated disclosure are best effort; no response timeline is promised.

## Supported versions

Only current `main` is supported. Older commits, forks, modified builds, and third-party deployments may lack fixes.

## Intended security boundaries

- KageTamga is a static browser application with no application signaling service, account database, transcript, offline mailbox, or server-side key/message store.
- OpenPGP identities hard-fail unless every key packet matches the accepted v4 Ed25519-signing/X25519-encryption profile and the 40-hex fingerprint is internally consistent.
- Every operational identity also requires an exact ML-KEM-768 pair signed into the room assertion; there is no classical-only, missing-PQ, alternate-KEM, or alternate-curve fallback.
- The first connection uses room-key-encrypted manual offer/answer codes whose exact SDP and identity are signed by the origin peer.
- Peer-assisted setup requires a valid origin signature plus a fresh outer signature from the direct relayer.
- The receiver drops even correctly dual-signed relay data unless the direct relayer fingerprint is in that receiver's persistent owner-signed trust list. A red event shows the denied fingerprint when known.
- The receiver also drops cryptographically valid setup unless the embedded newcomer/origin fingerprint independently already exists in that same local persistent list. A separate red event names that denied origin.
- Trust is local, directional, persistent, and non-transitive. Signed trust announcements are information only.
- Each message uses an inner signed/encrypted OpenPGP payload, a fresh random AES-256-GCM content key, recipient-specific ML-KEM-768/HKDF/AES wrapping, and a signed recipient-bound delivery manifest.
- Chat packets travel through WebRTC data channels. Public/default STUN and optional user-supplied TURN are ICE infrastructure, not participant discovery or application signaling.
- Passphrase-protected identity material, owner-signed trusted contacts, and encrypted history stay in origin-scoped IndexedDB until local purge.
- Complete encrypted `.kagetamga.json` backups contain identity data and the persistent trusted-fingerprint list.
- Production resources and dependencies are locally bundled. A build-stamped, manifest-pinned Service Worker hard-fails on inconsistent executable resources after one guarded trust-on-first-use reload.

These are not anonymity or endpoint-compromise guarantees. The static host is trusted for first delivery and later Service Worker updates. Direct peers and ICE operators can observe network metadata. A malicious same-origin bundle, hostile extension, compromised browser/OS, malware, unlocked profile, or verified malicious peer may access plaintext or keys.

The ML-KEM nesting is experimental defense in depth. It is not X-Wing compatibility, a formal hybrid proof, post-quantum authentication, a ratchet, forward secrecy, or post-compromise security. See [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md).

## High-value report areas

Reports are especially useful when they demonstrate:

- private-key, ML-KEM-secret, passphrase, room-capability, plaintext, TURN-credential, or decrypted-backup leakage;
- CSPRNG/key/nonce reuse or broken domain separation;
- acceptance of RSA, unsupported curves, hidden mixed subkeys, invalid/expired/revoked keys, missing ML-KEM, wrong ML-KEM sizes, or algorithm downgrade;
- forged identity assertions, SDP, trust announcements, delivery manifests, envelopes, or recipient sets;
- a valid/invalid/unsigned/stale/replayed relay processed when the direct relayer or embedded origin is not persistently trusted;
- a denied setup that fails to identify the known denied relayer/origin fingerprint or still processes the nested introduction;
- automatic transitive trust or encryption to a fingerprint the sender did not locally verify;
- trust-change races that still send to a revoked/ignored/replaced session;
- same-fingerprint UI confusion, distinct-fingerprint merging, or key-change suppression;
- backup plaintext leakage, contact omission, owner-signature bypass, wrong-key import, or unauthenticated header/payload substitution;
- cross-site scripting, Trusted Types/CSP bypass, remote script execution, or developer JSON secret/plaintext exposure;
- integrity-manifest, build-stamp, Service Worker scope/cache/controller, guarded-reload, or digest-comparison bypass;
- unexpected application network services, server persistence, analytics, or runtime CDN use;
- conflicting authenticated message replay acceptance;
- local purge affecting data outside its explicit scope.

## Documented limitations

The following are not vulnerabilities by themselves:

- first-use and later Service Worker update trust in the static host;
- public/network address exposure to direct peers and configured ICE operators;
- TURN visibility into encrypted packet metadata when the user configures it;
- room attempts by anyone possessing the full room link;
- no offline delivery, account recovery, remote recall, read receipt, ratchet, forward secrecy, or post-compromise security;
- validly signed but locally untrusted plaintext displayed red when the user was selected as a recipient;
- encrypted envelope/manifest visibility without plaintext when the viewer was not selected;
- peer retention after local purge;
- local/session Ignore rather than global blocking or invite revocation;
- limited plaintext indexing/display metadata beside local encrypted message envelopes;
- endpoint compromise, screenshots, clipboard history, browser remnants, hostile extensions, or an unlocked device;
- denial of service against the static host, ICE service, browser, or room peers;
- a persistently trusted malicious relayer withholding or selectively forwarding valid data.

## If an identity may be compromised

1. Stop using the identity and affected device.
2. Create and back up a new identity from a trusted device.
3. Use the saved OpenPGP revocation certificate where contacts can independently verify it. The app does not publish it automatically.
4. Tell contacts through an already authenticated channel and compare the new full fingerprint.
5. Remove the old persistent trust on every device.
6. Preserve evidence as needed, then purge the old identity and local conversations.

Purge cannot delete peer copies, screenshots, exported backups, browser sync/device backups, network/provider metadata, or forensic remnants.

## Backup safety

- Download the complete `name.kagetamga.json` after creation and after important trust-list changes.
- The encrypted payload contains OpenPGP identity data, the matching ML-KEM public data, revocation certificate, and owner-signed trusted contacts. The protected ML-KEM secret in the outer header is required to derive the backup decryption key after passphrase unlock.
- Individual `.asc` files are supplemental OpenPGP recovery, not a complete KageTamga restore.
- Use a long unique passphrase and store backups in an appropriate offline/encrypted location.
- Test restoration in a disposable browser profile.
- Treat the backup as sensitive: it permits offline passphrase attempts.

There is no escrow or recovery service. Lost keys and forgotten passphrases are unrecoverable.

## Deployment responsibility

Operators must protect source and hosting accounts, publish one complete unchanged `dist/`, serve it through HTTPS, disable runtime injection/analytics/transforms, preserve licenses, verify headers and MIME types, and compare the deployed digest. They should keep dependencies current and apply normal static-host availability controls. Follow [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

A fork that adds hosted signaling, analytics, remote runtime code, mandatory TURN, account state, persistence, logging, or different cryptography changes the threat model and must disclose that prominently.
