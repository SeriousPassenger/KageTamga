# Security policy

QuietWire handles cryptographic keys and private conversations, so responsible reports are appreciated. This repository is an **initial, unaudited MVP**. It has no security certification, formal verification, bug bounty, or claim of fitness for high-risk use.

## Reporting a vulnerability

Please report vulnerabilities privately to **seriouspassenger@proton.me** with the subject `QuietWire security report`.

Include, when possible:

- the affected commit or deployed version;
- a concise description of the impact and threat scenario;
- reproduction steps or a minimal proof of concept;
- affected browsers and operating systems; and
- a suggested remediation, if you have one.

Do not include real private keys, passphrases, room links, conversation contents, personal data, or credentials. Generate disposable test identities and rooms. Please do not open a public GitHub issue for an unpatched vulnerability that could expose users.

Receipt and remediation are handled on a best-effort basis; this project does not promise a particular response or disclosure timeline. Coordinate public disclosure first when practical.

## Supported versions

Only the current `main` branch is supported. Older commits, forks, modified deployments, and third-party hosted copies may not contain the latest fixes.

## Security boundaries

The intended properties are:

- private key generation, import, unlock, signing, and decryption happen in the browser; generated/imported OpenPGP identities are restricted to v4 Ed25519 signing plus X25519 encryption and 40-hex fingerprints, and every operational identity must also contain an exact ML-KEM-768 key pair;
- passphrase-protected identity material and message ciphertext are stored only in that browser's IndexedDB unless the user explicitly downloads an identity backup/export;
- chat packets travel over WebRTC data channels and are encrypted at the application layer;
- SDP and ICE signaling contents are AES-256-GCM encrypted before the Cloudflare Worker sees them;
- the Durable Object is an ephemeral rendezvous and does not call persistent storage APIs;
- the production bundle contains no intentional analytics or third-party runtime resources;
- every network request passes through the Worker so it can enforce HTTPS and security headers before the Static Assets binding serves application files; and
- a same-origin integrity Service Worker, stamped for each shell build and included in the manifest/build digest, verifies and pins the listed public application shell in a build-specific cache after its trust-on-first-use installation. It does not cache `/api` responses or user data, and a first installation forces a reload through the new controller.

These are not anonymity guarantees. Cloudflare sees normal infrastructure metadata, and direct peers can normally learn one another's public IP information. Cloudflare is also trusted on the first load and for integrity Service Worker updates. A malicious same-origin bundle or Service Worker can access browser plaintext; the pinned shell does not remove this web-delivery trust point.

The post-quantum layer is experimental defense in depth. It does not make the entire protocol post-quantum secure, and it does not provide post-quantum authentication. QuietWire has no classical-only or PQ downgrade mode: an invalid or incomplete combined OpenPGP/ML-KEM identity fails closed. See [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md).

Trust is local, directional, and non-transitive. A sender encrypts only to fingerprints that sender has independently verified. Signed room-scoped trust announcements report another participant's claim but never create local or inherited trust. A signed delivery manifest binds the envelope digest and exact recipient set; it authenticates the sender's selection, not delivery. An excluded peer can see a signed not-shared notice, while an included recipient who has not verified the sender can decrypt but sees the message marked red and untrusted.

## High-value report areas

Reports are especially useful when they demonstrate:

- private key, passphrase, room-secret, or plaintext transmission outside the intended peer channel;
- a bypass of message signature verification or fingerprint/key-change warnings;
- a way for Cloudflare signaling code to recover encrypted SDP/ICE contents without the room secret;
- cross-site scripting, CSP/Trusted Types bypass, or third-party script execution;
- persistent server-side storage of messages, keys, or signaling payloads;
- cryptographic nonce/key reuse, envelope substitution, downgrade, or recipient-confusion flaws;
- ML-KEM/OpenPGP key-binding failures that enable identity substitution;
- a delivery-manifest bypass that changes the envelope or recipient set without detection, grants trust transitively, or encrypts to a recipient the sender did not locally verify;
- an import/restore bypass that accepts a revoked, expired, invalid, v6, RSA, P-curve, or otherwise unsupported OpenPGP identity;
- a combined-profile downgrade that accepts a missing, malformed, or mismatched ML-KEM-768 key;
- unintended plaintext in logs, error reports, URLs, caches, or browser storage;
- integrity-manifest, Service Worker, pinned-cache, build-digest, or unknown-registration bypasses;
- secret or plaintext exposure through developer JSON, including the opt-in per-message raw encrypted transport panel;
- accidental ciphertext disclosure through a metadata panel that is meant to remain redacted (the nested raw transport panel intentionally shows ciphertext);
- an Origin, room/socket/client cap, signaling rate-limit, or local-ignore bypass with security impact beyond the documented limits;
- remote deletion outside the explicit local purge scope; or
- dependency/build compromise that changes security-relevant output.

The following are documented limitations rather than vulnerabilities by themselves:

- public IP exposure to direct WebRTC peers and the STUN provider;
- lack of TURN fallback, offline delivery, a Signal-style Double Ratchet, or remote message recall;
- Cloudflare access to IP, timing, size, derived room-ID, and temporary peer-ID metadata;
- room access by someone who possesses the full room link;
- disclosure of signed trust announcements and exact delivery recipient sets to other connected room peers;
- validly signed but locally untrusted plaintext that contains misleading, malicious, or unsafe instructions;
- lack of delivery/read receipts and the fact that a local send is not evidence of receipt;
- retention by another participant after local purge;
- room-local/session-local ignore, which is not a persistent or server-side block and does not revoke the room capability;
- local compromise by malware, a hostile extension, a malicious participant, or an unlocked device;
- browser/filesystem remnants after IndexedDB deletion;
- trust-on-first-use limitations of the same-origin integrity Service Worker; and
- denial of service against the public Worker or a shared room.

## If your identity may be compromised

1. Stop using the affected identity and device.
2. From a trusted device, create a new identity and back it up.
3. Use the saved OpenPGP revocation certificate where your contacts can verify it. QuietWire does not publish revocations to a keyserver for you.
4. Tell contacts through an already authenticated channel and compare the new full fingerprint.
5. Purge the old local identity and conversations only after preserving anything required for incident analysis.

Purging cannot delete data held by peers, browser synchronization systems, device backups, screenshots, or forensic storage remnants. Deleting the identity also deletes locally signed contacts, but it does not delete message ciphertext; use the separate full-purge action when that is the intended scope.

## Key-backup safety

- Back up the complete `.quietwire.json` identity file before depending on an identity. It is the one complete operational/recovery bundle: it contains both passphrase-protected OpenPGP private material and the separately protected exact ML-KEM-768 secret, plus public identity data and any generated revocation certificate.
- Treat `.private.asc` as OpenPGP recovery material, not a complete QuietWire backup or a classical-only operating mode. Only supported v4 Ed25519/X25519 identities can be imported; importing one creates a fresh required ML-KEM-768 key, requires verification of a new complete `.quietwire.json` backup before saving, and cannot recover older outer ML-KEM envelopes.
- Use a unique, high-entropy passphrase and store recovery material in an appropriate offline or encrypted location.
- Test the `.quietwire.json` restoration in a disposable, isolated browser profile; the application's check verifies both the OpenPGP fingerprint and ML-KEM public key.
- Never paste a private key, passphrase, or live room link into a GitHub issue or security report.
- A public key and its fingerprint are meant to be shared; a private key and passphrase are not.

There is no account recovery, escrow, or server copy. Lost OpenPGP/ML-KEM keys and forgotten passphrases are unrecoverable. Although the backup's secret fields are encrypted, the file enables offline passphrase guessing and remains sensitive.

## Deployment responsibility

Operators must keep dependencies and Wrangler current, protect their Cloudflare and GitHub accounts, disable Cloudflare Web Analytics/Browser Insights and Workers Logs, keep `assets.run_worker_first: true`, and verify the Worker's deployed CSP, integrity manifest, stamped Service Worker, build-specific cache, and bundle. They should also add suitable Cloudflare edge IP/rate controls for their threat and traffic model; the built-in room and per-socket bounds are not a complete denial-of-service defense. Follow [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md). A fork that adds telemetry, remote scripts, TURN credentials, persistence, or logging changes the threat model and must disclose that clearly.
