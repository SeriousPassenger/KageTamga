# KageTamga threat model

## Status and scope

KageTamga is an unaudited experimental messenger. This document describes intended properties of the current source, not a certification. The application targets small, simultaneously online groups using modern desktop browsers, a trusted HTTPS static deployment, independently compared full fingerprints, and uncompromised endpoints.

The design aims to:

- keep chat plaintext, private keys, passphrases, room capabilities, trusted-contact lists, and signaling plaintext out of any application backend by having no application backend;
- authenticate people through locally verified full OpenPGP fingerprints rather than names or room possession;
- encrypt each message to an independently selected recipient set with both OpenPGP Curve25519 and ML-KEM-768-based content-key wrapping;
- permit mesh expansion without central signaling while authenticating the newcomer and every direct relayer;
- reject setup unless both the direct sender and the embedded newcomer/origin fingerprint were persistently trusted independently by that receiver;
- retain encrypted history and owner-signed trust only in the user's browser until purge;
- ship every runtime dependency locally and detect an inconsistent pinned application shell.

It does not promise anonymity, traffic-flow secrecy, deniability, offline delivery, guaranteed availability, endpoint compromise resistance, application-layer forward secrecy, post-compromise security, or protection from malicious code accepted on first use.

## Assets

High-value assets are:

- OpenPGP private signing/decryption key;
- ML-KEM-768 secret key;
- private-key passphrase;
- decrypted backup payload;
- room capability in the URL fragment;
- message plaintext and decrypted history;
- persistent trusted-fingerprint decisions;
- contact public keys and owner signatures;
- manual offer/answer plaintext, including ICE candidates;
- configured TURN credentials;
- the integrity build digest as obtained through an independent path.

Public or intentionally peer-visible values include public keys, full fingerprints, display names, signed assertions, signed trust announcements, signed delivery manifests, ciphertext envelopes, room-derived opaque ID, temporary peer IDs, and message timing.

## Trust boundaries

### Static host and first delivery

The static host serves all executable code. A malicious host can replace the first HTML, JavaScript, manifest, and Service Worker consistently. CSP cannot stop intentional same-origin malicious code. The pinned Service Worker reduces accidental drift and some later resource substitution, but its own updates are also delivered by the host.

Users therefore trust the first delivered application until they compare the complete build digest through a separately trusted repository view. That comparison is evidence of consistency, not a proof that the source, build process, repository account, browser, or endpoint is safe.

### Browser and operating system

The browser supplies the CSPRNG, WebCrypto, IndexedDB, Service Worker, WebRTC, TLS validation, sandbox, and rendering engine. The operating system supplies entropy and protects the browser profile. A compromised browser, hostile extension, malware, injected accessibility/debug tooling, unlocked profile, swap/crash dump, or physical attacker can access plaintext and unlocked keys.

### Peers

Every participant receives ciphertext transport data and can retain everything visible to it. A verified peer can send malicious content, screenshot plaintext, export its own history, leak room links, share manual codes, or collude. Fingerprint verification authenticates a key, not good behavior.

### Independent comparison channel

Human identity rests on comparing all 40 hexadecimal fingerprint characters through a separate channel the user accepts, such as an in-person meeting or authenticated call. Comparing only a name, short suffix, avatar, room link, QR supplied by the same untrusted channel, or “valid signature” indicator is insufficient.

### ICE operators and network providers

Configured STUN operators can see client IP/address and timing metadata. TURN operators also relay packet traffic and observe endpoints, timing, sizes, and volume, though application payloads remain encrypted. Network providers and the static host see normal connection metadata. Direct WebRTC normally exposes network-address information to the other peer.

## Identity and algorithm enforcement

Accepted OpenPGP certificates must be v4 with 40-hex fingerprints, a supported Ed25519 primary/signing family, an X25519 encryption subkey, and no unsupported hidden subkeys. The validator checks revocation, expiration, primary key, selected keys, and all subkeys. Mixed RSA, NIST-curve, and unsupported certificates hard-fail.

Each room assertion must bind the exact OpenPGP certificate/fingerprint, exact ML-KEM-768 public key, display name, room ID, peer ID, fresh session nonce, and timestamp under an accepted Ed25519 signature. The ML-KEM public key is canonical Base64URL and exactly the FIPS 203 ML-KEM-768 public-key size. There is no downgrade path to missing ML-KEM, OpenPGP-only, another KEM, another curve, or an unrecognized algorithm label.

Names are not identifiers. The full fingerprint is. Multiple valid sessions for one fingerprint collapse in the UI; distinct fingerprints do not. A different fingerprint reusing a normalized trusted name becomes a key-change warning.

## Persistent trust

Trusted contact records are origin-scoped IndexedDB values signed by the local identity owner. A record binds version, normalized name, full fingerprint, complete public key, verification time, and owner fingerprint. The app verifies the contact public-key fingerprint and owner signature when loading or importing it.

Trust is:

- **directional:** Alice trusting Bob does not mean Bob trusts Alice;
- **local:** another participant's trust announcement does not change Alice's recipient set;
- **non-transitive:** Alice trusting Bob and Bob trusting Carol does not make Alice trust Carol;
- **persistent:** a new signed session using the same fingerprint is recognized after restart;
- **replaceable by explicit verification:** a changed fingerprint requires a new independent decision.

Signed room trust announcements are informational and auditable. They are room-, initiator-, subject-, state-, timestamp-, and nonce-bound. They never grant trust automatically.

## Room capability and manual signaling

The random 256-bit room capability is a bearer secret in the URL fragment. Normal HTTP requests omit the fragment, but copied URLs, browser history, screenshots, clipboard managers, extensions, crash reports, and shoulder surfing may expose it. Anyone with it can derive the opaque room ID and manual-signaling AES key.

Manual codes are AES-256-GCM encrypted under a room-derived key. The inner offer or answer has an independent origin signature binding exact SDP, origin and target, exchange, room, identity, time, and nonce. Code encryption hides SDP from a transport channel that lacks the room capability; it does not protect against another room-link holder.

Pending offer state is in tab memory. Answers must match an unused exchange ID. Code size, canonical encoding, freshness, room, target, and replay checks contain malformed and repeated input. Manual copy/paste does not guarantee delivery or prevent a recipient from forwarding the code.

## Dual-signed introductions and relay denial

Peer-assisted setup has two required signature levels:

1. the newcomer signs its identity and each exact targeted offer/answer;
2. the direct peer transmitting that object signs an outer mesh statement binding its relayer fingerprint and peer ID, final target, room, hop count, timestamp, nonce, and complete nested object.

Before verifying the nested payload, the receiver requires the data-channel peer's full fingerprint to be in its local persistent trust authorization. A valid pair of cryptographic signatures never overrides that requirement. If the relayer fingerprint is absent, ignored, or changed, the packet is dropped and the UI emits a red event with the denied fingerprint when its signed identity is known.

After signature verification, the receiver separately requires the newcomer/origin fingerprint embedded in the introduction or offer/answer to exist in its own persistent owner-signed trust list. A cryptographically valid but locally unknown origin is dropped with a red error naming that introduced fingerprint.

An intermediate peer applies the same rules to the peer it received from, the embedded origin, and the direct next hop it would use. Each hop creates a new outer signature. Unsigned, extra-field, malformed, stale, replayed, wrong-room, wrong-target, over-hop, fingerprint/key-mismatched, or invalid-signature packets are dropped.

These checks prevent an untrusted direct channel from becoming a signaling relay merely because it possesses valid newcomer data. They do not prevent a persistently trusted malicious relayer from withholding, delaying, duplicating before replay detection, or selectively routing valid introductions. A relayer cannot forge newcomer identity/SDP without the newcomer key, but it can lie socially about who the valid fingerprint belongs to. Independent comparison remains necessary.

Trust never transfers through the relayer: an introduction succeeds only if that receiver made its own earlier fingerprint decision. An unknown newcomer must connect manually for verification or be pre-added using a separately obtained full public key.

## Message confidentiality and authenticity

Every outgoing message selects only currently connected, locally verified fingerprint identities. Recipient state is snapshotted and rechecked after cryptographic work, before persistence, and immediately before the synchronous data-channel send. The snapshot binds session peer ID, nonce, display name, full fingerprint, complete OpenPGP public key, exact ML-KEM algorithm/public key, route, and trust state.

The inner OpenPGP message is signed with Ed25519 and encrypted with X25519 to the sender and selected recipients. A fresh random AES-256-GCM key encrypts the complete signed OpenPGP ciphertext. ML-KEM-768 plus salted HKDF-SHA-512 derives a separate wrapping key for each recipient, which AES-GCM wraps the content key under recipient/message/algorithm context. A delivery manifest signs the canonical outer-envelope hash and recipient set.

Security consequences:

- a peer not selected as a recipient sees the envelope and manifest but cannot recover the content key under the intended cryptography;
- a selected recipient can decrypt even if it has not locally trusted the valid sender, so the UI marks that plaintext red;
- changing a message, recipient set, content-key wrapper, sender, room, or ID invalidates cryptography or the manifest;
- a conflicting authenticated replay using the same sender fingerprint and message ID is rejected;
- compromise of a long-term recipient private key can expose stored ciphertext for that recipient; there is no ratchet-derived forward secrecy;
- the application-specific nested composition has not been independently analyzed as a formal hybrid encryption construction.

Cryptographic libraries are OpenPGP.js and the FIPS 203 ML-KEM implementation from `@noble/post-quantum`, bundled locally at locked versions. Browser `crypto.getRandomValues` supplies random message IDs, nonces, AES keys, IVs, room capabilities, and library entropy where requested.

## Metadata

### Static host can observe

- client and network addresses;
- requested public asset paths;
- timing, sizes, user-agent/TLS/network characteristics;
- operational, abuse, and availability signals retained by the host.

The intended static request path does not include room fragments, identities, public keys, manual codes, chat envelopes, or chat plaintext.

### Direct peers can observe

- network candidates/addresses exposed by WebRTC;
- display name, full fingerprint, OpenPGP public key, ML-KEM public key;
- room-derived ID and temporary peer/session data;
- encrypted message envelopes and signed manifests sent across their channels;
- timing, sizes, connection state, and trust announcements;
- plaintext for messages whose content keys they can recover.

### ICE operators can observe

- network endpoint and timing metadata for discovery;
- for TURN, relayed packet sizes, timing, duration, volume, and endpoints.

KageTamga does not attempt onion routing, cover traffic, padding to a fixed schedule, or IP anonymity.

## Browser storage and purge

IndexedDB is origin-scoped, so ordinary different subdomains and origins cannot read it under the browser same-origin policy. It is not “secure storage” against same-origin code or local profile access. Stored messages include ciphertext plus limited plaintext indexing/display metadata; “local encrypted history” does not mean every metadata field is encrypted.

Conversation purge removes this browser's room records. Identity purge removes local keys and owner-signed contacts. Full purge deletes the database, local/session storage, application caches, and Service Worker registrations when browser APIs allow. Other tabs may block deletion. No purge command can delete peer copies, screenshots, exported backups, browser/OS remnants, or network/provider logs.

Locking wipes the in-memory ML-KEM secret on a best-effort basis, leaves the room, and removes the room fragment. JavaScript and garbage-collected memory cannot guarantee forensic erasure.

## Backup threat model

The `.kagetamga.json` backup encrypts the complete identity and trusted-fingerprint list using AES-256-GCM under an HKDF-SHA-512 key derived from the unlocked ML-KEM secret. The outer file includes the passphrase-protected ML-KEM secret so the passphrase can restore the decryption key. Tampering with the header or ciphertext fails authentication.

The private-key passphrase is therefore the offline attack boundary for a stolen backup. Users need a long unique passphrase and must protect the file. A malicious already-unlocked page can export decrypted key material regardless of backup encryption. Restoring the complete file preserves ML-KEM history decryptability and persistent trust; importing individual OpenPGP armor alone generates a new ML-KEM identity and cannot recover old outer envelopes.

## Availability and abuse

There is no room-creation service to flood, but availability still depends on the static host, DNS, TLS, configured ICE services, browser limits, participant connectivity, and manual code delivery.

Client limits cap active peers, cumulative peer IDs, pending offers, message/control sizes, buffered bytes, hop count, nonce caches, and timeouts. Local Ignore closes all sessions sharing the fingerprint and prevents local send/receive for the rest of the room component lifetime. These bounds do not prevent distributed traffic against the static host or ICE service, malicious valid WebRTC packets, browser implementation bugs, CPU-heavy valid cryptography, or social flooding by peers with the room link.

Random room capabilities make blind room guessing impractical when browser randomness and secrecy hold. They are not a substitute for static-host availability controls or endpoint protection.

## Not protected

KageTamga cannot protect against:

- compromised source, build, hosting, browser, OS, or endpoint accepted before detection;
- a malicious verified participant reading or redistributing plaintext;
- weak/reused passphrases or stolen backups;
- incorrect human fingerprint comparison;
- IP/timing/size metadata exposure;
- traffic analysis or participant-count inference by direct peers/ICE operators;
- denial of service, packet withholding, selective forwarding, or offline recipients;
- screenshots, clipboard history, notifications, accessibility tools, or shoulder surfing;
- undiscovered cryptographic or implementation vulnerabilities;
- long-term-key compromise exposing retained recipient ciphertext;
- legal/operational metadata collection by infrastructure providers.

## Security invariants for changes

A release must fail if it weakens any of these without an explicit protocol version and documentation update:

- Ed25519/X25519-only certificate profile across all key packets;
- mandatory ML-KEM-768 assertion and envelope use;
- per-message random AES-256-GCM content key;
- recipient-specific KEM wrapping and signed delivery manifest;
- exact origin signature on every SDP;
- persistent local trust required for every direct relayer;
- persistent local trust required for every introduced/relayed origin fingerprint;
- red denied-fingerprint event for untrusted relay attempts;
- no automatic transitive trust;
- no application backend or runtime remote script;
- encrypted backup of the complete owner-signed trust list;
- mandatory pinned-shell and browser-capability preflight before unlock.
