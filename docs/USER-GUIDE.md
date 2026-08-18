# KageTamga user guide

KageTamga is a browser-only encrypted messenger for small groups. There is no account or recovery service. Read the warnings and create a verified encrypted backup before relying on an identity.

## 1. Startup security checks

The app remains locked until every check passes:

- expected application-path integrity Service Worker and pinned same-origin resources;
- HTTPS secure context and cross-origin isolation;
- browser CSPRNG and AES-256-GCM round trip;
- Ed25519/X25519 OpenPGP sign/encrypt/decrypt round trip;
- mandatory ML-KEM-768 encapsulation and content-key unwrap round trip;
- origin-scoped IndexedDB read/write;
- WebRTC data-channel APIs;
- backend-free manual-signaling encryption controls.

On first use, one automatic reload is expected. The first page cannot be retroactively authenticated by a Service Worker installed from that page, so KageTamga reloads once and then requires the exact expected controller. Repeated reloads or a failure after that single reload indicate a deployment, Service Worker, or browser-profile problem. Do not create or unlock an identity until it is fixed.

After preflight, expand the integrity section and compare either full SHA-256 encoding with the static card on a separately opened repository source page. The README contains a copyable console command that independently asks the controlling worker to reverify its pinned cache.

## 2. Create or import an identity

### Create

1. Choose a display name.
2. Enter a long unique passphrase of at least 12 characters; substantially longer is recommended.
3. Generate the identity. OpenPGP Ed25519/X25519 and ML-KEM-768 keys are created in the browser using browser cryptographic randomness.
4. Download the complete `.kagetamga.json` file.
5. Re-import that file immediately and enter its passphrase. Chat remains disabled until the backup fingerprint, ML-KEM public key, and trusted-contact payload exactly match.

Separate OpenPGP private/public armor and revocation certificate downloads are useful supplements. They are not a complete KageTamga recovery because they do not preserve the ML-KEM secret or trusted-fingerprint list.

### Import

You may import:

- a complete encrypted `.kagetamga.json` backup; or
- an existing compatible encrypted OpenPGP Curve25519 private key.

An individual OpenPGP import creates a fresh ML-KEM-768 pair. It cannot decrypt old KageTamga outer envelopes created for another ML-KEM key. Unsupported, RSA, mixed-algorithm, expired, revoked, public-only, malformed, or fingerprint-inconsistent keys are rejected.

## 3. Persistent trust before a room

The pre-room page always shows the persistent trusted-fingerprint list before room creation or joining.

To add a person in advance:

1. Obtain their complete armored public key through a channel you accept.
2. Ask them for the complete 40-hex OpenPGP fingerprint through an independent trusted channel.
3. Compare every group. Do not compare only the beginning or ending.
4. Enter a name, paste the full key and fingerprint, confirm the comparison, and add it.

KageTamga parses the key, enforces Ed25519/X25519 across every key packet, compares the fingerprint, and signs the contact record with your own identity. Only entries whose owner signature still verifies can authorize a relayer.

Removing trust immediately affects future sessions and future backups. It does not revoke the other person's key or erase messages already encrypted for them.

## 4. Configure ICE

Expand **ICE network settings** before entering a room.

- `stun:` or `stuns:` helps browsers discover usable network paths.
- `turn:` or `turns:` relays encrypted WebRTC packets when a direct path fails.
- Neither discovers participants or replaces the offer/answer exchange.

The initial public STUN endpoints are defaults, not endorsements or anonymity services. Every configured operator can see connection metadata. TURN also sees packet timing, sizes, endpoints, and volume. Replace them with operators you accept. TURN URLs require both username and credential. Leaving every URL empty limits the browser to locally gathered candidates and is mainly useful on the same LAN.

Custom endpoints and credentials remain only in that tab's memory. They are not stored in IndexedDB, exported in backups, or exposed in developer JSON.

## 5. Create or join a room

Creating a room generates a random 256-bit capability and places it after `#room=` in the invite URL. Share the complete URL privately. Normal HTTP requests omit the fragment, but browser history, clipboard tools, extensions, screenshots, and anyone receiving the URL can obtain it.

The room link lets a holder attempt connection and decrypt manual signaling codes. It does not prove a human identity and does not add a trusted fingerprint.

Opening an invite does not skip the pre-room trust/ICE screen. Review those settings and explicitly choose Join.

## 6. Connect the first two browsers

KageTamga has no signaling server.

1. One participant selects **Create signed offer code**.
2. Send the complete `KTG1…` code to the intended room partner through any existing channel.
3. The partner pastes it and selects **Verify and process code**.
4. The partner sends the generated signed answer code back.
5. The offer creator pastes and processes that answer in the same tab that created the offer.

The codes are encrypted with a key derived from the room capability, but a room-link holder can decrypt them. Their origin signatures bind the exact identity and SDP. They expire with signed freshness and in-tab pending exchange state. Do not edit, truncate, reuse, publish, or send them to unintended participants.

If the connection fails, check that both browsers use the same complete room link, codes were not altered, the offer tab remained open, clocks are reasonable, ICE configuration is valid, and the networks permit a compatible WebRTC route.

## 7. Verify a connected peer

A valid room signature proves that one key controls the current protocol session. It does not prove the person's real identity.

1. Expand the peer verification panel.
2. Compare the full 40-hex fingerprint through a different trusted channel.
3. Read it in groups and compare every character.
4. Type the complete fingerprint and confirm.

Verification creates a persistent owner-signed contact. It has two separate local effects:

- future chat messages may be encrypted for that fingerprint;
- that fingerprint may send signed introduction/setup relay statements to you.

It does not make the peer trust you. The app may broadcast a signed informational trust announcement, but no recipient automatically changes trust because of it.

## 8. Add more peers through the mesh

Any new browser can first connect manually to one participant. A persistently trusted connected peer may then tell other persistently trusted neighbors about that newcomer and relay exact targeted WebRTC setup objects.

Each accepted introduction requires:

- a valid newcomer signature on the newcomer identity or SDP;
- a valid fresh signature from the direct relayer that sent it over this data channel;
- the direct relayer's exact fingerprint already present in your persistent trusted list;
- the newcomer's/origin's exact fingerprint separately already present in your persistent trusted list;
- matching room, target, peer IDs, nonce, time, and hop limit;
- no replay or malformed/extra fields.

Even two valid signatures are not enough when either the direct relayer or introduced origin fingerprint is absent from your persistent list. KageTamga drops the statement and posts a red chat security event such as:

`Relay denied: fingerprint 1234 … CDEF is not in your persistent trusted-fingerprint list.`

The origin-denial event likewise prints the exact introduced fingerprint. A forwarding participant refuses and records an error when its chosen direct next hop or the embedded origin is not locally trusted. Invalid, unsigned, stale, replayed, or tampered statements produce a separate red invalid-relay error. The encrypted chat payload is never processed as control data after a setup denial.

A newcomer unknown to one participant is not connected to that participant through the mesh. It must connect manually for independent verification or be pre-added from a separately obtained complete public key. Trust never transfers through the relayer.

## 9. Peer list behavior

The UI groups transport sessions by verified fingerprint:

- the same fingerprint with a newer valid signed name appears once under the newest active name;
- an online session replaces an offline duplicate;
- different fingerprints with the same name remain separate and may trigger key-change warnings;
- unsigned sessions remain separate;
- offline and ignored peers are collapsed under **Offline and ignored peers**.

Ignoring a peer acts on every current session with the same fingerprint, closes local channels, and prevents this room component from sending to or receiving from it. Ignore is local; other participants remain connected. Reloading or leaving starts a new room session, while removing persistent trust must be done from the pre-room list.

## 10. Send and receive messages

Sending requires at least one connected locally verified recipient. KageTamga encrypts only for currently verified unique fingerprints. The same envelope can travel over channels visible to untrusted peers, but those peers do not receive a wrapped content key.

Message states:

- **Green/normal verified:** signature valid and sender fingerprint locally trusted.
- **Red untrusted:** signature valid and you were selected as recipient, but you have not trusted the sender fingerprint. Treat its text, links, and instructions as untrusted.
- **Withheld:** the signed envelope/manifest is visible, but the sender did not trust your key and did not wrap the content key for you.
- **Invalid/rejected:** malformed envelope, wrong algorithm, bad signature, recipient mismatch, bad manifest, replay conflict, or decrypt failure; plaintext is not shown.

“Encrypted for N locally trusted recipients” describes cryptographic recipient selection, not delivery. There is no offline queue and a data-channel send is not proof that another browser displayed or retained the message.

## 11. Back up at any time

After unlock, the header and pre-room trust panel both provide **Download complete KageTamga backup**. The filename is normalized from the display name as `name.kagetamga.json`.

The file contains:

- an outer format/version/export-time header;
- the passphrase-protected ML-KEM secret blob needed for restoration;
- one authenticated ciphertext containing the full stored OpenPGP identity, matching ML-KEM public data, revocation certificate, and all owner-signed persistent trusted contacts.

The inner ciphertext uses AES-256-GCM under an HKDF-SHA-512 key derived from the unlocked ML-KEM secret. Changing header or ciphertext fails authentication. Protect the file and use a strong unique passphrase: a thief can perform offline passphrase attempts against a stolen backup.

Verify a newly downloaded backup in a disposable profile or during the required creation flow. Never upload private backups to a person claiming to provide support.

## 12. Local history and purge

Encrypted message envelopes remain in this browser's IndexedDB until purge. Decrypted text is in page memory while displayed. Local records also contain limited unencrypted indexing/display metadata such as room ID, timestamps, sender fingerprint, and sender public key.

- **Purge this conversation** deletes local records for the current room.
- **Delete local identity** deletes the local identity and its signed contacts.
- **Purge all local data** deletes the app database, local/session storage, app caches, and Service Worker registrations where browser APIs permit.
- **Lock identity** leaves the room, removes its fragment, and best-effort wipes the in-memory ML-KEM secret.

Close other tabs if deletion is blocked. Purge cannot erase a peer's history, screenshots, exported files, backups, browser/OS remnants, or provider logs.

## 13. Developer mode

Anyone can enable **Developer JSON** from the header. It is split to avoid one huge dump:

- application panel: version, locale, runtime capabilities, integrity digests, redacted storage/privacy summary;
- room panel: derived room ID, topology, redacted ICE configuration, session peer IDs, routes, fingerprints, algorithm labels, and verified trust announcements;
- per-message panel: sender fingerprint, envelope metadata, recipient fingerprints, manifest status, trust state, and optional collapsed raw encrypted transport JSON.

Developer mode does not intentionally include passphrases, private keys, ML-KEM secret, room capability, TURN credential, or plaintext in JSON. Raw transport output is ciphertext but may reveal public keys, fingerprints, recipients, timing, sizes, and room metadata. Share it only with that disclosure in mind.

## 14. Language support

The app detects saved preference first, then browser language preferences, then English. Supported interfaces are English, German, Japanese, Turkish, Spanish, French, Simplified Chinese, and Traditional Chinese. Language changes do not recreate the mesh or clear an active room's ignored-fingerprint set.
