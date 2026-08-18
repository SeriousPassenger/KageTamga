# Cloudflare deployment and privacy hardening

QuietWire is packaged as Cloudflare Workers Static Assets, one Worker, and one SQLite-backed Durable Object class. `assets.run_worker_first` is globally `true`: every network request reaches the Worker first for HTTPS enforcement and security headers, then application files are served through the Static Assets binding. The Durable Object is used only for live WebSocket signaling, and the code does not use its persistent storage. There is no D1, KV, R2, Queue, external API, TURN credential, or application secret to provision.

This guide favors privacy over telemetry and convenience. Cloudflare dashboard names can change; when a label differs, search the dashboard for the named feature and verify the result from the browser.

## Prerequisites

- A Cloudflare account with Workers enabled. The project is designed to be usable on the Workers Free plan within its current limits; traffic and platform limits remain the operator's responsibility.
- Node.js 22 or newer and npm.
- A modern browser with Service Workers, Cache Storage, WebRTC data channels, WebCrypto, IndexedDB, and current JavaScript support.
- Optional: a domain active in the **same Cloudflare account** as the Worker.

## One-command application deploy

```bash
git clone https://github.com/SeriousPassenger/cloudflare-p2p-e2ee-chat.git
cd cloudflare-p2p-e2ee-chat
npm ci
npx wrangler login
npm run deploy
```

`npm run deploy` performs a TypeScript and Vite build, generates third-party notices, stamps the integrity Service Worker for that shell, generates the shell-integrity manifest/build digest including the stamped worker, runs the generated-bundle security scan, and calls `wrangler deploy`. On the first deploy, Wrangler applies the `v1` migration in `wrangler.jsonc` and creates the `SignalingRoom` Durable Object class.

No environment variables or secrets are required. The resulting `https://…workers.dev` address is a secure context and should work immediately.

If the Worker name already exists in your account, change only the top-level `name` in `wrangler.jsonc`. Do not casually rename `SignalingRoom` or edit an already-applied migration; Durable Object class migrations require an explicit new migration tag.

Check the deployment:

```bash
curl -fsS https://YOUR-WORKER.YOUR-SUBDOMAIN.workers.dev/api/health
```

The expected response includes `"ok":true`, `"storage":"none"`, and `"signaling":"ephemeral"`.

## Add a custom domain

Use the Worker's native custom-domain flow:

1. Open **Workers & Pages** and select the deployed Worker.
2. Open **Settings** → **Domains & Routes** (or the equivalent current domain/route panel).
3. Choose **Add** → **Custom domain**.
4. Enter a hostname from a zone in the same Cloudflare account and let Cloudflare create the DNS binding and certificate.

Do not manually CNAME the hostname to another account's `workers.dev` or `default-page.registrar.cloudflare.com` host. Cloudflare rejects many cross-account CNAME arrangements with Error 1014. A Worker custom domain or same-zone Worker route is the supported approach.

Because the Worker runs first globally, it returns an HTTPS redirect before serving an initial HTTP shell request. Still enable Cloudflare **Always Use HTTPS** or an equivalent zone Redirect Rule for the custom hostname as defense in depth and, where it runs before Workers, to avoid spending a Worker invocation on redirects. The application preflight also refuses a non-local insecure context. All Worker/static responses send HSTS. Do not publish an alternate HTTP-only origin. The HSTS value includes `includeSubDomains` and `preload`; use a dedicated chat hostname unless every hostname below the chosen name is permanently HTTPS-ready. The header alone does not submit a registrable domain to browser preload lists.

## Required Cloudflare privacy settings

Source configuration cannot control every zone/account feature. Apply this checklist to the production hostname.

### Disable browser telemetry and injection

- Turn **Browser Insights** off for the zone.
- Disable/remove the site from **Web Analytics**, and remove any manually installed analytics snippet.
- Keep **Zaraz** and Cloudflare Apps/integrations disabled unless their exact scripts and data flows have been reviewed and deliberately added to the threat model.
- Turn **Rocket Loader** off. It rewrites script loading and is unnecessary for this small application.
- Disable any feature, Transform Rule, Worker route, HTML rewriter, tag manager, font optimizer, or email-obfuscation feature that injects or rewrites page markup.

The response CSP permits scripts and network connections only from the same origin. That should block many accidental additions, but an injection attempt is still a deployment error. Do not rely on CSP as the only control.

A browser analytics product may be documented as collecting only performance data, but any JavaScript that actually executes in the document inherits that page's ability to observe DOM state and application memory. That makes “not intended to read keys” weaker than “no extra script is present.” QuietWire therefore removes and blocks such scripts instead of granting them trust.

### Disable Worker application logs

`wrangler.jsonc` contains:

```json
"observability": {
  "enabled": false
}
```

After deployment, open the Worker's **Observability** or **Logs** settings and confirm Workers Logs are disabled. Do not add `console.log` statements containing URLs, room IDs, peer IDs, signaling packets, keys, errors with cryptographic material, or message data.

Disabling Workers Logs does not mean Cloudflare has no records. Cloudflare can still process account, billing, abuse, firewall, request, network, and operational metadata under its platform policies. The goal is to avoid creating an application-level log or transcript.

### Do not add server storage

The only bindings should be `ASSETS` plus `SIGNALING_ROOMS`, and `assets.run_worker_first` should remain globally `true`. This guarantees the first-visit redirect and Worker security headers but means each network asset request invokes the Worker. The integrity Service Worker's verified, build-specific pinned cache minimizes later shell traffic after it controls the page. Do not add D1, KV, R2, Queues, Analytics Engine, Logpush, or a third-party monitoring destination without redesigning and disclosing the privacy model.

The Durable Object's SQLite-backed class type is required by current Cloudflare deployment mechanics, but QuietWire does not call `ctx.storage`. Its hibernatable WebSocket state exists only to route currently connected peers.

### Apply edge abuse controls

The source requires an exact same-origin WebSocket `Origin`, caps a room at eight signaling peers, limits each signaling socket to 200 messages per 10 seconds, and enforces client room/unique-peer caps. Keep those checks enabled. They do not stop distributed floods, IP rotation, repeated room creation, or all resource exhaustion. Configure suitable Cloudflare WAF/rate-limiting and IP abuse rules for the deployed hostname and expected traffic. Apply rules to `/api/signal/*` with care so legitimate WebSocket upgrades continue to work; test them with multiple disposable peers. Do not log signaling bodies as part of abuse inspection.

## Verify the deployed result

### 1. Verify the local bundle

```bash
npm ci
npm run check
```

The build hashes the non-Service-Worker HTML/JavaScript/CSS shell, stamps that shell digest into `dist/integrity-worker.js`, and then generates `dist/integrity-manifest.json`. The manifest contains SHA-256 digests of the stamped `/integrity-worker.js` and every other generated HTML/JavaScript/CSS asset; its `shellDigest` covers the non-worker shell and its `buildDigest` covers the complete canonical asset map including the stamped worker. The verifier independently reads and hashes every manifest-listed built file, recomputes both canonical digests, and checks the worker's embedded stamp. The build also fails if generated HTML, JavaScript, CSS, or JSON contains the configured Cloudflare RUM/common analytics markers. Generated HTML fails if a `<script src>` or `<link href>` points to an HTTP(S) or protocol-relative remote URL.

This is not a general static proof that code cannot construct a remote URL dynamically, and documentation/source links are not runtime script/style references. Runtime preflight and deployed Network inspection remain separate controls.

### 2. Verify headers at the edge

Check both an application path and an API path. Both pass through the Worker's authoritative header function before a static or API response is returned:

```bash
curl -sS -D - -o /dev/null https://chat.example.com/
curl -sS -D - -o /dev/null https://chat.example.com/api/health
```

Confirm both responses contain at least:

- `Content-Security-Policy` with `default-src 'self'`, `script-src 'self'`, `connect-src 'self'`, `worker-src 'self'`, `object-src 'none'`, `frame-ancestors 'none'`, and Trusted Types;
- `Cross-Origin-Opener-Policy: same-origin`;
- `Cross-Origin-Embedder-Policy: require-corp`;
- `Cross-Origin-Resource-Policy: same-origin`;
- `Permissions-Policy` disabling unused sensitive capabilities;
- `Referrer-Policy: no-referrer`;
- `X-Content-Type-Options: nosniff`;
- `Strict-Transport-Security`; and
- `Cache-Control: no-store, no-transform`.

Test the real custom hostname through Cloudflare, not only localhost. A different route or upstream Worker can change headers.

### 3. Verify there is no injected beacon

In browser developer tools:

1. Open **Network**, enable “Disable cache,” and reload.
2. Confirm every script, style, font, image, fetch, and WebSocket belongs to the application's own origin, except WebRTC's non-HTTP STUN traffic.
3. Search requests and page source for `beacon.min.js`, `cloudflareinsights.com`, `/cdn-cgi/rum`, analytics, and tag managers.
4. Inspect **Application** → **Service Workers**. Exactly one same-origin `/integrity-worker.js` registration with `/` scope is expected. Any other registration is a failure, and startup preflight should reject it.
5. On a clean profile, confirm the first installation automatically reloads once and that the next page runs under the `/integrity-worker.js` controller. A page that continues without Service Worker control is a failure.
6. Inspect Cache Storage. Exactly one current `quietwire-pinned-shell-<shell-digest>` cache should contain only `integrity-manifest.json` and the manifest-listed public HTML/JavaScript/CSS shell, including the stamped `/integrity-worker.js`—not `/api` responses, keys, contacts, or messages. Build updates use different cache names and activation removes older QuietWire build caches. There should be no analytics cookies/local-storage records.
7. Check the Console for CSP violations. Investigate them; do not weaken the CSP merely to silence an unexpected request.

The initial document, hashed Vite asset filenames, integrity manifest, and integrity worker are expected. Network requests for those files pass through the Worker unless satisfied by the controlling integrity Service Worker's local pinned cache. During a room session, the application opens a same-origin `wss://…/api/signal/…` WebSocket. Chat payloads should not appear as HTTP/fetch requests.

Run the first-visit injection check in a clean disposable browser profile. A previously installed integrity worker can legitimately serve its pinned shell instead of a newly altered edge response.

### 4. Compare the integrity build digest

Startup preflight installs/verifies the build-stamped integrity Service Worker and displays the complete SHA-256 build digest covering its pinned asset map, including `/integrity-worker.js`. Developer JSON also shows the digest, and the UI provides a console command that asks the active worker to recompute it from its pinned manifest/cache.

For the exact deployed commit:

1. open its successful GitHub Actions run;
2. read the `QuietWire build digest` value from the log or download the `quietwire-integrity-manifest` artifact;
3. compare every character with the value reported by the application through a separate trusted view; and
4. investigate any mismatch before creating or unlocking an identity.

This is a trust-on-first-use consistency check, not an origin-independent signature. Stamping and manifest coverage detect an inconsistent worker/build pair, and first install reloads through the controller, but the initial page executes before control exists and every worker/update response still comes from the same origin. A compromised GitHub/build chain also defeats the comparison.

### 5. Verify signaling is opaque

Using disposable test identities, connect two separate browser profiles. In the WebSocket inspector, application signaling frames should contain only routing/envelope fields such as a target peer ID, nonce, and ciphertext. SDP strings, ICE candidates, public keys, display names, and messages must not appear in plaintext in those frames.

Cloudflare still sees client IP addresses at the connection layer; encryption cannot hide them from the network provider.

### 6. Inspect developer JSON boundaries

Enable **Developer JSON** and inspect the application, room, peer, and individual-message metadata panels. Expected metadata includes build digest, secure-context capabilities, room/peer/message IDs, fingerprints, route/trust state, algorithms, recipient counts, and approximate ciphertext sizes. Those metadata panels must keep raw ciphertext redacted or absent.

Then explicitly expand one message's nested **raw encrypted transport JSON**. It is expected to contain the signed delivery manifest and exact encrypted hybrid envelope, including recipient fingerprints, ciphertext, signatures, nonces, salts, and ML-KEM encapsulations. It is opt-in, per-message, and should remain collapsed by default. Neither this raw view nor the metadata panels may contain a passphrase, private key, room secret, or message plaintext.

The panels are local and do not send this data, but displayed identifiers, exact recipient sets, signed trust state, and size/timing-adjacent values are still metadata; the raw view also discloses the encrypted packet itself. Do not publish screenshots or copies without reviewing them.

## Direct-only networking

This version uses Cloudflare STUN for ICE address discovery and sets `iceTransportPolicy: "all"`, but configures no TURN server. In practice:

- compatible NAT/firewall pairs connect directly;
- each peer can normally learn the other peer's public IP/network information;
- restrictive networks may fail to connect; and
- the UI should show the connection as direct, connecting, or offline. A relay status is reserved for a future explicitly configured TURN path.

Networks must allow the browser's WebRTC traffic and access to `stun.cloudflare.com` on the configured STUN ports. Do not advertise IP anonymity.

TURN is intentionally omitted from the out-of-box deployment. A public credential-minting endpoint can be abused, relay traffic changes the metadata/cost model, and adding a third party changes the threat model. A future relay feature should use short-lived credentials, explicit direct/auto/relay user choices, abuse controls, a clear provider disclosure, and tests that never expose long-lived TURN secrets to the client.

The in-room **ignore peer** action is also direct/local-only. It closes that tab's P2P connection and suppresses the asserted fingerprint for that room session, but it is not a persistent or server-side block, does not revoke the capability link, and does not stop the peer from connecting to others. Do not describe it as moderation infrastructure.

## Local development

Use the Wrangler-based development command so the Static Assets rules, API Worker, Durable Object, integrity manifest, and Service Worker are all present:

```bash
npm ci
npm run dev
```

The command builds first and then starts Wrangler. Running Vite alone is insufficient: the global Worker redirect/header path, `/api/health`, Durable Object signaling, and the integrity shell contract would not match production.

The exact `localhost` origin is considered a secure context by browsers, even if the local URL is HTTP. Testing on a LAN IP over plain HTTP is **not** equivalent; use an HTTPS tunnel you trust or a preview deployment.

For a realistic test:

1. use two browser profiles or two devices;
2. create disposable identities in each;
3. create a room in one profile and transfer the complete fragment link directly;
4. compare full fingerprints separately and verify only one direction at first;
5. confirm the verifying sender can send to that peer, while the included recipient can decrypt but sees the unverified sender's message in red;
6. add a third profile, confirm a sender encrypts only to that sender's locally verified recipients, and confirm an excluded peer sees an authenticated not-shared notice rather than plaintext;
7. inspect signed trust announcements and delivery recipient lists, and confirm an announcement never grants reverse or transitive local trust;
8. confirm the developer metadata panels remain redacted, then opt in to one nested raw encrypted transport view and confirm it contains ciphertext but no plaintext/secrets;
9. ignore a disposable peer, confirm its local P2P connection closes and later communication is suppressed in that room session, and do not mistake this for a server block;
10. locally lock signaling after the intended peers connect, confirm their existing chat continues, and confirm that the locked tab cannot accept a new peer;
11. restore a disposable `.quietwire.json` backup and confirm both OpenPGP and exact ML-KEM-768 identity values match; confirm a raw OpenPGP import creates a new required ML-KEM key rather than a classical-only mode; and
12. test conversation purge, identity deletion, and full local purge in both profiles. Identity deletion must remove locally signed contacts but leave ciphertext history; full purge must also remove the integrity cache and Service Worker.

## Updating and rollback

Before every deploy:

```bash
npm ci
npm run check
npm audit
```

Review changes to `package-lock.json`, cryptographic dependencies, `worker/index.ts`, `wrangler.jsonc`, `public/_headers`, `public/integrity-worker.js`, the manifest/build-verification scripts, backup/storage code, developer JSON allowlists, and protocol version labels. An automated audit result is only one signal; it is not a security review.

The checked-in CI workflow pins third-party GitHub Actions to full commit SHAs. Keep them pinned, review any SHA update against the intended upstream release, and do not replace the build verifier with a step that merely trusts or prints manifest-provided digests.

Use Cloudflare Worker Versions/Deployments to roll back a bad static/Worker release. Test Service Worker upgrade/rollback behavior in a disposable profile: every shell produces a differently stamped worker and build-specific cache, an installed worker may keep serving its pinned shell, and an update can remain waiting until all tabs close. Preflight should reject a waiting update, and activation should delete older QuietWire build caches. A rollback cannot undo plaintext already exposed by malicious client code and cannot delete copies held by peers. After a suspected code-delivery compromise, rotate the Cloudflare/GitHub credentials, investigate the build chain, publish a clean version, compare the new independent digest, and advise users to replace and re-verify identities when key exposure is plausible.
