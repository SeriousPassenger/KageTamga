import { useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import QRCode from "qrcode";
import type { StoredIdentity, StoredMessage } from "../lib/db";
import {
  deleteMessage,
  getContact,
  listContactsForFingerprint,
  listMessages,
  purgeRoom,
  saveContact,
  saveMessage,
} from "../lib/db";
import { groupedFingerprint, type UnlockedIdentity } from "../lib/identity";
import type { Translator } from "../lib/i18n";
import { unwrapCiphertext, wrapCiphertext, type HybridEnvelope } from "../lib/hybrid-crypto";
import { decryptChat, encryptChat, type ChatPayload } from "../lib/message-crypto";
import {
  MeshNetwork,
  type BroadcastResult,
  type ConnectionRoute,
  type PeerConnectionState,
} from "../lib/mesh";
import { coalescePeerIdentities, isInactivePeer } from "../lib/peer-display";
import {
  normalizeFingerprint,
  PROTOCOL_VERSION,
  signIdentityAssertion,
  verifyIdentityAssertion,
  type SignedIdentityAssertion,
} from "../lib/protocol";
import { randomId } from "../lib/encoding";
import { roomLink } from "../lib/room";
import {
  signDeliveryManifest,
  signTrustAnnouncement,
  verifyDeliveryManifest,
  verifyTrustAnnouncement,
  type SignedDeliveryManifest,
  type SignedTrustAnnouncement,
} from "../lib/room-events";
import {
  createTrustedContact,
  decideContactTrust,
  normalizeContactName,
  verifyTrustedContact,
} from "../lib/trust";

type TrustState = "awaiting" | "unverified" | "verified" | "changed" | "invalid" | "ignored";

interface PeerView {
  peerId: string;
  route: ConnectionRoute;
  assertion?: SignedIdentityAssertion;
  trust: TrustState;
  error?: string;
}

interface VisibleMessage extends ChatPayload {
  mine: boolean;
  verified: boolean;
  locallyTrusted: boolean;
  withheld: boolean;
  deliveryVerified: boolean;
  debug: Record<string, unknown>;
  rawTransport: Record<string, unknown>;
}

interface ChatRoomProps {
  t: Translator;
  locale: string;
  identity: StoredIdentity;
  unlocked: UnlockedIdentity;
  roomSecret: string;
  iceServers: readonly RTCIceServer[];
  developerMode: boolean;
  onLeave(): void;
  onLockIdentity(): void;
}

export function ChatRoom({
  t,
  locale,
  identity,
  unlocked,
  roomSecret,
  iceServers,
  developerMode,
  onLeave,
  onLockIdentity,
}: ChatRoomProps) {
  const meshRef = useRef<MeshNetwork | null>(null);
  const roomIdRef = useRef("");
  const assertionRef = useRef<SignedIdentityAssertion | null>(null);
  const peersRef = useRef(new Map<string, PeerView>());
  const trustAnnouncementsRef = useRef(new Map<string, SignedTrustAnnouncement>());
  const trustNoncesRef = useRef(new Set<string>());
  const announcedSubjectsRef = useRef(new Set<string>());
  const ignoredFingerprintsRef = useRef(new Set<string>());
  const translatorRef = useRef(t);
  const [roomId, setRoomId] = useState("");
  const [peers, setPeers] = useState<PeerView[]>([]);
  const [messages, setMessages] = useState<VisibleMessage[]>([]);
  const [body, setBody] = useState("");
  const [error, setError] = useState<string>();
  const [copiedInvite, setCopiedInvite] = useState(false);
  const [manualInput, setManualInput] = useState("");
  const [manualOutput, setManualOutput] = useState("");
  const [manualOutputKind, setManualOutputKind] = useState<"offer" | "answer">("offer");
  const [manualBusy, setManualBusy] = useState(false);
  const [copiedConnectionCode, setCopiedConnectionCode] = useState(false);
  const [securityNotices, setSecurityNotices] = useState<Array<{
    id: string;
    message: string;
  }>>([]);
  const [verificationInputs, setVerificationInputs] = useState<Record<string, string>>({});
  const [comparisonChecks, setComparisonChecks] = useState<Record<string, boolean>>({});
  const [trustAnnouncements, setTrustAnnouncements] = useState<SignedTrustAnnouncement[]>([]);
  const invite = useMemo(() => roomLink(roomSecret), [roomSecret]);

  useEffect(() => {
    translatorRef.current = t;
  }, [t]);

  function updatePeer(peerId: string, update: Partial<PeerView>) {
    const previous = peersRef.current.get(peerId) ?? {
      peerId,
      route: "connecting" as const,
      trust: "awaiting" as const,
    };
    peersRef.current.set(peerId, { ...previous, ...update });
    setPeers([...peersRef.current.values()].sort((left, right) => left.peerId.localeCompare(right.peerId)));
  }

  function reconcileCurrentContact(contact: { name: string; fingerprint: string }) {
    for (const [peerId, current] of peersRef.current) {
      if (!current.assertion || current.trust === "ignored" || current.trust === "invalid") {
        continue;
      }
      const decision = current.assertion.pgpFingerprint === contact.fingerprint
        ? "verified"
        : decideContactTrust(
            current.assertion.displayName,
            current.assertion.pgpFingerprint,
            contact.name,
            contact.fingerprint,
          );
      if (decision === "unrelated") continue;
      peersRef.current.set(peerId, {
        ...current,
        trust: decision,
        error: undefined,
      });
    }
    setPeers(
      [...peersRef.current.values()].sort((left, right) =>
        left.peerId.localeCompare(right.peerId)),
    );
    setMessages((previous) => previous.map((message) => {
      if (message.mine) return message;
      const decision = message.senderFingerprint === contact.fingerprint
        ? "verified"
        : decideContactTrust(
            message.senderName,
            message.senderFingerprint,
            contact.name,
            contact.fingerprint,
          );
      return decision === "unrelated"
        ? message
        : { ...message, locallyTrusted: decision === "verified" };
    }));
  }

  async function hasLocalTrust(displayName: string, fingerprint: string): Promise<boolean> {
    const contact = await getContact(normalizeContactName(displayName));
    if (contact) {
      return contact.fingerprint === fingerprint &&
        await verifyTrustedContact(contact, identity.publicKeyArmored, identity.fingerprint);
    }
    return Boolean(await findTrustedContactForFingerprint(fingerprint));
  }

  async function findTrustedContactForFingerprint(fingerprint: string) {
    const contacts = await listContactsForFingerprint(fingerprint);
    for (const candidate of contacts) {
      if (await verifyTrustedContact(candidate, identity.publicKeyArmored, identity.fingerprint)) {
        return candidate;
      }
    }
    return undefined;
  }

  function recordTrustAnnouncement(announcement: SignedTrustAnnouncement) {
    const key = `${announcement.initiatorFingerprint}:${announcement.subjectFingerprint}`;
    const previous = trustAnnouncementsRef.current.get(key);
    if (previous && previous.issuedAt >= announcement.issuedAt) return;
    trustAnnouncementsRef.current.set(key, announcement);
    setTrustAnnouncements(
      [...trustAnnouncementsRef.current.values()].sort((left, right) =>
        left.issuedAt.localeCompare(right.issuedAt)),
    );
  }

  useEffect(() => {
    let active = true;
    let assertionRefreshTimer: number | undefined;
    const mesh = new MeshNetwork(roomSecret, {
      onData(peerId, payload) {
        void receivePeerData(peerId, payload);
      },
      onPeerState(state) {
        peerStateChanged(state);
      },
      onError() {
        if (active) setError(translatorRef.current("connectionFailed"));
      },
      async isPersistentFingerprintTrusted(assertion) {
        return hasLocalTrust(assertion.displayName, assertion.pgpFingerprint);
      },
      onSecurityEvent(event) {
        if (!active) return;
        const fingerprint = event.fingerprint
          ? groupedFingerprint(event.fingerprint)
          : translatorRef.current("unknown");
        const key = event.type === "untrusted-relay"
          ? "untrustedRelayDenied"
          : event.type === "untrusted-origin"
            ? "untrustedOriginDenied"
            : "invalidRelayDenied";
        const message = translatorRef.current(key, { fingerprint });
        setSecurityNotices((previous) => [
          ...previous.slice(-7),
          { id: `${Date.now()}:${event.peerId}:${event.type}`, message },
        ]);
        setError(message);
      },
    }, iceServers);
    meshRef.current = mesh;

    void mesh.connect().then(async (derivedRoomId) => {
      if (!active) return;
      roomIdRef.current = derivedRoomId;
      setRoomId(derivedRoomId);
      history.replaceState(
        null,
        "",
        `${location.pathname}${location.search}#room=${roomSecret}`,
      );
      const sessionNonce = randomId();
      const refreshAssertion = async () => {
        const assertion = await signIdentityAssertion({
          version: PROTOCOL_VERSION,
          peerId: mesh.peerId,
          roomId: derivedRoomId,
          displayName: identity.displayName,
          pgpFingerprint: identity.fingerprint,
          pgpPublicKey: identity.publicKeyArmored,
          kemAlgorithm: "ML-KEM-768",
          kemPublicKey: identity.hybridPublicKey,
          issuedAt: new Date().toISOString(),
          sessionNonce,
        }, unlocked.pgpPrivateKey);
        if (!active) return;
        assertionRef.current = assertion;
        await mesh.setLocalIdentity(assertion, unlocked.pgpPrivateKey);
        mesh.broadcast(assertion);
      };
      await refreshAssertion();
      assertionRefreshTimer = window.setInterval(() => {
        void refreshAssertion().catch(() => setError(translatorRef.current("operationFailed")));
      }, 7 * 60 * 1000);
      await loadHistory(derivedRoomId);
    }).catch(() => {
      if (active) setError(translatorRef.current("connectionFailed"));
    });

    function peerStateChanged(state: PeerConnectionState) {
      if (!active) return;
      updatePeer(state.peerId, { route: state.route });
      if (state.route === "connecting" || state.route === "direct" || state.route === "relay") {
        if (assertionRef.current) mesh.broadcast(assertionRef.current);
      }
    }

    async function receivePeerData(peerId: string, value: unknown) {
      if (!active || !roomIdRef.current || !value || typeof value !== "object") return;
      const kind = (value as { kind?: unknown }).kind;
      if (kind === "identity-assertion") {
        try {
          const assertion = await verifyIdentityAssertion(value, peerId, roomIdRef.current);
          const existingPeer = peersRef.current.get(peerId);
          await mesh.observePeerIdentity(peerId, assertion);
          if (ignoredFingerprintsRef.current.has(assertion.pgpFingerprint)) {
            mesh.ignorePeer(peerId);
            updatePeer(peerId, { assertion, route: "offline", trust: "ignored", error: undefined });
            return;
          }
          if (
            existingPeer?.assertion &&
            (existingPeer.assertion.sessionNonce !== assertion.sessionNonce ||
              existingPeer.assertion.pgpFingerprint !== assertion.pgpFingerprint ||
              existingPeer.assertion.pgpPublicKey !== assertion.pgpPublicKey ||
              existingPeer.assertion.kemPublicKey !== assertion.kemPublicKey ||
              existingPeer.assertion.displayName !== assertion.displayName)
          ) {
            throw new Error("A connected peer changed its signed identity.");
          }
          const contact = await getContact(normalizeContactName(assertion.displayName));
          let trust: TrustState;
          if (contact) {
            const authenticRecord = await verifyTrustedContact(
              contact,
              identity.publicKeyArmored,
              identity.fingerprint,
            );
            trust = !authenticRecord
              ? "invalid"
              : contact.fingerprint === assertion.pgpFingerprint
                ? "verified"
                : "changed";
          } else {
            trust = await findTrustedContactForFingerprint(assertion.pgpFingerprint)
              ? "verified"
              : "unverified";
          }
          updatePeer(peerId, { assertion, trust, error: undefined });
          if (!existingPeer?.assertion) {
            for (const trustedPeer of peersRef.current.values()) {
              if (trustedPeer.trust === "verified") {
                void broadcastTrustForPeer(trustedPeer, true);
              }
            }
          }
          if (trust === "verified") {
            void mesh.authorizePeer(peerId, assertion).catch(() => {
              setError(translatorRef.current("invalidRelayDenied", {
                fingerprint: groupedFingerprint(assertion.pgpFingerprint),
              }));
            });
            void broadcastTrustForPeer({ peerId, route: existingPeer?.route ?? "connecting", assertion, trust });
          }
        } catch {
          updatePeer(peerId, {
            trust: "invalid",
            error: translatorRef.current("invalidMessage"),
          });
        }
        return;
      }

      if (kind === "trust-announcement") {
        const peer = peersRef.current.get(peerId);
        if (!peer?.assertion || peer.trust === "ignored") return;
        try {
          const announcement = await verifyTrustAnnouncement(
            value,
            peer.assertion.pgpPublicKey,
            roomIdRef.current,
            peerId,
            peer.assertion.pgpFingerprint,
          );
          const nonceKey = `${announcement.initiatorFingerprint}:${announcement.nonce}`;
          if (trustNoncesRef.current.has(nonceKey)) return;
          trustNoncesRef.current.add(nonceKey);
          recordTrustAnnouncement(announcement);
        } catch {
          setError(translatorRef.current("invalidMessage"));
        }
        return;
      }

      if (kind === "hybrid-message") {
        const peer = peersRef.current.get(peerId);
        if (!peer?.assertion || peer.trust === "ignored") return;
        try {
          const packet = value as {
            kind?: unknown;
            envelope?: HybridEnvelope;
            delivery?: SignedDeliveryManifest;
          };
          const keys = Object.keys(value).sort();
          if (
            keys.length !== 3 ||
            keys[0] !== "delivery" ||
            keys[1] !== "envelope" ||
            keys[2] !== "kind" ||
            !packet.envelope ||
            !packet.delivery
          ) {
            throw new Error(translatorRef.current("invalidMessage"));
          }
          const envelope = packet.envelope;
          const delivery = await verifyDeliveryManifest(
            packet.delivery,
            envelope,
            peer.assertion.pgpPublicKey,
            roomIdRef.current,
            peerId,
            peer.assertion.pgpFingerprint,
          );
          if (
            delivery.senderName !== peer.assertion.displayName ||
            Math.abs(Date.parse(delivery.sentAt) - Date.now()) > 10 * 60 * 1000
          ) {
            throw new Error(translatorRef.current("invalidMessage"));
          }
          const stored: StoredMessage = {
            key: `${roomIdRef.current}:${delivery.senderFingerprint}:${delivery.messageId}`,
            roomId: roomIdRef.current,
            id: delivery.messageId,
            sentAt: delivery.sentAt,
            senderFingerprint: delivery.senderFingerprint,
            senderPublicKey: peer.assertion.pgpPublicKey,
            ciphertext: JSON.stringify(envelope),
            delivery,
          };
          await saveMessage(stored);
          const rawTransport = { kind: "hybrid-message", delivery, envelope };
          const locallyTrusted = peer.trust === "verified";
          if (!delivery.recipientFingerprints.includes(identity.fingerprint)) {
            appendMessage({
              version: 1,
              id: delivery.messageId,
              roomId: delivery.roomId,
              senderName: delivery.senderName,
              senderFingerprint: delivery.senderFingerprint,
              sentAt: delivery.sentAt,
              body: "",
              mine: false,
              verified: false,
              locallyTrusted,
              withheld: true,
              deliveryVerified: true,
              debug: envelopeDebug(envelope, delivery, "peer", peerId, null, locallyTrusted, true),
              rawTransport,
            });
            return;
          }
          const inner = await unwrapCiphertext(
            envelope,
            identity.fingerprint,
            unlocked.hybridSecretKey,
          );
          const decrypted = await decryptChat(
            inner,
            unlocked.pgpPrivateKey,
            peer.assertion.pgpPublicKey,
          );
          if (decrypted.signerFingerprint !== peer.assertion.pgpFingerprint) {
            throw new Error(translatorRef.current("signatureInvalid"));
          }
          validatePayload(decrypted.payload, envelope.messageId, {
            fingerprint: delivery.senderFingerprint,
            name: delivery.senderName,
            sentAt: delivery.sentAt,
          });
          if (!decrypted.verified) {
            throw new Error(translatorRef.current("signatureInvalid"));
          }
          appendMessage({
            ...decrypted.payload,
            mine: false,
            verified: true,
            locallyTrusted,
            withheld: false,
            deliveryVerified: true,
            debug: envelopeDebug(
              envelope,
              delivery,
              "peer",
              peerId,
              decrypted.payload.body.length,
              locallyTrusted,
              false,
            ),
            rawTransport,
          });
        } catch {
          setError(translatorRef.current("invalidMessage"));
        }
      }
    }

    async function loadHistory(derivedRoomId: string) {
      const storedMessages = await listMessages(derivedRoomId);
      const restored: VisibleMessage[] = [];
      for (const stored of storedMessages) {
        try {
          const envelope = JSON.parse(stored.ciphertext) as HybridEnvelope;
          const delivery = await verifyDeliveryManifest(
            stored.delivery,
            envelope,
            stored.senderPublicKey,
            derivedRoomId,
            stored.delivery.senderPeerId,
            stored.senderFingerprint,
          );
          if (
            delivery.messageId !== stored.id ||
            delivery.sentAt !== stored.sentAt ||
            delivery.senderFingerprint !== stored.senderFingerprint
          ) {
            continue;
          }
          const mine = delivery.senderFingerprint === identity.fingerprint;
          const locallyTrusted = mine || await hasLocalTrust(
            delivery.senderName,
            delivery.senderFingerprint,
          );
          const rawTransport = { kind: "hybrid-message", delivery, envelope };
          if (!delivery.recipientFingerprints.includes(identity.fingerprint)) {
            restored.push({
              version: 1,
              id: delivery.messageId,
              roomId: delivery.roomId,
              senderName: delivery.senderName,
              senderFingerprint: delivery.senderFingerprint,
              sentAt: delivery.sentAt,
              body: "",
              mine: false,
              verified: false,
              locallyTrusted,
              withheld: true,
              deliveryVerified: true,
              debug: envelopeDebug(envelope, delivery, "indexeddb", null, null, locallyTrusted, true),
              rawTransport,
            });
            continue;
          }
          const inner = await unwrapCiphertext(
            envelope,
            identity.fingerprint,
            unlocked.hybridSecretKey,
          );
          const decrypted = await decryptChat(
            inner,
            unlocked.pgpPrivateKey,
            stored.senderPublicKey,
          );
          validatePayload(decrypted.payload, envelope.messageId, {
            fingerprint: delivery.senderFingerprint,
            name: delivery.senderName,
            sentAt: delivery.sentAt,
          });
          if (
            decrypted.payload.roomId !== derivedRoomId ||
            decrypted.payload.id !== envelope.messageId ||
            decrypted.payload.senderFingerprint !== stored.senderFingerprint ||
            decrypted.signerFingerprint !== stored.senderFingerprint ||
            !decrypted.verified
          ) {
            continue;
          }
          restored.push({
            ...decrypted.payload,
            mine,
            verified: true,
            locallyTrusted,
            withheld: false,
            deliveryVerified: true,
            debug: envelopeDebug(
              envelope,
              delivery,
              "indexeddb",
              null,
              decrypted.payload.body.length,
              locallyTrusted,
              false,
            ),
            rawTransport,
          });
        } catch {
          // Corrupt or no-longer-decryptable local records are not rendered.
        }
      }
      if (active) setMessages(restored.sort((left, right) => left.sentAt.localeCompare(right.sentAt)));
    }

    return () => {
      active = false;
      if (assertionRefreshTimer !== undefined) window.clearInterval(assertionRefreshTimer);
      mesh.close();
      meshRef.current = null;
      peersRef.current.clear();
      trustAnnouncementsRef.current.clear();
      trustNoncesRef.current.clear();
      announcedSubjectsRef.current.clear();
      ignoredFingerprintsRef.current.clear();
    };
  }, [iceServers, identity, roomSecret, unlocked]);

  function appendMessage(message: VisibleMessage) {
    setMessages((previous) => {
      if (
        previous.some((entry) =>
          entry.id === message.id && entry.senderFingerprint === message.senderFingerprint)
      ) {
        return previous;
      }
      return [...previous, message].sort((left, right) => left.sentAt.localeCompare(right.sentAt));
    });
  }

  function validatePayload(
    payload: ChatPayload,
    envelopeMessageId: string,
    expected: { fingerprint: string; name: string; sentAt: string },
  ) {
    if (
      payload.version !== 1 ||
      payload.id !== envelopeMessageId ||
      payload.roomId !== roomIdRef.current ||
      payload.senderFingerprint !== expected.fingerprint ||
      payload.senderName !== expected.name ||
      payload.sentAt !== expected.sentAt ||
      !Number.isFinite(Date.parse(payload.sentAt)) ||
      payload.body.length < 1 ||
      payload.body.length > 4_000
    ) {
      throw new Error(translatorRef.current("invalidMessage"));
    }
  }

  const visiblePeers = useMemo(() => coalescePeerIdentities(peers), [peers]);
  const activePeers = visiblePeers.filter((peer) => !isInactivePeer(peer));
  const inactivePeers = visiblePeers.filter(isInactivePeer);
  const connectedPeers = visiblePeers.filter(
    (peer) =>
      peer.trust !== "ignored" &&
      (peer.route === "direct" || peer.route === "relay"),
  );
  const trustedRecipients = connectedPeers.filter(
    (peer): peer is PeerView & { assertion: SignedIdentityAssertion } =>
      peer.trust === "verified" && Boolean(peer.assertion),
  );
  const canSend = trustedRecipients.length > 0;

  function recipientSnapshotIsCurrent(
    selected: ReadonlyArray<PeerView & { assertion: SignedIdentityAssertion }>,
  ): boolean {
    const currentRecipients = coalescePeerIdentities([...peersRef.current.values()]).filter(
      (peer): peer is PeerView & { assertion: SignedIdentityAssertion } =>
        peer.trust === "verified" &&
        Boolean(peer.assertion) &&
        (peer.route === "direct" || peer.route === "relay"),
    );
    if (selected.length === 0 || selected.length !== currentRecipients.length) return false;
    const currentByFingerprint = new Map(
      currentRecipients.map((peer) => [peer.assertion.pgpFingerprint, peer]),
    );
    return selected.every((snapshot) => {
      const representative = currentByFingerprint.get(snapshot.assertion.pgpFingerprint);
      const current = peersRef.current.get(snapshot.peerId);
      const assertion = current?.assertion;
      return Boolean(
        representative?.peerId === snapshot.peerId &&
        current &&
        assertion &&
        current.trust === "verified" &&
        (current.route === "direct" || current.route === "relay") &&
        assertion.peerId === snapshot.assertion.peerId &&
        assertion.sessionNonce === snapshot.assertion.sessionNonce &&
        assertion.displayName === snapshot.assertion.displayName &&
        assertion.pgpFingerprint === snapshot.assertion.pgpFingerprint &&
        assertion.pgpPublicKey === snapshot.assertion.pgpPublicKey &&
        assertion.kemAlgorithm === "ML-KEM-768" &&
        assertion.kemPublicKey === snapshot.assertion.kemPublicKey
      );
    });
  }

  async function send(event: FormEvent) {
    event.preventDefault();
    const text = body.trim();
    const liveConnectedPeers = coalescePeerIdentities([...peersRef.current.values()]).filter(
      (peer) =>
        peer.trust !== "ignored" &&
        (peer.route === "direct" || peer.route === "relay"),
    );
    const liveTrustedRecipients = liveConnectedPeers.filter(
      (peer): peer is PeerView & { assertion: SignedIdentityAssertion } =>
        peer.trust === "verified" && Boolean(peer.assertion),
    );
    if (!text || text.length > 4_000 || liveTrustedRecipients.length === 0 || !roomId) {
      setError(liveConnectedPeers.length === 0 ? t("noPeers") : t("verifyPeerBeforeSending"));
      return;
    }
    setError(undefined);
    try {
      const peerAssertions = liveTrustedRecipients.map((peer) => peer.assertion);
      const seen = new Map<string, SignedIdentityAssertion>();
      for (const assertion of peerAssertions) {
        const previous = seen.get(assertion.pgpFingerprint);
        if (previous && previous.kemPublicKey !== assertion.kemPublicKey) {
          throw new Error(t("invalidMessage"));
        }
        seen.set(assertion.pgpFingerprint, assertion);
      }
      const id = randomId();
      const sentAt = new Date().toISOString();
      const payload: ChatPayload = {
        version: 1,
        id,
        roomId,
        senderName: identity.displayName,
        senderFingerprint: identity.fingerprint,
        sentAt,
        body: text,
      };
      const recipientAssertions = [...seen.values()];
      const inner = await encryptChat(payload, unlocked.pgpPrivateKey, [
        identity.publicKeyArmored,
        ...recipientAssertions.map((assertion) => assertion.pgpPublicKey),
      ]);
      const envelope = await wrapCiphertext(id, inner, [
        { fingerprint: identity.fingerprint, publicKey: identity.hybridPublicKey },
        ...recipientAssertions.map((assertion) => ({
          fingerprint: assertion.pgpFingerprint,
          publicKey: assertion.kemPublicKey,
        })),
      ]);
      const delivery = await signDeliveryManifest(
        {
          version: 1,
          roomId,
          senderPeerId: meshRef.current?.peerId ?? "",
          senderName: identity.displayName,
          senderFingerprint: identity.fingerprint,
          sentAt,
        },
        envelope,
        unlocked.pgpPrivateKey,
      );
      const stored: StoredMessage = {
        key: `${roomId}:${identity.fingerprint}:${id}`,
        roomId,
        id,
        sentAt: payload.sentAt,
        senderFingerprint: identity.fingerprint,
        senderPublicKey: identity.publicKeyArmored,
        ciphertext: JSON.stringify(envelope),
        delivery,
      };
      if (!recipientSnapshotIsCurrent(liveTrustedRecipients)) {
        throw new Error(translatorRef.current("verifyPeerBeforeSending"));
      }
      await saveMessage(stored);
      if (!recipientSnapshotIsCurrent(liveTrustedRecipients)) {
        await deleteMessage(stored.key);
        throw new Error(translatorRef.current("verifyPeerBeforeSending"));
      }
      const rawTransport = { kind: "hybrid-message", delivery, envelope };
      const outcome = meshRef.current?.broadcast(rawTransport) ?? {
        sent: [],
        unavailable: [],
        congested: [],
      };
      appendMessage({
        ...payload,
        mine: true,
        verified: true,
        locallyTrusted: true,
        withheld: false,
        deliveryVerified: true,
        debug: envelopeDebug(
          envelope,
          delivery,
          "local-send",
          meshRef.current?.peerId ?? null,
          text.length,
          true,
          false,
          outcome,
        ),
        rawTransport,
      });
      setBody("");
    } catch {
      setError(t("pqHandshakeFailed"));
    }
  }

  async function verifyPeer(peer: PeerView) {
    if (!peer.assertion || !comparisonChecks[peer.peerId]) return;
    if (normalizeFingerprint(verificationInputs[peer.peerId] ?? "") !== peer.assertion.pgpFingerprint) {
      setError(t("invalidMessage"));
      return;
    }
    setError(undefined);
    try {
      const contact = await createTrustedContact(
        normalizeContactName(peer.assertion.displayName),
        peer.assertion.pgpFingerprint,
        peer.assertion.pgpPublicKey,
        identity.fingerprint,
        unlocked.pgpPrivateKey,
      );
      await saveContact(contact);
      reconcileCurrentContact(contact);
      for (const reconciledPeer of peersRef.current.values()) {
        if (
          reconciledPeer.trust === "verified" &&
          reconciledPeer.assertion?.pgpFingerprint === contact.fingerprint
        ) {
          await meshRef.current?.authorizePeer(reconciledPeer.peerId, reconciledPeer.assertion);
          await broadcastTrustForPeer(reconciledPeer);
        }
      }
      setVerificationInputs((previous) => ({ ...previous, [peer.peerId]: "" }));
    } catch {
      setError(t("operationFailed"));
    }
  }

  async function broadcastTrustForPeer(peer: PeerView, rebroadcast = false) {
    if (
      !peer.assertion ||
      peer.assertion.pgpFingerprint === identity.fingerprint ||
      !roomIdRef.current ||
      !meshRef.current
    ) {
      return;
    }
    const announcementKey = `${peer.peerId}:${peer.assertion.pgpFingerprint}`;
    const existing = trustAnnouncementsRef.current.get(
      `${identity.fingerprint}:${peer.assertion.pgpFingerprint}`,
    );
    if (existing && Date.now() - Date.parse(existing.issuedAt) < 9 * 60 * 1000) {
      if (rebroadcast) meshRef.current.broadcast(existing);
      return;
    }
    if (!existing && announcedSubjectsRef.current.has(announcementKey)) return;
    if (existing) announcedSubjectsRef.current.delete(announcementKey);
    announcedSubjectsRef.current.add(announcementKey);
    try {
      const announcement = await signTrustAnnouncement(
        {
          version: 1,
          roomId: roomIdRef.current,
          initiatorPeerId: meshRef.current.peerId,
          initiatorFingerprint: identity.fingerprint,
          subjectFingerprint: peer.assertion.pgpFingerprint,
          issuedAt: new Date().toISOString(),
          nonce: randomId(),
          state: "trusted",
        },
        unlocked.pgpPrivateKey,
      );
      trustNoncesRef.current.add(`${announcement.initiatorFingerprint}:${announcement.nonce}`);
      recordTrustAnnouncement(announcement);
      meshRef.current.broadcast(announcement);
    } catch {
      announcedSubjectsRef.current.delete(announcementKey);
      setError(translatorRef.current("operationFailed"));
    }
  }

  function ignorePeer(peer: PeerView) {
    if (!confirm(t("ignorePeerConfirm"))) return;
    const fingerprint = peer.assertion?.pgpFingerprint;
    if (fingerprint) ignoredFingerprintsRef.current.add(fingerprint);
    const matchingPeerIds = [...peersRef.current.values()]
      .filter((candidate) =>
        candidate.peerId === peer.peerId ||
        Boolean(fingerprint && candidate.assertion?.pgpFingerprint === fingerprint),
      )
      .map((candidate) => candidate.peerId);
    for (const peerId of matchingPeerIds) {
      meshRef.current?.ignorePeer(peerId);
      const current = peersRef.current.get(peerId);
      if (current) {
        peersRef.current.set(peerId, {
          ...current,
          route: "offline",
          trust: "ignored",
          error: undefined,
        });
      }
    }
    setPeers(
      [...peersRef.current.values()].sort((left, right) => left.peerId.localeCompare(right.peerId)),
    );
    setError(undefined);
  }

  async function copyInvite() {
    await navigator.clipboard.writeText(invite);
    setCopiedInvite(true);
    window.setTimeout(() => setCopiedInvite(false), 1_500);
  }

  async function createConnectionOffer() {
    setManualBusy(true);
    setError(undefined);
    try {
      const code = await meshRef.current?.createManualOffer();
      if (!code) throw new Error("Mesh unavailable");
      setManualOutput(code);
      setManualOutputKind("offer");
    } catch {
      setError(t("connectionCodeFailed"));
    } finally {
      setManualBusy(false);
    }
  }

  async function processConnectionCode() {
    if (!manualInput.trim()) return;
    setManualBusy(true);
    setError(undefined);
    try {
      const result = await meshRef.current?.importManualSignal(manualInput);
      if (!result) throw new Error("Mesh unavailable");
      if (result.kind === "offer") {
        setManualOutput(result.answerCode);
        setManualOutputKind("answer");
      } else {
        setManualOutput("");
      }
      setManualInput("");
    } catch {
      setError(t("invalidConnectionCode"));
    } finally {
      setManualBusy(false);
    }
  }

  async function copyConnectionCode() {
    if (!manualOutput) return;
    await navigator.clipboard.writeText(manualOutput);
    setCopiedConnectionCode(true);
    window.setTimeout(() => setCopiedConnectionCode(false), 1_500);
  }

  async function purgeConversation() {
    if (!confirm(t("purgeConversationConfirm"))) return;
    await purgeRoom(roomId);
    setMessages([]);
  }

  function leave() {
    history.replaceState(null, "", `${location.pathname}${location.search}`);
    onLeave();
  }

  function nameForFingerprint(fingerprint: string): string {
    if (fingerprint === identity.fingerprint) return identity.displayName;
    return visiblePeers.find((peer) => peer.assertion?.pgpFingerprint === fingerprint)
      ?.assertion?.displayName ?? groupedFingerprint(fingerprint);
  }

  function renderPeerCard(peer: PeerView) {
    return (
      <PeerCard
        key={peer.peerId}
        peer={peer}
        t={t}
        input={verificationInputs[peer.peerId] ?? ""}
        compared={comparisonChecks[peer.peerId] ?? false}
        trustsYou={Boolean(
          peer.assertion && trustAnnouncements.some((announcement) =>
            announcement.initiatorFingerprint === peer.assertion?.pgpFingerprint &&
            announcement.subjectFingerprint === identity.fingerprint),
        )}
        onInput={(value) =>
          setVerificationInputs((previous) => ({ ...previous, [peer.peerId]: value }))
        }
        onCompared={(value) =>
          setComparisonChecks((previous) => ({ ...previous, [peer.peerId]: value }))
        }
        onVerify={() => void verifyPeer(peer)}
        onIgnore={() => ignorePeer(peer)}
      />
    );
  }

  return (
    <main className="chat-shell">
      <aside className="room-sidebar">
        <div>
          <div className="eyebrow">{t("chatTitle")}</div>
          <h1>{identity.displayName}</h1>
          <div className="signal-status online">
            <span />
            {t("manualMeshStatus")}
          </div>
        </div>

        <section className="invite-card">
          <h2>{t("inviteLink")}</h2>
          <p>{t("inviteWarning")}</p>
          <button className="button secondary" type="button" onClick={() => void copyInvite()}>
            {copiedInvite ? t("copied") : t("copyInvite")}
          </button>
        </section>

        <details className="manual-connect" open={connectedPeers.length === 0}>
          <summary>{t("manualConnectTitle")}</summary>
          <p>{t("manualConnectExplain")}</p>
          <div className="alert warning compact">{t("connectionCodeWarning")}</div>
          <button
            className="button secondary"
            type="button"
            disabled={manualBusy || !roomId}
            onClick={() => void createConnectionOffer()}
          >
            {manualBusy ? t("loading") : t("createConnectionOffer")}
          </button>
          <label>
            <span>{t("pasteConnectionCode")}</span>
            <textarea
              rows={5}
              spellCheck={false}
              autoComplete="off"
              value={manualInput}
              onChange={(event) => setManualInput(event.target.value)}
            />
          </label>
          <button
            className="button ghost"
            type="button"
            disabled={manualBusy || !manualInput.trim()}
            onClick={() => void processConnectionCode()}
          >
            {t("processConnectionCode")}
          </button>
          {manualOutput && (
            <div className="manual-output">
              <strong>{manualOutputKind === "offer" ? t("offerCodeReady") : t("answerCodeReady")}</strong>
              <textarea readOnly rows={5} value={manualOutput} />
              <button className="button secondary" type="button" onClick={() => void copyConnectionCode()}>
                {copiedConnectionCode ? t("copied") : t("copyConnectionCode")}
              </button>
            </div>
          )}
        </details>

        <section className="peer-list">
          <div className="section-heading">
            <h2>{t("peerCount", { count: connectedPeers.length })}</h2>
          </div>
          {visiblePeers.length === 0 && <p className="muted">{t("noPeers")}</p>}
          {activePeers.map(renderPeerCard)}
          {inactivePeers.length > 0 && (
            <details className="inactive-peer-list">
              <summary>{t("inactivePeers")} ({inactivePeers.length})</summary>
              <div className="inactive-peer-grid">
                {inactivePeers.map(renderPeerCard)}
              </div>
            </details>
          )}
        </section>

        {trustAnnouncements.length > 0 && (
          <details className="trust-announcements">
            <summary>{t("signedRoomTrustAnnouncements")} ({trustAnnouncements.length})</summary>
            <ul>
              {trustAnnouncements.map((announcement) => (
                <li key={`${announcement.initiatorFingerprint}:${announcement.subjectFingerprint}`}>
                  <span>{nameForFingerprint(announcement.initiatorFingerprint)}</span>
                  <span aria-hidden="true">→</span>
                  <span>{nameForFingerprint(announcement.subjectFingerprint)}</span>
                  <strong>✓</strong>
                </li>
              ))}
            </ul>
          </details>
        )}

        <div className="sidebar-actions stack">
          <button className="button ghost" type="button" onClick={leave}>{t("leaveRoom")}</button>
          <button className="text-button" type="button" onClick={onLockIdentity}>{t("lockIdentity")}</button>
        </div>
      </aside>

      <section className="conversation">
        <header className="conversation-header">
          <div>
            <span>{t("roomId")}</span>
            <code>{roomId ? `${roomId.slice(0, 10)}…${roomId.slice(-6)}` : t("loading")}</code>
          </div>
          <div className="protection-badge">
            <strong>{t("pqEnabled")}</strong>
            <span>{t("encryptedSigned")}</span>
          </div>
        </header>

        {securityNotices.length > 0 && (
          <section className="security-event-list" aria-live="assertive">
            {securityNotices.map((notice) => (
              <div className="alert danger" key={notice.id}>{notice.message}</div>
            ))}
          </section>
        )}

        {developerMode && (
          <details className="debug-panel room-debug">
            <summary>{t("debugRoom")} · {t("debugRedacted")}</summary>
            <pre>{JSON.stringify({
              roomId,
              roomSecret: "[REDACTED]",
              topology: "WebRTC full mesh",
              bootstrap: {
                mode: "manual encrypted offer/answer plus dual-signed trusted-peer introductions",
                applicationBackend: "none",
                centralizedRendezvous: false,
              },
              ice: {
                servers: iceServers.map((server) => server.urls),
                turnCredential: iceServers.some((server) => Boolean(server.credential))
                  ? "[REDACTED; MEMORY ONLY]"
                  : null,
              },
              localPeerId: meshRef.current?.peerId ?? null,
              peers: peers.map((peer) => ({
                peerId: peer.peerId,
                route: peer.route,
                trust: peer.trust,
                signedIdentityValid: Boolean(peer.assertion),
                displayName: peer.assertion?.displayName ?? null,
                pgpFingerprint: peer.assertion?.pgpFingerprint ?? null,
                kemAlgorithm: peer.assertion?.kemAlgorithm ?? null,
              })),
              directionalTrustAnnouncements: trustAnnouncements.map((announcement) => ({
                initiatorFingerprint: announcement.initiatorFingerprint,
                subjectFingerprint: announcement.subjectFingerprint,
                state: announcement.state,
                signatureVerifiedLocally: true,
                transitiveTrustGranted: false,
              })),
              localEncryptedMessages: messages.length,
            }, null, 2)}</pre>
          </details>
        )}

        <div className="message-list" aria-live="polite">
          {messages.length === 0 && <div className="empty-state">{t("emptyChat")}</div>}
          {messages.map((message) => (
            <article
              key={`${message.senderFingerprint}:${message.id}`}
              className={`message ${message.mine ? "mine" : "theirs"} ${
                !message.mine && !message.locallyTrusted ? "untrusted-message" : ""
              } ${message.withheld ? "withheld-message" : ""}`}
            >
              <header>
                <strong>{message.mine ? t("senderYou") : message.senderName}</strong>
                <time dateTime={message.sentAt}>
                  {new Intl.DateTimeFormat(locale, { dateStyle: "short", timeStyle: "short" }).format(
                    new Date(message.sentAt),
                  )}
                </time>
              </header>
              {message.withheld ? (
                <div className="message-trust-warning">{t("deliveryNotSharedBySender")}</div>
              ) : (
                <p>{message.body}</p>
              )}
              {!message.mine && !message.locallyTrusted && !message.withheld && (
                <div className="message-trust-warning">{t("untrustedSignedMessage")}</div>
              )}
              <footer>
                <span>✓ {message.withheld
                  ? t("deliveryManifestVerified")
                  : message.locallyTrusted || message.mine
                    ? t("signatureVerified")
                    : t("unknownSigner")}</span>
                <code>{groupedFingerprint(message.senderFingerprint)}</code>
                {message.mine && (
                  <span>{t("sentToTrustedRecipients", {
                    count: Number(message.debug.recipientCount ?? 1) - 1,
                  })}</span>
                )}
              </footer>
              {developerMode && (
                <details className="message-debug">
                  <summary>{t("debugMessage")}</summary>
                  <pre>{JSON.stringify(message.debug, null, 2)}</pre>
                  <RawTransportDebug t={t} value={message.rawTransport} />
                </details>
              )}
            </article>
          ))}
        </div>

        <form className="composer" onSubmit={(event) => void send(event)}>
          {error && <div className="alert danger">{error}</div>}
          {!canSend && connectedPeers.length > 0 && (
            <div className="alert warning">{t("verifyPeerBeforeSending")}</div>
          )}
          <div className="composer-row">
            <textarea
              rows={2}
              maxLength={4_000}
              placeholder={canSend ? t("messagePlaceholder") : t("verifyPeerBeforeSending")}
              disabled={!canSend}
              value={body}
              onChange={(event) => setBody(event.target.value)}
            />
            <button className="button primary" type="submit" disabled={!canSend || !body.trim()}>
              {t("send")}
            </button>
          </div>
          <div className="composer-meta">
            <span>{t("localHistory")}</span>
            <button className="text-button danger-text" type="button" onClick={() => void purgeConversation()}>
              {t("purgeConversation")}
            </button>
          </div>
        </form>
      </section>
    </main>
  );
}

function envelopeDebug(
  envelope: HybridEnvelope,
  delivery: SignedDeliveryManifest,
  source: "peer" | "indexeddb" | "local-send",
  transportPeerId: string | null,
  plaintextCharacters: number | null,
  locallyTrusted: boolean,
  withheld: boolean,
  broadcast?: BroadcastResult,
): Record<string, unknown> {
  return {
    version: envelope.version,
    messageId: envelope.messageId,
    source,
    transportPeerId,
    algorithm: envelope.algorithm,
    deliveryManifest: {
      senderFingerprint: delivery.senderFingerprint,
      envelopeDigest: delivery.envelopeDigest,
      signatureVerified: true,
    },
    freshRandomAes256ContentKeyPerMessage: true,
    contentCiphertextBytesApprox: Math.floor((envelope.content.ciphertext.length * 3) / 4),
    recipientCount: envelope.recipients.length,
    recipientFingerprints: envelope.recipients.map((entry) => entry.fingerprint),
    kemCiphertextBytesApprox: envelope.recipients.map((entry) =>
      Math.floor((entry.kemCiphertext.length * 3) / 4),
    ),
    plaintextCharacters,
    plaintext: "[REDACTED]",
    locallyTrusted,
    withheldFromThisIdentity: withheld,
    transportDelivery: broadcast ?? null,
    rawCiphertext: "available only in the nested opt-in encrypted transport panel",
    storedServerSide: false,
    storedLocallyAsCiphertext: true,
  };
}

function RawTransportDebug({ t, value }: { t: Translator; value: Record<string, unknown> }) {
  const [open, setOpen] = useState(false);
  return (
    <details
      className="raw-message-debug"
      onToggle={(event) => setOpen(event.currentTarget.open)}
    >
      <summary>{t("showRawTransportJson")}</summary>
      {open && <pre>{JSON.stringify(value, null, 2)}</pre>}
    </details>
  );
}

interface PeerCardProps {
  peer: PeerView;
  t: Translator;
  input: string;
  compared: boolean;
  trustsYou: boolean;
  onInput(value: string): void;
  onCompared(value: boolean): void;
  onVerify(): void;
  onIgnore(): void;
}

function PeerCard({
  peer,
  t,
  input,
  compared,
  trustsYou,
  onInput,
  onCompared,
  onVerify,
  onIgnore,
}: PeerCardProps) {
  const [qr, setQr] = useState<string>();
  useEffect(() => {
    if (!peer.assertion) return;
    void QRCode.toDataURL(`openpgp4fpr:${peer.assertion.pgpFingerprint}`, {
      width: 160,
      margin: 1,
      errorCorrectionLevel: "M",
      color: { dark: "#10231d", light: "#f5f0e6" },
    }).then(setQr);
  }, [peer.assertion]);

  return (
    <article className={`peer-card trust-${peer.trust}`}>
      <header>
        <strong>{peer.assertion?.displayName ?? t("unknown")}</strong>
        <span className={`route route-${peer.route}`}>
          {peer.route === "direct"
            ? t("statusDirect")
            : peer.route === "relay"
              ? t("statusRelay")
              : peer.route === "offline"
                ? t("statusOffline")
                : t("statusConnecting")}
        </span>
      </header>
      {peer.error && <div className="alert danger compact">{peer.error}</div>}
      {peer.trust === "ignored" && <div className="alert warning compact">{t("peerIgnored")}</div>}
      {peer.assertion && (
        <>
          {peer.trust === "changed" && (
            <div className="alert danger compact">
              <strong>{t("keyChangedTitle")}</strong> {t("keyChangedBody")}
            </div>
          )}
          <code className="peer-fingerprint">{groupedFingerprint(peer.assertion.pgpFingerprint)}</code>
          <div className={`remote-trust-line ${trustsYou ? "announced" : "not-announced"}`}>
            {trustsYou ? `✓ ${t("peerTrustsYourKey")}` : t("peerTrustNotAnnounced")}
          </div>
          {peer.trust === "verified" ? (
            <div className="verified-line">✓ {t("verified")}</div>
          ) : peer.trust !== "invalid" && peer.trust !== "ignored" ? (
            <details className="verify-peer" open={peer.trust === "changed"}>
              <summary>{t("compareFingerprint")}</summary>
              <p>{t("compareExplain")}</p>
              {qr && <img src={qr} alt="Peer OpenPGP fingerprint QR code" width="160" height="160" />}
              <label>
                <span>{t("fullFingerprint")}</span>
                <input
                  type="text"
                  autoComplete="off"
                  spellCheck={false}
                  value={input}
                  onChange={(event) => onInput(event.target.value)}
                />
              </label>
              <label className="checkbox-label">
                <input
                  type="checkbox"
                  checked={compared}
                  onChange={(event) => onCompared(event.target.checked)}
                />
                <span>{t("comparisonSteps")}</span>
              </label>
              <button
                className="button secondary"
                type="button"
                disabled={!compared || normalizeFingerprint(input).length !== 40}
                onClick={onVerify}
              >
                {t("verifyNow")}
              </button>
              <details>
                <summary>{t("showPublicKey")}</summary>
                <textarea readOnly rows={6} value={peer.assertion.pgpPublicKey} />
              </details>
            </details>
          ) : null}
        </>
      )}
      {peer.trust !== "ignored" && (
        <button className="text-button danger-text ignore-peer" type="button" onClick={onIgnore}>
          {t("ignorePeer")}
        </button>
      )}
    </article>
  );
}
