import type { PrivateKey } from "openpgp";
import { fromBase64Url, randomId, toBase64Url } from "./encoding";
import {
  signMeshStatement,
  verifyMeshStatement,
  type MeshStatementPayload,
  type SignedMeshStatement,
} from "./mesh-statement";
import {
  signPeerSignal,
  verifyPeerSignal,
  type PeerSignalDescription,
  type SignedPeerSignal,
} from "./peer-signal";
import { verifyIdentityAssertion, type SignedIdentityAssertion } from "./protocol";
import { deriveRoomId, deriveSignalingKey } from "./room";
import { decryptSignal, encryptSignal } from "./signaling-crypto";

export type ConnectionRoute = "connecting" | "direct" | "relay" | "offline";

export interface PeerConnectionState {
  peerId: string;
  route: ConnectionRoute;
}

export interface MeshCallbacks {
  onData(peerId: string, payload: unknown): void;
  onPeerState(state: PeerConnectionState): void;
  onError(error: Error): void;
  onSecurityEvent(event: MeshSecurityEvent): void;
  isPersistentFingerprintTrusted(assertion: SignedIdentityAssertion): Promise<boolean>;
}

export interface MeshSecurityEvent {
  type: "untrusted-relay" | "untrusted-origin" | "invalid-relay";
  peerId: string;
  fingerprint: string | null;
}

export interface BroadcastResult {
  sent: string[];
  unavailable: string[];
  congested: string[];
}

export type ManualSignalImportResult =
  | { kind: "offer"; peerId: string; answerCode: string }
  | { kind: "answer"; peerId: string };

interface PeerLink {
  connection: RTCPeerConnection;
  channel?: RTCDataChannel;
  peerId?: string;
  exchangeId: string;
}

interface PendingOffer {
  link: PeerLink;
  timer: number;
}

const MANUAL_CODE_PREFIX = "KTG1";
const MANUAL_TARGET_PEER_ID = "________________________";
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/u;
const FINGERPRINT_PATTERN = /^[A-F0-9]{40}$/u;
const MAX_DATA_MESSAGE_CHARACTERS = 2 * 1024 * 1024;
const MAX_CONTROL_MESSAGE_CHARACTERS = 192 * 1024;
const MAX_BUFFERED_BYTES = 4 * 1024 * 1024;
const MAX_ROOM_PEERS = 8;
const MAX_UNIQUE_PEERS_PER_SESSION = 32;
const MAX_MANUAL_CODE_CHARACTERS = 192 * 1024;
const MAX_FORWARD_HOPS = 3;
const MAX_SEEN_SIGNAL_NONCES = 512;
const NEGOTIATION_TIMEOUT_MS = 60_000;
const MANUAL_OFFER_LIFETIME_MS = 10 * 60 * 1000;
const DISCONNECTED_GRACE_MS = 12_000;
const ICE_GATHERING_TIMEOUT_MS = 20_000;

export class MeshNetwork {
  readonly peerId = randomId();
  private readonly links = new Map<string, PeerLink>();
  private readonly pendingOffers = new Map<string, PendingOffer>();
  private readonly ignoredPeers = new Set<string>();
  private readonly observedIdentities = new Map<string, SignedIdentityAssertion>();
  private readonly authorizedIdentities = new Map<string, SignedIdentityAssertion>();
  private readonly seenPeerIds = new Set<string>();
  private readonly seenSignalNonces = new Set<string>();
  private readonly seenStatementNonces = new Set<string>();
  private readonly routes = new Map<string, string>();
  private readonly cleanupTimers = new Map<string, number>();
  private signalingKey?: CryptoKey;
  private roomId?: string;
  private localAssertion?: SignedIdentityAssertion;
  private localPrivateKey?: PrivateKey;
  private closed = false;

  constructor(
    private readonly roomSecret: string,
    private readonly callbacks: MeshCallbacks,
    private readonly iceServers: readonly RTCIceServer[],
  ) {}

  async connect(): Promise<string> {
    if (this.closed) throw new Error("The peer mesh is closed.");
    this.roomId = await deriveRoomId(this.roomSecret);
    this.signalingKey = await deriveSignalingKey(this.roomSecret);
    return this.roomId;
  }

  async setLocalIdentity(
    assertion: SignedIdentityAssertion,
    privateKey: PrivateKey,
  ): Promise<void> {
    this.assertReady();
    this.localAssertion = await verifyIdentityAssertion(assertion, this.peerId, this.roomId!);
    this.localPrivateKey = privateKey;
  }

  /**
   * Only a locally verified identity may introduce peers or relay setup data.
   * This transport authorization never grants message-recipient trust.
   */
  async authorizePeer(peerId: string, assertion: SignedIdentityAssertion): Promise<void> {
    if (!this.links.has(peerId) || this.ignoredPeers.has(peerId) || !this.roomId) return;
    const verified = await verifyIdentityAssertion(assertion, peerId, this.roomId);
    this.authorizedIdentities.set(peerId, verified);
    await this.sendStatementDirect(peerId, peerId, { type: "topology-request" });
    await this.shareAuthorizedTopology(peerId);
  }

  async observePeerIdentity(peerId: string, assertion: SignedIdentityAssertion): Promise<void> {
    if (!this.roomId || peerId !== assertion.peerId) return;
    this.observedIdentities.set(
      peerId,
      await verifyIdentityAssertion(assertion, peerId, this.roomId),
    );
  }

  async createManualOffer(): Promise<string> {
    this.assertIdentityReady();
    this.assertCapacity();
    if (this.pendingOffers.size >= MAX_ROOM_PEERS - 1) {
      throw new Error("Too many unanswered connection offers are pending.");
    }

    const exchangeId = randomId();
    const link = this.createLink(undefined, exchangeId);
    this.attachChannel(link, link.connection.createDataChannel("kagetamga-chat", { ordered: true }));
    try {
      const description = await this.createCompleteDescription(link.connection, "offer");
      const signal = await this.signLocalDescription(
        MANUAL_TARGET_PEER_ID,
        exchangeId,
        description,
      );
      const timer = window.setTimeout(() => {
        const pending = this.pendingOffers.get(exchangeId);
        if (!pending) return;
        this.pendingOffers.delete(exchangeId);
        this.closeLink(pending.link);
      }, MANUAL_OFFER_LIFETIME_MS);
      this.pendingOffers.set(exchangeId, { link, timer });
      return await this.protectManualSignal(signal);
    } catch (error) {
      this.closeLink(link);
      throw error;
    }
  }

  async importManualSignal(code: string): Promise<ManualSignalImportResult> {
    this.assertIdentityReady();
    const value = await this.unprotectManualSignal(code);
    const target = isPlainObject(value) && value.toPeerId === MANUAL_TARGET_PEER_ID
      ? MANUAL_TARGET_PEER_ID
      : this.peerId;
    const signal = await verifyPeerSignal(value, this.roomId!, target);
    this.rememberSignalNonce(signal);
    if (signal.description.type === "offer" && signal.toPeerId === MANUAL_TARGET_PEER_ID) {
      const answerCode = await this.acceptManualOffer(signal);
      return { kind: "offer", peerId: signal.fromPeerId, answerCode };
    }
    if (signal.description.type === "answer" && signal.toPeerId === this.peerId) {
      await this.acceptManualAnswer(signal);
      return { kind: "answer", peerId: signal.fromPeerId };
    }
    throw new Error("The manual connection code has an invalid direction.");
  }

  broadcast(payload: unknown): BroadcastResult {
    const encoded = JSON.stringify(payload);
    const result: BroadcastResult = { sent: [], unavailable: [], congested: [] };
    if (encoded.length > MAX_DATA_MESSAGE_CHARACTERS) {
      this.callbacks.onError(new Error("The encrypted message exceeds the peer transport limit."));
      return result;
    }
    for (const [peerId, link] of this.links) {
      if (this.ignoredPeers.has(peerId)) continue;
      if (link.channel?.readyState === "open") {
        if (link.channel.bufferedAmount > MAX_BUFFERED_BYTES) {
          this.callbacks.onError(new Error("A peer connection is congested; the message was not queued."));
          result.congested.push(peerId);
          continue;
        }
        link.channel.send(encoded);
        result.sent.push(peerId);
      } else {
        result.unavailable.push(peerId);
      }
    }
    return result;
  }

  connectedPeerIds(): string[] {
    return [...this.links.entries()]
      .filter(([, link]) => link.channel?.readyState === "open")
      .map(([peerId]) => peerId);
  }

  ignorePeer(peerId: string): void {
    this.ignoredPeers.add(peerId);
    this.authorizedIdentities.delete(peerId);
    this.removePeer(peerId, true);
  }

  close(): void {
    this.closed = true;
    for (const peerId of [...this.links.keys()]) this.removePeer(peerId, true);
    for (const pending of this.pendingOffers.values()) {
      window.clearTimeout(pending.timer);
      this.closeLink(pending.link);
    }
    this.pendingOffers.clear();
    for (const timer of this.cleanupTimers.values()) window.clearTimeout(timer);
    this.cleanupTimers.clear();
    this.routes.clear();
    this.authorizedIdentities.clear();
    this.observedIdentities.clear();
    this.localAssertion = undefined;
    this.localPrivateKey = undefined;
  }

  private async acceptManualOffer(signal: SignedPeerSignal): Promise<string> {
    this.assertCapacity();
    if (this.links.has(signal.fromPeerId) || this.ignoredPeers.has(signal.fromPeerId)) {
      throw new Error("That peer is already connected or locally ignored.");
    }
    this.rememberPeer(signal.fromPeerId);
    const link = this.createLink(signal.fromPeerId, signal.exchangeId);
    this.links.set(signal.fromPeerId, link);
    this.callbacks.onPeerState({ peerId: signal.fromPeerId, route: "connecting" });
    this.scheduleCleanup(signal.fromPeerId, NEGOTIATION_TIMEOUT_MS);
    try {
      await link.connection.setRemoteDescription(signal.description);
      const description = await this.createCompleteDescription(link.connection, "answer");
      const answer = await this.signLocalDescription(
        signal.fromPeerId,
        signal.exchangeId,
        description,
      );
      return await this.protectManualSignal(answer);
    } catch (error) {
      this.removePeer(signal.fromPeerId, true);
      throw error;
    }
  }

  private async acceptManualAnswer(signal: SignedPeerSignal): Promise<void> {
    if (this.links.has(signal.fromPeerId) || this.ignoredPeers.has(signal.fromPeerId)) {
      throw new Error("That peer is already connected or locally ignored.");
    }
    const pending = this.pendingOffers.get(signal.exchangeId);
    if (!pending) throw new Error("No matching unused connection offer exists in this tab.");
    this.assertCapacity();
    this.rememberPeer(signal.fromPeerId);
    window.clearTimeout(pending.timer);
    this.pendingOffers.delete(signal.exchangeId);
    pending.link.peerId = signal.fromPeerId;
    this.links.set(signal.fromPeerId, pending.link);
    this.callbacks.onPeerState({ peerId: signal.fromPeerId, route: "connecting" });
    this.scheduleCleanup(signal.fromPeerId, NEGOTIATION_TIMEOUT_MS);
    try {
      await pending.link.connection.setRemoteDescription(signal.description);
    } catch (error) {
      this.removePeer(signal.fromPeerId, true);
      throw error;
    }
  }

  private createLink(peerId: string | undefined, exchangeId: string): PeerLink {
    const connection = new RTCPeerConnection({
      iceServers: this.iceServers.map((server) => ({
        ...server,
        urls: Array.isArray(server.urls) ? [...server.urls] : server.urls,
      })),
      iceTransportPolicy: "all",
      bundlePolicy: "max-bundle",
    });
    const link: PeerLink = { connection, peerId, exchangeId };
    connection.ondatachannel = (event) => this.attachChannel(link, event.channel);
    connection.onconnectionstatechange = () => {
      if (!link.peerId) return;
      if (connection.connectionState === "connected") {
        this.clearCleanup(link.peerId);
        this.routes.delete(link.peerId);
        void this.detectRoute(link.peerId, connection);
      } else if (connection.connectionState === "disconnected") {
        this.callbacks.onPeerState({ peerId: link.peerId, route: "offline" });
        this.scheduleCleanup(link.peerId, DISCONNECTED_GRACE_MS);
      } else if (["failed", "closed"].includes(connection.connectionState)) {
        this.removePeer(link.peerId, true);
      }
    };
    return link;
  }

  private attachChannel(link: PeerLink, channel: RTCDataChannel): void {
    link.channel = channel;
    channel.onopen = () => {
      if (!link.peerId) return;
      this.callbacks.onPeerState({ peerId: link.peerId, route: "connecting" });
      void this.detectRoute(link.peerId, link.connection);
      if (this.authorizedIdentities.has(link.peerId)) {
        void this.shareAuthorizedTopology(link.peerId).catch((error: unknown) => {
          this.callbacks.onError(error instanceof Error ? error : new Error("Topology sharing failed."));
        });
      }
    };
    channel.onmessage = (event) => {
      if (!link.peerId) {
        channel.close();
        this.callbacks.onError(new Error("An unidentified peer channel sent data."));
        return;
      }
      try {
        const encoded = String(event.data);
        if (encoded.length > MAX_DATA_MESSAGE_CHARACTERS) {
          channel.close();
          throw new Error("A peer exceeded the encrypted message size limit.");
        }
        const value = JSON.parse(encoded) as unknown;
        if (isMeshProtocolValue(value)) {
          if (encoded.length > MAX_CONTROL_MESSAGE_CHARACTERS) {
            throw new Error("A peer exceeded the setup-control size limit.");
          }
          void this.handleStatement(link.peerId, value).catch(() => {
            this.callbacks.onSecurityEvent({
              type: "invalid-relay",
              peerId: link.peerId!,
              fingerprint: this.observedIdentities.get(link.peerId!)?.pgpFingerprint ??
                claimedRelayerFingerprint(value),
            });
          });
          return;
        }
        this.callbacks.onData(link.peerId, value);
      } catch {
        this.callbacks.onError(new Error("A peer sent an invalid message."));
      }
    };
    channel.onclose = () => {
      if (link.peerId) this.removePeer(link.peerId, true);
      else this.closeLink(link);
    };
    channel.onerror = () => this.callbacks.onError(new Error("A peer data channel failed."));
  }

  private async handleStatement(transportPeerId: string, value: unknown): Promise<void> {
    const relayer = this.authorizedIdentities.get(transportPeerId);
    if (!relayer || this.ignoredPeers.has(transportPeerId)) {
      this.reportUntrustedRelay(transportPeerId, claimedRelayerFingerprint(value) ?? undefined);
      return;
    }
    const statement = await verifyMeshStatement(
      value,
      relayer.pgpPublicKey,
      this.roomId!,
      transportPeerId,
      relayer.pgpFingerprint,
    );
    this.rememberStatementNonce(statement);

    const introducedIdentity = statement.payload.type === "introduction"
      ? statement.payload.identity
      : statement.payload.type === "relay-signal"
        ? statement.payload.signal.identity
        : undefined;
    if (introducedIdentity && !await this.isPersistentOriginTrusted(introducedIdentity)) {
      this.callbacks.onSecurityEvent({
        type: "untrusted-origin",
        peerId: introducedIdentity.peerId,
        fingerprint: introducedIdentity.pgpFingerprint,
      });
      return;
    }

    if (statement.payload.type === "topology-request") {
      if (statement.targetPeerId !== this.peerId) {
        throw new Error("A topology request targeted another peer.");
      }
      await this.sendRoster(transportPeerId);
      return;
    }
    if (statement.payload.type === "introduction") {
      if (statement.targetPeerId !== this.peerId) {
        throw new Error("A peer introduction targeted another peer.");
      }
      const assertion = statement.payload.identity;
      if (
        assertion.peerId === this.peerId ||
        this.ignoredPeers.has(assertion.peerId) ||
        this.links.get(assertion.peerId)?.channel?.readyState === "open"
      ) return;
      this.routes.set(assertion.peerId, transportPeerId);
      if (this.peerId < assertion.peerId && !this.links.has(assertion.peerId)) {
        await this.createPeerAssistedOffer(assertion.peerId);
      }
      return;
    }

    const signal = statement.payload.signal;
    if (signal.toPeerId !== statement.targetPeerId) {
      throw new Error("Relayed setup routing does not match its signed contents.");
    }
    this.rememberSignalNonce(signal);
    if (statement.targetPeerId === this.peerId) {
      this.routes.set(signal.fromPeerId, transportPeerId);
      await this.acceptPeerAssistedSignal(signal);
      return;
    }
    if (statement.hops >= MAX_FORWARD_HOPS) return;
    const nextHop = this.nextHopFor(statement.targetPeerId, transportPeerId);
    if (!nextHop) return;
    if (!this.authorizedIdentities.has(nextHop)) {
      this.reportUntrustedRelay(nextHop);
      return;
    }
    await this.sendStatementDirect(
      nextHop,
      statement.targetPeerId,
      { type: "relay-signal", signal },
      statement.hops + 1,
    );
  }

  private async createPeerAssistedOffer(peerId: string): Promise<void> {
    this.assertIdentityReady();
    this.assertCapacity();
    this.rememberPeer(peerId);
    const exchangeId = randomId();
    const link = this.createLink(peerId, exchangeId);
    this.links.set(peerId, link);
    this.callbacks.onPeerState({ peerId, route: "connecting" });
    this.scheduleCleanup(peerId, NEGOTIATION_TIMEOUT_MS);
    this.attachChannel(link, link.connection.createDataChannel("kagetamga-chat", { ordered: true }));
    try {
      const description = await this.createCompleteDescription(link.connection, "offer");
      const signal = await this.signLocalDescription(peerId, exchangeId, description);
      await this.sendRoutedSignal(signal);
    } catch (error) {
      this.removePeer(peerId, true);
      throw error;
    }
  }

  private async acceptPeerAssistedSignal(signal: SignedPeerSignal): Promise<void> {
    if (this.ignoredPeers.has(signal.fromPeerId)) return;
    if (signal.description.type === "offer") {
      if (this.links.has(signal.fromPeerId)) return;
      this.assertCapacity();
      this.rememberPeer(signal.fromPeerId);
      const link = this.createLink(signal.fromPeerId, signal.exchangeId);
      this.links.set(signal.fromPeerId, link);
      this.callbacks.onPeerState({ peerId: signal.fromPeerId, route: "connecting" });
      this.scheduleCleanup(signal.fromPeerId, NEGOTIATION_TIMEOUT_MS);
      try {
        await link.connection.setRemoteDescription(signal.description);
        const description = await this.createCompleteDescription(link.connection, "answer");
        await this.sendRoutedSignal(await this.signLocalDescription(
          signal.fromPeerId,
          signal.exchangeId,
          description,
        ));
      } catch (error) {
        this.removePeer(signal.fromPeerId, true);
        throw error;
      }
      return;
    }

    const link = this.links.get(signal.fromPeerId);
    if (!link || link.exchangeId !== signal.exchangeId) {
      throw new Error("The signed answer does not match a pending peer-assisted offer.");
    }
    await link.connection.setRemoteDescription(signal.description);
  }

  private async shareAuthorizedTopology(newPeerId: string): Promise<void> {
    await this.sendRoster(newPeerId);
    const newIdentity = this.authorizedIdentities.get(newPeerId);
    if (!newIdentity) return;
    for (const peerId of this.authorizedConnectedPeerIds()) {
      if (peerId === newPeerId) continue;
      await this.sendStatementDirect(peerId, peerId, {
        type: "introduction",
        identity: newIdentity,
      });
    }
  }

  private async sendRoster(to: string): Promise<void> {
    const identities = this.authorizedConnectedPeerIds()
      .filter((peerId) => peerId !== to)
      .map((peerId) => this.authorizedIdentities.get(peerId))
      .filter((assertion): assertion is SignedIdentityAssertion => Boolean(assertion));
    for (const introducedIdentity of identities) {
      await this.sendStatementDirect(to, to, {
        type: "introduction",
        identity: introducedIdentity,
      });
    }
  }

  private authorizedConnectedPeerIds(): string[] {
    return [...this.authorizedIdentities.keys()]
      .filter((peerId) => this.links.get(peerId)?.channel?.readyState === "open")
      .slice(0, MAX_ROOM_PEERS);
  }

  private async sendStatementDirect(
    peerId: string,
    targetPeerId: string,
    payload: MeshStatementPayload,
    hops = 0,
  ): Promise<void> {
    const channel = this.links.get(peerId)?.channel;
    if (channel?.readyState !== "open" || this.ignoredPeers.has(peerId)) return;
    if (!this.authorizedIdentities.has(peerId)) {
      this.reportUntrustedRelay(peerId);
      return;
    }
    this.assertIdentityReady();
    const statement = await signMeshStatement({
      version: 1,
      roomId: this.roomId!,
      relayerPeerId: this.peerId,
      relayerFingerprint: this.localAssertion!.pgpFingerprint,
      targetPeerId,
      hops,
      issuedAt: new Date().toISOString(),
      nonce: randomId(),
      payload,
    }, this.localPrivateKey!);
    const encoded = JSON.stringify(statement);
    if (encoded.length > MAX_CONTROL_MESSAGE_CHARACTERS || channel.bufferedAmount > MAX_BUFFERED_BYTES) {
      this.callbacks.onError(new Error("Peer-assisted setup could not be queued safely."));
      return;
    }
    channel.send(encoded);
  }

  private async sendRoutedSignal(signal: SignedPeerSignal): Promise<void> {
    const nextHop = this.nextHopFor(signal.toPeerId);
    if (!nextHop) {
      throw new Error("No locally trusted peer can relay this signed connection setup.");
    }
    if (!this.authorizedIdentities.has(nextHop)) {
      this.reportUntrustedRelay(nextHop);
      throw new Error("The available relayer fingerprint is not persistently trusted.");
    }
    await this.sendStatementDirect(nextHop, signal.toPeerId, {
      type: "relay-signal",
      signal,
    });
  }

  private nextHopFor(target: string, exclude?: string): string | undefined {
    const direct = this.links.get(target);
    if (target !== exclude && direct?.channel?.readyState === "open") return target;
    const routed = this.routes.get(target);
    if (routed && routed !== exclude && this.links.get(routed)?.channel?.readyState === "open") {
      return routed;
    }
    return undefined;
  }

  private async signLocalDescription(
    toPeerId: string,
    exchangeId: string,
    description: PeerSignalDescription,
  ): Promise<SignedPeerSignal> {
    this.assertIdentityReady();
    return signPeerSignal({
      version: 1,
      roomId: this.roomId!,
      fromPeerId: this.peerId,
      toPeerId,
      exchangeId,
      issuedAt: new Date().toISOString(),
      nonce: randomId(),
      description,
      identity: this.localAssertion!,
    }, this.localPrivateKey!);
  }

  private async protectManualSignal(signal: SignedPeerSignal): Promise<string> {
    const encrypted = await encryptSignal(this.signalingKey!, signal);
    return `${MANUAL_CODE_PREFIX}.${encrypted.iv}.${encrypted.ciphertext}`;
  }

  private async unprotectManualSignal(code: string): Promise<unknown> {
    const trimmed = code.trim();
    if (trimmed.length > MAX_MANUAL_CODE_CHARACTERS) throw new Error("The connection code is too large.");
    const parts = trimmed.split(".");
    const prefix = parts[0];
    const iv = parts[1];
    const ciphertext = parts[2];
    if (
      parts.length !== 3 ||
      prefix !== MANUAL_CODE_PREFIX ||
      !iv ||
      !ciphertext ||
      iv.length !== 16 ||
      ciphertext.length < 24 ||
      !BASE64URL_PATTERN.test(iv) ||
      !BASE64URL_PATTERN.test(ciphertext) ||
      !isCanonicalBase64Url(iv) ||
      !isCanonicalBase64Url(ciphertext)
    ) {
      throw new Error("The encrypted connection code is malformed.");
    }
    return decryptSignal<unknown>(this.signalingKey!, { iv, ciphertext });
  }

  private async createCompleteDescription(
    connection: RTCPeerConnection,
    type: "offer" | "answer",
  ): Promise<PeerSignalDescription> {
    const initial = type === "offer"
      ? await connection.createOffer()
      : await connection.createAnswer();
    await connection.setLocalDescription(initial);
    await this.waitForIceGathering(connection);
    const description = connection.localDescription;
    if (description?.type !== type || !description.sdp) {
      throw new Error("The browser produced an invalid WebRTC description.");
    }
    return { type, sdp: description.sdp };
  }

  private waitForIceGathering(connection: RTCPeerConnection): Promise<void> {
    if (connection.iceGatheringState === "complete") return Promise.resolve();
    return new Promise((resolve, reject) => {
      const changed = () => {
        if (connection.iceGatheringState !== "complete") return;
        window.clearTimeout(timeout);
        connection.removeEventListener("icegatheringstatechange", changed);
        resolve();
      };
      const timeout = window.setTimeout(() => {
        connection.removeEventListener("icegatheringstatechange", changed);
        reject(new Error("ICE candidate gathering timed out."));
      }, ICE_GATHERING_TIMEOUT_MS);
      connection.addEventListener("icegatheringstatechange", changed);
    });
  }

  private async detectRoute(peerId: string, connection: RTCPeerConnection): Promise<void> {
    const stats = await connection.getStats();
    let route: ConnectionRoute | undefined;
    for (const report of stats.values()) {
      const pair = report as RTCStats & {
        type: string;
        nominated?: boolean;
        state?: string;
        localCandidateId?: string;
        remoteCandidateId?: string;
      };
      if (pair.type !== "candidate-pair" || pair.state !== "succeeded" || !pair.nominated) continue;
      const local = pair.localCandidateId
        ? (stats.get(pair.localCandidateId) as (RTCStats & { candidateType?: string }) | undefined)
        : undefined;
      const remote = pair.remoteCandidateId
        ? (stats.get(pair.remoteCandidateId) as (RTCStats & { candidateType?: string }) | undefined)
        : undefined;
      route = local?.candidateType === "relay" || remote?.candidateType === "relay"
        ? "relay"
        : "direct";
      break;
    }
    if (route) this.callbacks.onPeerState({ peerId, route });
  }

  private rememberSignalNonce(signal: SignedPeerSignal): void {
    const key = `${signal.fromPeerId}:${signal.nonce}`;
    if (this.seenSignalNonces.has(key)) throw new Error("A signed setup packet was replayed.");
    this.seenSignalNonces.add(key);
    if (this.seenSignalNonces.size > MAX_SEEN_SIGNAL_NONCES) {
      const oldest = this.seenSignalNonces.values().next().value;
      if (oldest) this.seenSignalNonces.delete(oldest);
    }
  }

  private rememberStatementNonce(statement: SignedMeshStatement): void {
    const key = `${statement.relayerPeerId}:${statement.nonce}`;
    if (this.seenStatementNonces.has(key)) {
      throw new Error("A signed relayer statement was replayed.");
    }
    this.seenStatementNonces.add(key);
    if (this.seenStatementNonces.size > MAX_SEEN_SIGNAL_NONCES) {
      const oldest = this.seenStatementNonces.values().next().value;
      if (oldest) this.seenStatementNonces.delete(oldest);
    }
  }

  private rememberPeer(peerId: string): void {
    if (this.seenPeerIds.has(peerId)) return;
    if (this.seenPeerIds.size >= MAX_UNIQUE_PEERS_PER_SESSION) {
      this.ignoredPeers.add(peerId);
      throw new Error("This tab reached its unique-peer safety limit for the room.");
    }
    this.seenPeerIds.add(peerId);
  }

  private reportUntrustedRelay(peerId: string, claimedFingerprint?: string): void {
    this.callbacks.onSecurityEvent({
      type: "untrusted-relay",
      peerId,
      fingerprint: this.observedIdentities.get(peerId)?.pgpFingerprint ?? claimedFingerprint ?? null,
    });
  }

  private async isPersistentOriginTrusted(assertion: SignedIdentityAssertion): Promise<boolean> {
    try {
      return await this.callbacks.isPersistentFingerprintTrusted(assertion);
    } catch {
      return false;
    }
  }

  private scheduleCleanup(peerId: string, delayMs: number): void {
    this.clearCleanup(peerId);
    const timer = window.setTimeout(() => {
      const link = this.links.get(peerId);
      if (link && link.connection.connectionState !== "connected") this.removePeer(peerId, true);
    }, delayMs);
    this.cleanupTimers.set(peerId, timer);
  }

  private clearCleanup(peerId: string): void {
    const timer = this.cleanupTimers.get(peerId);
    if (timer !== undefined) window.clearTimeout(timer);
    this.cleanupTimers.delete(peerId);
  }

  private removePeer(peerId: string, notify: boolean): void {
    this.clearCleanup(peerId);
    const link = this.links.get(peerId);
    this.links.delete(peerId);
    this.authorizedIdentities.delete(peerId);
    this.observedIdentities.delete(peerId);
    this.routes.delete(peerId);
    for (const [target, nextHop] of this.routes) {
      if (nextHop === peerId) this.routes.delete(target);
    }
    if (link) this.closeLink(link);
    if (notify) this.callbacks.onPeerState({ peerId, route: "offline" });
  }

  private closeLink(link: PeerLink): void {
    if (link.channel) {
      link.channel.onclose = null;
      link.channel.onerror = null;
      link.channel.onmessage = null;
      link.channel.onopen = null;
    }
    link.connection.onconnectionstatechange = null;
    link.connection.ondatachannel = null;
    link.channel?.close();
    link.connection.close();
  }

  private assertReady(): void {
    if (this.closed || !this.roomId || !this.signalingKey) {
      throw new Error("The browser mesh is not ready.");
    }
  }

  private assertIdentityReady(): void {
    this.assertReady();
    if (!this.localAssertion || !this.localPrivateKey) {
      throw new Error("The signed room identity is not ready.");
    }
  }

  private assertCapacity(): void {
    if (this.links.size + this.pendingOffers.size >= MAX_ROOM_PEERS - 1) {
      throw new Error("The room peer limit has been reached in this tab.");
    }
  }
}

function isCanonicalBase64Url(value: string): boolean {
  try {
    return toBase64Url(fromBase64Url(value)) === value;
  } catch {
    return false;
  }
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function isMeshProtocolValue(value: unknown): boolean {
  if (!isPlainObject(value)) return false;
  return value.kind === "mesh-statement" || value.kind === "kagetamga-mesh-control";
}

function claimedRelayerFingerprint(value: unknown): string | null {
  return isPlainObject(value) &&
    typeof value.relayerFingerprint === "string" &&
    FINGERPRINT_PATTERN.test(value.relayerFingerprint)
    ? value.relayerFingerprint
    : null;
}
