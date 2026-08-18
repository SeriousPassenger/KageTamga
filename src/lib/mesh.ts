import { randomId } from "./encoding";
import { deriveRoomId, deriveSignalingKey } from "./room";
import { decryptSignal, encryptSignal, type EncryptedSignal } from "./signaling-crypto";

export type ConnectionRoute = "connecting" | "direct" | "relay" | "offline";

export interface PeerConnectionState {
  peerId: string;
  route: ConnectionRoute;
}

export interface MeshCallbacks {
  onData(peerId: string, payload: unknown): void;
  onPeerState(state: PeerConnectionState): void;
  onError(error: Error): void;
  onSignalState(connected: boolean): void;
}

export interface BroadcastResult {
  sent: string[];
  unavailable: string[];
  congested: string[];
}

type SignalPayload =
  | { kind: "description"; description: RTCSessionDescriptionInit }
  | { kind: "candidate"; candidate: RTCIceCandidateInit };

interface PeerLink {
  connection: RTCPeerConnection;
  channel?: RTCDataChannel;
  pendingCandidates: RTCIceCandidateInit[];
}

interface SignalMessage extends EncryptedSignal {
  type: "signal";
  from: string;
}

const ICE_SERVERS: RTCIceServer[] = [
  { urls: ["stun:stun.cloudflare.com:3478", "stun:stun.cloudflare.com:53"] },
];
const MAX_DATA_MESSAGE_CHARACTERS = 2 * 1024 * 1024;
const MAX_BUFFERED_BYTES = 4 * 1024 * 1024;
const MAX_ROOM_PEERS = 8;
const MAX_UNIQUE_PEERS_PER_SESSION = 32;
const NEGOTIATION_TIMEOUT_MS = 30_000;
const DISCONNECTED_GRACE_MS = 12_000;
const PEER_ID_PATTERN = /^[A-Za-z0-9_-]{24}$/u;

export class MeshNetwork {
  readonly peerId = randomId();
  private readonly links = new Map<string, PeerLink>();
  private readonly ignoredPeers = new Set<string>();
  private readonly seenPeerIds = new Set<string>();
  private readonly cleanupTimers = new Map<string, number>();
  private socket?: WebSocket;
  private signalingKey?: CryptoKey;
  private roomId?: string;
  private closed = false;
  private signalingLocked = false;

  constructor(
    private readonly roomSecret: string,
    private readonly callbacks: MeshCallbacks,
  ) {}

  async connect(): Promise<string> {
    this.roomId = await deriveRoomId(this.roomSecret);
    this.signalingKey = await deriveSignalingKey(this.roomSecret);
    this.openSocket();
    return this.roomId;
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

  lockSignaling(): void {
    this.signalingLocked = true;
    this.socket?.close(1000, "Room signaling locked");
    this.callbacks.onSignalState(false);
  }

  ignorePeer(peerId: string): void {
    this.ignoredPeers.add(peerId);
    this.removePeer(peerId, true);
  }

  close(): void {
    this.closed = true;
    this.signalingLocked = true;
    this.socket?.close(1000, "Leaving room");
    for (const peerId of [...this.links.keys()]) this.removePeer(peerId, true);
    for (const timer of this.cleanupTimers.values()) window.clearTimeout(timer);
    this.cleanupTimers.clear();
  }

  private openSocket(): void {
    if (this.closed || this.signalingLocked || !this.roomId) return;
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const socketUrl = new URL(`${protocol}//${window.location.host}/api/signal/${this.roomId}`);
    socketUrl.searchParams.set("peer", this.peerId);
    const socket = new WebSocket(socketUrl);
    this.socket = socket;

    socket.onopen = () => this.callbacks.onSignalState(true);
    socket.onclose = () => {
      this.callbacks.onSignalState(false);
      if (!this.closed && !this.signalingLocked) window.setTimeout(() => this.openSocket(), 1_500);
    };
    socket.onerror = () => this.callbacks.onError(new Error("The signaling connection failed."));
    socket.onmessage = (event) => {
      void this.handleSocketMessage(String(event.data)).catch((error: unknown) => {
        this.callbacks.onError(error instanceof Error ? error : new Error("Invalid signal"));
      });
    };
  }

  private async handleSocketMessage(encoded: string): Promise<void> {
    const message = JSON.parse(encoded) as
      | { type: "roster"; peerIds: string[] }
      | { type: "peer-joined" | "peer-left"; peerId: string }
      | SignalMessage;

    if (message.type === "roster") {
      if (
        !Array.isArray(message.peerIds) ||
        message.peerIds.length > MAX_ROOM_PEERS ||
        message.peerIds.some((peerId) => !PEER_ID_PATTERN.test(peerId))
      ) {
        throw new Error("The signaling roster was malformed.");
      }
      for (const peerId of message.peerIds) {
        if (!this.ignoredPeers.has(peerId) && this.peerId < peerId) {
          await this.ensurePeer(peerId, true);
        }
      }
      return;
    }
    if (message.type === "peer-joined") {
      if (!PEER_ID_PATTERN.test(message.peerId)) throw new Error("Invalid peer identifier.");
      if (!this.ignoredPeers.has(message.peerId) && this.peerId < message.peerId) {
        await this.ensurePeer(message.peerId, true);
      }
      return;
    }
    if (message.type === "peer-left") {
      if (!PEER_ID_PATTERN.test(message.peerId)) throw new Error("Invalid peer identifier.");
      // A signaling socket may be intentionally closed after WebRTC is established.
      // The data channel's own state is authoritative for peer departure.
      const link = this.links.get(message.peerId);
      if (link && link.channel?.readyState !== "open") this.removePeer(message.peerId, true);
      return;
    }
    if (message.type === "signal" && this.signalingKey) {
      if (!PEER_ID_PATTERN.test(message.from) || this.ignoredPeers.has(message.from)) return;
      const payload = await decryptSignal<SignalPayload>(this.signalingKey, message);
      if (!isSignalPayload(payload)) throw new Error("The decrypted signaling payload was malformed.");
      await this.handleSignal(message.from, payload);
      return;
    }
    throw new Error("Unknown signaling message.");
  }

  private async ensurePeer(peerId: string, initiator: boolean): Promise<PeerLink> {
    if (!PEER_ID_PATTERN.test(peerId) || peerId === this.peerId || this.ignoredPeers.has(peerId)) {
      throw new Error("Invalid or ignored peer identifier.");
    }
    const existing = this.links.get(peerId);
    if (existing) {
      if (!["failed", "closed"].includes(existing.connection.connectionState)) return existing;
      this.removePeer(peerId, false);
    }
    if (!this.seenPeerIds.has(peerId)) {
      if (this.seenPeerIds.size >= MAX_UNIQUE_PEERS_PER_SESSION) {
        this.ignoredPeers.add(peerId);
        throw new Error("This tab reached its unique-peer safety limit for the room.");
      }
      this.seenPeerIds.add(peerId);
    }

    const connection = new RTCPeerConnection({
      iceServers: ICE_SERVERS,
      iceTransportPolicy: "all",
      bundlePolicy: "max-bundle",
    });
    const link: PeerLink = { connection, pendingCandidates: [] };
    this.links.set(peerId, link);
    this.callbacks.onPeerState({ peerId, route: "connecting" });
    this.scheduleCleanup(peerId, NEGOTIATION_TIMEOUT_MS);

    connection.onicecandidate = (event) => {
      if (event.candidate) {
        void this.sendSignal(peerId, { kind: "candidate", candidate: event.candidate.toJSON() })
          .catch((error: unknown) => {
            if (!this.signalingLocked && !this.closed) {
              this.callbacks.onError(error instanceof Error ? error : new Error("Signaling failed."));
            }
          });
      }
    };
    connection.ondatachannel = (event) => this.attachChannel(peerId, link, event.channel);
    connection.onconnectionstatechange = () => {
      if (connection.connectionState === "connected") {
        this.clearCleanup(peerId);
        void this.detectRoute(peerId, connection);
      } else if (connection.connectionState === "disconnected") {
        this.callbacks.onPeerState({ peerId, route: "offline" });
        this.scheduleCleanup(peerId, DISCONNECTED_GRACE_MS);
      } else if (["failed", "closed"].includes(connection.connectionState)) {
        this.removePeer(peerId, true);
      }
    };

    if (initiator) {
      this.attachChannel(peerId, link, connection.createDataChannel("quietwire-chat", {
        ordered: true,
      }));
      const offer = await connection.createOffer();
      await connection.setLocalDescription(offer);
      await this.sendSignal(peerId, { kind: "description", description: offer });
    }
    return link;
  }

  private attachChannel(peerId: string, link: PeerLink, channel: RTCDataChannel): void {
    link.channel = channel;
    channel.onopen = () => {
      this.callbacks.onPeerState({ peerId, route: "connecting" });
      void this.detectRoute(peerId, link.connection);
    };
    channel.onmessage = (event) => {
      try {
        const encoded = String(event.data);
        if (encoded.length > MAX_DATA_MESSAGE_CHARACTERS) {
          channel.close();
          throw new Error("A peer exceeded the encrypted message size limit.");
        }
        this.callbacks.onData(peerId, JSON.parse(encoded) as unknown);
      } catch {
        this.callbacks.onError(new Error("A peer sent an invalid message."));
      }
    };
    channel.onclose = () => this.removePeer(peerId, true);
    channel.onerror = () => this.callbacks.onError(new Error("A peer data channel failed."));
  }

  private async handleSignal(peerId: string, signal: SignalPayload): Promise<void> {
    if (this.ignoredPeers.has(peerId)) return;
    const link = await this.ensurePeer(peerId, false);
    if (signal.kind === "description") {
      await link.connection.setRemoteDescription(signal.description);
      for (const candidate of link.pendingCandidates.splice(0)) {
        await link.connection.addIceCandidate(candidate);
      }
      if (signal.description.type === "offer") {
        const answer = await link.connection.createAnswer();
        await link.connection.setLocalDescription(answer);
        await this.sendSignal(peerId, { kind: "description", description: answer });
      }
      return;
    }

    if (link.connection.remoteDescription) {
      await link.connection.addIceCandidate(signal.candidate);
    } else {
      link.pendingCandidates.push(signal.candidate);
    }
  }

  private async sendSignal(to: string, payload: SignalPayload): Promise<void> {
    if (this.ignoredPeers.has(to)) return;
    if (!this.signalingKey) throw new Error("Signaling is not ready");
    const encrypted = await encryptSignal(this.signalingKey, payload);
    const encoded = JSON.stringify({ to, ...encrypted });
    if (this.socket?.readyState === WebSocket.OPEN) {
      this.socket.send(encoded);
    } else {
      throw new Error("Signaling is offline");
    }
  }

  private async detectRoute(peerId: string, connection: RTCPeerConnection): Promise<void> {
    const stats = await connection.getStats();
    let route: ConnectionRoute | undefined;
    for (const report of stats.values()) {
      const candidatePair = report as RTCStats & {
        type: string;
        nominated?: boolean;
        state?: string;
        localCandidateId?: string;
        remoteCandidateId?: string;
      };
      if (
        candidatePair.type !== "candidate-pair" ||
        candidatePair.state !== "succeeded" ||
        !candidatePair.nominated
      ) {
        continue;
      }
      const local = candidatePair.localCandidateId
        ? (stats.get(candidatePair.localCandidateId) as (RTCStats & { candidateType?: string }) | undefined)
        : undefined;
      const remote = candidatePair.remoteCandidateId
        ? (stats.get(candidatePair.remoteCandidateId) as (RTCStats & { candidateType?: string }) | undefined)
        : undefined;
      route = local?.candidateType === "relay" || remote?.candidateType === "relay"
        ? "relay"
        : "direct";
      break;
    }
    if (route) this.callbacks.onPeerState({ peerId, route });
  }

  private scheduleCleanup(peerId: string, delayMs: number): void {
    this.clearCleanup(peerId);
    const timer = window.setTimeout(() => {
      const link = this.links.get(peerId);
      if (link && link.connection.connectionState !== "connected") {
        this.removePeer(peerId, true);
      }
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
    if (!link) {
      if (notify) this.callbacks.onPeerState({ peerId, route: "offline" });
      return;
    }
    this.links.delete(peerId);
    if (link.channel) {
      link.channel.onclose = null;
      link.channel.onerror = null;
      link.channel.onmessage = null;
    }
    link.connection.onconnectionstatechange = null;
    link.connection.onicecandidate = null;
    link.connection.ondatachannel = null;
    link.channel?.close();
    link.connection.close();
    if (notify) this.callbacks.onPeerState({ peerId, route: "offline" });
  }

}

function isSignalPayload(value: unknown): value is SignalPayload {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  if (record.kind === "description") {
    const description = record.description;
    return Boolean(
      description &&
      typeof description === "object" &&
      !Array.isArray(description) &&
      ["offer", "answer", "pranswer", "rollback"].includes(
        String((description as { type?: unknown }).type),
      ),
    );
  }
  if (record.kind === "candidate") {
    return Boolean(record.candidate && typeof record.candidate === "object" && !Array.isArray(record.candidate));
  }
  return false;
}
