export interface Env {
  ASSETS: Fetcher;
  SIGNALING_ROOMS: DurableObjectNamespace<SignalingRoom>;
}

interface SocketAttachment {
  peerId: string;
  rateWindowStartedAt: number;
  messagesInWindow: number;
}

interface ClientSignal {
  to: string;
  iv: string;
  ciphertext: string;
}

const ROOM_ID_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const PEER_ID_PATTERN = /^[A-Za-z0-9_-]{16,64}$/;
const MAX_SIGNAL_BYTES = 64 * 1024;
const MAX_ROOM_PEERS = 8;
const RATE_WINDOW_MS = 10_000;
const MAX_SIGNALS_PER_WINDOW = 200;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;

const securityHeaders: Record<string, string> = {
  "Content-Security-Policy": [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self'",
    "img-src 'self' data: blob:",
    "connect-src 'self'",
    "font-src 'self'",
    "worker-src 'self'",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    "manifest-src 'self'",
    "require-trusted-types-for 'script'",
    "trusted-types quietwire",
  ].join("; "),
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Embedder-Policy": "require-corp",
  "Cross-Origin-Resource-Policy": "same-origin",
  "Origin-Agent-Cluster": "?1",
  "Permissions-Policy":
    "accelerometer=(), camera=(), display-capture=(), geolocation=(), gyroscope=(), microphone=(), payment=(), usb=()",
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "X-Robots-Tag": "noindex, nofollow, noarchive",
  "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
};

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      ...securityHeaders,
    },
  });
}

function withSecurityHeaders(response: Response): Response {
  const secured = new Response(response.body, response);
  for (const [name, value] of Object.entries(securityHeaders)) {
    secured.headers.set(name, value);
  }
  secured.headers.set("Cache-Control", "no-store, max-age=0");
  secured.headers.set("CDN-Cache-Control", "no-store");
  secured.headers.set("Cloudflare-CDN-Cache-Control", "no-store");
  secured.headers.set("Surrogate-Control", "no-store");
  secured.headers.set("X-Content-Type-Options", "nosniff");
  secured.headers.set("Cache-Control", "no-store, no-transform");
  return secured;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (url.protocol !== "https:" && url.hostname !== "localhost" && url.hostname !== "127.0.0.1") {
      url.protocol = "https:";
      return Response.redirect(url, 308);
    }

    if (url.pathname === "/api/health") {
      return json({ ok: true, storage: "none", signaling: "ephemeral" });
    }

    if (url.pathname.startsWith("/api/signal/")) {
      if (
        request.method !== "GET" ||
        request.headers.get("Upgrade")?.toLowerCase() !== "websocket"
      ) {
        return json({ error: "WebSocket upgrade required" }, 426);
      }
      if (request.headers.get("Origin") !== url.origin) {
        return json({ error: "Cross-origin signaling is not allowed" }, 403);
      }

      const roomId = url.pathname.slice("/api/signal/".length);
      const peerId = url.searchParams.get("peer") ?? "";
      if (!ROOM_ID_PATTERN.test(roomId) || !PEER_ID_PATTERN.test(peerId)) {
        return json({ error: "Invalid room or peer identifier" }, 400);
      }

      const id = env.SIGNALING_ROOMS.idFromName(roomId);
      return env.SIGNALING_ROOMS.get(id).fetch(request);
    }

    if (url.pathname.startsWith("/api/")) {
      return json({ error: "Not found" }, 404);
    }

    return withSecurityHeaders(await env.ASSETS.fetch(request));
  },
} satisfies ExportedHandler<Env>;

export class SignalingRoom extends DurableObject<Env> {

  fetch(request: Request): Response {
    const url = new URL(request.url);
    const peerId = url.searchParams.get("peer") ?? "";
    if (
      request.headers.get("Upgrade")?.toLowerCase() !== "websocket" ||
      request.headers.get("Origin") !== url.origin ||
      !PEER_ID_PATTERN.test(peerId)
    ) {
      return new Response("Bad request", { status: 400 });
    }

    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1];
    if (this.ctx.getWebSockets(`peer:${peerId}`).length > 0) {
      return new Response("Peer identifier already connected", { status: 409 });
    }
    if (this.ctx.getWebSockets("room").length >= MAX_ROOM_PEERS) {
      return new Response("Room peer limit reached", { status: 429 });
    }
    this.ctx.acceptWebSocket(server, ["room", `peer:${peerId}`]);
    server.serializeAttachment({
      peerId,
      rateWindowStartedAt: Date.now(),
      messagesInWindow: 0,
    } satisfies SocketAttachment);

    const existingPeers = this.ctx
      .getWebSockets("room")
      .filter((socket) => socket !== server)
      .map((socket) => socket.deserializeAttachment() as SocketAttachment | null)
      .filter((attachment): attachment is SocketAttachment => Boolean(attachment?.peerId))
      .map((attachment) => attachment.peerId);

    server.send(JSON.stringify({ type: "roster", peerIds: existingPeers }));
    this.broadcast({ type: "peer-joined", peerId }, server);

    return new Response(null, { status: 101, webSocket: client });
  }

  webSocketMessage(socket: WebSocket, message: string | ArrayBuffer): void {
    const text = typeof message === "string" ? message : new TextDecoder().decode(message);
    if (new TextEncoder().encode(text).byteLength > MAX_SIGNAL_BYTES) {
      socket.close(1009, "Signal too large");
      return;
    }

    const attachment = socket.deserializeAttachment() as SocketAttachment | null;
    if (!attachment?.peerId) {
      socket.close(1011, "Missing socket identity");
      return;
    }

    const now = Date.now();
    if (now - attachment.rateWindowStartedAt >= RATE_WINDOW_MS) {
      attachment.rateWindowStartedAt = now;
      attachment.messagesInWindow = 0;
    }
    attachment.messagesInWindow += 1;
    socket.serializeAttachment(attachment);
    if (attachment.messagesInWindow > MAX_SIGNALS_PER_WINDOW) {
      socket.close(1008, "Signal rate limit exceeded");
      return;
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(text) as unknown;
    } catch {
      socket.close(1007, "Invalid JSON");
      return;
    }

    if (!isClientSignal(parsed)) {
      socket.close(1008, "Invalid signal envelope");
      return;
    }
    const signal: ClientSignal = parsed;
    if (
      !PEER_ID_PATTERN.test(signal.to) ||
      signal.iv.length !== 16 ||
      signal.ciphertext.length > 87_382 ||
      signal.ciphertext.length % 4 === 1 ||
      !BASE64URL_PATTERN.test(signal.iv) ||
      !BASE64URL_PATTERN.test(signal.ciphertext)
    ) {
      socket.close(1008, "Invalid signal envelope");
      return;
    }

    const outbound = JSON.stringify({
      type: "signal",
      from: attachment.peerId,
      iv: signal.iv,
      ciphertext: signal.ciphertext,
    });
    for (const target of this.ctx.getWebSockets(`peer:${signal.to}`)) {
      if (target.readyState === WebSocket.OPEN) target.send(outbound);
    }
  }

  webSocketClose(socket: WebSocket, code: number, reason: string): void {
    const attachment = socket.deserializeAttachment() as SocketAttachment | null;
    if (attachment?.peerId) {
      this.broadcast({ type: "peer-left", peerId: attachment.peerId }, socket);
    }
    socket.close(code, reason);
  }

  webSocketError(socket: WebSocket): void {
    const attachment = socket.deserializeAttachment() as SocketAttachment | null;
    if (attachment?.peerId) {
      this.broadcast({ type: "peer-left", peerId: attachment.peerId }, socket);
    }
  }

  private broadcast(payload: unknown, except?: WebSocket): void {
    const encoded = JSON.stringify(payload);
    for (const socket of this.ctx.getWebSockets("room")) {
      if (socket !== except && socket.readyState === WebSocket.OPEN) socket.send(encoded);
    }
  }
}

function isClientSignal(value: unknown): value is ClientSignal {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).sort();
  return (
    keys.length === 3 &&
    keys[0] === "ciphertext" &&
    keys[1] === "iv" &&
    keys[2] === "to" &&
    typeof record.to === "string" &&
    typeof record.iv === "string" &&
    typeof record.ciphertext === "string"
  );
}
import { DurableObject } from "cloudflare:workers";
