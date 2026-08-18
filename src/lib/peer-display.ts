import type { ConnectionRoute } from "./mesh";

export interface PeerDisplayCandidate {
  peerId: string;
  route: ConnectionRoute;
  trust: string;
  assertion?: {
    pgpFingerprint: string;
    issuedAt: string;
  };
}

/**
 * Offline and ignored sessions stay visible for diagnostics, but are not part
 * of the primary peer list.
 */
export function isInactivePeer(peer: PeerDisplayCandidate): boolean {
  return peer.route === "offline" || peer.trust === "ignored";
}

function preferenceRank(peer: PeerDisplayCandidate): number {
  if (peer.trust === "ignored") return 0;
  if (peer.route === "offline") return 1;
  if (peer.route === "connecting") return 2;
  return 3;
}

function assertionTime(peer: PeerDisplayCandidate): number {
  const value = peer.assertion ? Date.parse(peer.assertion.issuedAt) : Number.NaN;
  return Number.isFinite(value) ? value : Number.NEGATIVE_INFINITY;
}

function prefer<T extends PeerDisplayCandidate>(left: T, right: T): T {
  const rankDifference = preferenceRank(right) - preferenceRank(left);
  if (rankDifference !== 0) return rankDifference > 0 ? right : left;

  const timeDifference = assertionTime(right) - assertionTime(left);
  if (timeDifference !== 0) return timeDifference > 0 ? right : left;

  return right.peerId.localeCompare(left.peerId) < 0 ? right : left;
}

/**
 * A verified OpenPGP fingerprint is the durable identity. Multiple transport
 * sessions presenting that same fingerprint are one UI identity. Sessions
 * without a verified signed assertion remain separate and cannot borrow an
 * asserted identity.
 */
export function coalescePeerIdentities<T extends PeerDisplayCandidate>(peers: readonly T[]): T[] {
  const identities = new Map<string, T>();
  for (const peer of peers) {
    const fingerprint = peer.assertion?.pgpFingerprint.toUpperCase();
    const key = fingerprint ? `fingerprint:${fingerprint}` : `session:${peer.peerId}`;
    const previous = identities.get(key);
    identities.set(key, previous ? prefer(previous, peer) : peer);
  }
  return [...identities.values()].sort((left, right) => left.peerId.localeCompare(right.peerId));
}
