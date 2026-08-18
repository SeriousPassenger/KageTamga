import { describe, expect, it } from "vitest";
import { coalescePeerIdentities, isInactivePeer, type PeerDisplayCandidate } from "./peer-display";

function peer(
  peerId: string,
  fingerprint: string | undefined,
  issuedAt: string,
  route: PeerDisplayCandidate["route"] = "direct",
  trust = "verified",
): PeerDisplayCandidate & { displayName: string } {
  return {
    peerId,
    route,
    trust,
    displayName: peerId,
    assertion: fingerprint ? { pgpFingerprint: fingerprint, issuedAt } : undefined,
  };
}

describe("peer identity display", () => {
  it("uses the newest signed assertion for active sessions sharing a fingerprint", () => {
    const oldSession = peer("old-name", "AAAA", "2026-08-19T00:00:00.000Z");
    const newSession = peer("new-name", "aaaa", "2026-08-19T00:01:00.000Z");

    expect(coalescePeerIdentities([oldSession, newSession])).toEqual([newSession]);
  });

  it("prefers an online session over a newer offline copy of the same identity", () => {
    const online = peer("online", "AAAA", "2026-08-19T00:00:00.000Z", "direct");
    const offline = peer("offline", "AAAA", "2026-08-19T00:01:00.000Z", "offline");

    expect(coalescePeerIdentities([offline, online])).toEqual([online]);
  });

  it("never merges distinct fingerprints even when other identity fields match", () => {
    const first = peer("same-name-a", "AAAA", "2026-08-19T00:00:00.000Z");
    const second = peer("same-name-b", "BBBB", "2026-08-19T00:01:00.000Z");

    expect(coalescePeerIdentities([first, second])).toHaveLength(2);
  });

  it("keeps sessions without a signed assertion separate", () => {
    const first = peer("awaiting-a", undefined, "");
    const second = peer("awaiting-b", undefined, "");

    expect(coalescePeerIdentities([first, second])).toHaveLength(2);
  });

  it("classifies both offline and locally ignored sessions as inactive", () => {
    expect(isInactivePeer(peer("offline", "AAAA", "", "offline"))).toBe(true);
    expect(isInactivePeer(peer("ignored", "BBBB", "", "direct", "ignored"))).toBe(true);
    expect(isInactivePeer(peer("online", "CCCC", "", "relay"))).toBe(false);
  });
});
