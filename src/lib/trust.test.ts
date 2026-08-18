import { describe, expect, it } from "vitest";
import { decideContactTrust, normalizeContactName } from "./trust";

describe("normalized contact reconciliation", () => {
  it("normalizes compatibility forms, surrounding space and case deterministically", () => {
    expect(normalizeContactName("  ＡLICE  ")).toBe("alice");
  });

  it("keeps only the current fingerprint verified for a normalized display name", () => {
    expect(decideContactTrust("Alice", "AAAA", "alice", "AAAA")).toBe("verified");
    expect(decideContactTrust("ＡLICE", "BBBB", "alice", "AAAA")).toBe("changed");
  });

  it("does not alter identities belonging to another normalized name", () => {
    expect(decideContactTrust("Bob", "BBBB", "alice", "AAAA")).toBe("unrelated");
  });
});
