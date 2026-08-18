import { describe, expect, it } from "vitest";
import { DEFAULT_ICE_SETTINGS, iceServersFromSettings } from "./ice-config";

describe("ICE configuration", () => {
  it("uses public STUN defaults without embedding credentials", () => {
    expect(iceServersFromSettings(DEFAULT_ICE_SETTINGS)).toEqual([{
      urls: ["stun:stun.l.google.com:19302", "stun:stun1.l.google.com:19302"],
    }]);
  });

  it("accepts strict TURN configuration and keeps credentials separate from URLs", () => {
    expect(iceServersFromSettings({
      urlsText: "stun:stun.example.org:3478\nturns:turn.example.org:5349?transport=tcp",
      username: "alice",
      credential: "secret",
    })).toEqual([
      { urls: ["stun:stun.example.org:3478"] },
      {
        urls: ["turns:turn.example.org:5349?transport=tcp"],
        username: "alice",
        credential: "secret",
      },
    ]);
  });

  it("allows an empty endpoint list for LAN-only host candidates", () => {
    expect(iceServersFromSettings({ urlsText: "", username: "", credential: "" })).toEqual([]);
  });

  it("rejects malformed endpoints and incomplete TURN credentials", () => {
    expect(() => iceServersFromSettings({
      urlsText: "https://not-an-ice-server.example",
      username: "",
      credential: "",
    })).toThrow();
    expect(() => iceServersFromSettings({
      urlsText: "turn:turn.example.org:3478",
      username: "alice",
      credential: "",
    })).toThrow();
  });
});
