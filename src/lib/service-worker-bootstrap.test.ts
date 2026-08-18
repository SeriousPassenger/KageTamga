import { describe, expect, it } from "vitest";
import {
  integrityBootstrapAction,
  waitForExpectedController,
} from "./service-worker-bootstrap";

class FakeServiceWorkerContainer extends EventTarget {
  controller: ServiceWorker | null = null;

  setController(scriptURL: string) {
    this.controller = { scriptURL } as ServiceWorker;
    this.dispatchEvent(new Event("controllerchange"));
  }
}

describe("integrityBootstrapAction", () => {
  it("verifies only shells that were controlled when their JavaScript started", () => {
    expect(integrityBootstrapAction(true, false)).toBe("verify");
    expect(integrityBootstrapAction(true, true)).toBe("verify");
  });

  it("permits exactly one reload for an initially uncontrolled shell", () => {
    expect(integrityBootstrapAction(false, false)).toBe("reload");
    expect(integrityBootstrapAction(false, true)).toBe("stop");
  });
});

describe("waitForExpectedController", () => {
  it("resolves when the exact integrity worker claims the page", async () => {
    const container = new FakeServiceWorkerContainer();
    const pending = waitForExpectedController(
      container as unknown as ServiceWorkerContainer,
      "https://chat.example/integrity-worker.js",
      1_000,
    );

    container.setController("https://chat.example/integrity-worker.js");
    await expect(pending).resolves.toMatchObject({
      scriptURL: "https://chat.example/integrity-worker.js",
    });
  });

  it("rejects a controller with any other script URL", async () => {
    const container = new FakeServiceWorkerContainer();
    const pending = waitForExpectedController(
      container as unknown as ServiceWorkerContainer,
      "https://chat.example/integrity-worker.js",
      1_000,
    );

    container.setController("https://chat.example/other-worker.js");
    await expect(pending).rejects.toThrow("An unexpected Service Worker controls this page.");
  });

  it("fails closed instead of reloading when control is never acquired", async () => {
    const container = new FakeServiceWorkerContainer();
    await expect(
      waitForExpectedController(
        container as unknown as ServiceWorkerContainer,
        "https://chat.example/integrity-worker.js",
        5,
      ),
    ).rejects.toThrow("activated but did not take control");
  });
});
