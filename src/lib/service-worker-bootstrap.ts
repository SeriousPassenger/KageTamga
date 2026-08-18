export type IntegrityBootstrapAction = "verify" | "reload" | "stop";

export function integrityBootstrapAction(
  controlledAtStartup: boolean,
  reloadAlreadyAttempted: boolean,
): IntegrityBootstrapAction {
  if (controlledAtStartup) return "verify";
  return reloadAlreadyAttempted ? "stop" : "reload";
}

export async function waitForExpectedController(
  container: ServiceWorkerContainer,
  expectedScriptUrl: string,
  timeoutMs = 15_000,
): Promise<ServiceWorker> {
  return new Promise<ServiceWorker>((resolve, reject) => {
    let settled = false;
    let timeout: ReturnType<typeof setTimeout>;

    const cleanup = () => {
      clearTimeout(timeout);
      container.removeEventListener("controllerchange", inspectController);
    };
    const finish = (worker: ServiceWorker | undefined, error?: Error) => {
      if (settled) return;
      settled = true;
      cleanup();
      if (error) reject(error);
      else if (worker) resolve(worker);
    };
    const inspectController = () => {
      const controller = container.controller;
      if (!controller) return;
      if (controller.scriptURL !== expectedScriptUrl) {
        finish(undefined, new Error("An unexpected Service Worker controls this page."));
        return;
      }
      finish(controller);
    };

    container.addEventListener("controllerchange", inspectController);
    timeout = setTimeout(
      () =>
        finish(
          undefined,
          new Error("The integrity Service Worker activated but did not take control of this page."),
        ),
      timeoutMs,
    );
    inspectController();
  });
}
