/*
 * CF-P1: `DatabaseContainerDO` — Container lifecycle only (brief §4.1.3).
 *
 * The ONLY class in the control plane that extends the Cloudflare Container
 * helper. It owns start/stop/status/port readiness/HTTP proxying and
 * persists nothing but lifecycle observations + idempotency state.
 *
 * By construction it holds NO authority tables and NO capability to
 * allocate TypeSequence/AppendLsn/ControlSeq, epochs, command outcomes,
 * checkpoints, pins, or deletes (inv. 148–150). Its reports to the
 * controller are signed observations the controller treats as advisory.
 */

import { Container } from "@cloudflare/containers";

export class DatabaseContainerDO extends Container {
  // Explicit release policy (inv. 167): never inherit the default silently.
  // Hibernation must be controller-approved (P-CTR-03); until CF-P4 lands
  // the container is effectively always-on while a database is READY.
  sleepAfter = "2h";

  override onStart(): void {
    void this.reportObservation({ kind: "STARTED", at: Date.now() });
  }

  override onStop(): void {
    void this.reportObservation({ kind: "STOPPED", at: Date.now() });
  }

  override onError(error: unknown): void {
    void this.reportObservation({ kind: "PLATFORM_ERROR", at: Date.now(), error: String(error) });
  }

  /**
   * Idempotent observation report to DatabaseControllerDO. Loss or
   * duplication of this call can never grant or revoke database authority;
   * the controller records it as an observation row keyed by
   * (containerIdentity, processNonce, kind, at).
   */
  private async reportObservation(obs: Record<string, unknown>): Promise<void> {
    // service-binding RPC to the controller; fire-and-forget with bounded
    // retry via the DO alarm — implemented with CF-P3.
    void obs;
  }
}
