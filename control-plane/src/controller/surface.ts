/*
 * Production surface gate (audit C-P0-01/03/09; PR0 containment).
 *
 * The production surface PHYSICALLY excludes: local capability issuance
 * (production issuance is controller-internal), the legacy one-call
 * register takeover and fence (C-P0-03 - only the lifecycle protocol may
 * move authority), budget admin, batch finalization (C-P0-09 - the v16
 * batch contract is not authorized before G2), admin incarnation bump, and
 * the raw outbox/audit surfaces.
 *
 * The gate fails CLOSED: only the exact CONTROLLER_SURFACE value
 * "local-dev" opens these routes, so a deployment that loses the variable
 * loses the dev routes, never gains them. Kept free of workerd imports so
 * the refusal matrix is unit-testable as a pure function under node.
 */
export function devOnlyRoute(path: string): boolean {
  if (path === "/capability" || path === "/session/register" || path === "/session/fence"
      || path === "/budgets" || path === "/wal/finalize-batch") return true;
  if (path.startsWith("/admin/") || path.startsWith("/outbox/")) return true;
  return /^\/wal\/[^/]+\/\d+\/audit$/.test(path);
}
