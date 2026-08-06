import type { RefreshLeaseStore } from "../storage/postgres-refresh-lease-store.ts";

import { randomUUID } from "node:crypto";

export interface PostgresRefreshCoordinatorOptions {
  leaseDurationMs?: number;
  maxWaitMs?: number;
  pollIntervalMs?: number;
  now?: () => number;
  sleep?: (milliseconds: number) => Promise<void>;
}

/** Serializes credential resolution for one connection across runtime replicas. */
export class PostgresRefreshCoordinator {
  private readonly leaseDurationMs: number;
  private readonly maxWaitMs: number;
  private readonly pollIntervalMs: number;
  private readonly now: () => number;
  private readonly sleep: (milliseconds: number) => Promise<void>;
  private readonly leases: RefreshLeaseStore;

  constructor(leases: RefreshLeaseStore, options: PostgresRefreshCoordinatorOptions = {}) {
    this.leases = leases;
    this.leaseDurationMs = positiveInteger(options.leaseDurationMs ?? 60_000, "lease duration");
    this.maxWaitMs = positiveInteger(options.maxWaitMs ?? 120_000, "maximum wait");
    this.pollIntervalMs = positiveInteger(options.pollIntervalMs ?? 50, "poll interval");
    this.now = options.now ?? Date.now;
    this.sleep =
      options.sleep ??
      ((milliseconds) => {
        const { promise, resolve } = Promise.withResolvers<void>();
        setTimeout(resolve, milliseconds);
        return promise;
      });
  }

  async runExclusive<T>(connectionId: string, operation: () => Promise<T>): Promise<T> {
    const holder = randomUUID();
    const deadline = this.now() + this.maxWaitMs;

    for (;;) {
      const result = await this.leases.acquire(connectionId, holder, this.leaseDurationMs);
      if (result.kind === "missing") throw new Error("The scoped connection no longer exists");
      if (result.kind === "acquired") break;

      const remainingMs = deadline - this.now();
      if (remainingMs <= 0) throw new Error("Timed out waiting for credential refresh lease");
      await this.sleep(Math.min(result.retryAfterMs, this.pollIntervalMs, remainingMs));
    }

    try {
      return await operation();
    } finally {
      await this.leases.release(connectionId, holder);
    }
  }
}

function positiveInteger(value: number, name: string): number {
  if (!Number.isInteger(value) || value <= 0) throw new Error(`Refresh ${name} must be a positive integer`);
  return value;
}
