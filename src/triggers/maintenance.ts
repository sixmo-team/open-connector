import type { RuntimeExecutionOptions } from "../core/runtime-execution.ts";
import type { RuntimeLogger } from "../core/types.ts";
import type { TriggerStore, TriggerSubscription } from "./store.ts";
import type { TriggerRunner } from "./trigger-runner.ts";

import { ExecutionError } from "../core/execution-error.ts";
import { withRuntimeExecution } from "../core/runtime-execution.ts";
import { withSubscription } from "./subscriptions.ts";

export interface TriggerSubscriptionSummary {
  id: string;
  mode: "webhook" | "resource" | "resource-set";
  ownerId: string;
  connectionId: string;
  providerAccountId: string;
  triggerId: string;
  requestKey: string;
  status: "active" | "deleting" | "deleted" | "abandoned";
  reconcileAt: number;
}

interface TriggerMaintenanceOptions extends RuntimeExecutionOptions {
  store: TriggerStore;
  runner: TriggerRunner;
  mayContinue: (record: TriggerSubscription) => Promise<boolean>;
  logger?: RuntimeLogger;
}

export class TriggerMaintenance {
  private readonly options: TriggerMaintenanceOptions;
  constructor(options: TriggerMaintenanceOptions) {
    this.options = options;
  }

  async list(): Promise<TriggerSubscriptionSummary[]> {
    return (await this.options.store.list())
      .filter((record) => record.mode !== "resource-set")
      .map((record) => ({
        id: record.id,
        mode: record.mode,
        ownerId: record.ownerId,
        connectionId: record.connectionId,
        providerAccountId: record.providerAccountId,
        triggerId: record.triggerId,
        requestKey: record.requestKey,
        status: record.status,
        reconcileAt: record.reconcileAt,
      }));
  }

  async cancel(id: string, signal: AbortSignal): Promise<void> {
    await withSubscription(this.options.store, id, signal, async (record, save) => {
      if (record.mode === "resource-set")
        throw new ExecutionError("invalid_input", "Cancel the owning resource subscriptions.");
      if (record.status === "deleted") return;
      record.status = "deleting";
      await save();
      await this.options.runner.cleanup(record, save, signal);
    });
  }

  async abandon(id: string, signal: AbortSignal): Promise<void> {
    await withSubscription(this.options.store, id, signal, async (record, save) => {
      if (record.mode === "resource-set")
        throw new ExecutionError("invalid_input", "Abandon the owning resource subscriptions.");
      if (record.status === "deleted" || record.status === "abandoned") return;
      if (record.mode === "resource") await this.options.runner.abandonResource(record, signal);
      record.status = "abandoned";
      await save();
    });
  }

  /** The trusted host supplies fresh verified scope/store and cancellation for each bounded pass. */
  run(signal: AbortSignal): Promise<void> {
    return withRuntimeExecution(this.options, { operation: "runtime" }, () => this.runBatch(signal));
  }

  private async runBatch(requestSignal: AbortSignal): Promise<void> {
    const deadline = Date.now() + 50_000;
    const records = await this.options.store.listFlowTriggersForMaintenance(Date.now(), 10);
    let failure: Error | undefined;
    for (const candidate of records) {
      requestSignal.throwIfAborted();
      if (Date.now() >= deadline) break;
      const signal = AbortSignal.any([
        requestSignal,
        AbortSignal.timeout(Math.max(1, Math.min(45_000, deadline - Date.now()))),
      ]);
      try {
        await withSubscription(this.options.store, candidate.id, signal, async (record, save) => {
          if (record.status === "deleted" || record.status === "abandoned") return;
          if (record.status === "active" && (await this.options.mayContinue(record))) {
            await save();
            return;
          }
          record.status = "deleting";
          await save();
          try {
            await this.options.runner.cleanup(record, save, signal);
          } catch (error) {
            if (!signal.aborted) await save();
            throw error;
          }
        });
      } catch (error) {
        failure ??= error instanceof Error ? error : new Error("Trigger cleanup failed");
        this.options.logger?.warn(
          { subscriptionId: candidate.id, errorCode: "trigger_cleanup_failed" },
          "Trigger subscription cleanup failed; pending work is retained",
        );
      }
    }
    if (failure) throw failure;
  }
}
