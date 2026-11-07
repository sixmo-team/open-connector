import type { ConnectionSummary } from "../../connection-service.ts";
import type { StoredLocalConnection } from "../../connection-store.ts";
import type { ActionDefinition, ActionExecutor, ProviderDefinition, ResolvedCredential } from "../../core/types.ts";
import type { IProviderLoader } from "../../providers/provider-loader.ts";
import type { SaasRequestScope } from "../contracts.ts";
import type {
  ExecutionCompletion,
  ExecutionFailure,
  ExecutionIntent,
  ExecutionJournal,
  SaasActionIdempotencyStore,
  SaasActionRunResult,
  SaasIdempotencyClaimInput,
  SaasIdempotencyClaimResult,
  SaasIdempotencyCompletionInput,
  SaasActionRunnerOptions,
} from "./saas-action-runner.ts";

import { Buffer } from "node:buffer";
import { describe, expect, it, vi } from "vitest";
import { createCatalogStore } from "../../catalog-store.ts";
import { canonicalActionRequestHash } from "./canonical-request.ts";
import { SaasActionRunner } from "./saas-action-runner.ts";

const action: ActionDefinition = {
  id: "example.echo",
  service: "example",
  name: "echo",
  description: "Echo input.",
  operationType: "read",
  requiredScopes: [],
  providerPermissions: [],
  inputSchema: { type: "object" },
  outputSchema: { type: "object" },
};
const provider: ProviderDefinition = {
  service: "example",
  displayName: "Example",
  categories: ["Developer Tools"],
  authTypes: ["api_key"],
  auth: [{ type: "api_key" }],
  actions: [action],
};
const connectorConnectionId = "11111111-1111-4111-8111-111111111111";
const credential: Extract<ResolvedCredential, { authType: "api_key" }> = {
  authType: "api_key",
  apiKey: "provider-secret",
  values: {},
  profile: { accountId: "account", displayName: "Account", grantedScopes: [] },
  metadata: {},
};
const storedConnection: StoredLocalConnection = {
  id: connectorConnectionId,
  revision: "revision-1",
  service: "example",
  connectionName: "opaque-alias",
  credential,
};

interface RunnerFixture {
  runner: SaasActionRunner;
  journal: MemoryJournal;
  providerExecutor: ActionExecutor;
  idempotency: MemoryScopedIdempotency;
}

describe("SaasActionRunner", () => {
  it("keeps cached output private to the actor when a workspace credential and request key are shared", async () => {
    const records = new Map<string, MemoryIdempotencyRecord>();
    const first = createRunner({ records, providerExecutor: async () => ({ ok: true, output: { actor: "first" } }) });
    const second = createRunner({
      records,
      scope: { ...executionScope({ message: "hello" }), actorUserId: "actor-b" },
      providerExecutor: async () => ({ ok: true, output: { actor: "second" } }),
    });
    const original = await first.runner.run(request({ message: "hello" }));
    await expect(second.runner.run(request({ message: "hello" }))).resolves.toMatchObject({
      ok: true,
      output: { actor: "second" },
    });
    await expect(first.runner.run(request({ message: "hello" }))).resolves.toEqual(original);
  });
  it("denies a rule disabled while connection authorization is waiting", async () => {
    let enabled = true;
    const entered = Promise.withResolvers<void>(),
      released = Promise.withResolvers<void>();
    const store = new MemoryConnectionStore(storedConnection);
    const fixture = createRunner({
      permission: () => enabled,
      connectionStore: {
        async getSafeConnection(id) {
          entered.resolve();
          await released.promise;
          return store.getSafeConnection(id);
        },
      },
    });
    const pending = fixture.runner.run(request({ message: "hello" }));
    await entered.promise;
    enabled = false;
    released.resolve();
    await expect(pending).resolves.toMatchObject({ ok: false, error: { code: "action_not_granted" } });
    expect(fixture.providerExecutor).not.toHaveBeenCalled();
  });
  it("denies a rule disabled while the executor is loading before provider dispatch", async () => {
    let enabled = true;
    const entered = Promise.withResolvers<void>(),
      released = Promise.withResolvers<void>();
    const providerExecutor = vi.fn<ActionExecutor>(async () => ({ ok: true, output: { effect: "sent" } }));
    const fixture = createRunner({
      permission: () => enabled,
      providerExecutor,
      loadActionExecutor: async () => {
        entered.resolve();
        await released.promise;
        return providerExecutor;
      },
    });
    const pending = fixture.runner.run(request({ message: "hello" }));
    await entered.promise;
    enabled = false;
    released.resolve();
    await expect(pending).resolves.toMatchObject({ ok: false, error: { code: "action_not_granted" } });
    expect(providerExecutor).not.toHaveBeenCalled();
  });
  it("denies a rule disabled while a persisted replay is being read", async () => {
    let enabled = true,
      holdReplay = false;
    const entered = Promise.withResolvers<void>(),
      released = Promise.withResolvers<void>();
    const idempotency = new MemoryScopedIdempotency(new Map(), "tenant-a");
    const claim = idempotency.claimAction.bind(idempotency);
    vi.spyOn(idempotency, "claimAction").mockImplementation(async (input) => {
      const result = await claim(input);
      if (holdReplay) {
        entered.resolve();
        await released.promise;
      }
      return result;
    });
    const fixture = createRunner({ idempotency, permission: () => enabled });
    await expect(fixture.runner.run(request({ message: "hello" }))).resolves.toMatchObject({ ok: true });
    holdReplay = true;
    const pending = fixture.runner.run(request({ message: "hello" }));
    await entered.promise;
    enabled = false;
    released.resolve();
    await expect(pending).resolves.toMatchObject({ ok: false, error: { code: "action_not_granted" } });
    expect(fixture.providerExecutor).toHaveBeenCalledTimes(1);
  });
  it("checks current permission before provider work and distinguishes an unavailable policy store", async () => {
    const denied = createRunner({ permission: () => false });
    const unavailable = createRunner({
      permission: () => {
        throw new Error("policy storage unavailable");
      },
    });
    await expect(denied.runner.run(request({ message: "hello" }))).resolves.toMatchObject({
      ok: false,
      error: { code: "action_not_granted" },
    });
    await expect(unavailable.runner.run(request({ message: "hello" }))).resolves.toMatchObject({
      ok: false,
      error: { code: "action_policy_unavailable" },
    });
    expect(denied.providerExecutor).not.toHaveBeenCalled();
    expect(unavailable.providerExecutor).not.toHaveBeenCalled();
    expect(denied.idempotency.claimCalls).toBe(0);
    expect(unavailable.idempotency.claimCalls).toBe(0);
  });

  it("rechecks permission before replaying a persisted success", async () => {
    let enabled = true;
    const fixture = createRunner({ permission: () => enabled });
    await expect(fixture.runner.run(request({ message: "hello" }))).resolves.toMatchObject({ ok: true });
    enabled = false;
    await expect(fixture.runner.run(request({ message: "hello" }))).resolves.toMatchObject({
      ok: false,
      error: { code: "action_not_granted" },
    });
    expect(fixture.providerExecutor).toHaveBeenCalledTimes(1);
  });

  it("rejects a saved result after the credential owner unshares the connection", async () => {
    const connectionStore = new MemoryConnectionStore(storedConnection);
    const fixture = createRunner({ connectionStore });
    await expect(fixture.runner.run(request({ message: "hello" }))).resolves.toMatchObject({ ok: true });
    connectionStore.visibility = "user";
    await expect(fixture.runner.run(request({ message: "hello" }))).resolves.toMatchObject({
      ok: false,
      error: { code: "connection_provider_mismatch" },
    });
    expect(fixture.providerExecutor).toHaveBeenCalledTimes(1);
  });
  it("rejects a saved result after the connection is transferred to another owner", async () => {
    const connectionStore = new MemoryConnectionStore(storedConnection);
    const fixture = createRunner({ connectionStore });
    await expect(fixture.runner.run(request({ message: "hello" }))).resolves.toMatchObject({ ok: true });
    connectionStore.subjectUserId = "new-owner";
    await expect(fixture.runner.run(request({ message: "hello" }))).resolves.toMatchObject({
      ok: false,
      error: { code: "connection_provider_mismatch" },
    });
    expect(fixture.providerExecutor).toHaveBeenCalledTimes(1);
  });

  it("does not call the provider when durable run intent fails", async () => {
    const fixture = createRunner({ journal: new MemoryJournal({ failStart: true }) });

    const result = await fixture.runner.run(request({ message: "hello" }));

    expect(result).toMatchObject({ ok: false, status: "unknown", error: { code: "audit_unavailable" } });
    expect(fixture.providerExecutor).not.toHaveBeenCalled();
  });

  it("rejects request-hash, action, and connection-provider binding drift before claiming", async () => {
    const input = { message: "authorized" };
    const wrongHash = createRunner({ scope: executionScope({ message: "different" }) });
    const wrongAction = createRunner({ scope: { ...executionScope(input), actionId: "other.action" } });
    const wrongProvider = createRunner({ input, connectionStore: new MemoryConnectionStore(undefined) });

    await expect(wrongHash.runner.run(request(input))).resolves.toMatchObject({
      ok: false,
      error: { code: "request_hash_mismatch" },
    });
    await expect(wrongAction.runner.run(request(input))).resolves.toMatchObject({
      ok: false,
      error: { code: "forbidden" },
    });
    await expect(wrongProvider.runner.run(request(input))).resolves.toMatchObject({
      ok: false,
      error: { code: "connection_provider_mismatch" },
    });
    expect(wrongHash.idempotency.claimCalls).toBe(0);
    expect(wrongAction.idempotency.claimCalls).toBe(0);
    expect(wrongProvider.idempotency.claimCalls).toBe(0);
  });

  it("rejects a caller-supplied connector connection id before provider execution", async () => {
    const fixture = createRunner();

    await expect(
      fixture.runner.run({
        ...request({ message: "hello" }),
        connectorConnectionId: "attacker-selected-connection",
      }),
    ).resolves.toMatchObject({ ok: false });
    expect(fixture.providerExecutor).not.toHaveBeenCalled();
    expect(fixture.idempotency.claimCalls).toBe(0);
  });

  it("replays the exact completed result, conflicts on payload drift, and partitions keys by tenant", async () => {
    const records = new Map<string, MemoryIdempotencyRecord>();
    const tenantA = createRunner({ records, tenantId: "tenant-a", input: { message: "one" } });
    const first = await tenantA.runner.run(request({ message: "one" }));
    const replay = await tenantA.runner.run(request({ message: "one" }));
    expect(replay).toEqual(first);
    expect(tenantA.providerExecutor).toHaveBeenCalledTimes(1);
    expect(tenantA.journal.completions[0].outputBytes).toBe(Buffer.byteLength(JSON.stringify({ message: "one" })));

    const drift = createRunner({
      records,
      tenantId: "tenant-a",
      scope: executionScope({ message: "two" }, "tenant-a"),
    });
    await expect(drift.runner.run(request({ message: "two" }))).resolves.toMatchObject({
      ok: false,
      error: { code: "idempotency_conflict" },
    });
    expect(drift.providerExecutor).not.toHaveBeenCalled();

    const tenantB = createRunner({ records, tenantId: "tenant-b", input: { message: "one" } });
    await expect(tenantB.runner.run(request({ message: "one" }))).resolves.toMatchObject({ ok: true });
    expect(tenantB.providerExecutor).toHaveBeenCalledTimes(1);
  });

  it("accepts output at the signed limit and persists only a bounded failure above it", async () => {
    const input = { message: "bounded" };
    const atLimitOutput = { value: "界" };
    const atLimitBytes = Buffer.byteLength(JSON.stringify(atLimitOutput));
    const atLimitRecords = new Map<string, MemoryIdempotencyRecord>();
    const atLimitExecutor = vi.fn<ActionExecutor>(async () => ({ ok: true, output: atLimitOutput }));
    const atLimit = createRunner({
      records: atLimitRecords,
      input,
      providerExecutor: atLimitExecutor,
      scope: executionScope(input, "tenant-a", atLimitBytes),
    });

    await expect(atLimit.runner.run(request(input))).resolves.toMatchObject({ ok: true, output: atLimitOutput });
    expect(atLimit.journal.completions[0].outputBytes).toBe(atLimitBytes);
    const downgradedExecutor = vi.fn<ActionExecutor>(async () => ({ ok: true, output: null }));
    const downgraded = createRunner({
      records: atLimitRecords,
      input,
      providerExecutor: downgradedExecutor,
      scope: executionScope(input, "tenant-a", atLimitBytes - 1),
    });
    const downgradedReplay = await downgraded.runner.run(request(input));
    expect(downgradedReplay).toMatchObject({ ok: false, error: { code: "action_output_too_large" } });
    expect(downgradedReplay).not.toHaveProperty("output");
    expect(JSON.stringify(downgradedReplay)).not.toContain("界");
    expect(downgradedExecutor).not.toHaveBeenCalled();

    const secret = "provider-output-must-not-persist";
    const records = new Map<string, MemoryIdempotencyRecord>();
    const overLimitExecutor = vi.fn<ActionExecutor>(async () => ({ ok: true, output: { value: secret } }));
    const overLimit = createRunner({
      records,
      input,
      providerExecutor: overLimitExecutor,
      scope: executionScope(input, "tenant-a", atLimitBytes),
    });
    const first = await overLimit.runner.run(request(input));
    const replay = await overLimit.runner.run(request(input));

    expect(first).toEqual({
      ok: false,
      executionId: expect.any(String),
      status: "failed",
      error: { code: "action_output_too_large", message: "Action output exceeds its reviewed size limit." },
    });
    expect(replay).toEqual(first);
    expect(overLimitExecutor).toHaveBeenCalledTimes(1);
    expect(overLimit.journal.failures).toEqual([
      expect.objectContaining({ outputBytes: 0, safeErrorCode: "action_output_too_large" }),
    ]);
    const persisted = JSON.stringify([...records.values()]);
    expect(persisted).not.toContain(secret);
    expect(persisted).not.toContain('"output"');
    expect(JSON.stringify({ first, replay, journal: overLimit.journal })).not.toContain(secret);
    expect(Buffer.byteLength(JSON.stringify(first))).toBeLessThan(256);
  });

  it("stores byte metrics and only a safe provider error", async () => {
    const secret = "Bearer must-not-escape";
    const providerExecutor = vi.fn<ActionExecutor>(async () => ({
      ok: false,
      error: { code: `token_${secret}`, message: secret, details: { authorization: secret } },
    }));
    const input = { message: "é" };
    const fixture = createRunner({ providerExecutor, input, providerRequestCount: 2 });

    const result = await fixture.runner.run(request(input));

    expect(result).toMatchObject({
      ok: false,
      status: "failed",
      error: { code: "provider_error", message: "Action execution failed." },
    });
    expect(JSON.stringify(result)).not.toContain(secret);
    expect(fixture.journal.intents[0].inputBytes).toBe(Buffer.byteLength(JSON.stringify(input)));
    expect(fixture.journal.failures[0]).toMatchObject({
      outputBytes: 0,
      providerRequestCount: 2,
      safeErrorCode: "provider_error",
    });
    expect(JSON.stringify(fixture.journal)).not.toContain(secret);
  });

  it("retains an unknown in-progress claim when post-provider journal persistence is lost", async () => {
    const fixture = createRunner({ journal: new MemoryJournal({ failComplete: true }) });

    const first = await fixture.runner.run(request({ message: "hello" }));
    const retry = await fixture.runner.run(request({ message: "hello" }));

    expect(first).toMatchObject({
      ok: false,
      status: "unknown",
      error: { code: "execution_reconciliation_required", retryable: true },
    });
    expect(retry).toMatchObject({ ok: false, status: "unknown" });
    expect(fixture.providerExecutor).toHaveBeenCalledTimes(1);
    expect(fixture.idempotency.completedCalls).toBe(0);
  });

  it("blocks retries when a provider attempt has an unknown outcome", async () => {
    const providerExecutor = vi.fn<ActionExecutor>(async () => {
      throw new Error("socket closed after request");
    });
    const fixture = createRunner({ providerExecutor });

    await expect(fixture.runner.run(request({ message: "hello" }))).resolves.toMatchObject({
      ok: false,
      status: "unknown",
      error: { code: "execution_reconciliation_required" },
    });
    await expect(fixture.runner.run(request({ message: "hello" }))).resolves.toMatchObject({
      ok: false,
      status: "unknown",
    });
    expect(providerExecutor).toHaveBeenCalledTimes(1);
    expect(fixture.journal.failures).toEqual([
      expect.objectContaining({ status: "unknown", safeErrorCode: "execution_reconciliation_required" }),
    ]);
  });

  it("never repeats a known effect when idempotency completion persistence is lost", async () => {
    const idempotency = new MemoryScopedIdempotency(new Map(), "tenant-a", true);
    const fixture = createRunner({ idempotency });

    await expect(fixture.runner.run(request({ message: "hello" }))).resolves.toMatchObject({
      ok: false,
      status: "unknown",
    });
    await expect(fixture.runner.run(request({ message: "hello" }))).resolves.toMatchObject({
      ok: false,
      status: "unknown",
    });
    expect(fixture.providerExecutor).toHaveBeenCalledTimes(1);
    expect(fixture.journal.completions).toHaveLength(1);
  });
});

function createRunner(
  options: {
    records?: Map<string, MemoryIdempotencyRecord>;
    tenantId?: string;
    scope?: SaasRequestScope;
    journal?: MemoryJournal;
    idempotency?: MemoryScopedIdempotency;
    connectionStore?: SaasActionRunnerOptions["connectionStore"];
    providerExecutor?: ActionExecutor;
    loadActionExecutor?: IProviderLoader["loadActionExecutor"];
    input?: unknown;
    providerRequestCount?: number;
    permission?: () => boolean;
  } = {},
): RunnerFixture {
  const providerExecutor =
    options.providerExecutor ?? vi.fn<ActionExecutor>(async (input) => ({ ok: true, output: input }));
  const providerLoader: IProviderLoader = {
    loadActionExecutor: options.loadActionExecutor ?? (async () => providerExecutor),
    async loadProxyExecutor() {
      return undefined;
    },
    async loadCredentialValidators() {
      return undefined;
    },
  };
  const tenantId = options.tenantId ?? "tenant-a";
  const scope = options.scope ?? executionScope(options.input ?? { message: "hello" }, tenantId);
  const journal = options.journal ?? new MemoryJournal();
  const idempotency = options.idempotency ?? new MemoryScopedIdempotency(options.records ?? new Map(), tenantId);
  const catalog = createCatalogStore([provider], { executableActionIds: [action.id] });
  const summary: ConnectionSummary = {
    id: storedConnection.id,
    service: storedConnection.service,
    connectionName: storedConnection.connectionName,
    authType: "api_key",
    configured: true,
    virtual: false,
    default: false,
    profile: credential.profile,
  };
  const runner = new SaasActionRunner({
    scope,
    catalog,
    providerLoader,
    connectionStore: options.connectionStore ?? new MemoryConnectionStore(storedConnection),
    actionPolicy: {
      async getEffectiveForActor(_scope, actionIds) {
        const enabled = options.permission?.() ?? true;
        return actionIds.map((actionId) => ({
          actionId,
          enabled,
          source: "platform" as const,
          individualEnabled: null,
          defaultEnabled: enabled,
        }));
      },
    },
    connections: {
      async getConnectionSummary() {
        return summary;
      },
      async resolveConnection() {
        return { source: "local", summary, credential };
      },
    },
    idempotency,
    journal,
    providerRequestCount: options.providerRequestCount === undefined ? undefined : () => options.providerRequestCount,
  });
  return { runner, journal, providerExecutor, idempotency };
}

function executionScope(input: unknown, tenantId = "tenant-a", maxOutputBytes = 8_388_608): SaasRequestScope {
  return {
    tenantId,
    workspaceId: "workspace-a",
    actorUserId: "actor-a",
    subjectUserId: "user-a",
    workspaceRole: "member",
    purpose: "action:execute:v2",
    permissions: ["action:execute:v2"],
    localConnectionId: "local-connection",
    connectorConnectionId,
    actionId: action.id,
    maxOutputBytes,
    requestHash: canonicalActionRequestHash(action.id, connectorConnectionId, input),
  };
}

function request(input: unknown) {
  return { actionId: action.id, connectorConnectionId, input, idempotencyKey: "same-key" };
}

class MemoryJournal implements ExecutionJournal {
  readonly intents: ExecutionIntent[] = [];
  readonly completions: ExecutionCompletion[] = [];
  readonly failures: ExecutionFailure[] = [];
  private readonly failuresToInject: { failStart?: boolean; failComplete?: boolean; failFailure?: boolean };

  constructor(failuresToInject: { failStart?: boolean; failComplete?: boolean; failFailure?: boolean } = {}) {
    this.failuresToInject = failuresToInject;
  }

  async start(intent: ExecutionIntent): Promise<void> {
    if (this.failuresToInject.failStart) throw new Error("postgres unavailable");
    this.intents.push(intent);
  }

  async complete(completion: ExecutionCompletion): Promise<void> {
    if (this.failuresToInject.failComplete) throw new Error("postgres unavailable");
    this.completions.push(completion);
  }

  async fail(failure: ExecutionFailure): Promise<void> {
    if (this.failuresToInject.failFailure) throw new Error("postgres unavailable");
    this.failures.push(failure);
  }
}

interface MemoryIdempotencyRecord {
  requestHash: string;
  claimId: string;
  response?: SaasActionRunResult;
}

class MemoryScopedIdempotency implements SaasActionIdempotencyStore {
  claimCalls = 0;
  completedCalls = 0;
  private readonly records: Map<string, MemoryIdempotencyRecord>;
  private readonly partition: string;
  private readonly failCompletion: boolean;

  constructor(records: Map<string, MemoryIdempotencyRecord>, partition: string, failCompletion = false) {
    this.records = records;
    this.partition = partition;
    this.failCompletion = failCompletion;
  }

  async claimAction(input: SaasIdempotencyClaimInput): Promise<SaasIdempotencyClaimResult> {
    this.claimCalls += 1;
    const key = `${this.partition}:${input.keyHash}`;
    const existing = this.records.get(key);
    if (!existing) {
      this.records.set(key, { requestHash: input.requestHash, claimId: input.claimId });
      return { kind: "acquired" };
    }
    if (existing.requestHash !== input.requestHash) return { kind: "conflict" };
    return existing.response ? { kind: "completed", response: existing.response } : { kind: "in_progress" };
  }

  async completeAction(input: SaasIdempotencyCompletionInput): Promise<boolean> {
    this.completedCalls += 1;
    if (this.failCompletion) return false;
    const record = this.records.get(`${this.partition}:${input.keyHash}`);
    if (!record || record.claimId !== input.claimId || record.requestHash !== input.requestHash || record.response)
      return false;
    record.response = structuredClone(input.response);
    return true;
  }
}

class MemoryConnectionStore {
  visibility: "user" | "workspace" = "workspace";
  subjectUserId = "user-a";
  private readonly connection: StoredLocalConnection | undefined;

  constructor(connection: StoredLocalConnection | undefined) {
    this.connection = connection;
  }

  async getSafeConnection(id: string) {
    const connection = this.connection;
    if (!connection || connection.id !== id) return undefined;
    return {
      id,
      subjectUserId: this.subjectUserId,
      localConnectionId: "local-connection",
      service: connection.service,
      connectionName: connection.connectionName,
      visibility: this.visibility,
      status: "active" as const,
      profile: credential.profile,
      createdAt: new Date(0).toISOString(),
      updatedAt: new Date(0).toISOString(),
    };
  }
}
