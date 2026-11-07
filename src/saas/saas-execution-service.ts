import type { IConnectionStore, SaasConnectionReference } from "../connection-store.ts";
import type { ManagedProject } from "../saas/storage/postgres-saas-project-store.ts";
import type { SaasRequestScope } from "./contracts.ts";
import type { SaasActionResult, SaasProxyResult } from "./saas-client.ts";
import type { SaasProjectService } from "./saas-project-service.ts";

import { assertProcessingActive, captureRequestProcessing, remainingProcessingMs } from "../core/cancellation.ts";
import { parseSaasProxyRequest, SaasClient, SaasError } from "./saas-client.ts";

const discoveryRejections = new Set([
  "oauth_source_unauthorized",
  "provider_config_not_found",
  "provider_not_found",
  "provider_not_configured",
  "proxy_not_supported",
]);

export interface SaasExecutionServiceOptions {
  scope: Readonly<SaasRequestScope>;
  connections: IConnectionStore;
  projects: SaasProjectService;
  client: SaasClient;
}

/** Resolves capabilities for the selected connection without fetching provider credentials or profiles. */
export class SaasExecutionService {
  private readonly options: SaasExecutionServiceOptions;
  private readonly scope: Readonly<SaasRequestScope>;

  constructor(options: SaasExecutionServiceOptions) {
    this.options = options;
    this.scope = captureRequestProcessing(
      Object.freeze({ ...options.scope, permissions: [...options.scope.permissions] }),
    );
  }

  async executeAction(
    reference: SaasConnectionReference,
    service: string,
    actionId: string,
    input: unknown,
    signal?: AbortSignal,
  ): Promise<SaasActionResult> {
    if (this.scope.actionId !== actionId)
      throw new SaasError("connection_not_found", "The managed action does not match the signed execution.", 404);
    signal = await this.authorize(reference, service, signal);
    const { project, config } = await this.options.projects.resolveExecutionConfig(
      service,
      reference.providerConfigId,
      reference.managedProjectId,
      signal,
    );
    if (!config.actionIds.includes(actionId))
      throw new SaasError("oauth_source_unsupported", "The selected SaaS connection does not support this action.");
    assertProcessingActive(this.scope);
    signal?.throwIfAborted();
    return this.execute(project, () => this.options.client.executeAction(project, reference, actionId, input, signal));
  }

  async executeProxy(
    reference: SaasConnectionReference,
    service: string,
    input: unknown,
    signal?: AbortSignal,
  ): Promise<SaasProxyResult> {
    signal = await this.authorize(reference, service, signal);
    const request = await parseSaasProxyRequest(input);
    const { project, config } = await this.options.projects.resolveExecutionConfig(
      service,
      reference.providerConfigId,
      reference.managedProjectId,
      signal,
    );
    if (!config.proxyAvailable)
      throw new SaasError("proxy_not_supported", "The selected SaaS connection does not support proxy execution.", 501);
    assertProcessingActive(this.scope);
    signal?.throwIfAborted();
    return this.execute(project, () => this.options.client.executeProxy(project, reference, service, request, signal));
  }

  private async authorize(
    reference: SaasConnectionReference,
    service: string,
    signal?: AbortSignal,
  ): Promise<AbortSignal | undefined> {
    assertProcessingActive(this.scope);
    if (
      this.scope.purpose !== "action:execute:v2" ||
      !this.scope.connectorConnectionId ||
      !this.scope.localConnectionId
    )
      throw new SaasError("connection_not_found", "Managed execution requires an exact signed connection.", 404);
    const stored = await this.options.connections.getById(this.scope.connectorConnectionId);
    if (
      !stored ||
      stored.source !== "saas" ||
      stored.service !== service ||
      stored.status !== "active" ||
      (
        ["managedProjectId", "providerConfigId", "externalUserId", "connectedAccountId", "localRequestId"] as const
      ).some((key) => stored.reference[key] !== reference[key])
    )
      throw new SaasError("connection_not_found", "The managed account no longer matches this execution.", 404);
    const remaining = remainingProcessingMs(this.scope);
    const signals = [
      this.scope.requestSignal,
      signal,
      remaining === undefined ? undefined : AbortSignal.timeout(remaining),
    ].filter((value): value is AbortSignal => value !== undefined);
    const bounded = signals.length ? AbortSignal.any(signals) : undefined;
    bounded?.throwIfAborted();
    return bounded;
  }
  private async execute<T>(project: ManagedProject, request: () => Promise<T>): Promise<T> {
    try {
      return await request();
    } catch (error) {
      if (error instanceof SaasError && discoveryRejections.has(error.code))
        this.options.projects.invalidateDiscovery(project);
      throw error;
    }
  }
}
