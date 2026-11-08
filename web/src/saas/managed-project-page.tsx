import type {
  AdminWorkspaceTarget,
  ManagedProjectState,
  ManagedProviderConfig,
  ManagedSource,
  ManagedSourceInput,
} from "./admin-api";
import type { ReactNode } from "react";

import { useTranslate } from "@embra/i18n/react";
import { useEffect, useRef, useState } from "react";
import { InlineError } from "../shared-ui";
import {
  AdminApiError,
  configureManagedProject,
  listManagedProviderConfigs,
  readManagedProject,
  readManagedSource,
  removeManagedProject,
  setManagedSource,
} from "./admin-api";
import { Button } from "@/components/ui/button";

export function ManagedProjectPage({ target }: { target: AdminWorkspaceTarget }): ReactNode {
  const t = useTranslate();
  const [project, setProject] = useState<ManagedProjectState | null>(null);
  const [configs, setConfigs] = useState<ManagedProviderConfig[]>([]);
  const [baseUrl, setBaseUrl] = useState("");
  const [projectApiKey, setProjectApiKey] = useState("");
  const [reason, setReason] = useState("");
  const [service, setService] = useState("");
  const [requestedService, setRequestedService] = useState("");
  const [source, setSource] = useState<ManagedSource | null>(null);
  const [loadedService, setLoadedService] = useState("");
  const [sourceChoice, setSourceChoice] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [readError, setReadError] = useState<string | null>(null);
  const [sourceError, setSourceError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [sourceLoading, setSourceLoading] = useState(false);
  const [pending, setPending] = useState(false);
  const [revision, setRevision] = useState(0);
  const mounted = useRef(false);
  const writing = useRef(false);
  const sourceGeneration = useRef(0);
  const currentService = useRef(service);
  currentService.current = service;

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setReadError(null);
    setProject(null);
    setBaseUrl("");
    setConfigs([]);
    readManagedProject(target)
      .then(async (next) => {
        if (cancelled) return;
        setProject(next);
        setBaseUrl(next.baseUrl ?? "");
        if (next.configured) {
          const discovery = await listManagedProviderConfigs(target);
          if (!cancelled) setConfigs(discovery.providerConfigs);
        }
      })
      .catch(() => {
        if (!cancelled) setReadError(t("managed.loadError"));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [target.tenantId, target.workspaceId, revision, t]);

  useEffect(() => {
    const service = requestedService;
    const generation = ++sourceGeneration.current;
    let cancelled = false;
    setSource(null);
    setSourceChoice("");
    setSourceError(null);
    if (!service || !/^[a-z0-9][a-z0-9_-]*$/.test(service)) {
      setSourceLoading(false);
      return;
    }
    setSourceLoading(true);
    readManagedSource(target, service)
      .then((next) => {
        if (cancelled || generation !== sourceGeneration.current || currentService.current !== service) return;
        setSource(next);
        setLoadedService(service);
        setSourceChoice(next.mode === "local" ? "local" : next.providerConfigId);
      })
      .catch(() => {
        if (!cancelled && currentService.current === service) setSourceError(t("managed.sourceError"));
      })
      .finally(() => {
        if (!cancelled && currentService.current === service) setSourceLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [target.tenantId, target.workspaceId, requestedService, revision, t]);

  async function mutate(work: () => Promise<unknown>, clearKey = false): Promise<void> {
    if (writing.current || !reason.trim() || reason.trim().length > 500) return;
    writing.current = true;
    setPending(true);
    setError(null);
    try {
      await work();
    } catch (caught) {
      if (mounted.current)
        setError(
          t(caught instanceof AdminApiError && caught.status === 409 ? "managed.conflict" : "managed.saveError"),
        );
    } finally {
      writing.current = false;
      if (mounted.current) {
        if (clearKey) setProjectApiKey("");
        setLoading(true);
        setRevision((value) => value + 1);
        setPending(false);
      }
    }
  }

  const disabled = pending || loading;
  const canWrite = !disabled && Boolean(reason.trim()) && reason.trim().length <= 500;
  const serviceConfigs = configs.filter((config) => config.service === service);
  const sourceInput: ManagedSourceInput | null =
    sourceChoice === "local"
      ? { mode: "local" }
      : serviceConfigs.some((config) => config.id === sourceChoice)
        ? { mode: "saas", providerConfigId: sourceChoice }
        : null;
  const inputClass = "rounded-md border border-border bg-background p-2";

  return (
    <section className="detail-panel grid gap-4" aria-busy={loading || pending}>
      <h2>{t("managed.title")}</h2>
      <p>{t("managed.description")}</p>
      {error ? <InlineError message={error} /> : null}
      {readError ? <InlineError message={readError} /> : null}
      {loading || pending ? <p role="status">{t("common.loading")}</p> : null}
      {project ? (
        <div className="grid gap-1">
          <p>
            {t("managed.status")}: {t(`managed.statuses.${project.status}`)}
          </p>
          <p>
            {t("managed.cleanup")}: {project.cleanup.pending} / {project.cleanup.manual}
            {project.cleanup.paused ? ` · ${t("managed.paused")}` : ""}
          </p>
        </div>
      ) : null}
      <label className="grid gap-2">
        <span>{t("actions.reason")}</span>
        <input
          className={inputClass}
          value={reason}
          maxLength={500}
          disabled={disabled}
          onChange={(event) => setReason(event.target.value)}
          autoComplete="off"
        />
      </label>
      <form
        className="grid gap-3"
        onSubmit={(event) => {
          event.preventDefault();
          if (canWrite && projectApiKey.trim())
            void mutate(() => configureManagedProject(target, { baseUrl, projectApiKey }, reason), true);
        }}
      >
        <label className="grid gap-2">
          <span>{t("managed.baseUrl")}</span>
          <input
            className={inputClass}
            type="url"
            required
            value={baseUrl}
            disabled={disabled}
            onChange={(event) => setBaseUrl(event.target.value)}
            autoComplete="off"
          />
        </label>
        <label className="grid gap-2">
          <span>{t("managed.key")}</span>
          <input
            className={inputClass}
            type="password"
            required
            value={projectApiKey}
            disabled={disabled}
            onChange={(event) => setProjectApiKey(event.target.value)}
            autoComplete="new-password"
          />
        </label>
        <p>{t("managed.keyHint")}</p>
        <div className="flex flex-wrap gap-2">
          <Button type="submit" disabled={!canWrite || !projectApiKey.trim()}>
            {t("managed.configure")}
          </Button>
          <Button
            type="button"
            variant="outline"
            disabled={!canWrite}
            onClick={() => {
              void mutate(() => removeManagedProject(target, reason));
            }}
          >
            {t("managed.remove")}
          </Button>
          <Button type="button" variant="outline" disabled={disabled} onClick={() => setRevision((value) => value + 1)}>
            {t("common.refresh")}
          </Button>
        </div>
      </form>
      <h3>{t("managed.sources")}</h3>
      <form
        className="grid gap-3"
        onSubmit={(event) => {
          event.preventDefault();
          if (!disabled && /^[a-z0-9][a-z0-9_-]*$/.test(service)) setRequestedService(service);
        }}
      >
        <label className="grid gap-2">
          <span>{t("managed.service")}</span>
          <input
            className={inputClass}
            value={service}
            disabled={disabled}
            maxLength={255}
            required
            pattern="[a-z0-9][a-z0-9_-]*"
            list="managed-provider-services"
            onChange={(event) => {
              sourceGeneration.current += 1;
              setRequestedService("");
              setService(event.target.value);
            }}
            autoComplete="off"
          />
          <datalist id="managed-provider-services">
            {[...new Set(configs.map((config) => config.service))].map((id) => (
              <option key={id} value={id} />
            ))}
          </datalist>
        </label>
        <Button type="submit" disabled={disabled || sourceLoading || !service}>
          {t("managed.readSource")}
        </Button>
      </form>
      {sourceLoading ? <p role="status">{t("common.loading")}</p> : null}
      {sourceError ? <InlineError message={sourceError} /> : null}
      {source && loadedService === service ? (
        <>
          <p>
            {t("managed.currentSource")}: {t(source.mode === "local" ? "managed.local" : "managed.managed")}
          </p>
          <label className="grid gap-2">
            <span>{t("managed.selectSource")}</span>
            <select
              className={inputClass}
              value={sourceChoice}
              disabled={disabled || sourceLoading}
              onChange={(event) => setSourceChoice(event.target.value)}
            >
              <option value="" disabled>
                {t("managed.selectSource")}
              </option>
              <option value="local">{t("managed.local")}</option>
              {serviceConfigs.map((config) => (
                <option key={config.id} value={config.id}>
                  {config.displayName}
                </option>
              ))}
            </select>
          </label>
          <Button
            type="button"
            disabled={!canWrite || sourceLoading || !sourceInput}
            onClick={() => {
              if (sourceInput) void mutate(() => setManagedSource(target, service, sourceInput, reason));
            }}
          >
            {t("managed.saveSource")}
          </Button>
        </>
      ) : null}
    </section>
  );
}
