# Private scoped OpenConnector Helm chart

This chart deploys the same reviewed Node 24 image as `docker/Dockerfile`, not an alternate runtime. It provides a ClusterIP service, restricted ingress NetworkPolicy, non-root/read-only Deployment, `/health` liveness and `/ready` readiness/startup, optional autoscaling/disruption policy, and a same-image pre-install/pre-upgrade migration hook. It creates no public Ingress, NodePort, LoadBalancer, persistent volume, database, secret backend or credential Secret.

## Prerequisites

- Qualify the candidate image first, then supply its actual repository and immutable `sha256` digest. There is no upstream image/tag default.
- Provide external PostgreSQL with distinct schema-owner/migrator and non-owner/non-BYPASSRLS runtime roles; external production OpenBao over verified TLS with a renewable least-privilege token; dedicated SeaweedFS/S3 bucket credentials; and the actual backend execution/control JWKS endpoints and issuer/audience/key IDs.
- The existing backend/BFF owns customer identity, business roles/tariffs and human consent. The chart does not install that service or supply operator login. Publish neither the connector nor its console publicly. OAuth callbacks enter through the existing protected backend integration.
- Require a NetworkPolicy-enforcing cluster. `networkPolicy.backendPodSelector.matchLabels` must select only actual trusted backend/control pods in the release namespace, not customer workloads. The chart permits provider egress; infrastructure must preserve the approved egress boundary and guarded provider networking.

Create the following external Kubernetes Secrets through the existing secret-management process (do not commit their contents or pass tokens on a CLI):

| Value                               | Required Secret keys                                                                                                  | Consumer                                                                |
| ----------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------- |
| `secret.existingSecret`             | `OPEN_CONNECTOR_POSTGRES_URL`, `OPEN_CONNECTOR_SEAWEEDFS_ACCESS_KEY_ID`, `OPEN_CONNECTOR_SEAWEEDFS_SECRET_ACCESS_KEY` | Server; migration hook reads only the runtime PostgreSQL URL            |
| `authSecret.existingSecret`         | `open_connector_openbao_token`, `open_connector_jwks_bearer_token`                                                    | Server-only read-only `/run/secrets` volume, mode 0440 and fsGroup 1000 |
| `database.migration.existingSecret` | `OPEN_CONNECTOR_POSTGRES_MIGRATOR_URL`                                                                                | Migration hook only; never injected into the server                     |

The external Secrets must predate the release because migration is a pre-install/pre-upgrade hook. The chart does not copy the owner URL or authentication tokens into a ConfigMap. `config` accepts only actual non-secret scoped environment keys. Token file paths are fixed by the runtime. Optional disabling of the migration hook requires a separately qualified same-image migration before rollout; never bypass pending schema checks.

## Render and deploy

Prepare a private operator values file with real addresses, Secret names, backend labels and the qualified image. `values.yaml` deliberately contains no usable infrastructure defaults; rendering without required values fails. Review the current [deployment/backup/rollback runbook](../../../docs/saas-deployment.md) before any migration or rollout.

```sh
helm lint deploy/helm/open-connector -f /secure/scoped-connector-values.yaml
helm template open-connector deploy/helm/open-connector -f /secure/scoped-connector-values.yaml
# Only after backup/restore, schema and image qualification:
helm upgrade --install open-connector deploy/helm/open-connector \
  --namespace integration-control -f /secure/scoped-connector-values.yaml --wait
```

For rendering tests only, `scripts/fixtures/helm-scoped-values.yaml` supplies inert test names and a non-existent image. Do not deploy that fixture. CI renders it with and without the migration hook and requires missing configuration and removed global options to fail.

Before accepting a release, inspect rendered resources: exactly one private listener/ClusterIP port 3000; no public route/PVC or local state; owner credentials absent from the Deployment; two required read-only token files; restricted backend selector; same immutable image for migration/runtime; runtime role and forced RLS actually enforced. Check readiness, two-tenant isolation, byte-bounded protected console/assets/downloads and the backend processing drain using the real services. Rendering does not prove those behaviors.

External Secret rotation does not automatically restart pods. Renew finite JWKS/OpenBao credentials and trigger an approved rollout after atomic replacement; never rely on a changed mounted file to reload a captured credential. The 185-second termination grace covers the existing bounded processing/shutdown contract; it does not establish that contract by itself. Keep the approved prior image digest and follow the runbook's shadow-migration and rollback qualification.
