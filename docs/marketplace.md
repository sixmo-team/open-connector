# Connector Marketplace

The native outbound Marketplace adapter uses genuine scoped connections and the protected backend contract. Marketplace and managed OAuth project credentials are distinct; see [managed OAuth](saas-oauth.md).

Connecting explicitly selects one service and a nonempty exact allowlist of current local/catalog AND discovered remote action IDs. It validates the real API key without executing a paid/destructive action and persists the binding in the existing OpenBao-backed connection. This technical action selection is not an OpenConnector function grant.

There are no global settings, automatic provider enablement, virtual/fallback connections or public discovery UI. Every execution rereads the authorized real row, exact scope/connector/revision and current remote identity/action intersection. A rejected key, discovery outage or mismatch fails closed, never switches to local credentials.


## Outbound vendor protocol

The external Marketplace v1 service exposes three endpoints; these are not incoming OpenConnector routes:

```text
GET  /.well-known/oomol-connector-marketplace
POST {validate}
POST {endpoint}/{actionId}
```

Discovery is public and returns JSON in this shape:

```json
{
  "version": 1,
  "id": "oomol",
  "name": "OOMOL Marketplace",
  "pricing": "metered",
  "validate": "/v1/marketplace/validate",
  "endpoint": "/v1/marketplace/actions",
  "actions": ["tinypng.shrink_image", "tinypng.output_image"]
}
```

- `version` is the integer `1`.
- `id` is a stable Marketplace identifier and `name` is its display name.
- `pricing` is either `free` or `metered`. It is informational; the Marketplace owns pricing and credit rules.
- `validate` and `endpoint` are path-absolute references beginning with `/`. They cannot contain a scheme, host, user information, query, or fragment, and are resolved against the discovery URL origin.
- `actions` is the complete, unpaginated allowlist of unique `<service>.<action>` IDs.
- Clients reject discovery redirects and responses larger than 4 MiB after decompression.

API key validation sends an empty authenticated request:

```http
POST /v1/marketplace/validate
Authorization: Bearer <marketplace-api-key>
Content-Length: 0
```

`204 No Content` means the key is valid and authorized. `401` means invalid, expired, or revoked; `403` means the caller is not permitted; `429` means rate limited; and `5xx` means temporarily unavailable. Failures use the normal Connector error envelope.

Action execution uses the full action ID in the path and only the ordinary Connector input in the body:

```http
POST /v1/marketplace/actions/tinypng.shrink_image
Authorization: Bearer <marketplace-api-key>
Content-Type: application/json

{"input":{"imageUrl":"https://example.com/image.png"}}
```

Success and failure use the normal Connector action envelopes. The success `meta` includes `executionId` and `actionId`; failure status codes and `errorCode` values follow Connector execution semantics. A Marketplace must authenticate the key, re-check its current allowlist and input schema, resolve its managed credential, and return the execution ID used for support and metering.

## Scoped connection and identity

The stored binding contains the actual tenant, workspace, local connection lineage, discovery URL, Marketplace ID and exact action IDs. The vendor protocol does not prove a provider account identity; local lineage must not be presented as a verified remote user. Ordinary provider credentials cannot inject this reserved routing metadata.

The vendor key never becomes local provider credentials. Remote execution sends only the action ID, input and Marketplace bearer key; local tenant/user/JWT/run identity and provider credentials are not forwarded. The private runner independently enforces the actual actor's current function rule and connection ownership/visibility before dispatch or replay. Replacement, disconnect and deletion use the same real connection/lifecycle owner as other integrations.
