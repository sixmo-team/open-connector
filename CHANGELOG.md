# Release notes

## Unreleased

### Added

- Private Node 24 package/container cutover: one scoped service and the protected `/integration-console` build, with explicit real-PostgreSQL permission/request/trigger/processing/lifecycle/file gates.
- The existing Helm chart now uses the same reviewed immutable image, external runtime/owner Secret references, read-only token files and restricted private ClusterIP access; no public console or local state.
- Operator-managed common action rules and explicit per-user overrides are owned and enforced by OpenConnector. Unconfigured actions remain denied; new users inherit common rules without copied grants.
- Scoped native managed authorization polling/cancellation, custom OAuth options, actor-private trigger state and complete native lifecycle metadata preserve the existing provider protocols behind the private service.
- Native Marketplace creation is reachable through a signed private API; its selected actions never grant execution permission. Existing backend recovery invokes one actor-bound OO maintenance pass without owning connector queues or data.

### Changed

- OpenConnector is now licensed under the OpenConnector License, a modified Apache License 2.0.
  You may still use, modify, self-host, and embed it for any purpose, including commercial use,
  but providing it to third parties as a hosted connector service requires a commercial license
  from OOMOL. Contributors agree to the contributor terms in section 2 of the license. Releases
  up to and including v1.9.4 remain under the unmodified Apache License 2.0.
- Native compact/lazy catalog loading, action contracts, schema-derived examples and deterministic drift checks are retained. Catalog files remain available for the runtime's lifetime.
- Removed obsolete global Node/SQLite/D1/Cloudflare listeners and state, static-token/bootstrap tools, inbound MCP/OAuth authorization server, Bun binary/headless npm packaging and old public console/deployment guides. Native provider transports, outbound MCP clients, optional SDKs, OAuth and shared trigger protocols remain reusable behind scoped admission.

### Security

- Saved action results are isolated by the verified actor even for shared connections; current permission is checked again immediately before dispatch or replay.
- Helm rejects undeclared container and pod security-context fields instead of accepting privileged-container or extra-group overrides.
- Transit-file metadata belongs to the initiating actor, not the owner of a shared credential; expired leases are purged for either bound actor or credential owner.
- Shopify client-credential tokens are partitioned by verified tenant, workspace, credential owner and connection lineage. Pending mints remain within their original bounded processing root, and cancelled work cannot populate the cache.
- Gmail attachment reads honor processing cancellation before send/draft writes. Native OAuth accepts Amazon's authorization-code alias while rejecting duplicate or conflicting callback codes before consuming state.

- The egress guard now always blocks the Azure platform endpoint `168.63.129.16` and the
  IPv6 metadata endpoints of Google Cloud (`fd20:ce::254`) and Oracle Cloud
  (`fd00:c1::a9fe:a9fe`), including when `OOMOL_CONNECT_ALLOW_PRIVATE_NETWORK=true` and when
  the IPv4 address is embedded in a v4-mapped, NAT64, 6to4, or Teredo IPv6 address. Previously
  `168.63.129.16` passed as a public address and the two IPv6 endpoints were reachable once
  private networks were allowed.
