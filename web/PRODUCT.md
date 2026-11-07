# Product

## Users

Authenticated integration operators. They inspect safe provider, connection, and run metadata for an explicitly selected tenant, workspace, and subject, and administer action permissions without exposing credentials or raw execution payloads.

## Product Purpose

The protected console is served at `/integration-console` through the application backend. Its only data boundary is the same-origin `/internal/integration-admin` BFF; it never connects directly to a connector port or local runtime.

## Brand Personality

Clear, restrained, professional. The interface should feel like a dependable administration tool: dense enough for repeated work, calm enough for investigation, and explicit about scope and effective permissions.

## Anti-references

Avoid marketing-style hero layouts, decorative gradients, oversized cards, playful affordances, and hidden debugging state. Avoid dense controls that visually disconnect a selected detail from the action browser.

## Design Principles

- Put the task first: filtering, inspecting metadata, and changing exact action IDs should be immediate.
- Choose action mode before scope: `/actions?mode=defaults` manages global defaults without customer context; `/actions?mode=individual` retains real tenant → workspace → subject selection.
- Show the owner's effective permission and source, never calculate inheritance in the browser. Individual choices are allow, deny, and inherit/remove exception; defaults are enable/disable.
- Require an operator-entered reason for each write. Selected-row and visible-row bulk changes are one atomic request for at most 5000 exact IDs, never a wildcard or a rule for future catalog additions.
- Keep human-confirmation overrides separate from permission changes and unavailable in global mode. Re-read actual owner state after saves and ambiguous failures.
- Favor familiar native/shared controls and preserve scanability across large catalogs. No credential editing, execution, product-admission, OAuth management, or alternate public/local console.

## Accessibility & Inclusion

Target WCAG AA contrast for text and controls. Preserve keyboard focus states, readable system fonts, reduced-motion behavior for animations, and responsive layouts that remain usable on narrow screens.
