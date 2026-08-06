import type { ProviderDisplay } from "./shared-ui";

import { describe, expect, it } from "vitest";
import { providerIconSource } from "./shared-ui";

function provider(options: Partial<ProviderDisplay> & Pick<ProviderDisplay, "service">): ProviderDisplay {
  return {
    displayName: options.displayName ?? options.service,
    ...options,
    service: options.service,
  };
}

describe("providerIconSource", () => {
  it("prefers the provider definition icon", () => {
    expect(
      providerIconSource(provider({ service: "example", iconUrl: " https://example.com/icon.svg " }), {
        example: "https://static.oomol.com/example.svg",
      }),
    ).toEqual({ kind: "url", value: "https://example.com/icon.svg" });
  });

  it("uses the bundled OOMOL catalog icon", () => {
    expect(
      providerIconSource(provider({ service: "example" }), {
        example: "https://static.oomol.com/example.svg",
      }),
    ).toEqual({ kind: "url", value: "https://static.oomol.com/example.svg" });
  });

  it("uses Google's favicon service when no icon is mapped", () => {
    expect(providerIconSource(provider({ service: "example", homepageUrl: "https://example.com/docs" }), {})).toEqual({
      kind: "url",
      value: "https://www.google.com/s2/favicons?sz=64&domain=example.com",
    });
  });

  it("falls back to initials when no icon or valid homepage is available", () => {
    expect(providerIconSource(provider({ service: "example", homepageUrl: "not a URL" }), {})).toBeUndefined();
  });
});
