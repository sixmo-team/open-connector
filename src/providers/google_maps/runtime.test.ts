import { describe, expect, it } from "vitest";
import { validateCredential } from "./runtime.ts";

function placesRestricted(): Response {
  return Response.json(
    {
      error: {
        code: 403,
        status: "PERMISSION_DENIED",
        message: "Places API is not permitted for this key",
        details: [
          {
            "@type": "type.googleapis.com/google.rpc.ErrorInfo",
            reason: "API_KEY_SERVICE_BLOCKED",
            domain: "googleapis.com",
            metadata: { service: "places.googleapis.com" },
          },
        ],
      },
    },
    { status: 403 },
  );
}

describe("Google Maps restricted API key validation", () => {
  it("accepts a real successful Routes probe when Places is disabled for a Routes-only key", async () => {
    const fetcher: typeof fetch = async (input) =>
      new URL(String(input)).hostname === "places.googleapis.com"
        ? placesRestricted()
        : Response.json({ routes: [{ distanceMeters: 500, duration: "60s" }] });
    const validation = await validateCredential({ apiKey: "routes-only-key" }, fetcher);
    expect(validation.metadata?.validationEndpoint).toBe("/directions/v2:computeRoutes");
  });

  it("does not claim valid credentials when neither enabled API accepts the key", async () => {
    const fetcher: typeof fetch = async (input) =>
      new URL(String(input)).hostname === "places.googleapis.com"
        ? placesRestricted()
        : Response.json(
            { error: { code: 403, status: "PERMISSION_DENIED", message: "Routes permission denied" } },
            { status: 403 },
          );
    await expect(validateCredential({ apiKey: "unauthorized-key" }, fetcher)).rejects.toMatchObject({ status: 400 });
  });

  it("does not turn a malformed Places response into successful credential verification", async () => {
    const fetcher: typeof fetch = async (input) =>
      new URL(String(input)).hostname === "places.googleapis.com"
        ? new Response("invalid JSON", { status: 200 })
        : Response.json({ routes: [{ distanceMeters: 500 }] });
    await expect(validateCredential({ apiKey: "unverified-key" }, fetcher)).rejects.toMatchObject({ status: 502 });
  });
});
