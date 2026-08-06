import { afterEach, describe, expect, it, vi } from "vitest";
import { validateJumpServerCredential } from "./runtime.ts";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("JumpServer MCP runtime", () => {
  it("uses Streamable HTTP with Worker-safe tool schema validation", async () => {
    const credential = {
      mcpEndpoint: "https://jumpserver.example.com/mcp",
      token: "jumpserver-token",
    };

    // Warm the SDK's Node-only Zod fast path so this test isolates tool output validation.
    await validateJumpServerCredential(credential, createStreamableMcpFetch());
    vi.stubGlobal("Function", function disabledFunctionConstructor() {
      throw new EvalError("Code generation from strings disallowed for this context");
    });

    const result = await validateJumpServerCredential(credential, createStreamableMcpFetch());

    expect(result.metadata).toMatchObject({
      mcpEndpoint: "https://jumpserver.example.com/mcp",
      availableActions: ["assets_assets_list"],
    });
  });
});

function createStreamableMcpFetch(): typeof fetch {
  return vi.fn(async (_input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const method = init?.method ?? "GET";
    if (method === "GET") {
      return new Response(null, { status: 405 });
    }

    const request = readRequest(init);
    if (!("id" in request)) {
      return new Response(null, { status: 202 });
    }

    const result =
      request.method === "initialize"
        ? {
            protocolVersion: "2025-03-26",
            capabilities: {},
            serverInfo: { name: "jumpserver", version: "1.0.0" },
          }
        : {
            tools: [
              {
                name: "assets_assets_list",
                inputSchema: { type: "object" },
                outputSchema: { type: "object" },
              },
            ],
          };

    return new Response(JSON.stringify({ jsonrpc: "2.0", id: request.id, result }), {
      headers: {
        "content-type": "application/json",
        "mcp-session-id": "test-session",
      },
    });
  }) as typeof fetch;
}

function readRequest(init?: RequestInit): Record<string, unknown> {
  return typeof init?.body === "string" ? (JSON.parse(init.body) as Record<string, unknown>) : {};
}
