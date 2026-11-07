import type { SaasHonoEnvironment } from "../auth/scoped-request.ts";
import type { ActionPolicyPage } from "../contracts.ts";
import type { Context } from "hono";

import { ZodError } from "zod/v4";
import { assertProcessingActive, getRequestSignal, waitForSignal } from "../../core/cancellation.ts";
import { SaasAuthorizationError } from "../auth/saas-jwt-verifier.ts";
import { actionPolicyPageSchema } from "../contracts.ts";

export class JsonBodyTooLargeError extends Error {}

/** Reject unknown/duplicate query parameters rather than silently changing signed request semantics. */
export function exactQuery(context: Context<SaasHonoEnvironment>, allowed: string[]): URLSearchParams | undefined {
  const query = new URL(context.req.url).searchParams;
  const keys = new Set(query.keys());
  if ([...keys].some((key) => !allowed.includes(key))) return undefined;
  if (allowed.some((key) => query.getAll(key).length > 1)) return undefined;
  return query;
}

export function readBoundedPage(context: Context<SaasHonoEnvironment>): ActionPolicyPage {
  const query = exactQuery(context, ["cursor", "limit"]);
  if (!query) throw new SyntaxError("Invalid page query");
  const limit = query.get("limit");
  if (limit !== null && !/^[1-9]\d*$/.test(limit)) throw new SyntaxError("Invalid page limit");
  return actionPolicyPageSchema.parse({
    ...(query.has("cursor") ? { cursor: query.get("cursor") } : {}),
    ...(limit === null ? {} : { limit: Number(limit) }),
  });
}

export async function runScopedHttpOperation(
  context: Context<SaasHonoEnvironment>,
  unavailableError: string,
  work: () => Promise<Response>,
): Promise<Response> {
  try {
    return await work();
  } catch (error) {
    if (error instanceof SaasAuthorizationError)
      return context.json({ error: error.status === 401 ? "unauthorized" : "forbidden" }, error.status);
    if (error instanceof JsonBodyTooLargeError) return context.json({ error: "payload_too_large" }, 413);
    if (error instanceof ZodError || error instanceof SyntaxError || error instanceof TypeError)
      return context.json({ error: "invalid_input" }, 400);
    return context.json({ error: unavailableError }, 503);
  }
}

export async function readBoundedJson(context: Context<SaasHonoEnvironment>, maximumBytes = 262_144): Promise<unknown> {
  assertProcessingActive();
  const contentType = context.req.header("content-type")?.split(";", 1)[0]?.trim().toLowerCase();
  if (contentType !== "application/json") throw new SyntaxError("JSON content type is required");
  const declaredLength = context.req.header("content-length");
  if (declaredLength !== undefined) {
    const bytes = Number(declaredLength);
    if (!Number.isSafeInteger(bytes) || bytes < 0) throw new SyntaxError("Invalid content length");
    if (bytes > maximumBytes) throw new JsonBodyTooLargeError();
  }
  const body = context.req.raw.body;
  if (!body) throw new SyntaxError("JSON body is required");
  const reader = body.getReader();
  const decoder = new TextDecoder("utf-8", { fatal: true });
  let bytes = 0;
  let text = "";
  try {
    while (true) {
      const part = await waitForSignal(reader.read(), getRequestSignal() ?? context.req.raw.signal);
      assertProcessingActive();
      if (part.done) break;
      bytes += part.value.byteLength;
      if (bytes > maximumBytes) throw new JsonBodyTooLargeError();
      text += decoder.decode(part.value, { stream: true });
    }
    text += decoder.decode();
    return JSON.parse(text) as unknown;
  } catch (error) {
    void reader.cancel().catch(() => undefined);
    throw error;
  } finally {
    reader.releaseLock();
  }
}
