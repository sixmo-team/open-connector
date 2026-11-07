import type { ActionPolicyJwtVerifier, SaasJwtVerifier } from "./saas-jwt-verifier.ts";
import type { AddressInfo } from "node:net";

import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { createServer } from "node:http";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createActionPolicyJwtVerifier, createSaasJwtVerifier } from "./saas-jwt-verifier.ts";

const target = {
  kind: "user",
  tenantId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
  workspaceId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
  userId: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
};
let executionKey: CryptoKey;
let controlKey: CryptoKey;
let close: () => Promise<void>;
let execution: { verify: SaasJwtVerifier; checkJwks: () => Promise<boolean> };
let control: { verify: ActionPolicyJwtVerifier; checkJwks: () => Promise<boolean> };
const fetched: Array<{ path: string; authorization?: string }> = [];
beforeAll(async () => {
  const exec = await generateKeyPair("EdDSA");
  const policy = await generateKeyPair("EdDSA");
  executionKey = exec.privateKey;
  controlKey = policy.privateKey;
  const execJwk = { ...(await exportJWK(exec.publicKey)), kid: "execution", alg: "EdDSA" };
  const controlJwk = { ...(await exportJWK(policy.publicKey)), kid: "control", alg: "EdDSA" };
  const server = createServer((request, response) => {
    fetched.push({ path: request.url!, authorization: request.headers.authorization });
    if (request.url === "/execution" && request.headers.authorization !== "Bearer bootstrap") {
      response.writeHead(401).end();
      return;
    }
    response.setHeader("content-type", "application/json");
    response.end(JSON.stringify({ keys: request.url === "/control" ? [controlJwk] : [execJwk] }));
  });
  const listening = Promise.withResolvers<void>();
  server.listen(0, "127.0.0.1", listening.resolve);
  await listening.promise;
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  execution = createSaasJwtVerifier(
    {
      jwksUrl: `${base}/execution`,
      jwtIssuer: "backend",
      jwtAudience: "open-connector-saas",
      jwtActiveKid: "execution",
    },
    "bootstrap",
  );
  control = createActionPolicyJwtVerifier({
    policyControlJwksUrl: `${base}/control`,
    policyControlIssuer: "operators",
    policyControlAudience: "custom-policy-audience",
    policyControlActiveKid: "control",
  });
  close = () => {
    const stopped = Promise.withResolvers<void>();
    server.close((error) => (error ? stopped.reject(error) : stopped.resolve()));
    return stopped.promise;
  };
});
afterAll(async () => close());
function claims(): Record<string, unknown> {
  const now = Math.floor(Date.now() / 1000);
  return {
    iss: "operators",
    aud: "custom-policy-audience",
    sub: "verified-operator",
    jti: "verified-request",
    iat: now,
    nbf: now,
    exp: now + 60,
    subject_kind: "policy_control",
    purpose: "action-policy:read",
    permissions: ["action-policy:read"],
    policy_target: target,
  };
}
async function signed(body: Record<string, unknown>, key = controlKey, kid = "control"): Promise<string> {
  return `Bearer ${await new SignJWT(body).setProtectedHeader({ alg: "EdDSA", kid }).sign(key)}`;
}

describe("separate action policy JWT profile", () => {
  it("verifies configurable trust and freezes principal, target and permissions", async () => {
    const principal = await control.verify(await signed(claims()));
    expect(principal).toMatchObject({
      subjectKind: "policy_control",
      subject: "verified-operator",
      requestId: "verified-request",
      target,
    });
    expect([principal, principal.target, principal.permissions].every(Object.isFrozen)).toBe(true);
    expect(principal).not.toHaveProperty("workspaceRole");
    await expect(control.checkJwks()).resolves.toBe(true);
    await expect(execution.checkJwks()).resolves.toBe(true);
    expect(
      fetched.filter((request) => request.path === "/control").every((request) => request.authorization === undefined),
    ).toBe(true);
    expect(
      fetched
        .filter((request) => request.path === "/execution")
        .every((request) => request.authorization === "Bearer bootstrap"),
    ).toBe(true);
  });
  it.each(["iss", "aud", "permissions", "policy_target", "exp"])("rejects invalid control %s", async (field) => {
    const body = claims();
    const values: Record<string, unknown> = {
      iss: "forged",
      aud: "forged",
      permissions: ["*"],
      policy_target: { kind: "tenant", tenantId: target.tenantId },
      exp: Number(body.iat) + 61,
    };
    await expect(control.verify(await signed({ ...body, [field]: values[field] }))).rejects.toThrow("unauthorized");
  });
  it("requires signed mutation hash and accepts platform writes with no fake customer", async () => {
    const body = {
      ...claims(),
      purpose: "action-policy:write",
      permissions: ["action-policy:write"],
      policy_target: { kind: "platform" },
    };
    await expect(control.verify(await signed(body))).rejects.toThrow("unauthorized");
    await expect(control.verify(await signed({ ...body, request_hash: "a".repeat(43) }))).resolves.toMatchObject({
      target: { kind: "platform" },
      subject: "verified-operator",
    });
  });
  it("rejects a forged execution signed by control key even when its kid claims execution", async () => {
    const body = {
      ...claims(),
      iss: "backend",
      aud: "open-connector-saas",
      sub: target.userId,
      subject_kind: undefined,
      policy_target: undefined,
      tenant_id: target.tenantId,
      workspace_id: target.workspaceId,
      actor_user_id: target.userId,
      subject_user_id: target.userId,
      workspace_role: "owner",
      purpose: "action:execute:v2",
      permissions: ["action:execute:v2"],
      action_id: "gmail.messages_list",
      local_connection_id: "local",
      connector_connection_id: "connector",
      max_output_bytes: 1024,
      request_hash: "a".repeat(43),
    };
    await expect(execution.verify(await signed(body))).rejects.toThrow("unauthorized");
    await expect(execution.verify(await signed(body, controlKey, "execution"))).rejects.toThrow("unauthorized");
    await expect(execution.verify(await signed(body, executionKey, "execution"))).resolves.toMatchObject({
      purpose: "action:execute:v2",
    });
    await expect(
      execution.verify(
        await signed(
          { ...body, purpose: "action:execute", permissions: ["action:execute"] },
          executionKey,
          "execution",
        ),
      ),
    ).rejects.toThrow("unauthorized");
  });
  it("admits service inventory only in execution profile and freezes its real target", async () => {
    const body = {
      ...claims(),
      iss: "backend",
      aud: "open-connector-saas",
      sub: "real-lifecycle-service",
      subject_kind: "service",
      purpose: "action-policy:subjects",
      permissions: ["action-policy:subjects"],
      policy_target: { kind: "tenant", tenantId: target.tenantId },
    };
    const principal = await execution.verify(await signed(body, executionKey, "execution"));
    expect(principal).toMatchObject({
      subjectKind: "service",
      subject: "real-lifecycle-service",
      target: body.policy_target,
    });
    expect("target" in principal && Object.isFrozen(principal.target)).toBe(true);
    await expect(control.verify(await signed(body))).rejects.toThrow("unauthorized");
  });
});
