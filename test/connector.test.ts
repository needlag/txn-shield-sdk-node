import { describe, expect, it, vi } from "vitest";
import type { RequestHandler } from "express";
import { createTxnShieldNode, type ConnectorOptions, type ConnectorRequest, type TxnShieldEvaluationResult } from "../src/index";
import { matchConnectorRoute, validateConnectorRoutes, type ConnectorRoute } from "../src/connector";

const route: ConnectorRoute = { id: "route1", method: "GET", path: "/api/customers/:id", operationKey: "quick.pii", resourceType: "customer", resourceParam: "id", responseMode: "json" };
const result: TxnShieldEvaluationResult = { decision: "allow", score: 10, riskBand: "low", reasons: [], telemetryId: "tel1" };
const actor = () => ({ id: "u1", authenticated: true, roles: ["support"] });
function response() {
  return {
    code: 200, payload: undefined as unknown, bytes: "",
    status(code: number) { this.code = code; return this; },
    json(payload: unknown) { this.payload = payload; return this.send(JSON.stringify(payload)); },
    send(payload?: unknown) { return this.end(payload); },
    writeHead(..._args: unknown[]) { return this; },
    write(payload: unknown) { this.bytes += String(payload); return true; },
    end(payload?: unknown) { this.writeHead(this.code); if (payload !== undefined) this.write(payload); return this; },
  };
}
function client(evaluation: unknown = result, routes: ConnectorRoute[] = [route], options: Partial<ConnectorOptions> = {}) {
  const fetchImpl = vi.fn(async (url: string | URL | Request, _init?: RequestInit) => Response.json(String(url).endsWith("/api/config/hosted") ? { connector: { version: 1, routes } } : evaluation));
  const shield = createTxnShieldNode({ secretKey: "txn_sec_test", apiBaseUrl: "https://shield.test", fetchImpl });
  const connector = shield.connector({ actor, ...options });
  // Compile-time integration contract against Express 5 middleware types.
  const expressMiddleware: RequestHandler = connector;
  void expressMiddleware;
  return { fetchImpl, connector };
}
const request = (): ConnectorRequest => ({ method: "GET", originalUrl: "/api/customers/42?format=json", user: { id: "u1" } });

describe("central Express connector", () => {
  it("resolves identity once and never promotes request body context or verification", async () => {
    const actorResolver = vi.fn(actor);
    const { connector, fetchImpl } = client(result, [route], { actor: actorResolver });
    const req = { ...request(), body: { actor: { id: "attacker" }, challengeResult: { passed: true }, requestedCount: 1 }, headers: { "x-txnshield-recent-human-signal": new Date().toISOString() } };
    const next = vi.fn();
    await connector(req, response(), next);
    expect(next).toHaveBeenCalledOnce(); expect(actorResolver).toHaveBeenCalledOnce();
    const input = JSON.parse(String(fetchImpl.mock.calls[1][1]?.body));
    expect(input).toMatchObject({ actor: { id: "u1", roles: ["support"] }, operationKey: "quick.pii", resource: { type: "customer", id: "42" }, metadata: { connectorRouteId: "route1" } });
    expect(input.challengeResult).toBeUndefined(); expect(input.session).toBeUndefined();
    expect(fetchImpl.mock.calls[0][1]?.headers).toMatchObject({ authorization: "Bearer txn_sec_test" });
  });

  it.each([["deny", 403], ["throttle", 429], ["step_up_required", 409]] as const)("enforces %s before the handler", async (decision, code) => {
    const { connector } = client({ ...result, decision, challenge: { type: "proof_token", id: "challenge1" } });
    const res = response(); const next = vi.fn(); await connector(request(), res, next);
    expect(res.code).toBe(code); expect(next).not.toHaveBeenCalled(); expect(res.payload).not.toHaveProperty("evaluation");
    if (decision === "step_up_required") expect(res.payload).toHaveProperty("challenge.id", "challenge1");
  });

  it("requires explicit authenticated identity", async () => {
    const { connector, fetchImpl } = client(result, [route], { actor: () => ({ id: "u1" }) });
    const res = response(); const next = vi.fn(); await connector(request(), res, next);
    expect(res.code).toBe(401); expect(next).not.toHaveBeenCalled(); expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it("lets unmapped routes through after reading current configuration", async () => {
    const { connector, fetchImpl } = client(); const next = vi.fn();
    await connector({ ...request(), originalUrl: "/api/health" }, response(), next);
    expect(next).toHaveBeenCalledOnce(); expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it("does not retain stale mappings when the configuration service fails", async () => {
    const { connector, fetchImpl } = client(); const next = vi.fn();
    await connector(request(), response(), next); next.mockClear();
    fetchImpl.mockResolvedValueOnce(Response.json({ error: "Unavailable" }, { status: 503 }));
    const res = response(); await connector({ ...request(), originalUrl: "/api/new-sensitive-route" }, res, next);
    expect(next).not.toHaveBeenCalled(); expect(res.code).toBe(503);
  });

  it.each(["config", "evaluation", "body"])("bounds a stalled %s request even if fetch ignores abort", async (stage) => {
    const { connector, fetchImpl } = client(result, [route], { configTimeoutMs: 10, evaluationTimeoutMs: 10 });
    const never = new Promise<Response>(() => {});
    if (stage === "config") fetchImpl.mockImplementationOnce(() => never);
    if (stage === "evaluation") fetchImpl.mockResolvedValueOnce(Response.json({ connector: { version: 1, routes: [route] } })).mockImplementationOnce(() => never);
    if (stage === "body") fetchImpl.mockResolvedValueOnce({ ok: true, json: () => new Promise(() => {}) } as unknown as Response);
    const next = vi.fn(); const res = response(); await connector(request(), res, next);
    expect(res.code).toBe(503); expect(next).not.toHaveBeenCalled();
  });

  it("automatically redacts nested JSON arrays without changing the original", async () => {
    const { connector } = client({ ...result, decision: "allow_redacted", redaction: { fields: ["data.email"], strategy: "drop" } });
    const res = response(); const payload = { data: [{ email: "private@test", name: "Ada" }] };
    await connector(request(), res, () => { res.json(payload); });
    expect(res.payload).toEqual({ data: [{ name: "Ada" }] }); expect(res.bytes).not.toContain("private@test"); expect(payload.data[0].email).toBe("private@test");
  });

  it.each(["send", "write", "end", "writeHead"] as const)("blocks %s from bypassing required JSON redaction", async (method) => {
    const { connector } = client({ ...result, decision: "allow_redacted", redaction: { fields: ["email"], strategy: "drop" } });
    const res = response();
    await connector(request(), res, () => { res[method]("secret@example.com"); res.end("more secret bytes"); });
    expect(res.code).toBe(500); expect(res.bytes).not.toContain("secret"); expect(res.payload).toEqual({ error: "protected_response_must_use_json" });
  });

  it("masks serialized model fields before Express serializes the response", async () => {
    const { connector } = client({ ...result, decision: "allow_redacted", redaction: { fields: ["email"], strategy: "drop" } });
    const res = response();
    await connector(request(), res, () => { res.json({ toJSON: () => ({ email: "private@test", name: "Ada" }) }); });
    expect(res.code).toBe(200); expect(res.bytes).toBe('{"name":"Ada"}');
  });

  it("rejects stringified JSON when field masking is required", async () => {
    const { connector } = client({ ...result, decision: "allow_redacted", redaction: { fields: ["email"], strategy: "drop" } });
    const res = response();
    await connector(request(), res, () => { res.json('{"email":"private@test"}'); });
    expect(res.code).toBe(500); expect(res.bytes).not.toContain("private@test");
  });

  it.each([undefined, { fields: [], strategy: "mask" }, { fields: ["__proto__.secret"], strategy: "drop" }, { fields: ["email"], strategy: "unknown" }])("blocks invalid redaction directives %j", async (redaction) => {
    const { connector } = client({ ...result, decision: "allow_redacted", redaction });
    const next = vi.fn(); const res = response(); await connector(request(), res, next);
    expect(res.code).toBe(503); expect(next).not.toHaveBeenCalled();
  });

  it("does not execute non-JSON handlers when masking is required", async () => {
    const { connector } = client({ ...result, decision: "allow_redacted", redaction: { fields: ["email"], strategy: "mask" } }, [{ ...route, responseMode: "passthrough" }]);
    const next = vi.fn(); const res = response(); await connector(request(), res, next);
    expect(res.code).toBe(503); expect(next).not.toHaveBeenCalled();
  });

  it("requires a trusted export count and accepts a verified shared context", async () => {
    const exportRoute = { ...route, requiresCount: true };
    const missing = client(result, [exportRoute]); const next = vi.fn(); const res = response();
    await missing.connector({ ...request(), body: { requestedCount: 10 } }, res, next);
    expect(res.code).toBe(503); expect(next).not.toHaveBeenCalled();
    const valid = client(result, [exportRoute], { context: () => ({ metadata: { requestedCount: 125, connectorRouteId: "spoof" }, challengeResult: { type: "proof_token", passed: true } }) });
    await valid.connector(request(), response(), next);
    expect(next).toHaveBeenCalledOnce();
    const input = JSON.parse(String(valid.fetchImpl.mock.calls[1][1]?.body));
    expect(input.metadata).toEqual({ requestedCount: 125, connectorRouteId: "route1" });
    expect(input.challengeResult).toEqual({ type: "proof_token", passed: true });
  });

  it("blocks unknown decisions", async () => {
    const { connector } = client({ ...result, decision: "approve" });
    const res = response(); const next = vi.fn(); await connector(request(), res, next);
    expect(res.code).toBe(503); expect(next).not.toHaveBeenCalled();
  });
});

describe("connector route matching", () => {
  it("covers HEAD, case-insensitive paths, encoded segments and trailing slashes", () => {
    expect(matchConnectorRoute([route], "HEAD", "/API/CUSTOMERS/%34%32/?a=1")?.params).toEqual({ id: "42" });
  });
  it("prefers a static route over a parameter", () => {
    const specific = { ...route, id: "route2", path: "/api/customers/export", resourceParam: null };
    expect(matchConnectorRoute([route, specific], "GET", "/api/customers/export")?.route.id).toBe("route2");
  });
  it("rejects equally specific overlapping mappings", () => {
    expect(() => matchConnectorRoute([{ ...route, path: "/api/:group/export" }, { ...route, path: "/api/customers/:id" }], "GET", "/api/customers/export")).toThrow("Ambiguous");
  });
  it.each(["/api/customers/%2fprivate", "/api/customers/%5cprivate", "/api/customers/..", "/api/customers/%252f", "/api/customers/%00", "/api/customers/%bad"])("rejects ambiguous path %s", (path) => {
    expect(() => matchConnectorRoute([route], "GET", path)).toThrow();
  });
  it("rejects duplicate aliases, unsupported schemas and malformed route maps", () => {
    expect(() => validateConnectorRoutes({ version: 1, routes: [route, { ...route, path: "/API/customers/:other", resourceParam: "other" }] })).toThrow("Duplicate");
    expect(() => validateConnectorRoutes({ version: 2, routes: [] })).toThrow();
    expect(() => validateConnectorRoutes({ version: 1, routes: [{ ...route, path: "/api/*" }] })).toThrow();
    expect(() => validateConnectorRoutes({ version: 1, routes: [{ ...route, resourceParam: "unknown" }] })).toThrow();
    expect(() => validateConnectorRoutes({ version: 1, routes: [{ ...route, path: "/:id/:id" }] })).toThrow();
  });
});
