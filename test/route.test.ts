import { describe, expect, it, vi } from "vitest";
import { createTxnShieldNode, type RouteConnectorOptions, type TxnShieldEvaluationResult } from "../src/index";
import type { ConnectorRoute } from "../src/connector";

const mapping: ConnectorRoute = { id: "route1", method: "GET", path: "/api/customers/:id", operationKey: "quick.pii", resourceType: "customer", resourceParam: "id", responseMode: "json" };
const allow: TxnShieldEvaluationResult = { decision: "allow", score: 10, riskBand: "low", reasons: [], telemetryId: "event1" };
const redacted = { ...allow, decision: "allow_redacted", redaction: { fields: ["data.email"], strategy: "drop" } };
const request = () => new Request("https://app.test/api/customers/42");
function setup(evaluation: unknown = allow, routes = [mapping], options: Partial<RouteConnectorOptions> = {}) {
  const fetchImpl = vi.fn(async (url: string | Request | URL, _init?: RequestInit) => Response.json(String(url).endsWith("/api/config/hosted") ? { connector: { version: 1, routes } } : evaluation));
  const shield = createTxnShieldNode({ secretKey: "txn_sec_test", apiBaseUrl: "https://shield.test", fetchImpl });
  const actor = vi.fn(() => ({ id: "u1", authenticated: true, roles: ["support"] }));
  const handler = vi.fn(async (_request: Request, _context: unknown) => Response.json({ data: [{ email: "private@test", name: "Ada" }] }));
  const run = shield.route({ actor, ...options }, handler);
  return { fetchImpl, actor, handler, run, shield };
}

describe("Next.js App Router connector", () => {
  it("preserves framework Request subtypes and async route parameters", async () => {
    class FrameworkRequest extends Request { readonly sessionId = "session1"; }
    const { shield } = setup();
    const handler = async (request: FrameworkRequest, context: { params: Promise<{ id: string }> }) => Response.json({ id: (await context.params).id, sessionId: request.sessionId });
    const wrapped = shield.route({ actor: () => ({ id: "u1", authenticated: true }) }, handler);
    const response = await wrapped(new FrameworkRequest(request()), { params: Promise.resolve({ id: "42" }) });
    expect(await response.json()).toEqual({ id: "42", sessionId: "session1" });
  });
  it("passes the original request and framework context, using dashboard mappings", async () => {
    const { run, handler, fetchImpl } = setup();
    const req = request(); const context = { params: Promise.resolve({ id: "42" }) };
    expect((await run(req, context)).status).toBe(200);
    expect(handler).toHaveBeenCalledExactlyOnceWith(req, context);
    expect(JSON.parse(String(fetchImpl.mock.calls[1][1]?.body))).toMatchObject({ operationKey: "quick.pii", resource: { type: "customer", id: "42" }, metadata: { connectorRouteId: "route1" } });
  });
  it.each([["deny", 403], ["throttle", 429], ["step_up_required", 409], ["unknown", 503]])("stops %s before any business side effect", async (decision, status) => {
    const { run, handler } = setup({ ...allow, decision, challenge: { type: "proof_token", id: "proof1" } });
    const response = await run(request(), {});
    expect(response.status).toBe(status);
    expect(response.headers.get("cache-control")).toContain("no-store");
    const body = await response.json();
    expect(body).not.toHaveProperty("evaluation");
    if (decision === "step_up_required") expect(body.challenge.id).toBe("proof1");
    expect(handler).not.toHaveBeenCalled();
  });
  it("does not trust client-supplied identity or proof", async () => {
    const { run, handler, fetchImpl } = setup(allow, [mapping], { actor: () => ({ id: "u1", authenticated: false }) });
    const req = new Request(request(), { headers: { "x-user-id": "admin", "x-txnshield-proof-token": "passed" } });
    expect((await run(req, {})).status).toBe(401);
    expect(fetchImpl).toHaveBeenCalledTimes(1); expect(handler).not.toHaveBeenCalled();
  });
  it("leaves unmapped handlers unchanged and does not evaluate them", async () => {
    const { run, handler, actor, fetchImpl } = setup(allow, []);
    const response = new Response("public", { headers: { "cache-control": "public, max-age=30" } });
    handler.mockResolvedValue(response);
    expect(await run(request(), {})).toBe(response);
    expect(actor).not.toHaveBeenCalled(); expect(fetchImpl).toHaveBeenCalledTimes(1);
  });
  it("redacts JSON before returning it and preserves status and cookies", async () => {
    const { run, handler } = setup(redacted);
    handler.mockResolvedValue(Response.json({ data: [{ email: "private@test", name: "Ada" }] }, { status: 201, headers: { "set-cookie": "session=example; HttpOnly", "content-length": "999", etag: "old", "cache-control": "public", "cdn-cache-control": "public", "vercel-cdn-cache-control": "public" } }));
    const response = await run(request(), {});
    expect(response.status).toBe(201);
    expect(await response.json()).toEqual({ data: [{ name: "Ada" }] });
    expect(response.headers.get("set-cookie")).toContain("HttpOnly");
    expect(response.headers.get("content-length")).toBeNull(); expect(response.headers.get("etag")).toBeNull();
    expect(response.headers.get("cache-control")).toBe("private, no-store");
    expect(response.headers.get("cdn-cache-control")).toBeNull(); expect(response.headers.get("vercel-cdn-cache-control")).toBeNull();
  });
  it("does not allow caching even for allowed mapped responses", async () => {
    const { run } = setup();
    expect((await run(request(), {})).headers.get("cache-control")).toBe("private, no-store");
  });
  it.each([
    () => new Response("email\nsecret", { headers: { "content-type": "text/csv" } }),
    () => Response.json("secret"),
    () => new Response("invalid JSON", { headers: { "content-type": "application/json" } }),
    () => new Response(null, { status: 204 }),
  ])("withholds data when the response cannot be redacted", async (makeResponse) => {
    const { run, handler } = setup(redacted); handler.mockResolvedValue(makeResponse());
    const response = await run(request(), {});
    expect(response.status).toBe(503); expect(await response.text()).not.toContain("secret");
  });
  it("bounds buffered response size", async () => {
    const { run } = setup(redacted, [mapping], { maxRedactionBytes: 8 });
    expect((await run(request(), {})).status).toBe(503);
  });
  it("bounds stalled response streams and cancels them", async () => {
    const { run, handler } = setup(redacted, [mapping], { redactionTimeoutMs: 10 });
    const cancel = vi.fn();
    handler.mockResolvedValue(new Response(new ReadableStream({ cancel }), { headers: { "content-type": "application/json" } }));
    expect((await run(request(), {})).status).toBe(503); expect(cancel).toHaveBeenCalled();
  });
  it.each([undefined, { fields: [], strategy: "mask" }, { fields: ["__proto__.secret"], strategy: "drop" }])("rejects invalid directives before execution", async (redaction) => {
    const { run, handler } = setup({ ...redacted, redaction });
    expect((await run(request(), {})).status).toBe(503); expect(handler).not.toHaveBeenCalled();
  });
  it("blocks redaction for passthrough mappings before execution", async () => {
    const { run, handler } = setup(redacted, [{ ...mapping, responseMode: "passthrough" }]);
    expect((await run(request(), {})).status).toBe(503); expect(handler).not.toHaveBeenCalled();
  });
  it("requires export count from trusted server context", async () => {
    const routes = [{ ...mapping, requiresCount: true }];
    const missing = setup(allow, routes);
    expect((await missing.run(request(), {})).status).toBe(503); expect(missing.handler).not.toHaveBeenCalled();
    const valid = setup(allow, routes, { context: () => ({ metadata: { requestedCount: 30 }, challengeResult: { type: "proof_token", passed: true } }) });
    expect((await valid.run(request(), {})).status).toBe(200);
    expect(JSON.parse(String(valid.fetchImpl.mock.calls[1][1]?.body))).toMatchObject({ metadata: { requestedCount: 30 }, challengeResult: { passed: true } });
  });
  it("retains framework exceptions without retrying the handler", async () => {
    const { run, handler } = setup();
    const redirect = new Error("NEXT_REDIRECT"); handler.mockRejectedValue(redirect);
    await expect(run(request(), {})).rejects.toBe(redirect); expect(handler).toHaveBeenCalledTimes(1);
  });
  it.each(["config", "evaluate"])("fails closed on stalled %s even if fetch ignores abort", async (stage) => {
    const { run, fetchImpl, handler } = setup(allow, [mapping], { configTimeoutMs: 10, evaluationTimeoutMs: 10 });
    if (stage === "evaluate") fetchImpl.mockResolvedValueOnce(Response.json({ connector: { version: 1, routes: [mapping] } }));
    fetchImpl.mockImplementationOnce(() => new Promise(() => {}));
    expect((await run(request(), {})).status).toBe(503); expect(handler).not.toHaveBeenCalled();
  });
  it("accepts typed asynchronous Next.js route params", async () => {
    const { shield } = setup();
    const handler = shield.route({ actor: async (_req, context: { params: Promise<{ id: string }> }) => ({ id: (await context.params).id, authenticated: true }) }, async (_req, context) => Response.json({ id: (await context.params).id }));
    expect(await (await handler(request(), { params: Promise.resolve({ id: "42" }) })).json()).toEqual({ id: "42" });
  });
});
