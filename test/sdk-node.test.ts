import { describe, expect, it, vi } from "vitest";

import { createTxnShieldNode, type TxnShieldEvaluationResult } from "../src/index.js";

const allowResult: TxnShieldEvaluationResult = {
  decision: "allow",
  score: 12,
  riskBand: "low",
  reasons: [],
  telemetryId: "tel_123",
};

describe("createTxnShieldNode", () => {
  it("posts evaluations to the hosted API with the secret key", async () => {
    const fetchImpl = vi.fn(async () => new Response(JSON.stringify(allowResult), { status: 200 }));
    const shield = createTxnShieldNode({
      secretKey: "txn_sec_test_123",
      apiBaseUrl: "https://api.txnshield.test",
      fetchImpl,
    });

    const response = await shield.evaluate({
      operationKey: "invoice.export",
      actor: { id: "user_1", authenticated: true, roles: ["support"] },
      resource: { type: "customer", id: "cus_1" },
      requestData: { requestedCount: 20 },
    });

    expect(response).toEqual(allowResult);
    expect(fetchImpl).toHaveBeenCalledWith(
      "https://api.txnshield.test/api/evaluate",
      expect.objectContaining({
        method: "POST",
        headers: expect.objectContaining({
          authorization: "Bearer txn_sec_test_123",
        }),
      }),
    );
    const [, init] = fetchImpl.mock.calls[0] as unknown as [string, RequestInit];
    expect(JSON.parse(String(init?.body))).toEqual(
      expect.objectContaining({ operationKey: "invoice.export" }),
    );
  });

  it("surfaces hosted API errors", async () => {
    const fetchImpl = vi.fn(async () => new Response(JSON.stringify({ error: "Invalid secret key." }), { status: 401 }));
    const shield = createTxnShieldNode({
      secretKey: "txn_sec_test_123",
      apiBaseUrl: "https://api.txnshield.test",
      fetchImpl,
    });

    await expect(
      shield.evaluate({
        operationKey: "invoice.export",
        actor: { id: "user_1" },
        resource: { type: "customer", id: "cus_1" },
      }),
    ).rejects.toThrow("Invalid secret key.");
  });

  it("allows protected routes when hosted evaluation allows", async () => {
    const fetchImpl = vi.fn(async () => new Response(JSON.stringify(allowResult), { status: 200 }));
    const shield = createTxnShieldNode({
      secretKey: "txn_sec_test_123",
      apiBaseUrl: "https://api.txnshield.test",
      fetchImpl,
    });
    const next = vi.fn();

    await shield.protect({
      operationKey: "invoice.export",
      actor: () => ({ id: "user_1", roles: ["support"] }),
      resource: () => ({ type: "customer", id: "cus_1" }),
    })(
      {
        body: { requestedCount: 1 },
        query: {},
        header: (name) => (name === "x-txnshield-session-id" ? "sess_1" : undefined),
      },
      { status: vi.fn() },
      next,
    );

    expect(next).toHaveBeenCalledWith();
  });

  it("returns step-up responses from protected routes", async () => {
    const fetchImpl = vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            decision: "step_up_required",
            score: 55,
            riskBand: "medium",
            reasons: ["policy_recent_human_signal_required"],
            telemetryId: "tel_123",
            challenge: { type: "proof_token", id: "chal_123" },
          } satisfies TxnShieldEvaluationResult),
          { status: 200 },
        ),
    );
    const shield = createTxnShieldNode({
      secretKey: "txn_sec_test_123",
      apiBaseUrl: "https://api.txnshield.test",
      fetchImpl,
    });
    const json = vi.fn();
    const status = vi.fn(() => ({ json }));

    await shield.protect({
      operationKey: "invoice.export",
      actor: () => ({ id: "user_1", roles: ["support"] }),
      resource: () => ({ type: "customer", id: "cus_1" }),
    })({ body: {}, query: {} }, { status }, vi.fn());

    expect(status).toHaveBeenCalledWith(409);
    expect(json).toHaveBeenCalledWith(
      expect.objectContaining({
        error: "step_up_required",
        challenge: { type: "proof_token", id: "chal_123" },
      }),
    );
  });

  it("redacts payloads without internal packages", () => {
    const shield = createTxnShieldNode({
      secretKey: "txn_sec_test_123",
      apiBaseUrl: "https://api.txnshield.test",
      fetchImpl: vi.fn(),
    });

    const redacted = shield.redact(
      { customer: { email: "ada@example.com", phone: "5555" } },
      { redaction: { fields: ["customer.email", "customer.phone"], strategy: "mask" } },
    );

    expect(redacted).toEqual({ customer: { email: "ad***********om", phone: "****" } });
  });
});
