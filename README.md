# `@txnshield/sdk-node`

Node-first runtime SDK for TxnShield.

It provides:

- hosted transaction evaluation against your TxnShield SaaS
- Express middleware for protected routes
- decision-aware redaction helpers
- optional challenge verification hooks

Example:

```ts
import { createTxnShieldNode } from "@txnshield/sdk-node";

const shield = createTxnShieldNode({
  secretKey: process.env.TXNSHIELD_SECRET_KEY!,
  apiBaseUrl: "https://api.txnshield.com",
});

const result = await shield.evaluate({
  operationKey: "invoice.export",
  actor: { id: "user_123", authenticated: true, roles: ["finance_manager"] },
  resource: { type: "customer_export", id: "batch_123" },
  requestData: { requestedCount: 250 },
});
```

## Plug-n-play Express connector

Install one connector after authentication and before your application handlers. Configure method/path → protected operation mappings in **Connector** in the control plane. The existing `evaluate()` and `protect()` APIs remain available for jobs and custom integrations. The environment header's **View** selector switches between **Plug-n-play** and **Advanced** without changing these mappings or runtime enforcement.

```ts
const shield = createTxnShieldNode({
  secretKey: process.env.TXNSHIELD_SECRET_KEY!,
  apiBaseUrl: process.env.TXNSHIELD_API_BASE_URL!,
});

app.use(authenticateUser); // Your existing middleware populates req.user.
app.use("/api", shield.connector({
  actor: (req) => ({
    id: req.user?.id ?? "anonymous",
    authenticated: Boolean(req.user?.id),
    roles: req.user?.roles ?? [],
  }),
}));

// Register application handlers AFTER the connector.
app.get("/api/customers/:id", async (req, res) => {
  // Keep application authorization and business logic here.
  res.json(await loadAuthorizedCustomer(req.user, req.params.id));
});
```

In the panel, map `GET /api/customers/:id` to the desired operation and select `id` as the resource parameter. Use the full original URL path, including a mount prefix such as `/api`. Install URL-rewriting middleware before the connector and keep route mappings consistent with the paths the connector receives. Prefer mounting only the API area you intend to manage.

- `allow` runs the handler.
- `allow_redacted` wraps `res.json()` and applies the returned field paths/strategy. Nested arrays are supported. Match paths to your actual response shape (`data.email`, for example). Raw sends, streaming writes and direct endings are blocked for that response.
- `deny` returns 403; `throttle` returns 429; `step_up_required` returns 409 and challenge metadata. These outcomes never run the handler.
- Non-JSON routes can use `passthrough`; if a decision requires redaction, the connector blocks before running their handler. CSV, streaming and file-specific redaction need a custom integration.
- Unknown decisions, unavailable config/evaluation, invalid redaction, and timeouts return 503 without running the handler. Invalid/missing authenticated identity on a protected route returns 401.

The connector reads hosted configuration on **every request**, then evaluates matched routes. There is no stale-config allow window or local policy cache. This adds a config round trip and, on matched routes, an evaluation round trip. A configuration outage blocks all requests in the mounted scope because the connector cannot know which routes are protected. With valid configuration, unmapped routes pass through; installation alone does not protect all transactions. Config and evaluation deadlines default to 5s and 35s, adjustable with `configTimeoutMs` and `evaluationTimeoutMs` (1–60,000 ms).

Paths support static segments and named `:parameters`, without wildcards or regular expressions. Matching is case-insensitive and ignores one trailing slash. GET also covers HEAD. More-specific static paths take priority; equally specific overlapping patterns fail closed. Encoded separators, dot segments and ambiguous paths are rejected. Review matching against your Express routing configuration.

### Shared business context and verification

A connector cannot infer database counts, resource ownership, session trust or a completed verification. Provide them once through a server-side `context` resolver. It receives the mapping and decoded path parameters even though Express has not executed the final route yet.

```ts
app.use("/api", shield.connector({
  actor: (req) => resolveAuthenticatedActor(req),
  context: async (req, route, params) => {
    if (route.operationKey === "quick.export") {
      // Resolve and store the exact export plan the handler will execute.
      const plan = await prepareAuthorizedExport(req);
      return {
        resource: { type: "export", id: plan.id },
        metadata: { requestedCount: plan.recordCount },
      };
    }
    return {};
  },
}));
```

Operations whose `actionType` is `export` require `metadata.requestedCount`; missing context blocks instead of assuming one record. Ensure the handler executes the same authorized plan/count to avoid evaluating one operation and executing another. Body/query counts and browser human-signal headers are not automatically trusted or copied by the connector.

For step-up, your UI handles 409, presents your verification flow, and retries. Return `challengeResult` from `context` only after your backend verifies the proof and binds it to the user/action. The connector does not supply a generic verification UI or blindly trust browser `passed` flags. Optional session and risk metadata also come from this resolver.

**Connection evidence:** the panel records the last successful policy evaluation for each mapping. This proves that the application reached the motor, not that every handler or response has been tested. Sandbox, paused and bypass decisions do not complete that evidence. Changing UI mode never changes runtime enforcement. The environment's existing pause/bypass controls still apply to evaluations.
