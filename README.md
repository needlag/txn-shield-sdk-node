# `@txnshield/sdk-node`

Node-first runtime SDK for TxnShield.

It provides:

- hosted transaction evaluation against your TxnShield SaaS
- Express middleware for protected routes
- a Next.js App Router adapter for existing Request/Response handlers
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

## Plug-n-play Next.js App Router

Available in `@txnshield/sdk-node@0.5.0`. Map an existing authenticated JSON endpoint in **Connect application**, then wrap its existing HTTP method handler. Keep its authorization, validation and business logic. A browser SDK is not required by the new quick profiles.

```ts
// lib/txnshield.ts
import "server-only";
import { createTxnShieldNode } from "@txnshield/sdk-node";

export const shield = createTxnShieldNode({
  secretKey: process.env.TXNSHIELD_SECRET_KEY!,
  apiBaseUrl: process.env.TXNSHIELD_API_BASE_URL!,
});
```

```ts
// In the existing app/api/customers/[id]/route.ts
import { shield } from "@/lib/txnshield";
import { getAuthenticatedUser } from "@/lib/auth"; // Your existing server helper.

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// Rename the existing GET function to existingGET without changing its body.
// Keep it in this file and replace its export with:
export const GET = shield.route({
  actor: async (request) => {
    const user = await getAuthenticatedUser(request);
    return { id: user?.id ?? "anonymous", authenticated: Boolean(user?.id), roles: user?.roles ?? [] };
  },
}, existingGET);
```

Map `GET /api/customers/:id` (including any public base path), using `:id` instead of `[id]`. Wrap each selected method. The original Request subtype (including NextRequest) and framework context, including asynchronous `params`, reach the handler unchanged. Application exceptions and Next.js redirects propagate; the handler is never automatically retried.

The adapter shares the Express connector's matching, configuration, authentication, context and decision behavior. `actor(request, frameworkContext)` is required; optional `context(request, route, decodedParams, frameworkContext)` supplies trusted resource/session/metadata/challenge context. Export mappings require an authorized `metadata.requestedCount`, using the same plan the handler executes. Existing application access checks remain required.

- Unmapped requests pass through unchanged when configuration is available. Only wrapped, mapped methods receive protection. A configuration failure blocks all requests reaching the wrapper.
- Mapped responses use `Cache-Control: private, no-store`; CDN-specific cache headers are removed. Keep protected routes dynamic to prevent framework caching from skipping evaluation.
- `allow_redacted` requires a structured JSON Response. It buffers at most **1 MiB** by default (`maxRedactionBytes`, up to 16 MiB), with a **5-second** stream deadline (`redactionTimeoutMs`, up to 60,000 ms). Invalid, compressed, unsupported, oversized or stalled responses return 503 without exposing the original body. The handler has already run at this response stage; use appropriate tests for mutations and never retry them automatically.
- Redaction preserves status and cookies and removes invalidated content length/digest/cache validator headers. Non-JSON redaction, CSV, downloads and streaming need a dedicated integration. Passthrough mappings block a redaction decision before the handler.
- Configuration/evaluation deadlines are the same as Express: `configTimeoutMs` defaults to 5,000 and `evaluationTimeoutMs` to 35,000. Deny, throttle, verification and unavailable protection stop before handler execution with 403, 429, 409 and 503 respectively; missing authentication returns 401.

Pages Router, Server Actions and Edge runtime use the advanced guides; this adapter does not convert them to App Router handlers.

## Assisted installation

After mapping a route, **Download setup prompt** provides a Markdown file for Codex/Cursor in your application repository. It includes route configuration and SDK examples, preserves existing handlers/authentication, and asks for local enforcement tests and unresolved-route reporting. The file contains no secret key; configure secrets separately. It does not deploy or confirm that the application is connected. Send a real authenticated development request and inspect mapping status after verifying handler behavior locally.

New quick policies explicitly ignore an absent browser signal during risk scoring. Supplied stale signals and other risk factors still count, and authentication/explicit verification requirements remain enforced. Existing policies retain their previous scoring.
