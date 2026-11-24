import type { CreateTxnShieldNodeOptions, TxnShieldActor, TxnShieldEvaluationResult } from "./index";
import type { ConnectorContext, ConnectorRoute } from "./connector";
import { authorizeConnectorRequest, validateConnectorOptions, withDeadline, type ConnectorTimeouts, type Evaluate } from "./connector-runtime";

/** Native Request/Response adapter for Next.js App Router in the Node.js runtime. */
export type RouteConnectorOptions<Context = unknown, RequestType extends Request = Request> = ConnectorTimeouts & {
  actor(request: RequestType, context: Context): TxnShieldActor | Promise<TxnShieldActor>;
  context?(request: RequestType, route: ConnectorRoute, params: Record<string, string>, context: Context): ConnectorContext | Promise<ConnectorContext>;
  /** Maximum response size to buffer when redaction is required. Default: 1 MiB. */
  maxRedactionBytes?: number;
  /** Maximum wait for a JSON response requiring redaction. Default: 5 seconds. */
  redactionTimeoutMs?: number;
};

async function readJson(response: Response, maxBytes: number, timeoutMs: number): Promise<unknown> {
  const contentType = response.headers.get("content-type")?.split(";")[0].trim().toLowerCase() ?? "";
  const encoding = response.headers.get("content-encoding");
  if (!(contentType === "application/json" || /^application\/[a-z0-9.+-]+\+json$/.test(contentType))
    || (encoding && encoding !== "identity") || !response.body) throw new Error("JSON response required.");
  const reader = response.body.getReader();
  try {
    return await withDeadline(timeoutMs, async (signal) => {
      const cancel = () => { void reader.cancel().catch(() => {}); };
      signal.addEventListener("abort", cancel, { once: true });
      try {
        const chunks: Uint8Array[] = [];
        let size = 0;
        while (true) {
          const { done, value } = await reader.read();
          if (signal.aborted) throw new Error("Redaction timed out.");
          if (done) break;
          size += value.byteLength;
          if (size > maxBytes) throw new Error("JSON response is too large.");
          chunks.push(value);
        }
        const bytes = new Uint8Array(size);
        let offset = 0;
        for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
        const payload: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
        if (payload === null || typeof payload !== "object") throw new Error("Structured JSON required.");
        return payload;
      } finally { signal.removeEventListener("abort", cancel); }
    });
  } finally {
    // Cancellation must not wait on an uncooperative response stream.
    void reader.cancel().catch(() => {});
  }
}

export function createRouteConnector<Context = unknown, RequestType extends Request = Request>(
  client: CreateTxnShieldNodeOptions, evaluate: Evaluate,
  redact: (payload: unknown, evaluation: TxnShieldEvaluationResult) => unknown,
  options: RouteConnectorOptions<Context, RequestType>, handler: (request: RequestType, context: Context) => Response | Promise<Response>,
) {
  validateConnectorOptions(options);
  const maxBytes = options.maxRedactionBytes ?? 1024 * 1024;
  const timeoutMs = options.redactionTimeoutMs ?? 5000;
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > 16 * 1024 * 1024
    || !Number.isFinite(timeoutMs) || timeoutMs < 1 || timeoutMs > 60000) throw new Error("Invalid redaction limits.");
  return async (request: RequestType, context: Context): Promise<Response> => {
    const url = new URL(request.url);
    const result = await authorizeConnectorRequest(client, evaluate, options, {
      method: request.method, url: url.pathname,
      actor: () => options.actor(request, context),
      context: (route, params) => options.context?.(request, route, params, context),
    });
    if (result.kind === "blocked") return Response.json(result.body, { status: result.status, headers: { "cache-control": "private, no-store" } });
    // Keep application exceptions (including Next.js redirects) in the framework.
    const response = await handler(request, context);
    if (result.kind === "unmapped") return response;
    const headers = new Headers(response.headers);
    headers.set("cache-control", "private, no-store");
    // Prevent framework/CDN-specific cache headers overriding the private response.
    headers.delete("cdn-cache-control"); headers.delete("vercel-cdn-cache-control");
    if (result.evaluation.decision !== "allow_redacted") {
      return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
    }
    try {
      const payload = await readJson(response, maxBytes, timeoutMs);
      for (const name of ["content-length", "etag", "content-md5", "digest", "content-range", "accept-ranges"]) headers.delete(name);
      headers.set("content-type", "application/json; charset=utf-8");
      return new Response(JSON.stringify(redact(payload, result.evaluation)), { status: response.status, statusText: response.statusText, headers });
    } catch {
      if (response.body && !response.body.locked) void response.body.cancel().catch(() => {});
      return Response.json({ error: "response_redaction_failed" }, { status: 503, headers: { "cache-control": "private, no-store" } });
    }
  };
}
