import type {
  CreateTxnShieldNodeOptions, TxnShieldActor, TxnShieldEvaluationInput,
  TxnShieldEvaluationResult, TxnShieldMiddlewareRequest, TxnShieldMiddlewareNext,
} from "./index";

export type ConnectorRoute = {
  id: string; method: string; path: string; operationKey: string; resourceType: string;
  requiresCount?: boolean; resourceParam?: string | null; responseMode: "json" | "passthrough";
};
export type ConnectorRequest = Omit<TxnShieldMiddlewareRequest, "params" | "get"> & {
  method?: string; originalUrl?: string; url?: string;
  params?: Record<string, string | string[] | undefined>;
  get?: (name: string) => string | null | undefined;
};
export type ConnectorResponse = {
  status(code: number): unknown;
  json(payload: unknown): unknown;
  send(payload?: unknown): unknown;
  write(...args: any[]): unknown;
  end(...args: any[]): unknown;
  writeHead(...args: any[]): unknown;
};
type ConnectorContext = Partial<Pick<TxnShieldEvaluationInput, "resource" | "session" | "metadata" | "challengeResult" | "rawSignals">>;
export type ConnectorOptions = {
  /** Resolve identity using your authentication middleware, never request body/header identity. */
  actor(req: ConnectorRequest): TxnShieldActor | Promise<TxnShieldActor>;
  /** Trusted business context and verified challenges, shared by all protected routes. */
  context?(req: ConnectorRequest, route: ConnectorRoute, params: Record<string, string>): ConnectorContext | Promise<ConnectorContext>;
  configTimeoutMs?: number;
  evaluationTimeoutMs?: number;
};
const routePattern = /^(?:\/(?:[A-Za-z0-9_~-]+(?:\.[A-Za-z0-9_~-]+)*|:[A-Za-z][A-Za-z0-9_]*))+\/?$/;
const methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];

export function validateConnectorRoutes(value: unknown): ConnectorRoute[] {
  if (!value || typeof value !== "object") throw new Error("Invalid connector configuration.");
  const config = value as { version?: unknown; routes?: unknown };
  if (config.version !== 1 || !Array.isArray(config.routes)) throw new Error("Unsupported connector configuration.");
  const seen = new Set<string>();
  return config.routes.map((item: unknown) => {
    if (!item || typeof item !== "object") throw new Error("Invalid route.");
    const route = item as ConnectorRoute;
    if (![route.id, route.operationKey, route.resourceType].every((v) => typeof v === "string" && v.length > 0)
      || !methods.includes(route.method) || typeof route.path !== "string"
      || !(route.path === "/" || routePattern.test(route.path))
      || (route.requiresCount !== undefined && typeof route.requiresCount !== "boolean")
      || !["json", "passthrough"].includes(route.responseMode)) throw new Error("Invalid route.");
    const params = route.path.split("/").filter((part) => part.startsWith(":"));
    if (new Set(params).size !== params.length || (route.resourceParam != null && !params.includes(`:${route.resourceParam}`))) throw new Error("Invalid resource parameter.");
    const key = `${route.method}:${route.path.replace(/\/$/, "").replace(/:[A-Za-z][A-Za-z0-9_]*/g, ":").toLowerCase()}`;
    if (seen.has(key)) throw new Error("Duplicate route.");
    seen.add(key);
    return route;
  });
}

export function matchConnectorRoute(routes: ConnectorRoute[], method: string, url: string) {
  const rawPath = url.split("?")[0];
  if (!rawPath.startsWith("/") || rawPath.includes("#")) throw new Error("Invalid request path.");
  const path = rawPath.split("/").map((part) => {
    const decoded = decodeURIComponent(part);
    if (/[\\/\x00-\x20%]/.test(decoded) || decoded === "." || decoded === "..") throw new Error("Ambiguous request path.");
    return decoded;
  }).join("/").replace(/\/$/, "");
  const parts = path.split("/");
  const matches = routes.flatMap((route) => {
    if (route.method !== (method === "HEAD" ? "GET" : method)) return [];
    const pattern = route.path.replace(/\/$/, "").split("/");
    if (parts.length !== pattern.length) return [];
    const params: Record<string, string> = Object.create(null);
    let specificity = 0;
    for (let i = 0; i < parts.length; i++) {
      if (pattern[i].startsWith(":")) {
        if (!parts[i]) return [];
        params[pattern[i].slice(1)] = parts[i];
      } else {
        if (pattern[i].toLowerCase() !== parts[i].toLowerCase()) return [];
        specificity++;
      }
    }
    return [{ route, params, specificity }];
  }).sort((a, b) => b.specificity - a.specificity);
  if (matches.length > 1 && matches[1].specificity === matches[0].specificity) throw new Error("Ambiguous route mapping.");
  return matches[0];
}

async function withDeadline<T>(ms: number, work: (signal: AbortSignal) => Promise<T>): Promise<T> {
  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([work(controller.signal), new Promise<never>((_, reject) => {
      timer = setTimeout(() => { controller.abort(); reject(new Error("TxnShield timed out.")); }, ms);
    })]);
  } finally { clearTimeout(timer); }
}

function guardJsonResponse(res: ConnectorResponse, transform: (payload: unknown) => unknown) {
  const json = res.json.bind(res);
  let internal = false;
  let blocked = false;
  const invoke = (payload: unknown) => {
    internal = true;
    try { return json(payload); } finally { internal = false; }
  };
  res.json = (payload) => {
    if (blocked) return res;
    try { return invoke(transform(payload)); }
    catch { blocked = true; res.status(500); return invoke({ error: "response_redaction_failed" }); }
  };
  // Express json() uses send()/end() internally. Only this guarded pipeline may write bytes.
  for (const name of ["send", "write", "end", "writeHead"] as const) {
    const original = res[name].bind(res);
    res[name] = (...args: any[]) => {
      if (internal) return original(...args);
      if (!blocked) {
        blocked = true;
        res.status(500);
        invoke({ error: "protected_response_must_use_json" });
      }
      return res;
    };
  }
}

export function createConnector(
  client: CreateTxnShieldNodeOptions,
  evaluate: (input: TxnShieldEvaluationInput, options?: { signal?: AbortSignal }) => Promise<TxnShieldEvaluationResult>,
  redact: (payload: unknown, evaluation: TxnShieldEvaluationResult) => unknown,
  options: ConnectorOptions,
) {
  if (typeof options.actor !== "function") throw new Error("The connector requires an authenticated actor resolver.");
  const configTimeout = options.configTimeoutMs ?? 5000;
  const evaluationTimeout = options.evaluationTimeoutMs ?? 35000;
  if (![configTimeout, evaluationTimeout].every((v) => Number.isFinite(v) && v >= 1 && v <= 60000)) throw new Error("Invalid connector timeout.");
  const fetchImpl = client.fetchImpl ?? fetch;
  return async (req: ConnectorRequest, res: ConnectorResponse, next: TxnShieldMiddlewareNext): Promise<void> => {
    let canContinue = false;
    try {
      // Read every request so new protected routes have no stale configuration allow window.
      const config = await withDeadline(configTimeout, async (signal) => {
        const response = await fetchImpl(`${client.apiBaseUrl.replace(/\/+$/, "")}/api/config/hosted`, {
          headers: { authorization: `Bearer ${client.secretKey}` }, cache: "no-store", signal,
        });
        if (!response.ok) throw new Error("Configuration unavailable.");
        return await response.json() as { connector?: unknown };
      });
      const routes = validateConnectorRoutes(config.connector);
      const match = matchConnectorRoute(routes, req.method ?? "", req.originalUrl ?? req.url ?? "");
      if (!match) { canContinue = true; }
      else {
        const { route, params } = match;
        const actor = await withDeadline(evaluationTimeout, async () => options.actor(req));
        if (!actor || !actor.id || actor.authenticated !== true) {
          res.status(401); res.json({ error: "authentication_required" }); return;
        }
        const context = await withDeadline(evaluationTimeout, async () => await options.context?.(req, route, params) ?? {});
        if (route.requiresCount && (!Number.isInteger(context.metadata?.requestedCount) || context.metadata!.requestedCount! < 0)) throw new Error("Export count required.");
        const evaluation = await withDeadline(evaluationTimeout, (signal) => evaluate({
          ...context, actor, operationKey: route.operationKey,
          resource: context.resource ?? { type: route.resourceType, id: route.resourceParam ? params[route.resourceParam] : route.operationKey },
          metadata: { ...context.metadata, connectorRouteId: route.id },
        }, { signal }));
        req.txnshield = { evaluation, session: context.session };
        switch (evaluation.decision) {
          case "allow": canContinue = true; break;
          case "allow_redacted": {
            const directive = evaluation.redaction;
            if (route.responseMode !== "json" || !directive || !Array.isArray(directive.fields) || !directive.fields.length
              || !directive.fields.every((field) => typeof field === "string" && field.split(".").every((segment) => segment && !["__proto__", "prototype", "constructor"].includes(segment)))
              || !["mask", "drop"].includes(directive.strategy)) throw new Error("Cannot enforce redaction.");
            if (!["json", "send", "write", "end", "writeHead"].every((key) => typeof res[key as keyof ConnectorResponse] === "function")) throw new Error("Express response required.");
            guardJsonResponse(res, (payload) => {
              // Resolve serializers before masking so toJSON() cannot reveal unmasked fields later.
              const jsonPayload: unknown = JSON.parse(JSON.stringify(payload));
              if (jsonPayload !== null && typeof jsonPayload !== "object") throw new Error("Structured JSON required for field masking.");
              return redact(jsonPayload, evaluation);
            });
            canContinue = true; break;
          }
          case "step_up_required": res.status(409); res.json({ error: "step_up_required", challenge: evaluation.challenge, telemetryId: evaluation.telemetryId }); break;
          case "throttle": res.status(429); res.json({ error: "transaction_throttled", telemetryId: evaluation.telemetryId }); break;
          case "deny": res.status(403); res.json({ error: "transaction_blocked", telemetryId: evaluation.telemetryId }); break;
          default: throw new Error("Invalid decision.");
        }
      }
    } catch {
      res.status(503); res.json({ error: "protection_unavailable" }); return;
    }
    if (canContinue) next();
  };
}
