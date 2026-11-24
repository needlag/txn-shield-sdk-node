import { authorizeConnectorRequest, validateConnectorOptions, type Evaluate } from "./connector-runtime";
export { matchConnectorRoute, validateConnectorRoutes } from "./connector-routes";
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
export type ConnectorContext = Partial<Pick<TxnShieldEvaluationInput, "resource" | "session" | "metadata" | "challengeResult" | "rawSignals">>;
export type ConnectorOptions = {
  /** Resolve identity using your authentication middleware, never request body/header identity. */
  actor(req: ConnectorRequest): TxnShieldActor | Promise<TxnShieldActor>;
  /** Trusted business context and verified challenges, shared by all protected routes. */
  context?(req: ConnectorRequest, route: ConnectorRoute, params: Record<string, string>): ConnectorContext | Promise<ConnectorContext>;
  configTimeoutMs?: number;
  evaluationTimeoutMs?: number;
};
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
  evaluate: Evaluate,
  redact: (payload: unknown, evaluation: TxnShieldEvaluationResult) => unknown,
  options: ConnectorOptions,
) {
  validateConnectorOptions(options);
  return async (req: ConnectorRequest, res: ConnectorResponse, next: TxnShieldMiddlewareNext): Promise<void> => {
    const result = await authorizeConnectorRequest(client, evaluate, options, {
      method: req.method ?? "", url: req.originalUrl ?? req.url ?? "",
      actor: () => options.actor(req),
      context: (route, params) => options.context?.(req, route, params),
    });
    if (result.kind === "blocked") {
      if (result.evaluation) req.txnshield = { evaluation: result.evaluation, session: result.context?.session };
      res.status(result.status); res.json(result.body); return;
    }
    if (result.kind === "allowed") {
      req.txnshield = { evaluation: result.evaluation, session: result.context.session };
      if (result.evaluation.decision === "allow_redacted") {
        if (!["json", "send", "write", "end", "writeHead"].every((key) => typeof res[key as keyof ConnectorResponse] === "function")) {
          res.status(503); res.json({ error: "protection_unavailable" }); return;
        }
        guardJsonResponse(res, (payload) => {
          const json: unknown = JSON.parse(JSON.stringify(payload));
          if (json !== null && typeof json !== "object") throw new Error("Structured JSON required for field masking.");
          return redact(json, result.evaluation);
        });
      }
    }
    next();
  };
}
