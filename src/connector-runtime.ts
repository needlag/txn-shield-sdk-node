import type { CreateTxnShieldNodeOptions, TxnShieldActor, TxnShieldEvaluationInput, TxnShieldEvaluationResult } from "./index";
import type { ConnectorContext, ConnectorRoute } from "./connector";
import { matchConnectorRoute, validateConnectorRoutes } from "./connector-routes";

export type Evaluate = (input: TxnShieldEvaluationInput, options?: { signal?: AbortSignal }) => Promise<TxnShieldEvaluationResult>;
export type ConnectorTimeouts = { configTimeoutMs?: number; evaluationTimeoutMs?: number };
type Authorization =
  | { kind: "unmapped" }
  | { kind: "blocked"; status: number; evaluation?: TxnShieldEvaluationResult; context?: ConnectorContext; body: { error: string; challenge?: TxnShieldEvaluationResult["challenge"]; telemetryId?: string } }
  | { kind: "allowed"; evaluation: TxnShieldEvaluationResult; context: ConnectorContext; route: ConnectorRoute };

export function validateConnectorOptions(options: ConnectorTimeouts & { actor: unknown }) {
  if (typeof options.actor !== "function") throw new Error("The connector requires an authenticated actor resolver.");
  if (![options.configTimeoutMs ?? 5000, options.evaluationTimeoutMs ?? 35000].every((ms) => Number.isFinite(ms) && ms >= 1 && ms <= 60000)) {
    throw new Error("Invalid connector timeout.");
  }
}

export async function withDeadline<T>(ms: number, work: (signal: AbortSignal) => Promise<T>): Promise<T> {
  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([work(controller.signal), new Promise<never>((_, reject) => {
      timer = setTimeout(() => { controller.abort(); reject(new Error("TxnShield timed out.")); }, ms);
    })]);
  } finally { clearTimeout(timer); }
}

export async function authorizeConnectorRequest(
  client: CreateTxnShieldNodeOptions, evaluate: Evaluate, timeouts: ConnectorTimeouts,
  request: {
    method: string; url: string;
    actor: () => TxnShieldActor | Promise<TxnShieldActor>;
    context: (route: ConnectorRoute, params: Record<string, string>) => ConnectorContext | Promise<ConnectorContext> | undefined;
  },
): Promise<Authorization> {
  const evaluationTimeout = timeouts.evaluationTimeoutMs ?? 35000;
  try {
    // Fresh configuration prevents newly protected routes passing through stale maps.
    const config = await withDeadline(timeouts.configTimeoutMs ?? 5000, async (signal) => {
      const response = await (client.fetchImpl ?? fetch)(`${client.apiBaseUrl.replace(/\/+$/, "")}/api/config/hosted`, {
        headers: { authorization: `Bearer ${client.secretKey}` }, cache: "no-store", signal,
      });
      if (!response.ok) throw new Error("Configuration unavailable.");
      return await response.json() as { connector?: unknown };
    });
    const match = matchConnectorRoute(validateConnectorRoutes(config.connector), request.method, request.url);
    if (!match) return { kind: "unmapped" };
    const { route, params } = match;
    const actor = await withDeadline(evaluationTimeout, async () => request.actor());
    if (!actor?.id || actor.authenticated !== true) return { kind: "blocked", status: 401, body: { error: "authentication_required" } };
    const context = await withDeadline(evaluationTimeout, async () => await request.context(route, params) ?? {});
    if (route.requiresCount && (!Number.isInteger(context.metadata?.requestedCount) || context.metadata!.requestedCount! < 0)) {
      throw new Error("Export count required.");
    }
    const evaluation = await withDeadline(evaluationTimeout, (signal) => evaluate({
      ...context, actor, operationKey: route.operationKey,
      resource: context.resource ?? { type: route.resourceType, id: route.resourceParam ? params[route.resourceParam] : route.operationKey },
      metadata: { ...context.metadata, connectorRouteId: route.id },
    }, { signal }));
    switch (evaluation.decision) {
      case "allow": return { kind: "allowed", evaluation, context, route };
      case "allow_redacted": {
        const directive = evaluation.redaction;
        if (route.responseMode !== "json" || !directive || !Array.isArray(directive.fields) || !directive.fields.length
          || !directive.fields.every((field) => typeof field === "string" && field.split(".").every((part) => part && !["__proto__", "prototype", "constructor"].includes(part)))
          || !["mask", "drop"].includes(directive.strategy)) throw new Error("Cannot enforce redaction.");
        return { kind: "allowed", evaluation, context, route };
      }
      case "deny": return { kind: "blocked", evaluation, context, status: 403, body: { error: "transaction_blocked", telemetryId: evaluation.telemetryId } };
      case "throttle": return { kind: "blocked", evaluation, context, status: 429, body: { error: "transaction_throttled", telemetryId: evaluation.telemetryId } };
      case "step_up_required": return { kind: "blocked", evaluation, context, status: 409, body: { error: "step_up_required", challenge: evaluation.challenge, telemetryId: evaluation.telemetryId } };
      default: throw new Error("Invalid decision.");
    }
  } catch {
    return { kind: "blocked", status: 503, body: { error: "protection_unavailable" } };
  }
}
