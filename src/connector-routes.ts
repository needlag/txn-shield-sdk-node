import type { ConnectorRoute } from "./connector";

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

