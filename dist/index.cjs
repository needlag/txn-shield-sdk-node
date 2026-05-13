"use strict";
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var index_exports = {};
__export(index_exports, {
  createTxnShieldNode: () => createTxnShieldNode
});
module.exports = __toCommonJS(index_exports);
function assertSecretKey(secretKey) {
  if (!secretKey.startsWith("txn_sec_")) {
    throw new Error("TxnShield secret keys must start with txn_sec_.");
  }
}
function joinUrl(baseUrl, path) {
  return `${baseUrl.replace(/\/+$/, "")}/${path.replace(/^\/+/, "")}`;
}
function readHeader(req, name) {
  const direct = req.header?.(name) ?? req.get?.(name);
  if (direct) {
    return direct;
  }
  const lowerName = name.toLowerCase();
  const value = req.headers?.[lowerName] ?? req.headers?.[name];
  return Array.isArray(value) ? value[0] : value;
}
function numberFrom(value) {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : void 0;
}
async function parseJsonResponse(response) {
  const text = await response.text();
  if (!text) {
    return {};
  }
  try {
    return JSON.parse(text);
  } catch {
    return { error: text };
  }
}
function assertEvaluationResult(value) {
  const result = value;
  if (!result || typeof result !== "object" || typeof result.decision !== "string" || typeof result.score !== "number" || typeof result.riskBand !== "string" || !Array.isArray(result.reasons) || typeof result.telemetryId !== "string") {
    throw new Error("TxnShield evaluate response was invalid.");
  }
  return result;
}
async function extractChallengeResult(req, handlers) {
  const proofToken = readHeader(req, "x-txnshield-proof-token") ?? (typeof req.body?.challengeProofToken === "string" ? req.body.challengeProofToken : void 0);
  if (proofToken && handlers?.verifyProofToken) {
    return {
      type: "proof_token",
      passed: await handlers.verifyProofToken(proofToken)
    };
  }
  const passkeyAssertion = readHeader(req, "x-txnshield-passkey-assertion") ?? (typeof req.body?.passkeyAssertion === "string" ? req.body.passkeyAssertion : void 0);
  if (passkeyAssertion && handlers?.verifyPasskeyAssertion) {
    return {
      type: "passkey",
      passed: await handlers.verifyPasskeyAssertion(passkeyAssertion)
    };
  }
  return void 0;
}
function maskValue(value) {
  if (typeof value === "string") {
    if (value.length <= 4) {
      return "*".repeat(value.length);
    }
    return `${value.slice(0, 2)}${"*".repeat(value.length - 4)}${value.slice(-2)}`;
  }
  if (typeof value === "number") {
    return 0;
  }
  return null;
}
function redactAtPath(target, segments, strategy) {
  if (!target || segments.length === 0) {
    return;
  }
  if (Array.isArray(target)) {
    for (const item of target) {
      redactAtPath(item, segments, strategy);
    }
    return;
  }
  if (typeof target !== "object") {
    return;
  }
  const [current, ...rest] = segments;
  const record = target;
  if (!current || !(current in record)) {
    return;
  }
  if (rest.length === 0) {
    if (strategy === "drop") {
      delete record[current];
    } else {
      record[current] = maskValue(record[current]);
    }
    return;
  }
  redactAtPath(record[current], rest, strategy);
}
function clone(value) {
  if (typeof structuredClone === "function") {
    return structuredClone(value);
  }
  return JSON.parse(JSON.stringify(value));
}
function createTxnShieldNode(options) {
  assertSecretKey(options.secretKey);
  if (!options.apiBaseUrl) {
    throw new Error("TxnShield apiBaseUrl is required.");
  }
  const fetchImpl = options.fetchImpl ?? fetch;
  const evaluateUrl = joinUrl(options.apiBaseUrl, options.evaluatePath ?? "/api/evaluate");
  const evaluate = async (input) => {
    const response = await fetchImpl(evaluateUrl, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${options.secretKey}`
      },
      body: JSON.stringify(input)
    });
    const payload = await parseJsonResponse(response);
    if (!response.ok) {
      const message = typeof payload.error === "string" ? payload.error : "TxnShield evaluate failed.";
      throw new Error(message);
    }
    return assertEvaluationResult(payload);
  };
  const protect = (definition) => {
    return async (req, res, next) => {
      try {
        const recentHumanSignalAt = readHeader(req, "x-txnshield-recent-human-signal") || void 0;
        const session = definition.session?.(req) ?? {
          sessionId: readHeader(req, "x-txnshield-session-id") || void 0,
          tabId: readHeader(req, "x-txnshield-tab-id") || void 0,
          isNewDevice: false,
          continuityStrength: 1,
          recentHumanSignalAt,
          recentHumanSignalAgeSeconds: recentHumanSignalAt ? Math.max(0, Math.round((Date.now() - new Date(recentHumanSignalAt).getTime()) / 1e3)) : void 0,
          geoChanged: false,
          networkChanged: false,
          ipAddress: req.ip,
          userAgent: readHeader(req, "user-agent") || void 0
        };
        const challengeResult = await extractChallengeResult(req, definition.challenge);
        const evaluation = await evaluate({
          intent: definition.intent,
          actor: {
            authenticated: true,
            roles: [],
            trusted: false,
            ...definition.actor(req)
          },
          resource: definition.resource(req),
          requestData: definition.requestData?.(req) ?? {},
          session,
          metadata: definition.metadata?.(req) ?? {
            requestedCount: numberFrom(req.body?.requestedCount ?? req.query?.requestedCount),
            velocityWindowCount: numberFrom(req.body?.velocityWindowCount ?? req.query?.velocityWindowCount),
            changedFields: Array.isArray(req.body?.changedFields) ? req.body.changedFields.map(String) : []
          },
          challengeResult,
          rawSignals: {}
        });
        req.txnshield = { evaluation, session };
        if (evaluation.decision === "allow" || evaluation.decision === "allow_redacted") {
          next();
          return;
        }
        if (evaluation.decision === "throttle") {
          res.status(429).json({ error: "transaction_throttled", evaluation });
          return;
        }
        if (evaluation.decision === "step_up_required") {
          res.status(409).json({
            error: "step_up_required",
            challenge: evaluation.challenge,
            evaluation
          });
          return;
        }
        res.status(403).json({ error: "transaction_blocked", evaluation });
      } catch (error) {
        next(error);
      }
    };
  };
  return {
    evaluate,
    protect,
    redact(payload, evaluation) {
      if (!evaluation.redaction) {
        return payload;
      }
      const redacted = clone(payload);
      for (const field of evaluation.redaction.fields) {
        redactAtPath(redacted, field.split("."), evaluation.redaction.strategy);
      }
      return redacted;
    }
  };
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  createTxnShieldNode
});
