export type TxnDecision = "allow" | "allow_redacted" | "step_up_required" | "throttle" | "deny";
export type RiskBand = "low" | "medium" | "high";
export type ChallengeType = "passkey" | "proof_token" | "interactive_challenge";
export type RedactionStrategy = "mask" | "drop";

export type TxnShieldActor = {
  id: string;
  authenticated?: boolean;
  role?: string;
  roles?: string[];
  sessionAgeMinutes?: number;
  trusted?: boolean;
};

export type TxnShieldResource = {
  type: string;
  id: string;
  ownerId?: string;
  classification?: string;
};

export type TxnShieldSession = {
  sessionId?: string;
  tabId?: string;
  isNewDevice?: boolean;
  continuityStrength?: number;
  recentHumanSignalAt?: string;
  recentHumanSignalAgeSeconds?: number;
  geoChanged?: boolean;
  networkChanged?: boolean;
  ipAddress?: string;
  userAgent?: string;
};

export type TxnShieldEvaluationInput = {
  intent: string;
  actor: TxnShieldActor;
  resource: TxnShieldResource;
  requestData?: Record<string, unknown>;
  session?: TxnShieldSession;
  metadata?: {
    requestedCount?: number;
    velocityWindowCount?: number;
    abnormalSequence?: boolean;
    objectAccessRare?: boolean;
    suspiciousTimeWindow?: boolean;
    localHour?: number;
    changedFields?: string[];
    resourceCount?: number;
    proofToken?: string;
    notes?: string;
  };
  challengeResult?: {
    type: ChallengeType;
    passed: boolean;
  };
  rawSignals?: Record<string, boolean | number>;
};

export type TxnShieldEvaluationResult = {
  decision: TxnDecision;
  score: number;
  riskBand: RiskBand;
  reasons: string[];
  challenge?: {
    type: ChallengeType;
    id: string;
  };
  redaction?: {
    fields: string[];
    strategy: RedactionStrategy;
  };
  telemetryId: string;
  policyVersionId?: string;
  aiAssessment?: {
    provider: string;
    mode: "disabled" | "byok" | "managed";
    status: "disabled" | "ok" | "unavailable";
    scoreDelta: number;
    reasons: string[];
    summary: Record<string, unknown>;
  };
};

export type CreateTxnShieldNodeOptions = {
  secretKey: string;
  apiBaseUrl: string;
  evaluatePath?: string;
  fetchImpl?: typeof fetch;
};

type HeaderReader = {
  header?: (name: string) => string | undefined;
  get?: (name: string) => string | null;
};

export type TxnShieldMiddlewareRequest = {
  body?: Record<string, unknown>;
  query?: Record<string, unknown>;
  params?: Record<string, string | undefined>;
  headers?: Record<string, string | string[] | undefined>;
  ip?: string;
  user?: { id?: string; role?: string; roles?: string[] };
  txnshield?: {
    evaluation: TxnShieldEvaluationResult;
    session?: TxnShieldSession;
  };
} & HeaderReader;

export type TxnShieldMiddlewareResponse = {
  status: (statusCode: number) => {
    json: (payload: unknown) => unknown;
  };
};

export type TxnShieldMiddlewareNext = (error?: unknown) => void;
export type TxnShieldMiddleware = (
  req: TxnShieldMiddlewareRequest,
  res: TxnShieldMiddlewareResponse,
  next: TxnShieldMiddlewareNext,
) => Promise<void>;

type ChallengeHandlers = {
  verifyProofToken?: (token: string) => boolean | Promise<boolean>;
  verifyPasskeyAssertion?: (assertion: string) => boolean | Promise<boolean>;
};

type ProtectRouteOptions = {
  intent: string;
  resource: (req: TxnShieldMiddlewareRequest) => TxnShieldResource;
  actor: (req: TxnShieldMiddlewareRequest) => TxnShieldActor;
  requestData?: (req: TxnShieldMiddlewareRequest) => Record<string, unknown>;
  session?: (req: TxnShieldMiddlewareRequest) => TxnShieldSession;
  metadata?: (req: TxnShieldMiddlewareRequest) => TxnShieldEvaluationInput["metadata"];
  challenge?: ChallengeHandlers;
};

function assertSecretKey(secretKey: string) {
  if (!secretKey.startsWith("txn_sec_")) {
    throw new Error("TxnShield secret keys must start with txn_sec_.");
  }
}

function joinUrl(baseUrl: string, path: string) {
  return `${baseUrl.replace(/\/+$/, "")}/${path.replace(/^\/+/, "")}`;
}

function readHeader(req: TxnShieldMiddlewareRequest, name: string) {
  const direct = req.header?.(name) ?? req.get?.(name);
  if (direct) {
    return direct;
  }

  const lowerName = name.toLowerCase();
  const value = req.headers?.[lowerName] ?? req.headers?.[name];
  return Array.isArray(value) ? value[0] : value;
}

function numberFrom(value: unknown) {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : undefined;
}

async function parseJsonResponse(response: Response) {
  const text = await response.text();
  if (!text) {
    return {};
  }

  try {
    return JSON.parse(text) as Record<string, unknown>;
  } catch {
    return { error: text };
  }
}

function assertEvaluationResult(value: unknown): TxnShieldEvaluationResult {
  const result = value as Partial<TxnShieldEvaluationResult>;
  if (
    !result ||
    typeof result !== "object" ||
    typeof result.decision !== "string" ||
    typeof result.score !== "number" ||
    typeof result.riskBand !== "string" ||
    !Array.isArray(result.reasons) ||
    typeof result.telemetryId !== "string"
  ) {
    throw new Error("TxnShield evaluate response was invalid.");
  }

  return result as TxnShieldEvaluationResult;
}

async function extractChallengeResult(
  req: TxnShieldMiddlewareRequest,
  handlers?: ChallengeHandlers,
): Promise<TxnShieldEvaluationInput["challengeResult"] | undefined> {
  const proofToken =
    readHeader(req, "x-txnshield-proof-token") ??
    (typeof req.body?.challengeProofToken === "string" ? req.body.challengeProofToken : undefined);
  if (proofToken && handlers?.verifyProofToken) {
    return {
      type: "proof_token",
      passed: await handlers.verifyProofToken(proofToken),
    };
  }

  const passkeyAssertion =
    readHeader(req, "x-txnshield-passkey-assertion") ??
    (typeof req.body?.passkeyAssertion === "string" ? req.body.passkeyAssertion : undefined);
  if (passkeyAssertion && handlers?.verifyPasskeyAssertion) {
    return {
      type: "passkey",
      passed: await handlers.verifyPasskeyAssertion(passkeyAssertion),
    };
  }

  return undefined;
}

function maskValue(value: unknown) {
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

function redactAtPath(target: unknown, segments: string[], strategy: RedactionStrategy) {
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
  const record = target as Record<string, unknown>;
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

function clone<T>(value: T) {
  if (typeof structuredClone === "function") {
    return structuredClone(value);
  }

  return JSON.parse(JSON.stringify(value)) as T;
}

export function createTxnShieldNode(options: CreateTxnShieldNodeOptions) {
  assertSecretKey(options.secretKey);

  if (!options.apiBaseUrl) {
    throw new Error("TxnShield apiBaseUrl is required.");
  }

  const fetchImpl = options.fetchImpl ?? fetch;
  const evaluateUrl = joinUrl(options.apiBaseUrl, options.evaluatePath ?? "/api/evaluate");

  const evaluate = async (input: TxnShieldEvaluationInput) => {
    const response = await fetchImpl(evaluateUrl, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${options.secretKey}`,
      },
      body: JSON.stringify(input),
    });
    const payload = await parseJsonResponse(response);

    if (!response.ok) {
      const message = typeof payload.error === "string" ? payload.error : "TxnShield evaluate failed.";
      throw new Error(message);
    }

    return assertEvaluationResult(payload);
  };

  const protect = (definition: ProtectRouteOptions): TxnShieldMiddleware => {
    return async (req, res, next) => {
      try {
        const recentHumanSignalAt = readHeader(req, "x-txnshield-recent-human-signal") || undefined;
        const session =
          definition.session?.(req) ??
          ({
            sessionId: readHeader(req, "x-txnshield-session-id") || undefined,
            tabId: readHeader(req, "x-txnshield-tab-id") || undefined,
            isNewDevice: false,
            continuityStrength: 1,
            recentHumanSignalAt,
            recentHumanSignalAgeSeconds: recentHumanSignalAt
              ? Math.max(0, Math.round((Date.now() - new Date(recentHumanSignalAt).getTime()) / 1000))
              : undefined,
            geoChanged: false,
            networkChanged: false,
            ipAddress: req.ip,
            userAgent: readHeader(req, "user-agent") || undefined,
          } satisfies TxnShieldSession);

        const challengeResult = await extractChallengeResult(req, definition.challenge);
        const evaluation = await evaluate({
          intent: definition.intent,
          actor: {
            authenticated: true,
            roles: [],
            trusted: false,
            ...definition.actor(req),
          },
          resource: definition.resource(req),
          requestData: definition.requestData?.(req) ?? {},
          session,
          metadata: definition.metadata?.(req) ?? {
            requestedCount: numberFrom(req.body?.requestedCount ?? req.query?.requestedCount),
            velocityWindowCount: numberFrom(req.body?.velocityWindowCount ?? req.query?.velocityWindowCount),
            changedFields: Array.isArray(req.body?.changedFields) ? req.body.changedFields.map(String) : [],
          },
          challengeResult,
          rawSignals: {},
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
            evaluation,
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
    redact<T>(payload: T, evaluation: { redaction?: { fields: string[]; strategy: RedactionStrategy } }) {
      if (!evaluation.redaction) {
        return payload;
      }

      const redacted = clone(payload);
      for (const field of evaluation.redaction.fields) {
        redactAtPath(redacted, field.split("."), evaluation.redaction.strategy);
      }
      return redacted;
    },
  };
}
