type TxnDecision = "allow" | "allow_redacted" | "step_up_required" | "throttle" | "deny";
type RiskBand = "low" | "medium" | "high";
type ChallengeType = "passkey" | "proof_token" | "interactive_challenge";
type RedactionStrategy = "mask" | "drop";
type TxnShieldActor = {
    id: string;
    authenticated?: boolean;
    role?: string;
    roles?: string[];
    sessionAgeMinutes?: number;
    trusted?: boolean;
};
type TxnShieldResource = {
    type: string;
    id: string;
    ownerId?: string;
    classification?: string;
};
type TxnShieldSession = {
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
type TxnShieldEvaluationInput = {
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
type TxnShieldEvaluationResult = {
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
type CreateTxnShieldNodeOptions = {
    secretKey: string;
    apiBaseUrl: string;
    evaluatePath?: string;
    fetchImpl?: typeof fetch;
};
type HeaderReader = {
    header?: (name: string) => string | undefined;
    get?: (name: string) => string | null;
};
type TxnShieldMiddlewareRequest = {
    body?: Record<string, unknown>;
    query?: Record<string, unknown>;
    params?: Record<string, string | undefined>;
    headers?: Record<string, string | string[] | undefined>;
    ip?: string;
    user?: {
        id?: string;
        role?: string;
        roles?: string[];
    };
    txnshield?: {
        evaluation: TxnShieldEvaluationResult;
        session?: TxnShieldSession;
    };
} & HeaderReader;
type TxnShieldMiddlewareResponse = {
    status: (statusCode: number) => {
        json: (payload: unknown) => unknown;
    };
};
type TxnShieldMiddlewareNext = (error?: unknown) => void;
type TxnShieldMiddleware = (req: TxnShieldMiddlewareRequest, res: TxnShieldMiddlewareResponse, next: TxnShieldMiddlewareNext) => Promise<void>;
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
declare function createTxnShieldNode(options: CreateTxnShieldNodeOptions): {
    evaluate: (input: TxnShieldEvaluationInput) => Promise<TxnShieldEvaluationResult>;
    protect: (definition: ProtectRouteOptions) => TxnShieldMiddleware;
    redact<T>(payload: T, evaluation: {
        redaction?: {
            fields: string[];
            strategy: RedactionStrategy;
        };
    }): T;
};

export { type ChallengeType, type CreateTxnShieldNodeOptions, type RedactionStrategy, type RiskBand, type TxnDecision, type TxnShieldActor, type TxnShieldEvaluationInput, type TxnShieldEvaluationResult, type TxnShieldMiddleware, type TxnShieldMiddlewareNext, type TxnShieldMiddlewareRequest, type TxnShieldMiddlewareResponse, type TxnShieldResource, type TxnShieldSession, createTxnShieldNode };
