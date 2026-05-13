import type { TxnShieldEvaluationResult, TxnShieldSession } from "./index.js";

declare global {
  namespace Express {
    interface Request {
      txnshield?: {
        evaluation: TxnShieldEvaluationResult;
        session?: TxnShieldSession;
      };
    }
  }
}

export {};
