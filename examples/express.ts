import express from "express";
import { createTxnShieldNode } from "@txnshield/sdk-node";

const app = express();
app.use(express.json());

const shield = createTxnShieldNode({
  secretKey: process.env.TXNSHIELD_SECRET_KEY!,
  apiBaseUrl: process.env.TXNSHIELD_API_BASE_URL ?? "https://api.txnshield.com",
});

app.post(
  "/customers/:id/export",
  shield.protect({
    operationKey: "invoice.export",
    actor: (req) => ({ id: req.user?.id ?? "anonymous", roles: ["support"] }),
    resource: (req) => ({ type: "customer", id: req.params.id }),
    requestData: (req) => ({ requestedCount: Number(req.body.requestedCount ?? 1) }),
  }),
  (_req, res) => res.json({ ok: true }),
);
