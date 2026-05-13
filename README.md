# `@txnshield/sdk-node`

Node-first runtime SDK for TxnShield.

It provides:

- hosted transaction evaluation against your TxnShield SaaS
- Express middleware for protected routes
- decision-aware redaction helpers
- optional challenge verification hooks

Example:

```ts
import { createTxnShieldNode } from "@txnshield/sdk-node";

const shield = createTxnShieldNode({
  secretKey: process.env.TXNSHIELD_SECRET_KEY!,
  apiBaseUrl: "https://api.txnshield.com",
});

const result = await shield.evaluate({
  intent: "export_customers",
  actor: { id: "user_123", authenticated: true, roles: ["finance_manager"] },
  resource: { type: "customer_export", id: "batch_123" },
  requestData: { requestedCount: 250 },
});
```
