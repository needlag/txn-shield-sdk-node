# @txnshield/sdk-node Changelog

## 0.5.0

- Add `route(options, existingHandler)` for Next.js App Router in the Node.js runtime, preserving native requests, asynchronous route parameters and handler exceptions.
- Share dashboard route matching and authorization with Express. Stop blocked requests before business logic and perform bounded JSON redaction before releasing responses.
- Prevent caching of mapped responses and fail closed on invalid/oversized redaction responses.
- Document minimal handler integration, response limits and assisted setup prompts. Existing `connector`, `evaluate` and `protect` APIs remain available.

## 0.1.0

- Pre-launch monorepo package prepared for npm publishing and future standalone extraction.
- Provides local policy evaluation, Express middleware, redaction helper, challenge result handling, and control-plane event publishing.
