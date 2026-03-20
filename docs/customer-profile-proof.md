# Customer Profile Proof

This pass adds durable customer profiles, explicit consent capture, and admin lookup endpoints.

## Live flow

The onboarding flow now captures consent explicitly before the second-part website satisfaction prompt.

States:

1. `Q2_AUDIT_EMAIL_OPTIN` or `Q2_CONFIRM_OWNERSHIP`
2. `Q2_CONSENT_TRAINING`
3. `Q2_CONSENT_MARKETING`
4. `Q2_HAPPY_COSTS`

Prompt text now includes:

- Training consent:
  - `One quick privacy question: can I save this conversation and the site preferences you share so the builder can learn your style and improve future builds for you? (yes/no)`
- Marketing consent:
  - `Last one: do you want occasional follow-up about new site-builder features, templates, or launch updates? (yes/no)`

## Durable D1 tables

Migration:

- [0013_customers_and_consents.sql](/Users/root1/Sitebuilder1.0/migrations/0013_customers_and_consents.sql)

Tables created:

- `customers`
- `customer_identities`
- `customer_sessions`

## Admin lookup endpoint

Token-protected endpoint:

- `GET /admin/customers/lookup`

Supported query params:

- `email`
- `wallet`
- `wallet_chain_id`
- `session_id`

Internal admin page:

- [customers.html](/Users/root1/Sitebuilder1.0/public/admin/customers.html)
- [customer-edit.html](/Users/root1/Sitebuilder1.0/public/admin/customer-edit.html)

Additional admin routes:

- `GET /admin/customers`
- `GET /admin/customers/:customer_id`
- `PATCH /admin/customers/:customer_id`

Example:

```bash
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
  "https://sitebuilder-agent.96psxbzqk2.workers.dev/admin/customers/lookup?email=owner@example.com"
```

## Proof in tests

The following tests pass in [worker.test.js](/Users/root1/Sitebuilder1.0/tests/worker.test.js):

- `q1/start creates durable customer profile records`
- `Q2_AUDIT_EMAIL_OPTIN saves choices and continues to second part`
- `repeat sessions link to the same customer by normalized email identity`
- `Q2_CONSENT_TRAINING saves explicit training consent and advances`
- `Q2_CONSENT_MARKETING saves explicit marketing consent and advances`
- `admin customer lookup requires a query key`
- `admin customer lookup returns customer by email`
- `admin customer lookup returns customer by session_id`
- `admin customer lookup returns customer by wallet`
- `admin customer list supports search and pagination`
- `admin customer detail returns identities and sessions`
- `admin customer patch updates consent flags and notes`

Test command:

```bash
npm test
```

Expected result for this pass:

- `128/128` passing

## Manual verification

1. Start a new onboarding session with `/q1/start`.
2. Move through website ownership or audit flow.
3. Answer the new training and marketing consent prompts.
4. Use `/admin/customers/lookup` with the session email or session id.
5. Confirm the resulting `customer_id` persists across a later session that reuses the same email or wallet identity.
