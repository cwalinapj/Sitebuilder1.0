import assert from "node:assert/strict";
import test from "node:test";
import { createHash, createHmac } from "node:crypto";
import { privateKeyToAccount } from "viem/accounts";

import worker from "../worker/index.js";

function createMockDb({ firstResponses = [], allResponses = [] } = {}) {
  const statements = [];
  const firstQueue = [...firstResponses];
  const allQueue = [...allResponses];

  return {
    statements,
    prepare(sql) {
      return {
        bind(...params) {
          return {
            async run() {
              statements.push({ sql, params, op: "run" });
              return { success: true };
            },
            async first() {
              statements.push({ sql, params, op: "first" });
              return firstQueue.shift() ?? null;
            },
            async all() {
              statements.push({ sql, params, op: "all" });
              return allQueue.shift() ?? { results: [] };
            },
          };
        },
      };
    },
  };
}

function buildSessionRow({
  ownSiteUrl = "https://acme.example",
  sitePlatform = null,
  isWordpress = false,
  typeFinal = "dive services",
  descriptionRaw = null,
} = {}) {
  return {
    independent_json: JSON.stringify({
      session_created_at: 1704067200000,
      person: { first_name: "Paul", last_name: "Cwalina", geo: { city: "Miami", region: "FL", country: "US" } },
      business: {
        description_raw: descriptionRaw,
        type_final: typeFinal,
        own_site_url: ownSiteUrl,
        site_platform: sitePlatform,
        is_wordpress: isWordpress,
        wants_site_scan: null,
      },
      demo: { last_demo_url: null, q1_vibe: null, q2_colors: null, q3_layout: null },
      style: { willing_to_view_examples: null },
      build: {
        website_guess: null,
        business_name: "Blue Reef Dive",
        goal: "bookings",
        vibe: "modern",
        service_area: "Miami, FL",
        phone: null,
        email: null,
      },
    }),
    dependent_json: JSON.stringify({
      draft: { type_guess: "restaurant" },
      name_proposals: [],
      scan: { status: null, request_id: null, latest_summary: null },
      research: { location_hint: "Miami, FL, US", sites: [], source: null },
      design: { liked: [], disliked: [], palette_hints: [], layout_hints: [], font_hints: [], raw_feedback: [], reference_feedback: [] },
      demo_build: { key: null, url: null },
    }),
    updated_at: 1704067200000,
  };
}

function withExpectedState(row, expectedState) {
  const independent = JSON.parse(row.independent_json);
  const dependent = JSON.parse(row.dependent_json);
  dependent.flow = { expected_state: expectedState };
  return {
    ...row,
    independent_json: JSON.stringify(independent),
    dependent_json: JSON.stringify(dependent),
  };
}

function withDemoUrl(row, demoUrl = "https://example-demo.test") {
  const independent = JSON.parse(row.independent_json);
  independent.demo = independent.demo || {};
  independent.demo.last_demo_url = demoUrl;
  return {
    ...row,
    independent_json: JSON.stringify(independent),
  };
}

function signPluginPayload(secret, timestamp, payload) {
  return createHmac("sha256", secret).update(`${timestamp}.${payload}`).digest("hex");
}

async function encryptVaultTokenForTest(secretText, keySecret) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(String(keySecret || "")));
  const key = await crypto.subtle.importKey("raw", digest, { name: "AES-GCM" }, false, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode(String(secretText || ""));
  const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext);
  const toB64 = (bytes) => Buffer.from(bytes).toString("base64");
  return `${toB64(iv)}.${toB64(new Uint8Array(cipher))}`;
}

test("q1/start rejects invalid first/last names", async () => {
  const db = createMockDb();
  const req = new Request("https://worker.example/q1/start", {
    method: "POST",
    headers: { "content-type": "application/json", "CF-Connecting-IP": "203.0.113.10" },
    body: JSON.stringify({ FirstName: "John3", LastName: "Doe" }),
  });

  const response = await worker.fetch(req, { DB: db });
  const body = await response.json();

  assert.equal(response.status, 400);
  assert.match(body.error, /FirstName/);
  assert.equal(db.statements.length, 0);
});

test("q1/start rejects short first/last names with explicit minimums", async () => {
  const db = createMockDb();
  const req = new Request("https://worker.example/q1/start", {
    method: "POST",
    headers: { "content-type": "application/json", "CF-Connecting-IP": "203.0.113.11" },
    body: JSON.stringify({ FirstName: "A", LastName: "Li" }),
  });

  const response = await worker.fetch(req, { DB: db });
  const body = await response.json();

  assert.equal(response.status, 400);
  assert.match(body.error, /FirstName must be at least 2 letters long/);
  assert.equal(db.statements.length, 0);
});

test("q1/start rejects last names shorter than 4 letters", async () => {
  const db = createMockDb();
  const req = new Request("https://worker.example/q1/start", {
    method: "POST",
    headers: { "content-type": "application/json", "CF-Connecting-IP": "203.0.113.14" },
    body: JSON.stringify({ FirstName: "John", LastName: "Li" }),
  });

  const response = await worker.fetch(req, { DB: db });
  const body = await response.json();

  assert.equal(response.status, 400);
  assert.match(body.error, /LastName must be at least 4 letters long/);
  assert.equal(db.statements.length, 0);
});

test("q1/start rejects blocked language in names", async () => {
  const db = createMockDb();
  const req = new Request("https://worker.example/q1/start", {
    method: "POST",
    headers: { "content-type": "application/json", "CF-Connecting-IP": "203.0.113.12" },
    body: JSON.stringify({ FirstName: "Fart", LastName: "Walker" }),
  });

  const response = await worker.fetch(req, { DB: db });
  const body = await response.json();

  assert.equal(response.status, 400);
  assert.match(body.error, /contains blocked language/);
  assert.equal(db.statements.length, 0);
});

test("q1/start rate limits burst attempts per ip", async () => {
  const db = createMockDb();
  let lastResponse = null;

  for (let i = 0; i < 13; i += 1) {
    const req = new Request("https://worker.example/q1/start", {
      method: "POST",
      headers: { "content-type": "application/json", "CF-Connecting-IP": "203.0.113.13" },
      body: JSON.stringify({ FirstName: "A", LastName: "Li" }),
    });
    lastResponse = await worker.fetch(req, { DB: db });
  }

  assert.ok(lastResponse);
  const body = await lastResponse.json();
  assert.equal(lastResponse.status, 429);
  assert.match(body.error, /Too many start attempts/);
});

test("security config exposes turnstile requirement and site key", async () => {
  const db = createMockDb();
  const req = new Request("https://worker.example/security/config");
  const response = await worker.fetch(req, {
    DB: db,
    TURNSTILE_SITE_KEY: "site-key-123",
    TURNSTILE_SECRET_KEY: "secret-key-123",
  });
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.ok, true);
  assert.equal(body.turnstile_required, true);
  assert.equal(body.turnstile_site_key, "site-key-123");
  assert.equal(body.wallet_login_enabled, true);
  assert.equal(Array.isArray(body.wallet_supported_methods), true);
});

test("auth/wallet/challenge returns nonce and signable message", async () => {
  const db = createMockDb();
  const req = new Request("https://worker.example/auth/wallet/challenge?provider=metamask&protocol=evm", {
    method: "GET",
    headers: { "CF-Connecting-IP": "203.0.113.30" },
  });
  const response = await worker.fetch(req, { DB: db });
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.ok, true);
  assert.equal(body.provider, "metamask");
  assert.equal(body.protocol, "evm");
  assert.match(String(body.nonce || ""), /^[A-Za-z0-9_-]{16,}$/);
  assert.match(String(body.message || ""), /Sitebuilder Wallet Sign-In/);
});

test("billing config exposes hybrid pricing model", async () => {
  const db = createMockDb();
  const req = new Request("https://worker.example/billing/config");
  const response = await worker.fetch(req, {
    DB: db,
    PREMIUM_SPL_SYMBOL: "SITE",
    PREMIUM_POINTS_SYMBOL: "APPPTS",
    PREMIUM_FREE_TOKENS: "1500",
    PREMIUM_FREE_POINTS: "900",
  });
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.ok, true);
  assert.equal(body.model, "hybrid_spl_points_v1");
  assert.equal(body.spl_symbol, "SITE");
  assert.equal(body.points_symbol, "APPPTS");
  assert.equal(body.free_tokens, 1500);
  assert.equal(body.free_points, 900);
  assert.equal(body.points_enabled, true);
  assert.ok(body.pricing_model);
  assert.equal(Object.prototype.hasOwnProperty.call(body.pricing_model, "points_per_token"), false);
  assert.ok(Array.isArray(body.points_packs));
  assert.ok(body.points_packs.length >= 1);
});

test("billing status returns wallet-gated balance snapshot", async () => {
  const row = buildSessionRow({ ownSiteUrl: null });
  const independent = JSON.parse(row.independent_json);
  const dependent = JSON.parse(row.dependent_json);
  independent.person.auth_method = "wallet";
  independent.person.wallet = { address: "0x1111111111111111111111111111111111111111" };
  dependent.billing = { token_balance: 777, tokens_spent: 90, premium_enabled: true };
  const sessionRow = {
    ...row,
    independent_json: JSON.stringify(independent),
    dependent_json: JSON.stringify(dependent),
  };

  const db = createMockDb({ firstResponses: [sessionRow, { m: 0 }] });
  const req = new Request("https://worker.example/billing/status?session_id=ses_bill_1");
  const response = await worker.fetch(req, { DB: db });
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.ok, true);
  assert.equal(body.billing.token_balance, 777);
  assert.equal(body.billing.active_unit, "tokens");
  assert.equal(body.billing.premium_enabled, true);
  assert.equal(Object.prototype.hasOwnProperty.call(body.billing, "points_per_token"), false);
  assert.equal(Object.prototype.hasOwnProperty.call(body.billing, "tokens_per_spl"), false);
});

test("q1/start requires turnstile token when configured", async () => {
  const db = createMockDb();
  const req = new Request("https://worker.example/q1/start", {
    method: "POST",
    headers: { "content-type": "application/json", "CF-Connecting-IP": "203.0.113.31" },
    body: JSON.stringify({ FirstName: "John", LastName: "Smith" }),
  });

  const response = await worker.fetch(req, {
    DB: db,
    TURNSTILE_SITE_KEY: "site-key-123",
    TURNSTILE_SECRET_KEY: "secret-key-123",
  });
  const body = await response.json();

  assert.equal(response.status, 403);
  assert.match(body.error, /Security verification token missing/);
});

test("q1/start accepts verified turnstile token when configured", async () => {
  const db = createMockDb({ firstResponses: [{ m: 0 }, { m: 1 }] });
  const originalFetch = globalThis.fetch;

  globalThis.fetch = async (target) => {
    if (String(target).includes("challenges.cloudflare.com/turnstile/v0/siteverify")) {
      return new Response(
        JSON.stringify({ success: true, action: "start", hostname: "sitebuilder1-03.pages.dev" }),
        { status: 200, headers: { "content-type": "application/json" } }
      );
    }
    return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
  };

  try {
    const req = new Request("https://worker.example/q1/start", {
      method: "POST",
      headers: { "content-type": "application/json", "CF-Connecting-IP": "203.0.113.32" },
      body: JSON.stringify({ FirstName: "John", LastName: "Smith", turnstile_token: "token-abc" }),
    });

    const response = await worker.fetch(req, {
      DB: db,
      TURNSTILE_SITE_KEY: "site-key-123",
      TURNSTILE_SECRET_KEY: "secret-key-123",
    });
    const body = await response.json();

    assert.equal(response.status, 200);
    assert.equal(body.ok, true);
    assert.equal(body.next_state, "Q1_DESCRIBE");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("q1/start accepts wallet login with verified EVM signature and blocks replay", async () => {
  const db = createMockDb({ firstResponses: [{ m: 0 }, { m: 1 }, { m: 2 }, { m: 3 }] });
  const account = privateKeyToAccount("0x59c6995e998f97a5a0044966f094538c5f8f57a96af3d6fdbf9f7a2d4fd0a3d4");

  const challengeReq = new Request("https://worker.example/auth/wallet/challenge?provider=metamask&protocol=evm", {
    method: "GET",
    headers: { "CF-Connecting-IP": "203.0.113.77" },
  });
  const challengeRes = await worker.fetch(challengeReq, { DB: db });
  const challengeBody = await challengeRes.json();
  assert.equal(challengeRes.status, 200);
  assert.equal(challengeBody.ok, true);

  const signature = await account.signMessage({ message: challengeBody.message });
  const startPayload = {
    login_method: "wallet",
    wallet_auth: {
      provider: "metamask",
      protocol: "evm",
      address: account.address,
      chain_id: 1,
      nonce: challengeBody.nonce,
      message: challengeBody.message,
      signature,
    },
  };

  const startReq = new Request("https://worker.example/q1/start", {
    method: "POST",
    headers: { "content-type": "application/json", "CF-Connecting-IP": "203.0.113.77" },
    body: JSON.stringify(startPayload),
  });
  const startRes = await worker.fetch(startReq, { DB: db });
  const startBody = await startRes.json();
  assert.equal(startRes.status, 200);
  assert.equal(startBody.ok, true);
  assert.equal(startBody.next_state, "Q1_DESCRIBE");

  const replayReq = new Request("https://worker.example/q1/start", {
    method: "POST",
    headers: { "content-type": "application/json", "CF-Connecting-IP": "203.0.113.77" },
    body: JSON.stringify(startPayload),
  });
  const replayRes = await worker.fetch(replayReq, { DB: db });
  const replayBody = await replayRes.json();
  assert.equal(replayRes.status, 401);
  assert.match(String(replayBody.error || ""), /already used/i);
});

test("premium builder request returns quote and enters confirm state", async () => {
  const sessionRow = withExpectedState(buildSessionRow({ ownSiteUrl: null }), "Q3_VIEW_EXAMPLES_YN");
  const db = createMockDb({
    firstResponses: [sessionRow, { m: 0 }, { m: 1 }],
  });
  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_premium_quote_1",
      state: "Q3_VIEW_EXAMPLES_YN",
      answer:
        "Build a modern premium website with Next.js App Router TypeScript Tailwind with 5 pages and Gumroad checkout.",
    }),
  });
  const response = await worker.fetch(req, { DB: db });
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.next_state, "Q_PREMIUM_CONFIRM");
  assert.ok(body.premium_quote);
  assert.equal(body.premium_quote.charge_unit, "points");
  assert.ok(Number(body.premium_quote.charge_amount) > 0);
  assert.equal(Object.prototype.hasOwnProperty.call(body.premium_quote, "tokens"), false);
});

test("premium builder quote uses points for non-wallet sessions", async () => {
  const sessionRow = withExpectedState(buildSessionRow({ ownSiteUrl: null }), "Q3_VIEW_EXAMPLES_YN");
  const db = createMockDb({
    firstResponses: [sessionRow, { m: 0 }, { m: 1 }],
  });
  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_premium_quote_points_1",
      state: "Q3_VIEW_EXAMPLES_YN",
      answer: "Build a premium repo marketplace in Next.js with 3 pages and Gumroad checkout.",
    }),
  });
  const response = await worker.fetch(req, {
    DB: db,
    PREMIUM_POINTS_SYMBOL: "PTS",
    PREMIUM_POINTS_PER_TOKEN: "2",
  });
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.next_state, "Q_PREMIUM_CONFIRM");
  assert.equal(body.premium_quote.charge_unit, "points");
  assert.ok(Number(body.premium_quote.charge_amount) > 0);
  assert.ok(Number(body.points_balance) >= 0);
});

test("Q_PREMIUM_CONFIRM yes charges tokens and enables premium mode", async () => {
  const row = buildSessionRow({ ownSiteUrl: null });
  const independent = JSON.parse(row.independent_json);
  const dependent = JSON.parse(row.dependent_json);
  independent.person.auth_method = "wallet";
  independent.person.wallet = { address: "0x2222222222222222222222222222222222222222" };
  dependent.flow = { expected_state: "Q_PREMIUM_CONFIRM", audit_requested: false };
  dependent.billing = {
    model: "spl_metered_v1",
    spl_symbol: "TOLLSPL",
    tokens_per_spl: 1000,
    free_tokens: 1200,
    token_balance: 1200,
    tokens_spent: 0,
    premium_enabled: false,
    wallet_required: true,
    wallet_verified: true,
    pending_quote: {
      tokens: 300,
      page_count: 3,
      complexity_units: 4,
      request_text: "Build a premium repo marketplace in Next.js with 3 pages.",
      state_to_resume: "Q3_VIEW_EXAMPLES_YN",
      quoted_at: 1704067200000,
    },
  };
  const sessionRow = {
    ...row,
    independent_json: JSON.stringify(independent),
    dependent_json: JSON.stringify(dependent),
  };
  const db = createMockDb({
    firstResponses: [sessionRow, { m: 0 }, { m: 1 }],
  });

  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_premium_confirm_1",
      state: "Q_PREMIUM_CONFIRM",
      answer: "yes",
    }),
  });
  const response = await worker.fetch(req, { DB: db });
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.next_state, "Q3_VIEW_EXAMPLES_YN");
  assert.equal(body.premium_mode, true);
  assert.equal(body.charged_tokens, 300);
  assert.equal(body.token_balance, 900);
});

test("Q_PREMIUM_CONFIRM yes charges points for non-wallet sessions", async () => {
  const row = buildSessionRow({ ownSiteUrl: null });
  const independent = JSON.parse(row.independent_json);
  const dependent = JSON.parse(row.dependent_json);
  independent.person.auth_method = "name";
  independent.person.wallet = null;
  dependent.flow = { expected_state: "Q_PREMIUM_CONFIRM", audit_requested: false };
  dependent.billing = {
    model: "hybrid_spl_points_v1",
    spl_symbol: "TOLLSPL",
    points_symbol: "PTS",
    points_per_token: 2,
    token_balance: 0,
    points_balance: 1000,
    points_spent: 0,
    premium_enabled: false,
    wallet_required: true,
    wallet_verified: false,
    points_enabled: true,
    pending_quote: {
      tokens: 300,
      page_count: 3,
      complexity_units: 4,
      request_text: "Build a premium repo marketplace in Next.js with 3 pages.",
      state_to_resume: "Q3_VIEW_EXAMPLES_YN",
      quoted_at: 1704067200000,
    },
  };
  const sessionRow = {
    ...row,
    independent_json: JSON.stringify(independent),
    dependent_json: JSON.stringify(dependent),
  };
  const db = createMockDb({
    firstResponses: [sessionRow, { m: 0 }, { m: 1 }],
  });

  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_premium_confirm_points_1",
      state: "Q_PREMIUM_CONFIRM",
      answer: "yes",
    }),
  });
  const response = await worker.fetch(req, {
    DB: db,
    PREMIUM_POINTS_PER_TOKEN: "2",
    PREMIUM_POINTS_SYMBOL: "PTS",
  });
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.next_state, "Q3_VIEW_EXAMPLES_YN");
  assert.equal(body.premium_mode, true);
  assert.equal(body.active_unit, "points");
  assert.equal(body.charged_amount, 600);
  assert.equal(body.points_balance, 400);
});

test("billing points credit endpoint adds points to non-wallet session", async () => {
  const row = buildSessionRow({ ownSiteUrl: null });
  const independent = JSON.parse(row.independent_json);
  const dependent = JSON.parse(row.dependent_json);
  dependent.billing = { points_balance: 25, points_enabled: true, points_symbol: "PTS" };
  const sessionRow = {
    ...row,
    independent_json: JSON.stringify(independent),
    dependent_json: JSON.stringify(dependent),
  };
  const db = createMockDb({
    firstResponses: [sessionRow, { m: 0 }],
  });

  const req = new Request("https://worker.example/billing/points/credit", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_points_credit_1",
      points: 40,
      reference: "order_123",
    }),
  });
  const response = await worker.fetch(req, { DB: db, PREMIUM_POINTS_SYMBOL: "PTS" });
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.ok, true);
  assert.equal(body.credited_points, 40);
  assert.equal(body.points_balance, 65);
});

test("billing points options returns point pack pricing and ad-reward settings", async () => {
  const db = createMockDb();
  const req = new Request("https://worker.example/billing/points/options");
  const response = await worker.fetch(req, {
    DB: db,
    PREMIUM_POINTS_SYMBOL: "PTS",
    PREMIUM_POINTS_PACK_PRICE_USD: "9.99",
    PREMIUM_POINTS_PACK_AMOUNT: "1200",
    PREMIUM_POINTS_CHECKOUT_URL: "https://checkout.example/points",
    PREMIUM_AD_REWARDS_ENABLED: "true",
    PREMIUM_AD_REWARD_POINTS: "50",
    PREMIUM_AD_REWARD_COOLDOWN_SEC: "180",
  });
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.ok, true);
  assert.equal(body.points_symbol, "PTS");
  assert.ok(Array.isArray(body.packs));
  assert.equal(body.packs[0].price_usd, 9.99);
  assert.equal(body.packs[0].points, 1200);
  assert.equal(body.packs[0].checkout_url, "https://checkout.example/points");
  assert.equal(body.ad_rewards.enabled, true);
  assert.equal(body.ad_rewards.reward_points, 50);
});

test("expensive actions are blocked when session is not security-verified", async () => {
  const sessionRow = withExpectedState(buildSessionRow({ ownSiteUrl: null }), "Q3_VIEW_EXAMPLES_YN");
  const db = createMockDb({
    firstResponses: [sessionRow, { m: 0 }],
  });

  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json", "CF-Connecting-IP": "203.0.113.33" },
    body: JSON.stringify({
      session_id: "ses_sec_1",
      state: "Q3_VIEW_EXAMPLES_YN",
      answer: "yes",
    }),
  });

  const response = await worker.fetch(req, {
    DB: db,
    TURNSTILE_SITE_KEY: "site-key-123",
    TURNSTILE_SECRET_KEY: "secret-key-123",
  });
  const body = await response.json();

  assert.equal(response.status, 403);
  assert.equal(body.code, "SECURITY_VERIFICATION_REQUIRED");
});

test("funnel status returns stage and CTA actions", async () => {
  const row = buildSessionRow({ ownSiteUrl: null });
  const independent = JSON.parse(row.independent_json);
  const dependent = JSON.parse(row.dependent_json);
  dependent.funnel = {
    signals: {
      forms_enabled: true,
      traffic_over_threshold: true,
      multiple_edits: false,
      custom_domain_requested: false,
    },
    metrics: {
      edit_requests_count: 1,
      traffic_monthly: 6000,
      traffic_threshold: 2000,
      form_submissions_monthly: 30,
    },
    ctas: {},
    sources: {},
    last_updated_at: 1704067200000,
  };
  dependent.upgrade = {
    managed_hosting_expires_at: new Date(Date.now() + 20 * 86400000).toISOString(),
  };
  const sessionRow = {
    ...row,
    independent_json: JSON.stringify(independent),
    dependent_json: JSON.stringify(dependent),
  };
  const db = createMockDb({ firstResponses: [sessionRow] });

  const req = new Request("https://worker.example/funnel/status?session_id=ses_40");
  const response = await worker.fetch(req, {
    DB: db,
    CONNECT_CLOUDFLARE_URL: "https://connect.example",
    MIGRATE_HOSTING_URL: "https://migrate.example",
  });
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.funnel_stage, "ready_for_migration");
  assert.ok(Array.isArray(body.cta_actions));
  assert.ok(body.cta_actions.some((a) => a.id === "connect_cloudflare"));
  assert.ok(body.cta_actions.some((a) => a.id === "migrate_hosting"));
});

test("funnel status includes dual-server monthly payment CTAs when configured", async () => {
  const row = buildSessionRow({ ownSiteUrl: null });
  const independent = JSON.parse(row.independent_json);
  const dependent = JSON.parse(row.dependent_json);
  dependent.funnel = {
    signals: {
      forms_enabled: true,
      traffic_over_threshold: true,
      multiple_edits: false,
      custom_domain_requested: false,
    },
    metrics: {
      edit_requests_count: 1,
      traffic_monthly: 7000,
      traffic_threshold: 2000,
      form_submissions_monthly: 25,
    },
    ctas: {},
    sources: {},
    last_updated_at: 1704067200000,
  };
  dependent.upgrade = {
    managed_hosting_expires_at: new Date(Date.now() + 20 * 86400000).toISOString(),
  };
  const sessionRow = {
    ...row,
    independent_json: JSON.stringify(independent),
    dependent_json: JSON.stringify(dependent),
  };
  const db = createMockDb({ firstResponses: [sessionRow] });

  const req = new Request("https://worker.example/funnel/status?session_id=ses_40b");
  const response = await worker.fetch(req, {
    DB: db,
    CONNECT_CLOUDFLARE_URL: "https://connect.example",
    MIGRATE_HOSTING_URL: "https://migrate.example",
    DUAL_SERVER_UPGRADE_URL: "https://upgrade.example/dual-server",
    UPGRADE_PAYPAL_URL: "https://upgrade.example/paypal",
    UPGRADE_CRYPTO_URL: "https://upgrade.example/crypto",
    FREE_VPS_BRIDGE_URL: "https://upgrade.example/free-vps-bridge",
  });
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.funnel_stage, "ready_for_migration");
  assert.ok(Array.isArray(body.cta_actions));
  assert.ok(body.cta_actions.some((a) => a.id === "dual_server_upgrade"));
  assert.ok(body.cta_actions.some((a) => a.id === "pay_monthly_paypal"));
  assert.ok(body.cta_actions.some((a) => a.id === "pay_monthly_crypto"));
  assert.ok(body.cta_actions.some((a) => a.id === "free_vps_bridge"));
});

test("funnel status does not include free VPS bridge when expiry is outside the month-before window", async () => {
  const row = buildSessionRow({ ownSiteUrl: null });
  const independent = JSON.parse(row.independent_json);
  const dependent = JSON.parse(row.dependent_json);
  dependent.funnel = {
    signals: {
      forms_enabled: true,
      traffic_over_threshold: true,
      multiple_edits: false,
      custom_domain_requested: false,
    },
    metrics: {
      edit_requests_count: 1,
      traffic_monthly: 7000,
      traffic_threshold: 2000,
      form_submissions_monthly: 25,
    },
    ctas: {},
    sources: {},
    last_updated_at: 1704067200000,
  };
  dependent.upgrade = {
    managed_hosting_expires_at: new Date(Date.now() + 40 * 86400000).toISOString(),
  };
  const sessionRow = {
    ...row,
    independent_json: JSON.stringify(independent),
    dependent_json: JSON.stringify(dependent),
  };
  const db = createMockDb({ firstResponses: [sessionRow] });

  const req = new Request("https://worker.example/funnel/status?session_id=ses_40c");
  const response = await worker.fetch(req, {
    DB: db,
    CONNECT_CLOUDFLARE_URL: "https://connect.example",
    MIGRATE_HOSTING_URL: "https://migrate.example",
    DUAL_SERVER_UPGRADE_URL: "https://upgrade.example/dual-server",
    UPGRADE_PAYPAL_URL: "https://upgrade.example/paypal",
    UPGRADE_CRYPTO_URL: "https://upgrade.example/crypto",
    FREE_VPS_BRIDGE_URL: "https://upgrade.example/free-vps-bridge",
  });
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.funnel_stage, "ready_for_migration");
  assert.ok(Array.isArray(body.cta_actions));
  assert.equal(body.cta_actions.some((a) => a.id === "free_vps_bridge"), false);
});

test("funnel signal endpoint updates traffic and stage", async () => {
  const row = buildSessionRow({ ownSiteUrl: null });
  const independent = JSON.parse(row.independent_json);
  const dependent = JSON.parse(row.dependent_json);
  dependent.funnel = {
    signals: {
      forms_enabled: true,
      traffic_over_threshold: false,
      multiple_edits: false,
      custom_domain_requested: false,
    },
    metrics: {
      edit_requests_count: 0,
      traffic_monthly: 400,
      traffic_threshold: 2000,
      form_submissions_monthly: 0,
    },
    ctas: {},
    sources: {},
    last_updated_at: 1704067200000,
  };
  const sessionRow = {
    ...row,
    independent_json: JSON.stringify(independent),
    dependent_json: JSON.stringify(dependent),
  };
  const db = createMockDb({ firstResponses: [sessionRow] });

  const req = new Request("https://worker.example/funnel/signal", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_41",
      signal: "traffic_monthly",
      value: "5000",
      source: "plugin",
    }),
  });
  const response = await worker.fetch(req, {
    DB: db,
    CONNECT_CLOUDFLARE_URL: "https://connect.example",
    MIGRATE_HOSTING_URL: "https://migrate.example",
  });
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.funnel_signals.traffic_over_threshold, true);
  assert.equal(body.funnel_stage, "ready_for_migration");
  assert.ok(body.cta_actions.some((a) => a.id === "migrate_hosting"));
});

test("Q_SCAN_PERMISSION starts inspector scan when URL already exists", async () => {
  const db = createMockDb({
    firstResponses: [buildSessionRow(), { m: 0 }, { m: 1 }],
  });
  const inspectorCalls = [];
  const env = {
    DB: db,
    INSPECTOR: {
      async fetch(request) {
        inspectorCalls.push(request);
        return new Response(JSON.stringify({ ok: true, request_id: "scan_1", status: "done" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      },
    },
  };

  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_1",
      state: "Q_SCAN_PERMISSION",
      answer: "yes",
    }),
  });

  const response = await worker.fetch(req, env);
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.next_state, "Q3_VIEW_EXAMPLES_YN");
  assert.equal(inspectorCalls.length, 1);
  assert.equal(new URL(inspectorCalls[0].url).pathname, "/inspect");

  const inspectorPayload = await inspectorCalls[0].json();
  assert.equal(inspectorPayload.session_id, "ses_1");
  assert.equal(inspectorPayload.url, "https://acme.example");
});

test("Q_SCAN_PERMISSION requests URL when none is available", async () => {
  const db = createMockDb({
    firstResponses: [buildSessionRow({ ownSiteUrl: null }), { m: 0 }, { m: 1 }],
  });
  const env = {
    DB: db,
    INSPECTOR: {
      async fetch() {
        throw new Error("inspector should not be called");
      },
    },
  };

  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_2",
      state: "Q_SCAN_PERMISSION",
      answer: "yes",
    }),
  });

  const response = await worker.fetch(req, env);
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.next_state, "Q_SCAN_URL");
});

test("q1/scan/status proxies inspector and stores summary", async () => {
  const db = createMockDb({
    firstResponses: [buildSessionRow()],
  });
  const env = {
    DB: db,
    INSPECTOR: {
      async fetch() {
        return new Response(
          JSON.stringify({
            ok: true,
            request: { request_id: "scan_7", status: "done" },
            result: {
              title: "Acme Plumbing",
              h1: "24/7 Plumbing",
              platform_hint: "wordpress",
              emails: ["info@acme.example"],
              phones: ["+15555555555"],
              schema_types: ["LocalBusiness"],
            },
          }),
          { status: 200, headers: { "content-type": "application/json" } }
        );
      },
    },
  };

  const req = new Request("https://worker.example/q1/scan/status?session_id=ses_3");
  const response = await worker.fetch(req, env);
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.ok, true);
  assert.equal(body.request.request_id, "scan_7");
  assert.ok(db.statements.some((s) => /INSERT INTO session_vars/.test(s.sql)));
});

test("Q3_VIEW_EXAMPLES_YN delegates nearby market search and returns openable link", async () => {
  const seedRow = withExpectedState(buildSessionRow({ ownSiteUrl: null }), "Q3_VIEW_EXAMPLES_YN");
  const seedIndependent = JSON.parse(seedRow.independent_json);
  const seedDependent = JSON.parse(seedRow.dependent_json);
  seedDependent.research = seedDependent.research || {};
  seedDependent.research.intent_text = "dive guiding service around Lake Tahoe";
  const sessionRow = {
    ...seedRow,
    independent_json: JSON.stringify(seedIndependent),
    dependent_json: JSON.stringify(seedDependent),
  };

  const db = createMockDb({
    firstResponses: [sessionRow, { m: 0 }, { m: 1 }],
  });
  const env = {
    DB: db,
    INSPECTOR: {
      async fetch(request) {
        assert.equal(new URL(request.url).pathname, "/market/nearby");
        const payload = await request.json();
        assert.equal(payload.intent_text, "dive guiding service around Lake Tahoe");
        return new Response(
          JSON.stringify({
            ok: true,
            source: "duckduckgo",
            sites: [{ title: "Dive Co", url: "https://diveco.example", snippet: "Scuba services", snapshot: { design_signals: { fonts: ["lato"], colors: ["#111"], layout_hints: ["hero_section"] } } }],
          }),
          { status: 200, headers: { "content-type": "application/json" } }
        );
      },
    },
  };

  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_10",
      state: "Q3_VIEW_EXAMPLES_YN",
      answer: "yes",
    }),
  });

  const response = await worker.fetch(req, env);
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.next_state, "Q3_VIEWING_DEMO");
  assert.match(String(body.open_url || ""), /^https:\/\/diveco\.example\/?$/);
  assert.match(String(body.demo_url || ""), /^https:\/\/diveco\.example\/?$/);
  assert.equal(body.auto_advance_after_seconds, 20);
});

test("Q3_VIEW_EXAMPLES_YN strips tracking redirect URLs from inspector results", async () => {
  const seedRow = withExpectedState(buildSessionRow({ ownSiteUrl: null }), "Q3_VIEW_EXAMPLES_YN");
  const db = createMockDb({
    firstResponses: [seedRow, { m: 0 }, { m: 1 }],
  });
  const env = {
    DB: db,
    INSPECTOR: {
      async fetch() {
        return new Response(
          JSON.stringify({
            ok: true,
            source: "inspector_market_search",
            sites: [
              {
                title: "Tracked",
                url: "https://duckduckgo.com/?uddg=https%3A%2F%2Fwww.hertz.com%2Fus%2Fen%2Flocation%2Funitedstates%2Fnevada%2Freno%2Frnot11",
              },
            ],
          }),
          { status: 200, headers: { "content-type": "application/json" } }
        );
      },
    },
  };

  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_10_tracking",
      state: "Q3_VIEW_EXAMPLES_YN",
      answer: "yes",
    }),
  });
  const response = await worker.fetch(req, env);
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.next_state, "Q3_VIEWING_DEMO");
  assert.match(String(body.open_url || ""), /^https:\/\/www\.hertz\.com\//);
  assert.doesNotMatch(String(body.open_url || ""), /duckduckgo\.com/);
});

test("Q3_VIEW_EXAMPLES_YN filters blacklisted content/news platforms from returned sites", async () => {
  const seedRow = withExpectedState(buildSessionRow({ ownSiteUrl: null }), "Q3_VIEW_EXAMPLES_YN");
  const db = createMockDb({
    firstResponses: [seedRow, { m: 0 }, { m: 1 }],
  });
  const env = {
    DB: db,
    INSPECTOR: {
      async fetch() {
        return new Response(
          JSON.stringify({
            ok: true,
            source: "inspector_market_search",
            sites: [
              { title: "Medium article", url: "https://medium.com/some-brand" },
              { title: "News listing", url: "https://mynews4.com/something" },
              { title: "Hertz Reno", url: "https://www.hertz.com/us/en/location/unitedstates/nevada/reno/rnot11" },
            ],
          }),
          { status: 200, headers: { "content-type": "application/json" } }
        );
      },
    },
  };

  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_10_blacklist",
      state: "Q3_VIEW_EXAMPLES_YN",
      answer: "yes",
    }),
  });
  const response = await worker.fetch(req, env);
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.next_state, "Q3_VIEWING_DEMO");
  assert.match(String(body.open_url || ""), /^https:\/\/www\.hertz\.com\//);
  assert.doesNotMatch(String(body.open_url || ""), /medium\.com|mynews4\.com/);
});

test("Q7_EMAIL publishes demo html and returns public demo URL when configured", async () => {
  const db = createMockDb({
    firstResponses: [buildSessionRow({ ownSiteUrl: null }), { m: 0 }, { m: 1 }],
  });
  const puts = [];
  const env = {
    DB: db,
    CONVO_BUCKET: {
      async put(key, body, opts) {
        puts.push({ key, body, opts });
      },
    },
    DEMO_PUBLIC_BASE_URL: "https://demo.example",
    CONNECT_CLOUDFLARE_URL: "https://connect.example",
  };

  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_11",
      state: "Q7_EMAIL",
      answer: "owner@bluereef.example",
    }),
  });

  const response = await worker.fetch(req, env);
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.next_state, "DONE");
  assert.ok(body.demo_site_url.startsWith("https://demo.example/demos/ses_11/"));
  assert.ok(puts.some((x) => x.key === "demos/ses_11/index.html"));
  assert.ok(puts.some((x) => /^demos\/ses_11\/assets\/site\.[a-f0-9]{12}\.css$/.test(x.key)));
  assert.ok(puts.some((x) => /^demos\/ses_11\/assets\/site\.[a-f0-9]{12}\.js$/.test(x.key)));
  assert.ok(puts.some((x) => /^demos\/ses_11\/assets\/hero\.[a-f0-9]{12}\.svg$/.test(x.key)));
  const cssPut = puts.find((x) => /\.css$/.test(x.key));
  const htmlPut = puts.find((x) => x.key === "demos/ses_11/index.html");
  assert.equal(cssPut?.opts?.httpMetadata?.cacheControl, "public, max-age=31536000, immutable");
  assert.equal(htmlPut?.opts?.httpMetadata?.cacheControl, "public, max-age=120");
  assert.match(String(htmlPut?.body || ""), /Book Appointment/i);
  assert.match(String(htmlPut?.body || ""), /Design profile:/i);
  assert.ok(Array.isArray(body.cta_actions));
  assert.ok(body.cta_actions.some((a) => a.id === "connect_cloudflare"));
});

test("design status returns computed profile and pattern analysis", async () => {
  const row = buildSessionRow({ ownSiteUrl: null });
  const independent = JSON.parse(row.independent_json);
  const dependent = JSON.parse(row.dependent_json);
  independent.build.goal = "bookings and calls";
  independent.build.vibe = "modern and clean";
  independent.build.colors = "blue and white";
  dependent.design = {
    ...(dependent.design || {}),
    liked: ["clean hero"],
    disliked: ["cluttered nav"],
    palette_hints: ["blue"],
    layout_hints: ["readable"],
    font_hints: ["sans"],
    raw_feedback: ["I like clean layout and easy to read sections."],
    reference_feedback: [],
  };
  dependent.analysis = {
    turns_processed: 4,
    preference_events: 2,
    preference_shifts: 0,
    frustration_signals: 0,
    positive_signals: 1,
    clarification_requests: 0,
    last_user_input: "looks good",
    last_summary: "",
    last_updated_at: null,
  };
  const sessionRow = {
    ...row,
    independent_json: JSON.stringify(independent),
    dependent_json: JSON.stringify(dependent),
  };
  const db = createMockDb({ firstResponses: [sessionRow, { m: 0 }] });

  const req = new Request("https://worker.example/design/status?session_id=ses_design_1");
  const response = await worker.fetch(req, { DB: db });
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.ok, true);
  assert.equal(body.design_profile.cta_focus, "bookings");
  assert.equal(body.design_profile.visual_style, "modern");
  assert.ok(Array.isArray(body.design_profile.section_plan));
  assert.ok(body.design_profile.section_plan.length >= 3);
  assert.equal(body.pattern_analysis.turns_processed, 4);
});

test("build brief endpoint is internal-only", async () => {
  const db = createMockDb({
    firstResponses: [buildSessionRow({ ownSiteUrl: null }), { m: 0 }],
  });
  const req = new Request("https://worker.example/build/brief?session_id=ses_brief_forbidden");
  const response = await worker.fetch(req, { DB: db });
  const body = await response.json();

  assert.equal(response.status, 403);
  assert.match(String(body.error || ""), /internal-only/i);
});

test("build brief endpoint compiles repo marketplace prompt when intent exists", async () => {
  const db = createMockDb({
    firstResponses: [
      buildSessionRow({
        ownSiteUrl: null,
        typeFinal: "developer repo marketplace",
        descriptionRaw: "I develop web repos for sale.",
      }),
      { m: 0 },
    ],
  });
  const req = new Request("https://worker.example/build/brief?session_id=ses_brief_1&internal=1", {
    headers: { "x-build-brief-internal": "1" },
  });
  const response = await worker.fetch(req, { DB: db });
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.ok, true);
  assert.equal(body.ready, true);
  assert.match(String(body.compiled_prompt || ""), /showcases and sells my code repos/i);
  assert.match(String(body.compiled_prompt || ""), /repos marketplace/i);
  assert.ok(body.slots);
  assert.equal(body.slots.persona, "developer_repo_seller");
});

test("Q1_DESCRIBE uses OpenAI candidates when deterministic type is too broad", async () => {
  const sessionRow = withExpectedState(buildSessionRow({ ownSiteUrl: null }), "Q1_DESCRIBE");
  const db = createMockDb({
    firstResponses: [sessionRow, { m: 0 }, null, { m: 1 }],
  });
  const env = {
    DB: db,
    OPENAI_API_KEY: "test-key",
  };
  const originalFetch = globalThis.fetch;

  globalThis.fetch = async (url) => {
    if (String(url).includes("api.openai.com/v1/responses")) {
      return new Response(
        JSON.stringify({
          output_text: '["auto repair shop","mechanic shop","tire repair shop"]',
        }),
        { status: 200, headers: { "content-type": "application/json" } }
      );
    }
    return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
  };

  try {
    const req = new Request("https://worker.example/q1/answer", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        session_id: "ses_20",
        state: "Q1_DESCRIBE",
        answer: "car repair",
      }),
    });

    const response = await worker.fetch(req, env);
    const body = await response.json();

    assert.equal(response.status, 200);
    assert.equal(body.next_state, "Q1_CHOOSE_TYPE");
    assert.ok(Array.isArray(body.candidates));
    assert.equal(body.candidates[0], "auto repair shop");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("Q1_DESCRIBE infers home hobbyist for hobby side-job language", async () => {
  const sessionRow = withExpectedState(buildSessionRow({ ownSiteUrl: null }), "Q1_DESCRIBE");
  const db = createMockDb({
    firstResponses: [sessionRow, { m: 0 }, { m: 1 }],
  });

  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_20_hobby",
      state: "Q1_DESCRIBE",
      answer: "well it is more of a hobby then a business, i garden",
    }),
  });

  const response = await worker.fetch(req, { DB: db });
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.next_state, "Q1_CONFIRM_TYPE");
  assert.match(body.prompt, /home hobbyist/i);
});

test("Q1_DESCRIBE infers developer repo marketplace from repo-sale language", async () => {
  const sessionRow = withExpectedState(buildSessionRow({ ownSiteUrl: null }), "Q1_DESCRIBE");
  const db = createMockDb({
    firstResponses: [sessionRow, { m: 0 }, { m: 1 }],
  });

  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_20_repo_market",
      state: "Q1_DESCRIBE",
      answer: "I develop web repos for sale and want a personal website to sell them.",
    }),
  });

  const response = await worker.fetch(req, { DB: db });
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.next_state, "Q1_CONFIRM_TYPE");
  assert.match(body.prompt, /developer repo marketplace/i);
});

test("Q1_CHOOSE_TYPE rejects long descriptive sentences as business type labels", async () => {
  const row = withExpectedState(buildSessionRow({ ownSiteUrl: null }), "Q1_CHOOSE_TYPE");
  const independent = JSON.parse(row.independent_json);
  const dependent = JSON.parse(row.dependent_json);
  dependent.draft.type_candidates = ["gardening service", "landscaping service", "plant nursery"];
  dependent.draft.type_guess = "gardening service";
  const sessionRow = {
    ...row,
    independent_json: JSON.stringify(independent),
    dependent_json: JSON.stringify(dependent),
  };
  const db = createMockDb({
    firstResponses: [sessionRow],
  });

  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_20_long_sentence",
      state: "Q1_CHOOSE_TYPE",
      answer:
        "well just for myself i garden but I want a website were i can sell some of my extra flowers from",
    }),
  });

  const response = await worker.fetch(req, { DB: db });
  const body = await response.json();

  assert.equal(response.status, 400);
  assert.match(body.error, /short business type label/i);
});

test("Q1_CONFIRM_TYPE accepts inline correction when user says no with quoted type", async () => {
  const row = withExpectedState(buildSessionRow({ ownSiteUrl: null }), "Q1_CONFIRM_TYPE");
  const independent = JSON.parse(row.independent_json);
  const dependent = JSON.parse(row.dependent_json);
  independent.business.description_raw = "hobby gardening and selling flowers";
  dependent.draft.type_candidates = ["gardening service", "landscaping service", "plant nursery"];
  dependent.draft.type_guess = "gardening service";
  const sessionRow = {
    ...row,
    independent_json: JSON.stringify(independent),
    dependent_json: JSON.stringify(dependent),
  };
  const db = createMockDb({
    firstResponses: [sessionRow, { m: 0 }, { m: 1 }],
  });

  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_20_inline_fix",
      state: "Q1_CONFIRM_TYPE",
      answer: 'no "home hobbyist"',
    }),
  });

  const response = await worker.fetch(req, { DB: db });
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.next_state, "Q1_CONFIRM_TYPE");
  assert.match(body.prompt, /home hobbyist/i);
});

test("Q1_DESCRIBE keeps sitebuilder flow when plugin intent is provided", async () => {
  const sessionRow = withExpectedState(buildSessionRow({ ownSiteUrl: null }), "Q1_DESCRIBE");
  const db = createMockDb({
    firstResponses: [sessionRow, { m: 0 }, { m: 1 }],
  });

  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_20_plugin",
      state: "Q1_DESCRIBE",
      answer: "i need to install your wp plugin",
    }),
  });

  const response = await worker.fetch(req, { DB: db });
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.next_state, "Q1_CONFIRM_TYPE");
  assert.match(body.prompt, /business type/i);
});

test("worker blocks out-of-order state transitions", async () => {
  const sessionRow = withExpectedState(buildSessionRow(), "Q1_DESCRIBE");
  const db = createMockDb({
    firstResponses: [sessionRow],
  });

  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_21",
      state: "Q7_EMAIL",
      answer: "owner@example.com",
    }),
  });

  const response = await worker.fetch(req, { DB: db });
  const body = await response.json();

  assert.equal(response.status, 409);
  assert.match(body.error, /Unexpected state/);
});

test("Q1_CONFIRM_TYPE persists user-confirmed business type memory", async () => {
  const row = withExpectedState(buildSessionRow({ ownSiteUrl: null }), "Q1_CONFIRM_TYPE");
  const independent = JSON.parse(row.independent_json);
  const dependent = JSON.parse(row.dependent_json);
  independent.business.description_raw = "car repair";
  dependent.draft.type_guess = "auto repair shop";
  dependent.draft.type_source = "openai";

  const db = createMockDb({
    firstResponses: [
      {
        ...row,
        independent_json: JSON.stringify(independent),
        dependent_json: JSON.stringify(dependent),
      },
      { m: 0 },
      { m: 1 },
    ],
  });

  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_22",
      state: "Q1_CONFIRM_TYPE",
      answer: "yes",
    }),
  });

  const response = await worker.fetch(req, { DB: db });
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.next_state, "Q2_PASTE_URL_OR_NO");
  assert.match(body.prompt, /if you have one/i);
  assert.match(body.prompt, /similar to what you want/i);
  assert.ok(db.statements.some((s) => /INSERT INTO business_type_memory/.test(s.sql)));
});

test("worker rejects oversized answers to protect flow and storage", async () => {
  const sessionRow = withExpectedState(buildSessionRow(), "Q1_DESCRIBE");
  const db = createMockDb({
    firstResponses: [sessionRow],
  });
  const longAnswer = "x".repeat(5000);

  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_23",
      state: "Q1_DESCRIBE",
      answer: longAnswer,
    }),
  });

  const response = await worker.fetch(req, { DB: db });
  const body = await response.json();

  assert.equal(response.status, 400);
  assert.match(body.error, /Answer too long/);
});

test('Q2_HAPPY_COSTS accepts "kinda" and moves to forced yes/no follow-up', async () => {
  const sessionRow = withExpectedState(buildSessionRow(), "Q2_HAPPY_COSTS");
  const db = createMockDb({
    firstResponses: [sessionRow, { m: 0 }, { m: 1 }],
  });

  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_24",
      state: "Q2_HAPPY_COSTS",
      answer: "kinda",
    }),
  });

  const response = await worker.fetch(req, { DB: db });
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.next_state, "Q2_HAPPY_COSTS_FORCED");
});

test("Q2_HAPPY_COSTS handles 'kinda + can you help me change it' without forced yes/no", async () => {
  const sessionRow = withExpectedState(buildSessionRow(), "Q2_HAPPY_COSTS");
  const db = createMockDb({
    firstResponses: [sessionRow, { m: 0 }, { m: 1 }],
  });

  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_24_change_help",
      state: "Q2_HAPPY_COSTS",
      answer: "kinda but i would like to make a lot of changes to it, can you help me with that?",
    }),
  });

  const response = await worker.fetch(req, { DB: db });
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.next_state, "Q3_VIEW_EXAMPLES_YN");
  assert.match(String(body.prompt || ""), /i can help/i);
});

test("Q2_HAPPY_COSTS answers benchmark question instead of hard failing", async () => {
  const baseRow = withExpectedState(
    buildSessionRow({ ownSiteUrl: "https://wp-site.example/", sitePlatform: "wordpress", isWordpress: true }),
    "Q2_HAPPY_COSTS"
  );
  const independent = JSON.parse(baseRow.independent_json);
  const dependent = JSON.parse(baseRow.dependent_json);
  dependent.scan = {
    status: "done",
    request_id: "scan_907",
    latest_summary: "Title: WP Site",
    platform_hint: "wordpress",
    latest_result: {
      title: "WP Site",
      h1: "Services",
      platform_hint: "wordpress",
      raw_size: 615313,
      emails: ["owner@wp-site.example"],
      phones: ["(775) 555-0100"],
      schema_types: [],
    },
  };
  dependent.plugin = {
    detected_platform: "wordpress",
    wordpress_offer_shown: true,
    wordpress_audit_completed: true,
    wordpress_audit_summary: {
      speedScore: 62,
      securityScore: 68,
      recommendations: [],
      summary: "WordPress audit summary: Speed 62/100, Security 68/100.",
    },
    connect: { status: "not_started" },
  };
  const sessionRow = {
    ...baseRow,
    independent_json: JSON.stringify(independent),
    dependent_json: JSON.stringify(dependent),
  };
  const db = createMockDb({
    firstResponses: [sessionRow, { m: 0 }, { m: 1 }],
  });

  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_24_benchmark",
      state: "Q2_HAPPY_COSTS",
      answer: "can you give me a benchmark on my current loading speed so I can compare after plugin?",
    }),
  });

  const response = await worker.fetch(req, { DB: db });
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.next_state, "Q2_HAPPY_COSTS");
  assert.match(body.prompt, /Current benchmark baseline/i);
  assert.match(body.prompt, /Expected after plugin \+ Cloudflare optimization/i);
});

test("Q2_HAPPY_COSTS can start schema setup flow on request", async () => {
  const sessionRow = withExpectedState(
    buildSessionRow({ ownSiteUrl: "https://wp-site.example/", sitePlatform: "wordpress", isWordpress: true }),
    "Q2_HAPPY_COSTS"
  );
  const db = createMockDb({
    firstResponses: [sessionRow, { m: 0 }, { m: 1 }],
  });
  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_24_schema",
      state: "Q2_HAPPY_COSTS",
      answer: "schema setup please",
    }),
  });

  const response = await worker.fetch(req, { DB: db });
  const body = await response.json();
  assert.equal(response.status, 200);
  assert.equal(body.next_state, "Q_SCHEMA_BUSINESS_NAME");
  assert.match(body.prompt, /set up your schema data/i);
});

test("Q2_HAPPY_COSTS explains schema questions without forcing schema flow", async () => {
  const baseRow = withExpectedState(
    buildSessionRow({ ownSiteUrl: "https://wp-site.example/", sitePlatform: "wordpress", isWordpress: true }),
    "Q2_HAPPY_COSTS"
  );
  const independent = JSON.parse(baseRow.independent_json);
  const dependent = JSON.parse(baseRow.dependent_json);
  dependent.plugin = dependent.plugin || {};
  dependent.plugin.wordpress_audit_summary = {
    recommendations: [
      "Optimize page weight and caching for faster first load.",
      "Protect public contact data with Worker form endpoints + Turnstile.",
      "Add structured data to strengthen local search visibility.",
    ],
  };
  const sessionRow = {
    ...baseRow,
    independent_json: JSON.stringify(independent),
    dependent_json: JSON.stringify(dependent),
  };

  const db = createMockDb({
    firstResponses: [sessionRow, { m: 0 }, { m: 1 }],
  });
  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_24_schema_explain",
      state: "Q2_HAPPY_COSTS",
      answer:
        "why would i want schema markup and I do not even know what FTP/SSH is, my site is slow and I am open to suggestions",
    }),
  });

  const response = await worker.fetch(req, { DB: db });
  const body = await response.json();
  assert.equal(response.status, 200);
  assert.equal(body.next_state, "Q2_HAPPY_COSTS");
  assert.match(body.prompt, /Schema markup is extra code/i);
  assert.doesNotMatch(body.prompt, /ftp|ssh/i);
  assert.match(body.prompt, /reply "schema setup"/i);
});

test("Q2_HAPPY_COSTS_FORCED handles change-help intent instead of strict yes/no error", async () => {
  const sessionRow = withExpectedState(buildSessionRow(), "Q2_HAPPY_COSTS_FORCED");
  const db = createMockDb({
    firstResponses: [sessionRow, { m: 0 }, { m: 1 }],
  });

  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_24_forced_change_help",
      state: "Q2_HAPPY_COSTS_FORCED",
      answer: "i am not sure but i want to improve this site a lot, can you help me with changes?",
    }),
  });

  const response = await worker.fetch(req, { DB: db });
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.next_state, "Q3_VIEW_EXAMPLES_YN");
  assert.match(String(body.prompt || ""), /i can help/i);
});

test("Q3_VIEW_EXAMPLES_YN prioritizes scan intent in mixed responses", async () => {
  const sessionRow = withExpectedState(buildSessionRow({ ownSiteUrl: "https://supremexdetail.com" }), "Q3_VIEW_EXAMPLES_YN");
  const db = createMockDb({
    firstResponses: [sessionRow, { m: 0 }, { m: 1 }],
  });
  const env = {
    DB: db,
    INSPECTOR: {
      async fetch(request) {
        assert.equal(new URL(request.url).pathname, "/inspect");
        return new Response(
          JSON.stringify({
            ok: true,
            request_id: "scan_901",
            status: "done",
            result: { title: "Supremex", h1: "Detailing", emails: [], phones: [] },
          }),
          { status: 200, headers: { "content-type": "application/json" } }
        );
      },
    },
  };

  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_25",
      state: "Q3_VIEW_EXAMPLES_YN",
      answer: "sure but have you looked over mine yet with the headless chrome?",
    }),
  });

  const response = await worker.fetch(req, env);
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.next_state, "Q3_VIEW_EXAMPLES_YN");
  assert.match(body.prompt, /I just scanned/);
});

test("Q_BUILD_TRIAL_YN handles how-do-i-know objection without error", async () => {
  const sessionRow = withExpectedState(buildSessionRow(), "Q_BUILD_TRIAL_YN");
  const db = createMockDb({
    firstResponses: [sessionRow, { m: 0 }, { m: 1 }],
  });

  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_26",
      state: "Q_BUILD_TRIAL_YN",
      answer: "how do i know i would like it?",
    }),
  });

  const response = await worker.fetch(req, { DB: db });
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.next_state, "Q_BUILD_TRIAL_YN");
  assert.match(body.prompt, /Totally fair/);
  assert.doesNotMatch(body.prompt, /no credit card|free 1-month|walk away/i);
});

test("Q3_VIEW_EXAMPLES_YN why response stays guidance-first (not sales-first)", async () => {
  const sessionRow = withExpectedState(buildSessionRow({ ownSiteUrl: null }), "Q3_VIEW_EXAMPLES_YN");
  const db = createMockDb({
    firstResponses: [sessionRow, { m: 0 }, { m: 1 }],
  });

  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_26_why",
      state: "Q3_VIEW_EXAMPLES_YN",
      answer: "why",
    }),
  });

  const response = await worker.fetch(req, { DB: db });
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.next_state, "Q3_VIEW_EXAMPLES_YN");
  assert.match(body.prompt, /understand your taste/i);
  assert.doesNotMatch(body.prompt, /no credit card|nothing to lose|free 1-month/i);
});

test("Q3_VIEW_EXAMPLES_YN keeps sitebuilder flow when user asks for plugin install", async () => {
  const baseRow = buildSessionRow({ ownSiteUrl: "https://wp-site.example/", sitePlatform: "wordpress", isWordpress: true });
  const dependent = JSON.parse(baseRow.dependent_json);
  dependent.plugin = dependent.plugin || {};
  dependent.plugin.detected_platform = "wordpress";
  const sessionRow = withExpectedState(
    {
      ...baseRow,
      dependent_json: JSON.stringify(dependent),
    },
    "Q3_VIEW_EXAMPLES_YN"
  );
  const db = createMockDb({
    firstResponses: [sessionRow, { m: 0 }, { m: 1 }],
  });

  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_25_plugin_route",
      state: "Q3_VIEW_EXAMPLES_YN",
      answer: "no just install plugin to see increase in scores",
    }),
  });

  const response = await worker.fetch(req, { DB: db });
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.next_state, "Q_BUILD_TRIAL_YN");
  assert.match(body.prompt, /draft a sample site/i);
  assert.doesNotMatch(body.prompt, /plugin install now/i);
});

test('Q_BUILD_TRIAL_YN accepts "maybe later" without hard error', async () => {
  const sessionRow = withExpectedState(buildSessionRow(), "Q_BUILD_TRIAL_YN");
  const db = createMockDb({
    firstResponses: [sessionRow, { m: 0 }, { m: 1 }],
  });

  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_26b",
      state: "Q_BUILD_TRIAL_YN",
      answer: "maybe later",
    }),
  });

  const response = await worker.fetch(req, { DB: db });
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.next_state, "DONE");
  assert.match(body.prompt, /skip the sample for now/i);
  assert.doesNotMatch(body.prompt, /plugin install/i);
});

test("DONE follow-up request can recover email from scanned current site", async () => {
  const sessionRow = withExpectedState(buildSessionRow({ ownSiteUrl: "https://supremexdetail.com" }), "DONE");
  const db = createMockDb({
    firstResponses: [sessionRow, { m: 0 }, { m: 1 }],
  });
  const env = {
    DB: db,
    INSPECTOR: {
      async fetch(request) {
        assert.equal(new URL(request.url).pathname, "/inspect");
        return new Response(
          JSON.stringify({
            ok: true,
            request_id: "scan_902",
            status: "done",
            result: { emails: ["owner@supremexdetail.com"], phones: [] },
          }),
          { status: 200, headers: { "content-type": "application/json" } }
        );
      },
    },
  };

  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_27",
      state: "DONE",
      answer: "will you emsil me with a website demo in a week? my email is on my current site",
    }),
  });

  const response = await worker.fetch(req, env);
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.next_state, "DONE");
  assert.match(body.prompt, /found and saved owner@supremexdetail\.com/i);
});

test("DONE plugin-install request returns WordPress plugin setup guidance", async () => {
  const base = buildSessionRow({
    ownSiteUrl: "https://supremexdetail.com",
    sitePlatform: "wordpress",
    isWordpress: true,
  });
  const dependent = JSON.parse(base.dependent_json);
  dependent.scan = dependent.scan || {};
  dependent.scan.platform_hint = "wordpress";
  dependent.plugin = dependent.plugin || {};
  dependent.plugin.detected_platform = "wordpress";
  const sessionRow = withExpectedState(
    {
      ...base,
      dependent_json: JSON.stringify(dependent),
    },
    "DONE"
  );
  const db = createMockDb({
    firstResponses: [sessionRow, { m: 0 }, { m: 1 }],
  });

  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_27_plugin",
      state: "DONE",
      answer: "ok now to the plugin install?",
    }),
  });

  const response = await worker.fetch(req, {
    DB: db,
    PLUGIN_FREE_URL: "https://app.example/plugin-free",
    CONNECT_CLOUDFLARE_URL: "https://app.example/connect-cloudflare",
    TOLLDNS_URL: "https://app.example/tolldns-install",
    GITHUB_SIGNUP_URL: "https://github.com/signup",
  });
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.next_state, "DONE");
  assert.match(body.prompt, /start plugin install now/i);
  assert.match(body.prompt, /install ai-webadmin plugin/i);
  assert.ok(Array.isArray(body.cta_actions));
  assert.ok(body.cta_actions.some((a) => a.id === "install_ai_webadmin_plugin"));
});

test("DONE plugin step number opens selected install link", async () => {
  const base = buildSessionRow({
    ownSiteUrl: "https://supremexdetail.com",
    sitePlatform: "wordpress",
    isWordpress: true,
  });
  const dependent = JSON.parse(base.dependent_json);
  dependent.scan = dependent.scan || {};
  dependent.scan.platform_hint = "wordpress";
  dependent.plugin = dependent.plugin || {};
  dependent.plugin.detected_platform = "wordpress";
  const sessionRow = withExpectedState(
    {
      ...base,
      dependent_json: JSON.stringify(dependent),
    },
    "DONE"
  );
  const db = createMockDb({
    firstResponses: [sessionRow, { m: 0 }, { m: 1 }],
  });

  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_27_plugin_step",
      state: "DONE",
      answer: "1",
    }),
  });

  const response = await worker.fetch(req, {
    DB: db,
    PLUGIN_FREE_URL: "https://app.example/plugin-free",
    CONNECT_CLOUDFLARE_URL: "https://app.example/connect-cloudflare",
    TOLLDNS_URL: "https://app.example/tolldns-install",
    GITHUB_SIGNUP_URL: "https://github.com/signup",
  });
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.next_state, "DONE");
  assert.match(body.prompt, /Opening step 1/i);
  assert.equal(body.open_url, "https://app.example/plugin-free");
});

test('DONE interprets "ok and the plugin?" as plugin-install intent', async () => {
  const base = buildSessionRow({
    ownSiteUrl: "https://supremexdetail.com",
    sitePlatform: "wordpress",
    isWordpress: true,
  });
  const dependent = JSON.parse(base.dependent_json);
  dependent.scan = dependent.scan || {};
  dependent.scan.platform_hint = "wordpress";
  dependent.plugin = dependent.plugin || {};
  dependent.plugin.detected_platform = "wordpress";
  const sessionRow = withExpectedState(
    {
      ...base,
      dependent_json: JSON.stringify(dependent),
    },
    "DONE"
  );
  const db = createMockDb({
    firstResponses: [sessionRow, { m: 0 }, { m: 1 }],
  });

  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_27_plugin_short",
      state: "DONE",
      answer: "ok and the plugin?",
    }),
  });

  const response = await worker.fetch(req, {
    DB: db,
    PLUGIN_FREE_URL: "https://app.example/plugin-free",
    CONNECT_CLOUDFLARE_URL: "https://app.example/connect-cloudflare",
    TOLLDNS_URL: "https://app.example/tolldns-install",
  });
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.next_state, "DONE");
  assert.match(body.prompt, /start plugin install now/i);
  assert.ok(Array.isArray(body.cta_actions));
  assert.ok(body.cta_actions.some((a) => a.id === "install_ai_webadmin_plugin"));
});

test("DONE dual-server request returns month-to-month no-auto-enroll offer and payment CTAs", async () => {
  const sessionRow = withExpectedState(buildSessionRow({ ownSiteUrl: "https://supremexdetail.com" }), "DONE");
  const db = createMockDb({
    firstResponses: [sessionRow, { m: 0 }, { m: 1 }],
  });

  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_27b",
      state: "DONE",
      answer: "I want dual server high availability and load balancing, and I prefer paypal",
    }),
  });

  const response = await worker.fetch(req, {
    DB: db,
    DUAL_SERVER_UPGRADE_URL: "https://upgrade.example/dual-server",
    UPGRADE_PAYPAL_URL: "https://upgrade.example/paypal",
    UPGRADE_CRYPTO_URL: "https://upgrade.example/crypto",
  });
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.next_state, "DONE");
  assert.match(body.prompt, /month-to-month only/i);
  assert.match(body.prompt, /no auto-enrollment/i);
  assert.ok(Array.isArray(body.cta_actions));
  assert.ok(body.cta_actions.some((a) => a.id === "dual_server_upgrade"));
  assert.ok(body.cta_actions.some((a) => a.id === "pay_monthly_paypal"));
  assert.ok(body.cta_actions.some((a) => a.id === "pay_monthly_crypto"));
});

test('Q2_HAPPY_COSTS treats "I do not know" as maybe and forces a decision', async () => {
  const sessionRow = withExpectedState(buildSessionRow(), "Q2_HAPPY_COSTS");
  const db = createMockDb({
    firstResponses: [sessionRow, { m: 0 }, { m: 1 }],
  });

  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_28",
      state: "Q2_HAPPY_COSTS",
      answer: "I do not know",
    }),
  });

  const response = await worker.fetch(req, { DB: db });
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.next_state, "Q2_HAPPY_COSTS_FORCED");
});

test("Q2_CONFIRM_OWNERSHIP yes runs scan immediately and returns reviewed prompt", async () => {
  const sessionRow = withExpectedState(buildSessionRow({ ownSiteUrl: "https://rootermanrenocarson.com/" }), "Q2_CONFIRM_OWNERSHIP");
  const db = createMockDb({
    firstResponses: [sessionRow, { m: 0 }, { m: 1 }],
  });
  const env = {
    DB: db,
    INSPECTOR: {
      async fetch(request) {
        assert.equal(new URL(request.url).pathname, "/inspect");
        return new Response(
          JSON.stringify({
            ok: true,
            request_id: "scan_903",
            status: "done",
            result: {
              title: "Roto Rooter Reno Carson",
              h1: "24/7 Plumbing",
              emails: ["hello@rootermanrenocarson.com"],
              phones: ["(775) 555-0100"],
              addresses: ["123 Main St, Reno, NV 89501"],
            },
          }),
          { status: 200, headers: { "content-type": "application/json" } }
        );
      },
    },
  };

  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_29",
      state: "Q2_CONFIRM_OWNERSHIP",
      answer: "yes",
    }),
  });

  const response = await worker.fetch(req, env);
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.next_state, "Q2_HAPPY_COSTS");
  assert.match(body.prompt, /I reviewed your current site/i);
});

test('Q2_CONFIRM_OWNERSHIP accepts "yah" as yes and continues flow', async () => {
  const sessionRow = withExpectedState(buildSessionRow({ ownSiteUrl: "https://rootermanrenocarson.com/" }), "Q2_CONFIRM_OWNERSHIP");
  const db = createMockDb({
    firstResponses: [sessionRow, { m: 0 }, { m: 1 }],
  });
  const env = {
    DB: db,
    INSPECTOR: {
      async fetch(request) {
        assert.equal(new URL(request.url).pathname, "/inspect");
        return new Response(
          JSON.stringify({
            ok: true,
            request_id: "scan_903b",
            status: "done",
            result: {
              title: "Roto Rooter Reno Carson",
              h1: "24/7 Plumbing",
              emails: ["hello@rootermanrenocarson.com"],
              phones: ["(775) 555-0100"],
              addresses: ["123 Main St, Reno, NV 89501"],
            },
          }),
          { status: 200, headers: { "content-type": "application/json" } }
        );
      },
    },
  };

  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_29b",
      state: "Q2_CONFIRM_OWNERSHIP",
      answer: "yah",
    }),
  });

  const response = await worker.fetch(req, env);
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.next_state, "Q2_HAPPY_COSTS");
  assert.match(body.prompt, /I reviewed your current site/i);
});

test("Q2_CONFIRM_OWNERSHIP no converts saved URL into reference flow", async () => {
  const sessionRow = withExpectedState(buildSessionRow({ ownSiteUrl: "https://brittanychiang.com/" }), "Q2_CONFIRM_OWNERSHIP");
  const db = createMockDb({
    firstResponses: [sessionRow, { m: 0 }, { m: 1 }],
  });

  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_29_reference",
      state: "Q2_CONFIRM_OWNERSHIP",
      answer: "no",
    }),
  });

  const response = await worker.fetch(req, { DB: db });
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.next_state, "Q3_FEEDBACK_OPEN");
  assert.equal(body.demo_url, "https://brittanychiang.com/");
  assert.equal(body.open_url, "https://brittanychiang.com/");
  assert.match(String(body.prompt || ""), /reference site/i);

  const writes = db.statements.filter((s) => s.op === "run" && /INSERT INTO session_vars/i.test(s.sql));
  assert.ok(writes.length >= 1);
  const latestIndependent = JSON.parse(writes.at(-1).params[2]);
  const latestDependent = JSON.parse(writes.at(-1).params[3]);
  assert.equal(latestIndependent.business.own_site_url, null);
  assert.equal(latestIndependent.business.own_site_confirmed, false);
  assert.equal(latestDependent.research.user_reference_url, "https://brittanychiang.com/");
});

test("Q2_CONFIRM_OWNERSHIP yes on WordPress offers audit prompt without CTA buttons", async () => {
  const sessionRow = withExpectedState(buildSessionRow({ ownSiteUrl: "https://wp-site.example/" }), "Q2_CONFIRM_OWNERSHIP");
  const db = createMockDb({
    firstResponses: [sessionRow, { m: 0 }, { m: 1 }],
  });
  const env = {
    DB: db,
    INSPECTOR: {
      async fetch(request) {
        assert.equal(new URL(request.url).pathname, "/inspect");
        return new Response(
          JSON.stringify({
            ok: true,
            request_id: "scan_904",
            status: "done",
            result: {
              title: "WP Site",
              h1: "Services",
              platform_hint: "wordpress",
              emails: ["owner@wp-site.example"],
              phones: ["(775) 555-0199"],
            },
          }),
          { status: 200, headers: { "content-type": "application/json" } }
        );
      },
    },
  };

  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_29_wp",
      state: "Q2_CONFIRM_OWNERSHIP",
      answer: "yes",
    }),
  });

  const response = await worker.fetch(req, env);
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.next_state, "Q2_WP_AUDIT_OFFER");
  assert.match(body.prompt, /detected your site is on WordPress/i);
  assert.match(body.prompt, /If you want more detail first/i);
  assert.ok(!("cta_actions" in body));
});

test("Q2_CONFIRM_OWNERSHIP auto-runs WordPress audit when audit was requested upfront", async () => {
  const baseRow = withExpectedState(
    buildSessionRow({ ownSiteUrl: "https://wp-site.example/" }),
    "Q2_CONFIRM_OWNERSHIP"
  );
  const independent = JSON.parse(baseRow.independent_json);
  const dependent = JSON.parse(baseRow.dependent_json);
  dependent.flow = dependent.flow || {};
  dependent.flow.audit_requested = true;
  const sessionRow = {
    ...baseRow,
    independent_json: JSON.stringify(independent),
    dependent_json: JSON.stringify(dependent),
  };
  const db = createMockDb({
    firstResponses: [sessionRow, { m: 0 }, { m: 1 }],
  });
  const env = {
    DB: db,
    INSPECTOR: {
      async fetch(request) {
        assert.equal(new URL(request.url).pathname, "/inspect");
        return new Response(
          JSON.stringify({
            ok: true,
            request_id: "scan_905_auto",
            status: "done",
            result: {
              title: "WP Site",
              h1: "Services",
              platform_hint: "wordpress",
              raw_size: 620000,
              emails: ["owner@wp-site.example"],
              phones: ["(775) 555-0100"],
              schema_types: [],
              link_audit: { checked_count: 10, broken_count: 1, broken_paths: ["/old-page"] },
            },
          }),
          { status: 200, headers: { "content-type": "application/json" } }
        );
      },
    },
  };

  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_29_wp_auto_audit",
      state: "Q2_CONFIRM_OWNERSHIP",
      answer: "yes",
    }),
  });

  const response = await worker.fetch(req, env);
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.next_state, "Q2_AUDIT_EMAIL_OPTIN");
  assert.ok(body.wordpress_audit);
  assert.match(body.prompt, /WordPress audit summary/i);
  assert.match(body.prompt, /email this audit report/i);
  assert.ok(!("cta_actions" in body));
});

test("Q2_WP_AUDIT_OFFER yes returns audit summary and continues", async () => {
  const baseRow = withExpectedState(
    buildSessionRow({ ownSiteUrl: "https://wp-site.example/", sitePlatform: "wordpress", isWordpress: true }),
    "Q2_WP_AUDIT_OFFER"
  );
  const independent = JSON.parse(baseRow.independent_json);
  const dependent = JSON.parse(baseRow.dependent_json);
  dependent.scan = {
    status: "done",
    request_id: "scan_905",
    latest_summary: "Title: WP Site",
    platform_hint: "wordpress",
    latest_result: {
      title: "WP Site",
      h1: "Book Services",
      platform_hint: "wordpress",
      raw_size: 620000,
      emails: ["owner@wp-site.example"],
      phones: ["(775) 555-0100", "(775) 555-0101"],
      schema_types: ["LocalBusiness"],
      link_audit: { checked_count: 12, broken_count: 3, broken_paths: ["/old-page", "/promo-2022"] },
      dns_profile: {
        ns_records: ["ns1.example.net", "ns2.example.net"],
      },
      infrastructure: {
        ip_addresses: ["203.0.113.44", "2606:4700:3031::ac43:9987"],
        a_record_primary_ip: "203.0.113.44",
        a_record_ips: ["203.0.113.44"],
        hosting_company: "Cloudflare",
        hosting_type_hint: "vps_or_cloud_vm",
        hosting_cost_estimate: {
          monthly_min_usd: 6,
          monthly_max_usd: 24,
          confidence: "low",
        },
        domain_expires_at: "2026-06-18T01:44:46Z",
      },
    },
  };
  dependent.plugin = {
    detected_platform: "wordpress",
    wordpress_offer_shown: true,
    wordpress_audit_completed: false,
    audit_metrics: {
      email_queue_count: 4,
      outdated_plugin_count: 7,
      pending_comment_moderation_count: 12,
    },
    connect: { status: "not_started" },
  };
  const sessionRow = {
    ...baseRow,
    independent_json: JSON.stringify(independent),
    dependent_json: JSON.stringify(dependent),
  };
  const db = createMockDb({
    firstResponses: [sessionRow, { m: 0 }, { m: 1 }],
  });

  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_29_wp_audit",
      state: "Q2_WP_AUDIT_OFFER",
      answer: "yes",
    }),
  });

  const response = await worker.fetch(req, { DB: db });
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.next_state, "Q2_AUDIT_EMAIL_OPTIN");
  assert.ok(body.wordpress_audit);
  assert.match(body.prompt, /WordPress audit summary/i);
  assert.match(body.prompt, /Admin-only checks \(run after secure admin connection\)/i);
  assert.match(body.prompt, /broken links:\s*3/i);
  assert.match(body.prompt, /with 0 schema types|schema helps search engines/i);
  assert.match(body.prompt, /Projected improvement/i);
  assert.match(body.prompt, /What is SSO and why it helps/i);
  assert.match(body.prompt, /Primary A record IP:\s*203\.0\.113\.44/i);
  assert.match(body.prompt, /Hosting type \(estimated\):\s*vps or cloud vm/i);
  assert.match(body.prompt, /Estimated hosting cost range:\s*\$6-\$24\/month/i);
  assert.doesNotMatch(body.prompt, /Domain registrar/i);
  const sessionWrites = db.statements.filter((s) => s.op === "run" && /INSERT INTO session_vars/i.test(s.sql));
  assert.ok(sessionWrites.length >= 1);
  const latestIndependent = JSON.parse(sessionWrites.at(-1).params[2]);
  assert.equal(latestIndependent.business.tech_profile.a_record_primary_ip, "203.0.113.44");
  assert.equal(latestIndependent.business.tech_profile.hosting_type_hint, "vps_or_cloud_vm");
  assert.equal(latestIndependent.business.tech_profile.hosting_cost_estimate.monthly_max_usd, 24);
  assert.ok(!("cta_actions" in body));
});

test("Q2_WP_AUDIT_OFFER accepts natural-language request to run audit", async () => {
  const baseRow = withExpectedState(
    buildSessionRow({ ownSiteUrl: "https://wp-site.example/", sitePlatform: "wordpress", isWordpress: true }),
    "Q2_WP_AUDIT_OFFER"
  );
  const independent = JSON.parse(baseRow.independent_json);
  const dependent = JSON.parse(baseRow.dependent_json);
  dependent.scan = {
    status: "done",
    request_id: "scan_906",
    latest_summary: "Title: WP Site",
    platform_hint: "wordpress",
    latest_result: {
      title: "WP Site",
      h1: "Book Services",
      platform_hint: "wordpress",
      raw_size: 540000,
      emails: ["owner@wp-site.example"],
      phones: ["(775) 555-0100"],
      schema_types: ["LocalBusiness"],
    },
  };
  dependent.plugin = {
    detected_platform: "wordpress",
    wordpress_offer_shown: true,
    wordpress_audit_completed: false,
    connect: { status: "not_started" },
  };
  const sessionRow = {
    ...baseRow,
    independent_json: JSON.stringify(independent),
    dependent_json: JSON.stringify(dependent),
  };
  const db = createMockDb({
    firstResponses: [sessionRow, { m: 0 }, { m: 1 }],
  });

  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_29_wp_audit_natural",
      state: "Q2_WP_AUDIT_OFFER",
      answer: "please just run the audit and then tell me how much the plugin would help",
    }),
  });

  const response = await worker.fetch(req, { DB: db });
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.next_state, "Q2_AUDIT_EMAIL_OPTIN");
  assert.match(body.prompt, /WordPress audit summary/i);
  assert.match(body.prompt, /Estimated impact/i);
});

test("Q2_WP_AUDIT_OFFER keeps audit flow when user asks to install plugin", async () => {
  const baseRow = withExpectedState(
    buildSessionRow({ ownSiteUrl: "https://wp-site.example/", sitePlatform: "wordpress", isWordpress: true }),
    "Q2_WP_AUDIT_OFFER"
  );
  const independent = JSON.parse(baseRow.independent_json);
  const dependent = JSON.parse(baseRow.dependent_json);
  dependent.plugin = {
    detected_platform: "wordpress",
    wordpress_offer_shown: true,
    wordpress_audit_completed: false,
    connect: { status: "not_started" },
  };
  const sessionRow = {
    ...baseRow,
    independent_json: JSON.stringify(independent),
    dependent_json: JSON.stringify(dependent),
  };
  const db = createMockDb({
    firstResponses: [sessionRow, { m: 0 }, { m: 1 }],
  });

  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_29_wp_audit_skip_plugin",
      state: "Q2_WP_AUDIT_OFFER",
      answer: "can i please install it now",
    }),
  });

  const response = await worker.fetch(req, { DB: db });
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.next_state, "Q2_WP_AUDIT_OFFER");
  assert.match(body.prompt, /reply "yes" to run it now, "no" to skip/i);
});

test("Q2_AUDIT_EMAIL_OPTIN saves choices and continues to second part", async () => {
  const sessionRow = withExpectedState(
    buildSessionRow({ ownSiteUrl: "https://wp-site.example/", sitePlatform: "wordpress", isWordpress: true }),
    "Q2_AUDIT_EMAIL_OPTIN"
  );
  const db = createMockDb({
    firstResponses: [sessionRow, { m: 0 }, { m: 1 }],
  });
  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_29_wp_email_optin",
      state: "Q2_AUDIT_EMAIL_OPTIN",
      answer: "report only",
    }),
  });

  const response = await worker.fetch(req, { DB: db });
  const body = await response.json();
  assert.equal(response.status, 200);
  assert.equal(body.next_state, "Q2_HAPPY_COSTS");
  assert.match(body.prompt, /email the audit report/i);
  assert.match(body.prompt, /Second part:/i);
});

test("Q2_AUDIT_EMAIL_OPTIN keeps onboarding flow when user mentions plugin install", async () => {
  const baseRow = buildSessionRow({ ownSiteUrl: "https://wp-site.example/", sitePlatform: "wordpress", isWordpress: true });
  const dependent = JSON.parse(baseRow.dependent_json);
  dependent.plugin = dependent.plugin || {};
  dependent.plugin.detected_platform = "wordpress";
  const sessionRow = withExpectedState(
    {
      ...baseRow,
      dependent_json: JSON.stringify(dependent),
    },
    "Q2_AUDIT_EMAIL_OPTIN"
  );
  const db = createMockDb({
    firstResponses: [sessionRow, { m: 0 }, { m: 1 }],
  });
  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_29_wp_email_optin_plugin",
      state: "Q2_AUDIT_EMAIL_OPTIN",
      answer: "yes and i would like to install the plugin",
    }),
  });

  const response = await worker.fetch(req, { DB: db });
  const body = await response.json();
  assert.equal(response.status, 200);
  assert.equal(body.next_state, "Q2_HAPPY_COSTS");
  assert.match(body.prompt, /email the audit report/i);
  assert.match(body.prompt, /Second part:/i);
});

test("Q2_WP_AUDIT_OFFER maybe returns more-detail prompt instead of error", async () => {
  const baseRow = withExpectedState(
    buildSessionRow({ ownSiteUrl: "https://wp-site.example/", sitePlatform: "wordpress", isWordpress: true }),
    "Q2_WP_AUDIT_OFFER"
  );
  const sessionRow = {
    ...baseRow,
    independent_json: baseRow.independent_json,
    dependent_json: baseRow.dependent_json,
  };
  const db = createMockDb({
    firstResponses: [sessionRow, { m: 0 }, { m: 1 }],
  });
  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_29_wp_audit_maybe",
      state: "Q2_WP_AUDIT_OFFER",
      answer: "maybe, tell me more first",
    }),
  });

  const response = await worker.fetch(req, { DB: db });
  const body = await response.json();
  assert.equal(response.status, 200);
  assert.equal(body.next_state, "Q2_WP_AUDIT_OFFER");
  assert.match(body.prompt, /I can give more detail first/i);
});

test("plugin/connect/start requires WordPress platform", async () => {
  const db = createMockDb({
    firstResponses: [buildSessionRow({ ownSiteUrl: "https://acme.example/" })],
  });
  const req = new Request("https://worker.example/plugin/connect/start", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ session_id: "ses_plugin_non_wp" }),
  });

  const response = await worker.fetch(req, { DB: db });
  const body = await response.json();
  assert.equal(response.status, 400);
  assert.match(body.error, /WordPress sites only/i);
});

test("plugin/connect/start returns connect_id and requirements for WordPress", async () => {
  const sessionRow = buildSessionRow({
    ownSiteUrl: "https://wp-site.example/",
    sitePlatform: "wordpress",
    isWordpress: true,
  });
  const db = createMockDb({
    firstResponses: [sessionRow],
  });

  const req = new Request("https://worker.example/plugin/connect/start", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ session_id: "ses_plugin_start" }),
  });

  const response = await worker.fetch(req, {
    DB: db,
    PLUGIN_FREE_URL: "https://plugin.example/free",
    TOLLDNS_URL: "https://tolldns.example/install",
    GITHUB_SIGNUP_URL: "https://github.com/signup",
  });
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.ok, true);
  assert.match(body.connect_id, /^plg_/);
  assert.equal(body.requirements.tolldns_required_for_free, true);
  assert.ok(Array.isArray(body.cta_actions));
  assert.ok(body.cta_actions.some((a) => a.id === "install_tolldns_required"));
});

test("plugin/connect/verify requires TollDNS for free tier", async () => {
  const baseRow = buildSessionRow({
    ownSiteUrl: "https://wp-site.example/",
    sitePlatform: "wordpress",
    isWordpress: true,
  });
  const independent = JSON.parse(baseRow.independent_json);
  const dependent = JSON.parse(baseRow.dependent_json);
  dependent.plugin = {
    detected_platform: "wordpress",
    connect: {
      pending_connect_id: "plg_test_123",
      status: "pending",
    },
  };
  const sessionRow = {
    ...baseRow,
    independent_json: JSON.stringify(independent),
    dependent_json: JSON.stringify(dependent),
  };
  const db = createMockDb({
    firstResponses: [sessionRow],
  });

  const req = new Request("https://worker.example/plugin/connect/verify", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_plugin_verify_1",
      connect_id: "plg_test_123",
      cloudflare_account_id: "acc_123",
      api_token: "cf_test_token_12345678",
      tolldns_installed: false,
    }),
  });

  const response = await worker.fetch(req, { DB: db });
  const body = await response.json();

  assert.equal(response.status, 400);
  assert.match(body.error, /TollDNS installation is required/i);
});

test("plugin/connect/verify requires GitHub vault connection before activation", async () => {
  const baseRow = buildSessionRow({
    ownSiteUrl: "https://wp-site.example/",
    sitePlatform: "wordpress",
    isWordpress: true,
  });
  const independent = JSON.parse(baseRow.independent_json);
  const dependent = JSON.parse(baseRow.dependent_json);
  dependent.plugin = {
    detected_platform: "wordpress",
    connect: {
      pending_connect_id: "plg_test_gh_required",
      status: "pending",
    },
  };
  const sessionRow = {
    ...baseRow,
    independent_json: JSON.stringify(independent),
    dependent_json: JSON.stringify(dependent),
  };
  const db = createMockDb({
    firstResponses: [sessionRow],
  });
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url) => {
    if (String(url).includes("api.cloudflare.com/client/v4/user/tokens/verify")) {
      return new Response(
        JSON.stringify({
          success: true,
          result: { id: "tok_123", status: "active" },
          errors: [],
          messages: [],
        }),
        { status: 200, headers: { "content-type": "application/json" } }
      );
    }
    return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
  };

  try {
    const req = new Request("https://worker.example/plugin/connect/verify", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        session_id: "ses_plugin_verify_gh_req",
        connect_id: "plg_test_gh_required",
        cloudflare_account_id: "acc_789",
        api_token: "cf_test_token_xyz123456789",
        tolldns_installed: true,
        github_connected: false,
      }),
    });

    const response = await worker.fetch(req, {
      DB: db,
      CONNECT_CLOUDFLARE_URL: "https://connect.example",
      PLUGIN_FREE_URL: "https://plugin.example/free",
      TOLLDNS_URL: "https://tolldns.example/install",
      GITHUB_SIGNUP_URL: "https://github.com/signup",
    });
    const body = await response.json();
    assert.equal(response.status, 400);
    assert.equal(body.requirement, "github_token_required");
    assert.match(body.error, /GitHub token vault connection is required/i);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("plugin/connect/verify validates token and stores masked metadata", async () => {
  const baseRow = buildSessionRow({
    ownSiteUrl: "https://wp-site.example/",
    sitePlatform: "wordpress",
    isWordpress: true,
  });
  const independent = JSON.parse(baseRow.independent_json);
  const dependent = JSON.parse(baseRow.dependent_json);
  dependent.plugin = {
    detected_platform: "wordpress",
    connect: {
      pending_connect_id: "plg_test_456",
      status: "pending",
      token_masked: null,
      token_hash: null,
      token_verified: false,
      tolldns_installed: false,
      github_connected: false,
      github_repo: null,
      connected_at: null,
    },
  };
  const sessionRow = {
    ...baseRow,
    independent_json: JSON.stringify(independent),
    dependent_json: JSON.stringify(dependent),
  };
  const db = createMockDb({
    firstResponses: [sessionRow],
  });
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url) => {
    if (String(url).includes("api.cloudflare.com/client/v4/user/tokens/verify")) {
      return new Response(
        JSON.stringify({
          success: true,
          result: { id: "tok_123", status: "active" },
          errors: [],
          messages: [],
        }),
        { status: 200, headers: { "content-type": "application/json" } }
      );
    }
    return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
  };

  try {
    const req = new Request("https://worker.example/plugin/connect/verify", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        session_id: "ses_plugin_verify_2",
        connect_id: "plg_test_456",
        cloudflare_account_id: "acc_456",
        api_token: "cf_test_token_abcdef123456",
        tolldns_installed: true,
        github_connected: true,
        github_repo: "owner/sandbox-backups",
      }),
    });

    const response = await worker.fetch(req, {
      DB: db,
      CONNECT_CLOUDFLARE_URL: "https://connect.example",
      PLUGIN_FREE_URL: "https://plugin.example/free",
      TOLLDNS_URL: "https://tolldns.example/install",
      GITHUB_SIGNUP_URL: "https://github.com/signup",
    });
    const body = await response.json();

    assert.equal(response.status, 200);
    assert.equal(body.ok, true);
    assert.equal(body.plugin_connection.status, "connected");
    assert.equal(body.plugin_connection.token_verified, true);
    assert.equal(body.plugin_connection.tolldns_installed, true);
    assert.equal(body.plugin_connection.github_connected, true);
    assert.equal(body.plugin_connection.github_repo, "owner/sandbox-backups");
    assert.match(body.plugin_connection.token_masked, /\.\.\./);
    assert.ok(Array.isArray(body.cta_actions));
    assert.ok(body.cta_actions.some((a) => a.id === "install_ai_webadmin_plugin"));
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("plugin/connect/verify rejects plaintext password fields", async () => {
  const baseRow = buildSessionRow({
    ownSiteUrl: "https://wp-site.example/",
    sitePlatform: "wordpress",
    isWordpress: true,
  });
  const sessionRow = {
    ...baseRow,
    dependent_json: JSON.stringify({
      ...JSON.parse(baseRow.dependent_json),
      plugin: {
        connect: {
          pending_connect_id: "plg_test_pw_1",
          status: "pending",
          token_masked: null,
          token_hash: null,
          token_verified: false,
          tolldns_installed: true,
          github_connected: false,
          github_repo: null,
          connected_at: null,
        },
      },
    }),
  };
  const db = createMockDb({
    firstResponses: [sessionRow],
  });
  const req = new Request("https://worker.example/plugin/connect/verify", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_plugin_pw_1",
      connect_id: "plg_test_pw_1",
      tolldns_installed: true,
      api_token: "cf_test_token_abcdef123456",
      panel_password: "SuperSecret123!",
    }),
  });
  const response = await worker.fetch(req, {
    DB: db,
  });
  const body = await response.json();
  assert.equal(response.status, 400);
  assert.match(body.error, /plaintext passwords are never collected/i);
});

test("plugin/wp/comments/moderate rejects when shared secret is not configured", async () => {
  const ts = String(Math.floor(Date.now() / 1000));
  const payload = JSON.stringify({
    site_url: "https://example.com",
    comment_id: 101,
    content: "Great post!",
  });
  const sig = signPluginPayload("dummy", ts, payload);
  const req = new Request("https://worker.example/plugin/wp/comments/moderate", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-plugin-timestamp": ts,
      "x-plugin-signature": sig,
    },
    body: payload,
  });

  const response = await worker.fetch(req, {});
  const body = await response.json();
  assert.equal(response.status, 503);
  assert.match(body.error, /secret is not configured/i);
});

test("plugin/wp/comments/moderate rejects invalid signature", async () => {
  const secret = "super-secret";
  const ts = String(Math.floor(Date.now() / 1000));
  const payload = JSON.stringify({
    site_url: "https://example.com",
    comment_id: 102,
    content: "Great post!",
  });
  const req = new Request("https://worker.example/plugin/wp/comments/moderate", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-plugin-timestamp": ts,
      "x-plugin-signature": "bad-signature",
    },
    body: payload,
  });

  const response = await worker.fetch(req, {
    WP_PLUGIN_SHARED_SECRET: secret,
  });
  const body = await response.json();
  assert.equal(response.status, 401);
  assert.match(body.error, /invalid plugin signature/i);
});

test("plugin/wp/comments/moderate classifies obvious spam as spam or trash", async () => {
  const secret = "super-secret";
  const ts = String(Math.floor(Date.now() / 1000));
  const payload = JSON.stringify({
    site_url: "https://example.com",
    comment_id: 103,
    content:
      "Best casino bonus click https://spam1.example now and https://spam2.example plus https://spam3.example",
    author_name: "SEO9999",
    author_email: "not-an-email",
    author_url: "https://spam4.example",
    user_agent: "",
    ip: "",
  });
  const sig = signPluginPayload(secret, ts, payload);
  const req = new Request("https://worker.example/plugin/wp/comments/moderate", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-plugin-timestamp": ts,
      "x-plugin-signature": sig,
    },
    body: payload,
  });

  const response = await worker.fetch(req, {
    WP_PLUGIN_SHARED_SECRET: secret,
  });
  const body = await response.json();
  assert.equal(response.status, 200);
  assert.equal(body.ok, true);
  assert.ok(["spam", "trash"].includes(body.action));
  assert.ok(["spam", "trash"].includes(body.wp_status));
  assert.ok(body.heuristic.score >= 4);
});

test("plugin/wp/comments/moderate defaults to trash for low-score uncertain comments when aggressive mode is on", async () => {
  const secret = "mod-secret";
  const ts = String(Math.floor(Date.now() / 1000));
  const payload = JSON.stringify({
    site_url: "https://wp-site.example/",
    comment_id: 556,
    content: "Looks good thanks",
    author_name: "John",
    author_email: "john@example.com",
    author_url: "",
    user_agent: "Mozilla/5.0",
    ip: "203.0.113.77",
  });
  const sig = signPluginPayload(secret, ts, payload);

  const req = new Request("https://worker.example/plugin/wp/comments/moderate", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-plugin-timestamp": ts,
      "x-plugin-signature": sig,
    },
    body: payload,
  });

  const response = await worker.fetch(req, {
    WP_PLUGIN_SHARED_SECRET: secret,
    WP_COMMENT_DEFAULT_DELETE: "1",
  });
  const body = await response.json();
  assert.equal(response.status, 200);
  assert.equal(body.ok, true);
  assert.equal(body.moderation_mode, "aggressive_default_delete");
  assert.equal(body.action, "trash");
});

test("plugin/wp/audit/sync stores queue/update/moderation counts", async () => {
  const baseRow = buildSessionRow({
    ownSiteUrl: "https://wp-site.example/",
    sitePlatform: "wordpress",
    isWordpress: true,
  });
  const independent = JSON.parse(baseRow.independent_json);
  const dependent = JSON.parse(baseRow.dependent_json);
  dependent.plugin = {
    detected_platform: "wordpress",
    audit_metrics: {
      email_queue_count: null,
      outdated_plugin_count: null,
      inactive_plugin_count: null,
      redundant_plugin_count: null,
      sso_plugin_count: null,
      pending_comment_moderation_count: null,
      synced_at: null,
    },
    connect: { status: "not_started" },
  };
  const sessionRow = {
    ...baseRow,
    independent_json: JSON.stringify(independent),
    dependent_json: JSON.stringify(dependent),
  };
  const db = createMockDb({
    firstResponses: [sessionRow],
  });

  const secret = "sync-secret";
  const ts = String(Math.floor(Date.now() / 1000));
  const payload = JSON.stringify({
    session_id: "ses_sync_1",
    site_url: "https://wp-site.example/",
    email_queue_count: 3,
    outdated_plugin_count: 5,
    inactive_plugin_count: 9,
    redundant_plugin_count: 2,
    sso_plugin_count: 0,
    pending_comment_moderation_count: 8,
    plugin_total_count: 20,
    active_plugin_count: 11,
    migration_plugin_count: 2,
    unneeded_plugin_count: 7,
    high_risk_plugin_count: 3,
    medium_risk_plugin_count: 4,
    autoload_option_count: 824,
    autoload_total_bytes: 911360,
    autoload_total_kb: 890,
    autoload_last_cleanup_at: 1769980830,
    autoload_last_cleanup_summary: "deleted_expired=22, autoload_flag_updates=71",
    page_cache_builtin_enabled: 1,
    page_cache_ttl_seconds: 600,
    page_cache_last_cleared_at: 1769980800,
    page_cache_last_clear_reason: "autoload_cleanup",
    page_cache_health_status: "critical",
    page_cache_header_detected: 0,
    page_cache_plugin_detected: 0,
    page_cache_median_ttfb_ms: 1923,
    page_cache_checked_at: 1769980840,
    smtp_plugin_count: 1,
    static_export_plugin_count: 1,
    static_export_memory_error_count: 1,
    static_export_removed_plugin_count: 1,
    static_export_last_status: "removed_after_memory_error",
    static_export_last_error_message:
      "Allowed memory size of 268435456 byte exhausted while running Simply Static crawler",
    static_export_last_error_source: "log_file:simply-static.log",
    static_export_last_error_at: 1769980834,
    analytics_site_kit_active: 1,
    analytics_pages_checked_count: 5,
    analytics_pages_with_tracking_count: 3,
    analytics_pages_missing_tracking_count: 2,
    analytics_tag_coverage_percent: 60,
    analytics_measurement_id_count: 1,
    analytics_gtm_container_count: 1,
    analytics_status: "partial",
    woocommerce_active: 1,
    woocommerce_status: "no_sales",
    woocommerce_product_count: 14,
    woocommerce_completed_order_count: 0,
    woocommerce_last_sale_at: 0,
    woocommerce_sales_stale_days: 999,
    inactive_user_deleted_count: 4,
    inactive_user_candidate_count: 10,
    plugin_inventory: {
      active_plugin_slugs: ["wp-super-cache/wp-cache.php", "autoptimize/autoptimize.php"],
      active_plugins: [
        { slug: "wp-super-cache/wp-cache.php", name: "WP Super Cache", version: "1.10.0" },
        { slug: "autoptimize/autoptimize.php", name: "Autoptimize", version: "3.1.0" },
      ],
      inactive_plugin_slugs: ["hello-dolly/hello.php"],
      migration_plugin_slugs: ["all-in-one-wp-migration/all-in-one-wp-migration.php"],
      unneeded_plugin_slugs: ["hello-dolly/hello.php"],
      risk_candidates: [
        {
          slug: "elementor-pro/elementor-pro.php",
          name: "Elementor Pro",
          risk_score: 9,
          risk_level: "high",
          reasons: ["High dependency plugin"],
          functional_checks: ["Homepage template renders", "Lead forms submit"],
        },
      ],
      analytics_missing_urls: ["https://wp-site.example/contact"],
    },
  });
  const sig = signPluginPayload(secret, ts, payload);

  const req = new Request("https://worker.example/plugin/wp/audit/sync", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-plugin-timestamp": ts,
      "x-plugin-signature": sig,
    },
    body: payload,
  });

  const response = await worker.fetch(req, {
    DB: db,
    WP_PLUGIN_SHARED_SECRET: secret,
  });
  const body = await response.json();
  assert.equal(response.status, 200);
  assert.equal(body.ok, true);
  assert.equal(body.audit_metrics.email_queue_count, 3);
  assert.equal(body.audit_metrics.outdated_plugin_count, 5);
  assert.equal(body.audit_metrics.inactive_plugin_count, 9);
  assert.equal(body.audit_metrics.redundant_plugin_count, 2);
  assert.equal(body.audit_metrics.sso_plugin_count, 0);
  assert.equal(body.audit_metrics.pending_comment_moderation_count, 8);
  assert.equal(body.audit_metrics.plugin_total_count, 20);
  assert.equal(body.audit_metrics.active_plugin_count, 11);
  assert.equal(body.audit_metrics.migration_plugin_count, 2);
  assert.equal(body.audit_metrics.unneeded_plugin_count, 7);
  assert.equal(body.audit_metrics.high_risk_plugin_count, 3);
  assert.equal(body.audit_metrics.medium_risk_plugin_count, 4);
  assert.equal(body.audit_metrics.autoload_option_count, 824);
  assert.equal(body.audit_metrics.autoload_total_bytes, 911360);
  assert.equal(body.audit_metrics.autoload_total_kb, 890);
  assert.equal(body.audit_metrics.autoload_last_cleanup_at, 1769980830);
  assert.match(String(body.audit_metrics.autoload_last_cleanup_summary || ""), /deleted_expired=22/i);
  assert.equal(body.audit_metrics.page_cache_builtin_enabled, true);
  assert.equal(body.audit_metrics.page_cache_ttl_seconds, 600);
  assert.equal(body.audit_metrics.page_cache_last_cleared_at, 1769980800);
  assert.equal(body.audit_metrics.page_cache_last_clear_reason, "autoload_cleanup");
  assert.equal(body.audit_metrics.page_cache_health_status, "critical");
  assert.equal(body.audit_metrics.page_cache_header_detected, false);
  assert.equal(body.audit_metrics.page_cache_plugin_detected, false);
  assert.equal(body.audit_metrics.page_cache_median_ttfb_ms, 1923);
  assert.equal(body.audit_metrics.page_cache_checked_at, 1769980840);
  assert.equal(body.audit_metrics.smtp_plugin_count, 1);
  assert.equal(body.audit_metrics.static_export_plugin_count, 1);
  assert.equal(body.audit_metrics.static_export_memory_error_count, 1);
  assert.equal(body.audit_metrics.static_export_removed_plugin_count, 1);
  assert.equal(body.audit_metrics.static_export_last_status, "removed_after_memory_error");
  assert.match(body.audit_metrics.static_export_last_error_message, /Allowed memory size/i);
  assert.equal(body.audit_metrics.static_export_last_error_source, "log_file:simply-static.log");
  assert.equal(body.audit_metrics.static_export_last_error_at, 1769980834);
  assert.equal(body.audit_metrics.analytics_site_kit_active, true);
  assert.equal(body.audit_metrics.analytics_pages_checked_count, 5);
  assert.equal(body.audit_metrics.analytics_pages_with_tracking_count, 3);
  assert.equal(body.audit_metrics.analytics_pages_missing_tracking_count, 2);
  assert.equal(body.audit_metrics.analytics_tag_coverage_percent, 60);
  assert.equal(body.audit_metrics.analytics_measurement_id_count, 1);
  assert.equal(body.audit_metrics.analytics_gtm_container_count, 1);
  assert.equal(body.audit_metrics.analytics_status, "partial");
  assert.equal(body.audit_metrics.analytics_missing_urls[0], "https://wp-site.example/contact");
  assert.equal(body.audit_metrics.woocommerce_active, true);
  assert.equal(body.audit_metrics.woocommerce_status, "no_sales");
  assert.equal(body.audit_metrics.woocommerce_product_count, 14);
  assert.equal(body.audit_metrics.woocommerce_completed_order_count, 0);
  assert.equal(body.audit_metrics.woocommerce_last_sale_at, 0);
  assert.equal(body.audit_metrics.woocommerce_sales_stale_days, 999);
  assert.equal(body.audit_metrics.inactive_user_deleted_count, 4);
  assert.equal(body.audit_metrics.inactive_user_candidate_count, 10);
  assert.equal(body.audit_metrics.plugin_inventory.inactive_plugin_slugs[0], "hello-dolly/hello.php");
  assert.equal(body.audit_metrics.plugin_inventory.active_plugins[0].slug, "wp-super-cache/wp-cache.php");
  assert.equal(body.optimization_plan.clone_status, "missing_github_connection");
  assert.ok(Array.isArray(body.optimization_plan.remove_now));
  assert.ok(body.optimization_plan.remove_now.some((x) => x.slug === "hello-dolly/hello.php"));
  assert.ok(Array.isArray(body.optimization_plan.remove_after_r2_cdn));
  assert.ok(body.optimization_plan.remove_after_r2_cdn.some((x) => x.slug === "wp-super-cache/wp-cache.php"));
});

test("plugin/wp/access/profile stores access metadata with ssh key and encrypted provider token", async () => {
  const baseRow = buildSessionRow({
    ownSiteUrl: "https://wp-site.example/",
    sitePlatform: "wordpress",
    isWordpress: true,
  });
  const dependent = JSON.parse(baseRow.dependent_json);
  dependent.scan = {
    latest_result: {
      infrastructure: {
        hosting_company: "Cloudflare",
        server_hardware_hints: {
          visibility: "public_scan_limited",
          server_stack_hints: ["nginx", "php"],
        },
      },
    },
  };
  const sessionRow = {
    ...baseRow,
    dependent_json: JSON.stringify(dependent),
  };
  const db = createMockDb({
    firstResponses: [sessionRow],
  });
  const secret = "sync-secret";
  const ts = String(Math.floor(Date.now() / 1000));
  const payload = JSON.stringify({
    session_id: "ses_access_profile_1",
    hosting_provider_name: "Cloudflare",
    control_panel_type: "cpanel",
    panel_username: "owner_admin",
    ssh_host: "srv.example.net",
    ssh_port: 22,
    ssh_username: "deploy",
    ssh_public_key:
      "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAID8x4R3fFhTQf8uQ6x6I0Uu8H6m9f1x9Y8kJvQ1kJ7YQ deploy@local",
    auth_preference: "ssh_key_only",
    disable_password_auth: true,
    managed_hosting_expires_at: new Date(Date.now() + 25 * 86400000).toISOString(),
    provider_api_token: "host_api_token_abc123456789",
    source: "plugin_sync",
  });
  const sig = signPluginPayload(secret, ts, payload);
  const req = new Request("https://worker.example/plugin/wp/access/profile", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-plugin-timestamp": ts,
      "x-plugin-signature": sig,
    },
    body: payload,
  });
  const response = await worker.fetch(req, {
    DB: db,
    WP_PLUGIN_SHARED_SECRET: secret,
    CREDENTIAL_VAULT_KEY: "cred-vault-secret-1",
  });
  const body = await response.json();
  assert.equal(response.status, 200);
  assert.equal(body.ok, true);
  assert.equal(body.access_profile.control_panel_type, "cpanel");
  assert.equal(body.access_profile.panel_username, "owner_admin");
  assert.equal(body.access_profile.auth_preference, "ssh_key_only");
  assert.equal(body.access_profile.password_auth_disabled, true);
  assert.match(body.access_profile.ssh_public_key_fingerprint, /^sha256:/);
  assert.match(body.access_profile.provider_api_token_masked, /\.\.\./);
  assert.equal(body.access_profile.free_vps_offer_eligible, true);
  assert.equal(body.access_profile.free_vps_offer_window_days, 30);
  assert.ok(Number(body.access_profile.days_until_managed_hosting_expiry) <= 30);
  assert.equal(body.access_profile.server_hardware_hints.visibility, "public_scan_limited");
});

test("plugin/wp/secrets/vault stores encrypted hosting provider token", async () => {
  const baseRow = buildSessionRow({
    ownSiteUrl: "https://wp-site.example/",
    sitePlatform: "wordpress",
    isWordpress: true,
  });
  const db = createMockDb({
    firstResponses: [baseRow],
  });
  const secret = "sync-secret";
  const ts = String(Math.floor(Date.now() / 1000));
  const payload = JSON.stringify({
    session_id: "ses_secret_vault_1",
    site_url: "https://wp-site.example/",
    secret_type: "hosting_provider_api_token",
    secret_value: "host_tok_abcdefghijklmnop",
    secret_label: "Host API",
  });
  const sig = signPluginPayload(secret, ts, payload);
  const req = new Request("https://worker.example/plugin/wp/secrets/vault", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-plugin-timestamp": ts,
      "x-plugin-signature": sig,
    },
    body: payload,
  });
  const response = await worker.fetch(req, {
    DB: db,
    WP_PLUGIN_SHARED_SECRET: secret,
    CREDENTIAL_VAULT_KEY: "cred-vault-key-1",
  });
  const body = await response.json();
  assert.equal(response.status, 200);
  assert.equal(body.ok, true);
  assert.equal(body.secret_type, "hosting_provider_api_token");
  assert.match(body.masked, /\.\.\./);
});

test("plugin/wp/secrets/vault stores encrypted openai api key", async () => {
  const baseRow = buildSessionRow({
    ownSiteUrl: "https://wp-site.example/",
    sitePlatform: "wordpress",
    isWordpress: true,
  });
  const db = createMockDb({
    firstResponses: [baseRow],
  });
  const secret = "sync-secret";
  const ts = String(Math.floor(Date.now() / 1000));
  const payload = JSON.stringify({
    session_id: "ses_secret_vault_openai_1",
    site_url: "https://wp-site.example/",
    secret_type: "openai_api_key",
    secret_value: "sk-proj_testkey_abcdefghijklmnopqrstuvwxyz123456",
    secret_label: "OpenAI API Key",
  });
  const sig = signPluginPayload(secret, ts, payload);
  const req = new Request("https://worker.example/plugin/wp/secrets/vault", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-plugin-timestamp": ts,
      "x-plugin-signature": sig,
    },
    body: payload,
  });
  const response = await worker.fetch(req, {
    DB: db,
    WP_PLUGIN_SHARED_SECRET: secret,
    CREDENTIAL_VAULT_KEY: "cred-vault-key-1",
  });
  const body = await response.json();
  assert.equal(response.status, 200);
  assert.equal(body.ok, true);
  assert.equal(body.secret_type, "openai_api_key");
  assert.match(body.masked, /^sk-/i);
});

test("plugin/wp/sandbox/preflight returns non-persistent risk report", async () => {
  const baseRow = buildSessionRow({
    ownSiteUrl: "https://wp-site.example/",
    sitePlatform: "wordpress",
    isWordpress: true,
  });
  const db = createMockDb({
    firstResponses: [baseRow],
  });
  const bucketPuts = [];
  const bucket = {
    async put(key, body, opts) {
      bucketPuts.push({ key, body, opts });
      return { key };
    },
  };
  const secret = "sync-secret";
  const ts = String(Math.floor(Date.now() / 1000));
  const payload = JSON.stringify({
    session_id: "ses_sandbox_1",
    site_url: "https://wp-site.example/",
    outdated_plugins: [
      { plugin_file: "elementor/elementor.php", name: "Elementor", current_version: "3.20.0", new_version: "3.24.0" },
      { plugin_file: "hello-dolly/hello.php", name: "Hello Dolly", current_version: "1.7.2", new_version: "1.7.3" },
    ],
    outdated_plugin_count: 2,
    active_plugin_count: 20,
    plugin_total_count: 25,
  });
  const sig = signPluginPayload(secret, ts, payload);
  const req = new Request("https://worker.example/plugin/wp/sandbox/preflight", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-plugin-timestamp": ts,
      "x-plugin-signature": sig,
    },
    body: payload,
  });
  const response = await worker.fetch(req, {
    DB: db,
    WP_PLUGIN_SHARED_SECRET: secret,
    CONVO_BUCKET: bucket,
  });
  const body = await response.json();
  assert.equal(response.status, 200);
  assert.equal(body.ok, true);
  assert.equal(body.sandbox_report.non_persistent, true);
  assert.equal(body.sandbox_report.outdated_plugin_count, 2);
  assert.match(body.sandbox_report.report_id, /^sbox_/);
  assert.ok(body.sandbox_report.sandbox_uninstall_plan);
  assert.ok(Array.isArray(body.sandbox_report.sandbox_uninstall_plan.phase_2_test_one_by_one));
  assert.equal(body.stored_in_r2, true);
  assert.equal(bucketPuts.length, 1);
});

test("plugin/wp/email/forward/config stores forwarding profile for session", async () => {
  const baseRow = buildSessionRow({
    ownSiteUrl: "https://wp-site.example/",
    sitePlatform: "wordpress",
    isWordpress: true,
  });
  const db = createMockDb({
    firstResponses: [baseRow],
  });
  const secret = "sync-secret";
  const ts = String(Math.floor(Date.now() / 1000));
  const payload = JSON.stringify({
    session_id: "ses_email_cfg_1",
    site_url: "https://wp-site.example/",
    forward_to_email: "owner@example.com",
    has_mx_records: true,
    mx_records: [
      { target: "aspmx.l.google.com", pri: 1 },
      { target: "alt1.aspmx.l.google.com", pri: 5 },
    ],
    email_provider_hint: "Google Workspace",
    source: "plugin_sync",
  });
  const sig = signPluginPayload(secret, ts, payload);
  const req = new Request("https://worker.example/plugin/wp/email/forward/config", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-plugin-timestamp": ts,
      "x-plugin-signature": sig,
    },
    body: payload,
  });
  const response = await worker.fetch(req, {
    DB: db,
    WP_PLUGIN_SHARED_SECRET: secret,
  });
  const body = await response.json();
  assert.equal(response.status, 200);
  assert.equal(body.ok, true);
  assert.equal(body.email_forwarding.enabled, true);
  assert.equal(body.email_forwarding.forward_to_email, "owner@example.com");
  assert.equal(body.email_forwarding.has_mx_records, true);
  assert.equal(body.email_forwarding.email_provider_hint, "Google Workspace");
  assert.equal(body.email_forwarding.mx_record_count, 2);
  assert.equal(body.email_forwarding.verification.status, "unverified");
  assert.equal(body.email_forwarding.verification.verified, false);
});

test("plugin/wp/email/forward/verification/start returns verify link and pending state", async () => {
  const baseRow = buildSessionRow({
    ownSiteUrl: "https://wp-site.example/",
    sitePlatform: "wordpress",
    isWordpress: true,
  });
  const db = createMockDb({
    firstResponses: [baseRow],
  });
  const secret = "sync-secret";
  const ts = String(Math.floor(Date.now() / 1000));
  const payload = JSON.stringify({
    session_id: "ses_email_verify_start_1",
    site_url: "https://wp-site.example/",
    forward_to_email: "owner@example.com",
  });
  const sig = signPluginPayload(secret, ts, payload);
  const req = new Request("https://worker.example/plugin/wp/email/forward/verification/start", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-plugin-timestamp": ts,
      "x-plugin-signature": sig,
    },
    body: payload,
  });
  const response = await worker.fetch(req, {
    DB: db,
    WP_PLUGIN_SHARED_SECRET: secret,
  });
  const body = await response.json();
  assert.equal(response.status, 200);
  assert.equal(body.ok, true);
  assert.equal(body.verification.status, "pending");
  assert.equal(body.verification.verified, false);
  assert.match(body.verification_url, /\/plugin\/wp\/email\/forward\/verification\/confirm\?/);
});

test("plugin/wp/email/forward/verification/confirm marks verification as complete", async () => {
  const token = "verify-token-123";
  const tokenHash = createHash("sha256").update(token).digest("hex");
  const baseRow = buildSessionRow({
    ownSiteUrl: "https://wp-site.example/",
    sitePlatform: "wordpress",
    isWordpress: true,
  });
  const dependent = JSON.parse(baseRow.dependent_json);
  dependent.plugin = {
    email_forwarding: {
      enabled: true,
      forward_to_email: "owner@example.com",
      verification_status: "pending",
      verification_email: "owner@example.com",
      verification_sent_at: Date.now() - 5_000,
      verification_confirmed_at: null,
      verification_pending_token_hash: tokenHash,
      verification_pending_expires_at: new Date(Date.now() + 3600_000).toISOString(),
      verification_last_token_id: "lfv_test_1",
      verification_last_error: null,
    },
  };
  const sessionRow = {
    ...baseRow,
    dependent_json: JSON.stringify(dependent),
  };
  const db = createMockDb({
    firstResponses: [sessionRow],
  });
  const req = new Request(
    `https://worker.example/plugin/wp/email/forward/verification/confirm?session_id=ses_email_verify_confirm_1&token=${encodeURIComponent(
      token
    )}&token_id=lfv_test_1`
  );
  const response = await worker.fetch(req, {
    DB: db,
  });
  const html = await response.text();
  assert.equal(response.status, 200);
  assert.match(html, /Email forwarding verified/i);
});

test("plugin/wp/email/forward/verification/status returns verification summary", async () => {
  const baseRow = buildSessionRow({
    ownSiteUrl: "https://wp-site.example/",
    sitePlatform: "wordpress",
    isWordpress: true,
  });
  const dependent = JSON.parse(baseRow.dependent_json);
  dependent.plugin = {
    email_forwarding: {
      enabled: true,
      forward_to_email: "owner@example.com",
      verification_status: "verified",
      verification_email: "owner@example.com",
      verification_sent_at: Date.now() - 120_000,
      verification_confirmed_at: Date.now() - 60_000,
      verification_pending_token_hash: null,
      verification_pending_expires_at: null,
      verification_last_token_id: "lfv_test_2",
      verification_last_error: null,
    },
  };
  const sessionRow = {
    ...baseRow,
    dependent_json: JSON.stringify(dependent),
  };
  const db = createMockDb({
    firstResponses: [sessionRow],
  });
  const secret = "sync-secret";
  const ts = String(Math.floor(Date.now() / 1000));
  const payload = JSON.stringify({
    session_id: "ses_email_verify_status_1",
  });
  const sig = signPluginPayload(secret, ts, payload);
  const req = new Request("https://worker.example/plugin/wp/email/forward/verification/status", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-plugin-timestamp": ts,
      "x-plugin-signature": sig,
    },
    body: payload,
  });
  const response = await worker.fetch(req, {
    DB: db,
    WP_PLUGIN_SHARED_SECRET: secret,
  });
  const body = await response.json();
  assert.equal(response.status, 200);
  assert.equal(body.ok, true);
  assert.equal(body.verification.status, "verified");
  assert.equal(body.verification.verified, true);
});

test("plugin/wp/lead/forward stores lead event in R2 and sends webhook when configured", async () => {
  const baseRow = buildSessionRow({
    ownSiteUrl: "https://wp-site.example/",
    sitePlatform: "wordpress",
    isWordpress: true,
  });
  const dependent = JSON.parse(baseRow.dependent_json);
  dependent.plugin = {
    email_forwarding: {
      enabled: true,
      forward_to_email: "owner@example.com",
      has_mx_records: true,
      email_provider_hint: "Google Workspace",
      mx_records: [{ target: "aspmx.l.google.com", pri: 1 }],
    },
  };
  const sessionRow = {
    ...baseRow,
    dependent_json: JSON.stringify(dependent),
  };
  const db = createMockDb({
    firstResponses: [sessionRow],
  });
  const bucketPuts = [];
  const bucket = {
    async put(key, body, opts) {
      bucketPuts.push({ key, body, opts });
      return { key };
    },
  };
  const secret = "sync-secret";
  const ts = String(Math.floor(Date.now() / 1000));
  const payload = JSON.stringify({
    session_id: "ses_lead_forward_1",
    site_url: "https://wp-site.example/",
    subject: "New contact form submission",
    message: "Name: Jane Doe\nEmail: jane@example.com\nMessage: Need a quote.",
    source: "wp_mail_hook",
    has_mx_records: true,
    mx_records: [{ target: "aspmx.l.google.com", pri: 1 }],
    email_provider_hint: "Google Workspace",
  });
  const sig = signPluginPayload(secret, ts, payload);
  const originalFetch = globalThis.fetch;
  const hookCalls = [];
  globalThis.fetch = async (target, init) => {
    hookCalls.push({ target: String(target), init });
    return new Response(JSON.stringify({ ok: true }), {
      status: 202,
      headers: { "content-type": "application/json" },
    });
  };

  try {
    const req = new Request("https://worker.example/plugin/wp/lead/forward", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-plugin-timestamp": ts,
        "x-plugin-signature": sig,
      },
      body: payload,
    });
    const response = await worker.fetch(req, {
      DB: db,
      WP_PLUGIN_SHARED_SECRET: secret,
      CONVO_BUCKET: bucket,
      LEAD_FORWARD_WEBHOOK_URL: "https://hooks.example/lead",
      LEAD_FORWARD_WEBHOOK_SECRET: "hook-secret",
    });
    const body = await response.json();
    assert.equal(response.status, 200);
    assert.equal(body.ok, true);
    assert.equal(body.forward_to_email, "owner@example.com");
    assert.equal(body.stored_in_r2, true);
    assert.equal(bucketPuts.length, 1);
    assert.match(bucketPuts[0].key, /plugin-lead-forward\/ses_lead_forward_1\//);
    assert.equal(body.webhook.attempted, true);
    assert.equal(body.webhook.ok, true);
    assert.equal(body.webhook.status, 202);
    assert.equal(hookCalls.length, 1);
    assert.equal(hookCalls[0].target, "https://hooks.example/lead");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("plugin/wp/schema/profile returns saved schema profile for session", async () => {
  const baseRow = buildSessionRow({
    ownSiteUrl: "https://wp-site.example/",
    sitePlatform: "wordpress",
    isWordpress: true,
  });
  const independent = JSON.parse(baseRow.independent_json);
  const dependent = JSON.parse(baseRow.dependent_json);
  dependent.schema_setup = {
    status: "ready",
    profile: {
      business_name: "Supreme X Detail",
      schema_type: "AutoDetailing",
      phone: "+17755550100",
    },
    jsonld: "{\"@context\":\"https://schema.org\",\"@type\":\"AutoDetailing\",\"name\":\"Supreme X Detail\"}",
  };
  const sessionRow = {
    ...baseRow,
    independent_json: JSON.stringify(independent),
    dependent_json: JSON.stringify(dependent),
  };
  const db = createMockDb({
    firstResponses: [sessionRow],
  });

  const secret = "sync-secret";
  const ts = String(Math.floor(Date.now() / 1000));
  const payload = JSON.stringify({
    session_id: "ses_schema_1",
    site_url: "https://wp-site.example/",
  });
  const sig = signPluginPayload(secret, ts, payload);

  const req = new Request("https://worker.example/plugin/wp/schema/profile", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-plugin-timestamp": ts,
      "x-plugin-signature": sig,
    },
    body: payload,
  });

  const response = await worker.fetch(req, {
    DB: db,
    WP_PLUGIN_SHARED_SECRET: secret,
  });
  const body = await response.json();
  assert.equal(response.status, 200);
  assert.equal(body.ok, true);
  assert.equal(body.schema_status, "ready");
  assert.equal(body.schema_profile.business_name, "Supreme X Detail");
  assert.match(body.schema_jsonld, /AutoDetailing/);
});

test("plugin/wp/redirects/profile returns normalized broken-link redirect paths", async () => {
  const baseRow = buildSessionRow({
    ownSiteUrl: "https://wp-site.example/",
    sitePlatform: "wordpress",
    isWordpress: true,
  });
  const independent = JSON.parse(baseRow.independent_json);
  const dependent = JSON.parse(baseRow.dependent_json);
  dependent.scan = {
    latest_result: {
      link_audit: {
        checked_count: 22,
        broken_count: 4,
        broken_paths: ["/old-page", "https://wp-site.example/dead-offer?x=1", "/wp-admin/tools.php", "/"],
      },
    },
  };
  const sessionRow = {
    ...baseRow,
    independent_json: JSON.stringify(independent),
    dependent_json: JSON.stringify(dependent),
  };
  const db = createMockDb({
    firstResponses: [sessionRow],
  });

  const secret = "sync-secret";
  const ts = String(Math.floor(Date.now() / 1000));
  const payload = JSON.stringify({
    session_id: "ses_redirects_1",
    site_url: "https://wp-site.example/",
  });
  const sig = signPluginPayload(secret, ts, payload);

  const req = new Request("https://worker.example/plugin/wp/redirects/profile", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-plugin-timestamp": ts,
      "x-plugin-signature": sig,
    },
    body: payload,
  });

  const response = await worker.fetch(req, {
    DB: db,
    WP_PLUGIN_SHARED_SECRET: secret,
  });
  const body = await response.json();
  assert.equal(response.status, 200);
  assert.equal(body.ok, true);
  assert.equal(body.checked_link_count, 22);
  assert.equal(body.broken_link_count, 4);
  assert.deepEqual(body.redirect_paths, ["/old-page", "/dead-offer?x=1"]);
});

test("plugin/wp/media/enrich returns OpenAI-generated metadata for image assets", async () => {
  const baseRow = buildSessionRow({
    ownSiteUrl: "https://wp-site.example/",
    sitePlatform: "wordpress",
    isWordpress: true,
  });
  const db = createMockDb({
    firstResponses: [baseRow, { m: 0 }, { m: 1 }],
  });
  const secret = "sync-secret";
  const ts = String(Math.floor(Date.now() / 1000));
  const payload = JSON.stringify({
    session_id: "ses_media_enrich_1",
    site_url: "https://wp-site.example/",
    context: {
      brand: "Supreme X Auto Detailing",
      location: "Reno, Nevada",
      primary_keyword: "car detailing",
    },
    assets: [{ attachment_id: 5677, url: "https://wp-site.example/wp-content/uploads/2026/01/photo.jpg" }],
  });
  const sig = signPluginPayload(secret, ts, payload);
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (target) => {
    const url = String(target);
    if (url.includes("api.openai.com/v1/responses")) {
      return new Response(
        JSON.stringify({
          output_text:
            '{"title":"Supreme X Auto Detailing Reno - Detailed Ambulance Rear View","alt":"Rear view of a freshly detailed ambulance by Supreme X Auto Detailing in Reno, Nevada.","caption":"Freshly detailed and ready for the road - Supreme X Auto Detailing, Reno NV","description":"Rear view of an ambulance freshly detailed by Supreme X Auto Detailing in Reno, Nevada.","filename_slug":"supreme-x-auto-detailing-reno-detailed-ambulance-rear-view"}',
        }),
        { status: 200, headers: { "content-type": "application/json" } }
      );
    }
    throw new Error(`unexpected fetch target: ${url}`);
  };

  try {
    const req = new Request("https://worker.example/plugin/wp/media/enrich", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-plugin-timestamp": ts,
        "x-plugin-signature": sig,
      },
      body: payload,
    });
    const response = await worker.fetch(req, {
      DB: db,
      WP_PLUGIN_SHARED_SECRET: secret,
      OPENAI_API_KEY: "sk-test-key-12345678901234567890",
    });
    const body = await response.json();
    assert.equal(response.status, 200);
    assert.equal(body.ok, true);
    assert.equal(body.processed_count, 1);
    assert.equal(body.failed_count, 0);
    assert.equal(body.openai_configured, true);
    assert.equal(body.items?.[0]?.source, "openai");
    assert.equal(body.items?.[0]?.attachment_id, 5677);
    assert.match(String(body.items?.[0]?.metadata?.alt || ""), /freshly detailed ambulance/i);
    assert.match(String(body.items?.[0]?.metadata?.filename_slug || ""), /^supreme-x-auto-detailing-reno-detailed-ambulance-rear-view/);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("plugin/wp/media/enrich can use vault OpenAI key encrypted with credential vault key", async () => {
  const baseRow = buildSessionRow({
    ownSiteUrl: "https://wp-site.example/",
    sitePlatform: "wordpress",
    isWordpress: true,
  });
  const independent = JSON.parse(baseRow.independent_json);
  const dependent = JSON.parse(baseRow.dependent_json);
  const vaultKey = "cred-vault-key-media-enrich-1";
  const cipher = await encryptVaultTokenForTest("sk-test-vault-openai-key-123456789012345", vaultKey);
  dependent.plugin = dependent.plugin || {};
  dependent.plugin.secrets_vault = dependent.plugin.secrets_vault || {};
  dependent.plugin.secrets_vault.items = dependent.plugin.secrets_vault.items || {};
  dependent.plugin.secrets_vault.items.openai_api_key = {
    token_cipher: cipher,
  };
  const sessionRow = {
    ...baseRow,
    independent_json: JSON.stringify(independent),
    dependent_json: JSON.stringify(dependent),
  };
  const db = createMockDb({
    firstResponses: [sessionRow, { m: 0 }, { m: 1 }],
  });
  const secret = "sync-secret";
  const ts = String(Math.floor(Date.now() / 1000));
  const payload = JSON.stringify({
    session_id: "ses_media_enrich_vault_1",
    site_url: "https://wp-site.example/",
    assets: [{ attachment_id: 42, url: "https://wp-site.example/wp-content/uploads/2026/01/photo.jpg" }],
  });
  const sig = signPluginPayload(secret, ts, payload);
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (target) => {
    const url = String(target);
    if (url.includes("api.openai.com/v1/responses")) {
      return new Response(
        JSON.stringify({
          output_text:
            '{"title":"Detailed Vehicle","alt":"Freshly detailed vehicle in driveway.","caption":"Detailed and ready.","description":"Vehicle exterior after detailing service.","filename_slug":"detailed-vehicle"}',
        }),
        { status: 200, headers: { "content-type": "application/json" } }
      );
    }
    throw new Error(`unexpected fetch target: ${url}`);
  };
  try {
    const req = new Request("https://worker.example/plugin/wp/media/enrich", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-plugin-timestamp": ts,
        "x-plugin-signature": sig,
      },
      body: payload,
    });
    const response = await worker.fetch(req, {
      DB: db,
      WP_PLUGIN_SHARED_SECRET: secret,
      CREDENTIAL_VAULT_KEY: vaultKey,
    });
    const body = await response.json();
    assert.equal(response.status, 200);
    assert.equal(body.ok, true);
    assert.equal(body.openai_configured, true);
    assert.equal(body.items?.[0]?.source, "openai");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("plugin/wp/media/enrich falls back when OpenAI key is unavailable", async () => {
  const baseRow = buildSessionRow({
    ownSiteUrl: "https://wp-site.example/",
    sitePlatform: "wordpress",
    isWordpress: true,
  });
  const db = createMockDb({
    firstResponses: [baseRow, { m: 0 }, { m: 1 }],
  });
  const secret = "sync-secret";
  const ts = String(Math.floor(Date.now() / 1000));
  const payload = JSON.stringify({
    session_id: "ses_media_enrich_fallback_1",
    site_url: "https://wp-site.example/",
    context: {
      brand: "Supreme X Auto Detailing",
      location: "Reno, Nevada",
      primary_keyword: "car detailing",
    },
    assets: [{ attachment_id: 55, url: "https://wp-site.example/wp-content/uploads/2026/01/photo.jpg" }],
  });
  const sig = signPluginPayload(secret, ts, payload);

  const req = new Request("https://worker.example/plugin/wp/media/enrich", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-plugin-timestamp": ts,
      "x-plugin-signature": sig,
    },
    body: payload,
  });
  const response = await worker.fetch(req, {
    DB: db,
    WP_PLUGIN_SHARED_SECRET: secret,
  });
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.ok, true);
  assert.equal(body.openai_configured, false);
  assert.equal(body.processed_count, 1);
  assert.equal(body.items?.[0]?.source, "fallback");
  assert.match(String(body.items?.[0]?.metadata?.title || ""), /Supreme X Auto Detailing/i);
  assert.ok(String(body.items?.[0]?.metadata?.filename_slug || "").length > 0);
});

test("plugin/wp/media/offload stores image batch in R2 and writes manifest", async () => {
  const baseRow = buildSessionRow({
    ownSiteUrl: "https://wp-site.example/",
    sitePlatform: "wordpress",
    isWordpress: true,
  });
  const db = createMockDb({
    firstResponses: [baseRow],
  });
  const bucketPuts = [];
  const bucket = {
    async put(key, body, opts) {
      bucketPuts.push({ key, body, opts });
      return { key };
    },
  };
  const secret = "sync-secret";
  const ts = String(Math.floor(Date.now() / 1000));
  const payload = JSON.stringify({
    session_id: "ses_media_offload_1",
    site_url: "https://wp-site.example/",
    media_public_base_url: "https://media.wp-site.example",
    assets: [{ attachment_id: 11, url: "https://wp-site.example/wp-content/uploads/2026/01/photo.jpg" }],
  });
  const sig = signPluginPayload(secret, ts, payload);
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (target) => {
    const url = String(target);
    if (url.includes("/wp-content/uploads/2026/01/photo.jpg")) {
      return new Response(new Uint8Array([1, 2, 3, 4]), {
        status: 200,
        headers: { "content-type": "image/jpeg" },
      });
    }
    throw new Error(`unexpected fetch target: ${url}`);
  };

  try {
    const req = new Request("https://worker.example/plugin/wp/media/offload", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-plugin-timestamp": ts,
        "x-plugin-signature": sig,
      },
      body: payload,
    });
    const response = await worker.fetch(req, {
      DB: db,
      WP_PLUGIN_SHARED_SECRET: secret,
      CONVO_BUCKET: bucket,
    });
    const body = await response.json();
    assert.equal(response.status, 200);
    assert.equal(body.ok, true);
    assert.equal(body.processed_count, 1);
    assert.equal(body.failed_count, 0);
    assert.equal(body.media_public_base_url, "https://media.wp-site.example");
    assert.ok(Array.isArray(body.processed));
    assert.equal(body.processed[0].attachment_id, 11);
    assert.match(String(body.processed[0].public_url || ""), /^https:\/\/media\.wp-site\.example\/wp-media-cache\//);
    assert.match(String(body.manifest_r2_key || ""), /^wp-media-cache\/ses_media_offload_1\/manifests\//);
    assert.ok(bucketPuts.some((x) => String(x.key).includes("/att_11.jpg")));
    assert.ok(bucketPuts.some((x) => String(x.key).includes("/manifests/")));
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("plugin/wp/media/offload honors provided SEO r2 key", async () => {
  const baseRow = buildSessionRow({
    ownSiteUrl: "https://wp-site.example/",
    sitePlatform: "wordpress",
    isWordpress: true,
  });
  const db = createMockDb({
    firstResponses: [baseRow],
  });
  const bucketPuts = [];
  const bucket = {
    async put(key, body, opts) {
      bucketPuts.push({ key, body, opts });
      return { key };
    },
  };
  const secret = "sync-secret";
  const ts = String(Math.floor(Date.now() / 1000));
  const customKey = "wp-media-cache/ses_media_offload_custom/wp-site.example/2026/01/supreme-x-auto-detailing-reno-detailed-ambulance-rear-view.jpg";
  const payload = JSON.stringify({
    session_id: "ses_media_offload_custom",
    site_url: "https://wp-site.example/",
    media_public_base_url: "https://media.wp-site.example",
    assets: [
      {
        attachment_id: 5677,
        url: "https://wp-site.example/wp-content/uploads/2026/01/photo.jpg",
        r2_key: customKey,
      },
    ],
  });
  const sig = signPluginPayload(secret, ts, payload);
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (target) => {
    const url = String(target);
    if (url.includes("/wp-content/uploads/2026/01/photo.jpg")) {
      return new Response(new Uint8Array([4, 3, 2, 1]), {
        status: 200,
        headers: { "content-type": "image/jpeg" },
      });
    }
    throw new Error(`unexpected fetch target: ${url}`);
  };

  try {
    const req = new Request("https://worker.example/plugin/wp/media/offload", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-plugin-timestamp": ts,
        "x-plugin-signature": sig,
      },
      body: payload,
    });
    const response = await worker.fetch(req, {
      DB: db,
      WP_PLUGIN_SHARED_SECRET: secret,
      CONVO_BUCKET: bucket,
    });
    const body = await response.json();
    assert.equal(response.status, 200);
    assert.equal(body.ok, true);
    assert.equal(body.processed_count, 1);
    assert.equal(String(body.processed?.[0]?.key || ""), customKey);
    assert.equal(String(body.processed?.[0]?.public_url || ""), `https://media.wp-site.example/${customKey}`);
    assert.ok(bucketPuts.some((x) => String(x.key) === customKey));
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("plugin/wp/github/vault stores masked token and repo metadata", async () => {
  const baseRow = buildSessionRow({
    ownSiteUrl: "https://wp-site.example/",
    sitePlatform: "wordpress",
    isWordpress: true,
  });
  const db = createMockDb({
    firstResponses: [baseRow],
  });
  const secret = "sync-secret";
  const ts = String(Math.floor(Date.now() / 1000));
  const payload = JSON.stringify({
    session_id: "ses_github_vault_1",
    site_url: "https://wp-site.example/",
    github_repo: "owner/repo",
    github_branch: "main",
    github_token: "ghp_example_token_1234567890",
  });
  const sig = signPluginPayload(secret, ts, payload);
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (target) => {
    const url = String(target);
    if (url === "https://api.github.com/user") {
      return new Response(JSON.stringify({ login: "repo-owner", id: 12345 }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }
    throw new Error(`unexpected fetch target: ${url}`);
  };

  try {
    const req = new Request("https://worker.example/plugin/wp/github/vault", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-plugin-timestamp": ts,
        "x-plugin-signature": sig,
      },
      body: payload,
    });
    const response = await worker.fetch(req, {
      DB: db,
      WP_PLUGIN_SHARED_SECRET: secret,
      GITHUB_VAULT_KEY: "vault-key-1",
    });
    const body = await response.json();
    assert.equal(response.status, 200);
    assert.equal(body.ok, true);
    assert.equal(body.github_repo, "owner/repo");
    assert.equal(body.github_user, "repo-owner");
    assert.match(body.token_masked, /\.\.\./);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("plugin/wp/backup/snapshot stores snapshot in R2 and degrades when github vault is missing", async () => {
  const baseRow = buildSessionRow({
    ownSiteUrl: "https://wp-site.example/",
    sitePlatform: "wordpress",
    isWordpress: true,
  });
  const sessionRow = {
    ...baseRow,
    dependent_json: JSON.stringify({
      ...JSON.parse(baseRow.dependent_json),
      plugin: {
        github_vault: {
          connected: false,
        },
      },
    }),
  };
  const db = createMockDb({
    firstResponses: [sessionRow],
  });
  const bucketPuts = [];
  const bucket = {
    async put(key, body, opts) {
      bucketPuts.push({ key, body, opts });
      return { key };
    },
  };
  const secret = "sync-secret";
  const ts = String(Math.floor(Date.now() / 1000));
  const payload = JSON.stringify({
    session_id: "ses_backup_1",
    site_url: "https://wp-site.example/",
    github_repo: "owner/repo",
    snapshot: {
      generated_at: "2026-02-25T00:00:00.000Z",
      scanned_files: 2,
      manifest_count: 2,
      files: [
        { path: "wp-config.php", size: 100, mtime: 1700000000, sha256: "abc" },
        { path: "index.php", size: 200, mtime: 1700000001, sha256: "def" },
      ],
    },
  });
  const sig = signPluginPayload(secret, ts, payload);
  const req = new Request("https://worker.example/plugin/wp/backup/snapshot", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-plugin-timestamp": ts,
      "x-plugin-signature": sig,
    },
    body: payload,
  });
  const response = await worker.fetch(req, {
    DB: db,
    WP_PLUGIN_SHARED_SECRET: secret,
    CONVO_BUCKET: bucket,
  });
  const body = await response.json();
  assert.equal(response.status, 200);
  assert.equal(body.ok, true);
  assert.equal(bucketPuts.length, 1);
  assert.match(body.message, /saved to Cloudflare/i);
  assert.equal(body.github.ok, false);
});

test("plugin/wp/auth/wallet/verify requires configured verification gateway", async () => {
  const baseRow = buildSessionRow({
    ownSiteUrl: "https://wp-site.example/",
    sitePlatform: "wordpress",
    isWordpress: true,
  });
  const db = createMockDb({
    firstResponses: [baseRow],
  });
  const secret = "sync-secret";
  const ts = String(Math.floor(Date.now() / 1000));
  const payload = JSON.stringify({
    session_id: "ses_wallet_1",
    site_url: "https://wp-site.example/",
    user_id: 77,
    user_login: "admin",
    wallet_address: "0x1111111111111111111111111111111111111111",
    wallet_signature: "0xdeadbeef",
    wallet_message: "AI WebAdmin Login Challenge\nNonce: abc123",
    wallet_nonce: "abc123",
    wallet_chain_id: 1,
  });
  const sig = signPluginPayload(secret, ts, payload);
  const req = new Request("https://worker.example/plugin/wp/auth/wallet/verify", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-plugin-timestamp": ts,
      "x-plugin-signature": sig,
    },
    body: payload,
  });
  const response = await worker.fetch(req, {
    DB: db,
    WP_PLUGIN_SHARED_SECRET: secret,
  });
  const body = await response.json();
  assert.equal(response.status, 400);
  assert.equal(body.verified, false);
  assert.match(body.error, /gateway not configured/i);
});

test("plugin/wp/auth/wallet/verify accepts webhook-verified wallet signature", async () => {
  const baseRow = buildSessionRow({
    ownSiteUrl: "https://wp-site.example/",
    sitePlatform: "wordpress",
    isWordpress: true,
  });
  const db = createMockDb({
    firstResponses: [baseRow, { m: 0 }, { m: 1 }],
  });
  const secret = "sync-secret";
  const ts = String(Math.floor(Date.now() / 1000));
  const payload = JSON.stringify({
    session_id: "ses_wallet_2",
    site_url: "https://wp-site.example/",
    user_id: 88,
    user_login: "owner",
    wallet_address: "0x2222222222222222222222222222222222222222",
    wallet_signature: "0xbeadfeed",
    wallet_message: "AI WebAdmin Login Challenge\nNonce: nonce77",
    wallet_nonce: "nonce77",
    wallet_chain_id: 1,
  });
  const sig = signPluginPayload(secret, ts, payload);
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (target, init) => {
    const url = String(target);
    if (url === "https://wallet-verify.example/verify") {
      const posted = JSON.parse(String(init?.body || "{}"));
      return new Response(
        JSON.stringify({
          ok: true,
          verified: true,
          wallet_address: posted.wallet_address,
          source: "test_wallet_gateway",
        }),
        {
          status: 200,
          headers: { "content-type": "application/json" },
        }
      );
    }
    throw new Error(`unexpected fetch target: ${url}`);
  };

  try {
    const req = new Request("https://worker.example/plugin/wp/auth/wallet/verify", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-plugin-timestamp": ts,
        "x-plugin-signature": sig,
      },
      body: payload,
    });
    const response = await worker.fetch(req, {
      DB: db,
      WP_PLUGIN_SHARED_SECRET: secret,
      WALLET_VERIFY_WEBHOOK: "https://wallet-verify.example/verify",
      WALLET_VERIFY_WEBHOOK_SECRET: "wallet-webhook-secret",
    });
    const body = await response.json();
    assert.equal(response.status, 200);
    assert.equal(body.ok, true);
    assert.equal(body.verified, true);
    assert.equal(body.wallet_address, "0x2222222222222222222222222222222222222222");
    assert.equal(body.source, "test_wallet_gateway");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("plugin/wp/agent/chat returns proof-backed answer with source paths", async () => {
  const baseRow = buildSessionRow({
    ownSiteUrl: "https://wp-site.example/",
    sitePlatform: "wordpress",
    isWordpress: true,
  });
  const dependent = JSON.parse(baseRow.dependent_json);
  dependent.plugin = {
    audit_metrics: {
      outdated_plugin_count: 4,
      inactive_plugin_count: 2,
      redundant_plugin_count: 1,
      plugin_inventory: {
        active_plugin_slugs: ["wp-super-cache/wp-cache.php", "autoptimize/autoptimize.php"],
        active_plugins: [
          { slug: "wp-super-cache/wp-cache.php", name: "WP Super Cache", version: "1.10.0" },
          { slug: "autoptimize/autoptimize.php", name: "Autoptimize", version: "3.1.0" },
        ],
        inactive_plugin_slugs: ["hello-dolly/hello.php"],
        migration_plugin_slugs: [],
        unneeded_plugin_slugs: ["hello-dolly/hello.php"],
      },
    },
    github_vault: { connected: true },
    backup: { last_github_status: "ok", last_github_path: "sitebuilder-backups/wp-site/2026-02-25/1.json" },
  };
  const sessionRow = {
    ...baseRow,
    dependent_json: JSON.stringify(dependent),
  };
  const db = createMockDb({
    firstResponses: [sessionRow],
  });
  const secret = "sync-secret";
  const ts = String(Math.floor(Date.now() / 1000));
  const payload = JSON.stringify({
    session_id: "ses_agent_chat_1",
    question: "Which plugins can I remove after r2 and cdn caching?",
  });
  const sig = signPluginPayload(secret, ts, payload);
  const req = new Request("https://worker.example/plugin/wp/agent/chat", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-plugin-timestamp": ts,
      "x-plugin-signature": sig,
    },
    body: payload,
  });
  const response = await worker.fetch(req, {
    DB: db,
    WP_PLUGIN_SHARED_SECRET: secret,
  });
  const body = await response.json();
  assert.equal(response.status, 200);
  assert.equal(body.ok, true);
  assert.ok(Array.isArray(body.proofs));
  assert.ok(body.proofs.length > 0);
  assert.ok(body.proofs.some((p) => String(p.source_path || "").includes("dependent.plugin.optimization.plan")));
  assert.match(String(body.answer || "").toLowerCase(), /plugin cleanup plan|remove/);
});

test("Q3_VIEWING_DEMO keeps user in viewing step when link did not open", async () => {
  const baseRow = withExpectedState(buildSessionRow({ ownSiteUrl: null }), "Q3_VIEWING_DEMO");
  const sessionRow = withDemoUrl(baseRow, "https://demo-link.example");
  const db = createMockDb({
    firstResponses: [sessionRow, { m: 0 }, { m: 1 }],
  });

  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_30",
      state: "Q3_VIEWING_DEMO",
      answer: "nothing opened in a new tab",
    }),
  });

  const response = await worker.fetch(req, { DB: db });
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.next_state, "Q3_VIEWING_DEMO");
  assert.match(String(body.demo_url || ""), /^https:\/\/demo-link\.example\/?$/);
});

test("Q3_VIEWING_DEMO handles 400-style error feedback with safer retry guidance", async () => {
  const baseRow = withExpectedState(buildSessionRow({ ownSiteUrl: null }), "Q3_VIEWING_DEMO");
  const sessionRow = withDemoUrl(baseRow, "https://demo-link.example");
  const db = createMockDb({
    firstResponses: [sessionRow, { m: 0 }, { m: 1 }],
  });

  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_30_400",
      state: "Q3_VIEWING_DEMO",
      answer: "I got a 400 bad request on that link",
    }),
  });

  const response = await worker.fetch(req, { DB: db });
  const body = await response.json();
  assert.equal(response.status, 200);
  assert.equal(body.next_state, "Q3_VIEWING_DEMO");
  assert.match(String(body.prompt || ""), /paste a direct website url/i);
});

test("Q3_VIEWING_DEMO help-style message returns plain-language next step", async () => {
  const baseRow = withExpectedState(buildSessionRow({ ownSiteUrl: null }), "Q3_VIEWING_DEMO");
  const sessionRow = withDemoUrl(baseRow, "https://demo-link.example");
  const db = createMockDb({
    firstResponses: [sessionRow, { m: 0 }, { m: 1 }],
  });

  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_30_help",
      state: "Q3_VIEWING_DEMO",
      answer: "help",
    }),
  });

  const response = await worker.fetch(req, { DB: db });
  const body = await response.json();
  assert.equal(response.status, 200);
  assert.equal(body.next_state, "Q3_VIEWING_DEMO");
  assert.match(String(body.prompt || ""), /paste a direct website url/i);
});

test("Q3_VIEWING_DEMO accepts a user-provided direct reference URL", async () => {
  const baseRow = withExpectedState(buildSessionRow({ ownSiteUrl: null }), "Q3_VIEWING_DEMO");
  const sessionRow = withDemoUrl(baseRow, "https://demo-link.example");
  const db = createMockDb({
    firstResponses: [sessionRow, { m: 0 }, { m: 1 }],
  });

  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_30_direct",
      state: "Q3_VIEWING_DEMO",
      answer: "how about this one https://www.hertz.com/us/en/location/unitedstates/nevada/reno/rnot11",
    }),
  });
  const response = await worker.fetch(req, { DB: db });
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.next_state, "Q3_VIEWING_DEMO");
  assert.equal(body.open_url, "https://www.hertz.com/us/en/location/unitedstates/nevada/reno/rnot11");
});

test("Q3_FEEDBACK_OPEN routes back to viewing when user could not access site", async () => {
  const baseRow = withExpectedState(buildSessionRow({ ownSiteUrl: null }), "Q3_FEEDBACK_OPEN");
  const sessionRow = withDemoUrl(baseRow, "https://demo-link.example");
  const db = createMockDb({
    firstResponses: [sessionRow, { m: 0 }, { m: 1 }],
  });

  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_31",
      state: "Q3_FEEDBACK_OPEN",
      answer: "i was not able to go to the site",
    }),
  });

  const response = await worker.fetch(req, { DB: db });
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.next_state, "Q3_VIEWING_DEMO");
  assert.match(String(body.demo_url || ""), /^https:\/\/demo-link\.example\/?$/);
});

test("Q3_DEMO_Q1 accepts IDK and continues without hard error", async () => {
  const baseRow = withExpectedState(buildSessionRow({ ownSiteUrl: null }), "Q3_DEMO_Q1");
  const sessionRow = withDemoUrl(baseRow, "https://demo-link.example");
  const db = createMockDb({
    firstResponses: [sessionRow, { m: 0 }, { m: 1 }],
  });

  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_32",
      state: "Q3_DEMO_Q1",
      answer: "IDK",
    }),
  });

  const response = await worker.fetch(req, { DB: db });
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.next_state, "Q3_DEMO_Q2");
  assert.match(body.prompt, /No worries — let’s skip vibe/);
});

test("Q3_DEMO_Q1 accepts simple 'ok' and continues", async () => {
  const baseRow = withExpectedState(buildSessionRow({ ownSiteUrl: null }), "Q3_DEMO_Q1");
  const sessionRow = withDemoUrl(baseRow, "https://demo-link.example");
  const db = createMockDb({
    firstResponses: [sessionRow, { m: 0 }, { m: 1 }],
  });

  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_32_ok",
      state: "Q3_DEMO_Q1",
      answer: "ok",
    }),
  });

  const response = await worker.fetch(req, { DB: db });
  const body = await response.json();
  assert.equal(response.status, 200);
  assert.equal(body.next_state, "Q3_DEMO_Q2");
});

test("Q3_DEMO_Q1 accepts plain-language style word 'clean' as modern", async () => {
  const baseRow = withExpectedState(buildSessionRow({ ownSiteUrl: null }), "Q3_DEMO_Q1");
  const sessionRow = withDemoUrl(baseRow, "https://demo-link.example");
  const db = createMockDb({
    firstResponses: [sessionRow, { m: 0 }, { m: 1 }],
  });

  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_31_clean",
      state: "Q3_DEMO_Q1",
      answer: "clean",
    }),
  });

  const response = await worker.fetch(req, { DB: db });
  const body = await response.json();
  assert.equal(response.status, 200);
  assert.equal(body.next_state, "Q3_DEMO_Q2");
});

test("Q3_DEMO_Q2 accepts 'about right' as just right", async () => {
  const baseRow = withExpectedState(buildSessionRow({ ownSiteUrl: null }), "Q3_DEMO_Q2");
  const sessionRow = withDemoUrl(baseRow, "https://demo-link.example");
  const db = createMockDb({
    firstResponses: [sessionRow, { m: 0 }, { m: 1 }],
  });

  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_32_about_right",
      state: "Q3_DEMO_Q2",
      answer: "about right",
    }),
  });

  const response = await worker.fetch(req, { DB: db });
  const body = await response.json();
  assert.equal(response.status, 200);
  assert.equal(body.next_state, "Q3_PALETTE_PICK");
  assert.ok(Array.isArray(body.palette_options));
  assert.equal(body.palette_options.length, 3);
});

test("Q3_PALETTE_PICK accepts A/B/C selection and continues to layout question", async () => {
  const baseRow = withExpectedState(buildSessionRow({ ownSiteUrl: null }), "Q3_PALETTE_PICK");
  const rowWithDemo = withDemoUrl(baseRow, "https://demo-link.example");
  const independent = JSON.parse(rowWithDemo.independent_json);
  const dependent = JSON.parse(rowWithDemo.dependent_json);
  dependent.design = dependent.design || {};
  dependent.design.palette_options = [
    { id: "A", name: "Ocean Trust", description: "Clean and professional.", colors: ["#0b1f3a", "#1fa4ff", "#f6fbff"], hints: ["blue"] },
    { id: "B", name: "Warm Energy", description: "Bold and high-conversion.", colors: ["#2a160f", "#ff8c42", "#fff6ef"], hints: ["orange"] },
    { id: "C", name: "Natural Growth", description: "Friendly and approachable.", colors: ["#0f2418", "#3fcf8e", "#f3fff8"], hints: ["green"] },
  ];
  const sessionRow = {
    ...rowWithDemo,
    independent_json: JSON.stringify(independent),
    dependent_json: JSON.stringify(dependent),
  };
  const db = createMockDb({
    firstResponses: [sessionRow, { m: 0 }, { m: 1 }],
  });

  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_32_palette_pick",
      state: "Q3_PALETTE_PICK",
      answer: "B",
    }),
  });

  const response = await worker.fetch(req, { DB: db });
  const body = await response.json();
  assert.equal(response.status, 200);
  assert.equal(body.next_state, "Q3_DEMO_Q3");
  assert.match(body.prompt, /saved palette b/i);
});

test("Q3_DEMO_Q3 accepts plain-language 'crowded' as cluttered", async () => {
  const baseRow = withExpectedState(buildSessionRow({ ownSiteUrl: null }), "Q3_DEMO_Q3");
  const sessionRow = withDemoUrl(baseRow, "https://demo-link.example");
  const db = createMockDb({
    firstResponses: [sessionRow, { m: 0 }, { m: 1 }],
  });

  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_31_crowded",
      state: "Q3_DEMO_Q3",
      answer: "crowded",
    }),
  });

  const response = await worker.fetch(req, { DB: db });
  const body = await response.json();
  assert.equal(response.status, 200);
  assert.equal(body.next_state, "Q3_NEXT_REFERENCE_YN");
});

test("Q3_VIEWING_DEMO auto timer transitions to specific like question", async () => {
  const baseRow = withExpectedState(buildSessionRow({ ownSiteUrl: null }), "Q3_VIEWING_DEMO");
  const rowWithDemo = withDemoUrl(baseRow, "https://demo-link.example");
  const independent = JSON.parse(rowWithDemo.independent_json);
  const dependent = JSON.parse(rowWithDemo.dependent_json);
  dependent.research = {
    location_hint: "Miami, FL, US",
    source: "yelp_business_sites",
    current_site_index: 0,
    sites: [
      {
        title: "Dive One",
        url: "https://dive-one.example",
        snapshot: {
          design_signals: {
            fonts: ["poppins"],
            colors: ["#0b1f3a", "#1fa4ff"],
            layout_hints: ["hero_section"],
          },
        },
      },
    ],
  };

  const sessionRow = {
    ...rowWithDemo,
    independent_json: JSON.stringify(independent),
    dependent_json: JSON.stringify(dependent),
  };

  const db = createMockDb({
    firstResponses: [sessionRow, { m: 0 }, { m: 1 }],
  });

  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_33",
      state: "Q3_VIEWING_DEMO",
      answer: "__AUTO_AFTER_20S__",
    }),
  });

  const response = await worker.fetch(req, { DB: db });
  const body = await response.json();
  assert.equal(response.status, 200);
  assert.equal(body.next_state, "Q3_FEEDBACK_OPEN");
  assert.match(body.prompt, /What do you like most about this site/i);
});

test("stale Q3 state recovers without hard error", async () => {
  const baseRow = withExpectedState(buildSessionRow({ ownSiteUrl: null }), "Q3_VIEWING_DEMO");
  const sessionRow = withDemoUrl(baseRow, "https://www.justsoscuba.com/");
  const db = createMockDb({
    firstResponses: [sessionRow],
  });

  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_34",
      state: "Q3_VIEW_EXAMPLES_YN",
      answer: "yes",
    }),
  });

  const response = await worker.fetch(req, { DB: db });
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.ok, true);
  assert.equal(body.next_state, "Q3_VIEWING_DEMO");
  assert.equal(body.demo_url, "https://www.justsoscuba.com/");
  assert.equal(body.recovered_from_state, "Q3_VIEW_EXAMPLES_YN");
});

test("Q2_PASTE_URL_OR_NO accepts build-intent phrase as no-current-website", async () => {
  const sessionRow = withExpectedState(buildSessionRow({ ownSiteUrl: null }), "Q2_PASTE_URL_OR_NO");
  const db = createMockDb({
    firstResponses: [sessionRow, { m: 0 }, { m: 1 }],
  });

  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_35",
      state: "Q2_PASTE_URL_OR_NO",
      answer: "i would like to build a website with you",
    }),
  });

  const response = await worker.fetch(req, { DB: db });
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.next_state, "Q2_SITE_INTENT");
});

test("Q2_PASTE_URL_OR_NO saves URL without opening a browser tab", async () => {
  const sessionRow = withExpectedState(buildSessionRow({ ownSiteUrl: null }), "Q2_PASTE_URL_OR_NO");
  const db = createMockDb({
    firstResponses: [sessionRow, { m: 0 }, { m: 1 }],
  });

  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_35_url_bg_scan",
      state: "Q2_PASTE_URL_OR_NO",
      answer: "https://supremexdetail.com/",
    }),
  });

  const response = await worker.fetch(req, { DB: db });
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.next_state, "Q2_CONFIRM_OWNERSHIP");
  assert.ok(!("open_url" in body));
  assert.match(body.prompt, /I will review it in the background after you confirm/i);
});

test("Q2_PASTE_URL_OR_NO treats no-website + URL as reference seed (not ownership)", async () => {
  const sessionRow = withExpectedState(buildSessionRow({ ownSiteUrl: null }), "Q2_PASTE_URL_OR_NO");
  const db = createMockDb({
    firstResponses: [sessionRow, { m: 0 }, { m: 1 }],
  });

  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_35_reference_seed",
      state: "Q2_PASTE_URL_OR_NO",
      answer: "i do not have a website but i am very similiar to this business and in same location https://newportlanding.com/",
    }),
  });

  const response = await worker.fetch(req, { DB: db });
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.notEqual(body.next_state, "Q2_CONFIRM_OWNERSHIP");
  assert.doesNotMatch(String(body.prompt || ""), /is that your website/i);
  assert.match(String(body.prompt || ""), /reference example/i);

  const writes = db.statements.filter((s) => s.op === "run" && /INSERT INTO session_vars/i.test(s.sql));
  assert.ok(writes.length >= 1);
  const latestIndependent = JSON.parse(writes.at(-1).params[2]);
  const latestDependent = JSON.parse(writes.at(-1).params[3]);
  assert.equal(latestIndependent.business.own_site_url, null);
  assert.equal(latestDependent.research.user_reference_url, "https://newportlanding.com/");
});

test("Q2_PASTE_URL_OR_NO captures same-location ZIP from reference site scan", async () => {
  const sessionRow = withExpectedState(buildSessionRow({ ownSiteUrl: null }), "Q2_PASTE_URL_OR_NO");
  const db = createMockDb({
    firstResponses: [sessionRow, { m: 0 }, { m: 1 }],
  });
  const env = {
    DB: db,
    INSPECTOR: {
      async fetch(request) {
        assert.equal(new URL(request.url).pathname, "/inspect");
        return new Response(
          JSON.stringify({
            ok: true,
            request_id: "scan_ref_zip",
            status: "done",
            result: {
              addresses: ["309 Palm St, Newport Beach, CA 92661"],
              emails: [],
              phones: [],
            },
          }),
          { status: 200, headers: { "content-type": "application/json" } }
        );
      },
    },
  };

  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_35_reference_zip",
      state: "Q2_PASTE_URL_OR_NO",
      answer: "i do not have a website but i am in same location as https://newportlanding.com/",
    }),
  });

  const response = await worker.fetch(req, env);
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.match(String(body.prompt || ""), /ZIP 92661/i);

  const writes = db.statements.filter((s) => s.op === "run" && /INSERT INTO session_vars/i.test(s.sql));
  assert.ok(writes.length >= 1);
  const latestDependent = JSON.parse(writes.at(-1).params[3]);
  assert.equal(latestDependent.research.same_zip_as_reference, "92661");
  assert.equal(latestDependent.research.location_hint, "Newport Beach, CA");
});

test("Q3_VIEW_EXAMPLES_YN prioritizes user-provided reference URL as first site", async () => {
  const seedRow = withExpectedState(buildSessionRow({ ownSiteUrl: null }), "Q3_VIEW_EXAMPLES_YN");
  const seedIndependent = JSON.parse(seedRow.independent_json);
  const seedDependent = JSON.parse(seedRow.dependent_json);
  seedDependent.research = seedDependent.research || {};
  seedDependent.research.intent_text = "fishing charter site with bookings";
  seedDependent.research.user_reference_url = "https://newportlanding.com/";
  const sessionRow = {
    ...seedRow,
    independent_json: JSON.stringify(seedIndependent),
    dependent_json: JSON.stringify(seedDependent),
  };

  const db = createMockDb({
    firstResponses: [sessionRow, { m: 0 }, { m: 1 }],
  });
  const env = {
    DB: db,
    INSPECTOR: {
      async fetch() {
        return new Response(
          JSON.stringify({
            ok: true,
            source: "duckduckgo",
            sites: [{ title: "Other Charter", url: "https://other-charter.example/" }],
          }),
          { status: 200, headers: { "content-type": "application/json" } }
        );
      },
    },
  };

  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_35_reference_first",
      state: "Q3_VIEW_EXAMPLES_YN",
      answer: "yes",
    }),
  });

  const response = await worker.fetch(req, env);
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.next_state, "Q3_VIEWING_DEMO");
  assert.equal(body.open_url, "https://newportlanding.com/");
  assert.equal(body.reference_sites?.[0]?.url, "https://newportlanding.com/");
  assert.match(String(body.prompt || ""), /start with the reference you shared/i);
});

test("Q2_SITE_INTENT captures and confirms desired website focus", async () => {
  const sessionRow = withExpectedState(buildSessionRow({ ownSiteUrl: null }), "Q2_SITE_INTENT");
  const db = createMockDb({
    firstResponses: [sessionRow, { m: 0 }, { m: 1 }],
  });

  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_36",
      state: "Q2_SITE_INTENT",
      answer: "I want a dive guide website for Lake Tahoe visitors",
    }),
  });

  const response = await worker.fetch(req, { DB: db });
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.next_state, "Q2_SITE_INTENT_CONFIRM");
  assert.match(body.prompt, /I’ll search examples for/i);
});

test("Q2_SITE_INTENT_CONFIRM yes continues to examples step", async () => {
  const baseRow = withExpectedState(buildSessionRow({ ownSiteUrl: null }), "Q2_SITE_INTENT_CONFIRM");
  const independent = JSON.parse(baseRow.independent_json);
  const dependent = JSON.parse(baseRow.dependent_json);
  dependent.research = dependent.research || {};
  dependent.research.intent_draft = "dive guiding and scuba instruction service website";

  const sessionRow = {
    ...baseRow,
    independent_json: JSON.stringify(independent),
    dependent_json: JSON.stringify(dependent),
  };

  const db = createMockDb({
    firstResponses: [sessionRow, { m: 0 }, { m: 1 }],
  });

  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_37",
      state: "Q2_SITE_INTENT_CONFIRM",
      answer: "yes",
    }),
  });

  const response = await worker.fetch(req, { DB: db });
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.next_state, "Q3_VIEW_EXAMPLES_YN");
});

test("Q1_DESCRIBE routes wordpress audit intent directly to URL step", async () => {
  const sessionRow = withExpectedState(buildSessionRow({ ownSiteUrl: null }), "Q1_DESCRIBE");
  const db = createMockDb({
    firstResponses: [sessionRow, { m: 0 }, { m: 1 }],
  });

  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_38_audit_intent",
      state: "Q1_DESCRIBE",
      answer: "i would like to get my wordpress site checkouted",
    }),
  });

  const response = await worker.fetch(req, { DB: db });
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.next_state, "Q2_PASTE_URL_OR_NO");
  assert.match(body.prompt, /run a website audit first/i);
});
