import assert from "node:assert/strict";
import test from "node:test";
import { createHmac } from "node:crypto";

import worker from "../worker/index.js";

function createMockDb({ firstResponses = [], allResponses = [], runResponses = [] } = {}) {
  const statements = [];
  const firstQueue = [...firstResponses];
  const allQueue = [...allResponses];
  const runQueue = [...runResponses];

  return {
    statements,
    prepare(sql) {
      return {
        bind(...params) {
          return {
            async run() {
              statements.push({ sql, params, op: "run" });
              return runQueue.shift() ?? { success: true };
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

function buildSessionRow({ ownSiteUrl = "https://acme.example", sitePlatform = null, isWordpress = false } = {}) {
  return {
    independent_json: JSON.stringify({
      session_created_at: 1704067200000,
      person: { first_name: "Paul", last_name: "Cwalina", geo: { city: "Miami", region: "FL", country: "US" } },
      business: {
        type_final: "dive services",
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

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function createPluginApiStub(routeHandlers) {
  return {
    async fetch(request) {
      const url = new URL(request.url);
      const handler = routeHandlers[url.pathname];
      assert.ok(handler, `No PLUGIN_API stub for ${url.pathname}`);
      return handler(request, url);
    },
  };
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
    assert.equal(body.next_state, "Q0_HELP_INTENT");
    assert.match(body.prompt, /What can I help you with today/i);
  } finally {
    globalThis.fetch = originalFetch;
  }
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

test('Q0_HELP_INTENT turns "hello" into a friendly bridge prompt', async () => {
  const sessionRow = withExpectedState(buildSessionRow({ ownSiteUrl: null }), "Q0_HELP_INTENT");
  const db = createMockDb({
    firstResponses: [sessionRow, { m: 0 }, { m: 1 }],
  });

  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_q0_hello",
      state: "Q0_HELP_INTENT",
      answer: "hello",
    }),
  });

  const response = await worker.fetch(req, { DB: db });
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.next_state, "Q1_DESCRIBE");
  assert.match(body.prompt, /Hi there\./i);
  assert.match(body.prompt, /business, project, or website/i);
});

test('Q0_HELP_INTENT turns "help me" into a helpful opener', async () => {
  const sessionRow = withExpectedState(buildSessionRow({ ownSiteUrl: null }), "Q0_HELP_INTENT");
  const db = createMockDb({
    firstResponses: [sessionRow, { m: 0 }, { m: 1 }],
  });

  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_q0_help",
      state: "Q0_HELP_INTENT",
      answer: "can you help me",
    }),
  });

  const response = await worker.fetch(req, { DB: db });
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.next_state, "Q1_DESCRIBE");
  assert.match(body.prompt, /I can help with that\./i);
  assert.match(body.prompt, /trying to build, improve, or sell/i);
});

test('Q0_HELP_INTENT turns "not sure" into a collaborative prompt', async () => {
  const sessionRow = withExpectedState(buildSessionRow({ ownSiteUrl: null }), "Q0_HELP_INTENT");
  const db = createMockDb({
    firstResponses: [sessionRow, { m: 0 }, { m: 1 }],
  });

  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_q0_unsure",
      state: "Q0_HELP_INTENT",
      answer: "not sure yet, just looking around",
    }),
  });

  const response = await worker.fetch(req, { DB: db });
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.next_state, "Q1_DESCRIBE");
  assert.match(body.prompt, /we can figure it out together/i);
  assert.match(body.prompt, /business, project, or the kind of site/i);
});

test('Q0_HELP_INTENT turns a short negative opener into a soft reset', async () => {
  const sessionRow = withExpectedState(buildSessionRow({ ownSiteUrl: null }), "Q0_HELP_INTENT");
  const db = createMockDb({
    firstResponses: [sessionRow, { m: 0 }, { m: 1 }],
  });

  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_q0_no",
      state: "Q0_HELP_INTENT",
      answer: "nah",
    }),
  });

  const response = await worker.fetch(req, { DB: db });
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.next_state, "Q1_DESCRIBE");
  assert.match(body.prompt, /When you.?re ready/i);
  assert.match(body.prompt, /business, project, or website/i);
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
  assert.equal(body.open_url, "https://diveco.example");
  assert.equal(body.demo_url, "https://diveco.example");
  assert.equal(body.auto_advance_after_seconds, 20);
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
  assert.ok(Array.isArray(body.cta_actions));
  assert.ok(body.cta_actions.some((a) => a.id === "connect_cloudflare"));
});

test("Q1_DESCRIBE uses OpenAI candidates when catalog and heuristic matches are too weak", async () => {
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
        answer: "my shop mainly does vehicle alignments and similar work",
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

test("Q1_DESCRIBE extracts dependent location from the business sentence", async () => {
  const sessionRow = withExpectedState(buildSessionRow({ ownSiteUrl: null }), "Q1_DESCRIBE");
  const db = createMockDb({
    firstResponses: [sessionRow, { m: 0 }, { m: 1 }],
  });

  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_20_location",
      state: "Q1_DESCRIBE",
      answer: "scuba dive guide in Lake Tahoe",
    }),
  });

  const response = await worker.fetch(req, { DB: db });
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.next_state, "Q1_CONFIRM_TYPE");
  assert.match(body.prompt, /dive services/i);

  const upsert = db.statements.find((s) => /INSERT INTO session_vars/.test(s.sql));
  assert.ok(upsert, "expected session_vars upsert");
  const independentJson = String(upsert.params[2] || "");
  const dependentJson = String(upsert.params[3] || "");
  assert.match(independentJson, /"service_area":"Lake Tahoe"/);
  assert.match(dependentJson, /"location_hint":"Lake Tahoe"/);
});

test("Q1_DESCRIBE maps barber phrasing to the canonical barbershop label", async () => {
  const sessionRow = withExpectedState(buildSessionRow({ ownSiteUrl: null }), "Q1_DESCRIBE");
  const db = createMockDb({
    firstResponses: [sessionRow, { m: 0 }, { m: 1 }],
  });

  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_20_barber",
      state: "Q1_DESCRIBE",
      answer: "I am a barber in Reno",
    }),
  });

  const response = await worker.fetch(req, { DB: db });
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.next_state, "Q1_CONFIRM_TYPE");
  assert.match(body.prompt, /"barbershop"/i);
});

test("Q1_DESCRIBE maps pet store owner phrasing to the canonical pet store label", async () => {
  const row = withExpectedState(buildSessionRow({ ownSiteUrl: null }), "Q1_DESCRIBE");
  const db = createMockDb({
    firstResponses: [row],
  });

  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_pet_store",
      state: "Q1_DESCRIBE",
      answer: "sure i am a pet store owner",
    }),
  });

  const response = await worker.fetch(req, { DB: db });
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.next_state, "Q1_CONFIRM_TYPE");
  assert.match(body.prompt, /"pet store"/i);
});

test("Q1_TYPE_MANUAL normalizes aliases to canonical catalog labels", async () => {
  const sessionRow = withExpectedState(buildSessionRow({ ownSiteUrl: null }), "Q1_TYPE_MANUAL");
  const db = createMockDb({
    firstResponses: [sessionRow, { m: 0 }, { m: 1 }],
    allResponses: [
      { results: [{ canonical_type: "real estate agency" }] },
      { results: [{ alias_phrase: "realtor", canonical_type: "real estate agency" }] },
    ],
  });

  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_20_manual_alias",
      state: "Q1_TYPE_MANUAL",
      answer: "realtor",
    }),
  });

  const response = await worker.fetch(req, { DB: db });
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.next_state, "Q1_CONFIRM_TYPE");
  assert.match(body.prompt, /"real estate agency"/i);
});

test("Q1_TYPE_MANUAL does not revive deleted static aliases when D1 alias set is empty", async () => {
  const sessionRow = withExpectedState(buildSessionRow({ ownSiteUrl: null }), "Q1_TYPE_MANUAL");
  const db = createMockDb({
    firstResponses: [sessionRow, { m: 0 }, { m: 1 }],
    allResponses: [
      { results: [{ canonical_type: "real estate agency" }] },
      { results: [] },
      { results: [] },
    ],
  });

  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_20_manual_alias_deleted",
      state: "Q1_TYPE_MANUAL",
      answer: "realtor",
    }),
  });

  const response = await worker.fetch(req, { DB: db });
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.next_state, "Q1_CONFIRM_TYPE");
  assert.match(body.prompt, /"realtor"/i);
  assert.doesNotMatch(body.prompt, /real estate agency/i);
});

test("Q1_DESCRIBE heuristic fallback emits canonical plumbing company label", async () => {
  const sessionRow = withExpectedState(buildSessionRow({ ownSiteUrl: null }), "Q1_DESCRIBE");
  const db = createMockDb({
    firstResponses: [sessionRow, { m: 0 }, { m: 1 }],
    allResponses: [
      { results: [{ canonical_type: "plumbing company" }] },
      { results: [] },
      { results: [] },
    ],
  });

  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_plumbing_heuristic",
      state: "Q1_DESCRIBE",
      answer: "we do drain cleaning and leak repair",
    }),
  });

  const response = await worker.fetch(req, { DB: db });
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.next_state, "Q1_CONFIRM_TYPE");
  assert.match(body.prompt, /"plumbing company"/i);
});

test("debug business-types endpoint returns catalog, aliases, and memory counts", async () => {
  const db = createMockDb({
    allResponses: [
      {
        results: [
          { canonical_type: "restaurant", display_label: "Restaurant", category: "food_and_drink", is_confirmed: 1, is_active: 1 },
          { canonical_type: "car", display_label: "Car", category: "needs_review", is_confirmed: 1, is_active: 0 },
        ],
      },
      {
        results: [
          { alias_phrase: "realtor", canonical_type: "real estate agency", source: "seed", is_active: 1 },
        ],
      },
      {
        results: [],
      },
      {
        results: [
          { canonical_type: "dive services", phrase_count: 6, confirmation_count: 10 },
        ],
      },
    ],
  });

  const response = await worker.fetch(new Request("https://worker.example/debug/business-types"), { DB: db });
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.ok, true);
  assert.equal(body.counts.catalog_total, 2);
  assert.equal(body.counts.catalog_active_confirmed, 1);
  assert.equal(body.counts.alias_total, 1);
  assert.equal(body.counts.memory_label_total, 1);
});

test("debug business-types endpoint includes signal counts", async () => {
  const db = createMockDb({
    allResponses: [
      {
        results: [
          { canonical_type: "restaurant", display_label: "Restaurant", category: "food_and_drink", is_confirmed: 1, is_active: 1 },
        ],
      },
      { results: [] },
      {
        results: [
          { id: 1, canonical_type: "restaurant", signal_type: "strong_keyword", value: "burger joint", normalized_value: "burger joint", weight: 2.7, is_active: 1 },
        ],
      },
      { results: [] },
    ],
  });

  const response = await worker.fetch(new Request("https://worker.example/debug/business-types"), { DB: db });
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.counts.signal_total, 1);
  assert.equal(body.signals[0].signal_type, "strong_keyword");
});

test("admin business type routes require ADMIN_TOKEN", async () => {
  const db = createMockDb();
  const response = await worker.fetch(new Request("https://worker.example/admin/business-types"), { DB: db });
  const body = await response.json();

  assert.equal(response.status, 503);
  assert.equal(body.error, "ADMIN_TOKEN_NOT_CONFIGURED");
});

test("admin business type list rejects wrong bearer token", async () => {
  const db = createMockDb();
  const response = await worker.fetch(
    new Request("https://worker.example/admin/business-types", {
      headers: { authorization: "Bearer wrong-token" },
    }),
    { DB: db, ADMIN_TOKEN: "expected-token" }
  );
  const body = await response.json();

  assert.equal(response.status, 401);
  assert.equal(body.error, "unauthorized");
});

test("admin business type list returns catalog rows with valid bearer token", async () => {
  const db = createMockDb({
    allResponses: [
      {
        results: [
          {
            canonical_type: "law firm",
            display_label: "Law Firm",
            category: "professional_services",
            is_confirmed: 1,
            is_active: 1,
            created_at: 1,
            updated_at: 1,
            alias_count: 2,
            signal_count: 3,
          },
        ],
      },
    ],
  });

  const response = await worker.fetch(
    new Request("https://worker.example/admin/business-types", {
      headers: { authorization: "Bearer expected-token" },
    }),
    { DB: db, ADMIN_TOKEN: "expected-token" }
  );
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.ok, true);
  assert.equal(body.items[0].canonical_type, "law firm");
  assert.equal(body.items[0].signal_count, 3);
});

test("admin seed route upserts catalog aliases and signals with valid bearer token", async () => {
  const db = createMockDb();
  const payload = [
    {
      slug: "law firm",
      label: "Law Firm",
      category: "professional_services",
      aliases: ["attorney office"],
      signals: [{ signal_type: "profession", value: "lawyer", weight: 4 }],
    },
  ];

  const response = await worker.fetch(
    new Request("https://worker.example/admin/seed", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: "Bearer expected-token",
      },
      body: JSON.stringify(payload),
    }),
    { DB: db, ADMIN_TOKEN: "expected-token" }
  );
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.ok, true);
  assert.equal(body.count, 1);
  assert.ok(db.statements.some((s) => s.op === "run" && /INSERT INTO business_type_catalog/i.test(s.sql)));
  assert.ok(db.statements.some((s) => s.op === "run" && /INSERT INTO business_type_alias_catalog/i.test(s.sql)));
  assert.ok(db.statements.some((s) => s.op === "run" && /INSERT INTO business_type_signal_catalog/i.test(s.sql)));
  assert.ok(db.statements.some((s) => s.op === "run" && /INSERT INTO admin_audit_log/i.test(s.sql)));
});

test("Q1_DESCRIBE uses D1 signal evidence to classify family lawyer correctly", async () => {
  const sessionRow = withExpectedState(buildSessionRow({ ownSiteUrl: null }), "Q1_DESCRIBE");
  const db = createMockDb({
    firstResponses: [sessionRow, { m: 0 }, { m: 1 }],
    allResponses: [
      {
        results: [
          { canonical_type: "law firm" },
          { canonical_type: "restaurant" },
        ],
      },
      {
        results: [
          { alias_phrase: "attorney", canonical_type: "law firm" },
          { alias_phrase: "burger joint", canonical_type: "restaurant" },
        ],
      },
      {
        results: [
          { id: 1, canonical_type: "law firm", signal_type: "profession", value: "lawyer", normalized_value: "lawyer", weight: 4 },
          { id: 2, canonical_type: "law firm", signal_type: "service", value: "family law", normalized_value: "family law", weight: 2.5 },
        ],
      },
    ],
  });

  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_signal_family_law",
      state: "Q1_DESCRIBE",
      answer: "I'm a family lawyer in Lake Tahoe",
    }),
  });

  const response = await worker.fetch(req, { DB: db });
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.next_state, "Q1_CONFIRM_TYPE");
  assert.match(body.prompt, /law firm/i);
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
  assert.ok(db.statements.some((s) => /INSERT INTO business_type_memory/.test(s.sql)));
});

test("worker rejects oversized answers to protect flow and storage", async () => {
  const sessionRow = withExpectedState(buildSessionRow(), "Q1_DESCRIBE");
  const db = createMockDb({
    firstResponses: [sessionRow],
  });
  const longAnswer = "x".repeat(1300);

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
  assert.equal(body.next_state, "Q_CONTINUE_WITHOUT_DEMO_YN");
  assert.match(body.prompt, /skip the demo for now/i);
  assert.match(body.prompt, /help plan the site with you here in chat/i);
});

test('Q3_VIEW_EXAMPLES_YN treats "no thanks" as a natural decline and keeps moving', async () => {
  const sessionRow = withExpectedState(buildSessionRow({ ownSiteUrl: null }), "Q3_VIEW_EXAMPLES_YN");
  const db = createMockDb({
    firstResponses: [sessionRow, { m: 0 }, { m: 1 }],
  });

  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_q3_no_thanks",
      state: "Q3_VIEW_EXAMPLES_YN",
      answer: "no thanks",
    }),
  });

  const response = await worker.fetch(req, { DB: db });
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.next_state, "Q_BUILD_TRIAL_YN");
  assert.match(body.prompt, /Would you still like me to build you a demo site/i);
});

test('Q3_VIEW_EXAMPLES_YN handles "I just want to talk first" without forcing examples', async () => {
  const sessionRow = withExpectedState(buildSessionRow({ ownSiteUrl: null }), "Q3_VIEW_EXAMPLES_YN");
  const db = createMockDb({
    firstResponses: [sessionRow, { m: 0 }, { m: 1 }],
  });

  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_q3_talk_first",
      state: "Q3_VIEW_EXAMPLES_YN",
      answer: "I just want to talk first",
    }),
  });

  const response = await worker.fetch(req, { DB: db });
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.next_state, "Q_CONTINUE_WITHOUT_DEMO_YN");
  assert.match(body.prompt, /skip the example sites/i);
  assert.match(body.prompt, /talk through the site together here in chat/i);
});

test('Q_BUILD_TRIAL_YN treats "not right now" as a natural defer', async () => {
  const sessionRow = withExpectedState(buildSessionRow(), "Q_BUILD_TRIAL_YN");
  const db = createMockDb({
    firstResponses: [sessionRow, { m: 0 }, { m: 1 }],
  });

  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_qbuild_not_now",
      state: "Q_BUILD_TRIAL_YN",
      answer: "not right now",
    }),
  });

  const response = await worker.fetch(req, { DB: db });
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.next_state, "Q_CONTINUE_WITHOUT_DEMO_YN");
  assert.match(body.prompt, /skip the demo for now/i);
});

test('Q_BUILD_TRIAL_YN handles "I just want to talk first" as a planning request', async () => {
  const sessionRow = withExpectedState(buildSessionRow(), "Q_BUILD_TRIAL_YN");
  const db = createMockDb({
    firstResponses: [sessionRow, { m: 0 }, { m: 1 }],
  });

  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_qbuild_talk_first",
      state: "Q_BUILD_TRIAL_YN",
      answer: "I just want to talk first",
    }),
  });

  const response = await worker.fetch(req, { DB: db });
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.next_state, "Q4_BIZNAME");
  assert.match(body.prompt, /we can plan it together here first/i);
});

test('Q_CONTINUE_WITHOUT_DEMO_YN handles "I just want to talk first" naturally', async () => {
  const sessionRow = withExpectedState(buildSessionRow(), "Q_CONTINUE_WITHOUT_DEMO_YN");
  const db = createMockDb({
    firstResponses: [sessionRow, { m: 0 }, { m: 1 }],
  });

  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_continue_talk_first",
      state: "Q_CONTINUE_WITHOUT_DEMO_YN",
      answer: "I just want to talk first",
    }),
  });

  const response = await worker.fetch(req, { DB: db });
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.next_state, "Q4_BIZNAME");
  assert.match(body.prompt, /let.?s talk it through/i);
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

test('Q2_CONFIRM_OWNERSHIP accepts "current website" and continues as an owned site', async () => {
  const sessionRow = withExpectedState(buildSessionRow({ ownSiteUrl: "https://rootermanrenocarson.com/" }), "Q2_CONFIRM_OWNERSHIP");
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
            request_id: "scan_903c",
            status: "done",
            result: {
              title: "Roto Rooter Reno Carson",
              h1: "24/7 Plumbing",
              emails: ["hello@rootermanrenocarson.com"],
              phones: ["(775) 555-0100"],
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
      session_id: "ses_29c",
      state: "Q2_CONFIRM_OWNERSHIP",
      answer: "current website",
    }),
  });

  const response = await worker.fetch(req, env);
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.next_state, "Q2_HAPPY_COSTS");
  assert.match(body.prompt, /I reviewed your current site/i);
});

test('Q2_CONFIRM_OWNERSHIP accepts "reference site" and routes into reference feedback', async () => {
  const sessionRow = withExpectedState(buildSessionRow({ ownSiteUrl: "https://brittanychiang.com/" }), "Q2_CONFIRM_OWNERSHIP");
  const db = createMockDb({
    firstResponses: [sessionRow, { m: 0 }, { m: 1 }],
  });

  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_29d",
      state: "Q2_CONFIRM_OWNERSHIP",
      answer: "reference site",
    }),
  });

  const response = await worker.fetch(req, { DB: db });
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.next_state, "Q3_FEEDBACK_OPEN");
  assert.match(body.prompt, /what do you like most about this site/i);
});

test('Q2_CONFIRM_OWNERSHIP accepts natural reference phrasing like "one i like"', async () => {
  const sessionRow = withExpectedState(buildSessionRow({ ownSiteUrl: "https://divingcatalina.com/scuba-tours/" }), "Q2_CONFIRM_OWNERSHIP");
  const db = createMockDb({
    firstResponses: [sessionRow, { m: 0 }, { m: 1 }],
  });

  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_29d_like",
      state: "Q2_CONFIRM_OWNERSHIP",
      answer: "one i like",
    }),
  });

  const response = await worker.fetch(req, { DB: db });
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.next_state, "Q3_FEEDBACK_OPEN");
  assert.match(body.prompt, /what do you like most about this site/i);
});

test('Q2_CONFIRM_OWNERSHIP accepts "this is my current website"', async () => {
  const sessionRow = withExpectedState(buildSessionRow({ ownSiteUrl: "https://rootermanrenocarson.com/" }), "Q2_CONFIRM_OWNERSHIP");
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
            status: "done",
            request_id: "scan_cur_phrase",
            result: {
              title: "Rooter Man",
              h1: "Plumbing",
              platform_hint: null,
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
      session_id: "ses_29d_current_sentence",
      state: "Q2_CONFIRM_OWNERSHIP",
      answer: "this is my current website",
    }),
  });

  const response = await worker.fetch(req, env);
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.next_state, "Q2_HAPPY_COSTS");
});

test("Q2_CONFIRM_OWNERSHIP accepts \"it's just a site I like\"", async () => {
  const sessionRow = withExpectedState(buildSessionRow({ ownSiteUrl: "https://divingcatalina.com/scuba-tours/" }), "Q2_CONFIRM_OWNERSHIP");
  const db = createMockDb({
    firstResponses: [sessionRow, { m: 0 }, { m: 1 }],
  });

  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_29d_like_sentence",
      state: "Q2_CONFIRM_OWNERSHIP",
      answer: "it's just a site I like",
    }),
  });

  const response = await worker.fetch(req, { DB: db });
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.next_state, "Q3_FEEDBACK_OPEN");
});

test('Q2_CONFIRM_OWNERSHIP accepts "not my site, just inspiration"', async () => {
  const sessionRow = withExpectedState(buildSessionRow({ ownSiteUrl: "https://divingcatalina.com/scuba-tours/" }), "Q2_CONFIRM_OWNERSHIP");
  const db = createMockDb({
    firstResponses: [sessionRow, { m: 0 }, { m: 1 }],
  });

  const req = new Request("https://worker.example/q1/answer", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      session_id: "ses_29d_inspiration_sentence",
      state: "Q2_CONFIRM_OWNERSHIP",
      answer: "not my site, just inspiration",
    }),
  });

  const response = await worker.fetch(req, { DB: db });
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.next_state, "Q3_FEEDBACK_OPEN");
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
  assert.match(body.prompt, /Checks that need plugin access/i);
  assert.match(body.prompt, /broken links:\s*3/i);
  assert.match(body.prompt, /schema gives search engines clearer context|structured information about your business/i);
  assert.match(body.prompt, /improvement range i.?d expect/i);
  assert.match(body.prompt, /A quick note on SSO/i);
  assert.doesNotMatch(body.prompt, /Domain registrar/i);
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
  assert.match(body.prompt, /My take: the plugin would likely help/i);
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

  const response = await worker.fetch(req, {
    DB: db,
    PLUGIN_API: createPluginApiStub({
      "/plugin/connect/start": async () => jsonResponse({ ok: false, error: "WordPress sites only." }, 400),
    }),
  });
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
    PLUGIN_API: createPluginApiStub({
      "/plugin/connect/start": async () =>
        jsonResponse({
          ok: true,
          connect_id: "plg_test_connect_1",
          requirements: { tolldns_required_for_free: true },
          cta_actions: [{ id: "install_tolldns_required" }],
        }),
    }),
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

  const response = await worker.fetch(req, {
    DB: db,
    PLUGIN_API: createPluginApiStub({
      "/plugin/connect/verify": async () =>
        jsonResponse({ ok: false, error: "TollDNS installation is required for the free tier." }, 400),
    }),
  });
  const body = await response.json();

  assert.equal(response.status, 400);
  assert.match(body.error, /TollDNS installation is required/i);
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
      PLUGIN_API: createPluginApiStub({
        "/plugin/connect/verify": async () =>
          jsonResponse({
            ok: true,
            plugin_connection: {
              status: "connected",
              token_verified: true,
              tolldns_installed: true,
              github_connected: true,
              github_repo: "owner/sandbox-backups",
              token_masked: "cf_test_...3456",
            },
            cta_actions: [{ id: "install_ai_webadmin_plugin" }],
          }),
      }),
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
    PLUGIN_API: createPluginApiStub({
      "/plugin/connect/verify": async () =>
        jsonResponse({ ok: false, error: "Plaintext passwords are never collected." }, 400),
    }),
  });
  const body = await response.json();
  assert.equal(response.status, 400);
  assert.match(body.error, /plaintext passwords are never collected/i);
});

test("plugin paths return 503 when PLUGIN_API is not configured", async () => {
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
  assert.match(body.error, /Plugin API forwarding is not configured/i);
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
    PLUGIN_API: createPluginApiStub({
      "/plugin/wp/comments/moderate": async () => jsonResponse({ ok: false, error: "Invalid plugin signature." }, 401),
    }),
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
    PLUGIN_API: createPluginApiStub({
      "/plugin/wp/comments/moderate": async () =>
        jsonResponse({
          ok: true,
          action: "spam",
          wp_status: "spam",
          heuristic: { score: 5 },
        }),
    }),
  });
  const body = await response.json();
  assert.equal(response.status, 200);
  assert.equal(body.ok, true);
  assert.ok(["spam", "trash"].includes(body.action));
  assert.ok(["spam", "trash"].includes(body.wp_status));
  assert.ok(body.heuristic.score >= 4);
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
    smtp_plugin_count: 1,
    inactive_user_deleted_count: 4,
    inactive_user_candidate_count: 10,
    plugin_inventory: {
      inactive_plugin_slugs: ["hello-dolly/hello.php"],
      migration_plugin_slugs: ["all-in-one-wp-migration/all-in-one-wp-migration.php"],
      unneeded_plugin_slugs: ["hello-dolly/hello.php"],
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
    PLUGIN_API: createPluginApiStub({
      "/plugin/wp/audit/sync": async () =>
        jsonResponse({
          ok: true,
          audit_metrics: {
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
            smtp_plugin_count: 1,
            inactive_user_deleted_count: 4,
            inactive_user_candidate_count: 10,
            plugin_inventory: {
              inactive_plugin_slugs: ["hello-dolly/hello.php"],
            },
          },
        }),
    }),
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
  assert.equal(body.audit_metrics.smtp_plugin_count, 1);
  assert.equal(body.audit_metrics.inactive_user_deleted_count, 4);
  assert.equal(body.audit_metrics.inactive_user_candidate_count, 10);
  assert.equal(body.audit_metrics.plugin_inventory.inactive_plugin_slugs[0], "hello-dolly/hello.php");
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
    PLUGIN_API: createPluginApiStub({
      "/plugin/wp/access/profile": async () =>
        jsonResponse({
          ok: true,
          access_profile: {
            control_panel_type: "cpanel",
            panel_username: "owner_admin",
            auth_preference: "ssh_key_only",
            password_auth_disabled: true,
            ssh_public_key_fingerprint: "sha256:testfingerprint",
            provider_api_token_masked: "host_api_...6789",
            free_vps_offer_eligible: true,
            free_vps_offer_window_days: 30,
            days_until_managed_hosting_expiry: 25,
            server_hardware_hints: { visibility: "public_scan_limited" },
          },
        }),
    }),
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
    PLUGIN_API: createPluginApiStub({
      "/plugin/wp/email/forward/config": async () =>
        jsonResponse({
          ok: true,
          email_forwarding: {
            enabled: true,
            forward_to_email: "owner@example.com",
            has_mx_records: true,
            email_provider_hint: "Google Workspace",
            mx_record_count: 2,
          },
        }),
    }),
  });
  const body = await response.json();
  assert.equal(response.status, 200);
  assert.equal(body.ok, true);
  assert.equal(body.email_forwarding.enabled, true);
  assert.equal(body.email_forwarding.forward_to_email, "owner@example.com");
  assert.equal(body.email_forwarding.has_mx_records, true);
  assert.equal(body.email_forwarding.email_provider_hint, "Google Workspace");
  assert.equal(body.email_forwarding.mx_record_count, 2);
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
      PLUGIN_API: createPluginApiStub({
        "/plugin/wp/lead/forward": async () =>
          jsonResponse({
            ok: true,
            forward_to_email: "owner@example.com",
            stored_in_r2: true,
            webhook: { attempted: true, ok: true, status: 202 },
          }),
      }),
    });
    const body = await response.json();
    assert.equal(response.status, 200);
    assert.equal(body.ok, true);
    assert.equal(body.forward_to_email, "owner@example.com");
    assert.equal(body.stored_in_r2, true);
    assert.equal(bucketPuts.length, 0);
    assert.equal(body.webhook.attempted, true);
    assert.equal(body.webhook.ok, true);
    assert.equal(body.webhook.status, 202);
    assert.equal(hookCalls.length, 0);
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
    PLUGIN_API: createPluginApiStub({
      "/plugin/wp/schema/profile": async () =>
        jsonResponse({
          ok: true,
          schema_status: "ready",
          schema_profile: {
            business_name: "Supreme X Detail",
          },
          schema_jsonld: "{\"@type\":\"AutoDetailing\"}",
        }),
    }),
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
    PLUGIN_API: createPluginApiStub({
      "/plugin/wp/redirects/profile": async () =>
        jsonResponse({
          ok: true,
          checked_link_count: 22,
          broken_link_count: 4,
          redirect_paths: ["/old-page", "/dead-offer?x=1"],
        }),
    }),
  });
  const body = await response.json();
  assert.equal(response.status, 200);
  assert.equal(body.ok, true);
  assert.equal(body.checked_link_count, 22);
  assert.equal(body.broken_link_count, 4);
  assert.deepEqual(body.redirect_paths, ["/old-page", "/dead-offer?x=1"]);
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
      PLUGIN_API: createPluginApiStub({
        "/plugin/wp/github/vault": async () =>
          jsonResponse({
            ok: true,
            github_repo: "owner/repo",
            github_user: "repo-owner",
            token_masked: "ghp_exa...7890",
          }),
      }),
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
    PLUGIN_API: createPluginApiStub({
      "/plugin/wp/backup/snapshot": async () =>
        jsonResponse({
          ok: true,
          message: "Snapshot saved to Cloudflare.",
          github: { ok: false },
        }),
    }),
  });
  const body = await response.json();
  assert.equal(response.status, 200);
  assert.equal(body.ok, true);
  assert.equal(bucketPuts.length, 0);
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
    PLUGIN_API: createPluginApiStub({
      "/plugin/wp/auth/wallet/verify": async () =>
        jsonResponse({ ok: false, verified: false, error: "Wallet verification gateway not configured." }, 400),
    }),
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
      PLUGIN_API: createPluginApiStub({
        "/plugin/wp/auth/wallet/verify": async () =>
          jsonResponse({
            ok: true,
            verified: true,
            wallet_address: "0x2222222222222222222222222222222222222222",
            source: "test_wallet_gateway",
          }),
      }),
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
  assert.equal(body.demo_url, "https://demo-link.example");
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
  assert.equal(body.demo_url, "https://demo-link.example");
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
  assert.match(body.prompt, /current website, or just one you like as a reference/i);
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
  assert.match(body.prompt, /looking for examples around/i);
  assert.match(body.prompt, /Does that sound right/i);
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
