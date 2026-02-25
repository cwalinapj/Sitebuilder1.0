import assert from "node:assert/strict";
import test from "node:test";

import inspectorWorker from "../SitebuilderInspector/worker.js";

function createMockDb({ firstResponses = [] } = {}) {
  const statements = [];
  const firstQueue = [...firstResponses];

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
          };
        },
      };
    },
  };
}

test("inspector /inspect normalizes scheme and persists request/result rows", async () => {
  const db = createMockDb();
  const env = { DB: db };
  const originalFetch = globalThis.fetch;
  const fetchCalls = [];

  globalThis.fetch = async (target) => {
    fetchCalls.push(target);
    const html = "<html><head><title>Acme</title></head><body><h1>Hello</h1></body></html>";
    return new Response(html, { status: 200, headers: { "content-type": "text/html" } });
  };

  try {
    const req = new Request("https://inspector.example/inspect", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ session_id: "ses_1", url: "example.com" }),
    });

    const response = await inspectorWorker.fetch(req, env);
    const body = await response.json();

    assert.equal(response.status, 200);
    assert.equal(body.ok, true);
    assert.equal(fetchCalls[0], "https://example.com");
    assert.equal(body.result.link_audit.checked_count, 0);
    assert.equal(body.result.link_audit.broken_count, 0);
    assert.ok(db.statements.some((s) => /INSERT OR REPLACE INTO site_scan_requests/.test(s.sql)));
    assert.ok(db.statements.some((s) => /INSERT OR REPLACE INTO site_scan_results/.test(s.sql)));
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("inspector /inspect/status parses json columns into arrays", async () => {
  const db = createMockDb({
    firstResponses: [
      { request_id: "scan_1", status: "done", created_at: 1 },
      {
        request_id: "scan_1",
        session_id: "ses_1",
        url: "https://example.com",
        final_url: "https://example.com",
        title: "Acme",
        h1: "Welcome",
        meta_description: "desc",
        emails_json: JSON.stringify(["info@example.com"]),
        phones_json: JSON.stringify(["+15555555555"]),
        socials_json: JSON.stringify(["https://instagram.com/acme"]),
        platform_hint: "wordpress",
        schema_types_json: JSON.stringify(["LocalBusiness"]),
        raw_size: 1234,
        created_at: 2,
      },
    ],
  });
  const env = { DB: db };

  const req = new Request("https://inspector.example/inspect/status?session_id=ses_1");
  const response = await inspectorWorker.fetch(req, env);
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.ok, true);
  assert.deepEqual(body.result.emails, ["info@example.com"]);
  assert.deepEqual(body.result.schema_types, ["LocalBusiness"]);
});

test("inspector /inspect rejects missing url", async () => {
  const db = createMockDb();
  const env = { DB: db };

  const req = new Request("https://inspector.example/inspect", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ session_id: "ses_1" }),
  });

  const response = await inspectorWorker.fetch(req, env);
  const body = await response.json();

  assert.equal(response.status, 400);
  assert.equal(body.ok, false);
  assert.match(body.error, /session_id and url required/);
});

test("inspector /market/nearby returns top sites from fallback search", async () => {
  const db = createMockDb();
  const env = { DB: db };
  const originalFetch = globalThis.fetch;

  globalThis.fetch = async (target) => {
    const u = String(target);
    if (u.includes("yelp.com/search")) {
      const html = `<a href="/biz/alpha-dive-gardnerville">Alpha Dive</a>`;
      return new Response(html, { status: 200, headers: { "content-type": "text/html" } });
    }
    if (u.includes("yelp.com/biz/alpha-dive-gardnerville")) {
      const html = `<a href="/biz_redir?url=https%3A%2F%2Falpha.example">Website</a>`;
      return new Response(html, { status: 200, headers: { "content-type": "text/html" } });
    }
    if (u.includes("alpha.example")) {
      const html = "<html><head><title>Alpha Dive</title></head><body><h1>Scuba</h1></body></html>";
      return new Response(html, { status: 200, headers: { "content-type": "text/html" } });
    }
    const html = `<a class="result__a" href="https://beta.example">Beta Dive</a>`;
    return new Response(html, { status: 200, headers: { "content-type": "text/html" } });
  };

  try {
    const req = new Request("https://inspector.example/market/nearby", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        session_id: "ses_2",
        business_type: "dive services",
        location: "Miami, FL",
      }),
    });

    const response = await inspectorWorker.fetch(req, env);
    const body = await response.json();

    assert.equal(response.status, 200);
    assert.equal(body.ok, true);
    assert.ok(body.sites.length >= 1);
    assert.equal(body.sites[0].url, "https://alpha.example");
    assert.equal(body.source, "yelp_business_sites");
    assert.ok(db.statements.some((s) => /market_search_results/.test(s.sql)));
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("inspector /market/nearby ranks guide service site above dive shop when intent is guiding", async () => {
  const db = createMockDb();
  const env = { DB: db };
  const originalFetch = globalThis.fetch;

  globalThis.fetch = async (target) => {
    const u = String(target);
    if (u.includes("yelp.com/search")) {
      const html = `
        <a href="/biz/just-so-scuba-lake-tahoe">Just So Scuba</a>
        <a href="/biz/sierra-dive-center-lake-tahoe">Sierra Dive</a>
      `;
      return new Response(html, { status: 200, headers: { "content-type": "text/html" } });
    }
    if (u.includes("yelp.com/biz/just-so-scuba-lake-tahoe")) {
      const html = `<a href="/biz_redir?url=https%3A%2F%2Fwww.justsoscuba.com%2F">Website</a>`;
      return new Response(html, { status: 200, headers: { "content-type": "text/html" } });
    }
    if (u.includes("yelp.com/biz/sierra-dive-center-lake-tahoe")) {
      const html = `<a href="/biz_redir?url=https%3A%2F%2Fwww.sierradive.com%2F">Website</a>`;
      return new Response(html, { status: 200, headers: { "content-type": "text/html" } });
    }
    if (u.includes("justsoscuba.com")) {
      const html = `
        <html>
          <head><title>Just So Scuba | Guided Dives Lake Tahoe</title></head>
          <body><h1>Private Dive Guide Services</h1></body>
        </html>
      `;
      return new Response(html, { status: 200, headers: { "content-type": "text/html" } });
    }
    if (u.includes("sierradive.com")) {
      const html = `
        <html>
          <head><title>Sierra Dive Center | Scuba Shop and Equipment</title></head>
          <body><h1>Dive Gear Sales</h1></body>
        </html>
      `;
      return new Response(html, { status: 200, headers: { "content-type": "text/html" } });
    }
    return new Response("<html></html>", { status: 200, headers: { "content-type": "text/html" } });
  };

  try {
    const req = new Request("https://inspector.example/market/nearby", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        session_id: "ses_guide_1",
        business_type: "dive services",
        location: "Lake Tahoe, NV",
        intent_text: "dive guiding for lake tahoe tourists",
      }),
    });

    const response = await inspectorWorker.fetch(req, env);
    const body = await response.json();

    assert.equal(response.status, 200);
    assert.equal(body.ok, true);
    assert.equal(body.source, "yelp_business_sites");
    assert.equal(body.sites[0].url, "https://www.justsoscuba.com/");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("inspector /inspect extracts address candidates from schema/text", async () => {
  const db = createMockDb();
  const env = { DB: db };
  const originalFetch = globalThis.fetch;

  globalThis.fetch = async () => {
    const html = `
      <html><head><title>Acme</title>
      <script type="application/ld+json">
      {"@type":"LocalBusiness","address":{"streetAddress":"200 Oak Ave","addressLocality":"Reno","addressRegion":"NV","postalCode":"89501"}}
      </script>
      </head>
      <body><h1>Acme Plumbing</h1><p>Visit us at 123 Main St, Reno, NV 89501</p></body></html>
    `;
    return new Response(html, { status: 200, headers: { "content-type": "text/html" } });
  };

  try {
    const req = new Request("https://inspector.example/inspect", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ session_id: "ses_3", url: "example.com" }),
    });

    const response = await inspectorWorker.fetch(req, env);
    const body = await response.json();

    assert.equal(response.status, 200);
    assert.equal(body.ok, true);
    assert.ok(Array.isArray(body.result.addresses));
    assert.ok(body.result.addresses.length >= 1);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("inspector /market/nearby filters out yelp search/listing urls from fallback", async () => {
  const db = createMockDb();
  const env = { DB: db };
  const originalFetch = globalThis.fetch;

  globalThis.fetch = async (target) => {
    const u = String(target);
    if (u.includes("yelp.com/search")) {
      return new Response("<html><body>No biz links</body></html>", { status: 200 });
    }
    const ddg = `
      <a class="result__a" href="https://www.yelp.com/search?find_desc=scuba&find_loc=Carson+City">Yelp Search</a>
      <a class="result__a" href="https://www.justsoscuba.com/">Just So Scuba</a>
    `;
    return new Response(ddg, { status: 200, headers: { "content-type": "text/html" } });
  };

  try {
    const req = new Request("https://inspector.example/market/nearby", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ session_id: "ses_4", business_type: "dive services", location: "Carson City, NV" }),
    });
    const response = await inspectorWorker.fetch(req, env);
    const body = await response.json();

    assert.equal(response.status, 200);
    assert.equal(body.ok, true);
    assert.equal(body.sites[0].url, "https://www.justsoscuba.com/");
    assert.ok(body.sites.every((s) => !String(s.url).includes("yelp.com/search")));
  } finally {
    globalThis.fetch = originalFetch;
  }
});
