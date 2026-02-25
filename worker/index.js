// worker/index.js
export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // --- CORS (supports Pages preview subdomains like fe9edabd.sitebuilder1-03.pages.dev) ---
    const origin = request.headers.get("Origin") || "";
    const allowed =
      origin === "https://sitebuilder1-03.pages.dev" ||
      /^https:\/\/[a-z0-9-]+\.sitebuilder1-03\.pages\.dev$/.test(origin);

    const corsHeaders = {
      "Access-Control-Allow-Origin": allowed ? origin : "null",
      "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
      "Access-Control-Max-Age": "86400",
      "Vary": "Origin",
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    const json = (obj, status = 200) =>
      new Response(JSON.stringify(obj, null, 2), {
        status,
        headers: { "content-type": "application/json", ...corsHeaders },
      });

    // ---- helpers ----
    const now = () => Date.now();
    const newId = (prefix) => `${prefix}_${crypto.randomUUID()}`;

    async function upsertSessionVars(session_id, block_id, independent, dependent) {
      await env.DB.prepare(
        `INSERT INTO session_vars(session_id, block_id, independent_json, dependent_json, updated_at)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(session_id, block_id) DO UPDATE SET
           independent_json=excluded.independent_json,
           dependent_json=excluded.dependent_json,
           updated_at=excluded.updated_at`
      )
        .bind(session_id, block_id, JSON.stringify(independent), JSON.stringify(dependent), now())
        .run();
    }

    async function loadSessionVars(session_id, block_id) {
      const row = await env.DB.prepare(
        "SELECT independent_json, dependent_json, updated_at FROM session_vars WHERE session_id=? AND block_id=?"
      )
        .bind(session_id, block_id)
        .first();

      if (!row) return null;
      return {
        independent: JSON.parse(row.independent_json),
        dependent: JSON.parse(row.dependent_json),
        updated_at: row.updated_at,
      };
    }

    function guessCategory(oneSentence) {
      const s = (oneSentence || "").toLowerCase();

      if (/(restaurant|cafe|pizza|tacos|burger|bar|bistro|diner|sushi)/.test(s)) return "restaurant";
      if (/(plumb|drain|water heater|pipe|leak|sewer)/.test(s)) return "plumber";
      if (/(electric|breaker|panel|wiring|outlet|lighting)/.test(s)) return "electrician";
      if (/(barber|haircut|fade|beard|shave|salon)/.test(s)) return "barber";
      if (/(detail|detailing|ceramic|car wash|auto detailing|clean cars)/.test(s)) return "auto detailing";
      return "local business";
    }

    // ---- routes ----

    // Health
    if (request.method === "GET" && url.pathname === "/") {
      return json({ ok: true, service: "Onboarding Q1 demo", time: new Date().toISOString() });
    }

    // POST /q1/start
    if (request.method === "POST" && url.pathname === "/q1/start") {
      let body;
      try {
        body = await request.json();
      } catch {
        return json({ ok: false, error: "Invalid JSON" }, 400);
      }

      // ✅ FIXED LINE
      const first_name = String(body?.first_name || "").trim();
      if (!first_name) return json({ ok: false, error: "first_name required" }, 400);

      const user_id = newId("usr");
      const session_id = newId("ses");

      await env.DB.prepare("INSERT INTO users(user_id, first_name, created_at) VALUES (?,?,?)")
        .bind(user_id, first_name, now())
        .run();

      await env.DB.prepare(
        "INSERT INTO sessions(session_id, user_id, created_at, last_seen_at, status) VALUES (?,?,?,?,?)"
      )
        .bind(session_id, user_id, now(), now(), "active")
        .run();

      const independent_vars = {
        user: { first_name },
        session: { user_id, session_id },
        q1: {
          one_sentence: null,
          category_guess: null,
          category_confirmed_by_user: null,
          declared_business_type_raw: null,
          declared_business_type_definition_user: null,
          reference_site_url: null,
          business_name: null,
          business_city_state: null,
          business_website_user_provided: null,
          verification_confirmed_by_user: null,
        },
      };

      const dependent_vars = {
        q1: {
          business_type_final: null,
          business_type_definition_final: null,
          business_name_final: null,
          verification: { candidate_url: null, summary: null, source: null },
        },
      };

      await upsertSessionVars(session_id, "q1_business_identity", independent_vars, dependent_vars);

      return json({
        ok: true,
        user_id,
        session_id,
        next_state: "Q1A_ONE_SENTENCE",
        prompt: `${first_name}, if you could describe your business in one sentence, what would that sentence be?`,
      });
    }

    // POST /q1/answer
    if (request.method === "POST" && url.pathname === "/q1/answer") {
      let body;
      try {
        body = await request.json();
      } catch {
        return json({ ok: false, error: "Invalid JSON" }, 400);
      }

      const session_id = String(body?.session_id || "").trim();
      const state = String(body?.state || "").trim();
      const answer = body?.answer;

      if (!session_id || !state) return json({ ok: false, error: "session_id and state required" }, 400);

      const loaded = await loadSessionVars(session_id, "q1_business_identity");
      if (!loaded) return json({ ok: false, error: "Unknown session_id" }, 404);

      const independent_vars = loaded.independent;
      const dependent_vars = loaded.dependent;

      await env.DB.prepare("UPDATE sessions SET last_seen_at=? WHERE session_id=?")
        .bind(now(), session_id)
        .run();

      // --- Q1A ---
      if (state === "Q1A_ONE_SENTENCE") {
        const one_sentence = String(answer || "").trim();
        if (!one_sentence) return json({ ok: false, error: "answer required" }, 400);

        independent_vars.q1.one_sentence = one_sentence;
        independent_vars.q1.category_guess = guessCategory(one_sentence);

        await upsertSessionVars(session_id, "q1_business_identity", independent_vars, dependent_vars);

        return json({
          ok: true,
          next_state: "Q1B_CONFIRM_GUESSED_CATEGORY",
          prompt: `Are you a ${independent_vars.q1.category_guess} business?`,
        });
      }

      // --- Q1B yes/no ---
      if (state === "Q1B_CONFIRM_GUESSED_CATEGORY") {
        const yn = String(answer || "").trim().toLowerCase();

        if (yn === "yes" || yn === "y") {
          independent_vars.q1.category_confirmed_by_user = true;
          dependent_vars.q1.business_type_final = independent_vars.q1.category_guess;

          await upsertSessionVars(session_id, "q1_business_identity", independent_vars, dependent_vars);

          return json({
            ok: true,
            next_state: "Q1C_BUSINESS_NAME",
            prompt: "What is the name of your business?",
          });
        }

        if (yn === "no" || yn === "n") {
          independent_vars.q1.category_confirmed_by_user = false;

          await upsertSessionVars(session_id, "q1_business_identity", independent_vars, dependent_vars);

          return json({
            ok: true,
            next_state: "Q1B_NO_ASK_TYPE",
            prompt: "Well what type of business is it then?",
          });
        }

        return json({ ok: false, error: 'Please answer "yes" or "no".' }, 400);
      }

      // --- Q1B_NO ask type ---
      if (state === "Q1B_NO_ASK_TYPE") {
        const t = String(answer || "").trim();
        if (!t) return json({ ok: false, error: "Please enter the business type." }, 400);

        independent_vars.q1.declared_business_type_raw = t;
        dependent_vars.q1.business_type_final = t;

        await upsertSessionVars(session_id, "q1_business_identity", independent_vars, dependent_vars);

        return json({
          ok: true,
          next_state: "Q1C_BUSINESS_NAME",
          prompt: "What is the name of your business?",
        });
      }

      // --- Q1C business name ---
      if (state === "Q1C_BUSINESS_NAME") {
        const name = String(answer || "").trim();
        if (!name) return json({ ok: false, error: "Business name is required." }, 400);

        independent_vars.q1.business_name = name;
        dependent_vars.q1.business_name_final = name;

        await upsertSessionVars(session_id, "q1_business_identity", independent_vars, dependent_vars);

        return json({
          ok: true,
          next_state: "Q1_DONE",
          prompt: "Thanks. Question 1 is complete.",
        });
      }

      return json({ ok: false, error: `State not implemented yet: ${state}` }, 400);
    }

    // GET /q1/session?session_id=...
    if (request.method === "GET" && url.pathname === "/q1/session") {
      const session_id = url.searchParams.get("session_id") || "";
      if (!session_id) return json({ ok: false, error: "session_id required" }, 400);

      const loaded = await loadSessionVars(session_id, "q1_business_identity");
      if (!loaded) return json({ ok: false, error: "Unknown session_id" }, 404);

      return json({ ok: true, session_id, ...loaded });
    }

    return json({ ok: false, error: "Not Found" }, 404);
  },
};
