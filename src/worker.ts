// src/worker.ts
// Q1 demo Worker (TypeScript) with D1 storage.
//
// Endpoints:
//   POST /q1/start    { first_name: string }
//   POST /q1/answer   { session_id: string, state: "Q1A_ONE_SENTENCE", answer: string }
//   GET  /q1/session?session_id=...
//
// Requires D1 binding "DB" in wrangler.toml and tables:
//   users(user_id, first_name, created_at)
//   sessions(session_id, user_id, created_at, last_seen_at, status)
//   session_vars(session_id, block_id, independent_json, dependent_json, updated_at)
//
// Uses D1 Worker Binding API: env.DB.prepare(...).bind(...).run() and .first()
// https://developers.cloudflare.com/d1/worker-api/  (D1 Worker API)
// https://developers.cloudflare.com/d1/worker-api/prepared-statements/ (first())

export interface Env {
  DB: D1Database;
}

type Q1State = "Q1A_ONE_SENTENCE";

type IndependentVars = {
  user: { first_name: string };
  session: { user_id: string; session_id: string };
  q1: {
    one_sentence: string | null;
    category_guess: string | null;
    category_confirmed_by_user: boolean | null;

    declared_business_type_raw: string | null;
    declared_business_type_definition_user: string | null;
    reference_site_url: string | null;

    business_name: string | null;
    business_city_state: string | null;
    business_website_user_provided: string | null;
    verification_confirmed_by_user: boolean | null;
  };
};

type DependentVars = {
  q1: {
    business_type_final: string | null;
    business_type_definition_final: string | null;
    business_name_final: string | null;
    verification: { candidate_url: string | null; summary: string | null; source: string | null };
  };
};

const BLOCK_ID = "q1_business_identity";

function nowMs(): number {
  return Date.now();
}

function newId(prefix: string): string {
  return `${prefix}_${crypto.randomUUID()}`;
}

function json(obj: unknown, status = 200): Response {
  return new Response(JSON.stringify(obj, null, 2), {
    status,
    headers: { "content-type": "application/json" },
  });
}

async function upsertSessionVars(
  env: Env,
  session_id: string,
  block_id: string,
  independent: IndependentVars,
  dependent: DependentVars
) {
  await env.DB.prepare(
    `INSERT INTO session_vars(session_id, block_id, independent_json, dependent_json, updated_at)
     VALUES (?, ?, ?, ?, ?)
     ON CONFLICT(session_id, block_id) DO UPDATE SET
       independent_json=excluded.independent_json,
       dependent_json=excluded.dependent_json,
       updated_at=excluded.updated_at`
  )
    .bind(session_id, block_id, JSON.stringify(independent), JSON.stringify(dependent), nowMs())
    .run();
}

async function loadSessionVars(env: Env, session_id: string, block_id: string) {
  const row = await env.DB.prepare(
    "SELECT independent_json, dependent_json, updated_at FROM session_vars WHERE session_id=? AND block_id=?"
  )
    .bind(session_id, block_id)
    .first<{
      independent_json: string;
      dependent_json: string;
      updated_at: number;
    }>();

  if (!row) return null;

  return {
    independent: JSON.parse(row.independent_json) as IndependentVars,
    dependent: JSON.parse(row.dependent_json) as DependentVars,
    updated_at: row.updated_at,
  };
}

async function touchSession(env: Env, session_id: string) {
  await env.DB.prepare("UPDATE sessions SET last_seen_at=? WHERE session_id=?")
    .bind(nowMs(), session_id)
    .run();
}

function guessCategory(oneSentence: string): string {
  const s = oneSentence.toLowerCase();

  // Simple deterministic heuristic for demo (replace later with your full tree + lookups)
  if (/(restaurant|cafe|pizza|tacos|burger|bar|bistro|diner|sushi)/.test(s)) return "restaurant";
  if (/(plumb|drain|water heater|pipe|leak|sewer)/.test(s)) return "plumber";
  if (/(electric|breaker|panel|wiring|outlet|lighting)/.test(s)) return "electrician";
  if (/(barber|haircut|fade|beard|shave|salon)/.test(s)) return "barber";
  if (/(detail|detailing|ceramic|car wash|auto detailing)/.test(s)) return "auto detailing";
  return "local business";
}

function initialVars(first_name: string, user_id: string, session_id: string): {
  independent: IndependentVars;
  dependent: DependentVars;
} {
  const independent: IndependentVars = {
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

  const dependent: DependentVars = {
    q1: {
      business_type_final: null,
      business_type_definition_final: null,
      business_name_final: null,
      verification: { candidate_url: null, summary: null, source: null },
    },
  };

  return { independent, dependent };
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    // Health
    if (request.method === "GET" && url.pathname === "/") {
      return json({ ok: true, service: "Q1 demo", time: new Date().toISOString() });
    }

    // GET /q1/session?session_id=...
    if (request.method === "GET" && url.pathname === "/q1/session") {
      const session_id = (url.searchParams.get("session_id") || "").trim();
      if (!session_id) return json({ ok: false, error: "session_id required" }, 400);

      const loaded = await loadSessionVars(env, session_id, BLOCK_ID);
      if (!loaded) return json({ ok: false, error: "Unknown session_id" }, 404);

      return json({ ok: true, session_id, ...loaded });
    }

    // POST /q1/start  { first_name }
    if (request.method === "POST" && url.pathname === "/q1/start") {
      let body: any;
      try {
        body = await request.json();
      } catch {
        return json({ ok: false, error: "Invalid JSON" }, 400);
      }

      const first_name = String(body?.first_name || "").trim();
      if (!first_name) return json({ ok: false, error: "first_name required" }, 400);

      const user_id = newId("usr");
      const session_id = newId("ses");

      await env.DB.prepare("INSERT INTO users(user_id, first_name, created_at) VALUES (?,?,?)")
        .bind(user_id, first_name, nowMs())
        .run();

      await env.DB.prepare(
        "INSERT INTO sessions(session_id, user_id, created_at, last_seen_at, status) VALUES (?,?,?,?,?)"
      )
        .bind(session_id, user_id, nowMs(), nowMs(), "active")
        .run();

      const { independent, dependent } = initialVars(first_name, user_id, session_id);
      await upsertSessionVars(env, session_id, BLOCK_ID, independent, dependent);

      return json({
        ok: true,
        user_id,
        session_id,
        next_state: "Q1A_ONE_SENTENCE",
        prompt: `${first_name}, if you could describe your business in one sentence, what would that sentence be?`,
      });
    }

    // POST /q1/answer  { session_id, state, answer }
    if (request.method === "POST" && url.pathname === "/q1/answer") {
      let body: any;
      try {
        body = await request.json();
      } catch {
        return json({ ok: false, error: "Invalid JSON" }, 400);
      }

      const session_id = String(body?.session_id || "").trim();
      const state = String(body?.state || "").trim() as Q1State;
      const answer = body?.answer;

      if (!session_id || !state) return json({ ok: false, error: "session_id and state required" }, 400);

      const loaded = await loadSessionVars(env, session_id, BLOCK_ID);
      if (!loaded) return json({ ok: false, error: "Unknown session_id" }, 404);

      const { independent, dependent } = loaded;
      await touchSession(env, session_id);

      // Demo: implement Q1A only
      if (state === "Q1A_ONE_SENTENCE") {
        const one_sentence = String(answer || "").trim();
        if (!one_sentence) return json({ ok: false, error: "answer required" }, 400);

        independent.q1.one_sentence = one_sentence;
        independent.q1.category_guess = guessCategory(one_sentence);

        await upsertSessionVars(env, session_id, BLOCK_ID, independent, dependent);

        return json({
          ok: true,
          next_state: "Q1B_CONFIRM_GUESSED_CATEGORY",
          prompt: `Are you a ${independent.q1.category_guess} business?`,
          stored: {
            one_sentence: independent.q1.one_sentence,
            category_guess: independent.q1.category_guess,
          },
        });
      }

      return json({ ok: false, error: `State not implemented: ${state}` }, 400);
    }

    return json({ ok: false, error: "Not Found" }, 404);
  },
};
