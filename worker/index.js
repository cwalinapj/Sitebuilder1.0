// worker/index.js
export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // ===== CORS (supports Pages preview subdomains like fe9edabd.sitebuilder1-03.pages.dev) =====
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

    const now = () => Date.now();
    const newId = (prefix) => `${prefix}_${crypto.randomUUID()}`;

    // ===== D1 helpers =====
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

    // ===== name validation (no numbers) =====
    function cleanHumanName(s) {
      return String(s || "").trim().replace(/\s+/g, " ");
    }
    function isValidHumanName(s) {
      // letters + spaces + hyphen + apostrophe only
      return /^[A-Za-z][A-Za-z\s'-]{0,63}$/.test(String(s || "").trim());
    }

    // ===== deterministic business-type guess =====
    function guessBusinessType(desc) {
      const s = (desc || "").toLowerCase();

      // scuba / dive
      if (/(scuba|dive gear|diving|snorkel|dive shop|dive center)/.test(s)) return "dive shop";

      if (/(restaurant|cafe|pizza|tacos|burger|bar|bistro|diner|sushi|menu)/.test(s)) return "restaurant";
      if (/(plumb|drain|water heater|pipe|leak|sewer)/.test(s)) return "plumber";
      if (/(electric|breaker|panel|wiring|outlet|lighting)/.test(s)) return "electrician";
      if (/(barber|haircut|fade|beard|shave|salon)/.test(s)) return "barber";
      if (/(detail|detailing|ceramic|car wash|clean cars|wash cars)/.test(s)) return "auto detailing";
      if (/(sell cars|selling cars|car dealer|dealership|used cars|new cars)/.test(s)) return "car dealership";
      return "local business";
    }

    function yesNo(answer) {
      const yn = String(answer || "").trim().toLowerCase();
      if (["yes", "y", "yeah", "yep", "sure", "ok"].includes(yn)) return true;
      if (["no", "n", "nope", "nah", "stop"].includes(yn)) return false;
      return null;
    }

    function isZip(s) {
      return /^\d{5}(-\d{4})?$/.test(String(s || "").trim());
    }

    // ===== OpenAI web_search: top 3 candidates for (address + business_type) =====
    async function openaiSearchTop3(env, query) {
      if (!env.OPENAI_API_KEY) throw new Error("Missing OPENAI_API_KEY secret");

      const payload = {
        model: "gpt-4.1-mini",
        tools: [{ type: "web_search" }],
        input: [
          {
            role: "user",
            content: [
              {
                type: "text",
                text:
                  `You are helping identify a business at a physical address.\n` +
                  `Task: Find the best matches for what business is located at this address.\n` +
                  `Query: ${query}\n\n` +
                  `Return STRICT JSON ONLY: an array of up to 3 objects:\n` +
                  `[{"name":"","url":"","snippet":"","source_hint":""}]\n\n` +
                  `Rules:\n` +
                  `- Prefer official sites or Google Business/Maps, then Yelp/Facebook/BBB.\n` +
                  `- name must be the business name, not the category.\n` +
                  `- url must be https.\n` +
                  `- snippet should mention the address/city if possible.\n` +
                  `- No extra text outside JSON.`
              }
            ]
          }
        ]
      };

      const r = await fetch("https://api.openai.com/v1/responses", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${env.OPENAI_API_KEY}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(payload),
      });

      if (!r.ok) {
        const t = await r.text();
        throw new Error(`OpenAI error ${r.status}: ${t.slice(0, 500)}`);
      }

      const data = await r.json();
      const outText = (data.output_text || "").trim();

      try {
        const arr = JSON.parse(outText);
        if (!Array.isArray(arr)) return [];
        return arr
          .slice(0, 3)
          .map((x) => ({
            name: String(x?.name || "").trim(),
            url: String(x?.url || "").trim(),
            snippet: String(x?.snippet || "").trim(),
            source_hint: String(x?.source_hint || "").trim(),
          }))
          .filter((x) => x.name && x.url);
      } catch {
        return [];
      }
    }

    function formatCandidates(list) {
      if (!Array.isArray(list) || list.length === 0) return "I couldn’t find reliable matches.";
      const lines = [];
      for (let i = 0; i < list.length; i++) {
        const c = list[i];
        let domain = c.source_hint;
        if (!domain) {
          try { domain = new URL(c.url).hostname; } catch { domain = ""; }
        }
        const snip = c.snippet ? ` — ${c.snippet}` : "";
        lines.push(`${i + 1}) ${c.name}${domain ? ` (${domain})` : ""}${snip}`);
      }
      return lines.join("\n");
    }

    function pick123none(ans, max) {
      const a = String(ans || "").trim().toLowerCase();
      if (a === "none" || a === "no" || a === "n") return { kind: "none" };
      const m = a.match(/^\s*([1-9])\s*$/);
      if (m) {
        const n = Number(m[1]);
        if (n >= 1 && n <= max) return { kind: "pick", index: n - 1 };
      }
      return { kind: "invalid" };
    }

    // ===== ROUTES =====
    if (request.method === "GET" && url.pathname === "/") {
      return json({ ok: true, service: "Onboarding demo (Name + Q1 + Q2 + Q3/Q4)", time: new Date().toISOString() });
    }

    // Debug read
    if (request.method === "GET" && url.pathname === "/q1/session") {
      const session_id = (url.searchParams.get("session_id") || "").trim();
      if (!session_id) return json({ ok: false, error: "session_id required" }, 400);
      const loaded = await loadSessionVars(session_id, "onboarding_v1");
      if (!loaded) return json({ ok: false, error: "Unknown session_id" }, 404);
      return json({ ok: true, session_id, ...loaded });
    }

    // START: First Name + Last Name
    // POST /q1/start { FirstName, LastName }
    if (request.method === "POST" && url.pathname === "/q1/start") {
      let body;
      try { body = await request.json(); } catch { return json({ ok: false, error: "Invalid JSON" }, 400); }

      const first_name = cleanHumanName(body?.FirstName || body?.first_name);
      const last_name  = cleanHumanName(body?.LastName  || body?.last_name);

      if (!isValidHumanName(first_name) || !isValidHumanName(last_name)) {
        return json({
          ok: false,
          error: "FirstName and LastName must use letters only (spaces, hyphens, apostrophes allowed)."
        }, 400);
      }

      const user_id = newId("usr");
      const session_id = newId("ses");

      await env.DB.prepare("INSERT INTO users(user_id, first_name, created_at) VALUES (?,?,?)")
        .bind(user_id, first_name, now())
        .run();

      await env.DB.prepare("INSERT INTO sessions(session_id, user_id, created_at, last_seen_at, status) VALUES (?,?,?,?,?)")
        .bind(session_id, user_id, now(), now(), "active")
        .run();

      const independent_vars = {
        person: { first_name, last_name },
        session: { user_id, session_id },

        business: {
          description_brief_raw: null,
          address_raw: null,
          zip_raw: null,
          name_user_provided: null,
        },

        location: {
          location_count: null,
          service_model: null
        }
      };

      const dependent_vars = {
        business: {
          type_guess: null,
          name_final: null,
          website_candidate: null,
          zip_final: null
        },
        lookup: {
          query: null,
          candidates_top3: [],
          picked_index: null
        }
      };

      await upsertSessionVars(session_id, "onboarding_v1", independent_vars, dependent_vars);

      return json({
        ok: true,
        user_id,
        session_id,
        next_state: "Q1_DESCRIBE_BRIEFLY",
        prompt: `Hello ${first_name} ${last_name}, Could you please describe your business to me briefly?`
      });
    }

    // ANSWER: POST /q1/answer { session_id, state, answer }
    if (request.method === "POST" && url.pathname === "/q1/answer") {
      let body;
      try { body = await request.json(); } catch { return json({ ok: false, error: "Invalid JSON" }, 400); }

      const session_id = String(body?.session_id || "").trim();
      const state = String(body?.state || "").trim();
      const answer = body?.answer;

      if (!session_id || !state) return json({ ok: false, error: "session_id and state required" }, 400);

      const loaded = await loadSessionVars(session_id, "onboarding_v1");
      if (!loaded) return json({ ok: false, error: "Unknown session_id" }, 404);

      const independent_vars = loaded.independent;
      const dependent_vars = loaded.dependent;

      await env.DB.prepare("UPDATE sessions SET last_seen_at=? WHERE session_id=?")
        .bind(now(), session_id)
        .run();

      // Q1
      if (state === "Q1_DESCRIBE_BRIEFLY") {
        const desc = String(answer || "").trim();
        if (!desc) return json({ ok: false, error: "Please describe your business briefly." }, 400);

        independent_vars.business.description_brief_raw = desc;
        dependent_vars.business.type_guess = guessBusinessType(desc);

        await upsertSessionVars(session_id, "onboarding_v1", independent_vars, dependent_vars);

        return json({
          ok: true,
          next_state: "Q2_ADDRESS",
          prompt: `Could you please tell me your address to your ${dependent_vars.business.type_guess}?`
        });
      }

      // Q2 address -> search -> pick -> else manual name -> then ZIP
      if (state === "Q2_ADDRESS") {
        const addr = String(answer || "").trim();
        if (!addr) return json({ ok: false, error: "Address is required." }, 400);

        independent_vars.business.address_raw = addr;

        const q = `"${addr}" ${dependent_vars.business.type_guess || ""} business`;
        dependent_vars.lookup.query = q;

        await upsertSessionVars(session_id, "onboarding_v1", independent_vars, dependent_vars);

        let candidates = [];
        try {
          candidates = await openaiSearchTop3(env, q);
        } catch {
          await upsertSessionVars(session_id, "onboarding_v1", independent_vars, dependent_vars);
          return json({
            ok: true,
            next_state: "Q2_ASK_BUSINESS_NAME_MANUAL",
            prompt: "I couldn't complete the web search. What is the name of your business?"
          });
        }

        dependent_vars.lookup.candidates_top3 = candidates;
        await upsertSessionVars(session_id, "onboarding_v1", independent_vars, dependent_vars);

        if (!candidates.length) {
          return json({
            ok: true,
            next_state: "Q2_ASK_BUSINESS_NAME_MANUAL",
            prompt: "I couldn’t find reliable matches. What is the name of your business?"
          });
        }

        return json({
          ok: true,
          next_state: "Q2_PICK_1_2_3_NONE",
          prompt:
            "Which one is your business?\n" +
            formatCandidates(candidates) +
            "\n\nReply with 1, 2, 3, or none."
        });
      }

      if (state === "Q2_PICK_1_2_3_NONE") {
        const list = dependent_vars.lookup.candidates_top3 || [];
        const choice = pick123none(answer, list.length);

        if (choice.kind === "invalid") return json({ ok: false, error: 'Reply with "1", "2", "3", or "none".' }, 400);

        if (choice.kind === "none") {
          await upsertSessionVars(session_id, "onboarding_v1", independent_vars, dependent_vars);
          return json({
            ok: true,
            next_state: "Q2_ASK_BUSINESS_NAME_MANUAL",
            prompt: "What is the name of your business?"
          });
        }

        const picked = list[choice.index];
        dependent_vars.lookup.picked_index = choice.index;
        dependent_vars.business.name_final = picked.name;
        dependent_vars.business.website_candidate = picked.url;

        await upsertSessionVars(session_id, "onboarding_v1", independent_vars, dependent_vars);

        return json({
          ok: true,
          next_state: "Q2_BUSINESS_ZIP",
          prompt: "Could you give me the ZIP code of the business location?"
        });
      }

      if (state === "Q2_ASK_BUSINESS_NAME_MANUAL") {
        const name = String(answer || "").trim();
        if (!name) return json({ ok: false, error: "Business name is required." }, 400);

        independent_vars.business.name_user_provided = name;
        dependent_vars.business.name_final = name;

        await upsertSessionVars(session_id, "onboarding_v1", independent_vars, dependent_vars);

        return json({
          ok: true,
          next_state: "Q2_BUSINESS_ZIP",
          prompt: "Could you give me the ZIP code of the business location?"
        });
      }

      if (state === "Q2_BUSINESS_ZIP") {
        const zip = String(answer || "").trim();
        if (!isZip(zip)) return json({ ok: false, error: "Please enter a valid ZIP code (e.g., 89502)." }, 400);

        independent_vars.business.zip_raw = zip;
        dependent_vars.business.zip_final = zip;

        await upsertSessionVars(session_id, "onboarding_v1", independent_vars, dependent_vars);

        return json({
          ok: true,
          next_state: "ONBOARDING_PAUSE",
          prompt: "Next: would you like to continue to locations and customer ZIP distribution? (yes/no)"
        });
      }

      // PAUSE -> branch
      if (state === "ONBOARDING_PAUSE") {
        const yn = yesNo(answer);
        if (yn === null) return json({ ok: false, error: 'Please answer "yes" or "no".' }, 400);

        if (yn === false) {
          return json({
            ok: true,
            next_state: "ONBOARDING_DONE",
            prompt: "No problem. Onboarding is paused. Come back anytime to continue."
          });
        }

        return json({
          ok: true,
          next_state: "Q3_LOCATION_COUNT",
          prompt: "How many business locations do you have? (Just a number.)"
        });
      }

      // Q3 number of locations
      if (state === "Q3_LOCATION_COUNT") {
        const n = Number(String(answer || "").trim());
        if (!Number.isFinite(n) || n < 1 || n > 100) return json({ ok: false, error: "Please enter a number of locations (1–100)." }, 400);

        independent_vars.location.location_count = n;
        await upsertSessionVars(session_id, "onboarding_v1", independent_vars, dependent_vars);

        return json({
          ok: true,
          next_state: "Q4_SERVICE_MODEL",
          prompt: "Do customers mostly come to you, do you mostly go to them, or both? (come / go / both)"
        });
      }

      // Q4 service model
      if (state === "Q4_SERVICE_MODEL") {
        const s = String(answer || "").trim().toLowerCase();
        const mapped =
          (s === "come" || s === "storefront") ? "storefront" :
          (s === "go" || s === "service" || s === "service_area") ? "service_area" :
          (s === "both") ? "both" : null;

        if (!mapped) return json({ ok: false, error: 'Please reply: "come", "go", or "both".' }, 400);

        independent_vars.location.service_model = mapped;
        await upsertSessionVars(session_id, "onboarding_v1", independent_vars, dependent_vars);

        return json({
          ok: true,
          next_state: "ONBOARDING_DONE",
          prompt: "Great. Next we’ll do ranked customer ZIPs and % distribution (10/30/50/80+) and then start SERP runs."
        });
      }

      // DONE
      if (state === "ONBOARDING_DONE") {
        return json({
          ok: true,
          next_state: "ONBOARDING_DONE",
          prompt: "Onboarding is complete for now."
        });
      }

      return json({ ok: false, error: `State not implemented yet: ${state}` }, 400);
    }

    return json({ ok: false, error: "Not Found" }, 404);
  }
};
