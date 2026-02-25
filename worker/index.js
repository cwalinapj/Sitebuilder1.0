/* worker/index.js */
const START_RATE_LIMIT_WINDOW_MS = 60 * 1000;
const START_RATE_LIMIT_MAX = 12;
const startRateLimitMap = new Map();
const endpointRateLimitMap = new Map();

function consumeStartRateLimit(ip, ts) {
  const key = String(ip || "anon").trim() || "anon";
  const nowTs = Number(ts) || Date.now();
  const cutoff = nowTs - START_RATE_LIMIT_WINDOW_MS;
  const prev = startRateLimitMap.get(key) || [];
  const recent = prev.filter((x) => x > cutoff);
  recent.push(nowTs);
  startRateLimitMap.set(key, recent);

  // Opportunistic cleanup for memory safety in long-lived isolates.
  if (startRateLimitMap.size > 5000) {
    for (const [k, arr] of startRateLimitMap.entries()) {
      if (!arr.some((x) => x > cutoff)) startRateLimitMap.delete(k);
    }
  }

  return recent.length <= START_RATE_LIMIT_MAX;
}

function consumeEndpointRateLimit(ip, bucket, ts, windowMs, max) {
  const ipKey = String(ip || "anon").trim() || "anon";
  const key = `${bucket}:${ipKey}`;
  const nowTs = Number(ts) || Date.now();
  const cutoff = nowTs - windowMs;
  const prev = endpointRateLimitMap.get(key) || [];
  const recent = prev.filter((x) => x > cutoff);
  recent.push(nowTs);
  endpointRateLimitMap.set(key, recent);

  if (endpointRateLimitMap.size > 10000) {
    for (const [k, arr] of endpointRateLimitMap.entries()) {
      if (!arr.some((x) => x > cutoff)) endpointRateLimitMap.delete(k);
    }
  }

  return recent.length <= max;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // ===== CORS =====
    const origin = request.headers.get("Origin") || "";
    const configuredOrigins = String(env.CORS_ALLOWED_ORIGINS || "")
      .split(",")
      .map((x) => x.trim())
      .filter(Boolean);
    const explicitAllowedOrigins = new Set([
      "https://sitebuilder1-03.pages.dev",
      "https://app.cardetailingreno.com",
      ...configuredOrigins,
    ]);
    const allowed =
      explicitAllowedOrigins.has(origin) ||
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
    const clientIpFromRequest = () => {
      const cfIp = String(request.headers.get("CF-Connecting-IP") || "").trim();
      if (cfIp) return cfIp;
      const forwarded = String(request.headers.get("x-forwarded-for") || "").trim();
      if (forwarded) return forwarded.split(",")[0].trim() || "anon";
      return "anon";
    };
    const clientIp = clientIpFromRequest();

    const isTurnstileEnabled = () =>
      Boolean(String(env.TURNSTILE_SECRET_KEY || "").trim() && String(env.TURNSTILE_SITE_KEY || "").trim());

    async function verifyTurnstileToken(token, expectedAction = null) {
      if (!isTurnstileEnabled()) return { ok: true, skipped: true };

      const responseToken = String(token || "").trim();
      if (!responseToken) {
        return { ok: false, error: "Security verification token missing." };
      }

      try {
        const body = new URLSearchParams();
        body.set("secret", String(env.TURNSTILE_SECRET_KEY || ""));
        body.set("response", responseToken);
        if (clientIp && clientIp !== "anon") body.set("remoteip", clientIp);

        const r = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
          method: "POST",
          headers: { "content-type": "application/x-www-form-urlencoded" },
          body: body.toString(),
        });
        if (!r.ok) return { ok: false, error: "Security verification failed." };
        const data = await r.json().catch(() => null);
        if (!data?.success) {
          return {
            ok: false,
            error: "Security verification failed.",
            details: Array.isArray(data?.["error-codes"]) ? data["error-codes"] : [],
          };
        }

        if (expectedAction && data?.action && String(data.action) !== String(expectedAction)) {
          return { ok: false, error: "Security verification action mismatch." };
        }

        return {
          ok: true,
          challenge_ts: data?.challenge_ts || null,
          hostname: data?.hostname || null,
          action: data?.action || null,
        };
      } catch {
        return { ok: false, error: "Security verification failed." };
      }
    }

    function hasVerifiedSessionSecurity(dependent) {
      if (!isTurnstileEnabled()) return true;
      return Boolean(dependent?.security?.turnstile_verified);
    }

    function ensureExpensiveActionAllowed(dependent) {
      if (hasVerifiedSessionSecurity(dependent)) return null;
      return json(
        {
          ok: false,
          error: "Security verification required before scan/search/build actions. Please restart the chat and verify.",
          code: "SECURITY_VERIFICATION_REQUIRED",
        },
        403
      );
    }

    // ===== Placeholder demo URL for now =====
    const PLACEHOLDER_DEMO_URL = "https://1e8ee195.sitebuilder1-03.pages.dev/";

    // ===== R2 bucket picker =====
    function convoBucket() {
      return env.CONVO_BUCKET || env.seo_ai_apify_raw || null;
    }

    // ===== Conversation logging: D1 -> R2 JSONL =====
    async function nextTurnId(db, session_id) {
      const row = await db
        .prepare("SELECT COALESCE(MAX(turn_id), 0) AS m FROM convo_events WHERE session_id=?")
        .bind(session_id)
        .first();
      return Number(row?.m || 0) + 1;
    }

    async function logEvent(db, session_id, turn_id, speaker, state, text) {
      await db
        .prepare(
          "INSERT OR REPLACE INTO convo_events(session_id, turn_id, speaker, state, text, ts) VALUES (?,?,?,?,?,?)"
        )
        .bind(session_id, turn_id, speaker, state || null, String(text || ""), now())
        .run();
    }

    async function flushSessionToR2(db, session_id, session_created_at) {
      const bucket = convoBucket();
      if (!bucket) return null;

      const res = await db
        .prepare(
          "SELECT turn_id, speaker, state, text, ts FROM convo_events WHERE session_id=? ORDER BY turn_id ASC, CASE speaker WHEN 'user' THEN 0 ELSE 1 END ASC"
        )
        .bind(session_id)
        .all();

      const lines = (res.results || []).map((r) =>
        JSON.stringify({
          ts: r.ts,
          session_id,
          turn_id: r.turn_id,
          speaker: r.speaker,
          state: r.state,
          text: r.text,
        })
      );

      const body = lines.join("\n") + (lines.length ? "\n" : "");
      const key = `conversations/${session_id}_${session_created_at}.jsonl`;

      await bucket.put(key, { body }, { httpMetadata: { contentType: "application/x-ndjson" } }).catch(async () => {
        // Some Wrangler runtimes require bucket.put(key, string). Fall back:
        await bucket.put(key, body, { httpMetadata: { contentType: "application/x-ndjson" } });
      });

      return { key, bytes: body.length };
    }

    // ===== session_vars helpers =====
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

    async function insertUserRow(user_id, first_name, created_at) {
      try {
        await env.DB.prepare("INSERT INTO users(user_id, first_name, created_at) VALUES (?,?,?)")
          .bind(user_id, first_name, created_at)
          .run();
      } catch {
        // Backward compatibility for older schema that lacks users.first_name.
        await env.DB.prepare("INSERT INTO users(user_id, created_at) VALUES (?,?)").bind(user_id, created_at).run();
      }
    }

    async function insertSessionRow(session_id, user_id, created_at) {
      try {
        await env.DB.prepare("INSERT INTO sessions(session_id, user_id, created_at, last_seen_at, status) VALUES (?,?,?,?,?)")
          .bind(session_id, user_id, created_at, created_at, "active")
          .run();
      } catch {
        // Backward compatibility for older schema that lacks sessions.status.
        await env.DB.prepare("INSERT INTO sessions(session_id, user_id, created_at, last_seen_at) VALUES (?,?,?,?)")
          .bind(session_id, user_id, created_at, created_at)
          .run();
      }
    }

    async function callInspector(path, body = null) {
      if (env.INSPECTOR && typeof env.INSPECTOR.fetch === "function") {
        const req = new Request(`https://inspector.internal${path}`, {
          method: body ? "POST" : "GET",
          headers: body ? { "content-type": "application/json" } : undefined,
          body: body ? JSON.stringify(body) : undefined,
        });
        return env.INSPECTOR.fetch(req);
      }

      const base = String(env.INSPECTOR_BASE_URL || "").trim();
      if (!base) throw new Error("Inspector worker not configured");
      const target = new URL(path, base).toString();
      return fetch(target, {
        method: body ? "POST" : "GET",
        headers: body ? { "content-type": "application/json" } : undefined,
        body: body ? JSON.stringify(body) : undefined,
      });
    }

    async function startSiteScan(session_id, targetUrl) {
      const res = await callInspector("/inspect", { session_id, url: targetUrl });
      const payload = await res.json().catch(() => ({}));
      if (!res.ok || !payload?.ok) {
        throw new Error(payload?.error || `Inspector scan failed (${res.status})`);
      }
      return payload;
    }

    async function fetchScanStatus(session_id) {
      const encoded = encodeURIComponent(session_id);
      const res = await callInspector(`/inspect/status?session_id=${encoded}`);
      const payload = await res.json().catch(() => ({}));
      if (!res.ok || !payload?.ok) {
        throw new Error(payload?.error || `Inspector status failed (${res.status})`);
      }
      return payload;
    }

    function bestScanTarget(independent) {
      const own = toHttpsUrl(independent?.business?.own_site_url);
      if (own) return own;
      const guessed = toHttpsUrl(independent?.build?.website_guess);
      if (guessed) return guessed;
      return null;
    }

    function summarizeScan(result) {
      if (!result) return null;
      const parts = [];
      if (result.title) parts.push(`Title: ${result.title}`);
      if (result.h1) parts.push(`H1: ${result.h1}`);
      if (result.platform_hint) parts.push(`Platform hint: ${result.platform_hint}`);
      if (Array.isArray(result.emails) && result.emails.length) parts.push(`Emails found: ${result.emails.length}`);
      if (Array.isArray(result.phones) && result.phones.length) parts.push(`Phones found: ${result.phones.length}`);
      if (Array.isArray(result.schema_types) && result.schema_types.length) {
        parts.push(`Schema: ${result.schema_types.slice(0, 3).join(", ")}`);
      }
      return parts.join(" | ");
    }

    function pickFirstValid(values, validator = () => true) {
      const arr = Array.isArray(values) ? values : [];
      for (const v of arr) {
        const t = String(v || "").trim();
        if (!t) continue;
        if (validator(t)) return t;
      }
      return null;
    }

    function applyScanResultToSession(independent, dependent, result) {
      if (!result) return;
      const emails = Array.isArray(result.emails) ? result.emails : [];
      const phones = Array.isArray(result.phones) ? result.phones : [];
      const addresses = Array.isArray(result.addresses) ? result.addresses : [];
      const platformHint = String(result.platform_hint || "").toLowerCase() || null;
      const dnsProfile = result?.dns_profile && typeof result.dns_profile === "object" ? result.dns_profile : null;
      const infrastructure = result?.infrastructure && typeof result.infrastructure === "object" ? result.infrastructure : null;
      const vendors = result?.vendors && typeof result.vendors === "object" ? result.vendors : null;
      const linkAudit = result?.link_audit && typeof result.link_audit === "object" ? result.link_audit : null;

      dependent.scan = dependent.scan || {};
      dependent.scan.extracted = {
        emails: emails.slice(0, 5),
        phones: phones.slice(0, 5),
        addresses: addresses.slice(0, 5),
      };
      dependent.scan.platform_hint = platformHint;
      dependent.scan.latest_result = {
        title: result.title || null,
        h1: result.h1 || null,
        meta_description: result.meta_description || null,
        platform_hint: platformHint,
        raw_size: Number(result.raw_size || 0) || 0,
        emails: emails.slice(0, 10),
        phones: phones.slice(0, 10),
        addresses: addresses.slice(0, 10),
        schema_types: Array.isArray(result.schema_types) ? result.schema_types.slice(0, 20) : [],
        socials: Array.isArray(result.socials) ? result.socials.slice(0, 20) : [],
        dns_profile: dnsProfile,
        infrastructure,
        vendors,
        link_audit: linkAudit,
      };
      dependent.plugin = dependent.plugin || {};
      if (platformHint) dependent.plugin.detected_platform = platformHint;

      independent.business.site_platform = platformHint;
      independent.business.is_wordpress = platformHint === "wordpress";
      independent.business.tech_profile = independent.business.tech_profile || {
        registrar: null,
        nameservers: [],
        ip_addresses: [],
        hosting_company: null,
        domain_expires_at: null,
        email_provider: null,
        third_party_vendors: {},
        server_hardware_hints: null,
        broken_links: { checked_count: 0, broken_count: 0, broken_paths: [] },
        last_scanned_at: null,
      };
      if (dnsProfile || infrastructure || vendors || linkAudit) {
        independent.business.tech_profile.registrar = infrastructure?.registrar || independent.business.tech_profile.registrar;
        independent.business.tech_profile.nameservers = Array.isArray(dnsProfile?.ns_records)
          ? dnsProfile.ns_records.slice(0, 12)
          : independent.business.tech_profile.nameservers;
        independent.business.tech_profile.ip_addresses = Array.isArray(infrastructure?.ip_addresses)
          ? infrastructure.ip_addresses.slice(0, 12)
          : independent.business.tech_profile.ip_addresses;
        independent.business.tech_profile.hosting_company =
          infrastructure?.hosting_company || independent.business.tech_profile.hosting_company;
        independent.business.tech_profile.domain_expires_at =
          infrastructure?.domain_expires_at || independent.business.tech_profile.domain_expires_at;
        independent.business.tech_profile.email_provider =
          dnsProfile?.email_provider || independent.business.tech_profile.email_provider;
        independent.business.tech_profile.third_party_vendors = vendors || independent.business.tech_profile.third_party_vendors || {};
        independent.business.tech_profile.server_hardware_hints =
          infrastructure?.server_hardware_hints || independent.business.tech_profile.server_hardware_hints || null;
        independent.business.tech_profile.broken_links = linkAudit || independent.business.tech_profile.broken_links || {
          checked_count: 0,
          broken_count: 0,
          broken_paths: [],
        };
        independent.business.tech_profile.last_scanned_at = now();
      }

      const upgrade = ensureUpgradeState(dependent);
      const domainExpiryIso = normalizeIsoDateInput(infrastructure?.domain_expires_at);
      if (domainExpiryIso) {
        upgrade.domain_expiry_at = domainExpiryIso;
      }
      refreshUpgradeExpirySignals(upgrade);

      if (dependent?.plugin?.access_profile && infrastructure?.server_hardware_hints && !dependent.plugin.access_profile.server_hardware_hints) {
        dependent.plugin.access_profile.server_hardware_hints = infrastructure.server_hardware_hints;
      }

      if (!independent.build.email) {
        const firstEmail = pickFirstValid(emails, isLikelyEmail);
        if (firstEmail) independent.build.email = firstEmail;
      }
      if (!independent.build.phone) {
        const firstPhone = pickFirstValid(phones);
        if (firstPhone) independent.build.phone = normalizePhone(firstPhone) || firstPhone;
      }
      if (!independent.build.address && independent.build.location_mode !== "service_area") {
        const firstAddress = pickFirstValid(addresses);
        if (firstAddress) independent.build.address = firstAddress.slice(0, 220);
      }
    }

    function readClientGeo(request) {
      const cf = request?.cf || {};
      return {
        ip: request.headers.get("CF-Connecting-IP") || null,
        city: cf.city || null,
        region: cf.region || cf.regionCode || null,
        country: cf.country || null,
        timezone: cf.timezone || null,
      };
    }

    function geoToLocationText(geo) {
      if (!geo) return null;
      const parts = [geo.city, geo.region, geo.country].filter(Boolean);
      if (!parts.length) return null;
      return parts.join(", ");
    }

    async function searchNearbyReferenceSites(session_id, business_type, location_text, intent_text = null, exclude_urls = []) {
      const res = await callInspector("/market/nearby", {
        session_id,
        business_type,
        location: location_text,
        intent_text: intent_text || null,
        exclude_urls: Array.isArray(exclude_urls) ? exclude_urls.slice(0, 20) : [],
        limit: 3,
      });
      const payload = await res.json().catch(() => ({}));
      if (!res.ok || !payload?.ok) {
        throw new Error(payload?.error || `Market search failed (${res.status})`);
      }
      return payload;
    }

    async function persistPreferenceSnapshot(session_id, independent, dependent) {
      const bucket = convoBucket();
      if (!bucket) return null;
      const key = `preferences/${session_id}.json`;
      const body = JSON.stringify(
        {
          session_id,
          generated_at: now(),
          business_type: independent?.business?.type_final || null,
          location: geoToLocationText(independent?.person?.geo),
          reference_sites: dependent?.research?.sites || [],
          feedback: dependent?.design || null,
        },
        null,
        2
      );
      await bucket.put(key, body, { httpMetadata: { contentType: "application/json" } });
      return key;
    }

    function extractPreferenceSignals(text) {
      const raw = String(text || "").trim();
      const lower = raw.toLowerCase();

      const liked = [];
      const disliked = [];

      const likeMatch = lower.match(/(?:liked?|love(?:d)?|enjoy(?:ed)?)\s+([^.;\n]+)/i);
      const dislikeMatch = lower.match(/(?:didn'?t like|disliked?|hate(?:d)?)\s+([^.;\n]+)/i);

      if (likeMatch?.[1]) liked.push(likeMatch[1].trim());
      if (dislikeMatch?.[1]) disliked.push(dislikeMatch[1].trim());

      if (!liked.length && !disliked.length) {
        liked.push(raw);
      }

      const paletteHints = [];
      const colorWords = ["blue", "teal", "green", "orange", "red", "black", "white", "gold", "navy", "gray"];
      for (const w of colorWords) {
        if (new RegExp(`\\b${w}\\b`, "i").test(lower)) paletteHints.push(w);
      }

      const layoutHints = [];
      if (/\bclean|minimal|simple\b/.test(lower)) layoutHints.push("minimal");
      if (/\bbold|strong|high contrast\b/.test(lower)) layoutHints.push("bold");
      if (/\bclutter|busy|crowded\b/.test(lower)) layoutHints.push("avoid_clutter");
      if (/\beasy to read|readable|clear\b/.test(lower)) layoutHints.push("readable");

      const fontHints = [];
      if (/\bmodern|sans\b/.test(lower)) fontHints.push("sans");
      if (/\bclassic|serif\b/.test(lower)) fontHints.push("serif");

      return {
        raw,
        liked: Array.from(new Set(liked)),
        disliked: Array.from(new Set(disliked)),
        palette_hints: Array.from(new Set(paletteHints)),
        layout_hints: Array.from(new Set(layoutHints)),
        font_hints: Array.from(new Set(fontHints)),
      };
    }

    function cannotAccessDemoSite(text) {
      const t = String(text || "").toLowerCase();
      return (
        /\b(nothing opened|didn'?t open|did not open|not able to go|unable to go|unable to open|couldn'?t open|could not open|no links?|no link)\b/.test(
          t
        ) || /\b(was not able)\b/.test(t)
      );
    }

    function isReadyAfterOpeningDemo(text) {
      const t = String(text || "").toLowerCase();
      return /\b(ready|opened|done|looked|viewed|saw it|i opened it|i looked at it)\b/.test(t);
    }

    function impliesNoCurrentWebsite(text) {
      const t = String(text || "").toLowerCase();
      if (/\b(no website|dont have.*website|do not have.*website|without.*website|no site)\b/.test(t)) return true;
      if (/\b(i need|need|want|would like|like)\b.{0,40}\b(website|site)\b/.test(t) && /\b(build|create|make|with you)\b/.test(t)) return true;
      if (/\b(build|create|make)\b.{0,40}\b(website|site)\b/.test(t) && /\b(with you|together)\b/.test(t)) return true;
      return false;
    }

    function normalizeWebsiteIntentText(text) {
      return String(text || "")
        .replace(/\s+/g, " ")
        .trim()
        .slice(0, 220);
    }

    function fallbackWebsiteIntentFocus(rawIntent, businessType) {
      const raw = normalizeWebsiteIntentText(rawIntent);
      const lower = raw.toLowerCase();
      const bt = String(businessType || "").toLowerCase();

      if (/(dive|scuba)/.test(lower) && /(guide|guiding|instruct|training|lesson|teach|tour)/.test(lower)) {
        return "dive guiding and scuba instruction service website";
      }
      if (/(dive|scuba)/.test(lower) && /(shop|store|retail|gear|equipment|merch)/.test(lower)) {
        return "dive shop and gear retail website";
      }
      if (/(repair|mechanic|garage|tire|body shop|auto)/.test(lower)) {
        return "auto service and repair website";
      }
      if (/(detail|detailing|ceramic|paint correction)/.test(lower)) {
        return "auto detailing service website";
      }

      if (!raw && bt) return `${bt} service website`;
      if (raw && raw.split(/\s+/).length <= 2 && bt) return `${raw} ${bt} website`;
      return raw || `${bt || "local business"} website`;
    }

    async function inferWebsiteIntentFocusWithOpenAI(rawIntent, businessType, locationHint) {
      if (!env.OPENAI_API_KEY) return null;
      const raw = normalizeWebsiteIntentText(rawIntent);
      if (!raw) return null;

      try {
        const r = await fetch("https://api.openai.com/v1/responses", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            authorization: `Bearer ${env.OPENAI_API_KEY}`,
          },
          body: JSON.stringify({
            model: "gpt-4.1-mini",
            input:
              `A client wants a website. Business type: "${String(businessType || "").slice(0, 120)}". ` +
              `Location context: "${String(locationHint || "").slice(0, 120)}". ` +
              `Client message: "${raw}".\n` +
              "Return one short focus phrase (5-12 words) for choosing similar example business websites. " +
              "Return only the phrase.",
          }),
        });
        if (!r.ok) return null;
        const data = await r.json();
        const output =
          data?.output_text ||
          data?.output?.map((o) => o?.content?.map((c) => c?.text || "").join("\n") || "").join("\n") ||
          "";
        const firstLine = String(output || "")
          .split("\n")
          .map((x) => x.trim())
          .find(Boolean);
        const cleaned = normalizeWebsiteIntentText(firstLine);
        return cleaned || null;
      } catch {
        return null;
      }
    }

    async function resolveWebsiteIntentFocus(rawIntent, businessType, locationHint) {
      const raw = normalizeWebsiteIntentText(rawIntent);
      if (!raw) return { focus: null, source: "none", raw: "" };
      const ai = await inferWebsiteIntentFocusWithOpenAI(raw, businessType, locationHint);
      const fallback = fallbackWebsiteIntentFocus(raw, businessType);
      return {
        focus: ai || fallback || raw,
        source: ai ? "openai" : "fallback",
        raw,
      };
    }

    function extractIntentFromNoSiteReply(text) {
      const raw = normalizeWebsiteIntentText(text);
      if (!raw) return null;
      const cleaned = raw
        .replace(/\b(i\s*)?(do not|don't|dont|no)\s+(have|got)\s+(a\s+)?(website|site)(\s+yet)?\b/gi, "")
        .replace(/\b(i\s*)?(would|want|like|need|hoping)\s+(to\s+)?(build|create|make)\s+(a\s+)?(website|site)(\s+with you)?\b/gi, "")
        .replace(/\b(i\s*)?(was|am)\s+hoping\s+you\s+could\s+help\s+me\s+build\s+one\b/gi, "")
        .replace(/^[,\s-]+|[,\s-]+$/g, "")
        .replace(/\s+/g, " ")
        .trim();
      if (cleaned.split(/\s+/).length < 4) return null;
      return cleaned;
    }

    function currentReferenceSite(dependent) {
      const sites = Array.isArray(dependent?.research?.sites) ? dependent.research.sites : [];
      const idxRaw = Number(dependent?.research?.current_site_index ?? 0);
      const idx = Number.isFinite(idxRaw) ? Math.max(0, Math.min(idxRaw, sites.length - 1)) : 0;
      return sites[idx] || null;
    }

    function buildSpecificLikeQuestion(site) {
      const siteTitle = String(site?.snapshot?.title || site?.title || "").trim();
      if (siteTitle) {
        return "What do you like most about this site’s overall look and structure, and what would you change first?";
      }
      return "What do you like most about this site, and what would you change first?";
    }

    function normalizeHexColor(color) {
      const c = String(color || "").trim().toLowerCase();
      const m3 = c.match(/^#([0-9a-f]{3})$/i);
      if (m3) {
        const [a, b, d] = m3[1].split("");
        return `#${a}${a}${b}${b}${d}${d}`;
      }
      const m6 = c.match(/^#([0-9a-f]{6})$/i);
      if (m6) return `#${m6[0].slice(1).toLowerCase()}`;
      return c;
    }

    function layoutHintDescriptions(layoutHints) {
      const hints = Array.isArray(layoutHints) ? layoutHints : [];
      const map = {
        grid: "grid = card/tile blocks",
        flex: "flex = horizontal or vertical content rows",
        hero_section: "hero section = large top banner with headline",
        nav_menu: "nav menu = top navigation links",
        multi_section: "multi section = stacked content sections",
        contact_form: "contact form = inquiry form on page",
        gallery: "gallery = image portfolio section",
      };
      return hints.map((h) => map[h]).filter(Boolean).slice(0, 4);
    }

    function buildSiteFeedbackPrompt(site) {
      const signals = site?.snapshot?.design_signals || {};
      const color_swatches = (Array.isArray(signals.colors) ? signals.colors : [])
        .map((c) => normalizeHexColor(c))
        .filter((c) => /^#([0-9a-f]{6})$/i.test(c))
        .slice(0, 6);
      const layout_guide = layoutHintDescriptions(signals.layout_hints);

      const promptBase = buildSpecificLikeQuestion(site);
      const colorText = color_swatches.length
        ? "\nI added color swatches below so you can point to what you like/dislike."
        : "";
      const layoutText = layout_guide.length
        ? `\nLayout guide (plain language): ${layout_guide.join(" | ")}`
        : "";

      return {
        prompt: `${promptBase}${colorText}${layoutText}`,
        color_swatches,
        layout_guide,
      };
    }

    function userRejectedReferenceSite(text, businessType) {
      const t = String(text || "").toLowerCase();
      const bt = String(businessType || "").toLowerCase();
      const mismatchCore =
        /\b(not|isn'?t|wasn'?t|wrong|irrelevant|not relevant)\b/.test(t) &&
        /\b(site|shop|service|business)\b/.test(t);
      if (mismatchCore) return true;
      if (bt.includes("dive") && /\b(not a dive|not dive|not a dive shop|not a dive service)\b/.test(t)) return true;
      if (bt.includes("plumb") && /\b(not a plumber|not plumbing)\b/.test(t)) return true;
      return false;
    }

    function staleStateRecovery(expectedState, providedState, independent) {
      const demoUrl = independent?.demo?.last_demo_url || PLACEHOLDER_DEMO_URL;

      if (expectedState === "Q2_AUDIT_EMAIL_OPTIN" && providedState === "Q2_HAPPY_COSTS") {
        return {
          ok: true,
          next_state: "Q2_AUDIT_EMAIL_OPTIN",
          prompt:
            "Before we continue, would you like us to email this audit report and/or send domain-expiration reminder emails?\n" +
            'Reply "yes" or "no". You can also say "report only" or "reminders only".',
        };
      }

      if (expectedState === "Q3_VIEWING_DEMO" && providedState === "Q3_VIEW_EXAMPLES_YN") {
        return {
          ok: true,
          next_state: "Q3_VIEWING_DEMO",
          prompt:
            `We already moved to the reference site step. Open this link: ${demoUrl}\n\n` +
            "Reply \"opened\" once you can view it.",
          open_url: demoUrl,
          demo_url: demoUrl,
        };
      }

      if (expectedState === "Q3_FEEDBACK_OPEN" && (providedState === "Q3_VIEW_EXAMPLES_YN" || providedState === "Q3_VIEWING_DEMO")) {
        return {
          ok: true,
          next_state: "Q3_FEEDBACK_OPEN",
          prompt: "Tell me what you like most about this site and what you would change first.",
          open_url: demoUrl,
          demo_url: demoUrl,
        };
      }

      return null;
    }

    function pickDemoPalette(design) {
      const hints = Array.isArray(design?.palette_hints) ? design.palette_hints : [];
      if (hints.includes("blue") || hints.includes("teal") || hints.includes("navy")) {
        return { bg: "#0b1f3a", accent: "#1fa4ff", ink: "#f6fbff" };
      }
      if (hints.includes("green")) {
        return { bg: "#0f2418", accent: "#3fcf8e", ink: "#f3fff8" };
      }
      if (hints.includes("black") || hints.includes("gold")) {
        return { bg: "#111111", accent: "#d9b24c", ink: "#f5f2e9" };
      }
      return { bg: "#1a1a1a", accent: "#5ec2ff", ink: "#ffffff" };
    }

    function buildDemoCss(palette) {
      return `
:root { --bg: ${palette.bg}; --accent: ${palette.accent}; --ink: ${palette.ink}; }
* { box-sizing: border-box; }
body { margin: 0; font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; color: var(--ink); background: radial-gradient(circle at top right, #2d2d2d, var(--bg)); }
.wrap { max-width: 980px; margin: 0 auto; padding: 28px 16px 56px; }
.hero { border: 1px solid #ffffff2c; border-radius: 16px; padding: 28px; background: #ffffff12; backdrop-filter: blur(4px); position: relative; overflow: hidden; }
.hero-art { position: absolute; top: -8px; right: -8px; width: 240px; max-width: 42vw; opacity: 0.28; pointer-events: none; }
.cta { display: inline-block; margin-top: 14px; padding: 10px 14px; border-radius: 10px; background: var(--accent); color: #071015; text-decoration: none; font-weight: 700; }
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 14px; margin-top: 20px; }
.card { border: 1px solid #ffffff2c; border-radius: 12px; padding: 16px; background: #ffffff10; }
h1, h2, p { margin: 0 0 10px; }
ul { margin: 0; padding-left: 18px; }
.reveal { opacity: 0; transform: translateY(10px); transition: opacity .45s ease, transform .45s ease; }
.reveal.in { opacity: 1; transform: translateY(0); }
@media (max-width: 640px) {
  .hero-art { width: 160px; }
}
`.trim();
    }

    function buildDemoJs() {
      return `
(function () {
  var els = document.querySelectorAll(".reveal");
  if (!els.length) return;
  var reveal = function (el, delay) {
    window.setTimeout(function () {
      el.classList.add("in");
    }, delay);
  };
  for (var i = 0; i < els.length; i += 1) {
    reveal(els[i], i * 90);
  }
})();
`.trim();
    }

    function buildDemoHeroSvg(palette) {
      const bg = String(palette?.bg || "#1a1a1a").replace(/"/g, "");
      const accent = String(palette?.accent || "#5ec2ff").replace(/"/g, "");
      const ink = String(palette?.ink || "#ffffff").replace(/"/g, "");
      return `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 600 360" role="img" aria-label="Decorative hero">
  <defs>
    <linearGradient id="g1" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="${accent}" stop-opacity="0.95"/>
      <stop offset="100%" stop-color="${bg}" stop-opacity="0.8"/>
    </linearGradient>
  </defs>
  <rect width="600" height="360" fill="none"/>
  <circle cx="430" cy="84" r="72" fill="url(#g1)"/>
  <path d="M44 286 C 176 210, 286 346, 430 248 C 494 206, 542 186, 588 186" stroke="${ink}" stroke-opacity="0.42" stroke-width="9" fill="none" stroke-linecap="round"/>
  <path d="M44 324 C 176 248, 286 384, 430 286 C 494 244, 542 224, 588 224" stroke="${accent}" stroke-opacity="0.56" stroke-width="7" fill="none" stroke-linecap="round"/>
</svg>`;
    }

    function buildDemoHtml(independent, dependent, assets = null) {
      const esc = (v) =>
        String(v || "")
          .replace(/&/g, "&amp;")
          .replace(/</g, "&lt;")
          .replace(/>/g, "&gt;")
          .replace(/"/g, "&quot;")
          .replace(/'/g, "&#39;");

      const businessName = esc(independent?.build?.business_name || `${titleCaseWords(independent?.business?.type_final || "Local Business")} Demo`);
      const businessType = esc(independent?.business?.type_final || "local business");
      const goal = esc(independent?.build?.goal || "lead generation");
      const vibe = esc(independent?.build?.vibe || "modern and clean");
      const location = esc(geoToLocationText(independent?.person?.geo) || independent?.build?.service_area || independent?.build?.address || "");
      const phone = esc(independent?.build?.phone || "");
      const email = esc(independent?.build?.email || "");
      const design = dependent?.design || {};
      const palette = pickDemoPalette(design);
      const likes = (design?.liked || []).slice(0, 3).map(esc);
      const dislikes = (design?.disliked || []).slice(0, 3).map(esc);
      const cssHref = assets?.cssHref ? esc(assets.cssHref) : null;
      const jsSrc = assets?.jsSrc ? esc(assets.jsSrc) : null;
      const heroImageSrc = assets?.heroImageSrc ? esc(assets.heroImageSrc) : null;
      const inlineCss = buildDemoCss(palette);

      return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${businessName}</title>
  ${cssHref ? `<link rel="stylesheet" href="${cssHref}" />` : `<style>${inlineCss}</style>`}
</head>
<body>
  <main class="wrap">
    <section class="hero reveal">
      ${heroImageSrc ? `<img class="hero-art" src="${heroImageSrc}" alt="" aria-hidden="true" />` : ""}
      <h1>${businessName}</h1>
      <p>${titleCaseWords(businessType)} website concept tailored for a ${vibe} feel.</p>
      <p>Primary goal: ${goal}.</p>
      ${location ? `<p>Serving ${location}.</p>` : ""}
      <a class="cta" href="#contact">Request Service</a>
    </section>
    <section class="grid">
      <article class="card reveal">
        <h2>Design Signals</h2>
        <ul>
          ${likes.length ? likes.map((x) => `<li>Liked: ${x}</li>`).join("") : "<li>Liked: modern presentation</li>"}
          ${dislikes.length ? dislikes.map((x) => `<li>Avoid: ${x}</li>`).join("") : "<li>Avoid: cluttered layouts</li>"}
        </ul>
      </article>
      <article class="card reveal">
        <h2>Conversion Focus</h2>
        <p>Clear call-to-action, visible contact paths, and simplified page flow for faster decisions.</p>
      </article>
      <article class="card reveal" id="contact">
        <h2>Contact</h2>
        <p>${phone || "Phone: pending"}</p>
        <p>${email || "Email: pending"}</p>
      </article>
    </section>
  </main>
  ${jsSrc ? `<script defer src="${jsSrc}"></script>` : ""}
</body>
</html>`;
    }

    async function publishDemoSite(session_id, independent, dependent) {
      const bucket = env.DEMO_BUCKET || convoBucket();
      if (!bucket) return null;
      const key = `demos/${session_id}/index.html`;
      const assetPrefix = `demos/${session_id}/assets`;
      const design = dependent?.design || {};
      const palette = pickDemoPalette(design);
      const cssText = buildDemoCss(palette);
      const jsText = buildDemoJs();
      const heroSvg = buildDemoHeroSvg(palette);
      const cssHash = (await sha256Hex(cssText)).slice(0, 12);
      const jsHash = (await sha256Hex(jsText)).slice(0, 12);
      const svgHash = (await sha256Hex(heroSvg)).slice(0, 12);
      const cssFile = `site.${cssHash}.css`;
      const jsFile = `site.${jsHash}.js`;
      const heroFile = `hero.${svgHash}.svg`;
      const assetCacheControl = String(env.DEMO_ASSET_CACHE_CONTROL || "").trim() || "public, max-age=31536000, immutable";
      const htmlCacheControl = String(env.DEMO_HTML_CACHE_CONTROL || "").trim() || "public, max-age=120";

      await bucket.put(`${assetPrefix}/${cssFile}`, cssText, {
        httpMetadata: { contentType: "text/css; charset=utf-8", cacheControl: assetCacheControl },
      });
      await bucket.put(`${assetPrefix}/${jsFile}`, jsText, {
        httpMetadata: { contentType: "application/javascript; charset=utf-8", cacheControl: assetCacheControl },
      });
      await bucket.put(`${assetPrefix}/${heroFile}`, heroSvg, {
        httpMetadata: { contentType: "image/svg+xml", cacheControl: assetCacheControl },
      });

      const html = buildDemoHtml(independent, dependent, {
        cssHref: `assets/${cssFile}`,
        jsSrc: `assets/${jsFile}`,
        heroImageSrc: `assets/${heroFile}`,
      });
      await bucket.put(key, html, {
        httpMetadata: { contentType: "text/html; charset=utf-8", cacheControl: htmlCacheControl },
      });
      const base = String(env.DEMO_PUBLIC_BASE_URL || "").trim().replace(/\/+$/, "");
      if (!base) return { key, url: null, asset_keys: [`${assetPrefix}/${cssFile}`, `${assetPrefix}/${jsFile}`, `${assetPrefix}/${heroFile}`] };
      return {
        key,
        url: `${base}/${key}`,
        asset_keys: [`${assetPrefix}/${cssFile}`, `${assetPrefix}/${jsFile}`, `${assetPrefix}/${heroFile}`],
      };
    }

    // ===== helpers =====
    function cleanHumanName(s) {
      return String(s || "")
        .normalize("NFKC")
        .replace(/[\u200B-\u200D\uFEFF]/g, "")
        .trim()
        .replace(/\s+/g, " ");
    }

    const BLOCKED_NAME_TOKENS = new Set([
      "fuck",
      "fucking",
      "fucked",
      "fucker",
      "shit",
      "shitty",
      "bitch",
      "bastard",
      "asshole",
      "dick",
      "cunt",
      "fart",
      "penis",
      "vagina",
      "sex",
      "porn",
      "nigger",
      "nigga",
      "whore",
      "slut",
    ]);

    function isBlockedNameWord(word) {
      const w = String(word || "").toLowerCase();
      if (!w) return false;
      if (BLOCKED_NAME_TOKENS.has(w)) return true;
      if (/^fuck\w*$/.test(w)) return true;
      if (/^shit\w*$/.test(w)) return true;
      if (/^bitch\w*$/.test(w)) return true;
      return false;
    }

    function analyzeHumanName(raw, fieldLabel, minLetters) {
      const name = cleanHumanName(raw);
      if (!name) {
        return { ok: false, error: `${fieldLabel} is required.` };
      }
      if (!/^[A-Za-z][A-Za-z\s'-]{0,63}$/.test(name)) {
        return {
          ok: false,
          error: `${fieldLabel} must use letters only (spaces, hyphens, apostrophes allowed).`,
        };
      }

      const letterOnly = name.replace(/[^A-Za-z]/g, "");
      if (letterOnly.length < minLetters) {
        return {
          ok: false,
          error: `${fieldLabel} must be at least ${minLetters} letters long.`,
        };
      }

      if (/(.)\1{3,}/i.test(letterOnly)) {
        return { ok: false, error: `${fieldLabel} looks invalid. Please use your real name.` };
      }
      if (/^(qwerty|asdf|zxcv|test|admin|root|null|undefined|none|xxx)+$/i.test(letterOnly)) {
        return { ok: false, error: `${fieldLabel} looks invalid. Please use your real name.` };
      }

      const words = name
        .toLowerCase()
        .split(/[\s'-]+/)
        .map((x) => x.trim())
        .filter(Boolean);
      if (!words.length || words.some((w) => isBlockedNameWord(w))) {
        return { ok: false, error: `${fieldLabel} contains blocked language.` };
      }

      return { ok: true, value: name };
    }

    function extractUrlFromText(text) {
      const t = String(text || "").trim();
      const m1 = t.match(/https?:\/\/[^\s)]+/i);
      if (m1) return m1[0];
      const m2 = t.match(/\b([a-z0-9-]+\.)+[a-z]{2,}(\/[^\s)]*)?\b/i);
      if (m2) return m2[0];
      return null;
    }

    function toHttpsUrl(raw) {
      const s = String(raw || "").trim();
      if (!s) return null;
      if (s.startsWith("http://") || s.startsWith("https://")) return s;
      return "https://" + s;
    }

    function normalizePathForRedirect(rawPath) {
      const raw = String(rawPath || "").trim();
      if (!raw) return null;
      let candidate = raw;
      if (/^https?:\/\//i.test(candidate)) {
        try {
          const u = new URL(candidate);
          candidate = `${u.pathname || "/"}${u.search || ""}`;
        } catch {
          return null;
        }
      }
      if (!candidate.startsWith("/")) candidate = `/${candidate}`;
      candidate = candidate.replace(/\/{2,}/g, "/");
      if (candidate.length > 240) return null;
      if (candidate === "/" || candidate.startsWith("/wp-admin") || candidate.startsWith("/wp-login.php") || candidate.startsWith("/wp-json")) {
        return null;
      }
      return candidate;
    }

    // yes/no/maybe classifier (+ why/howknow/scan)
    function yesNoMaybe(answer) {
      const t = String(answer || "").trim().toLowerCase();
      const compact = t.replace(/[^a-z0-9]+/g, " ").trim();

      // Intent-first checks so mixed messages like
      // "sure, but did you scan my site?" do not get misrouted as plain "yes".
      if (/\b(headless|chrome|browser|scan|audit|pagespeed|analy|analysis)\b/.test(t)) return "scan";
      if (
        /\b(how do i know|how can i know|how would i know|prove it|what if i don'?t like|what if i don't like|would i like)\b/.test(
          t
        )
      )
        return "howknow";
      if (/\b(why|what for|what's the point|why do you need|why would i)\b/.test(t)) return "why";

      // maybe-ish
      if (
        /\b(kinda|kind of|sort of|sorta|somewhat|maybe|depends|not sure|unsure|neutral|in between|mixed|do not know|don't know)\b/.test(
          t
        )
      )
        return "maybe";
      if (/\b(could be better|not really sure)\b/.test(t)) return "maybe";

      // yes-ish
      if (/^(y|ya|yah|yep|yup|yeah)$/.test(compact)) return "yes";
      if (/\b(yes|yep|yeah|sure|affirmative|right|ok|okay|sounds good)\b/.test(t)) return "yes";

      // no-ish
      if (
        /\b(no|nope|nah|negative|no thanks|dont|do not|not yet|none|dont have|do not have|need one|i need one|want one|i want one)\b/.test(
          t
        )
      )
        return "no";

      return "unknown";
    }

    const MAX_ANSWER_CHARS = 1200;

    function normalizeBusinessPhrase(text) {
      return String(text || "")
        .toLowerCase()
        .replace(/[^a-z0-9\s&/-]/g, " ")
        .replace(/\s+/g, " ")
        .trim()
        .slice(0, 180);
    }

    function normalizeBusinessTypeLabel(text) {
      return String(text || "")
        .toLowerCase()
        .replace(/[^a-z0-9\s&/-]/g, " ")
        .replace(/\s+/g, " ")
        .trim()
        .slice(0, 80);
    }

    function fallbackSubtypeCandidates(desc) {
      const s = String(desc || "").toLowerCase();
      if (/(car repair|auto repair|mechanic|garage|brake|engine repair|transmission)/.test(s)) {
        return ["auto repair shop", "mechanic shop", "tire repair shop"];
      }
      if (/(tire|tyre|flat repair|wheel alignment)/.test(s)) {
        return ["tire repair shop", "auto repair shop", "mechanic shop"];
      }
      if (/(body shop|collision|paint shop|dent repair)/.test(s)) {
        return ["auto body shop", "collision repair shop", "paint and body shop"];
      }
      if (/(roofing|roofer)/.test(s)) {
        return ["roofing contractor", "roof repair company", "general contractor"];
      }
      if (/(hvac|heating|cooling|air conditioning|furnace)/.test(s)) {
        return ["hvac contractor", "heating and cooling service", "air conditioning service"];
      }
      return [];
    }

    function extractJsonArrayFromText(text) {
      const s = String(text || "");
      const start = s.indexOf("[");
      const end = s.lastIndexOf("]");
      if (start < 0 || end < 0 || end <= start) return null;
      try {
        const parsed = JSON.parse(s.slice(start, end + 1));
        return Array.isArray(parsed) ? parsed : null;
      } catch {
        return null;
      }
    }

    function wantsEmailFollowup(text) {
      const t = String(text || "").toLowerCase();
      return /\b(email|e-?mail|mail|emsil|send)\b/.test(t) && /\b(demo|site|website|link)\b/.test(t);
    }

    function wantsDualServerUpgradeInfo(text) {
      const t = String(text || "").toLowerCase();
      return /\b(dual server|two servers|2 servers|high availability|ha setup|redundan|failover|load balanc|cloudflare load|proxmox|colo|colocation|vps hardware)\b/.test(
        t
      );
    }

    function wantsPluginInstall(text) {
      const t = String(text || "").toLowerCase();
      return /\b(plugin install|install plugin|install the plugin|ai-webadmin|ai webadmin|ai-web admin|wordpress plugin|wp plugin|plugin setup|set up plugin)\b/.test(
        t
      );
    }

    function parseAuditEmailPreferences(text) {
      const t = String(text || "").toLowerCase().trim();
      if (!t) return { decision: "unknown", report: null, reminder: null };

      const yesNo = yesNoMaybe(t);
      const reportOnly = /\b(report|audit|summary)\b.{0,16}\bonly\b|\bonly\b.{0,16}\b(report|audit|summary)\b/.test(t);
      const reminderOnly = /\b(reminder|remind|expiry|expiration|expire|renew)\b.{0,16}\bonly\b|\bonly\b.{0,16}\b(reminder|remind|expiry|expiration|expire|renew)\b/.test(
        t
      );
      const bothRequested = /\b(both|all|both of those)\b/.test(t);
      const noReport = /\b(no report|don't send report|do not send report)\b/.test(t);
      const noReminder = /\b(no reminder|don't remind|do not remind|no expiry reminder|no expiration reminder)\b/.test(t);

      let report = null;
      let reminder = null;

      if (reportOnly) {
        report = true;
        reminder = false;
      }
      if (reminderOnly) {
        report = false;
        reminder = true;
      }
      if (bothRequested) {
        report = true;
        reminder = true;
      }

      if (/\b(report|audit|summary)\b/.test(t) && !noReport) report = report ?? true;
      if (/\b(reminder|remind|expiry|expiration|expire|renew)\b/.test(t) && !noReminder) reminder = reminder ?? true;
      if (noReport) report = false;
      if (noReminder) reminder = false;

      if (yesNo === "yes") {
        if (report === null) report = true;
        if (reminder === null) reminder = true;
        return { decision: "yes", report, reminder };
      }
      if (yesNo === "no") {
        if (report === null) report = false;
        if (reminder === null) reminder = false;
        return { decision: "no", report, reminder };
      }

      if (report !== null || reminder !== null) {
        if (report === null) report = false;
        if (reminder === null) reminder = false;
        return { decision: report || reminder ? "yes" : "no", report, reminder };
      }

      return { decision: "unknown", report: null, reminder: null };
    }

    function extractFollowupTimeframe(text) {
      const t = String(text || "").toLowerCase();
      if (/\b(in\s+a\s+week|next\s+week|one\s+week)\b/.test(t)) return "in_one_week";
      if (/\b(tomorrow)\b/.test(t)) return "tomorrow";
      if (/\b(today|asap|soon)\b/.test(t)) return "asap";
      return "unspecified";
    }

    async function recoverEmailFromCurrentSite(session_id, independent, dependent) {
      const existing = independent?.build?.email || null;
      if (existing) return existing;
      if (!hasVerifiedSessionSecurity(dependent)) return null;

      const targetUrl = bestScanTarget(independent);
      if (!targetUrl) return null;

      try {
        const scan = await startSiteScan(session_id, targetUrl);
        const emails = Array.isArray(scan?.result?.emails) ? scan.result.emails : [];
        const found = emails.find((e) => isLikelyEmail(e)) || null;
        if (found) {
          dependent.scan = dependent.scan || {};
          dependent.scan.status = scan.status || "done";
          dependent.scan.request_id = scan.request_id || dependent.scan.request_id || null;
          dependent.scan.latest_summary = summarizeScan(scan.result || null);
        }
        return found;
      } catch {
        return null;
      }
    }

    async function inferBusinessTypeCandidatesWithOpenAI(description, limit = 3) {
      if (!env.OPENAI_API_KEY) return [];
      try {
        const r = await fetch("https://api.openai.com/v1/responses", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            authorization: `Bearer ${env.OPENAI_API_KEY}`,
          },
          body: JSON.stringify({
            model: "gpt-4.1-mini",
            input:
              `Infer likely business types from this short description: "${String(description || "").slice(0, 300)}".\n` +
              `Return strict JSON array only with up to ${limit} labels, most likely first.\n` +
              `Example: ["auto repair shop","mechanic shop","tire repair shop"]`,
          }),
        });
        if (!r.ok) return [];
        const data = await r.json();
        const output =
          data?.output_text ||
          data?.output?.map((o) => o?.content?.map((c) => c?.text || "").join("\n") || "").join("\n") ||
          "";
        const arr = extractJsonArrayFromText(output) || [];
        return arr
          .map((x) => normalizeBusinessTypeLabel(x))
          .filter(Boolean)
          .slice(0, limit);
      } catch {
        return [];
      }
    }

    async function getRememberedBusinessType(description) {
      const phrase = normalizeBusinessPhrase(description);
      if (!phrase) return null;
      try {
        const row = await env.DB.prepare(
          "SELECT canonical_type FROM business_type_memory WHERE phrase=?"
        )
          .bind(phrase)
          .first();
        return normalizeBusinessTypeLabel(row?.canonical_type || "");
      } catch {
        return null;
      }
    }

    async function rememberBusinessType(description, canonical_type, source = "user_confirmed") {
      const phrase = normalizeBusinessPhrase(description);
      const type = normalizeBusinessTypeLabel(canonical_type);
      if (!phrase || !type) return;
      try {
        await env.DB.prepare(
          `INSERT INTO business_type_memory(phrase, canonical_type, source, confirmed_count, updated_at, created_at)
           VALUES (?, ?, ?, 1, ?, ?)
           ON CONFLICT(phrase) DO UPDATE SET
             canonical_type=excluded.canonical_type,
             source=excluded.source,
             confirmed_count=business_type_memory.confirmed_count + 1,
             updated_at=excluded.updated_at`
        )
          .bind(phrase, type, source, now(), now())
          .run();
      } catch {
        // best-effort memory; continue flow if table is not present
      }
    }

    async function resolveBusinessTypeCandidates(description) {
      const remembered = await getRememberedBusinessType(description);
      if (remembered) return { source: "remembered", candidates: [remembered] };

      const deterministic = normalizeBusinessTypeLabel(guessBusinessType(description));
      if (deterministic && deterministic !== "local business") {
        return { source: "heuristic", candidates: [deterministic] };
      }

      const fallback = fallbackSubtypeCandidates(description);
      const ai = await inferBusinessTypeCandidatesWithOpenAI(description, 3);
      const candidates = Array.from(
        new Set(
          [...fallback, ...ai]
            .map((x) => normalizeBusinessTypeLabel(x))
            .filter(Boolean)
            .filter((x) => x !== "local business")
        )
      ).slice(0, 3);

      if (!candidates.length) return { source: "fallback", candidates: ["local business"] };
      return { source: ai.length ? "openai" : "fallback", candidates };
    }

    function guessBusinessType(desc) {
      const s = (desc || "").toLowerCase();
      if (/(detail|detailing|ceramic|car wash|clean cars|wash cars)/.test(s)) return "auto detailing";
      if (/(scuba|instructor|diving|snorkel|dive guide|dive guiding|dive shop|dive center|divemaster)/.test(s))
        return "dive services";
      if (/(landscap|lawn|yard|hardscape|mulch|irrigation|sprinkler)/.test(s)) return "landscaping company";
      if (/(restaurant|cafe|pizza|tacos|burger|bar|bistro|diner|sushi|menu)/.test(s)) return "restaurant";
      if (/(plumb|drain|water heater|pipe|leak|sewer)/.test(s)) return "plumber";
      if (/(electric|breaker|panel|wiring|outlet|lighting)/.test(s)) return "electrician";
      if (/(barber|haircut|fade|beard|shave|salon)/.test(s)) return "barber";
      if (/(sell cars|selling cars|car dealer|dealership|used cars|new cars)/.test(s)) return "car dealership";
      return "local business";
    }

    function parseSpend(text) {
      const t = String(text || "").toLowerCase();
      const num = t.match(/(\$?\s*\d+(?:\.\d+)?)/);
      const amount = num ? Number(String(num[1]).replace(/[^\d.]/g, "")) : null;

      let period = "unknown";
      if (/(per\s*month|monthly|\/\s*mo\b|\bmo\b)/.test(t)) period = "monthly";
      if (/(per\s*year|yearly|annual|\/\s*yr\b|\byr\b|a year)/.test(t)) period = "yearly";

      return { amount, period };
    }

    function isLikelyEmail(s) {
      return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(s || "").trim());
    }
    function extractEmailFromText(t) {
      const m = String(t || "").match(/[^\s@]+@[^\s@]+\.[^\s@]+/);
      return m ? m[0] : null;
    }

    function normalizePhone(raw) {
      const s = String(raw || "").trim();
      if (!s) return null;
      const digits = s.replace(/[^\d+]/g, "");
      return digits || null;
    }
    function isSkip(s) {
      return /^\s*(skip|na|n\/a)\s*$/i.test(String(s || ""));
    }

    function titleCaseWords(s) {
      return String(s || "")
        .split(/\s+/)
        .filter(Boolean)
        .map((w) => w.charAt(0).toUpperCase() + w.slice(1).toLowerCase())
        .join(" ");
    }
    function cityFromServiceArea(serviceArea) {
      const t = String(serviceArea || "").trim();
      if (!t) return "";
      return t.split(",")[0].trim();
    }
    function proposeBusinessNames(businessType, serviceArea) {
      const city = titleCaseWords(cityFromServiceArea(serviceArea)) || "Your Area";
      const bt = (businessType || "").toLowerCase();
      if (bt.includes("detail")) return [`${city} Auto Detailing`, `${city} Mobile Detailing`, `${city} Shine & Detail`];
      if (bt.includes("dive")) return [`${city} Dive Guiding`, `${city} Scuba Instruction`, `${city} Underwater Adventures`];
      return [`${city} ${titleCaseWords(businessType) || "Local Business"}`, `${city} Services`, `${city} Co.`];
    }

    function parseLocationMode(ans) {
      const t = String(ans || "").trim().toLowerCase();
      if (t === "1" || /address|show address|physical|storefront|location/.test(t)) return "address";
      if (t === "2" || /service area|service_area|area|mobile|travel/.test(t)) return "service_area";
      return null;
    }

    function wantsWebsiteAuditFirst(text) {
      const t = String(text || "").toLowerCase();
      const mentionsSite = /\b(wordpress|wp-admin|website|site|web\s*site)\b/.test(t);
      const mentionsAudit =
        /\b(audit|review|scan|analy[sz]e|check\w*|check\s*up|performance|speed|security|schema|seo)\b/.test(t);
      return mentionsSite && mentionsAudit;
    }

    function wantsWordpressAuditNow(text) {
      const t = String(text || "").toLowerCase();
      return (
        /\b(run|do|start|perform)\b.{0,20}\b(audit)\b/.test(t) ||
        /\b(please)\b.{0,20}\b(audit)\b/.test(t) ||
        /\b(go ahead|yes please|please do|run it|do it)\b/.test(t)
      );
    }

    function wantsSchemaSetup(text) {
      const t = String(text || "").toLowerCase();
      const asksAboutSchema =
        /\bschema\b/.test(t) &&
        /\b(what|why|how|explain|dont know|don't know|not sure|confused)\b/.test(t);
      if (asksAboutSchema) return false;
      return (
        /\bschema setup\b/.test(t) ||
        /\bset up schema\b/.test(t) ||
        /\bsetup schema\b/.test(t) ||
        /\b(add|create|setup|set up|build)\b.{0,20}\b(schema|structured data|json-?ld|schema markup)\b/.test(t) ||
        /\b(schema|structured data|json-?ld|schema markup)\b.{0,20}\b(add|create|setup|set up|build)\b/.test(t)
      );
    }

    function asksForSchemaOrAccessExplanation(text) {
      const t = String(text || "").toLowerCase();
      const asks = /\b(what|why|how|explain|dont know|don't know|not sure|confused)\b/.test(t);
      const terms = /\b(schema|schema markup|structured data|ftp|ssh|sso|single sign-on)\b/.test(t);
      return asks && terms;
    }

    function buildSchemaAndAccessExplanationPrompt(dependent) {
      const recs = Array.isArray(dependent?.plugin?.wordpress_audit_summary?.recommendations)
        ? dependent.plugin.wordpress_audit_summary.recommendations.slice(0, 3)
        : [];
      const recLines = recs.length
        ? recs.map((x) => `- ${x}`)
        : [
            "- Reduce heavy page assets (especially large images/scripts).",
            "- Use caching to speed up repeat visits.",
            "- Keep contact/forms protected to reduce abuse and bot load.",
          ];
      return (
        "Great question.\n\n" +
        "Schema markup is extra code that helps Google clearly understand your business details (services, location, hours, reviews). " +
        "It can improve how your listing appears in search and help the right customers find you.\n\n" +
        "Since your site feels slow, here are the first fixes I recommend:\n" +
        `${recLines.join("\n")}\n\n` +
        'If you want, reply "schema setup" and I’ll guide that step-by-step.\n' +
        "Are you currently happy with your website overall?"
      );
    }

    function normalizeSchemaType(text, fallbackType = null) {
      const t = String(text || "").trim().toLowerCase();
      if (!t) return fallbackType || "LocalBusiness";
      if (/dentist/.test(t)) return "Dentist";
      if (/auto detail|detailing/.test(t)) return "AutoDetailing";
      if (/auto repair|mechanic|tire|body shop/.test(t)) return "AutoRepair";
      if (/plumb/.test(t)) return "Plumber";
      if (/electric/.test(t)) return "Electrician";
      if (/restaurant|cafe|food/.test(t)) return "Restaurant";
      if (/store|shop/.test(t)) return "Store";
      if (/real estate/.test(t)) return "RealEstateAgent";
      if (/localbusiness|local business/.test(t)) return "LocalBusiness";
      return t
        .replace(/[^a-z0-9 ]/g, " ")
        .split(/\s+/)
        .filter(Boolean)
        .map((x) => x.charAt(0).toUpperCase() + x.slice(1))
        .join("") || (fallbackType || "LocalBusiness");
    }

    function sanitizeSchemaText(value, maxLen = 220) {
      return String(value || "").replace(/\s+/g, " ").trim().slice(0, maxLen) || null;
    }

    function defaultSchemaTypeFromBusiness(independent) {
      const bt = String(independent?.business?.type_final || "").toLowerCase();
      return normalizeSchemaType(bt, "LocalBusiness");
    }

    function buildSchemaJsonLd(profile, pageUrl = null) {
      const p = profile || {};
      const schema = {
        "@context": "https://schema.org",
        "@type": p.schema_type || "LocalBusiness",
        name: p.business_name || null,
        telephone: p.phone || null,
        url: pageUrl || p.website_url || null,
      };

      if (p.address && p.address_mode !== "service_area") {
        schema.address = {
          "@type": "PostalAddress",
          streetAddress: p.address,
        };
      }
      if (p.service_area) schema.areaServed = p.service_area;
      if (p.hours && Array.isArray(p.hours) && p.hours.length) {
        schema.openingHours = p.hours;
      }

      const cleaned = {};
      for (const [k, v] of Object.entries(schema)) {
        if (v === null || v === undefined || v === "") continue;
        cleaned[k] = v;
      }
      return cleaned;
    }

    function asksForSpeedBenchmark(text) {
      const t = String(text || "").toLowerCase();
      return (
        /\b(benchmark|baseline|compare)\b/.test(t) ||
        /\b(load|loading|page)\s*speed\b/.test(t) ||
        /\b(speed|performance)\b.{0,24}\b(compare|comparison|after|before)\b/.test(t) ||
        /\bpagespeed\b/.test(t)
      );
    }

    function buildWordpressSpeedBenchmarkMessage(dependent) {
      const scanResult = dependent?.scan?.latest_result || null;
      let audit = dependent?.plugin?.wordpress_audit_summary || null;
      if (!audit && scanResult) audit = buildWordPressAuditSummary(scanResult);
      if (!audit) return null;

      const baseScore = Math.max(1, Math.min(100, Number(audit.speedScore || 0) || 1));
      const bytes = Number(scanResult?.raw_size || 0);
      const kb = bytes > 0 ? Math.round(bytes / 1024) : null;

      const gainMin = baseScore <= 55 ? 12 : 8;
      const gainMax = baseScore <= 55 ? 24 : 18;
      const projectedMin = Math.min(98, baseScore + gainMin);
      const projectedMax = Math.min(99, baseScore + gainMax);
      const repeatVisitFaster = baseScore <= 55 ? "30-55%" : "20-40%";

      const baselineLine =
        `Current benchmark baseline: speed score ${baseScore}/100` +
        (kb ? `, page payload about ${kb} KB.` : ".");
      const projectedLine =
        `Expected after plugin + Cloudflare optimization: roughly ${projectedMin}-${projectedMax}/100, ` +
        `with repeat visits often ${repeatVisitFaster} faster (cache-dependent).`;

      return `${baselineLine}\n${projectedLine}\n` + "This is an estimate from the current scan, not a guaranteed SLA.";
    }

    const DEFAULT_UPGRADE_TRAFFIC_THRESHOLD = 2000;
    const DEFAULT_FREE_VPS_OFFER_WINDOW_DAYS = 30;

    function normalizedUpgradeTrafficThreshold() {
      const raw = Number(env.UPGRADE_TRAFFIC_THRESHOLD || DEFAULT_UPGRADE_TRAFFIC_THRESHOLD);
      if (!Number.isFinite(raw) || raw <= 0) return DEFAULT_UPGRADE_TRAFFIC_THRESHOLD;
      return Math.round(raw);
    }

    function normalizedFreeVpsOfferWindowDays() {
      const raw = Number(env.FREE_VPS_OFFER_WINDOW_DAYS || DEFAULT_FREE_VPS_OFFER_WINDOW_DAYS);
      if (!Number.isFinite(raw) || raw <= 0) return DEFAULT_FREE_VPS_OFFER_WINDOW_DAYS;
      return Math.max(7, Math.min(90, Math.round(raw)));
    }

    function normalizeMaybeBool(value, fallback = null) {
      if (typeof value === "boolean") return value;
      if (value === null || value === undefined) return fallback;
      const t = String(value).trim().toLowerCase();
      if (["true", "1", "yes", "y", "on"].includes(t)) return true;
      if (["false", "0", "no", "n", "off"].includes(t)) return false;
      return fallback;
    }

    function parseMetricWithSuffix(raw) {
      const t = String(raw ?? "").trim().toLowerCase();
      const m = t.match(/(\d+(?:\.\d+)?)\s*([km])?/i);
      if (!m) return null;
      let value = Number(m[1]);
      if (!Number.isFinite(value)) return null;
      if ((m[2] || "").toLowerCase() === "k") value *= 1000;
      if ((m[2] || "").toLowerCase() === "m") value *= 1000000;
      return Math.round(value);
    }

    function normalizeMxRecords(raw, limit = 20) {
      if (!Array.isArray(raw)) return [];
      const out = [];
      for (const item of raw) {
        if (!item || typeof item !== "object") continue;
        const target = String(item.target || "")
          .trim()
          .toLowerCase()
          .slice(0, 190);
        if (!target) continue;
        const priRaw = Number(item.pri);
        const pri = Number.isFinite(priRaw) ? Math.max(0, Math.round(priRaw)) : null;
        out.push({ target, pri });
        if (out.length >= limit) break;
      }
      return out;
    }

    function parseTrafficMonthlyFromText(text) {
      const t = String(text || "").toLowerCase();
      const m =
        t.match(/(\d+(?:\.\d+)?\s*[km]?)\s*(?:visits?|visitors?|users?|sessions?|traffic)\b(?:[^a-z0-9]{0,12}(?:monthly|per month|a month|\/mo))?/i) ||
        t.match(/\b(?:monthly traffic|traffic per month|monthly visitors?)\b[^0-9]{0,20}(\d+(?:\.\d+)?\s*[km]?)/i);
      if (!m) return null;
      return parseMetricWithSuffix(m[1]);
    }

    function ensureFunnelState(dependent) {
      dependent.funnel = dependent.funnel || {};
      dependent.funnel.signals = dependent.funnel.signals || {
        forms_enabled: false,
        traffic_over_threshold: false,
        multiple_edits: false,
        custom_domain_requested: false,
      };
      dependent.funnel.metrics = dependent.funnel.metrics || {
        edit_requests_count: 0,
        traffic_monthly: null,
        traffic_threshold: normalizedUpgradeTrafficThreshold(),
        form_submissions_monthly: null,
      };
      dependent.funnel.ctas = dependent.funnel.ctas || {
        connect_cloudflare_url: null,
        migrate_hosting_url: null,
      };
      dependent.funnel.sources = dependent.funnel.sources || {};

      dependent.funnel.metrics.traffic_threshold = normalizedUpgradeTrafficThreshold();
      dependent.funnel.ctas.connect_cloudflare_url = String(env.CONNECT_CLOUDFLARE_URL || "").trim() || null;
      dependent.funnel.ctas.migrate_hosting_url = String(env.MIGRATE_HOSTING_URL || "").trim() || null;
      return dependent.funnel;
    }

    function ensurePluginState(dependent) {
      dependent.plugin = dependent.plugin || {};
      dependent.plugin.wordpress_offer_shown = Boolean(dependent.plugin.wordpress_offer_shown);
      dependent.plugin.wordpress_audit_completed = Boolean(dependent.plugin.wordpress_audit_completed);
      dependent.plugin.wordpress_audit_summary = dependent.plugin.wordpress_audit_summary || null;
      dependent.plugin.audit_metrics = dependent.plugin.audit_metrics || {};
      dependent.plugin.audit_metrics.email_queue_count = Number.isFinite(Number(dependent.plugin.audit_metrics.email_queue_count))
        ? Math.max(0, Math.round(Number(dependent.plugin.audit_metrics.email_queue_count)))
        : null;
      dependent.plugin.audit_metrics.outdated_plugin_count = Number.isFinite(Number(dependent.plugin.audit_metrics.outdated_plugin_count))
        ? Math.max(0, Math.round(Number(dependent.plugin.audit_metrics.outdated_plugin_count)))
        : null;
      dependent.plugin.audit_metrics.inactive_plugin_count = Number.isFinite(Number(dependent.plugin.audit_metrics.inactive_plugin_count))
        ? Math.max(0, Math.round(Number(dependent.plugin.audit_metrics.inactive_plugin_count)))
        : null;
      dependent.plugin.audit_metrics.redundant_plugin_count = Number.isFinite(Number(dependent.plugin.audit_metrics.redundant_plugin_count))
        ? Math.max(0, Math.round(Number(dependent.plugin.audit_metrics.redundant_plugin_count)))
        : null;
      dependent.plugin.audit_metrics.sso_plugin_count = Number.isFinite(Number(dependent.plugin.audit_metrics.sso_plugin_count))
        ? Math.max(0, Math.round(Number(dependent.plugin.audit_metrics.sso_plugin_count)))
        : null;
      dependent.plugin.audit_metrics.pending_comment_moderation_count = Number.isFinite(
        Number(dependent.plugin.audit_metrics.pending_comment_moderation_count)
      )
        ? Math.max(0, Math.round(Number(dependent.plugin.audit_metrics.pending_comment_moderation_count)))
        : null;
      dependent.plugin.audit_metrics.plugin_total_count = Number.isFinite(Number(dependent.plugin.audit_metrics.plugin_total_count))
        ? Math.max(0, Math.round(Number(dependent.plugin.audit_metrics.plugin_total_count)))
        : null;
      dependent.plugin.audit_metrics.active_plugin_count = Number.isFinite(Number(dependent.plugin.audit_metrics.active_plugin_count))
        ? Math.max(0, Math.round(Number(dependent.plugin.audit_metrics.active_plugin_count)))
        : null;
      dependent.plugin.audit_metrics.migration_plugin_count = Number.isFinite(Number(dependent.plugin.audit_metrics.migration_plugin_count))
        ? Math.max(0, Math.round(Number(dependent.plugin.audit_metrics.migration_plugin_count)))
        : null;
      dependent.plugin.audit_metrics.unneeded_plugin_count = Number.isFinite(Number(dependent.plugin.audit_metrics.unneeded_plugin_count))
        ? Math.max(0, Math.round(Number(dependent.plugin.audit_metrics.unneeded_plugin_count)))
        : null;
      dependent.plugin.audit_metrics.smtp_plugin_count = Number.isFinite(Number(dependent.plugin.audit_metrics.smtp_plugin_count))
        ? Math.max(0, Math.round(Number(dependent.plugin.audit_metrics.smtp_plugin_count)))
        : null;
      dependent.plugin.audit_metrics.inactive_user_deleted_count = Number.isFinite(
        Number(dependent.plugin.audit_metrics.inactive_user_deleted_count)
      )
        ? Math.max(0, Math.round(Number(dependent.plugin.audit_metrics.inactive_user_deleted_count)))
        : null;
      dependent.plugin.audit_metrics.inactive_user_candidate_count = Number.isFinite(
        Number(dependent.plugin.audit_metrics.inactive_user_candidate_count)
      )
        ? Math.max(0, Math.round(Number(dependent.plugin.audit_metrics.inactive_user_candidate_count)))
        : null;
      const rawPluginInventory = dependent.plugin.audit_metrics.plugin_inventory;
      dependent.plugin.audit_metrics.plugin_inventory = rawPluginInventory && typeof rawPluginInventory === "object" ? rawPluginInventory : null;
      dependent.plugin.audit_metrics.synced_at = dependent.plugin.audit_metrics.synced_at || null;
      dependent.plugin.audit_metrics.source = dependent.plugin.audit_metrics.source || null;
      dependent.plugin.free_tier_requires_tolldns = true;
      dependent.plugin.github_backup_opt_in = Boolean(dependent.plugin.github_backup_opt_in);
      dependent.plugin.github_vault = dependent.plugin.github_vault || {};
      dependent.plugin.github_vault.connected = Boolean(dependent.plugin.github_vault.connected);
      dependent.plugin.github_vault.repo_slug = dependent.plugin.github_vault.repo_slug || null;
      dependent.plugin.github_vault.owner = dependent.plugin.github_vault.owner || null;
      dependent.plugin.github_vault.repo = dependent.plugin.github_vault.repo || null;
      dependent.plugin.github_vault.branch = dependent.plugin.github_vault.branch || "main";
      dependent.plugin.github_vault.token_masked = dependent.plugin.github_vault.token_masked || null;
      dependent.plugin.github_vault.token_hash = dependent.plugin.github_vault.token_hash || null;
      dependent.plugin.github_vault.token_cipher = dependent.plugin.github_vault.token_cipher || null;
      dependent.plugin.github_vault.github_user = dependent.plugin.github_vault.github_user || null;
      dependent.plugin.github_vault.connected_at = dependent.plugin.github_vault.connected_at || null;
      dependent.plugin.backup = dependent.plugin.backup || {};
      dependent.plugin.backup.last_snapshot_at = dependent.plugin.backup.last_snapshot_at || null;
      dependent.plugin.backup.last_snapshot_key = dependent.plugin.backup.last_snapshot_key || null;
      dependent.plugin.backup.last_snapshot_status = dependent.plugin.backup.last_snapshot_status || null;
      dependent.plugin.backup.last_github_path = dependent.plugin.backup.last_github_path || null;
      dependent.plugin.backup.last_github_status = dependent.plugin.backup.last_github_status || null;
      dependent.plugin.backup.last_error = dependent.plugin.backup.last_error || null;
      dependent.plugin.wallet_auth = dependent.plugin.wallet_auth || {};
      dependent.plugin.wallet_auth.enabled = normalizeMaybeBool(dependent.plugin.wallet_auth.enabled, false) === true;
      dependent.plugin.wallet_auth.last_verified_at = dependent.plugin.wallet_auth.last_verified_at || null;
      dependent.plugin.wallet_auth.wallet_address = dependent.plugin.wallet_auth.wallet_address || null;
      dependent.plugin.wallet_auth.chain_id = Number.isFinite(Number(dependent.plugin.wallet_auth.chain_id))
        ? Math.max(1, Math.round(Number(dependent.plugin.wallet_auth.chain_id)))
        : null;
      dependent.plugin.wallet_auth.user_id = Number.isFinite(Number(dependent.plugin.wallet_auth.user_id))
        ? Math.max(1, Math.round(Number(dependent.plugin.wallet_auth.user_id)))
        : null;
      dependent.plugin.wallet_auth.user_login = dependent.plugin.wallet_auth.user_login || null;
      dependent.plugin.wallet_auth.last_status = dependent.plugin.wallet_auth.last_status || null;
      dependent.plugin.wallet_auth.last_error = dependent.plugin.wallet_auth.last_error || null;
      dependent.plugin.connect = dependent.plugin.connect || {};
      dependent.plugin.connect.pending_connect_id = dependent.plugin.connect.pending_connect_id || null;
      dependent.plugin.connect.status = dependent.plugin.connect.status || "not_started";
      dependent.plugin.connect.cf_account_id = dependent.plugin.connect.cf_account_id || null;
      dependent.plugin.connect.token_masked = dependent.plugin.connect.token_masked || null;
      dependent.plugin.connect.token_hash = dependent.plugin.connect.token_hash || null;
      dependent.plugin.connect.token_verified = Boolean(dependent.plugin.connect.token_verified);
      dependent.plugin.connect.tolldns_installed = Boolean(dependent.plugin.connect.tolldns_installed);
      dependent.plugin.connect.github_connected = Boolean(dependent.plugin.connect.github_connected);
      dependent.plugin.connect.github_repo = dependent.plugin.connect.github_repo || null;
      dependent.plugin.connect.connected_at = dependent.plugin.connect.connected_at || null;
      dependent.plugin.access_profile = dependent.plugin.access_profile || {};
      dependent.plugin.access_profile.hosting_provider = dependent.plugin.access_profile.hosting_provider || null;
      dependent.plugin.access_profile.host_login_url = dependent.plugin.access_profile.host_login_url || null;
      dependent.plugin.access_profile.control_panel_url = dependent.plugin.access_profile.control_panel_url || null;
      dependent.plugin.access_profile.control_panel_type = dependent.plugin.access_profile.control_panel_type || null;
      dependent.plugin.access_profile.panel_username = dependent.plugin.access_profile.panel_username || null;
      dependent.plugin.access_profile.sftp_host = dependent.plugin.access_profile.sftp_host || null;
      dependent.plugin.access_profile.sftp_username = dependent.plugin.access_profile.sftp_username || null;
      dependent.plugin.access_profile.ftp_host = dependent.plugin.access_profile.ftp_host || null;
      dependent.plugin.access_profile.ftp_username = dependent.plugin.access_profile.ftp_username || null;
      dependent.plugin.access_profile.ssh_host = dependent.plugin.access_profile.ssh_host || null;
      dependent.plugin.access_profile.ssh_port = Number.isFinite(Number(dependent.plugin.access_profile.ssh_port))
        ? Math.max(1, Math.min(65535, Math.round(Number(dependent.plugin.access_profile.ssh_port))))
        : 22;
      dependent.plugin.access_profile.ssh_username = dependent.plugin.access_profile.ssh_username || null;
      dependent.plugin.access_profile.ssh_public_key = dependent.plugin.access_profile.ssh_public_key || null;
      dependent.plugin.access_profile.ssh_public_key_fingerprint = dependent.plugin.access_profile.ssh_public_key_fingerprint || null;
      dependent.plugin.access_profile.auth_preference = dependent.plugin.access_profile.auth_preference || "token_or_ssh_key";
      dependent.plugin.access_profile.password_auth_disabled = normalizeMaybeBool(
        dependent.plugin.access_profile.password_auth_disabled,
        null
      );
      dependent.plugin.access_profile.provider_api_token_masked = dependent.plugin.access_profile.provider_api_token_masked || null;
      dependent.plugin.access_profile.provider_api_token_hash = dependent.plugin.access_profile.provider_api_token_hash || null;
      dependent.plugin.access_profile.provider_api_token_cipher = dependent.plugin.access_profile.provider_api_token_cipher || null;
      dependent.plugin.access_profile.server_hardware_hints = dependent.plugin.access_profile.server_hardware_hints || null;
      dependent.plugin.access_profile.notes = dependent.plugin.access_profile.notes || null;
      dependent.plugin.access_profile.updated_at = dependent.plugin.access_profile.updated_at || null;
      dependent.plugin.access_profile.source = dependent.plugin.access_profile.source || null;
      dependent.plugin.email_forwarding = dependent.plugin.email_forwarding || {};
      dependent.plugin.email_forwarding.enabled = normalizeMaybeBool(dependent.plugin.email_forwarding.enabled, false) === true;
      dependent.plugin.email_forwarding.forward_to_email = dependent.plugin.email_forwarding.forward_to_email || null;
      dependent.plugin.email_forwarding.has_mx_records = normalizeMaybeBool(dependent.plugin.email_forwarding.has_mx_records, null);
      dependent.plugin.email_forwarding.email_provider_hint = dependent.plugin.email_forwarding.email_provider_hint || null;
      dependent.plugin.email_forwarding.mx_records = Array.isArray(dependent.plugin.email_forwarding.mx_records)
        ? dependent.plugin.email_forwarding.mx_records
        : [];
      dependent.plugin.email_forwarding.last_configured_at = dependent.plugin.email_forwarding.last_configured_at || null;
      dependent.plugin.email_forwarding.last_forwarded_at = dependent.plugin.email_forwarding.last_forwarded_at || null;
      dependent.plugin.email_forwarding.last_forward_status = dependent.plugin.email_forwarding.last_forward_status || null;
      dependent.plugin.email_forwarding.last_event_id = dependent.plugin.email_forwarding.last_event_id || null;
      dependent.plugin.email_forwarding.last_r2_key = dependent.plugin.email_forwarding.last_r2_key || null;
      dependent.plugin.email_forwarding.last_webhook_status = dependent.plugin.email_forwarding.last_webhook_status || null;
      dependent.plugin.email_forwarding.last_error = dependent.plugin.email_forwarding.last_error || null;
      return dependent.plugin;
    }

    function ensureFollowupState(dependent) {
      dependent.followup = dependent.followup || {};
      dependent.followup.requested = Boolean(dependent.followup.requested);
      dependent.followup.channel = dependent.followup.channel || null;
      dependent.followup.timeframe = dependent.followup.timeframe || null;
      dependent.followup.email = dependent.followup.email || null;
      dependent.followup.requested_at = dependent.followup.requested_at || null;
      dependent.followup.audit_report_email_opt_in = normalizeMaybeBool(dependent.followup.audit_report_email_opt_in, null);
      dependent.followup.domain_expiry_reminder_opt_in = normalizeMaybeBool(dependent.followup.domain_expiry_reminder_opt_in, null);
      dependent.followup.audit_email_opted_at = dependent.followup.audit_email_opted_at || null;
      dependent.followup.audit_email_optin_source = dependent.followup.audit_email_optin_source || null;
      return dependent.followup;
    }

    function ensureUpgradeState(dependent) {
      dependent.upgrade = dependent.upgrade || {};
      dependent.upgrade.dual_server_interest = Boolean(dependent.upgrade.dual_server_interest);
      dependent.upgrade.dual_server_offered_at = dependent.upgrade.dual_server_offered_at || null;
      dependent.upgrade.payment_preference = dependent.upgrade.payment_preference || null;
      dependent.upgrade.domain_expiry_at = normalizeIsoDateInput(dependent.upgrade.domain_expiry_at);
      dependent.upgrade.days_until_domain_expiry = Number.isFinite(Number(dependent.upgrade.days_until_domain_expiry))
        ? Math.round(Number(dependent.upgrade.days_until_domain_expiry))
        : null;
      dependent.upgrade.managed_hosting_expires_at = normalizeIsoDateInput(dependent.upgrade.managed_hosting_expires_at);
      dependent.upgrade.days_until_managed_hosting_expiry = Number.isFinite(Number(dependent.upgrade.days_until_managed_hosting_expiry))
        ? Math.round(Number(dependent.upgrade.days_until_managed_hosting_expiry))
        : null;
      dependent.upgrade.free_vps_offer_window_days = Number.isFinite(Number(dependent.upgrade.free_vps_offer_window_days))
        ? Math.max(7, Math.min(90, Math.round(Number(dependent.upgrade.free_vps_offer_window_days))))
        : normalizedFreeVpsOfferWindowDays();
      dependent.upgrade.free_vps_offer_eligible = Boolean(dependent.upgrade.free_vps_offer_eligible);
      dependent.upgrade.free_vps_offer_reason = dependent.upgrade.free_vps_offer_reason || null;
      dependent.upgrade.last_evaluated_at = dependent.upgrade.last_evaluated_at || null;
      return dependent.upgrade;
    }

    function refreshUpgradeExpirySignals(upgrade, refNow = now()) {
      const u = upgrade || {};
      const offerWindowDays = normalizedFreeVpsOfferWindowDays();
      const domainDays = daysUntilDate(u.domain_expiry_at, refNow);
      const hostingDays = daysUntilDate(u.managed_hosting_expires_at, refNow);
      u.days_until_domain_expiry = domainDays;
      u.days_until_managed_hosting_expiry = hostingDays;
      u.free_vps_offer_window_days = offerWindowDays;
      let eligible = false;
      let reason = null;
      if (Number.isFinite(hostingDays) && hostingDays >= 0 && hostingDays <= offerWindowDays) {
        eligible = true;
        reason = "managed_hosting_expiry_window";
      } else if (Number.isFinite(domainDays) && domainDays >= 0 && domainDays <= offerWindowDays) {
        eligible = true;
        reason = "domain_expiry_window";
      }
      u.free_vps_offer_eligible = eligible;
      u.free_vps_offer_reason = reason;
      u.last_evaluated_at = refNow;
      return u;
    }

    function recomputeFunnelSignals(funnel) {
      const trafficMonthly = Number(funnel?.metrics?.traffic_monthly || 0);
      const trafficThreshold = Number(funnel?.metrics?.traffic_threshold || DEFAULT_UPGRADE_TRAFFIC_THRESHOLD);
      const edits = Number(funnel?.metrics?.edit_requests_count || 0);
      const formSubs = Number(funnel?.metrics?.form_submissions_monthly || 0);

      funnel.signals.traffic_over_threshold =
        Number.isFinite(trafficMonthly) && Number.isFinite(trafficThreshold) && trafficMonthly >= trafficThreshold;
      funnel.signals.multiple_edits = Number.isFinite(edits) && edits >= 2;
      if (Number.isFinite(formSubs) && formSubs > 0) funnel.signals.forms_enabled = true;
      return funnel;
    }

    function evaluateFunnel(dependent) {
      const funnel = ensureFunnelState(dependent);
      recomputeFunnelSignals(funnel);

      const signals = funnel.signals || {};
      const score =
        (signals.forms_enabled ? 1 : 0) +
        (signals.traffic_over_threshold ? 1 : 0) +
        (signals.multiple_edits ? 1 : 0) +
        (signals.custom_domain_requested ? 1 : 0);

      let stage = "demo_only";
      if (score >= 1) stage = "ready_for_connect";
      if (score >= 2 || (signals.traffic_over_threshold && (signals.forms_enabled || signals.custom_domain_requested))) {
        stage = "ready_for_migration";
      }
      return { funnel, stage, score };
    }

    function buildFunnelCtaActions(dependent) {
      const { funnel, stage, score } = evaluateFunnel(dependent);
      const plugin = ensurePluginState(dependent);
      const upgrade = ensureUpgradeState(dependent);
      refreshUpgradeExpirySignals(upgrade);
      const hasPublishedDemo = Boolean(dependent?.demo_build?.url);
      const isWordPressSite =
        String(dependent?.scan?.platform_hint || "").toLowerCase() === "wordpress" ||
        String(plugin?.detected_platform || "").toLowerCase() === "wordpress";
      const pluginFreeUrl = String(env.PLUGIN_FREE_URL || "").trim() || null;
      const tollDnsUrl = String(env.TOLLDNS_URL || "").trim() || null;
      const githubSignupUrl = String(env.GITHUB_SIGNUP_URL || "").trim() || null;
      const dualServerUpgradeUrl = String(env.DUAL_SERVER_UPGRADE_URL || "").trim() || null;
      const paypalUpgradeUrl = String(env.UPGRADE_PAYPAL_URL || "").trim() || null;
      const cryptoUpgradeUrl = String(env.UPGRADE_CRYPTO_URL || "").trim() || null;
      const freeVpsBridgeUrl = String(env.FREE_VPS_BRIDGE_URL || "").trim() || null;
      const shouldOfferDualServer = stage === "ready_for_migration" || upgrade.dual_server_interest;
      const actions = [];
      if (funnel?.ctas?.connect_cloudflare_url && (stage !== "demo_only" || isWordPressSite || hasPublishedDemo)) {
        actions.push({
          id: "connect_cloudflare",
          label: "Connect Cloudflare",
          url: funnel.ctas.connect_cloudflare_url,
          description: "Activate free 1-month hosting + subdomain.",
        });
      }
      if (stage === "ready_for_migration" && funnel?.ctas?.migrate_hosting_url) {
        actions.push({
          id: "migrate_hosting",
          label: "Migrate To Managed Hosting",
          url: funnel.ctas.migrate_hosting_url,
          description: "Move WordPress hosting to our managed stack.",
        });
      }
      if (shouldOfferDualServer && dualServerUpgradeUrl) {
        actions.push({
          id: "dual_server_upgrade",
          label: "Dual Server Upgrade",
          url: dualServerUpgradeUrl,
          description:
            "High-availability setup (2 servers) with Cloudflare load balancing; month-to-month only and no auto-enrollment.",
        });
      }
      if (shouldOfferDualServer && paypalUpgradeUrl) {
        actions.push({
          id: "pay_monthly_paypal",
          label: "Pay Monthly (PayPal)",
          url: paypalUpgradeUrl,
          description: "Manual month-to-month payment. Auto-enrollment is disabled.",
        });
      }
      if (shouldOfferDualServer && cryptoUpgradeUrl) {
        actions.push({
          id: "pay_monthly_crypto",
          label: "Pay Monthly (Crypto)",
          url: cryptoUpgradeUrl,
          description: "Manual month-to-month payment in crypto. Auto-enrollment is disabled.",
        });
      }
      if (upgrade.free_vps_offer_eligible && freeVpsBridgeUrl) {
        const windowDays = Number(upgrade.free_vps_offer_window_days || normalizedFreeVpsOfferWindowDays());
        actions.push({
          id: "free_vps_bridge",
          label: "Free VPS Bridge",
          url: freeVpsBridgeUrl,
          description:
            `Your renewal window is near (${windowDays}-day pre-renewal window). Move early to free VPS bridge hosting with Cloudflare + GitHub continuity.`,
        });
      }
      if (isWordPressSite && pluginFreeUrl) {
        actions.push({
          id: "install_ai_webadmin_plugin",
          label: "Install AI-WebAdmin Plugin",
          url: pluginFreeUrl,
          description: "Enable AI watchdogs, forms protection, and automation.",
        });
      }
      if (isWordPressSite && tollDnsUrl) {
        actions.push({
          id: "install_tolldns_required",
          label: "Install TollDNS (Required)",
          url: tollDnsUrl,
          description: "Free plugin tier requires TollDNS to be installed first.",
        });
      }
      if (isWordPressSite && githubSignupUrl) {
        actions.push({
          id: "signup_github_backup",
          label: "Sign Up For GitHub",
          url: githubSignupUrl,
          description: "Optional: enable sandbox backups before plugin/theme updates.",
        });
      }
      return { stage, score, actions, signals: funnel.signals, metrics: funnel.metrics };
    }

    function maskSecretToken(token) {
      const t = String(token || "").trim();
      if (!t) return null;
      if (t.length <= 8) return `${t.slice(0, 2)}***${t.slice(-2)}`;
      return `${t.slice(0, 4)}...${t.slice(-4)}`;
    }

    async function sha256Hex(value) {
      const text = String(value || "");
      const bytes = new TextEncoder().encode(text);
      const digest = await crypto.subtle.digest("SHA-256", bytes);
      const arr = Array.from(new Uint8Array(digest));
      return arr.map((b) => b.toString(16).padStart(2, "0")).join("");
    }

    async function hmacSha256Hex(secret, message) {
      const enc = new TextEncoder();
      const key = await crypto.subtle.importKey(
        "raw",
        enc.encode(String(secret || "")),
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"]
      );
      const sig = await crypto.subtle.sign("HMAC", key, enc.encode(String(message || "")));
      return Array.from(new Uint8Array(sig))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
    }

    function safeConstantCompareHex(a, b) {
      const x = String(a || "").trim().toLowerCase();
      const y = String(b || "").trim().toLowerCase();
      if (!x || !y || x.length !== y.length) return false;
      let mismatch = 0;
      for (let i = 0; i < x.length; i += 1) mismatch |= x.charCodeAt(i) ^ y.charCodeAt(i);
      return mismatch === 0;
    }

    function parseTimestampMs(tsRaw) {
      const n = Number(String(tsRaw || "").trim());
      if (!Number.isFinite(n) || n <= 0) return null;
      if (n < 1000000000000) return Math.round(n * 1000);
      return Math.round(n);
    }

    function normalizeIsoDateInput(raw) {
      const text = String(raw || "").trim();
      if (!text) return null;
      const d = new Date(text);
      if (!Number.isFinite(d.getTime())) return null;
      return d.toISOString();
    }

    function daysUntilDate(raw, refNow = now()) {
      const text = String(raw || "").trim();
      if (!text) return null;
      const d = new Date(text);
      if (!Number.isFinite(d.getTime())) return null;
      const diffMs = d.getTime() - Number(refNow || Date.now());
      return Math.ceil(diffMs / 86400000);
    }

    function trimTo(raw, max = 240) {
      return String(raw || "").trim().slice(0, max) || null;
    }

    function normalizeMaybeUrl(raw) {
      const v = trimTo(raw, 500);
      if (!v) return null;
      return toHttpsUrl(v);
    }

    function normalizeMaybeUsername(raw) {
      const v = trimTo(raw, 80);
      if (!v) return null;
      if (!/^[A-Za-z0-9._@-]{1,80}$/.test(v)) return null;
      return v;
    }

    function normalizeAuthPreference(raw) {
      const t = String(raw || "").trim().toLowerCase();
      if (["token_or_ssh_key", "ssh_key_only", "api_token_only", "oauth_only"].includes(t)) return t;
      return "token_or_ssh_key";
    }

    function looksLikePublicSshKey(raw) {
      const t = String(raw || "").trim();
      if (!t) return false;
      return /^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(?:256|384|521))\s+[A-Za-z0-9+/=]+(?:\s+.+)?$/.test(t);
    }

    function containsDisallowedPasswordField(body) {
      const forbiddenFields = [
        "password",
        "panel_password",
        "hosting_password",
        "cpanel_password",
        "ftp_password",
        "sftp_password",
        "ssh_password",
      ];
      for (const key of forbiddenFields) {
        const value = String(body?.[key] || "").trim();
        if (value) return key;
      }
      return null;
    }

    async function encryptSecretWithEnvKey(secretText, envKey, fallbackSecret = "") {
      const keySecret = String(env?.[envKey] || "").trim() || String(fallbackSecret || "").trim();
      if (!keySecret) throw new Error(`Missing ${envKey}`);
      const key = await importAesKeyFromSecret(keySecret);
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const plaintext = new TextEncoder().encode(String(secretText || ""));
      const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext);
      return `${bytesToBase64(iv)}.${bytesToBase64(new Uint8Array(ciphertext))}`;
    }

    function parseGitHubRepoSlug(raw) {
      const cleaned = String(raw || "")
        .trim()
        .replace(/^https?:\/\/github\.com\//i, "")
        .replace(/^git@github\.com:/i, "")
        .replace(/\.git$/i, "")
        .replace(/^\/+|\/+$/g, "");
      const m = cleaned.match(/^([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)$/);
      if (!m) return null;
      return {
        owner: m[1],
        repo: m[2],
        slug: `${m[1]}/${m[2]}`,
      };
    }

    function bytesToBase64(bytes) {
      const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes || []);
      let binary = "";
      const chunkSize = 0x8000;
      for (let i = 0; i < arr.length; i += chunkSize) {
        const chunk = arr.subarray(i, i + chunkSize);
        binary += String.fromCharCode(...chunk);
      }
      return btoa(binary);
    }

    function base64ToBytes(base64) {
      const clean = String(base64 || "").trim();
      if (!clean) return new Uint8Array();
      const binary = atob(clean);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
      return bytes;
    }

    async function importAesKeyFromSecret(secret) {
      const secretText = String(secret || "").trim();
      if (!secretText) throw new Error("Missing vault encryption secret");
      const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(secretText));
      return crypto.subtle.importKey("raw", digest, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
    }

    async function encryptSecretForVault(secretText) {
      const key = await importAesKeyFromSecret(env.GITHUB_VAULT_KEY || env.WP_PLUGIN_SHARED_SECRET || "");
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const plaintext = new TextEncoder().encode(String(secretText || ""));
      const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext);
      return `${bytesToBase64(iv)}.${bytesToBase64(new Uint8Array(ciphertext))}`;
    }

    async function decryptSecretFromVault(cipherText) {
      const key = await importAesKeyFromSecret(env.GITHUB_VAULT_KEY || env.WP_PLUGIN_SHARED_SECRET || "");
      const parts = String(cipherText || "").split(".");
      if (parts.length !== 2) throw new Error("Invalid vault ciphertext");
      const iv = base64ToBytes(parts[0]);
      const cipher = base64ToBytes(parts[1]);
      const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, cipher);
      return new TextDecoder().decode(plaintext);
    }

    async function verifyGitHubToken(token) {
      const t = String(token || "").trim();
      if (!t) return { ok: false, error: "GitHub token required." };
      try {
        const r = await fetch("https://api.github.com/user", {
          method: "GET",
          headers: {
            authorization: `Bearer ${t}`,
            accept: "application/vnd.github+json",
            "user-agent": "SitebuilderWorker/1.0",
          },
        });
        if (!r.ok) {
          return { ok: false, error: `GitHub token verification failed (${r.status}).` };
        }
        const data = await r.json().catch(() => null);
        return { ok: true, login: data?.login || null, id: data?.id || null };
      } catch {
        return { ok: false, error: "GitHub token verification failed." };
      }
    }

    async function pushSnapshotToGitHub(token, repo, path, contentText, message, branch = "main") {
      const owner = String(repo?.owner || "").trim();
      const repoName = String(repo?.repo || "").trim();
      if (!owner || !repoName) return { ok: false, error: "Invalid GitHub repo slug." };
      const targetPath = String(path || "").replace(/^\/+/, "");
      if (!targetPath) return { ok: false, error: "Invalid GitHub path." };
      const apiUrl = `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repoName)}/contents/${targetPath}`;
      try {
        const payload = {
          message: String(message || "chore: site snapshot backup"),
          content: bytesToBase64(new TextEncoder().encode(String(contentText || ""))),
          branch: String(branch || "main"),
        };
        const r = await fetch(apiUrl, {
          method: "PUT",
          headers: {
            authorization: `Bearer ${String(token || "").trim()}`,
            accept: "application/vnd.github+json",
            "content-type": "application/json",
            "user-agent": "SitebuilderWorker/1.0",
          },
          body: JSON.stringify(payload),
        });
        if (!r.ok) {
          const errBody = await r.text().catch(() => "");
          return { ok: false, error: `GitHub push failed (${r.status})`, details: errBody.slice(0, 240) };
        }
        const data = await r.json().catch(() => null);
        return {
          ok: true,
          commit_sha: data?.commit?.sha || null,
          content_path: data?.content?.path || targetPath,
        };
      } catch {
        return { ok: false, error: "GitHub push failed." };
      }
    }

    async function verifyWalletSignatureWithGateway(payload) {
      const gateway = String(env.WALLET_VERIFY_WEBHOOK || "").trim();
      if (!gateway) {
        return { ok: false, verified: false, error: "Wallet verification gateway not configured." };
      }
      const bodyText = JSON.stringify(payload || {});
      const headers = { "content-type": "application/json" };
      const webhookSecret = String(env.WALLET_VERIFY_WEBHOOK_SECRET || "").trim();
      if (webhookSecret) {
        headers["x-wallet-verify-signature"] = await hmacSha256Hex(webhookSecret, bodyText);
      }
      try {
        const r = await fetch(gateway, {
          method: "POST",
          headers,
          body: bodyText,
        });
        const data = await r.json().catch(() => null);
        if (!r.ok || !data?.ok) {
          return {
            ok: false,
            verified: false,
            error: data?.error || `Wallet verification gateway failed (${r.status}).`,
          };
        }
        const verified = data?.verified === true;
        const walletAddress = String(data?.wallet_address || payload?.wallet_address || "").trim();
        return {
          ok: true,
          verified,
          wallet_address: walletAddress || null,
          source: data?.source || "wallet_verify_webhook",
          details: data?.details || null,
          error: verified ? null : (data?.error || "Wallet signature not verified."),
        };
      } catch {
        return { ok: false, verified: false, error: "Wallet verification gateway request failed." };
      }
    }

    function suspiciousLinkCount(text) {
      const t = String(text || "");
      const direct = t.match(/https?:\/\/[^\s)]+/gi) || [];
      const bare = t.match(/\b([a-z0-9-]+\.)+[a-z]{2,}(\/[^\s)]*)?\b/gi) || [];
      return new Set([...direct, ...bare]).size;
    }

    function wpCommentHeuristicModeration(input) {
      const content = String(input?.content || "").trim();
      const author = String(input?.author_name || "").trim();
      const authorEmail = String(input?.author_email || "").trim();
      const authorUrl = String(input?.author_url || "").trim();
      const userAgent = String(input?.user_agent || "").trim();
      const ip = String(input?.ip || "").trim();
      const lower = content.toLowerCase();

      let score = 0;
      const reasons = [];

      const linkCount = suspiciousLinkCount(`${content}\n${authorUrl}`);
      if (linkCount >= 3) {
        score += 6;
        reasons.push("high_link_volume");
      } else if (linkCount === 2) {
        score += 4;
        reasons.push("multiple_links");
      } else if (linkCount === 1) {
        score += 1;
        reasons.push("contains_link");
      }

      const spamTerms = [
        "viagra",
        "cialis",
        "casino",
        "betting",
        "loan",
        "forex",
        "crypto giveaway",
        "essay writing",
        "seo service",
        "buy followers",
      ];
      for (const term of spamTerms) {
        if (lower.includes(term)) {
          score += 4;
          reasons.push(`spam_term:${term}`);
          break;
        }
      }

      if (/<a\s|<script|<iframe|javascript:/i.test(content)) {
        score += 4;
        reasons.push("html_or_script_payload");
      }

      if (/(.)\1{8,}/.test(content)) {
        score += 2;
        reasons.push("repeated_characters");
      }

      if (content.length > 1200) {
        score += 2;
        reasons.push("oversized_comment");
      }

      if (content.length < 8) {
        score += 1;
        reasons.push("very_short_comment");
      }

      if (!authorEmail || !isLikelyEmail(authorEmail)) {
        score += 1;
        reasons.push("missing_or_invalid_email");
      }

      if (authorUrl && suspiciousLinkCount(authorUrl) > 0) {
        score += 2;
        reasons.push("author_url_present");
      }

      if (/\d{4,}/.test(author)) {
        score += 1;
        reasons.push("numeric_author_pattern");
      }

      if (!userAgent) {
        score += 1;
        reasons.push("missing_user_agent");
      }

      if (!ip) {
        score += 1;
        reasons.push("missing_ip");
      }

      let action = "keep";
      if (score >= 8) action = "trash";
      else if (score >= 4) action = "spam";
      else if (score >= 2) action = "hold";
      const confidence = Math.max(0.35, Math.min(0.99, 0.45 + score * 0.06));
      return { action, score, confidence, reasons };
    }

    async function moderateWpCommentWithOpenAI(input, heuristic) {
      if (!env.OPENAI_API_KEY) return null;
      if (!input?.content) return null;
      if (heuristic?.score >= 8) return null;
      try {
        const body = {
          model: "gpt-4.1-mini",
          input:
            "You are a WordPress comment moderation classifier.\n" +
            "Classify exactly one action: keep | hold | spam | trash.\n" +
            "Return strict JSON only: {\"action\":\"...\",\"confidence\":0.0-1.0,\"reason\":\"...\"}.\n\n" +
            `Comment content: ${JSON.stringify(String(input.content || "").slice(0, 4000))}\n` +
            `Author: ${JSON.stringify(String(input.author_name || "").slice(0, 120))}\n` +
            `Author email: ${JSON.stringify(String(input.author_email || "").slice(0, 180))}\n` +
            `Author url: ${JSON.stringify(String(input.author_url || "").slice(0, 240))}\n` +
            `Heuristic score: ${Number(heuristic?.score || 0)}\n` +
            `Heuristic action: ${String(heuristic?.action || "keep")}\n`,
        };
        const r = await fetch("https://api.openai.com/v1/responses", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            authorization: `Bearer ${env.OPENAI_API_KEY}`,
          },
          body: JSON.stringify(body),
        });
        if (!r.ok) return null;
        const data = await r.json().catch(() => null);
        const output =
          data?.output_text ||
          data?.output?.map((o) => o?.content?.map((c) => c?.text || "").join("\n") || "").join("\n") ||
          "";
        const firstJsonMatch = String(output || "").match(/\{[\s\S]*\}/);
        if (!firstJsonMatch) return null;
        const parsed = JSON.parse(firstJsonMatch[0]);
        const action = String(parsed?.action || "").trim().toLowerCase();
        const confidence = Number(parsed?.confidence);
        const reason = String(parsed?.reason || "").slice(0, 200);
        if (!["keep", "hold", "spam", "trash"].includes(action)) return null;
        if (!Number.isFinite(confidence)) return null;
        return {
          action,
          confidence: Math.max(0, Math.min(1, confidence)),
          reason: reason || "openai_moderation",
        };
      } catch {
        return null;
      }
    }

    async function verifyCloudflareApiTokenWithCloudflare(apiToken) {
      const token = String(apiToken || "").trim();
      if (!token) return { ok: false, error: "Cloudflare API token is required." };
      try {
        const r = await fetch("https://api.cloudflare.com/client/v4/user/tokens/verify", {
          method: "GET",
          headers: {
            authorization: `Bearer ${token}`,
          },
        });
        const data = await r.json().catch(() => ({}));
        if (!r.ok || data?.success !== true) {
          return {
            ok: false,
            error: "Cloudflare API token could not be verified.",
            code: data?.errors?.[0]?.code || null,
          };
        }
        return {
          ok: true,
          status: data?.result?.status || "active",
          token_id: data?.result?.id || null,
        };
      } catch {
        return { ok: false, error: "Cloudflare API token verification failed." };
      }
    }

    function buildWordPressAuditSummary(scanResult, pluginMetrics = null) {
      const r = scanResult || {};
      const bytes = Number(r.raw_size || 0);
      const emails = Array.isArray(r.emails) ? r.emails : [];
      const phones = Array.isArray(r.phones) ? r.phones : [];
      const schema = Array.isArray(r.schema_types) ? r.schema_types : [];
      const linkAudit = r?.link_audit && typeof r.link_audit === "object" ? r.link_audit : {};
      const brokenLinks = Number.isFinite(Number(linkAudit?.broken_count)) ? Math.max(0, Math.round(Number(linkAudit.broken_count))) : 0;
      const metrics = pluginMetrics || {};
      const emailQueue = Number.isFinite(Number(metrics?.email_queue_count))
        ? Math.max(0, Math.round(Number(metrics.email_queue_count)))
        : null;
      const outdatedPlugins = Number.isFinite(Number(metrics?.outdated_plugin_count))
        ? Math.max(0, Math.round(Number(metrics.outdated_plugin_count)))
        : null;
      const inactivePlugins = Number.isFinite(Number(metrics?.inactive_plugin_count))
        ? Math.max(0, Math.round(Number(metrics.inactive_plugin_count)))
        : null;
      const redundantPlugins = Number.isFinite(Number(metrics?.redundant_plugin_count))
        ? Math.max(0, Math.round(Number(metrics.redundant_plugin_count)))
        : null;
      const ssoPluginCount = Number.isFinite(Number(metrics?.sso_plugin_count))
        ? Math.max(0, Math.round(Number(metrics.sso_plugin_count)))
        : null;
      const pendingComments = Number.isFinite(Number(metrics?.pending_comment_moderation_count))
        ? Math.max(0, Math.round(Number(metrics.pending_comment_moderation_count)))
        : null;
      const clamp = (v, min, max) => Math.max(min, Math.min(max, v));

      let speedScore = 85;
      if (bytes > 900000) speedScore = 45;
      else if (bytes > 500000) speedScore = 62;
      else if (bytes > 250000) speedScore = 76;

      let securityScore = 82;
      if (emails.length >= 2) securityScore -= 10;
      if (phones.length >= 5) securityScore -= 8;
      if (!schema.length) securityScore -= 6;
      if (Number.isFinite(outdatedPlugins) && outdatedPlugins > 0) securityScore -= outdatedPlugins >= 5 ? 8 : 4;
      if (Number.isFinite(inactivePlugins) && inactivePlugins >= 5) securityScore -= 3;
      if (Number.isFinite(redundantPlugins) && redundantPlugins >= 2) securityScore -= 3;
      if (Number.isFinite(ssoPluginCount) && ssoPluginCount < 1) securityScore -= 4;
      if (Number.isFinite(pendingComments) && pendingComments >= 20) securityScore -= 4;
      securityScore = clamp(securityScore, 35, 98);

      let schemaScore = 88;
      if (!schema.length) schemaScore = 36;
      else if (schema.length === 1) schemaScore = 64;
      else if (schema.length <= 3) schemaScore = 78;
      schemaScore = clamp(schemaScore, 25, 99);

      let reliabilityScore = 90;
      if (brokenLinks >= 20) reliabilityScore -= 30;
      else if (brokenLinks >= 10) reliabilityScore -= 20;
      else if (brokenLinks >= 5) reliabilityScore -= 10;
      else if (brokenLinks >= 1) reliabilityScore -= 4;
      if (Number.isFinite(pendingComments) && pendingComments >= 20) reliabilityScore -= 5;
      reliabilityScore = clamp(reliabilityScore, 30, 99);

      const speedGainMin = bytes > 500000 ? 10 : 6;
      const speedGainMax = bytes > 500000 ? 24 : 14;
      const securityGainMin = 5 + (Number.isFinite(outdatedPlugins) && outdatedPlugins > 0 ? 2 : 0);
      const securityGainMax =
        12 +
        (Number.isFinite(outdatedPlugins) && outdatedPlugins > 0 ? 4 : 0) +
        (Number.isFinite(pendingComments) && pendingComments > 0 ? 2 : 0);
      const schemaGainMin = schema.length ? 4 : 18;
      const schemaGainMax = schema.length ? 12 : 36;
      const reliabilityGainMin = brokenLinks > 0 ? Math.min(18, 3 + brokenLinks) : 2;
      const reliabilityGainMax = brokenLinks > 0 ? Math.min(35, 8 + brokenLinks * 2) : 8;

      const projectedGains = {
        speed: { min: speedGainMin, max: speedGainMax },
        security: { min: securityGainMin, max: securityGainMax },
        schema: { min: schemaGainMin, max: schemaGainMax },
        reliability: { min: reliabilityGainMin, max: reliabilityGainMax },
      };
      const projectedScores = {
        speed: { current: speedScore, min_after: clamp(speedScore + speedGainMin, 1, 99), max_after: clamp(speedScore + speedGainMax, 1, 99) },
        security: {
          current: securityScore,
          min_after: clamp(securityScore + securityGainMin, 1, 99),
          max_after: clamp(securityScore + securityGainMax, 1, 99),
        },
        schema: {
          current: schemaScore,
          min_after: clamp(schemaScore + schemaGainMin, 1, 99),
          max_after: clamp(schemaScore + schemaGainMax, 1, 99),
        },
        reliability: {
          current: reliabilityScore,
          min_after: clamp(reliabilityScore + reliabilityGainMin, 1, 99),
          max_after: clamp(reliabilityScore + reliabilityGainMax, 1, 99),
        },
      };

      const recommendations = [];
      if (bytes > 500000) recommendations.push("Optimize page weight and caching for faster first load.");
      if (emails.length) recommendations.push("Protect public contact data with Worker form endpoints + Turnstile.");
      if (!schema.length) recommendations.push("Add structured data to strengthen local search visibility.");
      if (Number.isFinite(outdatedPlugins) && outdatedPlugins > 0) {
        recommendations.push(`Update ${outdatedPlugins} outdated plugin${outdatedPlugins === 1 ? "" : "s"} with staging rollback checks.`);
      }
      if (Number.isFinite(inactivePlugins) && inactivePlugins > 0) {
        recommendations.push(`Disable/remove ${inactivePlugins} inactive plugin${inactivePlugins === 1 ? "" : "s"} that are not in use.`);
      }
      if (Number.isFinite(redundantPlugins) && redundantPlugins > 0) {
        recommendations.push(`Consolidate ${redundantPlugins} redundant plugin${redundantPlugins === 1 ? "" : "s"} with overlapping functionality.`);
      }
      if (Number.isFinite(pendingComments) && pendingComments > 0) {
        recommendations.push(`Clear ${pendingComments} queued comment moderation item${pendingComments === 1 ? "" : "s"} to reduce spam risk.`);
      }
      if (Number.isFinite(emailQueue) && emailQueue > 0) {
        recommendations.push(`Process ${emailQueue} queued email${emailQueue === 1 ? "" : "s"} to protect lead response time.`);
      }
      if (Number.isFinite(ssoPluginCount) && ssoPluginCount < 1) {
        recommendations.push("Enable wp-admin SSO with Cloudflare Access + Google/Facebook IdP.");
      }
      if (brokenLinks > 0) {
        recommendations.push(`Fix ${brokenLinks} broken internal link${brokenLinks === 1 ? "" : "s"} and force 301 redirect fallback to homepage for dead URLs.`);
      }
      recommendations.push("Use AI-WebAdmin plugin watchdogs for plugin/theme update safety checks.");
      const asDisplay = (v) => (Number.isFinite(Number(v)) ? String(Number(v)) : "unknown");

      const summary =
        `WordPress audit summary: Speed ${speedScore}/100, Security ${securityScore}/100, Schema ${schemaScore}/100, Reliability ${reliabilityScore}/100. ` +
        `Signals reviewed: page size ${bytes || 0} bytes, public emails ${emails.length}, phones ${phones.length}, schema types ${schema.length}. ` +
        `Operational snapshot: emails queued ${asDisplay(emailQueue)}, plugins not updated ${asDisplay(outdatedPlugins)}, inactive plugins ${asDisplay(
        inactivePlugins
        )}, redundant plugins ${asDisplay(redundantPlugins)}, wp-admin SSO plugins ${asDisplay(ssoPluginCount)}, comments awaiting moderation ${asDisplay(
          pendingComments
        )}, broken links ${brokenLinks}.`;
      return {
        speedScore,
        securityScore,
        schemaScore,
        reliabilityScore,
        projectedGains,
        projectedScores,
        recommendations,
        summary,
        emailQueue,
        outdatedPlugins,
        inactivePlugins,
        redundantPlugins,
        ssoPluginCount,
        pendingComments,
        brokenLinks,
      };
    }

    function summarizeSiteInfrastructure(result) {
      const infra = result?.infrastructure || {};
      const dns = result?.dns_profile || {};
      const linkAudit = result?.link_audit || {};
      const parts = [];
      if (infra?.registrar) parts.push(`Registrar: ${infra.registrar}`);
      if (infra?.hosting_company) parts.push(`Hosting hint: ${infra.hosting_company}`);
      if (infra?.domain_expires_at) parts.push(`Domain expiry: ${infra.domain_expires_at}`);
      if (dns?.email_provider) parts.push(`Email provider: ${dns.email_provider}`);
      const nsCount = Array.isArray(dns?.ns_records) ? dns.ns_records.length : 0;
      if (nsCount) parts.push(`Nameservers: ${nsCount}`);
      const ipCount = Array.isArray(infra?.ip_addresses) ? infra.ip_addresses.length : 0;
      if (ipCount) parts.push(`IP addresses: ${ipCount}`);
      const stackHints = Array.isArray(infra?.server_hardware_hints?.server_stack_hints)
        ? infra.server_hardware_hints.server_stack_hints.slice(0, 3)
        : [];
      if (stackHints.length) parts.push(`Server stack hints: ${stackHints.join(", ")}`);
      const brokenCount = Number.isFinite(Number(linkAudit?.broken_count)) ? Math.max(0, Math.round(Number(linkAudit.broken_count))) : 0;
      if (brokenCount > 0) parts.push(`Broken links: ${brokenCount}`);
      return parts.slice(0, 5);
    }

    function summarizeVendors(result) {
      const vendors = result?.vendors && typeof result.vendors === "object" ? result.vendors : {};
      const summarize = (key, label) => {
        const arr = Array.isArray(vendors?.[key]) ? vendors[key].slice(0, 3) : [];
        if (!arr.length) return null;
        return `${label}: ${arr.join(", ")}`;
      };
      return [
        summarize("crm", "CRM"),
        summarize("merchanting", "Payments"),
        summarize("booking", "Booking"),
        summarize("email_marketing", "Email tools"),
      ].filter(Boolean);
    }

    function formatIsoDateForDisplay(raw) {
      const v = String(raw || "").trim();
      if (!v) return null;
      try {
        const d = new Date(v);
        if (!Number.isFinite(d.getTime())) return v;
        return d.toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" });
      } catch {
        return v;
      }
    }

    function formatBytesForDisplay(rawBytes) {
      const bytes = Number(rawBytes || 0);
      if (!Number.isFinite(bytes) || bytes <= 0) return "unknown";
      if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
      return `${Math.round(bytes / 1024)} KB`;
    }

    function buildWordpressAuditCustomerPrompt(audit, result, infraSummary = [], vendorSummary = []) {
      const scan = result || {};
      const emailsFound = Array.isArray(scan?.emails) ? scan.emails.length : 0;
      const phonesFound = Array.isArray(scan?.phones) ? scan.phones.length : 0;
      const schemaTypes = Array.isArray(scan?.schema_types) ? scan.schema_types.length : 0;
      const pageSize = formatBytesForDisplay(scan?.raw_size || 0);
      const infra = scan?.infrastructure || {};
      const dns = scan?.dns_profile || {};
      const domainExpiry = formatIsoDateForDisplay(infra?.domain_expires_at);
      const daysUntilDomainExpiry = daysUntilDate(infra?.domain_expires_at);
      const freeVpsWindowDays = normalizedFreeVpsOfferWindowDays();
      const nameserverCount = Array.isArray(dns?.ns_records) ? dns.ns_records.length : 0;
      const asDisplay = (v) => (Number.isFinite(Number(v)) ? String(Number(v)) : "unknown");
      const publicRecommendations = (Array.isArray(audit?.recommendations) ? audit.recommendations : []).filter(
        (x) =>
          !/\b(outdated plugin|inactive plugin|redundant plugin|queued comment moderation|queued email)\b/i.test(String(x || ""))
      );
      const topRecommendations = (publicRecommendations.length ? publicRecommendations : audit.recommendations || []).slice(0, 3);

      const lines = [
        "WordPress audit summary",
        "",
        "Your current scores (0-100):",
        `- Speed (how fast your pages load): ${audit.speedScore}/100`,
        `- Security (how protected your site is): ${audit.securityScore}/100`,
        `- Schema (extra labels that help Google understand your business): ${audit.schemaScore}/100`,
        `- Reliability (how stable your links/pages are): ${audit.reliabilityScore}/100`,
        "",
        "What I checked:",
        `- Page size: ${pageSize} (${Number(scan?.raw_size || 0)} bytes)`,
        `- Public contact info found: ${emailsFound} email(s), ${phonesFound} phone number(s)`,
        `- Schema types found: ${schemaTypes}`,
        schemaTypes === 0
          ? "- Why this matters: with 0 schema types, Google gets less structured detail about your business, which can lower rich results and local search visibility."
          : "- Why this matters: schema helps search engines understand your business and services more accurately.",
        "",
        "Operational snapshot (public checks):",
        "- What this means: a quick external health check from public pages only (no login required).",
        `- Broken links: ${asDisplay(audit.brokenLinks)}`,
        "",
        "Admin-only checks (run after plugin install + connection):",
        "- Plugin update status, comment moderation queue, and internal email queue are checked once the plugin is installed.",
      ];

      const infraLines = [];
      if (infra?.hosting_company) infraLines.push(`- Hosting provider hint: ${infra.hosting_company}`);
      if (domainExpiry) infraLines.push(`- Domain expiration date: ${domainExpiry}`);
      if (dns?.email_provider) infraLines.push(`- Email provider: ${dns.email_provider}`);
      if (nameserverCount) infraLines.push(`- Nameservers: ${nameserverCount} (these connect your domain name to your website host)`);
      const stackHints = Array.isArray(infra?.server_hardware_hints?.server_stack_hints)
        ? infra.server_hardware_hints.server_stack_hints.slice(0, 3)
        : [];
      if (stackHints.length) infraLines.push(`- Server stack hints (public): ${stackHints.join(", ")}`);
      if (Number.isFinite(daysUntilDomainExpiry) && daysUntilDomainExpiry >= 0 && daysUntilDomainExpiry <= freeVpsWindowDays) {
        infraLines.push(
          `- Renewal window alert: about ${daysUntilDomainExpiry} day(s) left. We can schedule a free VPS bridge in the ${freeVpsWindowDays}-day pre-renewal window so you can cancel shared hosting in time.`
        );
      }
      if (infraLines.length) {
        lines.push("", "Infrastructure snapshot:", ...infraLines);
      }
      if (vendorSummary.length) {
        lines.push("", `Third-party tools detected: ${vendorSummary.join(" | ")}`);
      }
      lines.push(
        "",
        "Projected plugin lift (estimated point improvement):",
        `- Speed: +${audit.projectedGains.speed.min} to +${audit.projectedGains.speed.max}`,
        `- Security: +${audit.projectedGains.security.min} to +${audit.projectedGains.security.max}`,
        `- Schema: +${audit.projectedGains.schema.min} to +${audit.projectedGains.schema.max}`,
        `- Reliability: +${audit.projectedGains.reliability.min} to +${audit.projectedGains.reliability.max}`,
        "",
        "Estimated plugin impact: likely medium-to-high, especially for spam/form-abuse protection and safer updates.",
        "",
        "Top actions:",
        ...topRecommendations.map((x) => `- ${x}`),
        "",
        "What is SSO and why it helps:",
        "- SSO means Single Sign-On: you log into wp-admin with one trusted account (like Google) instead of separate passwords.",
        "- More secure: fewer passwords to steal/reuse, easier to enforce two-step verification, and faster access removal.",
        "- Easier: fewer password resets and simpler team login management.",
      );

      return lines.join("\n");
    }

    function buildAuditEmailOptInPrompt() {
      return (
        "Would you like us to email this audit report and/or send domain-expiration reminder emails?\n" +
        'Reply "yes" or "no". You can also say "report only" or "reminders only".'
      );
    }

    function buildSecondPartPrompt() {
      return "Second part: are you currently happy with your website overall? (yes/no or kinda)";
    }

    function buildWordpressAuditReplyPayload(independent, dependent, result) {
      const audit = buildWordPressAuditSummary(result || {}, dependent?.plugin?.audit_metrics || null);
      dependent.plugin.wordpress_audit_completed = true;
      dependent.plugin.wordpress_audit_summary = audit;
      const infraSummary = summarizeSiteInfrastructure(result || {});
      const vendorSummary = summarizeVendors(result || {});
      const auditPrompt = buildWordpressAuditCustomerPrompt(audit, result || {}, infraSummary, vendorSummary);
      return {
        prompt:
          `${auditPrompt}\n\n` +
          "I saved your hosting/DNS and tool profile so we can personalize recommendations later.\n" +
          'If you want me to build schema markup with you now, reply "schema setup" and I’ll ask a few quick questions.\n' +
          "If you want, I can also guide Cloudflare Access SSO setup for wp-admin (single sign-on with Google/Facebook).\n" +
          "You can use the AI-WebAdmin plugin to run watchdog checks, secure forms, automate updates, and take daily site snapshots/backups to help keep uptime as close to 99.99% as possible.\n" +
          "This is all FREE!!!!\n" +
          buildAuditEmailOptInPrompt(),
        wordpress_audit: {
          speed_score: audit.speedScore,
          security_score: audit.securityScore,
          recommendations: audit.recommendations,
          email_queue_count: audit.emailQueue,
          outdated_plugin_count: audit.outdatedPlugins,
          inactive_plugin_count: audit.inactivePlugins,
          redundant_plugin_count: audit.redundantPlugins,
          sso_plugin_count: audit.ssoPluginCount,
          pending_comment_moderation_count: audit.pendingComments,
          broken_link_count: audit.brokenLinks,
          projected_gains: audit.projectedGains,
          projected_scores: audit.projectedScores,
        },
      };
    }

    function applyAnswerToFunnelSignals(state, answerText, dependent) {
      const txt = String(answerText || "").trim();
      if (!txt || txt === "__AUTO_AFTER_20S__") return;
      const lower = txt.toLowerCase();
      const funnel = ensureFunnelState(dependent);

      if (/(form|opt[\s-]?in|lead capture|lead gen|booking form|contact form)/.test(lower)) {
        if (!/\b(no|without|dont|don't|do not)\b.{0,12}\b(form|opt[\s-]?in|lead)\b/.test(lower)) {
          funnel.signals.forms_enabled = true;
        }
      }

      if (/\b(custom domain|own domain|my domain|domain name|bring my domain)\b/.test(lower)) {
        funnel.signals.custom_domain_requested = true;
      }

      const trafficMonthly = parseTrafficMonthlyFromText(lower);
      if (Number.isFinite(trafficMonthly) && trafficMonthly > 0) {
        funnel.metrics.traffic_monthly = trafficMonthly;
      }

      if (state === "Q6_GOAL" && /\b(bookings?|leads?|contact|form|opt[\s-]?in)\b/.test(lower)) {
        funnel.signals.forms_enabled = true;
      }

      if (state === "DONE" && /\b(edit|change|revise|revision|tweak|update|another version|iterate)\b/.test(lower)) {
        funnel.metrics.edit_requests_count = Number(funnel.metrics.edit_requests_count || 0) + 1;
      }
      if (/\b(dual server|two servers|2 servers|high availability|ha setup|redundan|failover|load balanc|cloudflare load|proxmox|colo|colocation)\b/.test(lower)) {
        const upgrade = ensureUpgradeState(dependent);
        upgrade.dual_server_interest = true;
        upgrade.dual_server_offered_at = now();
        if (/\bpaypal\b/.test(lower)) upgrade.payment_preference = "paypal";
        if (/\bcrypto|bitcoin|btc|eth|usdc|usdt\b/.test(lower)) upgrade.payment_preference = "crypto";
      }

      recomputeFunnelSignals(funnel);
      funnel.last_updated_at = now();
    }

    // ===== DuckDuckGo search top URL =====
    async function searchTopUrlDuckDuckGo(query) {
      const u = new URL("https://duckduckgo.com/html/");
      u.searchParams.set("q", query);

      const r = await fetch(u.toString(), {
        headers: { "User-Agent": "Mozilla/5.0 (compatible; SitebuilderBot/1.0)" },
      });
      if (!r.ok) return null;

      const html = await r.text();
      const m = html.match(/<a[^>]+class="result__a"[^>]+href="([^"]+)"/i);
      if (!m) return null;

      let href = m[1];
      try {
        const parsed = new URL(href, "https://duckduckgo.com");
        const uddg = parsed.searchParams.get("uddg");
        if (uddg) href = decodeURIComponent(uddg);
        else href = parsed.toString();
      } catch {}

      if (!/^https?:\/\//i.test(href)) return null;
      return href;
    }

    // ===== ROUTES =====
    if (request.method === "GET" && url.pathname === "/") {
      return json({ ok: true, service: "Onboarding v8 (demo link + guided questions)", time: new Date().toISOString() });
    }

    if (request.method === "GET" && url.pathname === "/security/config") {
      return json({
        ok: true,
        turnstile_required: isTurnstileEnabled(),
        turnstile_site_key: isTurnstileEnabled() ? String(env.TURNSTILE_SITE_KEY || "") : null,
      });
    }

    if (request.method === "GET" && url.pathname === "/funnel/status") {
      if (!consumeEndpointRateLimit(clientIp, "funnel_status", now(), 60 * 1000, 120)) {
        return json({ ok: false, error: "Too many funnel status requests. Please slow down." }, 429);
      }
      const session_id = String(url.searchParams.get("session_id") || "").trim();
      if (!session_id) return json({ ok: false, error: "session_id required" }, 400);

      const loaded = await loadSessionVars(session_id, "onboarding_v8");
      if (!loaded) return json({ ok: false, error: "Unknown session_id" }, 404);
      const dependent = loaded.dependent || {};
      const summary = buildFunnelCtaActions(dependent);
      await upsertSessionVars(session_id, "onboarding_v8", loaded.independent, dependent);
      return json({
        ok: true,
        session_id,
        funnel_stage: summary.stage,
        upgrade_score: summary.score,
        funnel_signals: summary.signals,
        funnel_metrics: summary.metrics,
        cta_actions: summary.actions,
      });
    }

    if (request.method === "POST" && url.pathname === "/funnel/signal") {
      if (!consumeEndpointRateLimit(clientIp, "funnel_signal", now(), 60 * 1000, 80)) {
        return json({ ok: false, error: "Too many funnel signal updates. Please slow down." }, 429);
      }

      let body;
      try {
        body = await request.json();
      } catch {
        return json({ ok: false, error: "Invalid JSON" }, 400);
      }

      const session_id = String(body?.session_id || "").trim();
      const signal = String(body?.signal || "").trim();
      const source = String(body?.source || "api").trim().slice(0, 60) || "api";
      if (!session_id || !signal) return json({ ok: false, error: "session_id and signal required" }, 400);

      const loaded = await loadSessionVars(session_id, "onboarding_v8");
      if (!loaded) return json({ ok: false, error: "Unknown session_id" }, 404);
      const dependent = loaded.dependent || {};
      const funnel = ensureFunnelState(dependent);

      if (signal === "forms_enabled") {
        funnel.signals.forms_enabled = normalizeMaybeBool(body?.value, funnel.signals.forms_enabled) === true;
      } else if (signal === "custom_domain_requested") {
        funnel.signals.custom_domain_requested =
          normalizeMaybeBool(body?.value, funnel.signals.custom_domain_requested) === true;
      } else if (signal === "traffic_monthly") {
        const parsed = parseMetricWithSuffix(body?.value);
        if (!Number.isFinite(parsed) || parsed < 0) {
          return json({ ok: false, error: "traffic_monthly requires a non-negative number." }, 400);
        }
        funnel.metrics.traffic_monthly = parsed;
      } else if (signal === "form_submissions_monthly") {
        const parsed = parseMetricWithSuffix(body?.value);
        if (!Number.isFinite(parsed) || parsed < 0) {
          return json({ ok: false, error: "form_submissions_monthly requires a non-negative number." }, 400);
        }
        funnel.metrics.form_submissions_monthly = parsed;
      } else if (signal === "edit_request") {
        const deltaRaw = parseMetricWithSuffix(body?.value);
        const delta = Number.isFinite(deltaRaw) && deltaRaw > 0 ? deltaRaw : 1;
        funnel.metrics.edit_requests_count = Number(funnel.metrics.edit_requests_count || 0) + delta;
      } else {
        return json(
          {
            ok: false,
            error:
              'Unsupported signal. Use one of: "forms_enabled", "custom_domain_requested", "traffic_monthly", "form_submissions_monthly", "edit_request".',
          },
          400
        );
      }

      funnel.sources[signal] = source;
      funnel.last_updated_at = now();
      recomputeFunnelSignals(funnel);
      const summary = buildFunnelCtaActions(dependent);
      await upsertSessionVars(session_id, "onboarding_v8", loaded.independent, dependent);

      return json({
        ok: true,
        session_id,
        signal,
        source,
        funnel_stage: summary.stage,
        upgrade_score: summary.score,
        funnel_signals: summary.signals,
        funnel_metrics: summary.metrics,
        cta_actions: summary.actions,
      });
    }

    if (request.method === "POST" && url.pathname === "/plugin/wp/comments/moderate") {
      if (!consumeEndpointRateLimit(clientIp, "wp_comment_moderate", now(), 60 * 1000, 240)) {
        return json({ ok: false, error: "Too many moderation requests. Please slow down." }, 429);
      }

      const pluginSecret = String(env.WP_PLUGIN_SHARED_SECRET || "").trim();
      if (!pluginSecret) {
        return json({ ok: false, error: "WP plugin moderation secret is not configured." }, 503);
      }

      const tsHeader = request.headers.get("x-plugin-timestamp") || "";
      const sigHeader = request.headers.get("x-plugin-signature") || "";
      const tsMs = parseTimestampMs(tsHeader);
      if (!tsMs || Math.abs(now() - tsMs) > 5 * 60 * 1000) {
        return json({ ok: false, error: "Invalid or expired plugin timestamp." }, 401);
      }
      if (!sigHeader) return json({ ok: false, error: "Missing plugin signature." }, 401);

      const rawBody = await request.text();
      const expectedSig = await hmacSha256Hex(pluginSecret, `${tsHeader}.${rawBody}`);
      if (!safeConstantCompareHex(sigHeader, expectedSig)) {
        return json({ ok: false, error: "Invalid plugin signature." }, 401);
      }

      let body;
      try {
        body = JSON.parse(rawBody || "{}");
      } catch {
        return json({ ok: false, error: "Invalid JSON body." }, 400);
      }

      const site_url = toHttpsUrl(body?.site_url);
      const comment_id = Number(body?.comment_id || 0);
      const content = String(body?.content || "").trim();
      if (!site_url || !content || !Number.isFinite(comment_id) || comment_id <= 0) {
        return json({ ok: false, error: "site_url, comment_id, and content are required." }, 400);
      }

      const payload = {
        site_url,
        comment_id,
        content,
        author_name: String(body?.author_name || "").trim().slice(0, 120),
        author_email: String(body?.author_email || "").trim().slice(0, 180),
        author_url: toHttpsUrl(body?.author_url),
        ip: String(body?.ip || "").trim().slice(0, 80),
        user_agent: String(body?.user_agent || "").trim().slice(0, 260),
      };

      const heuristic = wpCommentHeuristicModeration(payload);
      const ai = await moderateWpCommentWithOpenAI(payload, heuristic);

      let action = heuristic.action;
      let confidence = heuristic.confidence;
      let reason = heuristic.reasons.join(", ") || "heuristic_clean";
      if (heuristic.action !== "trash" && ai) {
        const aiStrong = ai.confidence >= 0.8;
        const aiMedium = ai.confidence >= 0.65 && heuristic.score <= 3;
        if (aiStrong || aiMedium) {
          action = ai.action;
          confidence = ai.confidence;
          reason = `openai:${ai.reason}`;
        }
      }

      const statusMap = {
        keep: "approve",
        hold: "hold",
        spam: "spam",
        trash: "trash",
      };

      return json({
        ok: true,
        moderation_id: newId("mod"),
        site_url,
        comment_id,
        action,
        wp_status: statusMap[action] || "approve",
        confidence: Number(confidence.toFixed(3)),
        reason,
        heuristic: {
          action: heuristic.action,
          score: heuristic.score,
          reasons: heuristic.reasons,
        },
        ai: ai
          ? {
              action: ai.action,
              confidence: ai.confidence,
              reason: ai.reason,
            }
          : null,
      });
    }

    if (request.method === "POST" && url.pathname === "/plugin/wp/audit/sync") {
      if (!consumeEndpointRateLimit(clientIp, "wp_audit_sync", now(), 60 * 1000, 120)) {
        return json({ ok: false, error: "Too many audit sync requests. Please slow down." }, 429);
      }

      const pluginSecret = String(env.WP_PLUGIN_SHARED_SECRET || "").trim();
      if (!pluginSecret) return json({ ok: false, error: "WP plugin moderation secret is not configured." }, 503);

      const tsHeader = request.headers.get("x-plugin-timestamp") || "";
      const sigHeader = request.headers.get("x-plugin-signature") || "";
      const tsMs = parseTimestampMs(tsHeader);
      if (!tsMs || Math.abs(now() - tsMs) > 5 * 60 * 1000) {
        return json({ ok: false, error: "Invalid or expired plugin timestamp." }, 401);
      }
      if (!sigHeader) return json({ ok: false, error: "Missing plugin signature." }, 401);

      const rawBody = await request.text();
      const expectedSig = await hmacSha256Hex(pluginSecret, `${tsHeader}.${rawBody}`);
      if (!safeConstantCompareHex(sigHeader, expectedSig)) return json({ ok: false, error: "Invalid plugin signature." }, 401);

      let body;
      try {
        body = JSON.parse(rawBody || "{}");
      } catch {
        return json({ ok: false, error: "Invalid JSON body." }, 400);
      }

      const session_id = String(body?.session_id || "").trim();
      if (!session_id) return json({ ok: false, error: "session_id required." }, 400);

      const loaded = await loadSessionVars(session_id, "onboarding_v8");
      if (!loaded) return json({ ok: false, error: "Unknown session_id" }, 404);

      const parseCount = (raw) => {
        if (raw === null || raw === undefined || String(raw).trim() === "") return null;
        const parsed = parseMetricWithSuffix(raw);
        if (!Number.isFinite(parsed) || parsed < 0) return "__invalid__";
        return parsed;
      };

      const emailQueue = parseCount(body?.email_queue_count);
      const outdatedPlugins = parseCount(body?.outdated_plugin_count);
      const inactivePlugins = parseCount(body?.inactive_plugin_count);
      const redundantPlugins = parseCount(body?.redundant_plugin_count);
      const ssoPlugins = parseCount(body?.sso_plugin_count);
      const pendingComments = parseCount(body?.pending_comment_moderation_count);
      const pluginTotal = parseCount(body?.plugin_total_count);
      const activePluginCount = parseCount(body?.active_plugin_count);
      const migrationPluginCount = parseCount(body?.migration_plugin_count);
      const unneededPluginCount = parseCount(body?.unneeded_plugin_count);
      const inactiveUserDeletedCount = parseCount(body?.inactive_user_deleted_count);
      const inactiveUserCandidateCount = parseCount(body?.inactive_user_candidate_count);
      const smtpPluginCount = parseCount(body?.smtp_plugin_count);
      const pluginInventory =
        body?.plugin_inventory && typeof body.plugin_inventory === "object" ? body.plugin_inventory : null;
      if (
        emailQueue === "__invalid__" ||
        outdatedPlugins === "__invalid__" ||
        inactivePlugins === "__invalid__" ||
        redundantPlugins === "__invalid__" ||
        ssoPlugins === "__invalid__" ||
        pendingComments === "__invalid__" ||
        pluginTotal === "__invalid__" ||
        activePluginCount === "__invalid__" ||
        migrationPluginCount === "__invalid__" ||
        unneededPluginCount === "__invalid__" ||
        smtpPluginCount === "__invalid__" ||
        inactiveUserDeletedCount === "__invalid__" ||
        inactiveUserCandidateCount === "__invalid__"
      ) {
        return json({ ok: false, error: "Counts must be non-negative numbers." }, 400);
      }

      const independent = loaded.independent || {};
      const dependent = loaded.dependent || {};
      ensurePluginState(dependent);
      dependent.plugin.audit_metrics.email_queue_count = emailQueue;
      dependent.plugin.audit_metrics.outdated_plugin_count = outdatedPlugins;
      dependent.plugin.audit_metrics.inactive_plugin_count = inactivePlugins;
      dependent.plugin.audit_metrics.redundant_plugin_count = redundantPlugins;
      dependent.plugin.audit_metrics.sso_plugin_count = ssoPlugins;
      dependent.plugin.audit_metrics.pending_comment_moderation_count = pendingComments;
      dependent.plugin.audit_metrics.plugin_total_count = pluginTotal;
      dependent.plugin.audit_metrics.active_plugin_count = activePluginCount;
      dependent.plugin.audit_metrics.migration_plugin_count = migrationPluginCount;
      dependent.plugin.audit_metrics.unneeded_plugin_count = unneededPluginCount;
      dependent.plugin.audit_metrics.smtp_plugin_count = smtpPluginCount;
      dependent.plugin.audit_metrics.inactive_user_deleted_count = inactiveUserDeletedCount;
      dependent.plugin.audit_metrics.inactive_user_candidate_count = inactiveUserCandidateCount;
      dependent.plugin.audit_metrics.plugin_inventory = pluginInventory;
      dependent.plugin.audit_metrics.synced_at = now();
      dependent.plugin.audit_metrics.source = "plugin_sync";

      await upsertSessionVars(session_id, "onboarding_v8", independent, dependent);
      return json({
        ok: true,
        session_id,
        audit_metrics: dependent.plugin.audit_metrics,
      });
    }

    if (request.method === "POST" && url.pathname === "/plugin/wp/email/forward/config") {
      if (!consumeEndpointRateLimit(clientIp, "wp_email_forward_config", now(), 60 * 1000, 120)) {
        return json({ ok: false, error: "Too many email forwarding config requests. Please slow down." }, 429);
      }

      const pluginSecret = String(env.WP_PLUGIN_SHARED_SECRET || "").trim();
      if (!pluginSecret) return json({ ok: false, error: "WP plugin moderation secret is not configured." }, 503);

      const tsHeader = request.headers.get("x-plugin-timestamp") || "";
      const sigHeader = request.headers.get("x-plugin-signature") || "";
      const tsMs = parseTimestampMs(tsHeader);
      if (!tsMs || Math.abs(now() - tsMs) > 5 * 60 * 1000) {
        return json({ ok: false, error: "Invalid or expired plugin timestamp." }, 401);
      }
      if (!sigHeader) return json({ ok: false, error: "Missing plugin signature." }, 401);

      const rawBody = await request.text();
      const expectedSig = await hmacSha256Hex(pluginSecret, `${tsHeader}.${rawBody}`);
      if (!safeConstantCompareHex(sigHeader, expectedSig)) return json({ ok: false, error: "Invalid plugin signature." }, 401);

      let body;
      try {
        body = JSON.parse(rawBody || "{}");
      } catch {
        return json({ ok: false, error: "Invalid JSON body." }, 400);
      }

      const session_id = String(body?.session_id || "").trim();
      if (!session_id) return json({ ok: false, error: "session_id required." }, 400);

      const loaded = await loadSessionVars(session_id, "onboarding_v8");
      if (!loaded) return json({ ok: false, error: "Unknown session_id" }, 404);

      const forwardToEmailRaw = String(body?.forward_to_email || "").trim().toLowerCase();
      const forwardToEmail = forwardToEmailRaw && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(forwardToEmailRaw) ? forwardToEmailRaw : null;
      const hasMx = normalizeMaybeBool(body?.has_mx_records, null);
      const mxRecords = normalizeMxRecords(body?.mx_records, 20);
      const emailProviderHint = String(body?.email_provider_hint || "").trim().slice(0, 120) || null;
      const siteUrl = toHttpsUrl(body?.site_url);
      const source = String(body?.source || "plugin_sync").trim().slice(0, 80) || "plugin_sync";

      const independent = loaded.independent || {};
      const dependent = loaded.dependent || {};
      ensurePluginState(dependent);
      dependent.plugin.email_forwarding.enabled = true;
      dependent.plugin.email_forwarding.forward_to_email = forwardToEmail;
      dependent.plugin.email_forwarding.has_mx_records = hasMx;
      dependent.plugin.email_forwarding.mx_records = mxRecords;
      dependent.plugin.email_forwarding.email_provider_hint = emailProviderHint;
      dependent.plugin.email_forwarding.last_configured_at = now();
      dependent.plugin.email_forwarding.last_forward_status = source;
      if (siteUrl) dependent.plugin.email_forwarding.site_url = siteUrl;

      await upsertSessionVars(session_id, "onboarding_v8", independent, dependent);
      return json({
        ok: true,
        session_id,
        email_forwarding: {
          enabled: dependent.plugin.email_forwarding.enabled,
          forward_to_email: dependent.plugin.email_forwarding.forward_to_email,
          has_mx_records: dependent.plugin.email_forwarding.has_mx_records,
          email_provider_hint: dependent.plugin.email_forwarding.email_provider_hint,
          mx_record_count: dependent.plugin.email_forwarding.mx_records.length,
          configured_at: dependent.plugin.email_forwarding.last_configured_at,
        },
      });
    }

    if (request.method === "POST" && url.pathname === "/plugin/wp/access/profile") {
      if (!consumeEndpointRateLimit(clientIp, "wp_access_profile", now(), 60 * 1000, 120)) {
        return json({ ok: false, error: "Too many access profile requests. Please slow down." }, 429);
      }

      const pluginSecret = String(env.WP_PLUGIN_SHARED_SECRET || "").trim();
      if (!pluginSecret) return json({ ok: false, error: "WP plugin moderation secret is not configured." }, 503);

      const tsHeader = request.headers.get("x-plugin-timestamp") || "";
      const sigHeader = request.headers.get("x-plugin-signature") || "";
      const tsMs = parseTimestampMs(tsHeader);
      if (!tsMs || Math.abs(now() - tsMs) > 5 * 60 * 1000) {
        return json({ ok: false, error: "Invalid or expired plugin timestamp." }, 401);
      }
      if (!sigHeader) return json({ ok: false, error: "Missing plugin signature." }, 401);

      const rawBody = await request.text();
      const expectedSig = await hmacSha256Hex(pluginSecret, `${tsHeader}.${rawBody}`);
      if (!safeConstantCompareHex(sigHeader, expectedSig)) return json({ ok: false, error: "Invalid plugin signature." }, 401);

      let body;
      try {
        body = JSON.parse(rawBody || "{}");
      } catch {
        return json({ ok: false, error: "Invalid JSON body." }, 400);
      }

      const session_id = String(body?.session_id || "").trim();
      if (!session_id) return json({ ok: false, error: "session_id required." }, 400);

      const disallowedPasswordField = containsDisallowedPasswordField(body);
      if (disallowedPasswordField) {
        return json(
          {
            ok: false,
            error:
              `Field "${disallowedPasswordField}" is not accepted. For security, plaintext passwords are never collected or stored. ` +
              "Use scoped API tokens, SSO, and SSH public keys.",
          },
          400
        );
      }

      const loaded = await loadSessionVars(session_id, "onboarding_v8");
      if (!loaded) return json({ ok: false, error: "Unknown session_id" }, 404);

      const independent = loaded.independent || {};
      const dependent = loaded.dependent || {};
      ensurePluginState(dependent);
      const scanInfra = dependent?.scan?.latest_result?.infrastructure || {};
      const access = dependent.plugin.access_profile || {};
      access.hosting_provider = trimTo(body?.hosting_provider_name, 120) || scanInfra?.hosting_company || access.hosting_provider || null;
      access.host_login_url = normalizeMaybeUrl(body?.host_login_url) || access.host_login_url || null;
      access.control_panel_url = normalizeMaybeUrl(body?.control_panel_url) || access.control_panel_url || null;
      access.control_panel_type = trimTo(body?.control_panel_type, 80) || access.control_panel_type || null;
      access.panel_username = normalizeMaybeUsername(body?.panel_username) || access.panel_username || null;
      access.sftp_host = trimTo(body?.sftp_host, 160) || access.sftp_host || null;
      access.sftp_username = normalizeMaybeUsername(body?.sftp_username) || access.sftp_username || null;
      access.ftp_host = trimTo(body?.ftp_host, 160) || access.ftp_host || null;
      access.ftp_username = normalizeMaybeUsername(body?.ftp_username) || access.ftp_username || null;
      access.ssh_host = trimTo(body?.ssh_host, 160) || access.ssh_host || null;
      access.ssh_port = Number.isFinite(Number(body?.ssh_port))
        ? Math.max(1, Math.min(65535, Math.round(Number(body?.ssh_port))))
        : Number.isFinite(Number(access.ssh_port))
          ? access.ssh_port
          : 22;
      access.ssh_username = normalizeMaybeUsername(body?.ssh_username) || access.ssh_username || null;
      const sshPublicKey = String(body?.ssh_public_key || "").trim();
      if (sshPublicKey) {
        if (!looksLikePublicSshKey(sshPublicKey)) {
          return json({ ok: false, error: "ssh_public_key format is invalid." }, 400);
        }
        access.ssh_public_key = sshPublicKey;
        access.ssh_public_key_fingerprint = `sha256:${(await sha256Hex(sshPublicKey)).slice(0, 24)}`;
      }
      access.auth_preference = normalizeAuthPreference(body?.auth_preference || access.auth_preference);
      access.password_auth_disabled = normalizeMaybeBool(body?.disable_password_auth, access.password_auth_disabled);
      const upgrade = ensureUpgradeState(dependent);
      const managedHostingExpiry = normalizeIsoDateInput(body?.managed_hosting_expires_at);
      if (managedHostingExpiry) {
        upgrade.managed_hosting_expires_at = managedHostingExpiry;
      }
      if (access.auth_preference === "ssh_key_only" && !access.ssh_public_key) {
        return json({ ok: false, error: "ssh_public_key is required when auth_preference is ssh_key_only." }, 400);
      }
      const providerApiToken = String(body?.provider_api_token || "").trim();
      if (providerApiToken) {
        try {
          access.provider_api_token_masked = maskSecretToken(providerApiToken);
          access.provider_api_token_hash = await sha256Hex(providerApiToken);
          access.provider_api_token_cipher = await encryptSecretWithEnvKey(
            providerApiToken,
            "CREDENTIAL_VAULT_KEY",
            env.GITHUB_VAULT_KEY || env.WP_PLUGIN_SHARED_SECRET || ""
          );
        } catch (error) {
          return json({ ok: false, error: String(error?.message || "Failed to encrypt provider API token.") }, 503);
        }
      }
      access.server_hardware_hints =
        body?.server_hardware_hints && typeof body.server_hardware_hints === "object"
          ? body.server_hardware_hints
          : scanInfra?.server_hardware_hints || access.server_hardware_hints || null;
      access.notes = trimTo(body?.access_notes, 500) || access.notes || null;
      access.updated_at = now();
      access.source = String(body?.source || "plugin_sync").trim().slice(0, 80) || "plugin_sync";
      dependent.plugin.access_profile = access;
      refreshUpgradeExpirySignals(upgrade);

      await upsertSessionVars(session_id, "onboarding_v8", independent, dependent);
      return json({
        ok: true,
        session_id,
        access_profile: {
          hosting_provider: access.hosting_provider,
          panel_username: access.panel_username,
          control_panel_type: access.control_panel_type,
          auth_preference: access.auth_preference,
          password_auth_disabled: access.password_auth_disabled,
          ssh_public_key_fingerprint: access.ssh_public_key_fingerprint,
          provider_api_token_masked: access.provider_api_token_masked,
          managed_hosting_expires_at: dependent.upgrade?.managed_hosting_expires_at || null,
          days_until_managed_hosting_expiry: dependent.upgrade?.days_until_managed_hosting_expiry ?? null,
          free_vps_offer_window_days: dependent.upgrade?.free_vps_offer_window_days ?? normalizedFreeVpsOfferWindowDays(),
          free_vps_offer_eligible: Boolean(dependent.upgrade?.free_vps_offer_eligible),
          server_hardware_hints: access.server_hardware_hints,
          updated_at: access.updated_at,
        },
      });
    }

    if (request.method === "POST" && url.pathname === "/plugin/wp/lead/forward") {
      if (!consumeEndpointRateLimit(clientIp, "wp_lead_forward", now(), 60 * 1000, 240)) {
        return json({ ok: false, error: "Too many lead forward requests. Please slow down." }, 429);
      }

      const pluginSecret = String(env.WP_PLUGIN_SHARED_SECRET || "").trim();
      if (!pluginSecret) return json({ ok: false, error: "WP plugin moderation secret is not configured." }, 503);

      const tsHeader = request.headers.get("x-plugin-timestamp") || "";
      const sigHeader = request.headers.get("x-plugin-signature") || "";
      const tsMs = parseTimestampMs(tsHeader);
      if (!tsMs || Math.abs(now() - tsMs) > 5 * 60 * 1000) {
        return json({ ok: false, error: "Invalid or expired plugin timestamp." }, 401);
      }
      if (!sigHeader) return json({ ok: false, error: "Missing plugin signature." }, 401);

      const rawBody = await request.text();
      if (rawBody.length > 350_000) return json({ ok: false, error: "Lead forward payload too large." }, 413);
      const expectedSig = await hmacSha256Hex(pluginSecret, `${tsHeader}.${rawBody}`);
      if (!safeConstantCompareHex(sigHeader, expectedSig)) return json({ ok: false, error: "Invalid plugin signature." }, 401);

      let body;
      try {
        body = JSON.parse(rawBody || "{}");
      } catch {
        return json({ ok: false, error: "Invalid JSON body." }, 400);
      }

      const session_id = String(body?.session_id || "").trim();
      if (!session_id) return json({ ok: false, error: "session_id required." }, 400);

      const loaded = await loadSessionVars(session_id, "onboarding_v8");
      if (!loaded) return json({ ok: false, error: "Unknown session_id" }, 404);

      const siteUrl = toHttpsUrl(body?.site_url);
      const source = String(body?.source || "wp_mail_hook").trim().slice(0, 80) || "wp_mail_hook";
      const subject = String(body?.subject || "").trim().slice(0, 400);
      const message = String(body?.message || "").trim().slice(0, 20000);
      if (!subject && !message) return json({ ok: false, error: "subject or message required." }, 400);

      const forwardToEmailRaw = String(body?.forward_to_email || "").trim().toLowerCase();
      const requestedForwardEmail =
        forwardToEmailRaw && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(forwardToEmailRaw) ? forwardToEmailRaw : null;
      const toList = Array.isArray(body?.to) ? body.to.map((v) => String(v || "").trim()).filter(Boolean).slice(0, 20) : String(body?.to || "").trim() || null;
      const headersText = Array.isArray(body?.headers)
        ? body.headers.map((v) => String(v || "").trim()).filter(Boolean).slice(0, 40)
        : String(body?.headers || "").trim().slice(0, 4000) || null;
      const attachmentsList = Array.isArray(body?.attachments)
        ? body.attachments.map((v) => String(v || "").trim()).filter(Boolean).slice(0, 20)
        : null;
      const hasMx = normalizeMaybeBool(body?.has_mx_records, null);
      const mxRecords = normalizeMxRecords(body?.mx_records, 20);
      const emailProviderHint = String(body?.email_provider_hint || "").trim().slice(0, 120) || null;

      const independent = loaded.independent || {};
      const dependent = loaded.dependent || {};
      ensurePluginState(dependent);
      const fallbackForwardTo = String(dependent.plugin?.email_forwarding?.forward_to_email || "").trim().toLowerCase();
      const resolvedForwardTo =
        requestedForwardEmail ||
        (fallbackForwardTo && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(fallbackForwardTo) ? fallbackForwardTo : null);

      const eventId = newId("leadfwd");
      const eventDoc = {
        event_id: eventId,
        session_id,
        received_at: new Date().toISOString(),
        source,
        site_url: siteUrl || independent?.business?.own_site_url || null,
        forward_to_email: resolvedForwardTo,
        subject,
        message,
        to: toList,
        headers: headersText,
        attachments: attachmentsList,
        has_mx_records: hasMx,
        mx_records: mxRecords,
        email_provider_hint: emailProviderHint,
      };

      const bucket = convoBucket();
      let r2Key = null;
      if (bucket) {
        const safeSession = session_id.replace(/[^a-z0-9_-]/gi, "_").slice(0, 120);
        r2Key = `plugin-lead-forward/${safeSession}/${Date.now()}_${eventId}.json`;
        await bucket.put(r2Key, JSON.stringify(eventDoc, null, 2), { httpMetadata: { contentType: "application/json" } });
      }

      const webhookUrl = String(env.LEAD_FORWARD_WEBHOOK_URL || "").trim();
      const webhookSecret = String(env.LEAD_FORWARD_WEBHOOK_SECRET || "").trim();
      let webhook = { attempted: false, ok: null, status: null, error: null };
      if (webhookUrl) {
        webhook.attempted = true;
        const webhookPayload = JSON.stringify(eventDoc);
        const webhookHeaders = {
          "content-type": "application/json",
          "x-lead-forward-event-id": eventId,
        };
        if (webhookSecret) {
          const webhookTs = String(Math.floor(Date.now() / 1000));
          webhookHeaders["x-lead-forward-timestamp"] = webhookTs;
          webhookHeaders["x-lead-forward-signature"] = await hmacSha256Hex(webhookSecret, `${webhookTs}.${webhookPayload}`);
        }
        try {
          const hookRes = await fetch(webhookUrl, {
            method: "POST",
            headers: webhookHeaders,
            body: webhookPayload,
          });
          webhook.status = hookRes.status;
          webhook.ok = hookRes.status >= 200 && hookRes.status < 300;
          if (!webhook.ok) {
            webhook.error = `webhook_http_${hookRes.status}`;
          }
        } catch (error) {
          webhook.ok = false;
          webhook.error = String(error?.message || "webhook_failed");
        }
      }

      dependent.plugin.email_forwarding.enabled = true;
      dependent.plugin.email_forwarding.forward_to_email = resolvedForwardTo;
      dependent.plugin.email_forwarding.has_mx_records = hasMx;
      dependent.plugin.email_forwarding.mx_records = mxRecords;
      dependent.plugin.email_forwarding.email_provider_hint = emailProviderHint;
      dependent.plugin.email_forwarding.last_forwarded_at = now();
      dependent.plugin.email_forwarding.last_event_id = eventId;
      dependent.plugin.email_forwarding.last_r2_key = r2Key;
      dependent.plugin.email_forwarding.last_webhook_status = webhook.attempted ? webhook.status : null;
      dependent.plugin.email_forwarding.last_forward_status =
        webhook.attempted && webhook.ok === false ? "webhook_error" : "forward_event_received";
      dependent.plugin.email_forwarding.last_error = webhook.error || null;

      await upsertSessionVars(session_id, "onboarding_v8", independent, dependent);
      return json({
        ok: true,
        session_id,
        event_id: eventId,
        forward_to_email: resolvedForwardTo,
        stored_in_r2: Boolean(r2Key),
        r2_key: r2Key,
        webhook,
      });
    }

    if (request.method === "POST" && url.pathname === "/plugin/wp/schema/profile") {
      if (!consumeEndpointRateLimit(clientIp, "wp_schema_profile", now(), 60 * 1000, 120)) {
        return json({ ok: false, error: "Too many schema profile requests. Please slow down." }, 429);
      }

      const pluginSecret = String(env.WP_PLUGIN_SHARED_SECRET || "").trim();
      if (!pluginSecret) return json({ ok: false, error: "WP plugin moderation secret is not configured." }, 503);

      const tsHeader = request.headers.get("x-plugin-timestamp") || "";
      const sigHeader = request.headers.get("x-plugin-signature") || "";
      const tsMs = parseTimestampMs(tsHeader);
      if (!tsMs || Math.abs(now() - tsMs) > 5 * 60 * 1000) {
        return json({ ok: false, error: "Invalid or expired plugin timestamp." }, 401);
      }
      if (!sigHeader) return json({ ok: false, error: "Missing plugin signature." }, 401);

      const rawBody = await request.text();
      const expectedSig = await hmacSha256Hex(pluginSecret, `${tsHeader}.${rawBody}`);
      if (!safeConstantCompareHex(sigHeader, expectedSig)) return json({ ok: false, error: "Invalid plugin signature." }, 401);

      let body;
      try {
        body = JSON.parse(rawBody || "{}");
      } catch {
        return json({ ok: false, error: "Invalid JSON body." }, 400);
      }
      const session_id = String(body?.session_id || "").trim();
      if (!session_id) return json({ ok: false, error: "session_id required." }, 400);

      const loaded = await loadSessionVars(session_id, "onboarding_v8");
      if (!loaded) return json({ ok: false, error: "Unknown session_id" }, 404);
      const dependent = loaded.dependent || {};
      const profile = dependent?.schema_setup?.profile || null;
      const jsonld = dependent?.schema_setup?.jsonld || null;
      const status = dependent?.schema_setup?.status || "not_started";
      return json({
        ok: true,
        session_id,
        schema_status: status,
        schema_profile: profile,
        schema_jsonld: jsonld,
      });
    }

    if (request.method === "POST" && url.pathname === "/plugin/wp/redirects/profile") {
      if (!consumeEndpointRateLimit(clientIp, "wp_redirect_profile", now(), 60 * 1000, 120)) {
        return json({ ok: false, error: "Too many redirect profile requests. Please slow down." }, 429);
      }

      const pluginSecret = String(env.WP_PLUGIN_SHARED_SECRET || "").trim();
      if (!pluginSecret) return json({ ok: false, error: "WP plugin moderation secret is not configured." }, 503);

      const tsHeader = request.headers.get("x-plugin-timestamp") || "";
      const sigHeader = request.headers.get("x-plugin-signature") || "";
      const tsMs = parseTimestampMs(tsHeader);
      if (!tsMs || Math.abs(now() - tsMs) > 5 * 60 * 1000) {
        return json({ ok: false, error: "Invalid or expired plugin timestamp." }, 401);
      }
      if (!sigHeader) return json({ ok: false, error: "Missing plugin signature." }, 401);

      const rawBody = await request.text();
      const expectedSig = await hmacSha256Hex(pluginSecret, `${tsHeader}.${rawBody}`);
      if (!safeConstantCompareHex(sigHeader, expectedSig)) return json({ ok: false, error: "Invalid plugin signature." }, 401);

      let body;
      try {
        body = JSON.parse(rawBody || "{}");
      } catch {
        return json({ ok: false, error: "Invalid JSON body." }, 400);
      }

      const session_id = String(body?.session_id || "").trim();
      if (!session_id) return json({ ok: false, error: "session_id required." }, 400);

      const loaded = await loadSessionVars(session_id, "onboarding_v8");
      if (!loaded) return json({ ok: false, error: "Unknown session_id" }, 404);
      const linkAudit = loaded?.dependent?.scan?.latest_result?.link_audit || {};
      const rawPaths = Array.isArray(linkAudit?.broken_paths) ? linkAudit.broken_paths : [];
      const redirectPaths = Array.from(new Set(rawPaths.map((p) => normalizePathForRedirect(p)).filter(Boolean))).slice(0, 200);
      const brokenCount = Number.isFinite(Number(linkAudit?.broken_count)) ? Math.max(0, Math.round(Number(linkAudit.broken_count))) : redirectPaths.length;
      const checkedCount = Number.isFinite(Number(linkAudit?.checked_count)) ? Math.max(0, Math.round(Number(linkAudit.checked_count))) : 0;

      return json({
        ok: true,
        session_id,
        checked_link_count: checkedCount,
        broken_link_count: brokenCount,
        redirect_paths: redirectPaths,
      });
    }

    if (request.method === "POST" && url.pathname === "/plugin/wp/auth/wallet/verify") {
      if (!consumeEndpointRateLimit(clientIp, "wp_wallet_verify", now(), 60 * 1000, 80)) {
        return json({ ok: false, error: "Too many wallet verification requests. Please slow down." }, 429);
      }

      const pluginSecret = String(env.WP_PLUGIN_SHARED_SECRET || "").trim();
      if (!pluginSecret) return json({ ok: false, error: "WP plugin moderation secret is not configured." }, 503);

      const tsHeader = request.headers.get("x-plugin-timestamp") || "";
      const sigHeader = request.headers.get("x-plugin-signature") || "";
      const tsMs = parseTimestampMs(tsHeader);
      if (!tsMs || Math.abs(now() - tsMs) > 5 * 60 * 1000) {
        return json({ ok: false, error: "Invalid or expired plugin timestamp." }, 401);
      }
      if (!sigHeader) return json({ ok: false, error: "Missing plugin signature." }, 401);

      const rawBody = await request.text();
      const expectedSig = await hmacSha256Hex(pluginSecret, `${tsHeader}.${rawBody}`);
      if (!safeConstantCompareHex(sigHeader, expectedSig)) return json({ ok: false, error: "Invalid plugin signature." }, 401);

      let body;
      try {
        body = JSON.parse(rawBody || "{}");
      } catch {
        return json({ ok: false, error: "Invalid JSON body." }, 400);
      }

      const session_id = String(body?.session_id || "").trim();
      const walletAddress = String(body?.wallet_address || "").trim();
      const walletSignature = String(body?.wallet_signature || "").trim();
      const walletMessage = String(body?.wallet_message || "").trim();
      const walletNonce = String(body?.wallet_nonce || "").trim();
      const userId = Number(body?.user_id || 0);
      const userLogin = String(body?.user_login || "").trim();
      const chainId = Number(body?.wallet_chain_id || 1);
      if (!session_id) return json({ ok: false, error: "session_id required." }, 400);
      if (!walletAddress || !walletSignature || !walletMessage || !walletNonce) {
        return json({ ok: false, error: "wallet_address, wallet_signature, wallet_message, wallet_nonce required." }, 400);
      }
      if (!/0x[a-fA-F0-9]{40}/.test(walletAddress)) {
        return json({ ok: false, error: "Invalid wallet_address format." }, 400);
      }
      if (!walletMessage.includes(walletNonce)) {
        return json({ ok: false, error: "Wallet challenge nonce mismatch." }, 400);
      }

      const loaded = await loadSessionVars(session_id, "onboarding_v8");
      if (!loaded) return json({ ok: false, error: "Unknown session_id" }, 404);

      const verify = await verifyWalletSignatureWithGateway({
        session_id,
        site_url: toHttpsUrl(body?.site_url),
        wallet_address: walletAddress,
        wallet_signature: walletSignature,
        wallet_message: walletMessage,
        wallet_nonce: walletNonce,
        wallet_chain_id: Number.isFinite(chainId) ? chainId : 1,
        user_id: Number.isFinite(userId) ? userId : null,
        user_login: userLogin || null,
        user_email: String(body?.user_email || "").trim() || null,
      });
      if (!verify.ok || !verify.verified) {
        const errorText = verify.error || "Wallet signature not verified.";
        return json({ ok: false, verified: false, error: errorText }, 400);
      }

      const independent = loaded.independent || {};
      const dependent = loaded.dependent || {};
      ensurePluginState(dependent);
      dependent.plugin.wallet_auth.enabled = true;
      dependent.plugin.wallet_auth.last_verified_at = now();
      dependent.plugin.wallet_auth.wallet_address = verify.wallet_address || walletAddress;
      dependent.plugin.wallet_auth.chain_id = Number.isFinite(chainId) ? chainId : 1;
      dependent.plugin.wallet_auth.user_id = Number.isFinite(userId) && userId > 0 ? userId : null;
      dependent.plugin.wallet_auth.user_login = userLogin || null;
      dependent.plugin.wallet_auth.last_status = "verified";
      dependent.plugin.wallet_auth.last_error = null;
      await upsertSessionVars(session_id, "onboarding_v8", independent, dependent);

      return json({
        ok: true,
        verified: true,
        session_id,
        wallet_address: dependent.plugin.wallet_auth.wallet_address,
        chain_id: dependent.plugin.wallet_auth.chain_id,
        source: verify.source || "wallet_verify_webhook",
      });
    }

    if (request.method === "POST" && url.pathname === "/plugin/wp/github/vault") {
      if (!consumeEndpointRateLimit(clientIp, "wp_github_vault", now(), 60 * 1000, 60)) {
        return json({ ok: false, error: "Too many GitHub vault requests. Please slow down." }, 429);
      }

      const pluginSecret = String(env.WP_PLUGIN_SHARED_SECRET || "").trim();
      if (!pluginSecret) return json({ ok: false, error: "WP plugin moderation secret is not configured." }, 503);

      const tsHeader = request.headers.get("x-plugin-timestamp") || "";
      const sigHeader = request.headers.get("x-plugin-signature") || "";
      const tsMs = parseTimestampMs(tsHeader);
      if (!tsMs || Math.abs(now() - tsMs) > 5 * 60 * 1000) {
        return json({ ok: false, error: "Invalid or expired plugin timestamp." }, 401);
      }
      if (!sigHeader) return json({ ok: false, error: "Missing plugin signature." }, 401);

      const rawBody = await request.text();
      const expectedSig = await hmacSha256Hex(pluginSecret, `${tsHeader}.${rawBody}`);
      if (!safeConstantCompareHex(sigHeader, expectedSig)) return json({ ok: false, error: "Invalid plugin signature." }, 401);

      let body;
      try {
        body = JSON.parse(rawBody || "{}");
      } catch {
        return json({ ok: false, error: "Invalid JSON body." }, 400);
      }

      const session_id = String(body?.session_id || "").trim();
      const githubToken = String(body?.github_token || "").trim();
      const parsedRepo = parseGitHubRepoSlug(body?.github_repo);
      const githubBranch = String(body?.github_branch || "main").trim() || "main";
      if (!session_id) return json({ ok: false, error: "session_id required." }, 400);
      if (!githubToken) return json({ ok: false, error: "github_token required." }, 400);
      if (!parsedRepo) return json({ ok: false, error: "github_repo must be owner/repo." }, 400);

      const loaded = await loadSessionVars(session_id, "onboarding_v8");
      if (!loaded) return json({ ok: false, error: "Unknown session_id" }, 404);

      const verification = await verifyGitHubToken(githubToken);
      if (!verification.ok) return json({ ok: false, error: verification.error || "GitHub token verification failed." }, 400);

      let tokenCipher = null;
      try {
        tokenCipher = await encryptSecretForVault(githubToken);
      } catch (error) {
        return json({ ok: false, error: String(error?.message || "Failed to encrypt GitHub token.") }, 503);
      }

      const independent = loaded.independent || {};
      const dependent = loaded.dependent || {};
      ensurePluginState(dependent);
      dependent.plugin.github_vault.connected = true;
      dependent.plugin.github_vault.repo_slug = parsedRepo.slug;
      dependent.plugin.github_vault.owner = parsedRepo.owner;
      dependent.plugin.github_vault.repo = parsedRepo.repo;
      dependent.plugin.github_vault.branch = githubBranch;
      dependent.plugin.github_vault.token_masked = maskSecretToken(githubToken);
      dependent.plugin.github_vault.token_hash = await sha256Hex(githubToken);
      dependent.plugin.github_vault.token_cipher = tokenCipher;
      dependent.plugin.github_vault.github_user = verification.login || null;
      dependent.plugin.github_vault.connected_at = now();
      dependent.plugin.github_backup_opt_in = true;
      dependent.plugin.connect.github_connected = true;
      dependent.plugin.connect.github_repo = parsedRepo.slug;

      await upsertSessionVars(session_id, "onboarding_v8", independent, dependent);
      return json({
        ok: true,
        session_id,
        github_repo: parsedRepo.slug,
        github_branch: githubBranch,
        github_user: verification.login || null,
        token_masked: dependent.plugin.github_vault.token_masked,
        connected_at: dependent.plugin.github_vault.connected_at,
      });
    }

    if (request.method === "POST" && url.pathname === "/plugin/wp/backup/snapshot") {
      if (!consumeEndpointRateLimit(clientIp, "wp_backup_snapshot", now(), 60 * 1000, 30)) {
        return json({ ok: false, error: "Too many backup snapshot requests. Please slow down." }, 429);
      }

      const pluginSecret = String(env.WP_PLUGIN_SHARED_SECRET || "").trim();
      if (!pluginSecret) return json({ ok: false, error: "WP plugin moderation secret is not configured." }, 503);

      const tsHeader = request.headers.get("x-plugin-timestamp") || "";
      const sigHeader = request.headers.get("x-plugin-signature") || "";
      const tsMs = parseTimestampMs(tsHeader);
      if (!tsMs || Math.abs(now() - tsMs) > 5 * 60 * 1000) {
        return json({ ok: false, error: "Invalid or expired plugin timestamp." }, 401);
      }
      if (!sigHeader) return json({ ok: false, error: "Missing plugin signature." }, 401);

      const rawBody = await request.text();
      if (rawBody.length > 2_000_000) {
        return json({ ok: false, error: "Snapshot payload too large." }, 413);
      }
      const expectedSig = await hmacSha256Hex(pluginSecret, `${tsHeader}.${rawBody}`);
      if (!safeConstantCompareHex(sigHeader, expectedSig)) return json({ ok: false, error: "Invalid plugin signature." }, 401);

      let body;
      try {
        body = JSON.parse(rawBody || "{}");
      } catch {
        return json({ ok: false, error: "Invalid JSON body." }, 400);
      }

      const session_id = String(body?.session_id || "").trim();
      const siteUrl = toHttpsUrl(body?.site_url);
      const parsedRepo = parseGitHubRepoSlug(body?.github_repo);
      const snapshot = body?.snapshot && typeof body.snapshot === "object" ? body.snapshot : null;
      const snapshotFiles = Array.isArray(snapshot?.files) ? snapshot.files.slice(0, 12000) : [];
      if (!session_id) return json({ ok: false, error: "session_id required." }, 400);
      if (!snapshot || !snapshotFiles.length) return json({ ok: false, error: "snapshot.files required." }, 400);

      const loaded = await loadSessionVars(session_id, "onboarding_v8");
      if (!loaded) return json({ ok: false, error: "Unknown session_id" }, 404);

      const independent = loaded.independent || {};
      const dependent = loaded.dependent || {};
      ensurePluginState(dependent);

      const generatedAt = String(snapshot?.generated_at || new Date().toISOString());
      const host = (() => {
        try {
          return new URL(siteUrl || independent?.business?.own_site_url || "https://unknown.local").hostname || "unknown-site";
        } catch {
          return "unknown-site";
        }
      })();
      const safeHost = host.replace(/[^a-z0-9.-]/gi, "-").toLowerCase();
      const snapshotDoc = {
        session_id,
        site_url: siteUrl || independent?.business?.own_site_url || null,
        generated_at: generatedAt,
        received_at: new Date().toISOString(),
        files_count: snapshotFiles.length,
        truncated: Boolean(snapshot?.truncated),
        scanned_files: Number(snapshot?.scanned_files || snapshotFiles.length),
        manifest_count: Number(snapshot?.manifest_count || snapshotFiles.length),
        files: snapshotFiles,
      };

      const bucket = convoBucket();
      let r2Key = null;
      if (bucket) {
        r2Key = `plugin-backups/${session_id}/${Date.now()}_${safeHost}.json`;
        const snapshotText = JSON.stringify(snapshotDoc, null, 2);
        await bucket.put(r2Key, snapshotText, { httpMetadata: { contentType: "application/json" } });
      }

      let githubPush = null;
      let githubError = null;
      if (dependent?.plugin?.github_vault?.connected && dependent?.plugin?.github_vault?.token_cipher) {
        const repo = parsedRepo || parseGitHubRepoSlug(dependent.plugin.github_vault.repo_slug);
        if (repo) {
          try {
            const token = await decryptSecretFromVault(dependent.plugin.github_vault.token_cipher);
            const datePart = new Date().toISOString().slice(0, 10);
            const path = `sitebuilder-backups/${safeHost}/${datePart}/${Date.now()}.json`;
            const branch = String(body?.github_branch || dependent.plugin.github_vault.branch || "main").trim() || "main";
            githubPush = await pushSnapshotToGitHub(
              token,
              repo,
              path,
              JSON.stringify(snapshotDoc, null, 2),
              `chore: snapshot backup ${safeHost} ${generatedAt}`,
              branch
            );
            if (!githubPush?.ok) {
              githubError = githubPush?.error || "GitHub backup failed.";
            }
          } catch (error) {
            githubError = String(error?.message || error || "GitHub backup failed.");
          }
        } else {
          githubError = "GitHub repo not configured.";
        }
      } else {
        githubError = "GitHub vault token not connected.";
      }

      dependent.plugin.backup.last_snapshot_at = now();
      dependent.plugin.backup.last_snapshot_key = r2Key;
      dependent.plugin.backup.last_snapshot_status = "ok";
      dependent.plugin.backup.last_github_path = githubPush?.content_path || null;
      dependent.plugin.backup.last_github_status = githubPush?.ok ? "ok" : "error";
      dependent.plugin.backup.last_error = githubError;
      await upsertSessionVars(session_id, "onboarding_v8", independent, dependent);

      return json({
        ok: true,
        session_id,
        message: githubPush?.ok
          ? "Snapshot saved to Cloudflare and pushed to GitHub."
          : "Snapshot saved to Cloudflare; GitHub push unavailable.",
        r2_key: r2Key,
        github: githubPush?.ok
          ? {
              ok: true,
              path: githubPush.content_path,
              commit_sha: githubPush.commit_sha || null,
            }
          : {
              ok: false,
              error: githubError || "GitHub push unavailable.",
            },
      });
    }

    if (request.method === "POST" && url.pathname === "/plugin/connect/start") {
      if (!consumeEndpointRateLimit(clientIp, "plugin_connect_start", now(), 60 * 1000, 30)) {
        return json({ ok: false, error: "Too many plugin connect requests. Please slow down." }, 429);
      }
      let body;
      try {
        body = await request.json();
      } catch {
        return json({ ok: false, error: "Invalid JSON" }, 400);
      }

      const session_id = String(body?.session_id || "").trim();
      if (!session_id) return json({ ok: false, error: "session_id required" }, 400);
      const loaded = await loadSessionVars(session_id, "onboarding_v8");
      if (!loaded) return json({ ok: false, error: "Unknown session_id" }, 404);

      const independent = loaded.independent || {};
      const dependent = loaded.dependent || {};
      ensurePluginState(dependent);
      ensureFunnelState(dependent);
      const platform = String(independent?.business?.site_platform || dependent?.scan?.platform_hint || "").toLowerCase();
      if (platform !== "wordpress") {
        return json({ ok: false, error: "Plugin onboarding is currently available for WordPress sites only." }, 400);
      }

      const connect_id = newId("plg");
      dependent.plugin.detected_platform = "wordpress";
      dependent.plugin.connect.pending_connect_id = connect_id;
      dependent.plugin.connect.status = "pending";
      dependent.plugin.connect.connected_at = null;
      dependent.plugin.free_tier_requires_tolldns = true;
      dependent.plugin.wordpress_offer_shown = true;
      const summary = buildFunnelCtaActions(dependent);
      await upsertSessionVars(session_id, "onboarding_v8", independent, dependent);

      return json({
        ok: true,
        session_id,
        connect_id,
        requirements: {
          tolldns_required_for_free: true,
          github_optional_for_backups: true,
          scoped_cloudflare_token_required: true,
        },
        guidance:
          "Install TollDNS first for the free plugin tier. Then connect a scoped Cloudflare API token. " +
          "Optional: connect GitHub so AI workers can create sandbox backups before update operations. " +
          "For access credentials, use SSO/API tokens/SSH public keys only (no plaintext passwords).",
        cta_actions: summary.actions,
      });
    }

    if (request.method === "POST" && url.pathname === "/plugin/connect/verify") {
      if (!consumeEndpointRateLimit(clientIp, "plugin_connect_verify", now(), 60 * 1000, 30)) {
        return json({ ok: false, error: "Too many plugin verification requests. Please slow down." }, 429);
      }
      let body;
      try {
        body = await request.json();
      } catch {
        return json({ ok: false, error: "Invalid JSON" }, 400);
      }

      const session_id = String(body?.session_id || "").trim();
      const connect_id = String(body?.connect_id || "").trim();
      const account_id = String(body?.cloudflare_account_id || "").trim();
      const api_token = String(body?.api_token || "").trim();
      const tolldns_installed = normalizeMaybeBool(body?.tolldns_installed, null);
      const github_connected = normalizeMaybeBool(body?.github_connected, false) === true;
      const github_repo = String(body?.github_repo || "").trim() || null;
      const disallowedPasswordField = containsDisallowedPasswordField(body);
      if (disallowedPasswordField) {
        return json(
          {
            ok: false,
            error:
              `Field "${disallowedPasswordField}" is not accepted. For security, plaintext passwords are never collected or stored. ` +
              "Use scoped API tokens, SSO, and SSH public keys.",
          },
          400
        );
      }
      if (!session_id || !connect_id) return json({ ok: false, error: "session_id and connect_id required" }, 400);

      const loaded = await loadSessionVars(session_id, "onboarding_v8");
      if (!loaded) return json({ ok: false, error: "Unknown session_id" }, 404);

      const independent = loaded.independent || {};
      const dependent = loaded.dependent || {};
      ensurePluginState(dependent);
      ensureFunnelState(dependent);
      if (dependent.plugin.connect.pending_connect_id !== connect_id) {
        return json({ ok: false, error: "Invalid or expired connect_id." }, 400);
      }
      if (tolldns_installed !== true) {
        return json(
          {
            ok: false,
            error: "TollDNS installation is required for the free plugin tier.",
            requirement: "install_tolldns_required",
          },
          400
        );
      }
      if (!api_token) return json({ ok: false, error: "Cloudflare API token is required." }, 400);

      const verification = await verifyCloudflareApiTokenWithCloudflare(api_token);
      if (!verification.ok) return json({ ok: false, error: verification.error || "Cloudflare token verification failed." }, 400);

      const token_hash = await sha256Hex(api_token);
      const scanInfra = dependent?.scan?.latest_result?.infrastructure || {};
      const access = dependent.plugin.access_profile || {};
      access.hosting_provider = trimTo(body?.hosting_provider_name, 120) || scanInfra?.hosting_company || null;
      access.host_login_url = normalizeMaybeUrl(body?.host_login_url);
      access.control_panel_url = normalizeMaybeUrl(body?.control_panel_url);
      access.control_panel_type = trimTo(body?.control_panel_type, 80);
      access.panel_username = normalizeMaybeUsername(body?.panel_username);
      access.sftp_host = trimTo(body?.sftp_host, 160);
      access.sftp_username = normalizeMaybeUsername(body?.sftp_username);
      access.ftp_host = trimTo(body?.ftp_host, 160);
      access.ftp_username = normalizeMaybeUsername(body?.ftp_username);
      access.ssh_host = trimTo(body?.ssh_host, 160);
      access.ssh_port = Number.isFinite(Number(body?.ssh_port)) ? Math.max(1, Math.min(65535, Math.round(Number(body?.ssh_port)))) : 22;
      access.ssh_username = normalizeMaybeUsername(body?.ssh_username);
      const sshPublicKey = String(body?.ssh_public_key || "").trim();
      if (sshPublicKey && !looksLikePublicSshKey(sshPublicKey)) {
        return json({ ok: false, error: "ssh_public_key format is invalid." }, 400);
      }
      access.ssh_public_key = sshPublicKey || null;
      access.ssh_public_key_fingerprint = sshPublicKey ? `sha256:${(await sha256Hex(sshPublicKey)).slice(0, 24)}` : null;
      access.auth_preference = normalizeAuthPreference(body?.auth_preference);
      access.password_auth_disabled = normalizeMaybeBool(body?.disable_password_auth, null);
      const managedHostingExpiry = normalizeIsoDateInput(body?.managed_hosting_expires_at);
      const upgrade = ensureUpgradeState(dependent);
      if (managedHostingExpiry) {
        upgrade.managed_hosting_expires_at = managedHostingExpiry;
      }
      if (access.auth_preference === "ssh_key_only" && !access.ssh_public_key) {
        return json({ ok: false, error: "ssh_public_key is required when auth_preference is ssh_key_only." }, 400);
      }
      const providerApiToken = String(body?.provider_api_token || "").trim();
      if (providerApiToken) {
        try {
          const vaultKey = String(env.CREDENTIAL_VAULT_KEY || env.GITHUB_VAULT_KEY || env.WP_PLUGIN_SHARED_SECRET || "").trim();
          if (!vaultKey) {
            return json({ ok: false, error: "Credential vault key is not configured." }, 503);
          }
          access.provider_api_token_masked = maskSecretToken(providerApiToken);
          access.provider_api_token_hash = await sha256Hex(providerApiToken);
          access.provider_api_token_cipher = await encryptSecretWithEnvKey(
            providerApiToken,
            "CREDENTIAL_VAULT_KEY",
            env.GITHUB_VAULT_KEY || env.WP_PLUGIN_SHARED_SECRET || ""
          );
        } catch (error) {
          return json({ ok: false, error: String(error?.message || "Failed to encrypt provider API token.") }, 503);
        }
      }
      access.server_hardware_hints = body?.server_hardware_hints && typeof body.server_hardware_hints === "object"
        ? body.server_hardware_hints
        : scanInfra?.server_hardware_hints || access.server_hardware_hints || null;
      access.notes = trimTo(body?.access_notes, 500);
      access.updated_at = now();
      access.source = "plugin_connect_verify";
      refreshUpgradeExpirySignals(upgrade);

      dependent.plugin.connect.status = "connected";
      dependent.plugin.connect.pending_connect_id = null;
      dependent.plugin.connect.cf_account_id = account_id || null;
      dependent.plugin.connect.token_masked = maskSecretToken(api_token);
      dependent.plugin.connect.token_hash = token_hash;
      dependent.plugin.connect.token_verified = true;
      dependent.plugin.connect.tolldns_installed = true;
      dependent.plugin.connect.github_connected = github_connected;
      dependent.plugin.connect.github_repo = github_repo;
      dependent.plugin.connect.connected_at = now();
      dependent.plugin.github_backup_opt_in = github_connected;
      dependent.plugin.detected_platform = "wordpress";
      dependent.plugin.access_profile = access;

      // Connected plugin implies forms/watchdogs can be enabled.
      dependent.funnel.signals.forms_enabled = true;
      dependent.funnel.last_updated_at = now();
      recomputeFunnelSignals(dependent.funnel);
      const summary = buildFunnelCtaActions(dependent);
      await upsertSessionVars(session_id, "onboarding_v8", independent, dependent);

      return json({
        ok: true,
        session_id,
        plugin_connection: {
          status: dependent.plugin.connect.status,
          token_masked: dependent.plugin.connect.token_masked,
          token_verified: dependent.plugin.connect.token_verified,
          tolldns_installed: dependent.plugin.connect.tolldns_installed,
          github_connected: dependent.plugin.connect.github_connected,
          github_repo: dependent.plugin.connect.github_repo,
          connected_at: dependent.plugin.connect.connected_at,
        },
        access_profile: {
          hosting_provider: dependent.plugin.access_profile.hosting_provider,
          panel_username: dependent.plugin.access_profile.panel_username,
          control_panel_type: dependent.plugin.access_profile.control_panel_type,
          auth_preference: dependent.plugin.access_profile.auth_preference,
          password_auth_disabled: dependent.plugin.access_profile.password_auth_disabled,
          ssh_public_key_fingerprint: dependent.plugin.access_profile.ssh_public_key_fingerprint,
          server_hardware_hints: dependent.plugin.access_profile.server_hardware_hints,
          managed_hosting_expires_at: dependent.upgrade?.managed_hosting_expires_at || null,
          days_until_managed_hosting_expiry: dependent.upgrade?.days_until_managed_hosting_expiry ?? null,
          free_vps_offer_window_days: dependent.upgrade?.free_vps_offer_window_days ?? normalizedFreeVpsOfferWindowDays(),
          free_vps_offer_eligible: Boolean(dependent.upgrade?.free_vps_offer_eligible),
          updated_at: dependent.plugin.access_profile.updated_at,
        },
        funnel_stage: summary.stage,
        upgrade_score: summary.score,
        cta_actions: summary.actions,
      });
    }

    if (request.method === "GET" && url.pathname === "/q1/scan/status") {
      if (!consumeEndpointRateLimit(clientIp, "scan_status", now(), 60 * 1000, 120)) {
        return json({ ok: false, error: "Too many status checks. Please slow down." }, 429);
      }
      const session_id = String(url.searchParams.get("session_id") || "").trim();
      if (!session_id) return json({ ok: false, error: "session_id required" }, 400);

      const loaded = await loadSessionVars(session_id, "onboarding_v8");
      if (!loaded) return json({ ok: false, error: "Unknown session_id" }, 404);

      try {
        const statusPayload = await fetchScanStatus(session_id);
        const result = statusPayload?.result || null;
        if (result) {
          loaded.dependent.scan = loaded.dependent.scan || {};
          loaded.dependent.scan.latest_summary = summarizeScan(result);
          loaded.dependent.scan.latest_result = result;
          applyScanResultToSession(loaded.independent, loaded.dependent, result);
          await upsertSessionVars(session_id, "onboarding_v8", loaded.independent, loaded.dependent);
        }
        return json({ ok: true, session_id, ...statusPayload });
      } catch (error) {
        return json({ ok: false, error: String(error?.message || error) }, 502);
      }
    }

    if (request.method === "POST" && url.pathname === "/q1/scan/start") {
      if (!consumeEndpointRateLimit(clientIp, "scan_start", now(), 60 * 1000, 20)) {
        return json({ ok: false, error: "Too many scan requests. Please wait and try again." }, 429);
      }
      let body;
      try {
        body = await request.json();
      } catch {
        return json({ ok: false, error: "Invalid JSON" }, 400);
      }

      const session_id = String(body?.session_id || "").trim();
      const urlInput = toHttpsUrl(body?.url);
      if (!session_id) return json({ ok: false, error: "session_id required" }, 400);

      const loaded = await loadSessionVars(session_id, "onboarding_v8");
      if (!loaded) return json({ ok: false, error: "Unknown session_id" }, 404);
      {
        const denied = ensureExpensiveActionAllowed(loaded.dependent);
        if (denied) return denied;
      }

      const targetUrl = urlInput || bestScanTarget(loaded.independent);
      if (!targetUrl) return json({ ok: false, error: "No site URL available to scan" }, 400);

      try {
        const started = await startSiteScan(session_id, targetUrl);
        loaded.independent.business.wants_site_scan = true;
        loaded.independent.business.own_site_url = targetUrl;
        loaded.dependent.scan = {
          status: started.status || "running",
          request_id: started.request_id || null,
          latest_summary: summarizeScan(started.result || null),
          latest_result: started.result || null,
        };
        if (started?.result) {
          applyScanResultToSession(loaded.independent, loaded.dependent, started.result);
        }
        await upsertSessionVars(session_id, "onboarding_v8", loaded.independent, loaded.dependent);
        return json({ ok: true, session_id, target_url: targetUrl, scan: started });
      } catch (error) {
        return json({ ok: false, error: String(error?.message || error) }, 502);
      }
    }

    // START
    if (request.method === "POST" && url.pathname === "/q1/start") {
      let body;
      try {
        body = await request.json();
      } catch {
        return json({ ok: false, error: "Invalid JSON" }, 400);
      }

      if (!consumeStartRateLimit(clientIp, now())) {
        return json(
          {
            ok: false,
            error: "Too many start attempts from your IP. Please wait a minute and try again.",
          },
          429
        );
      }

      const verification = await verifyTurnstileToken(body?.turnstile_token, "start");
      if (!verification.ok) {
        return json({ ok: false, error: verification.error || "Security verification failed." }, 403);
      }

      const first_name = cleanHumanName(body?.FirstName || body?.first_name);
      const last_name = cleanHumanName(body?.LastName || body?.last_name);

      const firstCheck = analyzeHumanName(first_name, "FirstName", 2);
      if (!firstCheck.ok) return json({ ok: false, error: firstCheck.error }, 400);
      const lastCheck = analyzeHumanName(last_name, "LastName", 4);
      if (!lastCheck.ok) return json({ ok: false, error: lastCheck.error }, 400);

      const user_id = newId("usr");
      const session_id = newId("ses");
      const session_created_at = now();
      const clientGeo = readClientGeo(request);

      await insertUserRow(user_id, first_name, session_created_at);
      await insertSessionRow(session_id, user_id, session_created_at);

      const independent = {
        session_created_at,
        person: { first_name, last_name, geo: clientGeo },

        business: {
          description_raw: null,
          type_final: null,
          own_site_url: null,
          own_site_confirmed: null,
          site_platform: null,
          is_wordpress: false,
          happy_with_site_and_cost: null,

          spend_raw: null,
          spend_amount: null,
          spend_period: "unknown",

          wants_free_trial_build: null,
          wants_site_scan: null,
            tech_profile: {
              registrar: null,
              nameservers: [],
              ip_addresses: [],
              hosting_company: null,
              domain_expires_at: null,
              email_provider: null,
              third_party_vendors: {},
              server_hardware_hints: null,
              broken_links: { checked_count: 0, broken_count: 0, broken_paths: [] },
              last_scanned_at: null,
            },
        },

        demo: {
          last_demo_url: null,
          q1_vibe: null,
          q2_colors: null,
          q3_layout: null,
        },

        build: {
          business_name: null,
          website_guess: null,
          location_mode: null,
          address: null,
          service_area: null,
          vibe: null,
          colors: null,
          goal: null,
          phone: null,
          email: null,
        },

        style: { willing_to_view_examples: null },
      };

      const dependent = {
        draft: { type_guess: null, type_candidates: [], type_source: null },
        flow: { expected_state: "Q1_DESCRIBE", audit_requested: false },
        name_proposals: [],
        scan: {
          status: null,
          request_id: null,
          latest_summary: null,
        },
        research: {
          location_hint: geoToLocationText(clientGeo),
          intent_text: null,
          intent_raw: null,
          intent_draft: null,
          intent_source: null,
          sites: [],
          source: null,
          current_site_index: 0,
          refresh_count: 0,
        },
        design: {
          liked: [],
          disliked: [],
          palette_hints: [],
          layout_hints: [],
          font_hints: [],
          raw_feedback: [],
        },
        demo_build: {
          key: null,
          url: null,
        },
        followup: {
          requested: false,
          channel: null,
          timeframe: null,
          email: null,
          requested_at: null,
          audit_report_email_opt_in: null,
          domain_expiry_reminder_opt_in: null,
          audit_email_opted_at: null,
          audit_email_optin_source: null,
        },
        schema_setup: {
          profile: null,
          jsonld: null,
          status: "not_started",
          pending_return_state: null,
          last_updated_at: null,
        },
        plugin: {
          wordpress_offer_shown: false,
          wordpress_audit_completed: false,
          wordpress_audit_summary: null,
          audit_metrics: {
            email_queue_count: null,
            outdated_plugin_count: null,
            inactive_plugin_count: null,
            redundant_plugin_count: null,
            sso_plugin_count: null,
            pending_comment_moderation_count: null,
            synced_at: null,
            source: null,
          },
          free_tier_requires_tolldns: true,
          github_backup_opt_in: false,
          connect: {
            pending_connect_id: null,
            status: "not_started",
            cf_account_id: null,
            token_masked: null,
            token_hash: null,
            token_verified: false,
            tolldns_installed: false,
            github_connected: false,
            github_repo: null,
            connected_at: null,
          },
          access_profile: {
            hosting_provider: null,
            host_login_url: null,
            control_panel_url: null,
            control_panel_type: null,
            panel_username: null,
            sftp_host: null,
            sftp_username: null,
            ftp_host: null,
            ftp_username: null,
            ssh_host: null,
            ssh_port: 22,
            ssh_username: null,
            ssh_public_key: null,
            ssh_public_key_fingerprint: null,
            auth_preference: "token_or_ssh_key",
            password_auth_disabled: null,
            provider_api_token_masked: null,
            provider_api_token_hash: null,
            provider_api_token_cipher: null,
            server_hardware_hints: null,
            notes: null,
            updated_at: null,
            source: null,
          },
        },
        funnel: {
          signals: {
            forms_enabled: false,
            traffic_over_threshold: false,
            multiple_edits: false,
            custom_domain_requested: false,
          },
          metrics: {
            edit_requests_count: 0,
            traffic_monthly: null,
            traffic_threshold: normalizedUpgradeTrafficThreshold(),
            form_submissions_monthly: null,
          },
          ctas: {
            connect_cloudflare_url: String(env.CONNECT_CLOUDFLARE_URL || "").trim() || null,
            migrate_hosting_url: String(env.MIGRATE_HOSTING_URL || "").trim() || null,
          },
          sources: {},
          last_updated_at: now(),
        },
        upgrade: {
          dual_server_interest: false,
          dual_server_offered_at: null,
          payment_preference: null,
          domain_expiry_at: null,
          days_until_domain_expiry: null,
          managed_hosting_expires_at: null,
          days_until_managed_hosting_expiry: null,
          free_vps_offer_window_days: normalizedFreeVpsOfferWindowDays(),
          free_vps_offer_eligible: false,
          free_vps_offer_reason: null,
          last_evaluated_at: null,
        },
        security: {
          turnstile_enabled: isTurnstileEnabled(),
          turnstile_verified: verification.ok,
          verified_at: verification.ok ? now() : null,
          verified_ip: clientIp,
          verified_action: verification?.action || "start",
          verified_hostname: verification?.hostname || null,
        },
      };

      await upsertSessionVars(session_id, "onboarding_v8", independent, dependent);

      const prompt = `Hello ${first_name} ${last_name}, Could you please describe your business to me briefly?`;

      const t = await nextTurnId(env.DB, session_id);
      await logEvent(env.DB, session_id, t, "assistant", "Q1_DESCRIBE", prompt);
      await flushSessionToR2(env.DB, session_id, session_created_at);

      return json({ ok: true, user_id, session_id, next_state: "Q1_DESCRIBE", prompt });
    }

    // ANSWER
    if (request.method === "POST" && url.pathname === "/q1/answer") {
      if (!consumeEndpointRateLimit(clientIp, "q1_answer", now(), 60 * 1000, 120)) {
        return json({ ok: false, error: "Too many messages too quickly. Please slow down a bit." }, 429);
      }
      let body;
      try {
        body = await request.json();
      } catch {
        return json({ ok: false, error: "Invalid JSON" }, 400);
      }

      const session_id = String(body?.session_id || "").trim();
      const state = String(body?.state || "").trim();
      const answer = body?.answer;
      const answerText = String(answer ?? "").trim();

      if (!session_id || !state) return json({ ok: false, error: "session_id and state required" }, 400);
      if (answerText.length > MAX_ANSWER_CHARS) {
        return json({ ok: false, error: `Answer too long (${MAX_ANSWER_CHARS} chars max).` }, 400);
      }

      const loaded = await loadSessionVars(session_id, "onboarding_v8");
      if (!loaded) return json({ ok: false, error: "Unknown session_id" }, 404);

      const independent = loaded.independent;
      const dependent = loaded.dependent;
      ensureFunnelState(dependent);
      ensurePluginState(dependent);
      ensureFollowupState(dependent);
      dependent.security = dependent.security || {
        turnstile_enabled: isTurnstileEnabled(),
        turnstile_verified: !isTurnstileEnabled(),
        verified_at: null,
        verified_ip: null,
        verified_action: null,
        verified_hostname: null,
      };
      if (!isTurnstileEnabled()) {
        dependent.security.turnstile_enabled = false;
        dependent.security.turnstile_verified = true;
      } else if (dependent.security.turnstile_verified !== true) {
        dependent.security.turnstile_enabled = true;
        dependent.security.turnstile_verified = false;
      }
      dependent.flow = dependent.flow || {};
      if (typeof dependent.flow.audit_requested !== "boolean") dependent.flow.audit_requested = false;
      const session_created_at = independent?.session_created_at || now();
      const expectedState = dependent?.flow?.expected_state || null;

      if (expectedState && state !== expectedState) {
        const recovered = staleStateRecovery(expectedState, state, independent);
        if (recovered) {
          return json({ ...recovered, recovered_from_state: state, expected_state: expectedState });
        }

        return json(
          {
            ok: false,
            error: `Unexpected state. Expected "${expectedState}" but got "${state}".`,
            expected_state: expectedState,
          },
          409
        );
      }

      // log USER
      const userTurn = await nextTurnId(env.DB, session_id);
      await logEvent(env.DB, session_id, userTurn, "user", state, answerText);
      applyAnswerToFunnelSignals(state, answerText, dependent);

      const reply = async (obj) => {
        if (obj.next_state) {
          dependent.flow = dependent.flow || {};
          dependent.flow.expected_state = obj.next_state;
        }
        await upsertSessionVars(session_id, "onboarding_v8", independent, dependent);

        const assistantTurn = await nextTurnId(env.DB, session_id);
        await logEvent(env.DB, session_id, assistantTurn, "assistant", obj.next_state || state, obj.prompt || "");
        await flushSessionToR2(env.DB, session_id, session_created_at);
        return json(obj);
      };

      const handleReferenceMismatch = async (noteText) => {
        const txt = String(noteText || "").trim();
        const businessType = independent?.business?.type_final || dependent?.draft?.type_guess || "local business";
        const locationHint = dependent?.research?.location_hint || geoToLocationText(independent?.person?.geo) || "";
        const intentText = normalizeWebsiteIntentText(dependent?.research?.intent_text || independent?.build?.goal || "");
        const sites = Array.isArray(dependent?.research?.sites) ? dependent.research.sites : [];
        const idxRaw = Number(dependent?.research?.current_site_index ?? 0);
        const idx = Number.isFinite(idxRaw) ? idxRaw : 0;
        const nextIdx = idx + 1;

        dependent.design = dependent.design || {};
        dependent.design.reference_feedback = Array.isArray(dependent.design.reference_feedback)
          ? dependent.design.reference_feedback
          : [];
        dependent.design.reference_feedback.push({
          site_url: currentReferenceSite(dependent)?.url || independent?.demo?.last_demo_url || null,
          relevant: false,
          note: txt,
          ts: now(),
        });
        dependent.design.reference_feedback = dependent.design.reference_feedback.slice(-20);

        if (nextIdx < sites.length) {
          const nextSite = sites[nextIdx];
          dependent.research.current_site_index = nextIdx;
          independent.demo.last_demo_url = nextSite.url;
          return await reply({
            ok: true,
            next_state: "Q3_VIEWING_DEMO",
            prompt:
              `Understood — that one missed the mark. Try this example instead: ${nextSite.url}\n\n` +
              "I’ll ask what you like/dislike in about 20 seconds.",
            open_url: nextSite.url,
            demo_url: nextSite.url,
            auto_advance_after_seconds: 20,
            auto_advance_answer: "__AUTO_AFTER_20S__",
          });
        }

        const previousUrls = Array.from(
          new Set(
            [
              ...sites.map((s) => toHttpsUrl(s?.url)),
              ...dependent.design.reference_feedback.map((f) => toHttpsUrl(f?.site_url)),
            ].filter(Boolean)
          )
        );

        {
          const denied = ensureExpensiveActionAllowed(dependent);
          if (denied) return denied;
        }

        try {
          const market = await searchNearbyReferenceSites(
            session_id,
            businessType,
            locationHint,
            intentText || null,
            previousUrls
          );
          const freshSites = Array.isArray(market?.sites) ? market.sites.filter((s) => s?.url) : [];
          if (freshSites.length) {
            dependent.research = {
              ...(dependent.research || {}),
              location_hint: locationHint,
              intent_text: intentText || dependent?.research?.intent_text || null,
              sites: freshSites,
              source: market?.source || "inspector_market_search",
              current_site_index: 0,
              refresh_count: Number(dependent?.research?.refresh_count || 0) + 1,
            };
            independent.demo.last_demo_url = freshSites[0].url;
            return await reply({
              ok: true,
              next_state: "Q3_VIEWING_DEMO",
              prompt:
                `Thanks — I found a better match based on your feedback. Open this: ${freshSites[0].url}\n\n` +
                "I’ll ask what you liked/disliked in about 20 seconds.",
              open_url: freshSites[0].url,
              demo_url: freshSites[0].url,
              reference_sites: freshSites,
              auto_advance_after_seconds: 20,
              auto_advance_answer: "__AUTO_AFTER_20S__",
            });
          }
        } catch {}

        return await reply({
          ok: true,
          next_state: "Q2_SITE_INTENT",
          prompt:
            "Understood — tell me what kind of website you want instead (example: dive guiding service around Lake Tahoe), " +
            "and I’ll find better examples.",
        });
      };

      // DONE: handle email requests
      if (state === "DONE") {
        const txt = answerText;
        const email = extractEmailFromText(txt);
        const followupRequested = wantsEmailFollowup(txt);
        const dualServerRequested = wantsDualServerUpgradeInfo(txt);
        const pluginInstallRequested = wantsPluginInstall(txt);

        if (dualServerRequested) {
          const upgrade = ensureUpgradeState(dependent);
          upgrade.dual_server_interest = true;
          upgrade.dual_server_offered_at = now();
          if (/\bpaypal\b/i.test(txt)) upgrade.payment_preference = "paypal";
          if (/\bcrypto|bitcoin|btc|eth|usdc|usdt\b/i.test(txt)) upgrade.payment_preference = "crypto";
          refreshUpgradeExpirySignals(upgrade);
          const freeVpsWindowDays = Number(upgrade.free_vps_offer_window_days || normalizedFreeVpsOfferWindowDays());
          const renewalLine =
            upgrade.free_vps_offer_eligible
              ? `\n\nRenewal timing: we detected you are in the ${freeVpsWindowDays}-day pre-renewal window (${upgrade.days_until_managed_hosting_expiry ?? upgrade.days_until_domain_expiry} day(s) remaining), so we can start a free VPS bridge now.`
              : "";
          const funnelSummary = buildFunnelCtaActions(dependent);
          return await reply({
            ok: true,
            next_state: "DONE",
            prompt:
              "Yes — we can offer a Dual Server High-Availability upgrade.\n\n" +
              "What you get:\n" +
              "- Two live servers for failover/redundancy.\n" +
              "- Cloudflare load management + load balancing in front.\n" +
              "- Priority tuning for higher-end VPS hardware.\n" +
              "- Future-ready path to Proxmox colocation clusters.\n\n" +
              "Billing terms:\n" +
              "- Month-to-month only.\n" +
              "- No auto-enrollment and no auto-renew.\n" +
              "- Payment methods: PayPal or Crypto (only)." +
              renewalLine,
            funnel_stage: funnelSummary.stage,
            upgrade_score: funnelSummary.score,
            cta_actions: funnelSummary.actions,
          });
        }

        if (pluginInstallRequested) {
          const funnelSummary = buildFunnelCtaActions(dependent);
          const pluginAction = (funnelSummary.actions || []).find((a) => a?.id === "install_ai_webadmin_plugin");
          const connectAction = (funnelSummary.actions || []).find((a) => a?.id === "connect_cloudflare");
          const tollDnsAction = (funnelSummary.actions || []).find((a) => a?.id === "install_tolldns_required");
          const githubAction = (funnelSummary.actions || []).find((a) => a?.id === "signup_github_backup");
          const wpDetected =
            String(dependent?.scan?.platform_hint || "").toLowerCase() === "wordpress" ||
            String(dependent?.plugin?.detected_platform || "").toLowerCase() === "wordpress" ||
            String(independent?.business?.site_platform || "").toLowerCase() === "wordpress" ||
            independent?.business?.is_wordpress === true;

          if (!wpDetected) {
            return await reply({
              ok: true,
              next_state: "DONE",
              prompt:
                "I can install AI-WebAdmin on WordPress sites. Share your WordPress URL (or say \"audit my site\") and I’ll verify platform + start plugin onboarding.",
              funnel_stage: funnelSummary.stage,
              upgrade_score: funnelSummary.score,
              cta_actions: funnelSummary.actions,
            });
          }

          const lines = [
            "Yes — we can start plugin install now.",
            "",
            "Quick steps:",
            pluginAction?.url
              ? `1) Install AI-WebAdmin Plugin: ${pluginAction.url}`
              : "1) Install AI-WebAdmin Plugin from your WordPress admin plugin screen.",
            connectAction?.url
              ? `2) Connect Cloudflare account: ${connectAction.url}`
              : "2) Connect Cloudflare account in plugin settings.",
            tollDnsAction?.url
              ? `3) Install TollDNS (required for free tier): ${tollDnsAction.url}`
              : "3) Install TollDNS (required for free tier).",
            githubAction?.url
              ? `4) (Optional) Create/connect GitHub for backups: ${githubAction.url}`
              : "4) (Optional) Connect GitHub for backup snapshots.",
          ];
          return await reply({
            ok: true,
            next_state: "DONE",
            prompt: lines.join("\n"),
            funnel_stage: funnelSummary.stage,
            upgrade_score: funnelSummary.score,
            cta_actions: funnelSummary.actions,
          });
        }

        if (followupRequested || txt.toLowerCase().includes("email") || email) {
          let resolvedEmail = email || independent?.build?.email || null;
          if (!resolvedEmail) {
            resolvedEmail = await recoverEmailFromCurrentSite(session_id, independent, dependent);
          }

          if (email) {
            independent.build.email = resolvedEmail;
          } else if (resolvedEmail) {
            independent.build.email = resolvedEmail;
          }

          if (followupRequested) {
            dependent.followup = {
              requested: true,
              channel: "email",
              timeframe: extractFollowupTimeframe(txt),
              email: resolvedEmail,
              requested_at: now(),
            };
          }

          if (resolvedEmail) {
            const funnelSummary = buildFunnelCtaActions(dependent);
            return await reply({
              ok: true,
              next_state: "DONE",
              prompt: followupRequested
                ? `I found and saved ${resolvedEmail} for your follow-up demo request. I stored your request timing and contact info.`
                : `Got it — I saved ${resolvedEmail}. Paste a different email anytime.`,
              funnel_stage: funnelSummary.stage,
              upgrade_score: funnelSummary.score,
              cta_actions: funnelSummary.actions,
            });
          }
          const funnelSummary = buildFunnelCtaActions(dependent);
          return await reply({
            ok: true,
            next_state: "DONE",
            prompt:
              "I can do that, but I still need the exact email address. Please paste the email you want me to use for the demo link.",
            funnel_stage: funnelSummary.stage,
            upgrade_score: funnelSummary.score,
            cta_actions: funnelSummary.actions,
          });
        }
        const funnelSummary = buildFunnelCtaActions(dependent);
        return await reply({
          ok: true,
          next_state: "DONE",
          prompt: "Onboarding is complete for now.",
          funnel_stage: funnelSummary.stage,
          upgrade_score: funnelSummary.score,
          cta_actions: funnelSummary.actions,
        });
      }

      // Q1
      if (state === "Q1_DESCRIBE") {
        const desc = answerText.slice(0, 300);
        if (!desc) return json({ ok: false, error: "Please describe your business briefly." }, 400);

        independent.business.description_raw = desc;
        if (wantsWebsiteAuditFirst(desc)) {
          dependent.flow = dependent.flow || {};
          dependent.flow.audit_requested = true;
          dependent.draft.type_candidates = [];
          dependent.draft.type_source = "audit_intent";
          dependent.draft.type_guess = dependent.draft.type_guess || null;
          return await reply({
            ok: true,
            next_state: "Q2_PASTE_URL_OR_NO",
            prompt:
              "Absolutely — I can run a website audit first. Please paste your website URL so I can review it headlessly (or reply “no website”).",
          });
        }

        const resolved = await resolveBusinessTypeCandidates(desc);
        dependent.draft.type_candidates = resolved.candidates;
        dependent.draft.type_source = resolved.source;
        dependent.draft.type_guess = resolved.candidates[0] || "local business";

        if ((resolved.candidates || []).length > 1) {
          const numbered = resolved.candidates.map((c, i) => `${i + 1}) ${c}`).join("\n");
          return await reply({
            ok: true,
            next_state: "Q1_CHOOSE_TYPE",
            prompt:
              "I found a few likely business types. Reply with 1, 2, or 3 (or type your exact business type):\n" +
              `${numbered}`,
            candidates: resolved.candidates,
            source: resolved.source,
          });
        }

        return await reply({
          ok: true,
          next_state: "Q1_CONFIRM_TYPE",
          prompt: `Just to confirm before I save this: I’m going to label your business type as "${dependent.draft.type_guess}". Is that correct?`,
          source: resolved.source,
        });
      }

      if (state === "Q1_CHOOSE_TYPE") {
        const txt = answerText.toLowerCase();
        const candidates = Array.isArray(dependent?.draft?.type_candidates) ? dependent.draft.type_candidates : [];
        let picked = null;
        if (/^[123]$/.test(txt)) {
          const idx = Number(txt) - 1;
          if (candidates[idx]) picked = candidates[idx];
        }
        if (!picked) {
          picked = normalizeBusinessTypeLabel(answerText);
        }
        if (!picked) return json({ ok: false, error: "Please choose 1/2/3 or type a business type." }, 400);

        dependent.draft.type_guess = picked;
        return await reply({
          ok: true,
          next_state: "Q1_CONFIRM_TYPE",
          prompt: `Just to confirm before I save this: I’m going to label your business type as "${picked}". Is that correct?`,
        });
      }

      if (state === "Q1_CONFIRM_TYPE") {
        const v = yesNoMaybe(answer);
        if (v !== "yes" && v !== "no") return json({ ok: false, error: 'Please answer "yes" or "no".' }, 400);

        if (v === "no") {
          const candidates = Array.isArray(dependent?.draft?.type_candidates) ? dependent.draft.type_candidates : [];
          if (candidates.length > 1) {
            return await reply({
              ok: true,
              next_state: "Q1_CHOOSE_TYPE",
              prompt:
                "No problem. Pick the correct type (1/2/3) or type your exact business type:\n" +
                candidates.map((c, i) => `${i + 1}) ${c}`).join("\n"),
            });
          }
          return await reply({ ok: true, next_state: "Q1_TYPE_MANUAL", prompt: "What should I label your business type as?" });
        }

        independent.business.type_final = normalizeBusinessTypeLabel(dependent.draft.type_guess);
        await rememberBusinessType(independent.business.description_raw, independent.business.type_final, dependent?.draft?.type_source || "user_confirmed");

        return await reply({
          ok: true,
          next_state: "Q2_PASTE_URL_OR_NO",
          prompt: "Please paste your website URL so I can take a look (or reply “no website”).",
        });
      }

      if (state === "Q1_TYPE_MANUAL") {
        const t = normalizeBusinessTypeLabel(answerText);
        if (!t) return json({ ok: false, error: "Please provide a business type label." }, 400);
        dependent.draft.type_guess = t;
        dependent.draft.type_source = "manual";
        return await reply({
          ok: true,
          next_state: "Q1_CONFIRM_TYPE",
          prompt: `Just to confirm before I save this: I’m going to label your business type as "${t}". Is that correct?`,
        });
      }

      // URL implies permission
      if (state === "Q2_PASTE_URL_OR_NO") {
        const text = answerText;
        const foundUrl = extractUrlFromText(text);
        const v = yesNoMaybe(text);
        const noCurrentSite = impliesNoCurrentWebsite(text);

        if (!foundUrl && (v === "no" || noCurrentSite)) {
          independent.business.own_site_url = null;
          independent.business.own_site_confirmed = false;
          const impliedIntent = extractIntentFromNoSiteReply(text);
          if (impliedIntent) {
            const businessType = independent.business.type_final || dependent?.draft?.type_guess || "local business";
            const locationHint = dependent?.research?.location_hint || geoToLocationText(independent?.person?.geo) || "";
            const resolved = await resolveWebsiteIntentFocus(impliedIntent, businessType, locationHint);
            dependent.research = dependent.research || {};
            dependent.research.intent_raw = resolved.raw || impliedIntent;
            dependent.research.intent_draft = resolved.focus || impliedIntent;
            dependent.research.intent_source = resolved.source || "user";
            return await reply({
              ok: true,
              next_state: "Q2_SITE_INTENT_CONFIRM",
              prompt: `Perfect — I’ll search examples for "${dependent.research.intent_draft}". Is that correct?`,
            });
          }
          return await reply({
            ok: true,
            next_state: "Q2_SITE_INTENT",
            prompt:
              "No problem. What type of website do you want? " +
              'For example: "dive guiding service around Lake Tahoe with online bookings."',
          });
        }

        if (!foundUrl) return json({ ok: false, error: 'Please paste a URL or reply "no website".' }, 400);

        const u = toHttpsUrl(foundUrl);
        independent.business.own_site_url = u;
        await upsertSessionVars(session_id, "onboarding_v8", independent, dependent);

        return await reply({
          ok: true,
          next_state: "Q2_CONFIRM_OWNERSHIP",
          prompt: `Thanks — I saved ${u}. I will review it in the background after you confirm. Is that your website?`,
        });
      }

      if (state === "Q2_SITE_INTENT") {
        const rawIntent = normalizeWebsiteIntentText(answerText);
        if (!rawIntent) {
          return json(
            {
              ok: false,
              error:
                'Please describe the type of site you want (example: "dive guide website for Lake Tahoe tourists").',
            },
            400
          );
        }
        const businessType = independent.business.type_final || dependent?.draft?.type_guess || "local business";
        const locationHint = dependent?.research?.location_hint || geoToLocationText(independent?.person?.geo) || "";
        const resolved = await resolveWebsiteIntentFocus(rawIntent, businessType, locationHint);
        dependent.research = dependent.research || {};
        dependent.research.intent_raw = resolved.raw || rawIntent;
        dependent.research.intent_draft = resolved.focus || rawIntent;
        dependent.research.intent_source = resolved.source || "user";

        return await reply({
          ok: true,
          next_state: "Q2_SITE_INTENT_CONFIRM",
          prompt: `Perfect — I’ll search examples for "${dependent.research.intent_draft}". Is that correct?`,
        });
      }

      if (state === "Q2_SITE_INTENT_CONFIRM") {
        const v = yesNoMaybe(answer);
        if (v !== "yes" && v !== "no") return json({ ok: false, error: 'Please answer "yes" or "no".' }, 400);

        if (v === "no") {
          dependent.research = dependent.research || {};
          dependent.research.intent_draft = null;
          return await reply({
            ok: true,
            next_state: "Q2_SITE_INTENT",
            prompt: "No problem — tell me the type of website you want, in your own words.",
          });
        }

        dependent.research = dependent.research || {};
        const intentText = normalizeWebsiteIntentText(dependent?.research?.intent_draft || dependent?.research?.intent_raw || "");
        dependent.research.intent_text = intentText || null;
        dependent.research.intent_draft = null;
        if (intentText && !independent.build.goal) independent.build.goal = intentText;

        return await reply({
          ok: true,
          next_state: "Q3_VIEW_EXAMPLES_YN",
          prompt: "Great — would you be willing to view a few example sites with me and tell me what you like or don’t like?",
        });
      }

      if (state === "Q2_CONFIRM_OWNERSHIP") {
        const v = yesNoMaybe(answer);
        if (v !== "yes" && v !== "no") return json({ ok: false, error: 'Please answer "yes" or "no".' }, 400);

        independent.business.own_site_confirmed = (v === "yes");

        if (v === "no") {
          return await reply({
            ok: true,
            next_state: "Q3_VIEW_EXAMPLES_YN",
            prompt: "No problem — would you be willing to view a few example sites with me and tell me what you like or don’t like?",
          });
        }

        // Immediately scan confirmed website to pull key contact variables.
        const targetUrl = bestScanTarget(independent);
        if (targetUrl) {
          const denied = ensureExpensiveActionAllowed(dependent);
          if (denied) return denied;
          try {
            const started = await startSiteScan(session_id, targetUrl);
            dependent.scan = dependent.scan || {};
            dependent.scan.status = started.status || "done";
            dependent.scan.request_id = started.request_id || null;
            dependent.scan.latest_summary = summarizeScan(started.result || null);
            dependent.scan.latest_result = started.result || null;
            applyScanResultToSession(independent, dependent, started.result || null);
          } catch (error) {
            dependent.scan = dependent.scan || {};
            dependent.scan.status = "failed";
            dependent.scan.error = String(error?.message || error);
          }
        }

        if (independent?.business?.is_wordpress === true) {
          ensurePluginState(dependent);
          dependent.plugin.detected_platform = "wordpress";
          const autoAuditRequested = dependent?.flow?.audit_requested === true;
          if (autoAuditRequested) {
            dependent.flow.audit_requested = false;
            dependent.plugin.wordpress_offer_shown = true;
            const auditResult = dependent?.scan?.latest_result || null;
            const payload = buildWordpressAuditReplyPayload(independent, dependent, auditResult);
            return await reply({
              ok: true,
              next_state: "Q2_AUDIT_EMAIL_OPTIN",
              ...payload,
            });
          }
          if (!dependent.plugin.wordpress_offer_shown) {
            dependent.plugin.wordpress_offer_shown = true;
            return await reply({
              ok: true,
              next_state: "Q2_WP_AUDIT_OFFER",
              prompt:
                "I detected your site is on WordPress. I can run a free security + speed +schema audit now and let you know how you score to see if our AI-admin plugin might help?\n\n" +
                "Want me to run the audit now? (yes/no)\n" +
                "If you want more detail first, tell me what you want to know.",
            });
          }
        }

        return await reply({
          ok: true,
          next_state: "Q2_HAPPY_COSTS",
          prompt:
            dependent?.scan?.latest_summary
              ? `I reviewed your current site and captured key details (${dependent.scan.latest_summary}). ${buildSecondPartPrompt()}`
              : buildSecondPartPrompt(),
        });
      }

      if (state === "Q2_WP_AUDIT_OFFER") {
        let v = yesNoMaybe(answer);
        if (v !== "yes" && v !== "no" && wantsWordpressAuditNow(answer)) v = "yes";
        if (v !== "yes" && v !== "no") {
          return await reply({
            ok: true,
            next_state: "Q2_WP_AUDIT_OFFER",
            prompt:
              "No problem — I can give more detail first. The audit will score security, speed, and schema, and include operational counts for email queue, plugin updates, inactive/redundant plugins, and comments awaiting moderation when available.\n\n" +
              "Reply \"yes\" to run it now, \"no\" to skip, or ask a specific question.",
          });
        }
        ensurePluginState(dependent);

        if (v === "yes") {
          let result = dependent?.scan?.latest_result || null;
          if (!result) {
            const denied = ensureExpensiveActionAllowed(dependent);
            if (denied) return denied;
            const targetUrl = bestScanTarget(independent);
            if (targetUrl) {
              try {
                const started = await startSiteScan(session_id, targetUrl);
                result = started?.result || null;
                dependent.scan = dependent.scan || {};
                dependent.scan.status = started.status || "done";
                dependent.scan.request_id = started.request_id || null;
                dependent.scan.latest_summary = summarizeScan(result);
                dependent.scan.latest_result = result;
                applyScanResultToSession(independent, dependent, result);
              } catch {}
            }
          }
          dependent.flow.audit_requested = false;
          const payload = buildWordpressAuditReplyPayload(independent, dependent, result || {});
          return await reply({
            ok: true,
            next_state: "Q2_AUDIT_EMAIL_OPTIN",
            ...payload,
          });
        }

        dependent.flow.audit_requested = false;
        return await reply({
          ok: true,
          next_state: "Q2_HAPPY_COSTS",
          prompt:
            "No problem — we can skip the audit for now. If you want later, I can still run a WordPress security/speed audit.\n" +
            buildSecondPartPrompt(),
        });
      }

      if (state === "Q2_AUDIT_EMAIL_OPTIN") {
        const pref = parseAuditEmailPreferences(answer);
        const suppliedEmail = extractEmailFromText(answer);
        if (suppliedEmail) {
          independent.build.email = suppliedEmail;
          dependent.followup.email = suppliedEmail;
        }

        let reportOptIn = false;
        let reminderOptIn = false;
        let saveNote = "I couldn't detect a clear yes/no, so I left both email follow-ups off for now.";

        if (pref.decision === "yes") {
          reportOptIn = Boolean(pref.report);
          reminderOptIn = Boolean(pref.reminder);
          if (reportOptIn && reminderOptIn) saveNote = "Perfect — I’ll email the audit report and domain-expiration reminders.";
          else if (reportOptIn) saveNote = "Perfect — I’ll email the audit report.";
          else if (reminderOptIn) saveNote = "Perfect — I’ll send domain-expiration reminders.";
          else saveNote = "Thanks — I saved your preference.";
        } else if (pref.decision === "no") {
          saveNote = "No problem — I won’t send report or domain reminder emails.";
        }

        dependent.followup.audit_report_email_opt_in = reportOptIn;
        dependent.followup.domain_expiry_reminder_opt_in = reminderOptIn;
        dependent.followup.audit_email_opted_at = now();
        dependent.followup.audit_email_optin_source = "chat";

        return await reply({
          ok: true,
          next_state: "Q2_HAPPY_COSTS",
          prompt: `${saveNote}\n\n${buildSecondPartPrompt()}`,
        });
      }

      if (state === "Q_SCHEMA_BUSINESS_NAME") {
        const name = sanitizeSchemaText(answer, 180);
        if (!name) return json({ ok: false, error: "Please provide the business name for schema." }, 400);
        dependent.schema_setup = dependent.schema_setup || {};
        dependent.schema_setup.profile = dependent.schema_setup.profile || {};
        dependent.schema_setup.profile.business_name = name;
        dependent.schema_setup.status = "collecting";
        dependent.schema_setup.last_updated_at = now();
        return await reply({
          ok: true,
          next_state: "Q_SCHEMA_TYPE",
          prompt: `Great. What schema type should we use? (example: ${defaultSchemaTypeFromBusiness(independent)}, LocalBusiness, AutoRepair, Restaurant)`,
        });
      }

      if (state === "Q_SCHEMA_TYPE") {
        dependent.schema_setup = dependent.schema_setup || {};
        dependent.schema_setup.profile = dependent.schema_setup.profile || {};
        dependent.schema_setup.profile.schema_type = normalizeSchemaType(answer, defaultSchemaTypeFromBusiness(independent));
        dependent.schema_setup.last_updated_at = now();
        return await reply({
          ok: true,
          next_state: "Q_SCHEMA_PHONE",
          prompt: "What phone number should be in schema? (or reply skip)",
        });
      }

      if (state === "Q_SCHEMA_PHONE") {
        const txt = String(answer || "").trim();
        dependent.schema_setup = dependent.schema_setup || {};
        dependent.schema_setup.profile = dependent.schema_setup.profile || {};
        dependent.schema_setup.profile.phone = isSkip(txt) ? null : normalizePhone(txt) || sanitizeSchemaText(txt, 80);
        dependent.schema_setup.last_updated_at = now();
        return await reply({
          ok: true,
          next_state: "Q_SCHEMA_ADDRESS",
          prompt: "Use a physical address or service area in schema? (reply: address / service area / skip)",
        });
      }

      if (state === "Q_SCHEMA_ADDRESS") {
        const t = String(answer || "").toLowerCase();
        dependent.schema_setup = dependent.schema_setup || {};
        dependent.schema_setup.profile = dependent.schema_setup.profile || {};
        if (/\bservice\b/.test(t)) {
          dependent.schema_setup.profile.address_mode = "service_area";
          return await reply({
            ok: true,
            next_state: "Q_SCHEMA_SERVICE_AREA",
            prompt: "What service area should we include? (example: Reno, Carson City, Lake Tahoe)",
          });
        }
        if (isSkip(t)) {
          dependent.schema_setup.profile.address_mode = "skip";
          dependent.schema_setup.profile.address = null;
          dependent.schema_setup.profile.service_area = null;
          return await reply({
            ok: true,
            next_state: "Q_SCHEMA_HOURS",
            prompt: 'What opening hours should we include? (example: "Mo-Fr 09:00-18:00", or skip)',
          });
        }
        dependent.schema_setup.profile.address_mode = "address";
        dependent.schema_setup.profile.address = sanitizeSchemaText(answer, 220);
        return await reply({
          ok: true,
          next_state: "Q_SCHEMA_HOURS",
          prompt: 'What opening hours should we include? (example: "Mo-Fr 09:00-18:00", or skip)',
        });
      }

      if (state === "Q_SCHEMA_SERVICE_AREA") {
        dependent.schema_setup = dependent.schema_setup || {};
        dependent.schema_setup.profile = dependent.schema_setup.profile || {};
        dependent.schema_setup.profile.service_area = sanitizeSchemaText(answer, 220);
        return await reply({
          ok: true,
          next_state: "Q_SCHEMA_HOURS",
          prompt: 'What opening hours should we include? (example: "Mo-Fr 09:00-18:00", or skip)',
        });
      }

      if (state === "Q_SCHEMA_HOURS") {
        const txt = String(answer || "").trim();
        const hours = isSkip(txt)
          ? []
          : txt
              .split(/[,;]+/)
              .map((x) => sanitizeSchemaText(x, 60))
              .filter(Boolean)
              .slice(0, 12);
        dependent.schema_setup = dependent.schema_setup || {};
        dependent.schema_setup.profile = dependent.schema_setup.profile || {};
        dependent.schema_setup.profile.hours = hours;
        dependent.schema_setup.profile.website_url =
          bestScanTarget(independent) || toHttpsUrl(independent?.business?.own_site_url) || null;
        dependent.schema_setup.last_updated_at = now();

        const draft = buildSchemaJsonLd(dependent.schema_setup.profile, dependent.schema_setup.profile.website_url || null);
        dependent.schema_setup.jsonld = JSON.stringify(draft, null, 2);
        return await reply({
          ok: true,
          next_state: "Q_SCHEMA_CONFIRM",
          prompt:
            "Here is your schema draft. Save this?\n\n" +
            dependent.schema_setup.jsonld +
            "\n\nReply yes to save, no to edit again.",
        });
      }

      if (state === "Q_SCHEMA_CONFIRM") {
        const v = yesNoMaybe(answer);
        if (v !== "yes" && v !== "no") return json({ ok: false, error: 'Please answer "yes" or "no".' }, 400);
        dependent.schema_setup = dependent.schema_setup || {};
        dependent.schema_setup.status = v === "yes" ? "ready" : "collecting";
        dependent.schema_setup.last_updated_at = now();
        if (v === "no") {
          return await reply({
            ok: true,
            next_state: "Q_SCHEMA_BUSINESS_NAME",
            prompt: "No problem — let’s edit it. What business name should we use?",
          });
        }

        const backState = dependent.schema_setup.pending_return_state || "Q2_HAPPY_COSTS";
        return await reply({
          ok: true,
          next_state: backState,
          prompt:
            "Saved. I stored this schema profile for your site and plugin sync.\n" +
            `When ready, the plugin can pull it and inject JSON-LD automatically.\n\n` +
            `Now, ${buildSecondPartPrompt().toLowerCase()}`,
          schema_profile: dependent.schema_setup.profile,
          schema_jsonld: dependent.schema_setup.jsonld,
        });
      }

      if (state === "Q2_HAPPY_COSTS") {
        const v = yesNoMaybe(answer);
        if (asksForSchemaOrAccessExplanation(answer)) {
          return await reply({
            ok: true,
            next_state: "Q2_HAPPY_COSTS",
            prompt: buildSchemaAndAccessExplanationPrompt(dependent),
          });
        }
        if (wantsSchemaSetup(answer)) {
          dependent.schema_setup = dependent.schema_setup || {};
          dependent.schema_setup.pending_return_state = "Q2_HAPPY_COSTS";
          dependent.schema_setup.status = "collecting";
          dependent.schema_setup.profile = dependent.schema_setup.profile || {};
          return await reply({
            ok: true,
            next_state: "Q_SCHEMA_BUSINESS_NAME",
            prompt: "Great — let’s set up your schema data. What business name should appear?",
          });
        }
        if (asksForSpeedBenchmark(answer)) {
          const benchmark = buildWordpressSpeedBenchmarkMessage(dependent);
          if (benchmark) {
            return await reply({
              ok: true,
              next_state: "Q2_HAPPY_COSTS",
              prompt:
                `${benchmark}\n\n` +
                `Given that benchmark, ${buildSecondPartPrompt().toLowerCase()}`,
            });
          }
          return await reply({
            ok: true,
            next_state: "Q2_HAPPY_COSTS",
            prompt:
              `I can benchmark once we have a site scan/audit result. For now, ${buildSecondPartPrompt().toLowerCase()}`,
          });
        }

        if (v === "maybe") {
          return await reply({
            ok: true,
            next_state: "Q2_HAPPY_COSTS_FORCED",
            prompt: "No worries — if you had to choose, would you say you're overall happy (yes) or not happy (no)?",
          });
        }
        if (v !== "yes" && v !== "no") return json({ ok: false, error: 'Please answer "yes" or "no" (or "kinda").' }, 400);

        independent.business.happy_with_site_and_cost = (v === "yes");
        await upsertSessionVars(session_id, "onboarding_v8", independent, dependent);

        return await reply({
          ok: true,
          next_state: "Q3_VIEW_EXAMPLES_YN",
          prompt:
            v === "yes"
              ? "Great. Would you still be willing to view a few example sites with me and tell me what you like or don’t like?"
              : "Would you be willing to view a few example sites with me and tell me what you like or don’t like compared to your site?",
        });
      }

      if (state === "Q2_HAPPY_COSTS_FORCED") {
        const v = yesNoMaybe(answer);
        if (asksForSchemaOrAccessExplanation(answer)) {
          return await reply({
            ok: true,
            next_state: "Q2_HAPPY_COSTS_FORCED",
            prompt:
              `${buildSchemaAndAccessExplanationPrompt(dependent)}\n\n` +
              "If you had to choose right now, are you overall happy? (yes/no)",
          });
        }
        if (wantsSchemaSetup(answer)) {
          dependent.schema_setup = dependent.schema_setup || {};
          dependent.schema_setup.pending_return_state = "Q2_HAPPY_COSTS_FORCED";
          dependent.schema_setup.status = "collecting";
          dependent.schema_setup.profile = dependent.schema_setup.profile || {};
          return await reply({
            ok: true,
            next_state: "Q_SCHEMA_BUSINESS_NAME",
            prompt: "Great — let’s set up your schema data. What business name should appear?",
          });
        }
        if (asksForSpeedBenchmark(answer)) {
          const benchmark = buildWordpressSpeedBenchmarkMessage(dependent);
          if (benchmark) {
            return await reply({
              ok: true,
              next_state: "Q2_HAPPY_COSTS_FORCED",
              prompt: `${benchmark}\n\nIf you had to choose right now, are you currently happy with your website overall? (yes/no)`,
            });
          }
        }
        if (v !== "yes" && v !== "no") return json({ ok: false, error: 'Please answer "yes" or "no".' }, 400);

        independent.business.happy_with_site_and_cost = (v === "yes");
        await upsertSessionVars(session_id, "onboarding_v8", independent, dependent);

        return await reply({
          ok: true,
          next_state: "Q3_VIEW_EXAMPLES_YN",
          prompt:
            v === "yes"
              ? "Great. Would you still be willing to view a few example sites with me and tell me what you like or don’t like?"
              : "Would you be willing to view a few example sites with me and tell me what you like or don’t like compared to your site?",
        });
      }

      if (state === "Q2_SPEND_TOTAL") {
        const txt = String(answer || "").trim();
        if (!txt) return json({ ok: false, error: "Please give a rough estimate (monthly or yearly)." }, 400);

        independent.business.spend_raw = txt;
        const parsed = parseSpend(txt);
        independent.business.spend_amount = parsed.amount;
        independent.business.spend_period = parsed.period;
        await upsertSessionVars(session_id, "onboarding_v8", independent, dependent);

        return await reply({
          ok: true,
          next_state: "Q3_VIEW_EXAMPLES_YN",
          prompt: "Would you be willing to view a few example sites with me and tell me what you like or don’t like compared to your site?",
        });
      }

      // ===== VIEW EXAMPLES -> show link -> guided Qs =====
      if (state === "Q3_VIEW_EXAMPLES_YN") {
        const v = yesNoMaybe(answer);

        if (v === "scan") {
          if (dependent?.scan?.request_id) {
            try {
              const statusPayload = await fetchScanStatus(session_id);
              const result = statusPayload?.result || null;
              if (result) {
                dependent.scan = dependent.scan || {};
                dependent.scan.latest_summary = summarizeScan(result);
                return await reply({
                  ok: true,
                  next_state: "Q3_VIEW_EXAMPLES_YN",
                  prompt:
                    `Yes — I reviewed your site. ${dependent.scan.latest_summary}. ` +
                    "Would you still be willing to view a few comparison sites together?",
                });
              }
            } catch {}
          }

          const targetUrl = bestScanTarget(independent);
          if (targetUrl) {
            const denied = ensureExpensiveActionAllowed(dependent);
            if (denied) return denied;
            try {
              const started = await startSiteScan(session_id, targetUrl);
              dependent.scan = {
                status: started.status || "done",
                request_id: started.request_id || null,
                latest_summary: summarizeScan(started.result || null),
              };
              return await reply({
                ok: true,
                next_state: "Q3_VIEW_EXAMPLES_YN",
                prompt:
                  `I just scanned ${targetUrl}. ${dependent.scan.latest_summary || "I pulled the key page signals."} ` +
                  "Would you still be willing to view a few example sites with me and tell me what you like or don’t like?",
              });
            } catch {}
          }

          return await reply({
            ok: true,
            next_state: "Q_SCAN_PERMISSION",
            prompt:
              "Not yet — so far I’ve only opened the link. If you want, I can run an automated scan (fully rendered page + basic checks) and come back with specific optimization ideas. Want me to do that?",
          });
        }

        if (v === "why") {
          return await reply({
            ok: true,
            next_state: "Q3_VIEW_EXAMPLES_YN",
            prompt:
              "Because I want to see if I could build you a website for free right now that you might like more — " +
              "no commitment, no credit card, and a free 1-month trial. You have nothing to lose. " +
              "Would you be willing to view a few example sites with me and tell me what you like or don’t like?",
          });
        }

        if (v === "howknow") {
          return await reply({
            ok: true,
            next_state: "Q3_VIEW_EXAMPLES_YN",
            prompt:
              "Totally fair — that’s why we start with examples and then I build a demo you can review. If you don’t like it, you walk away. " +
              "Would you be willing to view a couple examples?",
          });
        }

        if (v !== "yes" && v !== "no") return json({ ok: false, error: 'Please answer "yes" or "no".' }, 400);

        if (v === "no") {
          return await reply({
            ok: true,
            next_state: "Q_BUILD_TRIAL_YN",
            prompt: "No problem. Would you still like me to build you a demo site for a free 1-month, no-risk trial on a subdomain? No credit card needed.",
          });
        }

        // YES: fetch localized reference sites from inspector worker
        independent.style.willing_to_view_examples = true;
        {
          const denied = ensureExpensiveActionAllowed(dependent);
          if (denied) return denied;
        }
        const businessType = independent.business.type_final || dependent.draft.type_guess || "local business";
        const locationHint = dependent?.research?.location_hint || geoToLocationText(independent?.person?.geo) || "";
        const intentText = normalizeWebsiteIntentText(dependent?.research?.intent_text || independent?.build?.goal || "");
        const excludedUrls = Array.from(
          new Set(
            (Array.isArray(dependent?.design?.reference_feedback) ? dependent.design.reference_feedback : [])
              .map((f) => toHttpsUrl(f?.site_url))
              .filter(Boolean)
          )
        );
        let demoUrl = PLACEHOLDER_DEMO_URL;
        let source = "fallback_demo";
        let sites = [];

        try {
          const market = await searchNearbyReferenceSites(session_id, businessType, locationHint, intentText || null, excludedUrls);
          sites = Array.isArray(market?.sites) ? market.sites.filter((s) => s?.url) : [];
          source = market?.source || "inspector_market_search";
          if (sites.length) demoUrl = sites[0].url;
        } catch (error) {
          sites = [];
          source = "fallback_demo";
        }

        independent.demo.last_demo_url = demoUrl;
        dependent.research = {
          ...(dependent.research || {}),
          location_hint: locationHint,
          intent_text: intentText || dependent?.research?.intent_text || null,
          sites,
          source,
          current_site_index: 0,
          refresh_count: 0,
        };
        await upsertSessionVars(session_id, "onboarding_v8", independent, dependent);

        const scopeLine = intentText ? ` that matches your goal (“${intentText}”)` : " near your location";
        return await reply({
          ok: true,
          next_state: "Q3_VIEWING_DEMO",
          prompt:
            `Awesome — I found a reference site${scopeLine}. Open this link in a new tab: ` +
            `${demoUrl}\n\nBrowse for ~20–30 seconds, then come back and tell me when you’re ready.`,
          open_url: demoUrl,
          demo_url: demoUrl,
          reference_sites: sites,
          auto_advance_after_seconds: 20,
          auto_advance_answer: "__AUTO_AFTER_20S__",
        });
      }

      if (state === "Q3_VIEWING_DEMO") {
        if (answerText === "__AUTO_AFTER_20S__") {
          const site = currentReferenceSite(dependent);
          const next = buildSiteFeedbackPrompt(site);
          return await reply({
            ok: true,
            next_state: "Q3_FEEDBACK_OPEN",
            prompt: next.prompt,
            color_swatches: next.color_swatches,
            layout_guide: next.layout_guide,
          });
        }

        const txt = answerText;
        const demoUrl = independent?.demo?.last_demo_url || PLACEHOLDER_DEMO_URL;

        if (cannotAccessDemoSite(txt)) {
          return await reply({
            ok: true,
            next_state: "Q3_VIEWING_DEMO",
            prompt:
              `No problem — use this link directly: ${demoUrl}\n\n` +
              "If it doesn't open automatically, copy/paste it into a new tab. Reply \"opened\" when you can view it.",
            open_url: demoUrl,
            demo_url: demoUrl,
          });
        }

        if (!isReadyAfterOpeningDemo(txt) && yesNoMaybe(txt) !== "yes") {
          return await reply({
            ok: true,
            next_state: "Q3_VIEWING_DEMO",
            prompt:
              `When you're ready, open this link: ${demoUrl}\n\n` +
              "Reply \"opened\" once you've seen it for 20–30 seconds.",
            open_url: demoUrl,
            demo_url: demoUrl,
          });
        }

        return await reply({
          ok: true,
          next_state: "Q3_FEEDBACK_OPEN",
          ...buildSiteFeedbackPrompt(currentReferenceSite(dependent)),
        });
      }

      if (state === "Q3_FEEDBACK_OPEN") {
        const txt = answerText;
        if (!txt) return json({ ok: false, error: "Please share at least one like/dislike." }, 400);
        const demoUrl = independent?.demo?.last_demo_url || PLACEHOLDER_DEMO_URL;

        if (cannotAccessDemoSite(txt)) {
          return await reply({
            ok: true,
            next_state: "Q3_VIEWING_DEMO",
            prompt:
              `Understood — try this direct link: ${demoUrl}\n\n` +
              "Once it opens, reply \"opened\" and we’ll continue.",
            open_url: demoUrl,
            demo_url: demoUrl,
          });
        }

        const businessType = independent?.business?.type_final || dependent?.draft?.type_guess || "";
        if (userRejectedReferenceSite(txt, businessType)) {
          return await handleReferenceMismatch(txt);
        }

        const signals = extractPreferenceSignals(txt);
        dependent.design = dependent.design || {
          liked: [],
          disliked: [],
          palette_hints: [],
          layout_hints: [],
          font_hints: [],
          raw_feedback: [],
        };

        dependent.design.liked = Array.from(new Set([...(dependent.design.liked || []), ...signals.liked])).slice(0, 20);
        dependent.design.disliked = Array.from(new Set([...(dependent.design.disliked || []), ...signals.disliked])).slice(0, 20);
        dependent.design.palette_hints = Array.from(new Set([...(dependent.design.palette_hints || []), ...signals.palette_hints])).slice(0, 20);
        dependent.design.layout_hints = Array.from(new Set([...(dependent.design.layout_hints || []), ...signals.layout_hints])).slice(0, 20);
        dependent.design.font_hints = Array.from(new Set([...(dependent.design.font_hints || []), ...signals.font_hints])).slice(0, 20);
        dependent.design.raw_feedback = [...(dependent.design.raw_feedback || []), signals.raw].slice(-20);
        dependent.design.reference_feedback = Array.isArray(dependent.design.reference_feedback)
          ? dependent.design.reference_feedback
          : [];
        dependent.design.reference_feedback.push({
          site_url: currentReferenceSite(dependent)?.url || independent?.demo?.last_demo_url || null,
          liked: signals.liked,
          disliked: signals.disliked,
          colors: signals.palette_hints,
          layouts: signals.layout_hints,
          fonts: signals.font_hints,
          ts: now(),
        });
        dependent.design.reference_feedback = dependent.design.reference_feedback.slice(-10);

        await upsertSessionVars(session_id, "onboarding_v8", independent, dependent);
        await persistPreferenceSnapshot(session_id, independent, dependent);

        return await reply({
          ok: true,
          next_state: "Q3_DEMO_Q1",
          prompt: 'First impression: did this example feel more "modern/clean" or more "bold/flashy"? (modern / bold)',
        });
      }

      if (state === "Q3_DEMO_Q1") {
        const t = answerText.toLowerCase();
        const demoUrl = independent?.demo?.last_demo_url || PLACEHOLDER_DEMO_URL;

        if (cannotAccessDemoSite(t)) {
          return await reply({
            ok: true,
            next_state: "Q3_VIEWING_DEMO",
            prompt:
              `No problem — open this link first: ${demoUrl}\n\n` +
              "Reply \"opened\" once you can see it, then we’ll continue.",
            open_url: demoUrl,
            demo_url: demoUrl,
          });
        }

        if (/\b(idk|i don'?t know|dont know|not sure|unsure)\b/.test(t)) {
          independent.demo.q1_vibe = "neutral";
          dependent.design = dependent.design || {};
          dependent.design.layout_hints = Array.from(new Set([...(dependent.design.layout_hints || []), "balanced"]));
          await upsertSessionVars(session_id, "onboarding_v8", independent, dependent);
          return await reply({
            ok: true,
            next_state: "Q3_DEMO_Q2",
            prompt: "No worries — let’s skip vibe for now. What did you think about the colors? (too bright / too dark / just right)",
          });
        }

        const businessType = independent?.business?.type_final || dependent?.draft?.type_guess || "";
        if (userRejectedReferenceSite(t, businessType)) {
          return await handleReferenceMismatch(t);
        }

        const modern = t.includes("modern");
        const bold = t.includes("bold");
        if (!modern && !bold) return json({ ok: false, error: 'Please reply "modern" or "bold".' }, 400);

        independent.demo.q1_vibe = modern ? "modern" : "bold";
        dependent.design = dependent.design || {};
        dependent.design.layout_hints = Array.from(
          new Set([...(dependent.design.layout_hints || []), modern ? "clean_modern" : "bold_visual"])
        );
        await upsertSessionVars(session_id, "onboarding_v8", independent, dependent);

        return await reply({
          ok: true,
          next_state: "Q3_DEMO_Q2",
          prompt: "What did you think about the colors? (too bright / too dark / just right)",
        });
      }

      if (state === "Q3_DEMO_Q2") {
        const t = String(answer || "").trim().toLowerCase();
        const ok = /(too bright|too dark|just right)/.test(t);
        if (!ok) return json({ ok: false, error: 'Please reply "too bright", "too dark", or "just right".' }, 400);

        independent.demo.q2_colors = t.includes("bright") ? "too bright" : t.includes("dark") ? "too dark" : "just right";
        dependent.design = dependent.design || {};
        if (t.includes("bright")) dependent.design.palette_hints = Array.from(new Set([...(dependent.design.palette_hints || []), "avoid_too_bright"]));
        if (t.includes("dark")) dependent.design.palette_hints = Array.from(new Set([...(dependent.design.palette_hints || []), "avoid_too_dark"]));
        if (t.includes("just right")) dependent.design.palette_hints = Array.from(new Set([...(dependent.design.palette_hints || []), "balanced_contrast"]));
        await upsertSessionVars(session_id, "onboarding_v8", independent, dependent);

        return await reply({
          ok: true,
          next_state: "Q3_DEMO_Q3",
          prompt: "How did the layout feel? (easy to read / cluttered / too empty)",
        });
      }

      if (state === "Q3_DEMO_Q3") {
        const t = String(answer || "").trim().toLowerCase();
        const ok = /(easy to read|cluttered|too empty)/.test(t);
        if (!ok) return json({ ok: false, error: 'Please reply "easy to read", "cluttered", or "too empty".' }, 400);

        independent.demo.q3_layout = t.includes("easy") ? "easy to read" : t.includes("clutter") ? "cluttered" : "too empty";
        dependent.design = dependent.design || {};
        if (t.includes("easy")) dependent.design.layout_hints = Array.from(new Set([...(dependent.design.layout_hints || []), "readable"]));
        if (t.includes("clutter")) dependent.design.layout_hints = Array.from(new Set([...(dependent.design.layout_hints || []), "avoid_clutter"]));
        if (t.includes("too empty")) dependent.design.layout_hints = Array.from(new Set([...(dependent.design.layout_hints || []), "denser_sections"]));
        await upsertSessionVars(session_id, "onboarding_v8", independent, dependent);
        await persistPreferenceSnapshot(session_id, independent, dependent);

        return await reply({
          ok: true,
          next_state: "Q3_NEXT_REFERENCE_YN",
          prompt: "Want to review one more reference site before I build your demo? (yes/no)",
        });
      }

      if (state === "Q3_NEXT_REFERENCE_YN") {
        const v = yesNoMaybe(answer);
        if (v !== "yes" && v !== "no") return json({ ok: false, error: 'Please answer "yes" or "no".' }, 400);

        const sites = Array.isArray(dependent?.research?.sites) ? dependent.research.sites : [];
        const idxRaw = Number(dependent?.research?.current_site_index ?? 0);
        const idx = Number.isFinite(idxRaw) ? idxRaw : 0;
        const nextIdx = idx + 1;

        if (v === "yes" && nextIdx < sites.length) {
          const nextSite = sites[nextIdx];
          dependent.research.current_site_index = nextIdx;
          independent.demo.last_demo_url = nextSite.url;

          return await reply({
            ok: true,
            next_state: "Q3_VIEWING_DEMO",
            prompt:
              "Great — here’s the next reference site. Open this in a new tab: " +
              `${nextSite.url}\n\nI’ll ask you what you like most in about 20 seconds.`,
            open_url: nextSite.url,
            demo_url: nextSite.url,
            auto_advance_after_seconds: 20,
            auto_advance_answer: "__AUTO_AFTER_20S__",
          });
        }

        return await reply({
          ok: true,
          next_state: "Q_BUILD_TRIAL_YN",
          prompt:
            "Thanks — based on your feedback, would you like me to build you a demo site for a free 1-month, no-risk trial on a subdomain? No credit card needed.",
        });
      }

      // Scan permission
      if (state === "Q_SCAN_PERMISSION") {
        const v = yesNoMaybe(answer);
        if (v === "why") {
          return await reply({
            ok: true,
            next_state: "Q_SCAN_PERMISSION",
            prompt: "So I can come back with specific, actionable improvements instead of guessing. Want me to run the scan?",
          });
        }
        if (v !== "yes" && v !== "no") return json({ ok: false, error: 'Please answer "yes" or "no".' }, 400);

        independent.business.wants_site_scan = (v === "yes");
        await upsertSessionVars(session_id, "onboarding_v8", independent, dependent);

        if (v === "yes") {
          {
            const denied = ensureExpensiveActionAllowed(dependent);
            if (denied) return denied;
          }
          const targetUrl = bestScanTarget(independent);
          if (!targetUrl) {
            return await reply({
              ok: true,
              next_state: "Q_SCAN_URL",
              prompt: "Perfect — paste the website URL you want scanned, and I’ll run it now.",
            });
          }

          try {
            const started = await startSiteScan(session_id, targetUrl);
            dependent.scan = {
              status: started.status || "running",
              request_id: started.request_id || null,
              latest_summary: null,
            };
            independent.business.own_site_url = targetUrl;
            await upsertSessionVars(session_id, "onboarding_v8", independent, dependent);

            return await reply({
              ok: true,
              next_state: "Q3_VIEW_EXAMPLES_YN",
              prompt:
                `Perfect — I started a scan for ${targetUrl}. ` +
                "I’ll use those insights while we continue. Would you be willing to view a few example sites with me and tell me what you like or don’t like?",
            });
          } catch (error) {
            return await reply({
              ok: true,
              next_state: "Q_SCAN_URL",
              prompt:
                "I couldn't start the scan automatically. Paste the exact website URL and I’ll retry the scan now.",
            });
          }
        }

        return await reply({
          ok: true,
          next_state: "Q3_VIEW_EXAMPLES_YN",
          prompt: "No problem. Would you still be willing to view a few example sites with me and tell me what you like or don’t like?",
        });
      }

      if (state === "Q_SCAN_URL") {
        const targetUrl = toHttpsUrl(extractUrlFromText(answer));
        if (!targetUrl) return json({ ok: false, error: "Please paste a valid URL so I can run the scan." }, 400);
        {
          const denied = ensureExpensiveActionAllowed(dependent);
          if (denied) return denied;
        }

        try {
          const started = await startSiteScan(session_id, targetUrl);
          independent.business.own_site_url = targetUrl;
          independent.business.wants_site_scan = true;
          dependent.scan = {
            status: started.status || "running",
            request_id: started.request_id || null,
            latest_summary: null,
          };
          await upsertSessionVars(session_id, "onboarding_v8", independent, dependent);

          return await reply({
            ok: true,
            next_state: "Q3_VIEW_EXAMPLES_YN",
            prompt:
              `Scan started for ${targetUrl}. ` +
              "Would you be willing to view a few example sites with me and tell me what you like or don’t like?",
          });
        } catch (error) {
          return json({ ok: false, error: String(error?.message || error) }, 502);
        }
      }

      // Build trial
      if (state === "Q_BUILD_TRIAL_YN") {
        const v = yesNoMaybe(answer);

        if (v === "howknow" || v === "why") {
          return await reply({
            ok: true,
            next_state: "Q_BUILD_TRIAL_YN",
            prompt:
              "Totally fair — you’ll see a real demo before committing. It’s free for a month, no credit card, and if you don’t like it you can walk away. Want me to build the demo?",
          });
        }

        if (v === "maybe") {
          const funnelSummary = buildFunnelCtaActions(dependent);
          return await reply({
            ok: true,
            next_state: "DONE",
            prompt: "No problem — we can skip the demo for now. If you want to move ahead with plugin setup, just reply \"plugin install\".",
            funnel_stage: funnelSummary.stage,
            upgrade_score: funnelSummary.score,
            cta_actions: funnelSummary.actions,
          });
        }

        if (v !== "yes" && v !== "no") return json({ ok: false, error: 'Please answer "yes" or "no".' }, 400);

        independent.business.wants_free_trial_build = (v === "yes");
        await upsertSessionVars(session_id, "onboarding_v8", independent, dependent);

        if (v === "no") {
          return await reply({ ok: true, next_state: "DONE", prompt: "No problem. If you change your mind, come back anytime." });
        }

        return await reply({
          ok: true,
          next_state: "Q4_BIZNAME",
          prompt: 'What’s your business name? If you don’t have one yet, type “none” and I’ll propose a few.',
        });
      }

      // Business name -> proposals -> DDG -> confirm
      if (state === "Q4_BIZNAME") {
        const txt = String(answer || "").trim();
        if (!txt) return json({ ok: false, error: "Please enter a business name or type none." }, 400);

        const lower = txt.toLowerCase();
        if (lower === "none" || lower === "not sure" || lower === "no name" || lower === "dont have one") {
          const sa = independent.build.service_area || "";
          const proposals = proposeBusinessNames(independent.business.type_final, sa);
          dependent.name_proposals = proposals;
          await upsertSessionVars(session_id, "onboarding_v8", independent, dependent);

          return await reply({
            ok: true,
            next_state: "Q4_BIZNAME_PICK",
            prompt:
              "Here are a few business name ideas:\n" +
              `1) ${proposals[0]}\n2) ${proposals[1]}\n3) ${proposals[2]}\n\n` +
              "Reply with 1, 2, or 3 — or type your own name.",
          });
        }

        independent.build.business_name = txt;
        await upsertSessionVars(session_id, "onboarding_v8", independent, dependent);

        const urlGuess = await searchTopUrlDuckDuckGo(txt);
        independent.build.website_guess = urlGuess || null;
        await upsertSessionVars(session_id, "onboarding_v8", independent, dependent);

        if (!urlGuess) {
          return await reply({
            ok: true,
            next_state: "Q4_WEBSITE_PASTE",
            prompt: `I couldn’t find a clear website for "${txt}". Please paste your website URL (or say “no website yet”).`,
          });
        }

        return await reply({
          ok: true,
          next_state: "Q4_WEBSITE_CONFIRM",
          prompt: `I found this website for "${txt}": ${urlGuess} — is that your website?`,
        });
      }

      if (state === "Q4_BIZNAME_PICK") {
        const txt = String(answer || "").trim();
        const proposals = Array.isArray(dependent.name_proposals) ? dependent.name_proposals : [];

        if (/^[123]$/.test(txt) && proposals.length >= 3) {
          independent.build.business_name = proposals[Number(txt) - 1];
        } else {
          if (!txt) return json({ ok: false, error: "Reply 1/2/3 or type a business name." }, 400);
          independent.build.business_name = txt;
        }

        await upsertSessionVars(session_id, "onboarding_v8", independent, dependent);

        const urlGuess = await searchTopUrlDuckDuckGo(independent.build.business_name);
        independent.build.website_guess = urlGuess || null;
        await upsertSessionVars(session_id, "onboarding_v8", independent, dependent);

        if (!urlGuess) {
          return await reply({
            ok: true,
            next_state: "Q4_WEBSITE_PASTE",
            prompt: `I couldn’t find a clear website for "${independent.build.business_name}". Please paste your website URL (or say “no website yet”).`,
          });
        }

        return await reply({
          ok: true,
          next_state: "Q4_WEBSITE_CONFIRM",
          prompt: `I found this website for "${independent.build.business_name}": ${urlGuess} — is that your website?`,
        });
      }

      if (state === "Q4_WEBSITE_CONFIRM") {
        const v = yesNoMaybe(answer);
        if (v !== "yes" && v !== "no") return json({ ok: false, error: 'Please answer "yes" or "no".' }, 400);

        if (v === "yes") {
          independent.business.own_site_url = independent.build.website_guess;
          independent.business.own_site_confirmed = true;
          await upsertSessionVars(session_id, "onboarding_v8", independent, dependent);

          return await reply({
            ok: true,
            next_state: "Q5_LOCATION_MODE",
            prompt: 'Do you want your address shown on the website, or do you only serve an area? Reply "1" for address or "2" for service area.',
          });
        }

        return await reply({
          ok: true,
          next_state: "Q4_WEBSITE_PASTE",
          prompt: 'Please paste the correct website URL (or say “no website yet”).',
        });
      }

      if (state === "Q4_WEBSITE_PASTE") {
        const txt = String(answer || "").trim();
        const foundUrl = extractUrlFromText(txt);

        if (foundUrl) {
          independent.business.own_site_url = toHttpsUrl(foundUrl);
          independent.business.own_site_confirmed = true;
          await upsertSessionVars(session_id, "onboarding_v8", independent, dependent);

          return await reply({
            ok: true,
            next_state: "Q5_LOCATION_MODE",
            prompt: 'Do you want your address shown on the website, or do you only serve an area? Reply "1" for address or "2" for service area.',
          });
        }

        const v = yesNoMaybe(txt);
        if (v === "no") {
          independent.business.own_site_url = null;
          independent.business.own_site_confirmed = false;
          await upsertSessionVars(session_id, "onboarding_v8", independent, dependent);

          return await reply({
            ok: true,
            next_state: "Q5_LOCATION_MODE",
            prompt: 'No problem. Do you want your address shown on the website, or do you only serve an area? Reply "1" for address or "2" for service area.',
          });
        }

        return json({ ok: false, error: "Please paste a URL or say “no website yet”." }, 400);
      }

      // Location mode + address/service area
      if (state === "Q5_LOCATION_MODE") {
        const mode = parseLocationMode(answer);
        if (!mode) return json({ ok: false, error: 'Please reply "1" (address) or "2" (service area).' }, 400);

        independent.build.location_mode = mode;
        await upsertSessionVars(session_id, "onboarding_v8", independent, dependent);

        if (mode === "address") {
          return await reply({ ok: true, next_state: "Q5_ADDRESS", prompt: "Please type the address you want shown on your website." });
        }
        return await reply({ ok: true, next_state: "Q5_SERVICE_AREA", prompt: "What city/region do you serve? (example: Reno, NV or Lake Tahoe area)" });
      }

      if (state === "Q5_ADDRESS") {
        const txt = String(answer || "").trim();
        if (!txt) return json({ ok: false, error: "Please type an address." }, 400);

        independent.build.address = txt;
        await upsertSessionVars(session_id, "onboarding_v8", independent, dependent);

        return await reply({
          ok: true,
          next_state: "Q6_VIBE",
          prompt: "What vibe do you want your website to feel like? (examples: modern, adventurous, luxury, friendly, minimal)",
        });
      }

      if (state === "Q5_SERVICE_AREA") {
        const txt = String(answer || "").trim();
        if (!txt) return json({ ok: false, error: "Please type a city/region." }, 400);

        independent.build.service_area = txt;
        await upsertSessionVars(session_id, "onboarding_v8", independent, dependent);

        return await reply({
          ok: true,
          next_state: "Q6_VIBE",
          prompt: "What vibe do you want your website to feel like? (examples: modern, adventurous, luxury, friendly, minimal)",
        });
      }

      // Style questions
      if (state === "Q6_VIBE") {
        independent.build.vibe = String(answer || "").trim().slice(0, 200) || null;
        await upsertSessionVars(session_id, "onboarding_v8", independent, dependent);

        return await reply({
          ok: true,
          next_state: "Q6_COLORS",
          prompt: "Any color preferences? (examples: blue/teal, black/gold, white/clean, no preference)",
        });
      }

      if (state === "Q6_COLORS") {
        independent.build.colors = String(answer || "").trim().slice(0, 200) || null;
        await upsertSessionVars(session_id, "onboarding_v8", independent, dependent);

        return await reply({ ok: true, next_state: "Q6_GOAL", prompt: "What’s the #1 goal for the site? (bookings, phone calls, leads, info/portfolio)" });
      }

      if (state === "Q6_GOAL") {
        independent.build.goal = String(answer || "").trim().slice(0, 200) || null;
        await upsertSessionVars(session_id, "onboarding_v8", independent, dependent);

        return await reply({
          ok: true,
          next_state: "Q7_PHONE",
          prompt: "What’s the best phone number to reach you at? (You can type “skip” if you prefer.)",
        });
      }

      if (state === "Q7_PHONE") {
        const txt = String(answer || "").trim();
        if (!txt) return json({ ok: false, error: "Please enter a phone number or type skip." }, 400);

        independent.build.phone = isSkip(txt) ? null : normalizePhone(txt) || txt;
        await upsertSessionVars(session_id, "onboarding_v8", independent, dependent);

        return await reply({
          ok: true,
          next_state: "Q7_EMAIL",
          prompt: "What’s the best email to reach you at? (You can type “skip” if you prefer.)",
        });
      }

      if (state === "Q7_EMAIL") {
        const txt = String(answer || "").trim();
        if (!txt) return json({ ok: false, error: "Please enter an email or type skip." }, 400);

        if (isSkip(txt)) {
          independent.build.email = null;
        } else {
          if (!isLikelyEmail(txt)) return json({ ok: false, error: "That email doesn’t look valid. Try again or type skip." }, 400);
          independent.build.email = txt;
        }

        let demo = null;
        {
          const denied = ensureExpensiveActionAllowed(dependent);
          if (denied) return denied;
        }
        try {
          demo = await publishDemoSite(session_id, independent, dependent);
        } catch {}

        if (demo) {
          dependent.demo_build = {
            key: demo.key || null,
            url: demo.url || null,
          };
        }

        await upsertSessionVars(session_id, "onboarding_v8", independent, dependent);
        await persistPreferenceSnapshot(session_id, independent, dependent);
        const funnelSummary = buildFunnelCtaActions(dependent);
        const connectAction = (funnelSummary.actions || []).find((a) => a.id === "connect_cloudflare");
        const migrateAction = (funnelSummary.actions || []).find((a) => a.id === "migrate_hosting");
        const extraLines = [];
        if (connectAction?.url) extraLines.push(`Connect Cloudflare to activate your free 1-month hosting + subdomain: ${connectAction.url}`);
        if (migrateAction?.url) extraLines.push(`Ready for full managed migration? ${migrateAction.url}`);
        const ctaText = extraLines.length ? `\n\n${extraLines.join("\n")}` : "";

        return await reply({
          ok: true,
          next_state: "DONE",
          prompt:
            demo?.url
              ? `Perfect. Your first demo site is ready: ${demo.url} . Review it and reply with edits, and I’ll iterate from your feedback.${ctaText}`
              : `Perfect. I stored your design preferences and generated your first static demo draft in storage. Next I can publish a public subdomain link once DEMO_PUBLIC_BASE_URL is configured.${ctaText}`,
          demo_site_url: demo?.url || null,
          demo_storage_key: demo?.key || null,
          funnel_stage: funnelSummary.stage,
          upgrade_score: funnelSummary.score,
          cta_actions: funnelSummary.actions,
        });
      }

      return json({ ok: false, error: `State not implemented yet: ${state}` }, 400);
    }

    return json({ ok: false, error: "Not Found" }, 404);
  },
};
