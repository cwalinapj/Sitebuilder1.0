import { verifyMessage } from "viem";
import nacl from "tweetnacl";
import bs58 from "bs58";

/* worker/index.js */
const START_RATE_LIMIT_WINDOW_MS = 60 * 1000;
const START_RATE_LIMIT_MAX = 12;
const WALLET_CHALLENGE_TTL_MS = 10 * 60 * 1000;
const startRateLimitMap = new Map();
const endpointRateLimitMap = new Map();
const walletChallengeMap = new Map();
const REFERENCE_BLOCKED_ROOT_DOMAINS = new Set([
  "wordpress.com",
  "medium.com",
  "blogger.com",
  "wix.com",
  "tumblr.com",
  "weebly.com",
  "google.com",
  "livejournal.com",
  "zoho.com",
  "hubpages.com",
  "reddit.com",
  "trustpilot.com",
  "crunchbase.com",
  "angel.co",
  "angellist.com",
  "yellowpages.com",
  "justlanded.com",
  "reviewcentre.com",
  "blogarama.com",
  "lacartes.com",
  "tupalo.com",
  "ebusinesspages.com",
  "seekingalpha.com",
  "ehow.com",
  "biggerpockets.com",
  "brighthub.com",
  "articlesfactory.com",
  "articlealley.com",
  "webpronews.com",
  "idleexperts.com",
  "sharehealthtips.com",
  "uberarticles.com",
  "youtube.com",
  "facebook.com",
  "instagram.com",
  "wikipedia.org",
  "twitter.com",
  "linkedin.com",
  "pinterest.com",
  "tiktok.com",
  "amazon.com",
  "freefind.com",
  "viesearch.com",
  "ontoplist.com",
  "exactseek.com",
  "000directory.com.ar",
  "directory6.org",
  "submissionwebdirectory.com",
  "cipinet.com",
  "linkz.us",
  "somuch.com",
  "vk.com",
  "behance.net",
  "soundcloud.com",
  "dribbble.com",
  "issuu.com",
  "flickr.com",
  "squarespace.com",
  "webstarts.com",
  "micro.blog",
  "latimes.com",
  "netflix.com",
  "hbo.com",
  "hbomax.com",
  "hulu.com",
  "disneyplus.com",
  "tripadvisor.com",
  "yelp.com",
]);
const REFERENCE_BLOCKED_HOST_KEYWORDS = [
  "news",
  "entertainment",
  "streaming",
  "movies",
  "tv",
];

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
    const configuredReferenceBlockedRoots = new Set(
      String(env.REFERENCE_SITE_BLOCKLIST || "")
        .split(",")
        .map((x) => x.trim().toLowerCase())
        .filter(Boolean)
    );
    const configuredReferenceBlockedKeywords = String(env.REFERENCE_SITE_BLOCKLIST_KEYWORDS || "")
      .split(",")
      .map((x) => x.trim().toLowerCase())
      .filter(Boolean);

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

    function cleanupWalletChallenges(nowTs) {
      if (walletChallengeMap.size <= 10000) {
        for (const [nonce, entry] of walletChallengeMap.entries()) {
          if (!entry || Number(entry.expires_at || 0) <= nowTs) walletChallengeMap.delete(nonce);
        }
        return;
      }
      for (const [nonce, entry] of walletChallengeMap.entries()) {
        if (!entry || Number(entry.expires_at || 0) <= nowTs) walletChallengeMap.delete(nonce);
      }
    }

    function toBase64Url(bytes) {
      let s = "";
      for (const b of bytes) s += String.fromCharCode(b);
      return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
    }

    function fromHexToBytes(hex) {
      const cleaned = String(hex || "").trim().toLowerCase().replace(/^0x/, "");
      if (!cleaned || cleaned.length % 2 !== 0 || /[^0-9a-f]/.test(cleaned)) return null;
      const out = new Uint8Array(cleaned.length / 2);
      for (let i = 0; i < out.length; i += 1) {
        out[i] = Number.parseInt(cleaned.slice(i * 2, i * 2 + 2), 16);
      }
      return out;
    }

    function fromBase64ToBytes(raw) {
      const text = String(raw || "").trim();
      if (!text) return null;
      try {
        const norm = text.replace(/-/g, "+").replace(/_/g, "/");
        const padded = norm + "=".repeat((4 - (norm.length % 4 || 4)) % 4);
        const decoded = atob(padded);
        const out = new Uint8Array(decoded.length);
        for (let i = 0; i < decoded.length; i += 1) out[i] = decoded.charCodeAt(i);
        return out;
      } catch {
        return null;
      }
    }

    function normalizeWalletProvider(raw) {
      const p = String(raw || "")
        .trim()
        .toLowerCase();
      if (["metamask", "walletconnect", "ledger", "phantom"].includes(p)) return p;
      return null;
    }

    function normalizeWalletProtocol(raw) {
      const p = String(raw || "")
        .trim()
        .toLowerCase();
      if (p === "evm" || p === "solana") return p;
      return null;
    }

    function normalizeWalletChainId(raw) {
      if (typeof raw === "number" && Number.isFinite(raw)) return Math.max(1, Math.round(raw));
      const text = String(raw || "").trim();
      if (!text) return null;
      if (/^0x[0-9a-f]+$/i.test(text)) return Math.max(1, parseInt(text, 16) || 1);
      const n = Number(text);
      if (!Number.isFinite(n)) return null;
      return Math.max(1, Math.round(n));
    }

    function shortWalletAddress(address) {
      const s = String(address || "").trim();
      if (!s) return "wallet";
      if (s.length <= 12) return s;
      return `${s.slice(0, 6)}…${s.slice(-4)}`;
    }

    function issueWalletChallenge(provider, protocol, host, tsNow) {
      const nonceBytes = crypto.getRandomValues(new Uint8Array(16));
      const nonce = toBase64Url(nonceBytes);
      const issuedAt = Number(tsNow) || Date.now();
      const expiresAt = issuedAt + WALLET_CHALLENGE_TTL_MS;
      const message =
        "Sitebuilder Wallet Sign-In\n" +
        `Domain: ${String(host || "sitebuilder")}\n` +
        `Provider: ${provider}\n` +
        `Protocol: ${protocol}\n` +
        `Nonce: ${nonce}\n` +
        `Issued At: ${new Date(issuedAt).toISOString()}\n` +
        `Expires At: ${new Date(expiresAt).toISOString()}\n` +
        "Purpose: Start a secure onboarding session without typing your name.";

      walletChallengeMap.set(nonce, {
        nonce,
        provider,
        protocol,
        host: String(host || "").toLowerCase(),
        issued_at: issuedAt,
        expires_at: expiresAt,
        message,
        used: false,
      });
      cleanupWalletChallenges(issuedAt);

      return {
        nonce,
        message,
        issued_at: issuedAt,
        expires_at: expiresAt,
      };
    }

    async function verifyWalletStartPayload(body, host, tsNow) {
      const walletAuth = body?.wallet_auth && typeof body.wallet_auth === "object" ? body.wallet_auth : {};
      const provider = normalizeWalletProvider(walletAuth.provider);
      const protocol = normalizeWalletProtocol(walletAuth.protocol);
      const nonce = String(walletAuth.nonce || "").trim();
      const message = String(walletAuth.message || "").trim();
      const signature = String(walletAuth.signature || "").trim();
      const addressRaw = String(walletAuth.address || "").trim();

      if (!provider || !protocol) {
        return { ok: false, status: 400, error: "wallet_auth.provider and wallet_auth.protocol are required." };
      }
      if (!nonce || !message || !signature || !addressRaw) {
        return { ok: false, status: 400, error: "wallet_auth requires nonce, message, signature, and address." };
      }

      const challenge = walletChallengeMap.get(nonce);
      if (!challenge) return { ok: false, status: 401, error: "Wallet challenge is missing or expired." };
      if (challenge.used) return { ok: false, status: 401, error: "Wallet challenge was already used." };
      if (Number(challenge.expires_at || 0) <= tsNow) {
        walletChallengeMap.delete(nonce);
        return { ok: false, status: 401, error: "Wallet challenge expired. Please reconnect your wallet." };
      }
      if (String(challenge.message || "") !== message) {
        return { ok: false, status: 401, error: "Wallet challenge message mismatch." };
      }
      if (challenge.provider !== provider || challenge.protocol !== protocol) {
        return { ok: false, status: 401, error: "Wallet challenge provider/protocol mismatch." };
      }
      if (protocol === "evm") {
        const address = /^0x[a-f0-9]{40}$/i.test(addressRaw) ? addressRaw : null;
        const evmSig = /^0x[a-f0-9]{130}$/i.test(signature) ? signature : null;
        if (!address || !evmSig) {
          return { ok: false, status: 400, error: "Invalid EVM address/signature format." };
        }
        const verified = await verifyMessage({ address, message, signature: evmSig });
        if (!verified) return { ok: false, status: 401, error: "Wallet signature verification failed." };
        challenge.used = true;
        const chainId = normalizeWalletChainId(walletAuth.chain_id);
        return {
          ok: true,
          greeting_name: `wallet ${shortWalletAddress(address)}`,
          person: {
            auth_method: "wallet",
            wallet: {
              provider,
              protocol,
              address,
              chain_id: chainId,
              nonce,
              verified_at: tsNow,
            },
          },
        };
      }

      const pubKeyBytes = (() => {
        try {
          return bs58.decode(addressRaw);
        } catch {
          return null;
        }
      })();
      if (!pubKeyBytes || pubKeyBytes.length !== 32) {
        return { ok: false, status: 400, error: "Invalid Solana wallet address format." };
      }
      const sigBytes =
        fromBase64ToBytes(signature) ||
        (() => {
          try {
            return bs58.decode(signature);
          } catch {
            return null;
          }
        })() ||
        fromHexToBytes(signature);
      if (!sigBytes || sigBytes.length !== 64) {
        return { ok: false, status: 400, error: "Invalid Solana signature format." };
      }
      const msgBytes = new TextEncoder().encode(message);
      const verified = nacl.sign.detached.verify(msgBytes, sigBytes, pubKeyBytes);
      if (!verified) return { ok: false, status: 401, error: "Wallet signature verification failed." };

      challenge.used = true;
      return {
        ok: true,
        greeting_name: `wallet ${shortWalletAddress(addressRaw)}`,
        person: {
          auth_method: "wallet",
          wallet: {
            provider,
            protocol,
            address: addressRaw,
            chain_id: walletAuth.chain_id ? String(walletAuth.chain_id).slice(0, 64) : null,
            nonce,
            verified_at: tsNow,
          },
        },
      };
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
        await env.DB.prepare("INSERT OR IGNORE INTO users(user_id, first_name, created_at) VALUES (?,?,?)")
          .bind(user_id, first_name, created_at)
          .run();
      } catch {
        // Backward compatibility for older schema that lacks users.first_name.
        await env.DB.prepare("INSERT OR IGNORE INTO users(user_id, created_at) VALUES (?,?)").bind(user_id, created_at).run();
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
        a_record_primary_ip: null,
        a_record_ips: [],
        hosting_company: null,
        hosting_type_hint: null,
        hosting_cost_estimate: null,
        domain_expires_at: null,
        email_provider: null,
        third_party_vendors: {},
        server_hardware_hints: null,
        broken_links: { checked_count: 0, broken_count: 0, broken_paths: [] },
        last_scanned_at: null,
      };
      if (!Array.isArray(independent.business.tech_profile.nameservers)) independent.business.tech_profile.nameservers = [];
      if (!Array.isArray(independent.business.tech_profile.ip_addresses)) independent.business.tech_profile.ip_addresses = [];
      if (!Array.isArray(independent.business.tech_profile.a_record_ips)) independent.business.tech_profile.a_record_ips = [];
      if (!independent.business.tech_profile.hosting_type_hint) independent.business.tech_profile.hosting_type_hint = null;
      if (!independent.business.tech_profile.hosting_cost_estimate) independent.business.tech_profile.hosting_cost_estimate = null;
      if (!Object.prototype.hasOwnProperty.call(independent.business.tech_profile, "a_record_primary_ip")) {
        independent.business.tech_profile.a_record_primary_ip = null;
      }
      if (dnsProfile || infrastructure || vendors || linkAudit) {
        independent.business.tech_profile.registrar = infrastructure?.registrar || independent.business.tech_profile.registrar;
        independent.business.tech_profile.nameservers = Array.isArray(dnsProfile?.ns_records)
          ? dnsProfile.ns_records.slice(0, 12)
          : independent.business.tech_profile.nameservers;
        independent.business.tech_profile.ip_addresses = Array.isArray(infrastructure?.ip_addresses)
          ? infrastructure.ip_addresses.slice(0, 12)
          : independent.business.tech_profile.ip_addresses;
        independent.business.tech_profile.a_record_primary_ip =
          infrastructure?.a_record_primary_ip || independent.business.tech_profile.a_record_primary_ip;
        independent.business.tech_profile.a_record_ips = Array.isArray(infrastructure?.a_record_ips)
          ? infrastructure.a_record_ips.slice(0, 12)
          : independent.business.tech_profile.a_record_ips || [];
        independent.business.tech_profile.hosting_company =
          infrastructure?.hosting_company || independent.business.tech_profile.hosting_company;
        independent.business.tech_profile.hosting_type_hint =
          infrastructure?.hosting_type_hint || independent.business.tech_profile.hosting_type_hint;
        independent.business.tech_profile.hosting_cost_estimate =
          infrastructure?.hosting_cost_estimate || independent.business.tech_profile.hosting_cost_estimate || null;
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

    function extractUsZipCode(text) {
      const t = String(text || "");
      const m = t.match(/\b(\d{5})(?:-\d{4})?\b/);
      return m ? m[1] : null;
    }

    function deriveReferenceLocationVars(scanResult, sourceUrl) {
      const addresses = Array.isArray(scanResult?.addresses) ? scanResult.addresses : [];
      const firstAddress = pickFirstValid(addresses);
      const zipCode = extractUsZipCode(firstAddress);
      let city = null;
      let region = null;
      if (firstAddress) {
        const m = firstAddress.match(/,\s*([A-Za-z .'-]+),\s*([A-Z]{2})\s+\d{5}(?:-\d{4})?\b/);
        if (m) {
          city = String(m[1] || "").trim() || null;
          region = String(m[2] || "").trim() || null;
        }
      }
      const locationHint = city && region ? `${city}, ${region}` : firstAddress ? firstAddress.slice(0, 140) : null;
      const summary = zipCode
        ? `I scanned that reference and saved location signals (ZIP ${zipCode}).`
        : firstAddress
          ? "I scanned that reference and saved its location signals."
          : null;
      return {
        source_url: sanitizeReferenceUrl(sourceUrl),
        scanned_at: now(),
        address: firstAddress ? firstAddress.slice(0, 220) : null,
        zip_code: zipCode,
        city,
        region,
        location_hint: locationHint,
        summary,
      };
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
      const normalizedSites = normalizeReferenceSites(payload?.sites, exclude_urls);
      return {
        ...payload,
        sites: normalizedSites,
      };
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
          design_profile: dependent?.design?.profile || null,
          analysis: dependent?.analysis || null,
        },
        null,
        2
      );
      await bucket.put(key, body, { httpMetadata: { contentType: "application/json" } });
      return key;
    }

    function extractColorHintsFromText(text) {
      const lower = String(text || "").toLowerCase();
      if (!lower) return [];
      const colorWords = [
        "blue",
        "teal",
        "green",
        "orange",
        "red",
        "black",
        "white",
        "gold",
        "navy",
        "gray",
        "grey",
        "yellow",
        "purple",
      ];
      const out = [];
      for (const word of colorWords) {
        if (new RegExp(`\\b${word}\\b`, "i").test(lower)) out.push(word === "grey" ? "gray" : word);
      }
      return Array.from(new Set(out));
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

      const paletteHints = extractColorHintsFromText(lower);

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

    function ensureDesignState(dependent) {
      dependent.design = dependent.design || {};
      dependent.design.liked = Array.isArray(dependent.design.liked) ? dependent.design.liked : [];
      dependent.design.disliked = Array.isArray(dependent.design.disliked) ? dependent.design.disliked : [];
      dependent.design.palette_hints = Array.isArray(dependent.design.palette_hints) ? dependent.design.palette_hints : [];
      dependent.design.layout_hints = Array.isArray(dependent.design.layout_hints) ? dependent.design.layout_hints : [];
      dependent.design.font_hints = Array.isArray(dependent.design.font_hints) ? dependent.design.font_hints : [];
      dependent.design.raw_feedback = Array.isArray(dependent.design.raw_feedback) ? dependent.design.raw_feedback : [];
      dependent.design.reference_feedback = Array.isArray(dependent.design.reference_feedback) ? dependent.design.reference_feedback : [];
      dependent.design.palette_options = Array.isArray(dependent.design.palette_options) ? dependent.design.palette_options : [];
      dependent.design.selected_palette =
        dependent.design.selected_palette && typeof dependent.design.selected_palette === "object"
          ? dependent.design.selected_palette
          : null;
      dependent.design.profile =
        dependent.design.profile && typeof dependent.design.profile === "object" ? dependent.design.profile : null;
      return dependent.design;
    }

    function ensureResearchState(dependent) {
      dependent.research = dependent.research || {};
      dependent.research.location_hint = dependent.research.location_hint || null;
      dependent.research.intent_text = dependent.research.intent_text || null;
      dependent.research.intent_raw = dependent.research.intent_raw || null;
      dependent.research.intent_draft = dependent.research.intent_draft || null;
      dependent.research.intent_source = dependent.research.intent_source || null;
      dependent.research.sites = Array.isArray(dependent.research.sites) ? dependent.research.sites : [];
      dependent.research.source = dependent.research.source || null;
      dependent.research.current_site_index = Number.isFinite(Number(dependent.research.current_site_index))
        ? Math.max(0, Math.round(Number(dependent.research.current_site_index)))
        : 0;
      dependent.research.refresh_count = Number.isFinite(Number(dependent.research.refresh_count))
        ? Math.max(0, Math.round(Number(dependent.research.refresh_count)))
        : 0;
      dependent.research.user_reference_url = sanitizeReferenceUrl(dependent.research.user_reference_url) || null;
      dependent.research.same_zip_as_reference = dependent.research.same_zip_as_reference || null;
      dependent.research.reference_location =
        dependent.research.reference_location && typeof dependent.research.reference_location === "object"
          ? dependent.research.reference_location
          : null;
      return dependent.research;
    }

    function ensurePatternAnalysisState(dependent) {
      dependent.analysis = dependent.analysis || {};
      dependent.analysis.turns_processed = Number.isFinite(Number(dependent.analysis.turns_processed))
        ? Math.max(0, Math.round(Number(dependent.analysis.turns_processed)))
        : 0;
      dependent.analysis.preference_events = Number.isFinite(Number(dependent.analysis.preference_events))
        ? Math.max(0, Math.round(Number(dependent.analysis.preference_events)))
        : 0;
      dependent.analysis.preference_shifts = Number.isFinite(Number(dependent.analysis.preference_shifts))
        ? Math.max(0, Math.round(Number(dependent.analysis.preference_shifts)))
        : 0;
      dependent.analysis.frustration_signals = Number.isFinite(Number(dependent.analysis.frustration_signals))
        ? Math.max(0, Math.round(Number(dependent.analysis.frustration_signals)))
        : 0;
      dependent.analysis.positive_signals = Number.isFinite(Number(dependent.analysis.positive_signals))
        ? Math.max(0, Math.round(Number(dependent.analysis.positive_signals)))
        : 0;
      dependent.analysis.clarification_requests = Number.isFinite(Number(dependent.analysis.clarification_requests))
        ? Math.max(0, Math.round(Number(dependent.analysis.clarification_requests)))
        : 0;
      dependent.analysis.last_user_input = String(dependent.analysis.last_user_input || "");
      dependent.analysis.last_summary = String(dependent.analysis.last_summary || "");
      dependent.analysis.last_updated_at = dependent.analysis.last_updated_at || null;
      return dependent.analysis;
    }

    function ensureBuildBriefState(dependent) {
      dependent.build_brief = dependent.build_brief && typeof dependent.build_brief === "object" ? dependent.build_brief : {};
      const b = dependent.build_brief;
      b.persona = b.persona || null;
      b.audience = b.audience || null;
      b.primary_goal = b.primary_goal || null;
      b.secondary_goal = b.secondary_goal || null;
      b.tertiary_goal = b.tertiary_goal || null;
      b.offer_type = b.offer_type || null;
      b.repo_sale_model = b.repo_sale_model || null;
      b.payment_provider = b.payment_provider || null;
      b.style_pref = b.style_pref || null;
      b.dark_mode_friendly = b.dark_mode_friendly !== false;
      b.lead_capture = b.lead_capture !== false;
      b.stack_preference = b.stack_preference || null;
      b.stack_choice = b.stack_choice || null;
      b.stacks = Array.isArray(b.stacks) ? b.stacks.filter(Boolean).slice(0, 8) : [];
      b.trust_signals = Array.isArray(b.trust_signals) ? b.trust_signals.filter(Boolean).slice(0, 8) : [];
      b.ask_only_if_required = Array.isArray(b.ask_only_if_required) && b.ask_only_if_required.length
        ? b.ask_only_if_required.slice(0, 6)
        : ["name_or_brand", "preferred_colors", "payment_provider"];
      b.compiled_prompt = typeof b.compiled_prompt === "string" ? b.compiled_prompt : null;
      b.compiled_summary = typeof b.compiled_summary === "string" ? b.compiled_summary : null;
      b.compiled_at = Number.isFinite(Number(b.compiled_at)) ? Number(b.compiled_at) : null;
      b.version = Number.isFinite(Number(b.version)) ? Number(b.version) : 1;
      return b;
    }

    function premiumBuilderEnabled() {
      const raw = String(env.PREMIUM_BUILDER_ENABLED || "").trim().toLowerCase();
      if (!raw) return true;
      return !["0", "false", "off", "no"].includes(raw);
    }

    function premiumWalletRequired() {
      const raw = String(env.PREMIUM_WALLET_REQUIRED || "").trim().toLowerCase();
      if (!raw) return true;
      return !["0", "false", "off", "no"].includes(raw);
    }

    function premiumPointsEnabled() {
      const raw = String(env.PREMIUM_POINTS_ENABLED || "").trim().toLowerCase();
      if (!raw) return true;
      return !["0", "false", "off", "no"].includes(raw);
    }

    function normalizedPremiumFreeTokens() {
      const n = Number(env.PREMIUM_FREE_TOKENS);
      if (!Number.isFinite(n)) return 1200;
      return Math.max(0, Math.min(500000, Math.round(n)));
    }

    function normalizedPremiumFreePoints() {
      const n = Number(env.PREMIUM_FREE_POINTS);
      if (!Number.isFinite(n)) return 800;
      return Math.max(0, Math.min(5000000, Math.round(n)));
    }

    function normalizedPremiumBaseCost() {
      const n = Number(env.PREMIUM_BASE_COST_TOKENS);
      if (!Number.isFinite(n)) return 180;
      return Math.max(10, Math.min(100000, Math.round(n)));
    }

    function normalizedPremiumPerPageCost() {
      const n = Number(env.PREMIUM_PER_PAGE_COST_TOKENS);
      if (!Number.isFinite(n)) return 90;
      return Math.max(1, Math.min(50000, Math.round(n)));
    }

    function normalizedPremiumPerWordCost() {
      const n = Number(env.PREMIUM_PER_30_WORD_COST_TOKENS);
      if (!Number.isFinite(n)) return 8;
      return Math.max(0, Math.min(10000, Math.round(n)));
    }

    function normalizedPremiumComplexityCost() {
      const n = Number(env.PREMIUM_COMPLEXITY_UNIT_COST_TOKENS);
      if (!Number.isFinite(n)) return 30;
      return Math.max(0, Math.min(50000, Math.round(n)));
    }

    function normalizedTokensPerSpl() {
      const n = Number(env.PREMIUM_TOKENS_PER_SPL);
      if (!Number.isFinite(n)) return 1000;
      return Math.max(1, Math.min(10000000, Math.round(n)));
    }

    function normalizedPointsPerToken() {
      const n = Number(env.PREMIUM_POINTS_PER_TOKEN);
      if (!Number.isFinite(n)) return 1;
      return Math.max(1, Math.min(100000, Math.round(n)));
    }

    function premiumSplTokenSymbol() {
      return String(env.PREMIUM_SPL_SYMBOL || "TOLLSPL").trim() || "TOLLSPL";
    }

    function premiumTopupUrl() {
      return String(env.PREMIUM_TOPUP_URL || "").trim() || null;
    }

    function premiumPointsTopupUrl() {
      return String(env.PREMIUM_POINTS_TOPUP_URL || "").trim() || null;
    }

    function premiumPointsSymbol() {
      return String(env.PREMIUM_POINTS_SYMBOL || "PTS").trim() || "PTS";
    }

    function normalizedPointPackPriceUsd() {
      const n = Number(env.PREMIUM_POINTS_PACK_PRICE_USD);
      if (!Number.isFinite(n)) return 9.99;
      return Math.max(0.5, Math.min(10000, Math.round(n * 100) / 100));
    }

    function normalizedPointPackAmount() {
      const n = Number(env.PREMIUM_POINTS_PACK_AMOUNT);
      if (!Number.isFinite(n)) return 1200;
      return Math.max(10, Math.min(5000000, Math.round(n)));
    }

    function premiumPointsCheckoutUrl() {
      return String(env.PREMIUM_POINTS_CHECKOUT_URL || "").trim() || null;
    }

    function premiumAdRewardsEnabled() {
      const raw = String(env.PREMIUM_AD_REWARDS_ENABLED || "").trim().toLowerCase();
      if (!raw) return false;
      return !["0", "false", "off", "no"].includes(raw);
    }

    function normalizedAdRewardPoints() {
      const n = Number(env.PREMIUM_AD_REWARD_POINTS);
      if (!Number.isFinite(n)) return 40;
      return Math.max(1, Math.min(100000, Math.round(n)));
    }

    function normalizedAdRewardCooldownSec() {
      const n = Number(env.PREMIUM_AD_REWARD_COOLDOWN_SEC);
      if (!Number.isFinite(n)) return 300;
      return Math.max(30, Math.min(86400, Math.round(n)));
    }

    function inferRequestedPageCount(text) {
      const t = String(text || "");
      const explicitPages = t.match(/\b(\d{1,2})\s+pages?\b/i);
      if (explicitPages) {
        const n = Number(explicitPages[1]);
        if (Number.isFinite(n) && n > 0) return Math.min(20, Math.max(1, Math.round(n)));
      }

      const numbered = Array.from(t.matchAll(/(?:^|\n)\s*(\d{1,2})\)\s+/g));
      if (numbered.length) {
        const maxNum = Math.max(...numbered.map((m) => Number(m[1] || 0)).filter((n) => Number.isFinite(n)));
        if (Number.isFinite(maxNum) && maxNum > 0) return Math.min(20, maxNum);
      }

      if (/\b(one|single)\s+page\b/i.test(t)) return 1;
      return 1;
    }

    function inferPremiumComplexityUnits(text) {
      const t = String(text || "").toLowerCase();
      let score = 0;
      if (/\b(next\.?js|app router|typescript|tailwind|astro|react)\b/.test(t)) score += 2;
      if (/\b(repo detail|dynamic|slug|filters?|search bar|data model|schema)\b/.test(t)) score += 2;
      if (/\b(seo|lighthouse|accessibility|analytics|security)\b/.test(t)) score += 1;
      if (/\b(deliverables|folder structure|readme|deployment|vercel|cloudflare pages)\b/.test(t)) score += 1;
      if (/\b(gumroad|stripe|lemon squeezy|checkout|payment)\b/.test(t)) score += 1;
      if (String(text || "").length > 1200) score += 2;
      return Math.max(0, Math.min(12, score));
    }

    function isPremiumBuilderRequest(text) {
      const raw = String(text || "").trim();
      if (!raw) return false;
      if (raw.length > 900) return true;
      const t = raw.toLowerCase();
      const hasBuildVerb = /\b(build|create|generate|scaffold|produce|ship)\b/.test(t);
      const hasDevSiteContext = /\b(site|website|app|repo|repository|marketplace|portfolio)\b/.test(t);
      const hasStackOrSpec = /\b(next\.?js|typescript|tailwind|app router|deliverables|data model|seo|lighthouse|gumroad|stripe)\b/.test(t);
      return hasBuildVerb && hasDevSiteContext && hasStackOrSpec;
    }

    function estimatePremiumTokenCost(requestText) {
      const text = String(requestText || "").trim();
      const pageCount = inferRequestedPageCount(text);
      const words = text ? text.split(/\s+/).filter(Boolean).length : 0;
      const complexityUnits = inferPremiumComplexityUnits(text);
      const base = normalizedPremiumBaseCost();
      const pageCost = pageCount * normalizedPremiumPerPageCost();
      const wordCost = Math.ceil(words / 30) * normalizedPremiumPerWordCost();
      const complexityCost = complexityUnits * normalizedPremiumComplexityCost();
      const total = Math.max(1, Math.round(base + pageCost + wordCost + complexityCost));
      return {
        tokens: total,
        page_count: pageCount,
        words,
        complexity_units: complexityUnits,
        breakdown: { base, page_cost: pageCost, word_cost: wordCost, complexity_cost: complexityCost },
      };
    }

    function resolvePremiumLlmBackend() {
      const raw = String(env.PREMIUM_LLM_BACKEND || env.LLM_BACKEND || "").trim().toLowerCase();
      if (raw) return raw;
      if (String(env.PREMIUM_LLM_GPU_URL || env.LOCAL_LLM_URL || "").trim()) return "gpu";
      return "external";
    }

    function resolvePremiumGpuEndpoint() {
      const raw = String(env.PREMIUM_LLM_GPU_URL || env.LOCAL_LLM_URL || "").trim();
      return raw || null;
    }

    function premiumBillingUsesGpu(backend) {
      return String(backend || "").toLowerCase() === "gpu";
    }

    function resolvePremiumChargeUnit(billing) {
      if (billing?.wallet_verified) return "tokens";
      if (billing?.points_enabled) return "points";
      return "tokens";
    }

    function estimatePremiumCostInActiveUnit(estimateTokens, billing) {
      const unit = resolvePremiumChargeUnit(billing);
      if (unit === "points") {
        return {
          unit,
          amount: Math.max(1, Math.round(Number(estimateTokens || 0) * Number(billing?.points_per_token || 1))),
          symbol: billing?.points_symbol || "PTS",
        };
      }
      return {
        unit: "tokens",
        amount: Math.max(1, Math.round(Number(estimateTokens || 0))),
        symbol: "tokens",
      };
    }

    function getPremiumActiveTopupUrl(billing) {
      const unit = resolvePremiumChargeUnit(billing);
      if (unit === "points") return billing?.points_topup_url || null;
      return billing?.topup_url || null;
    }

    function buildPremiumQuoteSnapshot(estimate, billing) {
      const safeEstimate = estimate && typeof estimate === "object" ? estimate : { tokens: 0, page_count: 1, complexity_units: 0 };
      const active = estimatePremiumCostInActiveUnit(Number(safeEstimate.tokens || 0), billing);
      const tokenBalance = Math.max(0, Math.round(Number(billing?.token_balance || 0)));
      const pointsBalance = Math.max(0, Math.round(Number(billing?.points_balance || 0)));
      const activeBalance = active.unit === "points" ? pointsBalance : tokenBalance;
      const shortfallAmount = Math.max(0, active.amount - activeBalance);
      const pointsRequired = Math.max(1, Math.round(Number(safeEstimate.tokens || 0) * Number(billing?.points_per_token || 1)));
      const shortfallTokens = Math.max(0, Number(safeEstimate.tokens || 0) - tokenBalance);
      const shortfallPoints = Math.max(0, pointsRequired - pointsBalance);
      return {
        ...safeEstimate,
        charge_unit: active.unit,
        charge_amount: active.amount,
        charge_symbol: active.symbol,
        token_balance: tokenBalance,
        points_balance: pointsBalance,
        active_balance: activeBalance,
        shortfall_amount: shortfallAmount,
        shortfall_tokens: shortfallTokens,
        shortfall_points: shortfallPoints,
      };
    }

    function toPublicPremiumQuote(rawQuote, billing) {
      if (!rawQuote || typeof rawQuote !== "object") return null;
      const snapshot = buildPremiumQuoteSnapshot(rawQuote, billing || {});
      return {
        page_count: Number(snapshot.page_count || 1),
        complexity_units: Number(snapshot.complexity_units || 0),
        charge_unit: snapshot.charge_unit,
        charge_amount: Number(snapshot.charge_amount || 0),
        charge_symbol: snapshot.charge_symbol,
        shortfall_amount: Number(snapshot.shortfall_amount || 0),
        quoted_at: Number.isFinite(Number(rawQuote.quoted_at)) ? Number(rawQuote.quoted_at) : null,
        request_preview: typeof rawQuote.request_preview === "string" ? rawQuote.request_preview : null,
      };
    }

    function ensureBillingState(independent, dependent) {
      dependent.billing = dependent.billing && typeof dependent.billing === "object" ? dependent.billing : {};
      const billing = dependent.billing;
      const person = independent?.person || {};
      const authMethod = String(person?.auth_method || "name");
      const hasWallet = authMethod === "wallet" && person?.wallet && person?.wallet.address;
      billing.model = "hybrid_spl_points_v1";
      billing.spl_symbol = premiumSplTokenSymbol();
      billing.points_symbol = premiumPointsSymbol();
      billing.tokens_per_spl = normalizedTokensPerSpl();
      billing.points_per_token = normalizedPointsPerToken();
      billing.free_tokens = normalizedPremiumFreeTokens();
      billing.free_points = normalizedPremiumFreePoints();
      billing.premium_enabled = billing.premium_enabled === true;
      billing.llm_backend = resolvePremiumLlmBackend();
      billing.gpu_endpoint = resolvePremiumGpuEndpoint();
      billing.gpu_billing_enabled = premiumBillingUsesGpu(billing.llm_backend);
      billing.wallet_required = premiumWalletRequired();
      billing.wallet_verified = Boolean(hasWallet);
      billing.points_enabled = premiumPointsEnabled();
      billing.free_granted_at = Number.isFinite(Number(billing.free_granted_at)) ? Number(billing.free_granted_at) : null;
      billing.free_points_granted_at = Number.isFinite(Number(billing.free_points_granted_at))
        ? Number(billing.free_points_granted_at)
        : null;
      if (!Number.isFinite(Number(billing.token_balance))) {
        const starter = hasWallet ? billing.free_tokens : 0;
        billing.token_balance = starter;
        if (starter > 0) billing.free_granted_at = now();
      } else {
        billing.token_balance = Math.max(0, Math.round(Number(billing.token_balance)));
      }
      if (!Number.isFinite(Number(billing.points_balance))) {
        const starterPoints = !hasWallet && billing.points_enabled ? billing.free_points : 0;
        billing.points_balance = starterPoints;
        if (starterPoints > 0) billing.free_points_granted_at = now();
      } else {
        billing.points_balance = Math.max(0, Math.round(Number(billing.points_balance)));
      }
      billing.tokens_spent = Number.isFinite(Number(billing.tokens_spent)) ? Math.max(0, Math.round(Number(billing.tokens_spent))) : 0;
      billing.points_spent = Number.isFinite(Number(billing.points_spent)) ? Math.max(0, Math.round(Number(billing.points_spent))) : 0;
      billing.last_quote = billing.last_quote && typeof billing.last_quote === "object" ? billing.last_quote : null;
      billing.pending_quote = billing.pending_quote && typeof billing.pending_quote === "object" ? billing.pending_quote : null;
      billing.last_charge = billing.last_charge && typeof billing.last_charge === "object" ? billing.last_charge : null;
      billing.last_credit = billing.last_credit && typeof billing.last_credit === "object" ? billing.last_credit : null;
      billing.last_points_credit = billing.last_points_credit && typeof billing.last_points_credit === "object" ? billing.last_points_credit : null;
      billing.last_ad_reward_at = Number.isFinite(Number(billing.last_ad_reward_at)) ? Number(billing.last_ad_reward_at) : null;
      billing.point_pack = billing.point_pack && typeof billing.point_pack === "object" ? billing.point_pack : {};
      billing.point_pack.price_usd = normalizedPointPackPriceUsd();
      billing.point_pack.points = normalizedPointPackAmount();
      billing.point_pack.checkout_url = premiumPointsCheckoutUrl();
      billing.ad_rewards = billing.ad_rewards && typeof billing.ad_rewards === "object" ? billing.ad_rewards : {};
      billing.ad_rewards.enabled = premiumAdRewardsEnabled();
      billing.ad_rewards.points = normalizedAdRewardPoints();
      billing.ad_rewards.cooldown_sec = normalizedAdRewardCooldownSec();
      billing.topup_url = premiumTopupUrl();
      billing.points_topup_url = premiumPointsTopupUrl();
      billing.active_unit = resolvePremiumChargeUnit(billing);
      billing.updated_at = now();
      return billing;
    }

    function canUsePremiumBuilder(independent, dependent) {
      const billing = ensureBillingState(independent, dependent);
      if (!premiumBuilderEnabled()) return { ok: false, reason: "Premium builder is currently disabled." };
      if (billing.wallet_required && !billing.wallet_verified && !billing.points_enabled) {
        return { ok: false, reason: "Premium builder requires wallet sign-in (MetaMask, WalletConnect, Ledger, or Phantom)." };
      }
      const activeUnit = resolvePremiumChargeUnit(billing);
      const activeBalance = activeUnit === "points" ? billing.points_balance : billing.token_balance;
      if (activeBalance <= 0) {
        const pointPackPrice = Number(billing?.point_pack?.price_usd || normalizedPointPackPriceUsd());
        const adEnabled = billing?.ad_rewards?.enabled === true;
        return {
          ok: false,
          reason:
            activeUnit === "points"
              ? `You are out of premium points. Buy a point pack (from $${pointPackPrice.toFixed(2)})${
                  adEnabled ? " or watch a rewarded ad" : ""
                } and try again.`
              : `You are out of premium tokens. Top up with ${billing.spl_symbol} and try again.`,
        };
      }
      return { ok: true, unit: activeUnit, balance: activeBalance };
    }

    function applyPremiumTokenCharge(independent, dependent, chargeTokens, context = {}) {
      const billing = ensureBillingState(independent, dependent);
      const spendTokens = Math.max(0, Math.round(Number(chargeTokens || 0)));
      const unit = resolvePremiumChargeUnit(billing);
      if (context?.waive === true) {
        billing.last_charge = {
          requested_tokens: spendTokens,
          charged_amount: 0,
          unit,
          context,
          charged_at: now(),
        };
        billing.active_unit = resolvePremiumChargeUnit(billing);
        billing.updated_at = now();
        return {
          ok: true,
          unit,
          charged_amount: 0,
          balance: unit === "points" ? billing.points_balance : billing.token_balance,
          waived: true,
        };
      }
      const spendAmount = unit === "points"
        ? Math.max(1, Math.round(spendTokens * Number(billing.points_per_token || 1)))
        : spendTokens;
      if (unit === "points") {
        if (billing.points_balance < spendAmount) {
          return { ok: false, error: "insufficient_points", balance: billing.points_balance, unit };
        }
        billing.points_balance -= spendAmount;
        billing.points_spent += spendAmount;
      } else {
        if (billing.token_balance < spendAmount) {
          return { ok: false, error: "insufficient_tokens", balance: billing.token_balance, unit };
        }
        billing.token_balance -= spendAmount;
        billing.tokens_spent += spendAmount;
      }
      billing.last_charge = {
        requested_tokens: spendTokens,
        charged_amount: spendAmount,
        unit,
        context,
        charged_at: now(),
      };
      billing.active_unit = resolvePremiumChargeUnit(billing);
      billing.updated_at = now();
      return {
        ok: true,
        unit,
        charged_amount: spendAmount,
        balance: unit === "points" ? billing.points_balance : billing.token_balance,
      };
    }

    function applyPremiumTokenCredit(independent, dependent, creditTokens, context = {}) {
      const billing = ensureBillingState(independent, dependent);
      const add = Math.max(0, Math.round(Number(creditTokens || 0)));
      if (add <= 0) return { ok: false, error: "invalid_credit_amount" };
      billing.token_balance += add;
      billing.last_credit = { tokens: add, context, credited_at: now() };
      billing.active_unit = resolvePremiumChargeUnit(billing);
      billing.updated_at = now();
      return { ok: true, balance: billing.token_balance };
    }

    function applyPremiumPointsCredit(independent, dependent, creditPoints, context = {}) {
      const billing = ensureBillingState(independent, dependent);
      const add = Math.max(0, Math.round(Number(creditPoints || 0)));
      if (add <= 0) return { ok: false, error: "invalid_points_credit" };
      billing.points_balance += add;
      billing.last_points_credit = { points: add, context, credited_at: now() };
      billing.active_unit = resolvePremiumChargeUnit(billing);
      billing.updated_at = now();
      return { ok: true, balance: billing.points_balance };
    }

    function pushUniqueLimited(list, value, max = 8) {
      const v = String(value || "").trim();
      if (!v) return list;
      const next = Array.isArray(list) ? list.slice() : [];
      if (!next.includes(v)) next.push(v);
      return next.slice(0, max);
    }

    function inferBuildBriefSignalsFromText(independent, dependent, state, answerText) {
      const brief = ensureBuildBriefState(dependent);
      const t = String(answerText || "").toLowerCase();
      const businessType = String(independent?.business?.type_final || dependent?.draft?.type_guess || "").toLowerCase();
      const desc = String(independent?.business?.description_raw || "").toLowerCase();

      const isRepoSeller =
        businessType.includes("developer repo marketplace") ||
        (/\b(repo|repository|template|starter|boilerplate|source code|github repo)\b/.test(`${t} ${desc}`) &&
          /\b(sell|selling|for sale|buy|marketplace|checkout)\b/.test(`${t} ${desc}`));

      if (isRepoSeller) {
        if (!brief.persona) brief.persona = "developer_repo_seller";
        if (!brief.offer_type) brief.offer_type = "production-ready code repositories";
        if (!brief.repo_sale_model) brief.repo_sale_model = "repo marketplace";
        if (!brief.primary_goal) brief.primary_goal = "Convert visitors into buyers of your repos.";
        if (!brief.secondary_goal) brief.secondary_goal = "Build trust with a short About section and proof.";
        if (!brief.tertiary_goal) brief.tertiary_goal = "Capture leads with an email signup and contact form.";
        if (!brief.audience) brief.audience = "Founders, builders, and teams that want production-ready repos.";
        if (!brief.style_pref) {
          brief.style_pref =
            "Clean, modern, developer-premium aesthetic with crisp cards, whitespace, and subtle animation.";
        }
        brief.dark_mode_friendly = true;
        brief.lead_capture = true;
      }

      if (/\b(stripe)\b/.test(t)) brief.payment_provider = "Stripe Checkout";
      if (/\b(gumroad)\b/.test(t)) brief.payment_provider = "Gumroad";
      if (/\b(lemon\s*squeezy)\b/.test(t)) brief.payment_provider = "Lemon Squeezy";

      if (/\b(astro)\b/.test(t)) brief.stack_preference = "astro";
      if (/\b(next\.?js|react)\b/.test(t)) brief.stack_preference = "next";
      if (/\b(static|no backend)\b/.test(t)) brief.stack_preference = "static";
      if (/\b(cms|sanity|contentful|strapi)\b/.test(t)) brief.stack_preference = "cms_upgrade_path";

      if (/\b(tailwind)\b/.test(t)) brief.stacks = pushUniqueLimited(brief.stacks, "Tailwind CSS");
      if (/\b(type\s*script|typescript)\b/.test(t)) brief.stacks = pushUniqueLimited(brief.stacks, "TypeScript");
      if (/\b(next\.?js|app router)\b/.test(t)) brief.stacks = pushUniqueLimited(brief.stacks, "Next.js App Router");
      if (/\b(astro)\b/.test(t)) brief.stacks = pushUniqueLimited(brief.stacks, "Astro");

      if (/\b(testimonial|proof|downloads?|stars?|metrics?)\b/.test(t)) {
        brief.trust_signals = pushUniqueLimited(brief.trust_signals, "proof metrics + testimonials");
      }
      if (/\b(email signup|lead|contact form|capture leads?)\b/.test(t)) {
        brief.lead_capture = true;
      }

      if (state === "Q6_GOAL" && String(answerText || "").trim()) {
        brief.primary_goal = brief.primary_goal || String(answerText || "").trim().slice(0, 180);
      }
      return brief;
    }

    function resolveBuildBriefStackChoice(brief) {
      const pref = String(brief?.stack_preference || "").toLowerCase();
      if (pref === "astro" || pref === "static") return "Astro + Tailwind";
      return "Next.js (App Router) + TypeScript + Tailwind";
    }

    function compileBuildBrief(independent, dependent) {
      const brief = ensureBuildBriefState(dependent);
      inferBuildBriefSignalsFromText(independent, dependent, "__compile__", independent?.business?.description_raw || "");

      const businessType = String(independent?.business?.type_final || dependent?.draft?.type_guess || "").toLowerCase();
      const repoRelevant =
        String(brief.persona || "") === "developer_repo_seller" ||
        businessType.includes("developer repo marketplace");
      if (!repoRelevant) return null;

      const stackChoice = resolveBuildBriefStackChoice(brief);
      const paymentProvider = brief.payment_provider || "Stripe Checkout";
      const stacksLine = (brief.stacks || []).length ? brief.stacks.join(", ") : "TypeScript, Tailwind, modern static-friendly tooling";
      const trustLine = (brief.trust_signals || []).length
        ? brief.trust_signals.join(", ")
        : "portfolio examples, testimonials, and simple proof metrics";

      const prompt =
        "Build a modern, fast personal website for me that (1) showcases and sells my code repos, and (2) explains who I am and what I build.\n\n" +
        "GOALS\n" +
        `- Primary: ${brief.primary_goal || "Convert visitors into buyers of my repos."}\n` +
        `- Secondary: ${brief.secondary_goal || "Build trust with a short About section and proof."}\n` +
        `- Tertiary: ${brief.tertiary_goal || "Capture leads (email signup + contact form)."}\n\n` +
        "BRAND / STYLE\n" +
        `- ${brief.style_pref || "Clean, modern, slightly developer-premium aesthetic."}\n` +
        `- Dark-mode friendly with a toggle: ${brief.dark_mode_friendly ? "yes" : "no"}\n` +
        "- Mobile-first, fully responsive, strong Lighthouse performance.\n\n" +
        "SITE STRUCTURE (PAGES)\n" +
        "1) Home (hero, CTAs, trust strip, featured repos, About teaser, email capture)\n" +
        "2) Repos marketplace (filters, search, premium repo cards, buy CTA)\n" +
        "3) Repo detail template (problem/solution, media, features, stack, included, FAQ, related repos)\n" +
        "4) About (story, skills, principles)\n" +
        "5) Contact (form + social + custom build request)\n\n" +
        "CORE FEATURES\n" +
        "- Repo listing data from one source (JSON/YAML/MD/CMS).\n" +
        "- Payment integration: " + paymentProvider + ".\n" +
        "- Next-steps page after purchase (delivery workflow).\n\n" +
        "TECH REQUIREMENTS\n" +
        "- SEO metadata + OpenGraph + sitemap + robots.txt.\n" +
        "- Performance: image optimization, lazy loading, code splitting, caching.\n" +
        "- Accessibility: semantic HTML + keyboard support.\n" +
        "- Analytics integration ready.\n" +
        "- Security: sanitized forms + spam protection.\n\n" +
        "CONTENT\n" +
        "- Draft clear marketing copy (confident, non-hype).\n" +
        "- Include 6 realistic example repos with pricing and descriptions.\n" +
        "- Include placeholder gradient mock screenshots.\n\n" +
        "DELIVERABLES\n" +
        "- Complete source code and clear folder structure.\n" +
        "- README for local run/edit/deploy.\n" +
        "- Static build + optional CMS upgrade path.\n\n" +
        "STACK (choose one and commit)\n" +
        `- ${stackChoice}\n` +
        `- Stacks to emphasize: ${stacksLine}\n` +
        `- Trust assets to include: ${trustLine}\n\n` +
        "ASK ONLY IF REQUIRED\n" +
        `- ${brief.ask_only_if_required.join("\n- ")}`;

      brief.stack_choice = stackChoice;
      brief.compiled_prompt = prompt;
      brief.compiled_summary =
        "Repo marketplace brief ready: Home + Repos + Repo Detail + About + Contact with payment, SEO, performance, and lead capture.";
      brief.compiled_at = now();
      brief.version = 1;
      return {
        summary: brief.compiled_summary,
        stack_choice: stackChoice,
        prompt,
        slots: {
          persona: brief.persona,
          audience: brief.audience,
          primary_goal: brief.primary_goal,
          secondary_goal: brief.secondary_goal,
          tertiary_goal: brief.tertiary_goal,
          offer_type: brief.offer_type,
          repo_sale_model: brief.repo_sale_model,
          payment_provider: paymentProvider,
          style_pref: brief.style_pref,
          dark_mode_friendly: brief.dark_mode_friendly,
          lead_capture: brief.lead_capture,
          stacks: brief.stacks,
          trust_signals: brief.trust_signals,
        },
      };
    }

    function inferCtaFocus(goalText) {
      const lower = String(goalText || "").toLowerCase();
      if (/\b(book|books|booking|bookings|schedule|appointment|appointments|reserve|reservation|reservations)\b/.test(lower))
        return "bookings";
      if (/\b(call|phone)\b/.test(lower)) return "calls";
      if (/\b(lead|quote|estimate|contact|form|inquiry|enquiry)\b/.test(lower)) return "leads";
      if (/\b(portfolio|gallery|showcase|information|info|learn more)\b/.test(lower)) return "portfolio";
      return "consultation";
    }

    function inferTemplateVariant(ctaFocus, businessType, densityPreference) {
      const bt = String(businessType || "").toLowerCase();
      if (ctaFocus === "portfolio") return "portfolio_showcase";
      if (ctaFocus === "bookings") return "booking_focused";
      if (/\b(dive|tour|guide|rental|detail|repair|plumb|clean|service)\b/.test(bt)) {
        return densityPreference === "spacious" ? "service_story" : "service_conversion";
      }
      return "service_conversion";
    }

    function buildSectionPlan(templateVariant, ctaFocus, businessType) {
      const bt = String(businessType || "").toLowerCase();
      const base = [];
      if (templateVariant === "portfolio_showcase") {
        base.push("Featured Work", "Service Highlights", "Customer Reviews", "Contact");
      } else if (templateVariant === "booking_focused") {
        base.push("Service Packages", "Availability", "Booking Steps", "Contact");
      } else {
        base.push("Top Services", "Why Choose Us", "Proof & Reviews", "Contact");
      }
      if (ctaFocus === "calls" && !base.includes("Call-To-Action")) base.splice(2, 0, "Call-To-Action");
      if (bt.includes("dive") && !base.includes("Safety & Certifications")) base.splice(2, 0, "Safety & Certifications");
      if ((bt.includes("detail") || bt.includes("repair")) && !base.includes("Packages & Pricing")) base.splice(1, 0, "Packages & Pricing");
      return Array.from(new Set(base)).slice(0, 6);
    }

    function deriveDesignProfile(independent, dependent) {
      const design = ensureDesignState(dependent);
      const build = independent?.build || {};
      const demo = independent?.demo || {};
      const businessType = independent?.business?.type_final || dependent?.draft?.type_guess || "local business";
      const goalText = String(build?.goal || "").trim();
      const vibeText = String(build?.vibe || "").toLowerCase();
      const feedbackText = `${String(design.raw_feedback?.slice(-10).join(" ") || "")} ${vibeText}`.toLowerCase();

      const styleVotes = { modern: 0, bold: 0, balanced: 0 };
      if (demo?.q1_vibe === "modern") styleVotes.modern += 3;
      if (demo?.q1_vibe === "bold") styleVotes.bold += 3;
      if (demo?.q1_vibe === "neutral") styleVotes.balanced += 2;
      if (/\b(modern|clean|minimal|sleek)\b/.test(vibeText)) styleVotes.modern += 2;
      if (/\b(bold|flashy|luxury|high contrast|strong)\b/.test(vibeText)) styleVotes.bold += 2;
      if (/\b(friendly|simple|balanced|approachable)\b/.test(vibeText)) styleVotes.balanced += 1;
      if ((design.layout_hints || []).includes("clean_modern")) styleVotes.modern += 2;
      if ((design.layout_hints || []).includes("bold_visual")) styleVotes.bold += 2;
      if ((design.layout_hints || []).includes("balanced")) styleVotes.balanced += 1;
      if (/\b(clean|minimal)\b/.test(feedbackText)) styleVotes.modern += 1;
      if (/\b(bold|flashy|dramatic|loud)\b/.test(feedbackText)) styleVotes.bold += 1;

      const visualStyle = Object.entries(styleVotes).sort((a, b) => b[1] - a[1])[0]?.[0] || "balanced";

      let densityPreference = "balanced";
      if (demo?.q3_layout === "too empty") densityPreference = "information_rich";
      else if (demo?.q3_layout === "cluttered") densityPreference = "spacious";
      else if (demo?.q3_layout === "easy to read") densityPreference = "readable";
      else if ((design.layout_hints || []).includes("avoid_clutter")) densityPreference = "spacious";
      else if ((design.layout_hints || []).includes("denser_sections")) densityPreference = "information_rich";
      else if ((design.layout_hints || []).includes("readable")) densityPreference = "readable";

      let colorBalance = "balanced";
      if (demo?.q2_colors === "too bright") colorBalance = "muted";
      else if (demo?.q2_colors === "too dark") colorBalance = "lighter";
      const selectedPalette = design.selected_palette && typeof design.selected_palette === "object" ? design.selected_palette : null;
      const paletteHints = Array.from(
        new Set([
          ...(Array.isArray(design.palette_hints) ? design.palette_hints : []),
          ...(Array.isArray(selectedPalette?.hints) ? selectedPalette.hints : []),
          ...extractColorHintsFromText(build?.colors || ""),
        ])
      ).slice(0, 10);
      const ctaFocus = inferCtaFocus(goalText);
      const templateVariant = inferTemplateVariant(ctaFocus, businessType, densityPreference);
      const sectionPlan = buildSectionPlan(templateVariant, ctaFocus, businessType);
      const fontFamily = (design.font_hints || []).includes("serif") ? "serif" : "sans";

      const signalCount =
        Number(Boolean(goalText)) +
        Number(Boolean(build?.vibe)) +
        Number(Boolean(build?.colors)) +
        Number(Boolean(demo?.q1_vibe)) +
        Number(Boolean(demo?.q2_colors)) +
        Number(Boolean(demo?.q3_layout)) +
        Math.min(3, Math.max(0, Number((design.raw_feedback || []).length || 0)));
      const confidence = Math.min(0.96, Number((0.4 + signalCount * 0.07).toFixed(2)));

      return {
        visual_style: visualStyle,
        density_preference: densityPreference,
        color_balance: colorBalance,
        palette_hints: paletteHints,
        selected_palette_id: selectedPalette?.id || null,
        cta_focus: ctaFocus,
        template_variant: templateVariant,
        section_plan: sectionPlan,
        font_family: fontFamily,
        confidence,
        updated_at: now(),
      };
    }

    function refreshSessionInsights(state, answerText, independent, dependent) {
      const analysis = ensurePatternAnalysisState(dependent);
      const design = ensureDesignState(dependent);
      ensureBuildBriefState(dependent);
      const txt = String(answerText || "").trim().toLowerCase();

      if (txt && txt !== "__auto_after_20s__") {
        analysis.turns_processed += 1;
        analysis.last_user_input = String(answerText || "").slice(0, 500);

        if (/\b(help|stuck|confused|error|didn'?t open|bad request|not able|unable)\b/.test(txt)) {
          analysis.frustration_signals += 1;
        }
        if (/\b(thanks|great|perfect|awesome|sounds good|love|liked)\b/.test(txt)) {
          analysis.positive_signals += 1;
        }
        if (/\b(why|what does|what is|how do i know|explain|not sure|idk|i don't understand)\b/.test(txt)) {
          analysis.clarification_requests += 1;
        }
        if (/^q3_/.test(String(state || "").toLowerCase()) || /\b(like|dislike|prefer|color|layout|style)\b/.test(txt)) {
          analysis.preference_events += 1;
        }
      }

      const previousProfile = design.profile && typeof design.profile === "object" ? design.profile : null;
      const nextProfile = deriveDesignProfile(independent, dependent);
      design.profile = nextProfile;
      if (
        previousProfile &&
        (previousProfile.visual_style !== nextProfile.visual_style ||
          previousProfile.density_preference !== nextProfile.density_preference ||
          previousProfile.cta_focus !== nextProfile.cta_focus)
      ) {
        analysis.preference_shifts += 1;
      }
      analysis.last_summary =
        `${nextProfile.visual_style} style, ${nextProfile.density_preference} density, ` +
        `${nextProfile.cta_focus} primary CTA (confidence ${Math.round((nextProfile.confidence || 0) * 100)}%)`;
      analysis.last_updated_at = now();

      inferBuildBriefSignalsFromText(independent, dependent, state, answerText);
      compileBuildBrief(independent, dependent);
    }

    function cannotAccessDemoSite(text) {
      const t = String(text || "").toLowerCase();
      return (
        /\b(nothing opened|didn'?t open|did not open|not able to go|unable to go|unable to open|couldn'?t open|could not open|no links?|no link)\b/.test(
          t
        ) ||
        /\b(was not able|bad request|error code|http 4\d\d|http 5\d\d|404|400|500)\b/.test(t)
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

    async function inferWebsiteIntentFocusWithOpenAI(rawIntent, businessType, locationHint, openAiApiKey = null) {
      const apiKey = String(openAiApiKey || env.OPENAI_API_KEY || "").trim();
      if (!apiKey) return null;
      const raw = normalizeWebsiteIntentText(rawIntent);
      if (!raw) return null;

      try {
        const r = await fetch("https://api.openai.com/v1/responses", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            authorization: `Bearer ${apiKey}`,
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

    async function resolveWebsiteIntentFocus(rawIntent, businessType, locationHint, openAiApiKey = null) {
      const raw = normalizeWebsiteIntentText(rawIntent);
      if (!raw) return { focus: null, source: "none", raw: "" };
      const ai = await inferWebsiteIntentFocusWithOpenAI(raw, businessType, locationHint, openAiApiKey);
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
      const current = sites[idx] || null;
      if (!current || typeof current !== "object") return null;
      const safeUrl = sanitizeReferenceUrl(current.url);
      if (!safeUrl) return null;
      return { ...current, url: safeUrl };
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

    function buildPaletteChoiceOptions(independent, dependent) {
      const businessType = String(independent?.business?.type_final || dependent?.draft?.type_guess || "").toLowerCase();
      const vibe = String(independent?.demo?.q1_vibe || "").toLowerCase();
      const options = [
        {
          id: "A",
          name: "Ocean Trust",
          description: "Clean and professional.",
          colors: ["#0b1f3a", "#1fa4ff", "#f6fbff", "#103a5c", "#6bcbff"],
          hints: ["blue", "navy", "clean_modern"],
        },
        {
          id: "B",
          name: "Warm Energy",
          description: "Bold and high-conversion.",
          colors: ["#2a160f", "#ff8c42", "#fff6ef", "#8a4b2a", "#ffd0a6"],
          hints: ["orange", "bold_visual", "warm"],
        },
        {
          id: "C",
          name: "Natural Growth",
          description: "Friendly and approachable.",
          colors: ["#0f2418", "#3fcf8e", "#f3fff8", "#1c6b4a", "#a7e4c7"],
          hints: ["green", "balanced", "readable"],
        },
      ];

      if (/\b(garden|landscap|nursery|flor|plant|farm)\b/.test(businessType)) {
        return [options[2], options[0], options[1]];
      }
      if (vibe === "bold") {
        return [options[1], options[0], options[2]];
      }
      return options;
    }

    function parsePaletteChoice(text, options) {
      const list = Array.isArray(options) ? options : [];
      if (!list.length) return null;
      const t = String(text || "").trim().toLowerCase();
      if (!t) return null;

      if (/^[abc]$/.test(t)) {
        const found = list.find((o) => String(o?.id || "").toLowerCase() === t);
        if (found) return found;
      }
      const digit = t.match(/^([1-3])$/);
      if (digit) {
        const idx = Number(digit[1]) - 1;
        if (list[idx]) return list[idx];
      }
      const letterMatch = t.match(/\bpalette\s*([abc])\b/i);
      if (letterMatch?.[1]) {
        const found = list.find((o) => String(o?.id || "").toLowerCase() === letterMatch[1].toLowerCase());
        if (found) return found;
      }
      for (const option of list) {
        const name = String(option?.name || "").toLowerCase();
        if (name && t.includes(name)) return option;
      }
      return null;
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

    function pickDemoPalette(design, buildColors = "", profile = null) {
      const selected = design?.selected_palette;
      if (selected && Array.isArray(selected.colors) && selected.colors.length >= 3) {
        return {
          bg: normalizeHexColor(selected.colors[0]) || "#1a1a1a",
          accent: normalizeHexColor(selected.colors[1]) || "#5ec2ff",
          ink: normalizeHexColor(selected.colors[2]) || "#ffffff",
        };
      }
      const hints = Array.from(
        new Set([
          ...(Array.isArray(design?.palette_hints) ? design.palette_hints : []),
          ...extractColorHintsFromText(buildColors),
          ...(Array.isArray(profile?.palette_hints) ? profile.palette_hints : []),
        ])
      );
      if (hints.includes("blue") || hints.includes("teal") || hints.includes("navy")) {
        return { bg: "#0b1f3a", accent: "#1fa4ff", ink: "#f6fbff" };
      }
      if (hints.includes("green")) {
        return { bg: "#0f2418", accent: "#3fcf8e", ink: "#f3fff8" };
      }
      if (hints.includes("black") || hints.includes("gold")) {
        return { bg: "#111111", accent: "#d9b24c", ink: "#f5f2e9" };
      }
      if (hints.includes("orange") || hints.includes("red") || hints.includes("yellow")) {
        return { bg: "#2a160f", accent: "#ff8c42", ink: "#fff6ef" };
      }
      return { bg: "#1a1a1a", accent: "#5ec2ff", ink: "#ffffff" };
    }

    function buildDemoCss(palette, profile = null) {
      const density = String(profile?.density_preference || "balanced");
      const gridGap = density === "information_rich" ? 10 : density === "spacious" ? 18 : 14;
      const cardPadding = density === "information_rich" ? 14 : density === "spacious" ? 20 : 16;
      const fontStack =
        profile?.font_family === "serif"
          ? '"Lora", "Merriweather", Georgia, serif'
          : '"Manrope", "Avenir Next", "Segoe UI", sans-serif';
      return `
:root { --bg: ${palette.bg}; --accent: ${palette.accent}; --ink: ${palette.ink}; }
* { box-sizing: border-box; }
body { margin: 0; font-family: ${fontStack}; color: var(--ink); background: radial-gradient(circle at top right, #2d2d2d, var(--bg)); }
.wrap { max-width: 980px; margin: 0 auto; padding: 28px 16px 56px; }
.hero { border: 1px solid #ffffff2c; border-radius: 16px; padding: 28px; background: #ffffff12; backdrop-filter: blur(4px); position: relative; overflow: hidden; }
.hero-art { position: absolute; top: -8px; right: -8px; width: 240px; max-width: 42vw; opacity: 0.28; pointer-events: none; }
.cta { display: inline-block; margin-top: 14px; padding: 10px 14px; border-radius: 10px; background: var(--accent); color: #071015; text-decoration: none; font-weight: 700; }
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: ${gridGap}px; margin-top: 20px; }
.card { border: 1px solid #ffffff2c; border-radius: 12px; padding: ${cardPadding}px; background: #ffffff10; }
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
      const profile = deriveDesignProfile(independent, dependent);
      const palette = pickDemoPalette(design, independent?.build?.colors || "", profile);
      const likes = (design?.liked || []).slice(0, 3).map(esc);
      const dislikes = (design?.disliked || []).slice(0, 3).map(esc);
      const cssHref = assets?.cssHref ? esc(assets.cssHref) : null;
      const jsSrc = assets?.jsSrc ? esc(assets.jsSrc) : null;
      const heroImageSrc = assets?.heroImageSrc ? esc(assets.heroImageSrc) : null;
      const inlineCss = buildDemoCss(palette, profile);
      const ctaTextByFocus = {
        bookings: "Book Appointment",
        calls: "Call Now",
        leads: "Request Quote",
        portfolio: "See Work",
        consultation: "Get Started",
      };
      const ctaText = esc(ctaTextByFocus[profile.cta_focus] || "Request Service");
      const profileLine = `${titleCaseWords(profile.visual_style)} style, ${profile.density_preference.replace(/_/g, " ")}, ${profile.cta_focus} focus`;
      const sectionPlan = Array.isArray(profile.section_plan) ? profile.section_plan.slice(0, 3) : ["Top Services", "Why Choose Us", "Contact"];
      const goalText = esc(goal || "lead generation");

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
      <p>Primary goal: ${goalText}.</p>
      <p>Design profile: ${esc(profileLine)}.</p>
      ${location ? `<p>Serving ${location}.</p>` : ""}
      <a class="cta" href="#contact">${ctaText}</a>
    </section>
    <section class="grid">
      <article class="card reveal">
        <h2>${esc(sectionPlan[0] || "Design Signals")}</h2>
        <ul>
          ${likes.length ? likes.map((x) => `<li>Liked: ${x}</li>`).join("") : "<li>Liked: modern presentation</li>"}
          ${dislikes.length ? dislikes.map((x) => `<li>Avoid: ${x}</li>`).join("") : "<li>Avoid: cluttered layouts</li>"}
        </ul>
      </article>
      <article class="card reveal">
        <h2>${esc(sectionPlan[1] || "Conversion Focus")}</h2>
        <p>Clear call-to-action, visible contact paths, and simplified page flow tuned for ${goalText}.</p>
        <p>Color direction: ${esc((profile.palette_hints || []).slice(0, 3).join(", ") || "balanced contrast")}.</p>
      </article>
      <article class="card reveal" id="contact">
        <h2>${esc(sectionPlan[2] || "Contact")}</h2>
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
      const design = ensureDesignState(dependent);
      const profile = deriveDesignProfile(independent, dependent);
      design.profile = profile;
      const palette = pickDemoPalette(design, independent?.build?.colors || "", profile);
      const cssText = buildDemoCss(palette, profile);
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

    function decodeMaybeBase64UrlToken(raw) {
      const compact = String(raw || "")
        .trim()
        .replace(/\s+/g, "");
      if (!compact || !/^[A-Za-z0-9+/_=-]{24,}$/.test(compact)) return null;
      try {
        let b64 = compact.replace(/-/g, "+").replace(/_/g, "/");
        while (b64.length % 4 !== 0) b64 += "=";
        return atob(b64);
      } catch {
        return null;
      }
    }

    function extractHttpUrlCandidate(raw) {
      const candidates = [];
      const push = (value) => {
        const text = String(value || "").trim();
        if (!text) return;
        if (!candidates.includes(text)) candidates.push(text);
      };
      push(raw);
      try {
        push(decodeURIComponent(String(raw || "")));
      } catch {}
      const decodedB64 = decodeMaybeBase64UrlToken(raw);
      if (decodedB64) {
        push(decodedB64);
        try {
          push(decodeURIComponent(decodedB64));
        } catch {}
      }

      for (const item of candidates) {
        const m = String(item).match(/https?:\/\/[^\s"'<>]+/i);
        if (m?.[0]) {
          return m[0].replace(/[),.;]+$/g, "");
        }
      }
      return null;
    }

    function unwrapTrackingRedirectUrl(rawUrl, maxDepth = 4) {
      let current = toHttpsUrl(rawUrl);
      if (!current) return null;
      for (let i = 0; i < Math.max(1, maxDepth); i += 1) {
        let parsed = null;
        try {
          parsed = new URL(current);
        } catch {
          return current;
        }
        const host = (parsed.hostname || "").toLowerCase();
        const searchLikeHost =
          host.includes("duckduckgo.com") ||
          host.endsWith(".duckduckgo.com") ||
          host === "bing.com" ||
          host === "www.bing.com" ||
          host === "google.com" ||
          host.endsWith(".google.com") ||
          host === "search.yahoo.com" ||
          host === "yahoo.com";
        if (!searchLikeHost) return current;

        const paramKeys = ["uddg", "url", "u", "u2", "u3", "target", "dest", "destination", "redirect", "redirect_url", "r"];
        let found = null;
        for (const key of paramKeys) {
          const values = parsed.searchParams.getAll(key);
          for (const value of values) {
            const candidate = extractHttpUrlCandidate(value);
            if (candidate) {
              found = candidate;
              break;
            }
          }
          if (found) break;
        }
        if (!found) return current;
        current = found;
      }
      return current;
    }

    function rootDomainFromHostname(hostname) {
      const h = String(hostname || "").toLowerCase().trim();
      if (!h) return null;
      const parts = h.split(".").filter(Boolean);
      if (parts.length <= 2) return h;
      const twoLevelTlds = new Set([
        "co.uk",
        "org.uk",
        "ac.uk",
        "com.au",
        "net.au",
        "org.au",
        "co.nz",
        "com.br",
        "com.mx",
        "co.jp",
      ]);
      const tail2 = `${parts[parts.length - 2]}.${parts[parts.length - 1]}`;
      if (twoLevelTlds.has(tail2) && parts.length >= 3) {
        return `${parts[parts.length - 3]}.${tail2}`;
      }
      return `${parts[parts.length - 2]}.${parts[parts.length - 1]}`;
    }

    function isSearchOrTrackingHost(hostname) {
      const host = String(hostname || "").toLowerCase();
      if (!host) return true;
      const searchAndTrackingHosts = [
        "duckduckgo.com",
        "bing.com",
        "google.com",
        "search.yahoo.com",
        "yahoo.com",
        "yandex.com",
        "baidu.com",
        "googleadservices.com",
        "doubleclick.net",
      ];
      return searchAndTrackingHosts.some((domain) => host === domain || host.endsWith(`.${domain}`));
    }

    function isBlacklistedReferenceHost(hostname) {
      const host = String(hostname || "").toLowerCase().trim();
      if (!host) return true;
      const root = rootDomainFromHostname(host) || host;
      if (
        REFERENCE_BLOCKED_ROOT_DOMAINS.has(host) ||
        REFERENCE_BLOCKED_ROOT_DOMAINS.has(root) ||
        configuredReferenceBlockedRoots.has(host) ||
        configuredReferenceBlockedRoots.has(root)
      ) {
        return true;
      }

      const keywordMatched =
        REFERENCE_BLOCKED_HOST_KEYWORDS.some((k) => host.includes(k) || root.includes(k)) ||
        configuredReferenceBlockedKeywords.some((k) => host.includes(k) || root.includes(k));
      if (keywordMatched) return true;

      return false;
    }

    function sanitizeReferenceUrl(rawUrl) {
      const unwrapped = unwrapTrackingRedirectUrl(rawUrl);
      const candidate = toHttpsUrl(unwrapped);
      if (!candidate) return null;
      try {
        const parsed = new URL(candidate);
        const protocol = String(parsed.protocol || "").toLowerCase();
        if (protocol !== "http:" && protocol !== "https:") return null;
        const host = (parsed.hostname || "").toLowerCase();
        if (!host || isSearchOrTrackingHost(host) || isBlacklistedReferenceHost(host)) return null;
        const cleanedParams = new URLSearchParams(parsed.search || "");
        const trackedPrefixes = ["utm_", "ga_", "pk_"];
        const trackedKeys = new Set([
          "gclid",
          "fbclid",
          "msclkid",
          "vqd",
          "rut",
          "iurl",
          "ig",
          "cid",
          "id",
          "rlid",
          "ad_domain",
          "ad_provider",
          "ad_type",
          "click_metadata",
          "u",
          "u2",
          "u3",
          "url",
        ]);
        for (const key of Array.from(cleanedParams.keys())) {
          const k = String(key || "").toLowerCase();
          if (trackedKeys.has(k) || trackedPrefixes.some((p) => k.startsWith(p))) {
            cleanedParams.delete(key);
          }
        }
        const path = (parsed.pathname || "/").replace(/\/{2,}/g, "/");
        const query = cleanedParams.toString();
        const finalUrl = `${parsed.protocol}//${host}${path}${query ? `?${query}` : ""}`;
        if (finalUrl.length > 450) return null;
        return finalUrl;
      } catch {
        return null;
      }
    }

    function normalizeReferenceSites(rawSites, excludeUrls = []) {
      const items = Array.isArray(rawSites) ? rawSites : [];
      const out = [];
      const seen = new Set();
      const excluded = new Set(
        (Array.isArray(excludeUrls) ? excludeUrls : [])
          .map((u) => sanitizeReferenceUrl(u))
          .filter(Boolean)
      );
      for (const item of items) {
        const rawUrl =
          typeof item === "string"
            ? item
            : item && typeof item === "object"
              ? String(item.url || item.website_url || item.website || item.link || "").trim()
              : "";
        const cleanUrl = sanitizeReferenceUrl(rawUrl);
        if (!cleanUrl || seen.has(cleanUrl) || excluded.has(cleanUrl)) continue;
        seen.add(cleanUrl);
        const titleRaw =
          item && typeof item === "object"
            ? String(item.title || item.name || item.snapshot?.title || "").trim()
            : "";
        if (item && typeof item === "object") {
          out.push({
            ...item,
            url: cleanUrl,
            title: titleRaw.slice(0, 160) || null,
          });
        } else {
          out.push({ url: cleanUrl, title: null });
        }
        if (out.length >= 6) break;
      }
      return out;
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
      if (/^(y|ya|yah|yep|yup|yeah|yrs|yesh)$/.test(compact)) return "yes";
      if (/\b(yes|yep|yeah|sure|affirmative|right|ok|okay|sounds good|sure thing|absolutely|go ahead|lets do it|let's do it|works for me|i guess so)\b/.test(t))
        return "yes";

      // no-ish
      if (
        /\b(no|nope|nah|negative|no thanks|dont|do not|not yet|not now|not right now|rather not|skip for now|pass for now|none|dont have|do not have|need one|i need one|want one|i want one)\b/.test(
          t
        )
      )
        return "no";

      return "unknown";
    }

    const MAX_ANSWER_CHARS = 4000;

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

    function canonicalizeBusinessTypeLabel(label) {
      const t = normalizeBusinessTypeLabel(label);
      if (!t) return "";
      if (/\b(home hobby|hobbyist|side hustle|side job|micro business|small side|personal seller)\b/.test(t)) {
        return "home hobbyist";
      }
      if (
        /\b(repos?|repositories?|template|boilerplate|starter kit|codebase|source code)\b/.test(t) &&
        /\b(sell|seller|marketplace|shop|store|development|developer|software)\b/.test(t)
      ) {
        return "developer repo marketplace";
      }
      if (/\b(freelance developer|software developer|web developer|software development)\b/.test(t)) {
        return "software development";
      }
      return t;
    }

    function isLikelyBusinessTypeLabel(text) {
      const raw = String(text || "").trim();
      if (!raw) return false;
      if (/https?:\/\//i.test(raw)) return false;
      const t = normalizeBusinessTypeLabel(raw);
      if (!t) return false;
      const words = t.split(/\s+/).filter(Boolean);
      if (!words.length || words.length > 6) return false;
      if (t.length > 48) return false;
      if (/^(i|we|my|our)\b/.test(t)) return false;
      if (/\b(want|need|would like|website|site|for myself|because|but|full time|part time|this can apply)\b/.test(t)) return false;
      return true;
    }

    function extractManualTypeFromNoAnswer(text) {
      const raw = String(text || "").trim();
      if (!raw) return null;
      const quoteMatch = raw.match(/["“](.+?)["”]/);
      if (quoteMatch?.[1] && isLikelyBusinessTypeLabel(quoteMatch[1])) {
        return canonicalizeBusinessTypeLabel(quoteMatch[1]);
      }
      const m = raw.match(/^\s*no[\s,:-]+(.+)$/i);
      if (m?.[1] && isLikelyBusinessTypeLabel(m[1])) {
        return canonicalizeBusinessTypeLabel(m[1]);
      }
      return null;
    }

    function fallbackSubtypeCandidates(desc) {
      const s = String(desc || "").toLowerCase();
      if (
        /\b(repos?|repositories?|template|boilerplate|starter kit|source code|code repo|github repo)\b/.test(s) &&
        /\b(sell|selling|for sale|marketplace|buy|checkout)\b/.test(s)
      ) {
        return ["developer repo marketplace", "software development", "freelance developer"];
      }
      if (
        /\b(hobby|for myself|side hustle|side job|part[- ]?time|not full time|just for fun|extra)\b/.test(s) &&
        /\b(sell|selling|flowers|cookies|puppies|plants|crafts|online)\b/.test(s)
      ) {
        return ["home hobbyist", "small online seller", "local micro business"];
      }
      if (/\b(hobby|for myself|side hustle|side job|part[- ]?time|not full time|just for fun)\b/.test(s)) {
        return ["home hobbyist", "local micro business", "small home service"];
      }
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

    function extractJsonObjectFromText(text) {
      const s = String(text || "");
      const start = s.indexOf("{");
      const end = s.lastIndexOf("}");
      if (start < 0 || end < 0 || end <= start) return null;
      try {
        const parsed = JSON.parse(s.slice(start, end + 1));
        return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : null;
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
      return /\b(plugin install|install plugin|install the plugin|install it|ai-webadmin|ai webadmin|ai-web admin|wordpress plugin|wp plugin|plugin setup|set up plugin)\b/.test(
        t
      );
    }

    function parseSingleDigitChoice(text) {
      const t = String(text || "").trim();
      const m = t.match(/^([1-9])$/);
      if (!m) return null;
      const n = Number(m[1]);
      if (!Number.isFinite(n) || n < 1) return null;
      return n;
    }

    function parseMultipleDigitChoices(text, maxChoice = 9) {
      const t = String(text || "");
      if (!t) return [];
      const re = /(^|[^0-9])([1-9])([^0-9]|$)/g;
      const seen = new Set();
      const choices = [];
      let m;
      while ((m = re.exec(t)) !== null) {
        const n = Number(m[2]);
        if (!Number.isFinite(n) || n < 1 || n > maxChoice) continue;
        if (seen.has(n)) continue;
        seen.add(n);
        choices.push(n);
      }
      return choices;
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

    async function inferBusinessTypeCandidatesWithOpenAI(description, limit = 3, openAiApiKey = null) {
      const apiKey = String(openAiApiKey || env.OPENAI_API_KEY || "").trim();
      if (!apiKey) return [];
      try {
        const r = await fetch("https://api.openai.com/v1/responses", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            authorization: `Bearer ${apiKey}`,
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
        return canonicalizeBusinessTypeLabel(row?.canonical_type || "");
      } catch {
        return null;
      }
    }

    async function rememberBusinessType(description, canonical_type, source = "user_confirmed") {
      const phrase = normalizeBusinessPhrase(description);
      const type = canonicalizeBusinessTypeLabel(canonical_type);
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

    async function resolveBusinessTypeCandidates(description, openAiApiKey = null) {
      const remembered = await getRememberedBusinessType(description);
      if (remembered) return { source: "remembered", candidates: [remembered] };

      const deterministic = canonicalizeBusinessTypeLabel(guessBusinessType(description));
      if (deterministic && deterministic !== "local business") {
        return { source: "heuristic", candidates: [deterministic] };
      }

      const fallback = fallbackSubtypeCandidates(description);
      const ai = await inferBusinessTypeCandidatesWithOpenAI(description, 3, openAiApiKey);
      const candidates = Array.from(
        new Set(
          [...fallback, ...ai]
            .map((x) => canonicalizeBusinessTypeLabel(x))
            .filter(Boolean)
            .filter((x) => x !== "local business")
        )
      ).slice(0, 3);

      if (!candidates.length) return { source: "fallback", candidates: ["local business"] };
      return { source: ai.length ? "openai" : "fallback", candidates };
    }

    function guessBusinessType(desc) {
      const s = (desc || "").toLowerCase();
      if (
        /\b(repos?|repositories?|template|boilerplate|starter kit|source code|github repo|codebase)\b/.test(s) &&
        /\b(sell|selling|for sale|marketplace|buy|checkout)\b/.test(s)
      ) {
        return "developer repo marketplace";
      }
      if (/\b(web developer|software developer|build websites|build web apps|software engineer)\b/.test(s)) {
        return "software development";
      }
      if (/\b(hobby|for myself|side hustle|side job|part[- ]?time|not full time|just for fun)\b/.test(s)) return "home hobbyist";
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

    function wantsHelpWithWebsiteChanges(text) {
      const t = String(text || "").toLowerCase();
      const wantsHelp = /\b(help|can you|could you|assist|guide)\b/.test(t);
      const wantsChanges = /\b(change|changes|improve|improvements|update|updates|revamp|redo|iterate|edit|tweak)\b/.test(t);
      const siteContext = /\b(site|website|web site|design|layout|branding|ui|ux)\b/.test(t);
      const contextualPronoun = /\b(it|this|that)\b/.test(t);
      return wantsHelp && wantsChanges && (siteContext || contextualPronoun);
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

    function sanitizePluginSlugList(raw, limit = 300) {
      if (!Array.isArray(raw)) return [];
      const out = [];
      const seen = new Set();
      for (const item of raw) {
        const slug = String(item || "")
          .trim()
          .slice(0, 220);
        if (!slug || seen.has(slug)) continue;
        seen.add(slug);
        out.push(slug);
        if (out.length >= Math.max(1, limit)) break;
      }
      return out;
    }

    function sanitizeActivePluginEntries(raw, limit = 300) {
      if (!Array.isArray(raw)) return [];
      const out = [];
      const seen = new Set();
      for (const item of raw) {
        if (!item || typeof item !== "object") continue;
        const slug = String(item.slug || item.plugin_file || "")
          .trim()
          .slice(0, 220);
        if (!slug || seen.has(slug)) continue;
        seen.add(slug);
        out.push({
          slug,
          name: String(item.name || slug)
            .trim()
            .slice(0, 180),
          version: String(item.version || "")
            .trim()
            .slice(0, 60),
        });
        if (out.length >= Math.max(1, limit)) break;
      }
      return out;
    }

    function sanitizePluginRiskCandidates(raw, limit = 80) {
      if (!Array.isArray(raw)) return [];
      const out = [];
      const seen = new Set();
      for (const item of raw) {
        if (!item || typeof item !== "object") continue;
        const slug = String(item.slug || item.plugin_file || "")
          .trim()
          .slice(0, 220);
        if (!slug || seen.has(slug)) continue;
        seen.add(slug);
        const riskScoreRaw = Number(item.risk_score);
        const riskScore = Number.isFinite(riskScoreRaw) ? Math.max(1, Math.min(10, Math.round(riskScoreRaw))) : 1;
        const riskLevelRaw = String(item.risk_level || "").trim().toLowerCase();
        const riskLevel = ["high", "medium", "low"].includes(riskLevelRaw)
          ? riskLevelRaw
          : riskScore >= 8
            ? "high"
            : riskScore >= 6
              ? "medium"
              : "low";
        const updateAvailable = normalizeMaybeBool(item.update_available, false) === true;
        const reasons = Array.isArray(item.reasons)
          ? item.reasons
              .map((x) => String(x || "").trim().slice(0, 220))
              .filter(Boolean)
              .slice(0, 4)
          : [];
        const checks = Array.isArray(item.functional_checks)
          ? item.functional_checks
              .map((x) => String(x || "").trim().slice(0, 180))
              .filter(Boolean)
              .slice(0, 8)
          : [];
        out.push({
          slug,
          name: String(item.name || slug)
            .trim()
            .slice(0, 180),
          version: String(item.version || "")
            .trim()
            .slice(0, 60),
          risk_score: riskScore,
          risk_level: riskLevel,
          update_available: updateAvailable,
          reasons,
          suggested_action: String(item.suggested_action || "")
            .trim()
            .slice(0, 260),
          functional_checks: checks,
        });
        if (out.length >= Math.max(1, limit)) break;
      }
      return out;
    }

    function sanitizeUrlList(raw, limit = 20) {
      if (!Array.isArray(raw)) return [];
      const out = [];
      const seen = new Set();
      for (const value of raw) {
        const url = String(value || "").trim();
        if (!url || seen.has(url)) continue;
        if (!/^https?:\/\//i.test(url)) continue;
        seen.add(url);
        out.push(url.slice(0, 500));
        if (out.length >= Math.max(1, limit)) break;
      }
      return out;
    }

    function normalizePluginInventoryPayload(rawInventory) {
      const inv = rawInventory && typeof rawInventory === "object" ? rawInventory : {};
      return {
        inactive_plugin_slugs: sanitizePluginSlugList(inv.inactive_plugin_slugs, 300),
        migration_plugin_slugs: sanitizePluginSlugList(inv.migration_plugin_slugs, 300),
        unneeded_plugin_slugs: sanitizePluginSlugList(inv.unneeded_plugin_slugs, 300),
        active_plugin_slugs: sanitizePluginSlugList(inv.active_plugin_slugs, 400),
        active_plugins: sanitizeActivePluginEntries(inv.active_plugins, 400),
        risk_candidates: sanitizePluginRiskCandidates(inv.risk_candidates, 120),
        analytics_missing_urls: sanitizeUrlList(inv.analytics_missing_urls, 20),
        analytics_measurement_ids: sanitizePluginSlugList(inv.analytics_measurement_ids, 40),
        analytics_gtm_ids: sanitizePluginSlugList(inv.analytics_gtm_ids, 40),
      };
    }

    function inferR2CdnPluginCandidates(activePlugins) {
      const patterns = [
        { re: /(autoptimize|asset clean|perfmatters|wp[- ]?optimize|flyingpress|speed booster)/i, reason: "Asset optimization overlap once Worker + CDN caching is active." },
        { re: /(cache|rocket|litespeed|w3 total cache|wp super cache|cache enabler)/i, reason: "Page/static cache overlap after Cloudflare edge cache + R2 static offload." },
        { re: /(cdn|cloudinary|image optimizer|shortpixel|smush|imagify|lazy load|webp)/i, reason: "Image/CDN plugin may be reduced when media/static files are offloaded to R2 + CDN." },
      ];
      const out = [];
      const seen = new Set();
      for (const p of Array.isArray(activePlugins) ? activePlugins : []) {
        const slug = String(p?.slug || "").trim();
        const name = String(p?.name || slug).trim();
        if (!slug || seen.has(slug)) continue;
        const hay = `${slug} ${name}`.toLowerCase();
        for (const pat of patterns) {
          if (pat.re.test(hay)) {
            out.push({
              slug,
              name: name || slug,
              reason: pat.reason,
              confidence: "medium",
            });
            seen.add(slug);
            break;
          }
        }
      }
      return out.slice(0, 40);
    }

    function buildPluginOptimizationPlan(pluginState) {
      const plugin = pluginState && typeof pluginState === "object" ? pluginState : {};
      const metrics = plugin.audit_metrics && typeof plugin.audit_metrics === "object" ? plugin.audit_metrics : {};
      const inventory = normalizePluginInventoryPayload(metrics.plugin_inventory);
      const removeNowSet = new Set(
        []
          .concat(inventory.inactive_plugin_slugs || [])
          .concat(inventory.unneeded_plugin_slugs || [])
          .concat(inventory.migration_plugin_slugs || [])
      );
      const removeNow = Array.from(removeNowSet)
        .filter(Boolean)
        .slice(0, 80)
        .map((slug) => ({ slug, reason: "Inactive, unneeded, or migration-only plugin." }));
      const removeAfterR2 = inferR2CdnPluginCandidates(inventory.active_plugins).filter((x) => !removeNowSet.has(x.slug));
      const sandboxTestFirst = sanitizePluginRiskCandidates(inventory.risk_candidates, 60)
        .filter((x) => !removeNowSet.has(x.slug))
        .slice(0, 20)
        .map((x) => ({
          slug: x.slug,
          name: x.name || x.slug,
          risk_level: x.risk_level,
          risk_score: x.risk_score,
          reason:
            Array.isArray(x.reasons) && x.reasons.length
              ? x.reasons[0]
              : x.suggested_action || "High functional dependency plugin; test in sandbox before production changes.",
          functional_checks: Array.isArray(x.functional_checks) ? x.functional_checks.slice(0, 6) : [],
        }));

      const githubConnected = Boolean(plugin?.github_vault?.connected);
      const hasGithubSnapshot = String(plugin?.backup?.last_github_status || "").toLowerCase() === "ok";
      const cloneStatus = hasGithubSnapshot ? "ready" : githubConnected ? "pending_first_snapshot" : "missing_github_connection";
      const cloneSummary =
        cloneStatus === "ready"
          ? "GitHub baseline snapshot is present."
          : cloneStatus === "pending_first_snapshot"
            ? "GitHub is connected. Run initial snapshot/clone to capture current site state."
            : "Connect GitHub vault first to enable baseline clone and rollback snapshots.";
      const autoloadTotalKb = Number.isFinite(Number(metrics?.autoload_total_kb))
        ? Math.max(0, Math.round(Number(metrics.autoload_total_kb)))
        : null;
      const pageCacheMedianTtfbMs = Number.isFinite(Number(metrics?.page_cache_median_ttfb_ms))
        ? Math.max(0, Math.round(Number(metrics.page_cache_median_ttfb_ms)))
        : null;
      const pageCacheHeaderDetected = normalizeMaybeBool(metrics?.page_cache_header_detected, null);
      const performanceSignals = [];
      if (pageCacheHeaderDetected === false) {
        performanceSignals.push("page cache headers missing");
      }
      if (Number.isFinite(pageCacheMedianTtfbMs) && pageCacheMedianTtfbMs > 600) {
        performanceSignals.push(`median response ${pageCacheMedianTtfbMs}ms`);
      }
      if (Number.isFinite(autoloadTotalKb) && autoloadTotalKb >= 800) {
        performanceSignals.push(`autoload ${autoloadTotalKb}KB`);
      }
      const performanceSummary = performanceSignals.length
        ? ` Performance risks: ${performanceSignals.join(", ")}.`
        : "";

      const summary =
        `Remove now: ${removeNow.length}. ` +
        `Candidate removals after R2/CDN offload: ${removeAfterR2.length}. ` +
        `Sandbox test-first plugins: ${sandboxTestFirst.length}. ` +
        `${cloneSummary}${performanceSummary}`;
      return {
        generated_at: new Date().toISOString(),
        clone_status: cloneStatus,
        clone_summary: cloneSummary,
        remove_now: removeNow,
        remove_after_r2_cdn: removeAfterR2,
        sandbox_test_first: sandboxTestFirst,
        summary,
      };
    }

    function sanitizeMediaObjectKey(rawKey) {
      const key = String(rawKey || "").trim().replace(/^\/+/, "");
      if (!key) return "";
      if (key.length > 500) return "";
      if (key.includes("..")) return "";
      if (!/^[a-zA-Z0-9/_\-.]+$/.test(key)) return "";
      return key.replace(/\/{2,}/g, "/");
    }

    function sanitizeMediaAssetBatch(raw, limit = 40) {
      if (!Array.isArray(raw)) return [];
      const out = [];
      const seen = new Set();
      for (const item of raw) {
        let url = "";
        let attachmentId = null;
        let r2Key = "";
        if (typeof item === "string") {
          url = String(item).trim();
        } else if (item && typeof item === "object") {
          url = String(item.url || "").trim();
          const id = Number(item.attachment_id);
          attachmentId = Number.isFinite(id) && id > 0 ? Math.round(id) : null;
          r2Key = sanitizeMediaObjectKey(item.r2_key || "");
        }
        if (!url || seen.has(url)) continue;
        if (!/^https?:\/\//i.test(url)) continue;
        seen.add(url);
        out.push({ url, attachment_id: attachmentId, r2_key: r2Key || null });
        if (out.length >= Math.max(1, Math.min(200, limit))) break;
      }
      return out;
    }

    function imageExtFromUrlOrContentType(assetUrl, contentType = "") {
      const path = String(assetUrl || "")
        .split("?")[0]
        .toLowerCase();
      const m = path.match(/\.([a-z0-9]{2,5})$/i);
      if (m && ["jpg", "jpeg", "png", "gif", "webp", "svg", "avif", "bmp", "ico"].includes(m[1])) return m[1];
      const ct = String(contentType || "").toLowerCase();
      if (ct.includes("jpeg")) return "jpg";
      if (ct.includes("png")) return "png";
      if (ct.includes("gif")) return "gif";
      if (ct.includes("webp")) return "webp";
      if (ct.includes("svg")) return "svg";
      if (ct.includes("avif")) return "avif";
      if (ct.includes("bmp")) return "bmp";
      if (ct.includes("icon") || ct.includes("ico")) return "ico";
      return "img";
    }

    function normalizeMediaMetadataText(raw, maxLen = 220) {
      const limit = Math.max(20, Math.min(1000, Number(maxLen) || 220));
      return String(raw || "")
        .replace(/<[^>]*>/g, " ")
        .replace(/\s+/g, " ")
        .trim()
        .slice(0, limit);
    }

    function sanitizeFilenameSlug(raw, fallback = "media-asset") {
      const cleaned = String(raw || "")
        .toLowerCase()
        .replace(/\.[a-z0-9]{2,5}$/i, "")
        .replace(/[^a-z0-9\s_-]/g, " ")
        .replace(/[\s_]+/g, "-")
        .replace(/-+/g, "-")
        .replace(/^-+|-+$/g, "")
        .slice(0, 110);
      if (cleaned) return cleaned;
      const fallbackClean = String(fallback || "media-asset")
        .toLowerCase()
        .replace(/[^a-z0-9\s_-]/g, " ")
        .replace(/[\s_]+/g, "-")
        .replace(/-+/g, "-")
        .replace(/^-+|-+$/g, "")
        .slice(0, 110);
      return fallbackClean || "media-asset";
    }

    function mediaSubjectFromAssetUrl(assetUrl) {
      let base = "";
      try {
        const u = new URL(String(assetUrl || "").trim());
        const last = decodeURIComponent((u.pathname || "").split("/").pop() || "");
        base = last.replace(/\.[a-z0-9]{2,5}$/i, "");
      } catch {
        base = String(assetUrl || "")
          .split("/")
          .pop()
          .replace(/\?.*$/, "")
          .replace(/\.[a-z0-9]{2,5}$/i, "");
      }
      const cleaned = base
        .replace(/[_-]+/g, " ")
        .replace(/\b\d{2,}\b/g, " ")
        .replace(/\s+/g, " ")
        .trim();
      if (!cleaned || /^(image|photo|screenshot|img|attachment)$/i.test(cleaned)) return "Service photo";
      return cleaned
        .toLowerCase()
        .replace(/\b([a-z])/g, (m) => m.toUpperCase());
    }

    function buildFallbackMediaMetadata(asset, context = {}) {
      const subject = normalizeMediaMetadataText(mediaSubjectFromAssetUrl(asset?.url || ""), 90) || "Service photo";
      const brand = normalizeMediaMetadataText(context?.brand || "", 80);
      const location = normalizeMediaMetadataText(context?.location || "", 80);
      const primaryKeyword = normalizeMediaMetadataText(context?.primary_keyword || "", 80);

      const titleParts = [subject, brand, location].filter(Boolean);
      const title = normalizeMediaMetadataText(titleParts.join(" - ") || subject, 120);
      const alt = normalizeMediaMetadataText(
        `${subject}${brand ? ` by ${brand}` : ""}${location ? ` in ${location}` : ""}.`,
        190
      );
      const caption = normalizeMediaMetadataText(
        `${subject}${brand ? ` - ${brand}` : ""}${location ? `, ${location}` : ""}`,
        190
      );
      const description = normalizeMediaMetadataText(
        `${subject}${brand ? ` for ${brand}` : ""}${location ? ` in ${location}` : ""}${
          primaryKeyword ? `. Focus: ${primaryKeyword}.` : "."
        }`,
        380
      );
      const filenameSeed = [brand, primaryKeyword, location, subject].filter(Boolean).join(" ");
      const filename_slug = sanitizeFilenameSlug(filenameSeed, subject);

      return { title, alt, caption, description, filename_slug };
    }

    function mergeMediaMetadataWithFallback(candidate, fallback) {
      const base = fallback && typeof fallback === "object" ? fallback : {};
      const ai = candidate && typeof candidate === "object" ? candidate : {};
      return {
        title: normalizeMediaMetadataText(ai.title || base.title || "", 120),
        alt: normalizeMediaMetadataText(ai.alt || base.alt || "", 190),
        caption: normalizeMediaMetadataText(ai.caption || base.caption || "", 190),
        description: normalizeMediaMetadataText(ai.description || base.description || "", 380),
        filename_slug: sanitizeFilenameSlug(ai.filename_slug || base.filename_slug || "", "media-asset"),
      };
    }

    function normalizeHostOrNull(rawUrl) {
      try {
        const u = new URL(String(rawUrl || "").trim());
        return (u.hostname || "").toLowerCase() || null;
      } catch {
        return null;
      }
    }

    function questionTokens(text) {
      return String(text || "")
        .toLowerCase()
        .replace(/[^a-z0-9\s]/g, " ")
        .split(/\s+/)
        .filter((t) => t.length >= 3)
        .slice(0, 80);
    }

    function buildPluginAgentEvidenceCatalog(independent, dependent) {
      const plugin = ensurePluginState(dependent || {});
      const scan = dependent?.scan?.latest_result || {};
      const audit = plugin?.wordpress_audit_summary || null;
      const metrics = plugin?.audit_metrics || {};
      const plan = plugin?.optimization?.plan && typeof plugin.optimization.plan === "object" ? plugin.optimization.plan : buildPluginOptimizationPlan(plugin);
      const backup = plugin?.backup || {};
      const connect = plugin?.connect || {};
      const upgrade = ensureUpgradeState(dependent || {});

      const rows = [];
      const add = (title, value, sourcePath, keywords = []) => {
        const text = String(value ?? "").trim();
        if (!text) return;
        rows.push({
          title: String(title || "").trim(),
          value: text.slice(0, 320),
          source_path: String(sourcePath || "").trim(),
          keywords: Array.isArray(keywords) ? keywords.map((k) => String(k || "").toLowerCase()).filter(Boolean) : [],
        });
      };

      add("Business Type", independent?.business?.type_final || independent?.business?.type_confirmed, "independent.business.type_final", [
        "business",
        "type",
        "service",
      ]);
      add("Website URL", independent?.business?.own_site_url, "independent.business.own_site_url", ["website", "url", "domain"]);
      add("Platform Hint", scan?.platform_hint, "dependent.scan.latest_result.platform_hint", ["platform", "wordpress", "cms"]);

      if (audit) {
        add("Speed Score", `${audit.speedScore}/100`, "dependent.plugin.wordpress_audit_summary.speedScore", ["speed", "performance", "load"]);
        add("Security Score", `${audit.securityScore}/100`, "dependent.plugin.wordpress_audit_summary.securityScore", ["security", "safe", "risk"]);
        add("Schema Score", `${audit.schemaScore}/100`, "dependent.plugin.wordpress_audit_summary.schemaScore", ["schema", "seo", "google"]);
        add("Reliability Score", `${audit.reliabilityScore}/100`, "dependent.plugin.wordpress_audit_summary.reliabilityScore", ["reliability", "uptime", "links"]);
      }

      add("Outdated Plugins", metrics?.outdated_plugin_count, "dependent.plugin.audit_metrics.outdated_plugin_count", ["plugin", "outdated", "update"]);
      add("Inactive Plugins", metrics?.inactive_plugin_count, "dependent.plugin.audit_metrics.inactive_plugin_count", ["plugin", "inactive", "unused"]);
      add("Redundant Plugins", metrics?.redundant_plugin_count, "dependent.plugin.audit_metrics.redundant_plugin_count", ["plugin", "redundant", "duplicate"]);
      add("High-Risk Plugins", metrics?.high_risk_plugin_count, "dependent.plugin.audit_metrics.high_risk_plugin_count", [
        "plugin",
        "risk",
        "sandbox",
      ]);
      add("Medium-Risk Plugins", metrics?.medium_risk_plugin_count, "dependent.plugin.audit_metrics.medium_risk_plugin_count", [
        "plugin",
        "risk",
        "canary",
      ]);
      add("Pending Comment Moderation", metrics?.pending_comment_moderation_count, "dependent.plugin.audit_metrics.pending_comment_moderation_count", [
        "comment",
        "spam",
        "moderation",
      ]);
      add("Autoload Option Count", metrics?.autoload_option_count, "dependent.plugin.audit_metrics.autoload_option_count", [
        "autoload",
        "options",
        "performance",
      ]);
      add("Autoload Total KB", metrics?.autoload_total_kb, "dependent.plugin.audit_metrics.autoload_total_kb", [
        "autoload",
        "database",
        "size",
      ]);
      add("Page Cache Median TTFB", metrics?.page_cache_median_ttfb_ms, "dependent.plugin.audit_metrics.page_cache_median_ttfb_ms", [
        "page cache",
        "response",
        "speed",
      ]);
      add("Page Cache Header Detected", metrics?.page_cache_header_detected, "dependent.plugin.audit_metrics.page_cache_header_detected", [
        "page cache",
        "headers",
        "cache-control",
      ]);
      add("SMTP Plugins", metrics?.smtp_plugin_count, "dependent.plugin.audit_metrics.smtp_plugin_count", ["smtp", "email", "plugin"]);
      add("Site Kit Tracking Coverage", metrics?.analytics_tag_coverage_percent, "dependent.plugin.audit_metrics.analytics_tag_coverage_percent", [
        "analytics",
        "site kit",
        "tracking",
      ]);

      add(
        "Optimization Remove-Now Count",
        Array.isArray(plan?.remove_now) ? plan.remove_now.length : 0,
        "dependent.plugin.optimization.plan.remove_now",
        ["remove", "plugin", "unused", "cleanup"]
      );
      add(
        "Optimization After R2/CDN Count",
        Array.isArray(plan?.remove_after_r2_cdn) ? plan.remove_after_r2_cdn.length : 0,
        "dependent.plugin.optimization.plan.remove_after_r2_cdn",
        ["r2", "cdn", "cache", "asset", "plugin"]
      );
      add("Optimization Summary", plan?.summary, "dependent.plugin.optimization.plan.summary", ["optimize", "plugin", "summary"]);
      add("GitHub Clone Status", plan?.clone_status || backup?.last_github_status, "dependent.plugin.optimization.plan.clone_status", [
        "github",
        "clone",
        "backup",
        "snapshot",
      ]);
      add("GitHub Snapshot Path", backup?.last_github_path, "dependent.plugin.backup.last_github_path", ["github", "backup", "path", "snapshot"]);
      add("Cloudflare Connect Status", connect?.status, "dependent.plugin.connect.status", ["cloudflare", "connect", "status"]);
      add("Domain Expiry", upgrade?.domain_expiry_at, "dependent.upgrade.domain_expiry_at", ["domain", "expiry", "expiration"]);

      return rows;
    }

    function selectAgentProofs(question, evidenceRows, maxItems = 6) {
      const q = String(question || "").toLowerCase();
      const tokens = questionTokens(q);
      const scored = [];
      for (const row of Array.isArray(evidenceRows) ? evidenceRows : []) {
        let score = 0;
        const hay = `${row.title} ${row.value} ${row.source_path}`.toLowerCase();
        for (const token of tokens) {
          if (hay.includes(token)) score += 1;
        }
        for (const kw of row.keywords || []) {
          if (q.includes(kw)) score += 2;
        }
        if (score > 0) {
          scored.push({ ...row, score });
        }
      }
      scored.sort((a, b) => b.score - a.score);
      return scored.slice(0, Math.max(1, Math.min(12, maxItems)));
    }

    function buildAgentAnswerFromProofs(question, proofs, dependent) {
      const q = String(question || "").toLowerCase();
      const plugin = ensurePluginState(dependent || {});
      const plan = plugin?.optimization?.plan && typeof plugin.optimization.plan === "object" ? plugin.optimization.plan : buildPluginOptimizationPlan(plugin);

      if (/\b(remove|uninstall|unused|cleanup|clean up|which plugins)\b/.test(q)) {
        const removeNow = Array.isArray(plan?.remove_now) ? plan.remove_now.slice(0, 5).map((x) => x.slug) : [];
        const removeAfter = Array.isArray(plan?.remove_after_r2_cdn)
          ? plan.remove_after_r2_cdn.slice(0, 5).map((x) => x.slug)
          : [];
        const nowText = removeNow.length ? removeNow.join(", ") : "none detected yet";
        const afterText = removeAfter.length ? removeAfter.join(", ") : "none detected yet";
        return (
          `Here is the plugin cleanup plan I can verify now.\n` +
          `Remove now: ${nowText}.\n` +
          `Remove after R2/CDN offload: ${afterText}.`
        );
      }

      if (!Array.isArray(proofs) || proofs.length === 0) {
        return (
          "I can’t prove that from current synced data yet. Run `Run Audit Sync Now` in the Audit tab, then ask again and I’ll return proof-backed answers."
        );
      }

      const top = proofs.slice(0, 3).map((p) => `${p.title}: ${p.value}`).join(" | ");
      return `Based on current synced data, here is what I can verify: ${top}.`;
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
      dependent.plugin.audit_metrics.high_risk_plugin_count = Number.isFinite(Number(dependent.plugin.audit_metrics.high_risk_plugin_count))
        ? Math.max(0, Math.round(Number(dependent.plugin.audit_metrics.high_risk_plugin_count)))
        : null;
      dependent.plugin.audit_metrics.medium_risk_plugin_count = Number.isFinite(Number(dependent.plugin.audit_metrics.medium_risk_plugin_count))
        ? Math.max(0, Math.round(Number(dependent.plugin.audit_metrics.medium_risk_plugin_count)))
        : null;
      dependent.plugin.audit_metrics.autoload_option_count = Number.isFinite(Number(dependent.plugin.audit_metrics.autoload_option_count))
        ? Math.max(0, Math.round(Number(dependent.plugin.audit_metrics.autoload_option_count)))
        : null;
      dependent.plugin.audit_metrics.autoload_total_bytes = Number.isFinite(Number(dependent.plugin.audit_metrics.autoload_total_bytes))
        ? Math.max(0, Math.round(Number(dependent.plugin.audit_metrics.autoload_total_bytes)))
        : null;
      dependent.plugin.audit_metrics.autoload_total_kb = Number.isFinite(Number(dependent.plugin.audit_metrics.autoload_total_kb))
        ? Math.max(0, Math.round(Number(dependent.plugin.audit_metrics.autoload_total_kb)))
        : null;
      dependent.plugin.audit_metrics.autoload_last_cleanup_at = Number.isFinite(Number(dependent.plugin.audit_metrics.autoload_last_cleanup_at))
        ? Math.max(0, Math.round(Number(dependent.plugin.audit_metrics.autoload_last_cleanup_at)))
        : null;
      dependent.plugin.audit_metrics.autoload_last_cleanup_summary =
        String(dependent.plugin.audit_metrics.autoload_last_cleanup_summary || "").trim().slice(0, 200) || null;
      dependent.plugin.audit_metrics.page_cache_builtin_enabled = normalizeMaybeBool(
        dependent.plugin.audit_metrics.page_cache_builtin_enabled,
        null
      );
      dependent.plugin.audit_metrics.page_cache_ttl_seconds = Number.isFinite(Number(dependent.plugin.audit_metrics.page_cache_ttl_seconds))
        ? Math.max(0, Math.round(Number(dependent.plugin.audit_metrics.page_cache_ttl_seconds)))
        : null;
      dependent.plugin.audit_metrics.page_cache_last_cleared_at = Number.isFinite(
        Number(dependent.plugin.audit_metrics.page_cache_last_cleared_at)
      )
        ? Math.max(0, Math.round(Number(dependent.plugin.audit_metrics.page_cache_last_cleared_at)))
        : null;
      dependent.plugin.audit_metrics.page_cache_last_clear_reason =
        String(dependent.plugin.audit_metrics.page_cache_last_clear_reason || "").trim().slice(0, 120) || null;
      dependent.plugin.audit_metrics.page_cache_health_status =
        String(dependent.plugin.audit_metrics.page_cache_health_status || "").trim().toLowerCase().slice(0, 40) || null;
      dependent.plugin.audit_metrics.page_cache_header_detected = normalizeMaybeBool(
        dependent.plugin.audit_metrics.page_cache_header_detected,
        null
      );
      dependent.plugin.audit_metrics.page_cache_plugin_detected = normalizeMaybeBool(
        dependent.plugin.audit_metrics.page_cache_plugin_detected,
        null
      );
      dependent.plugin.audit_metrics.page_cache_median_ttfb_ms = Number.isFinite(
        Number(dependent.plugin.audit_metrics.page_cache_median_ttfb_ms)
      )
        ? Math.max(0, Math.round(Number(dependent.plugin.audit_metrics.page_cache_median_ttfb_ms)))
        : null;
      dependent.plugin.audit_metrics.page_cache_checked_at = Number.isFinite(Number(dependent.plugin.audit_metrics.page_cache_checked_at))
        ? Math.max(0, Math.round(Number(dependent.plugin.audit_metrics.page_cache_checked_at)))
        : null;
      dependent.plugin.audit_metrics.smtp_plugin_count = Number.isFinite(Number(dependent.plugin.audit_metrics.smtp_plugin_count))
        ? Math.max(0, Math.round(Number(dependent.plugin.audit_metrics.smtp_plugin_count)))
        : null;
      dependent.plugin.audit_metrics.static_export_plugin_count = Number.isFinite(Number(dependent.plugin.audit_metrics.static_export_plugin_count))
        ? Math.max(0, Math.round(Number(dependent.plugin.audit_metrics.static_export_plugin_count)))
        : null;
      dependent.plugin.audit_metrics.static_export_memory_error_count = Number.isFinite(
        Number(dependent.plugin.audit_metrics.static_export_memory_error_count)
      )
        ? Math.max(0, Math.round(Number(dependent.plugin.audit_metrics.static_export_memory_error_count)))
        : null;
      dependent.plugin.audit_metrics.static_export_removed_plugin_count = Number.isFinite(
        Number(dependent.plugin.audit_metrics.static_export_removed_plugin_count)
      )
        ? Math.max(0, Math.round(Number(dependent.plugin.audit_metrics.static_export_removed_plugin_count)))
        : null;
      dependent.plugin.audit_metrics.static_export_last_status = dependent.plugin.audit_metrics.static_export_last_status || null;
      dependent.plugin.audit_metrics.static_export_last_error_message =
        dependent.plugin.audit_metrics.static_export_last_error_message || null;
      dependent.plugin.audit_metrics.static_export_last_error_source = dependent.plugin.audit_metrics.static_export_last_error_source || null;
      dependent.plugin.audit_metrics.static_export_last_error_at = dependent.plugin.audit_metrics.static_export_last_error_at || null;
      dependent.plugin.audit_metrics.analytics_site_kit_active = normalizeMaybeBool(
        dependent.plugin.audit_metrics.analytics_site_kit_active,
        null
      );
      dependent.plugin.audit_metrics.analytics_pages_checked_count = Number.isFinite(
        Number(dependent.plugin.audit_metrics.analytics_pages_checked_count)
      )
        ? Math.max(0, Math.round(Number(dependent.plugin.audit_metrics.analytics_pages_checked_count)))
        : null;
      dependent.plugin.audit_metrics.analytics_pages_with_tracking_count = Number.isFinite(
        Number(dependent.plugin.audit_metrics.analytics_pages_with_tracking_count)
      )
        ? Math.max(0, Math.round(Number(dependent.plugin.audit_metrics.analytics_pages_with_tracking_count)))
        : null;
      dependent.plugin.audit_metrics.analytics_pages_missing_tracking_count = Number.isFinite(
        Number(dependent.plugin.audit_metrics.analytics_pages_missing_tracking_count)
      )
        ? Math.max(0, Math.round(Number(dependent.plugin.audit_metrics.analytics_pages_missing_tracking_count)))
        : null;
      dependent.plugin.audit_metrics.analytics_unreachable_page_count = Number.isFinite(
        Number(dependent.plugin.audit_metrics.analytics_unreachable_page_count)
      )
        ? Math.max(0, Math.round(Number(dependent.plugin.audit_metrics.analytics_unreachable_page_count)))
        : null;
      dependent.plugin.audit_metrics.analytics_tag_coverage_percent = Number.isFinite(
        Number(dependent.plugin.audit_metrics.analytics_tag_coverage_percent)
      )
        ? Math.max(0, Math.min(100, Math.round(Number(dependent.plugin.audit_metrics.analytics_tag_coverage_percent))))
        : null;
      dependent.plugin.audit_metrics.analytics_measurement_id_count = Number.isFinite(
        Number(dependent.plugin.audit_metrics.analytics_measurement_id_count)
      )
        ? Math.max(0, Math.round(Number(dependent.plugin.audit_metrics.analytics_measurement_id_count)))
        : null;
      dependent.plugin.audit_metrics.analytics_gtm_container_count = Number.isFinite(
        Number(dependent.plugin.audit_metrics.analytics_gtm_container_count)
      )
        ? Math.max(0, Math.round(Number(dependent.plugin.audit_metrics.analytics_gtm_container_count)))
        : null;
      dependent.plugin.audit_metrics.analytics_status = dependent.plugin.audit_metrics.analytics_status || null;
      dependent.plugin.audit_metrics.analytics_last_checked_at = Number.isFinite(
        Number(dependent.plugin.audit_metrics.analytics_last_checked_at)
      )
        ? Math.max(0, Math.round(Number(dependent.plugin.audit_metrics.analytics_last_checked_at)))
        : null;
      dependent.plugin.audit_metrics.woocommerce_active = normalizeMaybeBool(dependent.plugin.audit_metrics.woocommerce_active, null);
      dependent.plugin.audit_metrics.woocommerce_status = dependent.plugin.audit_metrics.woocommerce_status || null;
      dependent.plugin.audit_metrics.woocommerce_product_count = Number.isFinite(
        Number(dependent.plugin.audit_metrics.woocommerce_product_count)
      )
        ? Math.max(0, Math.round(Number(dependent.plugin.audit_metrics.woocommerce_product_count)))
        : null;
      dependent.plugin.audit_metrics.woocommerce_completed_order_count = Number.isFinite(
        Number(dependent.plugin.audit_metrics.woocommerce_completed_order_count)
      )
        ? Math.max(0, Math.round(Number(dependent.plugin.audit_metrics.woocommerce_completed_order_count)))
        : null;
      dependent.plugin.audit_metrics.woocommerce_last_sale_at = Number.isFinite(
        Number(dependent.plugin.audit_metrics.woocommerce_last_sale_at)
      )
        ? Math.max(0, Math.round(Number(dependent.plugin.audit_metrics.woocommerce_last_sale_at)))
        : null;
      dependent.plugin.audit_metrics.woocommerce_sales_stale_days = Number.isFinite(
        Number(dependent.plugin.audit_metrics.woocommerce_sales_stale_days)
      )
        ? Math.max(0, Math.round(Number(dependent.plugin.audit_metrics.woocommerce_sales_stale_days)))
        : null;
      dependent.plugin.audit_metrics.analytics_missing_urls = sanitizeUrlList(
        dependent.plugin.audit_metrics.analytics_missing_urls,
        20
      );
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
      dependent.plugin.secrets_vault = dependent.plugin.secrets_vault || {};
      dependent.plugin.secrets_vault.last_uploaded_at = dependent.plugin.secrets_vault.last_uploaded_at || null;
      dependent.plugin.secrets_vault.last_status = dependent.plugin.secrets_vault.last_status || null;
      dependent.plugin.secrets_vault.last_message = dependent.plugin.secrets_vault.last_message || null;
      dependent.plugin.secrets_vault.items = dependent.plugin.secrets_vault.items && typeof dependent.plugin.secrets_vault.items === "object"
        ? dependent.plugin.secrets_vault.items
        : {};
      dependent.plugin.sandbox = dependent.plugin.sandbox || {};
      dependent.plugin.sandbox.enabled = normalizeMaybeBool(dependent.plugin.sandbox.enabled, true) === true;
      dependent.plugin.sandbox.last_run_at = dependent.plugin.sandbox.last_run_at || null;
      dependent.plugin.sandbox.last_status = dependent.plugin.sandbox.last_status || null;
      dependent.plugin.sandbox.last_summary = dependent.plugin.sandbox.last_summary || null;
      dependent.plugin.sandbox.last_risk_level = dependent.plugin.sandbox.last_risk_level || null;
      dependent.plugin.sandbox.last_report_id = dependent.plugin.sandbox.last_report_id || null;
      dependent.plugin.sandbox.last_outdated_plugin_count = Number.isFinite(Number(dependent.plugin.sandbox.last_outdated_plugin_count))
        ? Math.max(0, Math.round(Number(dependent.plugin.sandbox.last_outdated_plugin_count)))
        : 0;
      dependent.plugin.sandbox.last_report = dependent.plugin.sandbox.last_report && typeof dependent.plugin.sandbox.last_report === "object"
        ? dependent.plugin.sandbox.last_report
        : null;
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
      dependent.plugin.email_forwarding.verification_status =
        dependent.plugin.email_forwarding.verification_status || "not_started";
      dependent.plugin.email_forwarding.verification_email = dependent.plugin.email_forwarding.verification_email || null;
      dependent.plugin.email_forwarding.verification_sent_at = dependent.plugin.email_forwarding.verification_sent_at || null;
      dependent.plugin.email_forwarding.verification_confirmed_at =
        dependent.plugin.email_forwarding.verification_confirmed_at || null;
      dependent.plugin.email_forwarding.verification_pending_token_hash =
        dependent.plugin.email_forwarding.verification_pending_token_hash || null;
      dependent.plugin.email_forwarding.verification_pending_expires_at =
        dependent.plugin.email_forwarding.verification_pending_expires_at || null;
      dependent.plugin.email_forwarding.verification_last_token_id =
        dependent.plugin.email_forwarding.verification_last_token_id || null;
      dependent.plugin.email_forwarding.verification_last_error =
        dependent.plugin.email_forwarding.verification_last_error || null;
      dependent.plugin.media_offload = dependent.plugin.media_offload || {};
      dependent.plugin.media_offload.enabled = normalizeMaybeBool(dependent.plugin.media_offload.enabled, true) === true;
      dependent.plugin.media_offload.last_run_at = dependent.plugin.media_offload.last_run_at || null;
      dependent.plugin.media_offload.last_status = dependent.plugin.media_offload.last_status || null;
      dependent.plugin.media_offload.last_message = dependent.plugin.media_offload.last_message || null;
      dependent.plugin.media_offload.last_manifest_r2_key = dependent.plugin.media_offload.last_manifest_r2_key || null;
      dependent.plugin.media_offload.last_github_manifest_status = dependent.plugin.media_offload.last_github_manifest_status || null;
      dependent.plugin.media_offload.last_github_manifest_path = dependent.plugin.media_offload.last_github_manifest_path || null;
      dependent.plugin.media_offload.last_github_manifest_error = dependent.plugin.media_offload.last_github_manifest_error || null;
      dependent.plugin.media_offload.last_processed_count = Number.isFinite(Number(dependent.plugin.media_offload.last_processed_count))
        ? Math.max(0, Math.round(Number(dependent.plugin.media_offload.last_processed_count)))
        : 0;
      dependent.plugin.media_offload.last_failed_count = Number.isFinite(Number(dependent.plugin.media_offload.last_failed_count))
        ? Math.max(0, Math.round(Number(dependent.plugin.media_offload.last_failed_count)))
        : 0;
      dependent.plugin.media_offload.last_max_attachment_id = Number.isFinite(Number(dependent.plugin.media_offload.last_max_attachment_id))
        ? Math.max(0, Math.round(Number(dependent.plugin.media_offload.last_max_attachment_id)))
        : 0;
      dependent.plugin.media_offload.total_processed = Number.isFinite(Number(dependent.plugin.media_offload.total_processed))
        ? Math.max(0, Math.round(Number(dependent.plugin.media_offload.total_processed)))
        : 0;
      dependent.plugin.media_offload.total_failed = Number.isFinite(Number(dependent.plugin.media_offload.total_failed))
        ? Math.max(0, Math.round(Number(dependent.plugin.media_offload.total_failed)))
        : 0;
      dependent.plugin.optimization = dependent.plugin.optimization || {};
      dependent.plugin.optimization.last_generated_at = dependent.plugin.optimization.last_generated_at || null;
      dependent.plugin.optimization.last_status = dependent.plugin.optimization.last_status || null;
      dependent.plugin.optimization.last_summary = dependent.plugin.optimization.last_summary || null;
      dependent.plugin.optimization.plan =
        dependent.plugin.optimization.plan && typeof dependent.plugin.optimization.plan === "object"
          ? dependent.plugin.optimization.plan
          : null;
      dependent.plugin.agent_chat = dependent.plugin.agent_chat || {};
      dependent.plugin.agent_chat.last_question = dependent.plugin.agent_chat.last_question || null;
      dependent.plugin.agent_chat.last_answer = dependent.plugin.agent_chat.last_answer || null;
      dependent.plugin.agent_chat.last_asked_at = dependent.plugin.agent_chat.last_asked_at || null;
      dependent.plugin.agent_chat.last_proofs = Array.isArray(dependent.plugin.agent_chat.last_proofs)
        ? dependent.plugin.agent_chat.last_proofs
        : [];
      dependent.plugin.agent_chat.history = Array.isArray(dependent.plugin.agent_chat.history) ? dependent.plugin.agent_chat.history : [];
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
          description: "Connect your Cloudflare account to publish and manage your site setup.",
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
          description: "Required for activation: connect GitHub token vault for sandbox-safe update workflows.",
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

    function normalizeVaultSecretType(raw) {
      const t = String(raw || "").trim().toLowerCase();
      if (t === "cloudflare_api_token") return "cloudflare_api_token";
      if (t === "github_token" || t === "github_fine_grained_token") return "github_token";
      if (t === "hosting_provider_api_token") return "hosting_provider_api_token";
      if (t === "openai_api_key" || t === "openai_key") return "openai_api_key";
      return null;
    }

    function isLikelyOpenAiApiKey(token) {
      const t = String(token || "").trim();
      if (!t) return false;
      return /^sk-[a-z0-9._-]{20,}$/i.test(t);
    }

    async function resolveOpenAiApiKeyForDependent(dependent) {
      const envKey = String(env.OPENAI_API_KEY || "").trim();
      if (envKey) return envKey;
      const cipher = String(dependent?.plugin?.secrets_vault?.items?.openai_api_key?.token_cipher || "").trim();
      if (!cipher) return null;
      try {
        const decrypted = await decryptSecretFromVault(cipher);
        return isLikelyOpenAiApiKey(decrypted) ? String(decrypted).trim() : null;
      } catch {
        return null;
      }
    }

    function majorVersion(text) {
      const raw = String(text || "").trim();
      const m = raw.match(/^(\d+)/);
      if (!m) return null;
      const n = Number(m[1]);
      return Number.isFinite(n) ? n : null;
    }

    function sandboxPluginRiskScore(item) {
      const name = String(item?.name || item?.plugin_file || "").toLowerCase();
      const currentMajor = majorVersion(item?.current_version);
      const newMajor = majorVersion(item?.new_version);
      let score = 1;
      if (name.includes("woocommerce") || name.includes("elementor")) score += 3;
      if (name.includes("security") || name.includes("wordfence") || name.includes("sucuri")) score += 2;
      if (name.includes("cache") || name.includes("rocket") || name.includes("litespeed")) score += 2;
      if (name.includes("builder") || name.includes("theme")) score += 1;
      if (Number.isFinite(currentMajor) && Number.isFinite(newMajor) && newMajor > currentMajor) {
        score += Math.min(3, Math.max(0, newMajor - currentMajor));
      }
      return Math.max(1, Math.min(10, score));
    }

    function sandboxChecksForPlugin(plugin) {
      const slug = String(plugin?.slug || plugin?.plugin_file || "").toLowerCase();
      const name = String(plugin?.name || "").toLowerCase();
      const hay = `${slug} ${name}`;
      if (/(woocommerce|cart|checkout|variation)/i.test(hay)) {
        return ["Product/variation selector works", "Add-to-cart works", "Checkout/payment flow works"];
      }
      if (/(elementor|template|builder|addon)/i.test(hay)) {
        return ["Homepage and landing layout render", "Header/footer templates render", "No widget or CSS regressions"];
      }
      if (/(site kit|analytics|gtm|google)/i.test(hay)) {
        return ["Tracking tags present on key pages", "Measurement IDs are consistent", "No analytics JS errors"];
      }
      if (/(instagram|feed|social)/i.test(hay)) {
        return ["Feed/widget blocks load", "No API/auth token errors", "Page speed remains acceptable"];
      }
      return ["Homepage loads with no errors", "Primary contact/lead form submits", "Critical CTA buttons and links work"];
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

    async function deriveWalletUserId(walletAddress) {
      const address = String(walletAddress || "").trim().toLowerCase();
      if (!address) return null;
      const digest = await sha256Hex(address);
      return `usr_wallet_${digest.slice(0, 24)}`;
    }

    function safeConstantCompareHex(a, b) {
      const x = String(a || "").trim().toLowerCase();
      const y = String(b || "").trim().toLowerCase();
      if (!x || !y || x.length !== y.length) return false;
      let mismatch = 0;
      for (let i = 0; i < x.length; i += 1) mismatch |= x.charCodeAt(i) ^ y.charCodeAt(i);
      return mismatch === 0;
    }

    function safeConstantCompareText(a, b) {
      const x = String(a || "");
      const y = String(b || "");
      if (!x || !y || x.length !== y.length) return false;
      let mismatch = 0;
      for (let i = 0; i < x.length; i += 1) mismatch |= x.charCodeAt(i) ^ y.charCodeAt(i);
      return mismatch === 0;
    }

    function normalizeForwardEmail(value) {
      const v = String(value || "").trim().toLowerCase();
      return v && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v) ? v : null;
    }

    function resetLeadForwardVerification(emailForwarding, reason = "unverified") {
      if (!emailForwarding || typeof emailForwarding !== "object") return;
      emailForwarding.verification_status = reason;
      emailForwarding.verification_confirmed_at = null;
      emailForwarding.verification_pending_token_hash = null;
      emailForwarding.verification_pending_expires_at = null;
      emailForwarding.verification_last_token_id = null;
      emailForwarding.verification_last_error = null;
    }

    function buildLeadForwardVerificationView(emailForwarding) {
      const state = emailForwarding && typeof emailForwarding === "object" ? emailForwarding : {};
      const status = String(state.verification_status || "not_started").trim() || "not_started";
      return {
        status,
        verified: status === "verified",
        email: normalizeForwardEmail(state.verification_email) || normalizeForwardEmail(state.forward_to_email),
        sent_at: state.verification_sent_at || null,
        confirmed_at: state.verification_confirmed_at || null,
        pending_expires_at: state.verification_pending_expires_at || null,
        last_error: state.verification_last_error || null,
      };
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
      const parts = String(cipherText || "").split(".");
      if (parts.length !== 2) throw new Error("Invalid vault ciphertext");
      const iv = base64ToBytes(parts[0]);
      const cipher = base64ToBytes(parts[1]);
      const candidates = Array.from(
        new Set(
          [env.CREDENTIAL_VAULT_KEY, env.GITHUB_VAULT_KEY, env.WP_PLUGIN_SHARED_SECRET]
            .map((v) => String(v || "").trim())
            .filter(Boolean)
        )
      );
      if (!candidates.length) throw new Error("Missing vault encryption secret");
      let lastError = null;
      for (const candidate of candidates) {
        try {
          const key = await importAesKeyFromSecret(candidate);
          const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, cipher);
          return new TextDecoder().decode(plaintext);
        } catch (error) {
          lastError = error;
        }
      }
      throw lastError || new Error("Invalid vault ciphertext");
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
        "affiliate earnings",
        "affiliate income",
        "earn money fast",
        "work from home",
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

    async function moderateWpCommentWithOpenAI(input, heuristic, openAiApiKey = null) {
      const apiKey = String(openAiApiKey || env.OPENAI_API_KEY || "").trim();
      if (!apiKey) return null;
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
            authorization: `Bearer ${apiKey}`,
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

    async function inferMediaMetadataWithOpenAI(asset, context = {}, openAiApiKey = null) {
      const apiKey = String(openAiApiKey || env.OPENAI_API_KEY || "").trim();
      const assetUrl = String(asset?.url || "").trim();
      if (!apiKey || !assetUrl) return null;
      try {
        const prompt =
          "You are an SEO + accessibility assistant for WordPress image media metadata.\n" +
          "Return strict JSON only with keys: title, alt, caption, description, filename_slug.\n" +
          "Rules:\n" +
          "- title: concise, readable, <= 110 chars.\n" +
          "- alt: accessibility-first image description; plain language; <= 180 chars.\n" +
          "- caption: short marketing caption; <= 180 chars.\n" +
          "- description: 1-2 sentences, useful context; <= 360 chars.\n" +
          "- filename_slug: lowercase hyphen slug only (a-z, 0-9, -), no extension.\n" +
          "- Avoid hashtags, emojis, HTML, and keyword stuffing.\n\n" +
          `Business context brand: "${normalizeMediaMetadataText(context?.brand || "", 90)}"\n` +
          `Location context: "${normalizeMediaMetadataText(context?.location || "", 90)}"\n` +
          `Primary keyword context: "${normalizeMediaMetadataText(context?.primary_keyword || "", 90)}"\n`;

        const r = await fetch("https://api.openai.com/v1/responses", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            authorization: `Bearer ${apiKey}`,
          },
          body: JSON.stringify({
            model: "gpt-4.1-mini",
            input: [
              {
                role: "user",
                content: [
                  { type: "input_text", text: prompt },
                  { type: "input_image", image_url: assetUrl, detail: "auto" },
                ],
              },
            ],
          }),
        });
        if (!r.ok) return null;
        const data = await r.json().catch(() => null);
        const output =
          data?.output_text ||
          data?.output?.map((o) => o?.content?.map((c) => c?.text || "").join("\n") || "").join("\n") ||
          "";
        const parsed = extractJsonObjectFromText(output);
        if (!parsed) return null;
        return {
          title: normalizeMediaMetadataText(parsed.title || "", 120),
          alt: normalizeMediaMetadataText(parsed.alt || "", 190),
          caption: normalizeMediaMetadataText(parsed.caption || "", 190),
          description: normalizeMediaMetadataText(parsed.description || "", 380),
          filename_slug: sanitizeFilenameSlug(parsed.filename_slug || parsed.title || "", "media-asset"),
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
      const inventory = normalizePluginInventoryPayload(metrics?.plugin_inventory);
      const r2CdnCandidates = inferR2CdnPluginCandidates(inventory.active_plugins);
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
      const highRiskPluginCount = Number.isFinite(Number(metrics?.high_risk_plugin_count))
        ? Math.max(0, Math.round(Number(metrics.high_risk_plugin_count)))
        : null;
      const mediumRiskPluginCount = Number.isFinite(Number(metrics?.medium_risk_plugin_count))
        ? Math.max(0, Math.round(Number(metrics.medium_risk_plugin_count)))
        : null;
      const staticExportPluginCount = Number.isFinite(Number(metrics?.static_export_plugin_count))
        ? Math.max(0, Math.round(Number(metrics.static_export_plugin_count)))
        : null;
      const staticExportMemoryErrorCount = Number.isFinite(Number(metrics?.static_export_memory_error_count))
        ? Math.max(0, Math.round(Number(metrics.static_export_memory_error_count)))
        : null;
      const staticExportRemovedPluginCount = Number.isFinite(Number(metrics?.static_export_removed_plugin_count))
        ? Math.max(0, Math.round(Number(metrics.static_export_removed_plugin_count)))
        : null;
      const staticExportLastStatus = String(metrics?.static_export_last_status || "").trim().toLowerCase();
      const analyticsSiteKitActive = normalizeMaybeBool(metrics?.analytics_site_kit_active, null);
      const analyticsPagesCheckedCount = Number.isFinite(Number(metrics?.analytics_pages_checked_count))
        ? Math.max(0, Math.round(Number(metrics.analytics_pages_checked_count)))
        : null;
      const analyticsPagesWithTrackingCount = Number.isFinite(Number(metrics?.analytics_pages_with_tracking_count))
        ? Math.max(0, Math.round(Number(metrics.analytics_pages_with_tracking_count)))
        : null;
      const analyticsUnreachablePageCount = Number.isFinite(Number(metrics?.analytics_unreachable_page_count))
        ? Math.max(0, Math.round(Number(metrics.analytics_unreachable_page_count)))
        : null;
      const analyticsTagCoveragePercent = Number.isFinite(Number(metrics?.analytics_tag_coverage_percent))
        ? Math.max(0, Math.min(100, Math.round(Number(metrics.analytics_tag_coverage_percent))))
        : null;
      const analyticsStatus = String(metrics?.analytics_status || "").trim().toLowerCase();
      const woocommerceActive = normalizeMaybeBool(metrics?.woocommerce_active, null);
      const woocommerceStatus = String(metrics?.woocommerce_status || "").trim().toLowerCase();
      const woocommerceProductCount = Number.isFinite(Number(metrics?.woocommerce_product_count))
        ? Math.max(0, Math.round(Number(metrics.woocommerce_product_count)))
        : null;
      const woocommerceCompletedOrderCount = Number.isFinite(Number(metrics?.woocommerce_completed_order_count))
        ? Math.max(0, Math.round(Number(metrics.woocommerce_completed_order_count)))
        : null;
      const woocommerceSalesStaleDays = Number.isFinite(Number(metrics?.woocommerce_sales_stale_days))
        ? Math.max(0, Math.round(Number(metrics.woocommerce_sales_stale_days)))
        : null;
      const autoloadOptionCount = Number.isFinite(Number(metrics?.autoload_option_count))
        ? Math.max(0, Math.round(Number(metrics.autoload_option_count)))
        : null;
      const autoloadTotalKb = Number.isFinite(Number(metrics?.autoload_total_kb))
        ? Math.max(0, Math.round(Number(metrics.autoload_total_kb)))
        : null;
      const autoloadLastCleanupAt = Number.isFinite(Number(metrics?.autoload_last_cleanup_at))
        ? Math.max(0, Math.round(Number(metrics.autoload_last_cleanup_at)))
        : null;
      const pageCacheBuiltinEnabled = normalizeMaybeBool(metrics?.page_cache_builtin_enabled, null);
      const pageCacheHeaderDetected = normalizeMaybeBool(metrics?.page_cache_header_detected, null);
      const pageCachePluginDetected = normalizeMaybeBool(metrics?.page_cache_plugin_detected, null);
      const pageCacheMedianTtfbMs = Number.isFinite(Number(metrics?.page_cache_median_ttfb_ms))
        ? Math.max(0, Math.round(Number(metrics.page_cache_median_ttfb_ms)))
        : null;
      const pageCacheHealthStatus = String(metrics?.page_cache_health_status || "")
        .trim()
        .toLowerCase();
      const pageCacheCheckedAt = Number.isFinite(Number(metrics?.page_cache_checked_at))
        ? Math.max(0, Math.round(Number(metrics.page_cache_checked_at)))
        : null;
      const clamp = (v, min, max) => Math.max(min, Math.min(max, v));

      let speedScore = 85;
      if (bytes > 900000) speedScore = 45;
      else if (bytes > 500000) speedScore = 62;
      else if (bytes > 250000) speedScore = 76;
      if (Number.isFinite(pageCacheMedianTtfbMs)) {
        if (pageCacheMedianTtfbMs > 1800) speedScore -= 18;
        else if (pageCacheMedianTtfbMs > 1200) speedScore -= 13;
        else if (pageCacheMedianTtfbMs > 900) speedScore -= 8;
        else if (pageCacheMedianTtfbMs > 600) speedScore -= 4;
      }
      if (pageCacheHeaderDetected === false) speedScore -= 8;
      if (pageCachePluginDetected === false && pageCacheBuiltinEnabled !== true) speedScore -= 6;
      if (pageCacheHealthStatus === "critical") speedScore -= 5;
      speedScore = clamp(speedScore, 25, 99);

      let securityScore = 82;
      if (emails.length >= 2) securityScore -= 10;
      if (phones.length >= 5) securityScore -= 8;
      if (!schema.length) securityScore -= 6;
      if (Number.isFinite(outdatedPlugins) && outdatedPlugins > 0) securityScore -= outdatedPlugins >= 5 ? 8 : 4;
      if (Number.isFinite(inactivePlugins) && inactivePlugins >= 5) securityScore -= 3;
      if (Number.isFinite(redundantPlugins) && redundantPlugins >= 2) securityScore -= 3;
      if (Number.isFinite(ssoPluginCount) && ssoPluginCount < 1) securityScore -= 4;
      if (Number.isFinite(pendingComments) && pendingComments >= 20) securityScore -= 4;
      if (analyticsSiteKitActive === true && Number.isFinite(analyticsTagCoveragePercent) && analyticsTagCoveragePercent < 80) securityScore -= 4;
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
      if (pageCacheHealthStatus === "critical") reliabilityScore -= 8;
      else if (pageCacheHealthStatus === "warning") reliabilityScore -= 4;
      reliabilityScore = clamp(reliabilityScore, 30, 99);

      let speedGainMin = bytes > 500000 ? 10 : 6;
      let speedGainMax = bytes > 500000 ? 24 : 14;
      if (pageCacheHeaderDetected === false || (pageCachePluginDetected === false && pageCacheBuiltinEnabled !== true)) {
        speedGainMin += 6;
        speedGainMax += 12;
      }
      if (Number.isFinite(pageCacheMedianTtfbMs) && pageCacheMedianTtfbMs > 1200) {
        speedGainMin += 4;
        speedGainMax += 8;
      } else if (Number.isFinite(pageCacheMedianTtfbMs) && pageCacheMedianTtfbMs > 600) {
        speedGainMin += 2;
        speedGainMax += 5;
      }
      if (Number.isFinite(autoloadTotalKb) && autoloadTotalKb >= 800) {
        speedGainMin += 3;
        speedGainMax += 7;
      } else if (Number.isFinite(autoloadTotalKb) && autoloadTotalKb >= 500) {
        speedGainMin += 2;
        speedGainMax += 4;
      }
      speedGainMin = clamp(speedGainMin, 4, 35);
      speedGainMax = clamp(speedGainMax, speedGainMin + 1, 50);
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
      if (pageCacheHeaderDetected === false || (pageCachePluginDetected === false && pageCacheBuiltinEnabled !== true)) {
        recommendations.push("Enable page caching so visitors get static HTML responses instead of full page rebuilds on every request.");
      }
      if (Number.isFinite(pageCacheMedianTtfbMs) && pageCacheMedianTtfbMs > 600) {
        recommendations.push(
          `Reduce server response time from ~${pageCacheMedianTtfbMs} ms toward the <600 ms target by enabling cache headers and trimming heavy startup work.`
        );
      }
      if (Number.isFinite(autoloadOptionCount) && Number.isFinite(autoloadTotalKb) && (autoloadOptionCount >= 800 || autoloadTotalKb >= 800)) {
        recommendations.push(
          `Reduce autoloaded options (currently ${autoloadOptionCount} entries, ~${autoloadTotalKb} KB) so less data is loaded on every WordPress page request.`
        );
      }
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
      if (r2CdnCandidates.length > 0) {
        recommendations.push(
          `${r2CdnCandidates.length} active plugin${r2CdnCandidates.length === 1 ? "" : "s"} may become optional after R2 + CDN static offload.`
        );
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
      if (Number.isFinite(highRiskPluginCount) && highRiskPluginCount > 0) {
        recommendations.push(
          `Run sandbox one-by-one update/remove tests for ${highRiskPluginCount} high-risk plugin${highRiskPluginCount === 1 ? "" : "s"} before any production changes.`
        );
      }
      if (Number.isFinite(mediumRiskPluginCount) && mediumRiskPluginCount > 0) {
        recommendations.push(
          `Schedule canary checks for ${mediumRiskPluginCount} medium-risk plugin${mediumRiskPluginCount === 1 ? "" : "s"} to confirm no layout/form regressions.`
        );
      }
      if (analyticsSiteKitActive === true && Number.isFinite(analyticsPagesCheckedCount) && analyticsPagesCheckedCount > 0) {
        if (Number.isFinite(analyticsTagCoveragePercent) && analyticsTagCoveragePercent < 100) {
          recommendations.push(
            `Site Kit tracking tags were detected on ${analyticsPagesWithTrackingCount || 0}/${analyticsPagesCheckedCount} checked pages (${analyticsTagCoveragePercent}% coverage).`
          );
        }
      } else if (analyticsSiteKitActive === true && analyticsStatus === "missing") {
        recommendations.push("Site Kit is active but no GA/GTM tracking tags were detected on sampled pages.");
      } else if (analyticsSiteKitActive === true && Number.isFinite(analyticsUnreachablePageCount) && analyticsUnreachablePageCount > 0) {
        recommendations.push(
          `Could not verify analytics tags on ${analyticsUnreachablePageCount} sampled page${
            analyticsUnreachablePageCount === 1 ? "" : "s"
          } due to fetch/access limits; run plugin-side verification after connection.`
        );
      }
      if (woocommerceActive === true) {
        if (Number.isFinite(woocommerceProductCount) && woocommerceProductCount > 0 && Number.isFinite(woocommerceCompletedOrderCount) && woocommerceCompletedOrderCount === 0) {
          recommendations.push(
            `WooCommerce is active with ${woocommerceProductCount} product${woocommerceProductCount === 1 ? "" : "s"} but no completed sales detected. Either refresh product strategy or remove low-performing store/affiliate features to streamline the site.`
          );
        } else if (Number.isFinite(woocommerceSalesStaleDays) && woocommerceSalesStaleDays >= 365) {
          recommendations.push(
            `WooCommerce sales appear stale (${woocommerceSalesStaleDays} day${woocommerceSalesStaleDays === 1 ? "" : "s"} since last completed sale). Refresh products/offers or remove store features that are not producing value.`
          );
        } else if (woocommerceStatus === "no_sales") {
          recommendations.push("WooCommerce is active but no completed sales were reported; review product viability versus performance overhead.");
        }
      }
      if (brokenLinks > 0) {
        recommendations.push(`Fix ${brokenLinks} broken internal link${brokenLinks === 1 ? "" : "s"} and force 301 redirect fallback to homepage for dead URLs.`);
      }
      if (Number.isFinite(staticExportMemoryErrorCount) && staticExportMemoryErrorCount > 0) {
        const removedCount = Number.isFinite(staticExportRemovedPluginCount) ? staticExportRemovedPluginCount : 0;
        recommendations.push(
          removedCount > 0
            ? `Static-export memory failure detected and ${removedCount} static-export plugin${removedCount === 1 ? "" : "s"} removed to reduce risk.`
            : "Static-export memory failure detected; remove static-export plugins and run exports in a higher-memory sandbox/VPS."
        );
      } else if (Number.isFinite(staticExportPluginCount) && staticExportPluginCount > 0) {
        recommendations.push(
          `Review ${staticExportPluginCount} static-export plugin${staticExportPluginCount === 1 ? "" : "s"} and run heavy export jobs in a sandbox/VPS to avoid memory-limit failures.`
        );
      }
      recommendations.push("Use automated watchdog checks and staged update safety checks before major plugin/theme updates.");
      const asDisplay = (v) => (Number.isFinite(Number(v)) ? String(Number(v)) : "unknown");

      const summary =
        `WordPress audit summary: Speed ${speedScore}/100, Security ${securityScore}/100, Schema ${schemaScore}/100, Reliability ${reliabilityScore}/100. ` +
        `Signals reviewed: page size ${bytes || 0} bytes, public emails ${emails.length}, phones ${phones.length}, schema types ${schema.length}. ` +
        `Operational snapshot: emails queued ${asDisplay(emailQueue)}, plugins not updated ${asDisplay(outdatedPlugins)}, inactive plugins ${asDisplay(
        inactivePlugins
        )}, redundant plugins ${asDisplay(redundantPlugins)}, high-risk plugins ${asDisplay(
          highRiskPluginCount
        )}, medium-risk plugins ${asDisplay(mediumRiskPluginCount)}, wp-admin SSO plugins ${asDisplay(ssoPluginCount)}, comments awaiting moderation ${asDisplay(
          pendingComments
        )}, broken links ${brokenLinks}, page cache headers ${
          pageCacheHeaderDetected === true ? "detected" : pageCacheHeaderDetected === false ? "not_detected" : "unknown"
        }, page cache median response ${asDisplay(pageCacheMedianTtfbMs)} ms, page cache status ${
          pageCacheHealthStatus || "unknown"
        }, autoload options ${asDisplay(autoloadOptionCount)}, autoload total ${asDisplay(
          autoloadTotalKb
        )} KB, site kit tracking coverage ${asDisplay(
          analyticsTagCoveragePercent
        )}% (${asDisplay(analyticsPagesWithTrackingCount)}/${asDisplay(analyticsPagesCheckedCount)} pages), analytics pages unreachable ${asDisplay(
          analyticsUnreachablePageCount
        )}, woo products ${asDisplay(woocommerceProductCount)}, woo completed sales ${asDisplay(
          woocommerceCompletedOrderCount
        )}, woo sales stale days ${asDisplay(
          woocommerceSalesStaleDays
        )}, static export plugins ${asDisplay(
          staticExportPluginCount
        )}, static export memory errors ${asDisplay(
          staticExportMemoryErrorCount
        )}, static export plugins removed ${asDisplay(staticExportRemovedPluginCount)}, static export status ${
          staticExportLastStatus || "unknown"
        }.`;
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
        highRiskPluginCount,
        mediumRiskPluginCount,
        autoloadOptionCount,
        autoloadTotalKb,
        autoloadLastCleanupAt,
        pageCacheBuiltinEnabled,
        pageCacheHeaderDetected,
        pageCachePluginDetected,
        pageCacheMedianTtfbMs,
        pageCacheHealthStatus: pageCacheHealthStatus || null,
        pageCacheCheckedAt,
        analyticsSiteKitActive,
        analyticsPagesCheckedCount,
        analyticsPagesWithTrackingCount,
        analyticsUnreachablePageCount,
        analyticsTagCoveragePercent,
        analyticsStatus: analyticsStatus || null,
        woocommerceActive,
        woocommerceStatus: woocommerceStatus || null,
        woocommerceProductCount,
        woocommerceCompletedOrderCount,
        woocommerceSalesStaleDays,
        staticExportPluginCount,
        staticExportMemoryErrorCount,
        staticExportRemovedPluginCount,
        staticExportLastStatus: staticExportLastStatus || null,
        r2CdnCandidateCount: r2CdnCandidates.length,
      };
    }

    function summarizeSiteInfrastructure(result) {
      const infra = result?.infrastructure || {};
      const dns = result?.dns_profile || {};
      const linkAudit = result?.link_audit || {};
      const parts = [];
      if (infra?.registrar) parts.push(`Registrar: ${infra.registrar}`);
      if (infra?.hosting_company) parts.push(`Hosting hint: ${infra.hosting_company}`);
      if (infra?.a_record_primary_ip) parts.push(`A record IP: ${infra.a_record_primary_ip}`);
      if (infra?.hosting_type_hint) parts.push(`Hosting type: ${infra.hosting_type_hint}`);
      const costMin = Number(infra?.hosting_cost_estimate?.monthly_min_usd);
      const costMax = Number(infra?.hosting_cost_estimate?.monthly_max_usd);
      if (Number.isFinite(costMin) && Number.isFinite(costMax)) {
        parts.push(`Hosting cost est.: $${Math.max(0, Math.round(costMin))}-$${Math.max(0, Math.round(costMax))}/mo`);
      }
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
      const pageCacheHeadersLabel =
        audit.pageCacheHeaderDetected === true ? "yes" : audit.pageCacheHeaderDetected === false ? "no" : "unknown";
      const pageCacheMedianLabel = Number.isFinite(Number(audit.pageCacheMedianTtfbMs))
        ? `${Math.max(0, Math.round(Number(audit.pageCacheMedianTtfbMs)))} ms`
        : "unknown";
      const pageCacheStatusLabel = String(audit.pageCacheHealthStatus || "unknown")
        .replace(/_/g, " ")
        .trim();
      const autoloadCountLabel = asDisplay(audit.autoloadOptionCount);
      const autoloadKbLabel = Number.isFinite(Number(audit.autoloadTotalKb))
        ? `${Math.max(0, Math.round(Number(audit.autoloadTotalKb)))} KB`
        : "unknown";
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
        `- Page cache headers detected: ${pageCacheHeadersLabel}`,
        `- Median server response time (home): ${pageCacheMedianLabel}`,
        `- Page cache status: ${pageCacheStatusLabel}`,
        `- Autoloaded options (loaded on every page request): ${autoloadCountLabel} option(s), about ${autoloadKbLabel}`,
        Number.isFinite(Number(audit.pageCacheMedianTtfbMs)) && Number(audit.pageCacheMedianTtfbMs) > 600
          ? "- Why this matters: response time above 600 ms usually means pages feel slower, especially on first visit."
          : "- Why this matters: response time under 600 ms is generally a healthy baseline.",
        Number.isFinite(audit.autoloadTotalKb) && Number(audit.autoloadTotalKb) >= 800
          ? "- Why this matters: large autoloaded option data forces WordPress to load extra data on every request, which can slow all pages."
          : "- Why this matters: keeping autoloaded option data small helps every page start faster.",
        Number.isFinite(audit.analyticsTagCoveragePercent) && Number.isFinite(audit.analyticsPagesCheckedCount)
          ? `- Analytics tag coverage (sampled pages): ${asDisplay(audit.analyticsTagCoveragePercent)}% (${asDisplay(
              audit.analyticsPagesWithTrackingCount
            )}/${asDisplay(audit.analyticsPagesCheckedCount)} pages)`
          : "- Analytics tag coverage (sampled pages): not available",
        Number.isFinite(audit.highRiskPluginCount)
          ? `- High-risk active plugins flagged for sandbox-first changes: ${asDisplay(audit.highRiskPluginCount)}`
          : "- High-risk active plugins flagged for sandbox-first changes: unknown",
        audit.woocommerceActive === true
          ? `- Store snapshot: WooCommerce active, ${asDisplay(audit.woocommerceProductCount)} product(s), ${asDisplay(
              audit.woocommerceCompletedOrderCount
            )} completed sale(s)`
          : "- Store snapshot: WooCommerce not detected in this audit.",
        audit.woocommerceActive === true &&
        Number.isFinite(audit.woocommerceProductCount) &&
        audit.woocommerceProductCount > 0 &&
        Number.isFinite(audit.woocommerceCompletedOrderCount) &&
        audit.woocommerceCompletedOrderCount === 0
          ? "- Store signal: products exist but no completed sales were detected; usually this means you should refresh catalog strategy or remove low-performing store features."
          : null,
        Number.isFinite(audit.analyticsUnreachablePageCount) && audit.analyticsUnreachablePageCount > 0
          ? `- Analytics scan note: ${asDisplay(audit.analyticsUnreachablePageCount)} sampled page(s) could not be fetched for tag verification.`
          : "- Analytics scan note: sampled pages were reachable for this check.",
        "",
        "Admin-only checks (run after secure admin connection):",
        "- Plugin update status, comment moderation queue, and internal email queue are checked once admin access is connected.",
      ];

      const infraLines = [];
      if (infra?.hosting_company) infraLines.push(`- Hosting provider hint: ${infra.hosting_company}`);
      if (infra?.a_record_primary_ip) {
        infraLines.push(`- Primary A record IP: ${infra.a_record_primary_ip}`);
      }
      if (infra?.hosting_type_hint) {
        infraLines.push(`- Hosting type (estimated): ${String(infra.hosting_type_hint).replace(/_/g, " ")}`);
      }
      const costMin = Number(infra?.hosting_cost_estimate?.monthly_min_usd);
      const costMax = Number(infra?.hosting_cost_estimate?.monthly_max_usd);
      if (Number.isFinite(costMin) && Number.isFinite(costMax)) {
        const costConfidence = String(infra?.hosting_cost_estimate?.confidence || "low");
        infraLines.push(
          `- Estimated hosting cost range: $${Math.max(0, Math.round(costMin))}-$${Math.max(0, Math.round(
            costMax
          ))}/month (public-signal estimate, confidence: ${costConfidence})`
        );
      }
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
        "Projected improvement (estimated point increase):",
        `- Speed: +${audit.projectedGains.speed.min} to +${audit.projectedGains.speed.max}`,
        `- Security: +${audit.projectedGains.security.min} to +${audit.projectedGains.security.max}`,
        `- Schema: +${audit.projectedGains.schema.min} to +${audit.projectedGains.schema.max}`,
        `- Reliability: +${audit.projectedGains.reliability.min} to +${audit.projectedGains.reliability.max}`,
        "",
        "Estimated impact: likely medium-to-high, especially for spam/form-abuse protection and safer updates.",
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
          "I can also help you prioritize the next performance/security actions and generate a concrete implementation checklist.\n" +
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
          autoload_option_count: audit.autoloadOptionCount,
          autoload_total_kb: audit.autoloadTotalKb,
          page_cache_header_detected: audit.pageCacheHeaderDetected,
          page_cache_median_ttfb_ms: audit.pageCacheMedianTtfbMs,
          page_cache_health_status: audit.pageCacheHealthStatus,
          projected_gains: audit.projectedGains,
          projected_scores: audit.projectedScores,
        },
      };
    }

    function buildPluginInstallReplyPayload(independent, dependent, prefixNote = null) {
      const funnelSummary = buildFunnelCtaActions(dependent);
      const actionsById = new Map((funnelSummary.actions || []).map((a) => [a?.id, a]));
      const pluginStepActions = [
        actionsById.get("install_ai_webadmin_plugin"),
        actionsById.get("connect_cloudflare"),
        actionsById.get("install_tolldns_required"),
        actionsById.get("signup_github_backup"),
      ].filter((a) => a && a.url);
      const pluginAction = actionsById.get("install_ai_webadmin_plugin");
      const connectAction = actionsById.get("connect_cloudflare");
      const tollDnsAction = actionsById.get("install_tolldns_required");
      const githubAction = actionsById.get("signup_github_backup");
      const wpDetected =
        String(dependent?.scan?.platform_hint || "").toLowerCase() === "wordpress" ||
        String(dependent?.plugin?.detected_platform || "").toLowerCase() === "wordpress" ||
        String(independent?.business?.site_platform || "").toLowerCase() === "wordpress" ||
        independent?.business?.is_wordpress === true;

      let prompt = "";
      if (!wpDetected) {
        prompt =
          "I can install AI-WebAdmin on WordPress sites. Share your WordPress URL (or say \"audit my site\") and I’ll verify platform + start plugin onboarding.";
      } else {
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
            ? `4) Create/connect GitHub token vault (required for activation): ${githubAction.url}`
            : "4) Connect GitHub token vault (required for activation).",
        ];
        prompt = lines.join("\n");
      }

      if (prefixNote) prompt = `${String(prefixNote).trim()}\n\n${prompt}`;
      return {
        ok: true,
        next_state: "DONE",
        prompt,
        funnel_stage: funnelSummary.stage,
        upgrade_score: funnelSummary.score,
        cta_actions: funnelSummary.actions,
        plugin_step_actions: pluginStepActions.map((a, i) => ({
          step: i + 1,
          id: a.id,
          label: a.label || `Step ${i + 1}`,
          url: a.url,
        })),
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

      const clean = sanitizeReferenceUrl(href);
      return clean || null;
    }

    function isBuildBriefRequestAuthorized(request, urlObj) {
      const internalFlag =
        String(request.headers.get("x-build-brief-internal") || "").trim() === "1" ||
        String(urlObj.searchParams.get("internal") || "").trim() === "1";
      if (!internalFlag) return false;
      const expectedKey = String(env.BUILD_BRIEF_DEBUG_KEY || "").trim();
      if (!expectedKey) return true;
      const providedKey =
        String(request.headers.get("x-build-brief-key") || "").trim() ||
        String(urlObj.searchParams.get("key") || "").trim();
      return safeConstantCompareText(providedKey, expectedKey);
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
        wallet_login_enabled: true,
        wallet_supported_methods: ["metamask", "walletconnect", "ledger", "phantom"],
        wallet_supported_protocols: ["evm", "solana"],
        walletconnect_project_id: String(env.WALLETCONNECT_PROJECT_ID || "").trim() || null,
        premium_builder_enabled: premiumBuilderEnabled(),
        premium_wallet_required: premiumWalletRequired(),
        premium_spl_symbol: premiumSplTokenSymbol(),
        premium_free_tokens: normalizedPremiumFreeTokens(),
        premium_points_enabled: premiumPointsEnabled(),
        premium_points_symbol: premiumPointsSymbol(),
        premium_free_points: normalizedPremiumFreePoints(),
        premium_point_pack_price_usd: normalizedPointPackPriceUsd(),
        premium_point_pack_points: normalizedPointPackAmount(),
        premium_ad_rewards_enabled: premiumAdRewardsEnabled(),
        premium_llm_backend: resolvePremiumLlmBackend(),
        premium_gpu_billing: premiumBillingUsesGpu(resolvePremiumLlmBackend()),
        premium_gpu_endpoint: resolvePremiumGpuEndpoint(),
      });
    }

    if (request.method === "GET" && url.pathname === "/billing/config") {
      const packs = [
        {
          id: "starter",
          label: "Starter Pack",
          points: normalizedPointPackAmount(),
          price_usd: normalizedPointPackPriceUsd(),
          checkout_url: premiumPointsCheckoutUrl(),
        },
      ];
      return json({
        ok: true,
        model: "hybrid_spl_points_v1",
        premium_builder_enabled: premiumBuilderEnabled(),
        premium_wallet_required: premiumWalletRequired(),
        points_enabled: premiumPointsEnabled(),
        spl_symbol: premiumSplTokenSymbol(),
        points_symbol: premiumPointsSymbol(),
        free_tokens: normalizedPremiumFreeTokens(),
        free_points: normalizedPremiumFreePoints(),
        llm_backend: resolvePremiumLlmBackend(),
        gpu_billing_enabled: premiumBillingUsesGpu(resolvePremiumLlmBackend()),
        gpu_endpoint: resolvePremiumGpuEndpoint(),
        pricing_model: {
          base_tokens: normalizedPremiumBaseCost(),
          per_page_tokens: normalizedPremiumPerPageCost(),
          per_30_words_tokens: normalizedPremiumPerWordCost(),
          per_complexity_unit_tokens: normalizedPremiumComplexityCost(),
        },
        topup_url: premiumTopupUrl(),
        points_topup_url: premiumPointsTopupUrl(),
        points_packs: packs,
        ad_rewards: {
          enabled: premiumAdRewardsEnabled(),
          reward_points: normalizedAdRewardPoints(),
          cooldown_sec: normalizedAdRewardCooldownSec(),
        },
      });
    }

    if (request.method === "GET" && url.pathname === "/billing/status") {
      if (!consumeEndpointRateLimit(clientIp, "billing_status", now(), 60 * 1000, 120)) {
        return json({ ok: false, error: "Too many billing status requests. Please slow down." }, 429);
      }
      const session_id = String(url.searchParams.get("session_id") || "").trim();
      if (!session_id) return json({ ok: false, error: "session_id required" }, 400);

      const loaded = await loadSessionVars(session_id, "onboarding_v8");
      if (!loaded) return json({ ok: false, error: "Unknown session_id" }, 404);
      const independent = loaded.independent || {};
      const dependent = loaded.dependent || {};
      const billing = ensureBillingState(independent, dependent);
      await upsertSessionVars(session_id, "onboarding_v8", independent, dependent);
      return json({
        ok: true,
        session_id,
        billing: {
          model: billing.model,
          premium_enabled: billing.premium_enabled === true,
          wallet_required: billing.wallet_required === true,
          wallet_verified: billing.wallet_verified === true,
        points_enabled: billing.points_enabled === true,
        active_unit: billing.active_unit,
        spl_symbol: billing.spl_symbol,
        points_symbol: billing.points_symbol,
        token_balance: billing.token_balance,
        points_balance: billing.points_balance,
        llm_backend: billing.llm_backend || resolvePremiumLlmBackend(),
        gpu_billing_enabled: billing.gpu_billing_enabled === true,
        gpu_endpoint: billing.gpu_endpoint || resolvePremiumGpuEndpoint(),
        free_tokens: billing.free_tokens,
        free_points: billing.free_points,
          tokens_spent: billing.tokens_spent,
          points_spent: billing.points_spent,
          topup_url: billing.topup_url || null,
          points_topup_url: billing.points_topup_url || null,
          active_topup_url: getPremiumActiveTopupUrl(billing),
          point_pack: billing.point_pack || null,
          ad_rewards: {
            enabled: billing.ad_rewards?.enabled === true,
            reward_points: Number(billing.ad_rewards?.points || 0),
            cooldown_sec: Number(billing.ad_rewards?.cooldown_sec || 0),
            last_claimed_at: billing.last_ad_reward_at || null,
            next_eligible_at:
              billing.last_ad_reward_at && Number.isFinite(Number(billing.ad_rewards?.cooldown_sec))
                ? Number(billing.last_ad_reward_at) + Number(billing.ad_rewards.cooldown_sec) * 1000
                : null,
          },
          last_quote: toPublicPremiumQuote(billing.last_quote, billing),
          pending_quote: toPublicPremiumQuote(billing.pending_quote, billing),
        },
      });
    }

    if (request.method === "POST" && url.pathname === "/billing/quote") {
      if (!consumeEndpointRateLimit(clientIp, "billing_quote", now(), 60 * 1000, 120)) {
        return json({ ok: false, error: "Too many quote requests. Please slow down." }, 429);
      }
      let body;
      try {
        body = await request.json();
      } catch {
        return json({ ok: false, error: "Invalid JSON" }, 400);
      }
      const session_id = String(body?.session_id || "").trim();
      const requestText = String(body?.request_text || body?.prompt || "").trim();
      if (!session_id || !requestText) return json({ ok: false, error: "session_id and request_text required." }, 400);

      const loaded = await loadSessionVars(session_id, "onboarding_v8");
      if (!loaded) return json({ ok: false, error: "Unknown session_id" }, 404);
      const independent = loaded.independent || {};
      const dependent = loaded.dependent || {};
      const billing = ensureBillingState(independent, dependent);
      const estimate = estimatePremiumTokenCost(requestText);
      const quote = buildPremiumQuoteSnapshot(estimate, billing);
      billing.last_quote = { ...quote, request_preview: requestText.slice(0, 280), quoted_at: now() };
      billing.pending_quote = { ...estimate, request_text: requestText.slice(0, 8000), state_to_resume: null, quoted_at: now() };
      await upsertSessionVars(session_id, "onboarding_v8", independent, dependent);
      return json({
        ok: true,
        session_id,
        quote: toPublicPremiumQuote(billing.last_quote, billing),
        active_unit: quote.charge_unit,
        quote_amount: quote.charge_amount,
        quote_symbol: quote.charge_symbol,
        active_balance: quote.active_balance,
        token_balance: billing.token_balance,
        points_balance: billing.points_balance,
        points_symbol: billing.points_symbol,
        spl_symbol: billing.spl_symbol,
        shortfall_amount: quote.shortfall_amount,
        shortfall_tokens: quote.shortfall_tokens,
        shortfall_points: quote.shortfall_points,
        topup_url: getPremiumActiveTopupUrl(billing),
      });
    }

    if (request.method === "POST" && url.pathname === "/billing/spl/credit") {
      if (!consumeEndpointRateLimit(clientIp, "billing_credit", now(), 60 * 1000, 80)) {
        return json({ ok: false, error: "Too many credit requests. Please slow down." }, 429);
      }
      let body;
      try {
        body = await request.json();
      } catch {
        return json({ ok: false, error: "Invalid JSON" }, 400);
      }

      const session_id = String(body?.session_id || "").trim();
      const splAmount = Number(body?.spl_amount);
      const txid = String(body?.txid || "").trim();
      if (!session_id || !Number.isFinite(splAmount) || splAmount <= 0 || !txid) {
        return json({ ok: false, error: "session_id, spl_amount (>0), and txid are required." }, 400);
      }

      const webhookSecret = String(env.PREMIUM_SPL_WEBHOOK_SECRET || "").trim();
      if (webhookSecret) {
        const tsHeader = String(request.headers.get("x-spl-timestamp") || "").trim();
        const sigHeader = String(request.headers.get("x-spl-signature") || "").trim().toLowerCase();
        const tsMs = parseTimestampMs(tsHeader);
        if (!tsMs || Math.abs(now() - tsMs) > 5 * 60 * 1000 || !sigHeader) {
          return json({ ok: false, error: "Invalid SPL webhook signature headers." }, 401);
        }
        const rawBody = JSON.stringify(body);
        const expected = await hmacSha256Hex(webhookSecret, `${tsHeader}.${rawBody}`);
        if (!safeConstantCompareHex(sigHeader, expected)) {
          return json({ ok: false, error: "Invalid SPL webhook signature." }, 401);
        }
      }

      const loaded = await loadSessionVars(session_id, "onboarding_v8");
      if (!loaded) return json({ ok: false, error: "Unknown session_id" }, 404);
      const independent = loaded.independent || {};
      const dependent = loaded.dependent || {};
      const tokens = Math.max(1, Math.round(splAmount * normalizedTokensPerSpl()));
      const credited = applyPremiumTokenCredit(independent, dependent, tokens, {
        source: "spl_webhook",
        spl_symbol: premiumSplTokenSymbol(),
        spl_amount: splAmount,
        txid: txid.slice(0, 180),
      });
      if (!credited.ok) return json({ ok: false, error: credited.error || "Credit failed." }, 400);
      await upsertSessionVars(session_id, "onboarding_v8", independent, dependent);
      return json({
        ok: true,
        session_id,
        credited_tokens: tokens,
        token_balance: dependent.billing.token_balance,
        spl_symbol: premiumSplTokenSymbol(),
      });
    }

    if (request.method === "GET" && url.pathname === "/billing/points/options") {
      const session_id = String(url.searchParams.get("session_id") || "").trim();
      let billing = null;
      if (session_id) {
        const loaded = await loadSessionVars(session_id, "onboarding_v8");
        if (loaded) {
          const independent = loaded.independent || {};
          const dependent = loaded.dependent || {};
          billing = ensureBillingState(independent, dependent);
          await upsertSessionVars(session_id, "onboarding_v8", independent, dependent);
        }
      }
      const packPoints = normalizedPointPackAmount();
      const packPrice = normalizedPointPackPriceUsd();
      const adCooldownSec = normalizedAdRewardCooldownSec();
      const lastClaimAt = Number(billing?.last_ad_reward_at || 0);
      const nextEligibleAt = lastClaimAt > 0 ? lastClaimAt + adCooldownSec * 1000 : null;
      return json({
        ok: true,
        session_id: session_id || null,
        points_symbol: premiumPointsSymbol(),
        points_balance: billing ? Number(billing.points_balance || 0) : null,
        packs: [
          {
            id: "starter",
            label: "Starter Pack",
            points: packPoints,
            price_usd: packPrice,
            checkout_url: premiumPointsCheckoutUrl(),
          },
        ],
        ad_rewards: {
          enabled: premiumAdRewardsEnabled(),
          reward_points: normalizedAdRewardPoints(),
          cooldown_sec: adCooldownSec,
          last_claimed_at: lastClaimAt > 0 ? lastClaimAt : null,
          next_eligible_at: nextEligibleAt,
        },
      });
    }

    if (request.method === "POST" && url.pathname === "/billing/points/credit") {
      if (!consumeEndpointRateLimit(clientIp, "billing_points_credit", now(), 60 * 1000, 80)) {
        return json({ ok: false, error: "Too many points-credit requests. Please slow down." }, 429);
      }
      if (!premiumPointsEnabled()) {
        return json({ ok: false, error: "Points billing is currently disabled." }, 403);
      }
      let body;
      try {
        body = await request.json();
      } catch {
        return json({ ok: false, error: "Invalid JSON" }, 400);
      }

      const session_id = String(body?.session_id || "").trim();
      const points = Number(body?.points);
      const reference = String(body?.reference || body?.txid || body?.order_id || "").trim();
      if (!session_id || !Number.isFinite(points) || points <= 0 || !reference) {
        return json({ ok: false, error: "session_id, points (>0), and reference are required." }, 400);
      }

      const webhookSecret = String(env.PREMIUM_POINTS_WEBHOOK_SECRET || "").trim();
      if (webhookSecret) {
        const tsHeader = String(request.headers.get("x-points-timestamp") || "").trim();
        const sigHeader = String(request.headers.get("x-points-signature") || "").trim().toLowerCase();
        const tsMs = parseTimestampMs(tsHeader);
        if (!tsMs || Math.abs(now() - tsMs) > 5 * 60 * 1000 || !sigHeader) {
          return json({ ok: false, error: "Invalid points-credit signature headers." }, 401);
        }
        const rawBody = JSON.stringify(body);
        const expected = await hmacSha256Hex(webhookSecret, `${tsHeader}.${rawBody}`);
        if (!safeConstantCompareHex(sigHeader, expected)) {
          return json({ ok: false, error: "Invalid points-credit signature." }, 401);
        }
      }

      const loaded = await loadSessionVars(session_id, "onboarding_v8");
      if (!loaded) return json({ ok: false, error: "Unknown session_id" }, 404);
      const independent = loaded.independent || {};
      const dependent = loaded.dependent || {};
      const credited = applyPremiumPointsCredit(independent, dependent, points, {
        source: "points_webhook",
        reference: reference.slice(0, 180),
      });
      if (!credited.ok) return json({ ok: false, error: credited.error || "Credit failed." }, 400);
      await upsertSessionVars(session_id, "onboarding_v8", independent, dependent);
      return json({
        ok: true,
        session_id,
        credited_points: Math.max(1, Math.round(points)),
        points_balance: dependent.billing.points_balance,
        points_symbol: dependent.billing.points_symbol || premiumPointsSymbol(),
      });
    }

    if (request.method === "POST" && url.pathname === "/billing/points/ad/reward") {
      if (!consumeEndpointRateLimit(clientIp, "billing_points_ad_reward", now(), 60 * 1000, 80)) {
        return json({ ok: false, error: "Too many ad-reward requests. Please slow down." }, 429);
      }
      if (!premiumPointsEnabled()) return json({ ok: false, error: "Points billing is currently disabled." }, 403);
      if (!premiumAdRewardsEnabled()) return json({ ok: false, error: "Ad rewards are currently disabled." }, 403);
      const webhookSecret = String(env.PREMIUM_AD_REWARD_WEBHOOK_SECRET || "").trim();
      if (!webhookSecret) {
        return json({ ok: false, error: "Ad reward webhook is not configured." }, 503);
      }

      let body;
      try {
        body = await request.json();
      } catch {
        return json({ ok: false, error: "Invalid JSON" }, 400);
      }
      const session_id = String(body?.session_id || "").trim();
      const rewardEventId = String(body?.reward_event_id || "").trim();
      if (!session_id || !rewardEventId) {
        return json({ ok: false, error: "session_id and reward_event_id are required." }, 400);
      }

      const tsHeader = String(request.headers.get("x-ad-timestamp") || "").trim();
      const sigHeader = String(request.headers.get("x-ad-signature") || "").trim().toLowerCase();
      const tsMs = parseTimestampMs(tsHeader);
      if (!tsMs || Math.abs(now() - tsMs) > 5 * 60 * 1000 || !sigHeader) {
        return json({ ok: false, error: "Invalid ad-reward signature headers." }, 401);
      }
      const rawBody = JSON.stringify(body);
      const expected = await hmacSha256Hex(webhookSecret, `${tsHeader}.${rawBody}`);
      if (!safeConstantCompareHex(sigHeader, expected)) {
        return json({ ok: false, error: "Invalid ad-reward signature." }, 401);
      }

      const loaded = await loadSessionVars(session_id, "onboarding_v8");
      if (!loaded) return json({ ok: false, error: "Unknown session_id" }, 404);
      const independent = loaded.independent || {};
      const dependent = loaded.dependent || {};
      const billing = ensureBillingState(independent, dependent);
      const cooldownMs = Math.max(30, Number(billing.ad_rewards?.cooldown_sec || normalizedAdRewardCooldownSec())) * 1000;
      const lastAt = Number(billing.last_ad_reward_at || 0);
      if (lastAt > 0 && now() - lastAt < cooldownMs) {
        return json(
          {
            ok: false,
            error: "Ad reward cooldown active.",
            next_eligible_at: lastAt + cooldownMs,
          },
          429
        );
      }
      const points = Math.max(1, Number(billing.ad_rewards?.points || normalizedAdRewardPoints()));
      const credited = applyPremiumPointsCredit(independent, dependent, points, {
        source: "ad_reward",
        reward_event_id: rewardEventId.slice(0, 180),
      });
      if (!credited.ok) return json({ ok: false, error: credited.error || "Credit failed." }, 400);
      billing.last_ad_reward_at = now();
      billing.updated_at = now();
      await upsertSessionVars(session_id, "onboarding_v8", independent, dependent);
      return json({
        ok: true,
        session_id,
        reward_points: points,
        points_balance: billing.points_balance,
        points_symbol: billing.points_symbol || premiumPointsSymbol(),
        next_eligible_at: billing.last_ad_reward_at + cooldownMs,
      });
    }

    if (request.method === "GET" && url.pathname === "/auth/wallet/challenge") {
      if (!consumeEndpointRateLimit(clientIp, "wallet_challenge", now(), 60 * 1000, 60)) {
        return json({ ok: false, error: "Too many wallet challenge requests. Please slow down." }, 429);
      }
      const provider = normalizeWalletProvider(url.searchParams.get("provider"));
      const protocol = normalizeWalletProtocol(url.searchParams.get("protocol") || "evm");
      if (!provider || !protocol) {
        return json({ ok: false, error: "provider and protocol are required." }, 400);
      }
      const issued = issueWalletChallenge(provider, protocol, url.host, now());
      return json({
        ok: true,
        provider,
        protocol,
        nonce: issued.nonce,
        message: issued.message,
        issued_at: issued.issued_at,
        expires_at: issued.expires_at,
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

    if (request.method === "GET" && url.pathname === "/design/status") {
      if (!consumeEndpointRateLimit(clientIp, "design_status", now(), 60 * 1000, 120)) {
        return json({ ok: false, error: "Too many design status requests. Please slow down." }, 429);
      }
      const session_id = String(url.searchParams.get("session_id") || "").trim();
      if (!session_id) return json({ ok: false, error: "session_id required" }, 400);

      const loaded = await loadSessionVars(session_id, "onboarding_v8");
      if (!loaded) return json({ ok: false, error: "Unknown session_id" }, 404);
      const independent = loaded.independent || {};
      const dependent = loaded.dependent || {};
      ensureDesignState(dependent);
      ensurePatternAnalysisState(dependent);
      ensureBuildBriefState(dependent);
      dependent.design.profile = deriveDesignProfile(independent, dependent);
      dependent.analysis.last_summary =
        `${dependent.design.profile.visual_style} style, ${dependent.design.profile.density_preference} density, ` +
        `${dependent.design.profile.cta_focus} CTA`;
      dependent.analysis.last_updated_at = now();
      const compiledBrief = compileBuildBrief(independent, dependent);
      await upsertSessionVars(session_id, "onboarding_v8", independent, dependent);

      return json({
        ok: true,
        session_id,
        design_profile: dependent.design.profile,
        design_feedback: {
          liked: dependent.design.liked || [],
          disliked: dependent.design.disliked || [],
          palette_hints: dependent.design.palette_hints || [],
          layout_hints: dependent.design.layout_hints || [],
          font_hints: dependent.design.font_hints || [],
        },
        pattern_analysis: dependent.analysis,
        build_brief: compiledBrief ? { summary: compiledBrief.summary, stack_choice: compiledBrief.stack_choice } : null,
      });
    }

    if (request.method === "GET" && url.pathname === "/build/brief") {
      if (!consumeEndpointRateLimit(clientIp, "build_brief", now(), 60 * 1000, 60)) {
        return json({ ok: false, error: "Too many build brief requests. Please slow down." }, 429);
      }
      if (!isBuildBriefRequestAuthorized(request, url)) {
        return json(
          {
            ok: false,
            error:
              "Forbidden. This endpoint is internal-only. Provide x-build-brief-internal: 1 and the debug key if configured.",
          },
          403
        );
      }

      const session_id = String(url.searchParams.get("session_id") || "").trim();
      if (!session_id) return json({ ok: false, error: "session_id required" }, 400);

      const loaded = await loadSessionVars(session_id, "onboarding_v8");
      if (!loaded) return json({ ok: false, error: "Unknown session_id" }, 404);
      const independent = loaded.independent || {};
      const dependent = loaded.dependent || {};
      ensureBuildBriefState(dependent);

      const compiled = compileBuildBrief(independent, dependent);
      await upsertSessionVars(session_id, "onboarding_v8", independent, dependent);
      if (!compiled) {
        return json({
          ok: true,
          session_id,
          ready: false,
          message: "Build brief compiler has no repo-marketplace intent yet for this session.",
        });
      }

      return json({
        ok: true,
        session_id,
        ready: true,
        summary: compiled.summary,
        stack_choice: compiled.stack_choice,
        slots: compiled.slots,
        compiled_prompt: compiled.prompt,
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
      const aggressiveDefaultDelete = normalizeMaybeBool(env.WP_COMMENT_DEFAULT_DELETE, true) === true;
      const uncertainThreshold = Number.isFinite(Number(env.WP_COMMENT_UNCERTAIN_THRESHOLD))
        ? Math.max(0, Math.min(6, Math.round(Number(env.WP_COMMENT_UNCERTAIN_THRESHOLD))))
        : 2;
      const uncertain = heuristic.score <= uncertainThreshold;
      const aiApiKey = String(env.OPENAI_API_KEY || "").trim();
      const ai = uncertain ? await moderateWpCommentWithOpenAI(payload, heuristic, aiApiKey) : null;

      let action = heuristic.action;
      let confidence = heuristic.confidence;
      let reason = heuristic.reasons.join(", ") || "heuristic_clean";
      if (aggressiveDefaultDelete) {
        action = "trash";
        confidence = Math.max(0.7, heuristic.confidence);
        reason = uncertain ? "aggressive_default_trash_uncertain" : `aggressive_default_trash:${heuristic.reasons.join(",") || "no_reasons"}`;
        if (ai) {
          action = ai.action;
          confidence = ai.confidence;
          reason = `openai:${ai.reason}`;
        } else if (uncertain && !aiApiKey) {
          reason = "aggressive_default_trash_uncertain_no_openai";
        }
      } else if (heuristic.action !== "trash" && ai) {
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
        moderation_mode: aggressiveDefaultDelete ? "aggressive_default_delete" : "balanced",
        uncertain_threshold: uncertainThreshold,
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
      const highRiskPluginCount = parseCount(body?.high_risk_plugin_count);
      const mediumRiskPluginCount = parseCount(body?.medium_risk_plugin_count);
      const inactiveUserDeletedCount = parseCount(body?.inactive_user_deleted_count);
      const inactiveUserCandidateCount = parseCount(body?.inactive_user_candidate_count);
      const autoloadOptionCount = parseCount(body?.autoload_option_count);
      const autoloadTotalBytes = parseCount(body?.autoload_total_bytes);
      const autoloadTotalKb = parseCount(body?.autoload_total_kb);
      const autoloadLastCleanupAt = parseCount(body?.autoload_last_cleanup_at);
      const autoloadLastCleanupSummary = trimTo(body?.autoload_last_cleanup_summary, 200) || null;
      const pageCacheBuiltinEnabled = normalizeMaybeBool(body?.page_cache_builtin_enabled, null);
      const pageCacheTtlSeconds = parseCount(body?.page_cache_ttl_seconds);
      const pageCacheLastClearedAt = parseCount(body?.page_cache_last_cleared_at);
      const pageCacheLastClearReason = trimTo(body?.page_cache_last_clear_reason, 120) || null;
      const pageCacheHealthStatus = trimTo(body?.page_cache_health_status, 40) || null;
      const pageCacheHeaderDetected = normalizeMaybeBool(body?.page_cache_header_detected, null);
      const pageCachePluginDetected = normalizeMaybeBool(body?.page_cache_plugin_detected, null);
      const pageCacheMedianTtfbMs = parseCount(body?.page_cache_median_ttfb_ms);
      const pageCacheCheckedAt = parseCount(body?.page_cache_checked_at);
      const smtpPluginCount = parseCount(body?.smtp_plugin_count);
      const staticExportPluginCount = parseCount(body?.static_export_plugin_count);
      const staticExportMemoryErrorCount = parseCount(body?.static_export_memory_error_count);
      const staticExportRemovedPluginCount = parseCount(body?.static_export_removed_plugin_count);
      const staticExportLastStatus = trimTo(body?.static_export_last_status, 80) || null;
      const staticExportLastErrorMessage = trimTo(body?.static_export_last_error_message, 400) || null;
      const staticExportLastErrorSource = trimTo(body?.static_export_last_error_source, 160) || null;
      const staticExportLastErrorAt = parseCount(body?.static_export_last_error_at);
      const analyticsSiteKitActive = normalizeMaybeBool(body?.analytics_site_kit_active, null);
      const analyticsPagesCheckedCount = parseCount(body?.analytics_pages_checked_count);
      const analyticsPagesWithTrackingCount = parseCount(body?.analytics_pages_with_tracking_count);
      const analyticsPagesMissingTrackingCount = parseCount(body?.analytics_pages_missing_tracking_count);
      const analyticsUnreachablePageCount = parseCount(body?.analytics_unreachable_page_count);
      const analyticsTagCoveragePercent = parseCount(body?.analytics_tag_coverage_percent);
      const analyticsMeasurementIdCount = parseCount(body?.analytics_measurement_id_count);
      const analyticsGtmContainerCount = parseCount(body?.analytics_gtm_container_count);
      const analyticsStatus = trimTo(body?.analytics_status, 80) || null;
      const analyticsLastCheckedAt = parseCount(body?.analytics_last_checked_at);
      const analyticsMissingUrls = sanitizeUrlList(body?.analytics_missing_urls, 20);
      const woocommerceActive = normalizeMaybeBool(body?.woocommerce_active, null);
      const woocommerceStatus = trimTo(body?.woocommerce_status, 80) || null;
      const woocommerceProductCount = parseCount(body?.woocommerce_product_count);
      const woocommerceCompletedOrderCount = parseCount(body?.woocommerce_completed_order_count);
      const woocommerceLastSaleAt = parseCount(body?.woocommerce_last_sale_at);
      const woocommerceSalesStaleDays = parseCount(body?.woocommerce_sales_stale_days);
      const pluginInventoryRaw = body?.plugin_inventory && typeof body.plugin_inventory === "object" ? body.plugin_inventory : null;
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
        highRiskPluginCount === "__invalid__" ||
        mediumRiskPluginCount === "__invalid__" ||
        autoloadOptionCount === "__invalid__" ||
        autoloadTotalBytes === "__invalid__" ||
        autoloadTotalKb === "__invalid__" ||
        autoloadLastCleanupAt === "__invalid__" ||
        pageCacheTtlSeconds === "__invalid__" ||
        pageCacheLastClearedAt === "__invalid__" ||
        pageCacheMedianTtfbMs === "__invalid__" ||
        pageCacheCheckedAt === "__invalid__" ||
        smtpPluginCount === "__invalid__" ||
        staticExportPluginCount === "__invalid__" ||
        staticExportMemoryErrorCount === "__invalid__" ||
        staticExportRemovedPluginCount === "__invalid__" ||
        staticExportLastErrorAt === "__invalid__" ||
        analyticsPagesCheckedCount === "__invalid__" ||
        analyticsPagesWithTrackingCount === "__invalid__" ||
        analyticsPagesMissingTrackingCount === "__invalid__" ||
        analyticsUnreachablePageCount === "__invalid__" ||
        analyticsTagCoveragePercent === "__invalid__" ||
        analyticsMeasurementIdCount === "__invalid__" ||
        analyticsGtmContainerCount === "__invalid__" ||
        analyticsLastCheckedAt === "__invalid__" ||
        woocommerceProductCount === "__invalid__" ||
        woocommerceCompletedOrderCount === "__invalid__" ||
        woocommerceLastSaleAt === "__invalid__" ||
        woocommerceSalesStaleDays === "__invalid__" ||
        inactiveUserDeletedCount === "__invalid__" ||
        inactiveUserCandidateCount === "__invalid__"
      ) {
        return json({ ok: false, error: "Counts must be non-negative numbers." }, 400);
      }
      if (Number.isFinite(Number(analyticsTagCoveragePercent)) && Number(analyticsTagCoveragePercent) > 100) {
        return json({ ok: false, error: "analytics_tag_coverage_percent must be between 0 and 100." }, 400);
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
      dependent.plugin.audit_metrics.high_risk_plugin_count = highRiskPluginCount;
      dependent.plugin.audit_metrics.medium_risk_plugin_count = mediumRiskPluginCount;
      dependent.plugin.audit_metrics.autoload_option_count = autoloadOptionCount;
      dependent.plugin.audit_metrics.autoload_total_bytes = autoloadTotalBytes;
      dependent.plugin.audit_metrics.autoload_total_kb = autoloadTotalKb;
      dependent.plugin.audit_metrics.autoload_last_cleanup_at = autoloadLastCleanupAt;
      dependent.plugin.audit_metrics.autoload_last_cleanup_summary = autoloadLastCleanupSummary;
      dependent.plugin.audit_metrics.page_cache_builtin_enabled = pageCacheBuiltinEnabled;
      dependent.plugin.audit_metrics.page_cache_ttl_seconds = pageCacheTtlSeconds;
      dependent.plugin.audit_metrics.page_cache_last_cleared_at = pageCacheLastClearedAt;
      dependent.plugin.audit_metrics.page_cache_last_clear_reason = pageCacheLastClearReason;
      dependent.plugin.audit_metrics.page_cache_health_status = pageCacheHealthStatus;
      dependent.plugin.audit_metrics.page_cache_header_detected = pageCacheHeaderDetected;
      dependent.plugin.audit_metrics.page_cache_plugin_detected = pageCachePluginDetected;
      dependent.plugin.audit_metrics.page_cache_median_ttfb_ms = pageCacheMedianTtfbMs;
      dependent.plugin.audit_metrics.page_cache_checked_at = pageCacheCheckedAt;
      dependent.plugin.audit_metrics.smtp_plugin_count = smtpPluginCount;
      dependent.plugin.audit_metrics.static_export_plugin_count = staticExportPluginCount;
      dependent.plugin.audit_metrics.static_export_memory_error_count = staticExportMemoryErrorCount;
      dependent.plugin.audit_metrics.static_export_removed_plugin_count = staticExportRemovedPluginCount;
      dependent.plugin.audit_metrics.static_export_last_status = staticExportLastStatus;
      dependent.plugin.audit_metrics.static_export_last_error_message = staticExportLastErrorMessage;
      dependent.plugin.audit_metrics.static_export_last_error_source = staticExportLastErrorSource;
      dependent.plugin.audit_metrics.static_export_last_error_at = staticExportLastErrorAt;
      dependent.plugin.audit_metrics.analytics_site_kit_active = analyticsSiteKitActive;
      dependent.plugin.audit_metrics.analytics_pages_checked_count = analyticsPagesCheckedCount;
      dependent.plugin.audit_metrics.analytics_pages_with_tracking_count = analyticsPagesWithTrackingCount;
      dependent.plugin.audit_metrics.analytics_pages_missing_tracking_count = analyticsPagesMissingTrackingCount;
      dependent.plugin.audit_metrics.analytics_unreachable_page_count = analyticsUnreachablePageCount;
      dependent.plugin.audit_metrics.analytics_tag_coverage_percent = analyticsTagCoveragePercent;
      dependent.plugin.audit_metrics.analytics_measurement_id_count = analyticsMeasurementIdCount;
      dependent.plugin.audit_metrics.analytics_gtm_container_count = analyticsGtmContainerCount;
      dependent.plugin.audit_metrics.analytics_status = analyticsStatus;
      dependent.plugin.audit_metrics.analytics_last_checked_at = analyticsLastCheckedAt;
      dependent.plugin.audit_metrics.woocommerce_active = woocommerceActive;
      dependent.plugin.audit_metrics.woocommerce_status = woocommerceStatus;
      dependent.plugin.audit_metrics.woocommerce_product_count = woocommerceProductCount;
      dependent.plugin.audit_metrics.woocommerce_completed_order_count = woocommerceCompletedOrderCount;
      dependent.plugin.audit_metrics.woocommerce_last_sale_at = woocommerceLastSaleAt;
      dependent.plugin.audit_metrics.woocommerce_sales_stale_days = woocommerceSalesStaleDays;
      const normalizedInventory = normalizePluginInventoryPayload(pluginInventoryRaw);
      dependent.plugin.audit_metrics.analytics_missing_urls =
        analyticsMissingUrls.length > 0 ? analyticsMissingUrls : sanitizeUrlList(normalizedInventory.analytics_missing_urls, 20);
      dependent.plugin.audit_metrics.inactive_user_deleted_count = inactiveUserDeletedCount;
      dependent.plugin.audit_metrics.inactive_user_candidate_count = inactiveUserCandidateCount;
      dependent.plugin.audit_metrics.plugin_inventory = normalizedInventory;
      dependent.plugin.audit_metrics.synced_at = now();
      dependent.plugin.audit_metrics.source = "plugin_sync";
      const optimizationPlan = buildPluginOptimizationPlan(dependent.plugin);
      dependent.plugin.optimization.last_generated_at = now();
      dependent.plugin.optimization.last_status = "ok";
      dependent.plugin.optimization.last_summary = optimizationPlan.summary;
      dependent.plugin.optimization.plan = optimizationPlan;

      await upsertSessionVars(session_id, "onboarding_v8", independent, dependent);
      return json({
        ok: true,
        session_id,
        audit_metrics: dependent.plugin.audit_metrics,
        optimization_plan: optimizationPlan,
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

      const forwardToEmail = normalizeForwardEmail(body?.forward_to_email);
      const hasMx = normalizeMaybeBool(body?.has_mx_records, null);
      const mxRecords = normalizeMxRecords(body?.mx_records, 20);
      const emailProviderHint = String(body?.email_provider_hint || "").trim().slice(0, 120) || null;
      const siteUrl = toHttpsUrl(body?.site_url);
      const source = String(body?.source || "plugin_sync").trim().slice(0, 80) || "plugin_sync";

      const independent = loaded.independent || {};
      const dependent = loaded.dependent || {};
      ensurePluginState(dependent);
      const previousForwardEmail = normalizeForwardEmail(dependent.plugin.email_forwarding.forward_to_email);
      dependent.plugin.email_forwarding.enabled = true;
      dependent.plugin.email_forwarding.forward_to_email = forwardToEmail;
      dependent.plugin.email_forwarding.has_mx_records = hasMx;
      dependent.plugin.email_forwarding.mx_records = mxRecords;
      dependent.plugin.email_forwarding.email_provider_hint = emailProviderHint;
      dependent.plugin.email_forwarding.last_configured_at = now();
      dependent.plugin.email_forwarding.last_forward_status = source;
      if (forwardToEmail) {
        dependent.plugin.email_forwarding.verification_email = forwardToEmail;
      }
      if (!forwardToEmail || forwardToEmail !== previousForwardEmail) {
        resetLeadForwardVerification(dependent.plugin.email_forwarding, "unverified");
      }
      if (siteUrl) dependent.plugin.email_forwarding.site_url = siteUrl;

      await upsertSessionVars(session_id, "onboarding_v8", independent, dependent);
      const verification = buildLeadForwardVerificationView(dependent.plugin.email_forwarding);
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
          verification,
        },
      });
    }

    if (request.method === "POST" && url.pathname === "/plugin/wp/email/forward/verification/start") {
      if (!consumeEndpointRateLimit(clientIp, "wp_email_forward_verify_start", now(), 60 * 1000, 60)) {
        return json({ ok: false, error: "Too many email verification start requests. Please slow down." }, 429);
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

      const independent = loaded.independent || {};
      const dependent = loaded.dependent || {};
      ensurePluginState(dependent);
      const requestedForwardEmail = normalizeForwardEmail(body?.forward_to_email);
      const fallbackForwardEmail = normalizeForwardEmail(dependent.plugin.email_forwarding.forward_to_email);
      const resolvedForwardEmail = requestedForwardEmail || fallbackForwardEmail;
      if (!resolvedForwardEmail) {
        return json({ ok: false, error: "forward_to_email required before verification can start." }, 400);
      }

      const token = `${crypto.randomUUID().replace(/-/g, "")}${crypto.randomUUID().replace(/-/g, "")}`;
      const tokenHash = await sha256Hex(token);
      const tokenId = newId("lfv");
      const expiresAtMs = now() + 24 * 60 * 60 * 1000;
      const expiresAtIso = new Date(expiresAtMs).toISOString();
      dependent.plugin.email_forwarding.enabled = true;
      dependent.plugin.email_forwarding.forward_to_email = resolvedForwardEmail;
      dependent.plugin.email_forwarding.verification_email = resolvedForwardEmail;
      dependent.plugin.email_forwarding.verification_status = "pending";
      dependent.plugin.email_forwarding.verification_sent_at = now();
      dependent.plugin.email_forwarding.verification_confirmed_at = null;
      dependent.plugin.email_forwarding.verification_pending_token_hash = tokenHash;
      dependent.plugin.email_forwarding.verification_pending_expires_at = expiresAtIso;
      dependent.plugin.email_forwarding.verification_last_token_id = tokenId;
      dependent.plugin.email_forwarding.verification_last_error = null;

      await upsertSessionVars(session_id, "onboarding_v8", independent, dependent);

      const origin = new URL(request.url).origin;
      const verifyUrl = new URL("/plugin/wp/email/forward/verification/confirm", origin);
      verifyUrl.searchParams.set("session_id", session_id);
      verifyUrl.searchParams.set("token", token);
      verifyUrl.searchParams.set("token_id", tokenId);
      return json({
        ok: true,
        session_id,
        verification: buildLeadForwardVerificationView(dependent.plugin.email_forwarding),
        verification_url: verifyUrl.toString(),
      });
    }

    if (request.method === "POST" && url.pathname === "/plugin/wp/email/forward/verification/status") {
      if (!consumeEndpointRateLimit(clientIp, "wp_email_forward_verify_status", now(), 60 * 1000, 120)) {
        return json({ ok: false, error: "Too many email verification status requests. Please slow down." }, 429);
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

      const independent = loaded.independent || {};
      const dependent = loaded.dependent || {};
      ensurePluginState(dependent);
      const verification = buildLeadForwardVerificationView(dependent.plugin.email_forwarding);
      return json({
        ok: true,
        session_id,
        verification,
      });
    }

    if (request.method === "GET" && url.pathname === "/plugin/wp/email/forward/verification/confirm") {
      if (!consumeEndpointRateLimit(clientIp, "wp_email_forward_verify_confirm", now(), 60 * 1000, 180)) {
        return new Response("Too many verification attempts. Please wait and try again.", {
          status: 429,
          headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" },
        });
      }
      const session_id = String(url.searchParams.get("session_id") || "").trim();
      const token = String(url.searchParams.get("token") || "").trim();
      const tokenId = String(url.searchParams.get("token_id") || "").trim();
      if (!session_id || !token) {
        return new Response("Verification link is missing required parameters.", {
          status: 400,
          headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" },
        });
      }

      const loaded = await loadSessionVars(session_id, "onboarding_v8");
      if (!loaded) {
        return new Response("Verification session was not found.", {
          status: 404,
          headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" },
        });
      }

      const independent = loaded.independent || {};
      const dependent = loaded.dependent || {};
      ensurePluginState(dependent);
      const emailForwarding = dependent.plugin.email_forwarding;
      const storedHash = String(emailForwarding.verification_pending_token_hash || "").trim().toLowerCase();
      const providedHash = await sha256Hex(token);
      const expiresRaw = String(emailForwarding.verification_pending_expires_at || "").trim();
      const expiresMs = Date.parse(expiresRaw);
      const nowMs = now();
      let errorText = null;
      if (!storedHash) errorText = "Verification token is not active for this session.";
      else if (!safeConstantCompareHex(storedHash, providedHash)) errorText = "Verification token is invalid.";
      else if (!Number.isFinite(expiresMs) || expiresMs <= nowMs) errorText = "Verification token has expired.";

      if (errorText) {
        emailForwarding.verification_status = "failed";
        emailForwarding.verification_last_error = errorText;
        await upsertSessionVars(session_id, "onboarding_v8", independent, dependent);
        const body = `<!doctype html><html><head><meta charset="utf-8"><title>Verification Failed</title></head><body><h1>Verification failed</h1><p>${errorText}</p></body></html>`;
        return new Response(body, {
          status: 400,
          headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" },
        });
      }

      emailForwarding.verification_status = "verified";
      emailForwarding.verification_confirmed_at = nowMs;
      emailForwarding.verification_pending_token_hash = null;
      emailForwarding.verification_pending_expires_at = null;
      emailForwarding.verification_last_error = null;
      if (tokenId) emailForwarding.verification_last_token_id = tokenId.slice(0, 120);
      await upsertSessionVars(session_id, "onboarding_v8", independent, dependent);

      const verification = buildLeadForwardVerificationView(emailForwarding);
      const verifiedEmail = verification.email ? ` for <strong>${verification.email}</strong>` : "";
      const body = `<!doctype html><html><head><meta charset="utf-8"><title>Verification Complete</title></head><body><h1>Email forwarding verified</h1><p>Your Cloudflare Worker lead forwarding is now verified${verifiedEmail}.</p><p>You can return to WordPress settings and enable local-mail suppression safely.</p></body></html>`;
      return new Response(body, {
        status: 200,
        headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" },
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

    if (request.method === "POST" && url.pathname === "/plugin/wp/secrets/vault") {
      if (!consumeEndpointRateLimit(clientIp, "wp_secrets_vault", now(), 60 * 1000, 80)) {
        return json({ ok: false, error: "Too many vault requests. Please slow down." }, 429);
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
      const secretType = normalizeVaultSecretType(body?.secret_type);
      const secretValue = String(body?.secret_value || "").trim();
      const secretLabel = String(body?.secret_label || "").trim().slice(0, 120) || null;
      if (!session_id) return json({ ok: false, error: "session_id required." }, 400);
      if (!secretType) return json({ ok: false, error: "Unsupported secret_type." }, 400);
      if (!secretValue) return json({ ok: false, error: "secret_value required." }, 400);
      if (secretValue.length > 4096) return json({ ok: false, error: "secret_value too large." }, 413);

      const loaded = await loadSessionVars(session_id, "onboarding_v8");
      if (!loaded) return json({ ok: false, error: "Unknown session_id" }, 404);

      if (secretType === "cloudflare_api_token") {
        const verification = await verifyCloudflareApiTokenWithCloudflare(secretValue);
        if (!verification.ok) return json({ ok: false, error: verification.error || "Cloudflare token verification failed." }, 400);
      } else if (secretType === "github_token") {
        const verification = await verifyGitHubToken(secretValue);
        if (!verification.ok) return json({ ok: false, error: verification.error || "GitHub token verification failed." }, 400);
      } else if (secretType === "openai_api_key") {
        if (!isLikelyOpenAiApiKey(secretValue)) {
          return json({ ok: false, error: "OpenAI API key format is invalid." }, 400);
        }
      }

      let tokenCipher;
      try {
        tokenCipher = await encryptSecretWithEnvKey(
          secretValue,
          "CREDENTIAL_VAULT_KEY",
          env.GITHUB_VAULT_KEY || env.WP_PLUGIN_SHARED_SECRET || ""
        );
      } catch (error) {
        return json({ ok: false, error: String(error?.message || "Failed to encrypt secret.") }, 503);
      }

      const masked = maskSecretToken(secretValue);
      const hashed = await sha256Hex(secretValue);
      const independent = loaded.independent || {};
      const dependent = loaded.dependent || {};
      ensurePluginState(dependent);
      dependent.plugin.secrets_vault.items[secretType] = {
        type: secretType,
        label: secretLabel,
        token_masked: masked,
        token_hash: hashed,
        token_cipher: tokenCipher,
        uploaded_at: now(),
      };
      dependent.plugin.secrets_vault.last_uploaded_at = now();
      dependent.plugin.secrets_vault.last_status = "ok";
      dependent.plugin.secrets_vault.last_message = `${secretType} uploaded.`;

      if (secretType === "cloudflare_api_token") {
        dependent.plugin.connect.token_masked = masked;
        dependent.plugin.connect.token_hash = hashed;
        dependent.plugin.connect.token_verified = true;
      } else if (secretType === "hosting_provider_api_token") {
        dependent.plugin.access_profile.provider_api_token_masked = masked;
        dependent.plugin.access_profile.provider_api_token_hash = hashed;
        dependent.plugin.access_profile.provider_api_token_cipher = tokenCipher;
        dependent.plugin.access_profile.updated_at = now();
        dependent.plugin.access_profile.source = "plugin_secret_vault";
      }

      await upsertSessionVars(session_id, "onboarding_v8", independent, dependent);
      return json({
        ok: true,
        session_id,
        secret_type: secretType,
        masked,
        message: `${secretType} uploaded to Worker vault.`,
      });
    }

    if (request.method === "POST" && url.pathname === "/plugin/wp/sandbox/preflight") {
      if (!consumeEndpointRateLimit(clientIp, "wp_sandbox_preflight", now(), 60 * 1000, 45)) {
        return json({ ok: false, error: "Too many sandbox preflight requests. Please slow down." }, 429);
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

      const rawOutdated = Array.isArray(body?.outdated_plugins) ? body.outdated_plugins.slice(0, 150) : [];
      const smokeUrls = sanitizeUrlList(body?.smoke_urls, 20);
      const submittedInventory = normalizePluginInventoryPayload(body?.plugin_inventory);
      const sanitizedPlugins = rawOutdated
        .map((item) => ({
          plugin_file: String(item?.plugin_file || "").trim().slice(0, 200),
          name: String(item?.name || item?.plugin_file || "").trim().slice(0, 200),
          current_version: String(item?.current_version || "").trim().slice(0, 40),
          new_version: String(item?.new_version || "").trim().slice(0, 40),
        }))
        .filter((p) => p.name);

      const scored = sanitizedPlugins
        .map((plugin) => ({ ...plugin, risk_score: sandboxPluginRiskScore(plugin) }))
        .sort((a, b) => b.risk_score - a.risk_score);
      const outdatedCount = scored.length;
      const maxRisk = scored.length ? scored[0].risk_score : 0;
      let riskLevel = "low";
      if (maxRisk >= 7 || outdatedCount >= 10) riskLevel = "high";
      else if (maxRisk >= 4 || outdatedCount >= 4) riskLevel = "medium";

      const recommendedBatchSize = riskLevel === "high" ? 2 : riskLevel === "medium" ? 4 : 8;
      const riskCandidates = sanitizePluginRiskCandidates(submittedInventory?.risk_candidates, 80).sort(
        (a, b) => Number(b?.risk_score || 0) - Number(a?.risk_score || 0)
      );
      const safeRemoveCandidates = Array.from(
        new Set(
          []
            .concat(submittedInventory?.inactive_plugin_slugs || [])
            .concat(submittedInventory?.unneeded_plugin_slugs || [])
            .filter(Boolean)
        )
      )
        .slice(0, 25)
        .map((slug) => ({
          slug,
          reason: "Inactive/unneeded plugin candidate; remove in sandbox first, then production if no regressions.",
        }));
      const sandboxTestFirst = riskCandidates.slice(0, 20).map((plugin) => ({
        slug: plugin.slug,
        name: plugin.name || plugin.slug,
        risk_level: plugin.risk_level,
        risk_score: plugin.risk_score,
        update_available: plugin.update_available === true,
        reason:
          Array.isArray(plugin.reasons) && plugin.reasons.length
            ? plugin.reasons[0]
            : plugin.suggested_action || "High dependency plugin; test one-by-one in sandbox.",
        functional_checks:
          Array.isArray(plugin.functional_checks) && plugin.functional_checks.length
            ? plugin.functional_checks.slice(0, 8)
            : sandboxChecksForPlugin(plugin),
      }));
      const reportId = newId("sbox");
      const summary =
        outdatedCount === 0
          ? "No outdated plugins were submitted. Sandbox dry-run reports low risk."
          : `Analyzed ${outdatedCount} outdated plugins with ${riskLevel} migration risk. Recommended update batch size: ${recommendedBatchSize}.`;
      const planSummary =
        `Safe remove candidates: ${safeRemoveCandidates.length}. ` +
        `Test-first high/medium-risk plugins: ${sandboxTestFirst.length}.`;

      const report = {
        report_id: reportId,
        status: "complete",
        non_persistent: true,
        risk_level: riskLevel,
        summary: `${summary} ${planSummary}`.trim(),
        recommended_batch_size: recommendedBatchSize,
        outdated_plugin_count: outdatedCount,
        top_risky_plugins: scored.slice(0, 12),
        sandbox_uninstall_plan: {
          phase_1_safe_remove: safeRemoveCandidates,
          phase_2_test_one_by_one: sandboxTestFirst,
          smoke_urls: smokeUrls,
          smoke_checks_default: [
            "Homepage renders with no critical errors",
            "Primary service/contact page loads",
            "Lead/contact forms submit successfully",
            "Key conversion CTA buttons still work",
          ],
        },
        generated_at: new Date().toISOString(),
      };

      const independent = loaded.independent || {};
      const dependent = loaded.dependent || {};
      ensurePluginState(dependent);
      dependent.plugin.sandbox.enabled = true;
      dependent.plugin.sandbox.last_run_at = now();
      dependent.plugin.sandbox.last_status = "complete";
      dependent.plugin.sandbox.last_summary = summary;
      dependent.plugin.sandbox.last_risk_level = riskLevel;
      dependent.plugin.sandbox.last_report_id = reportId;
      dependent.plugin.sandbox.last_outdated_plugin_count = outdatedCount;
      dependent.plugin.sandbox.last_report = report;

      let reportR2Key = null;
      const bucket = convoBucket();
      if (bucket) {
        const safeSession = session_id.replace(/[^a-z0-9_-]/gi, "_").slice(0, 120);
        reportR2Key = `plugin-sandbox/${safeSession}/${Date.now()}_${reportId}.json`;
        await bucket.put(reportR2Key, JSON.stringify(report, null, 2), {
          httpMetadata: { contentType: "application/json" },
        });
      }

      await upsertSessionVars(session_id, "onboarding_v8", independent, dependent);
      return json({
        ok: true,
        session_id,
        sandbox_report: report,
        stored_in_r2: Boolean(reportR2Key),
        r2_key: reportR2Key,
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

      const requestedForwardEmail = normalizeForwardEmail(body?.forward_to_email);
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
      const fallbackForwardTo = normalizeForwardEmail(dependent.plugin?.email_forwarding?.forward_to_email);
      const resolvedForwardTo =
        requestedForwardEmail ||
        fallbackForwardTo;

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
      const verification = buildLeadForwardVerificationView(dependent.plugin.email_forwarding);

      await upsertSessionVars(session_id, "onboarding_v8", independent, dependent);
      return json({
        ok: true,
        session_id,
        event_id: eventId,
        forward_to_email: resolvedForwardTo,
        stored_in_r2: Boolean(r2Key),
        r2_key: r2Key,
        webhook,
        verification,
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

    if (request.method === "POST" && url.pathname === "/plugin/wp/media/enrich") {
      if (!consumeEndpointRateLimit(clientIp, "wp_media_enrich", now(), 60 * 1000, 60)) {
        return json({ ok: false, error: "Too many media enrich requests. Please slow down." }, 429);
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
      const assets = sanitizeMediaAssetBatch(body?.assets, 20);
      if (!assets.length) return json({ ok: false, error: "assets batch is empty." }, 400);

      const loaded = await loadSessionVars(session_id, "onboarding_v8");
      if (!loaded) return json({ ok: false, error: "Unknown session_id" }, 404);
      const independent = loaded.independent || {};
      const dependent = loaded.dependent || {};
      ensurePluginState(dependent);

      const siteUrl = toHttpsUrl(body?.site_url || independent?.business?.own_site_url);
      const siteHost = normalizeHostOrNull(siteUrl || independent?.business?.own_site_url || "");
      const inputContext = body?.context && typeof body.context === "object" ? body.context : {};
      const context = {
        brand: normalizeMediaMetadataText(
          inputContext.brand || independent?.build?.business_name || independent?.person?.business_name || "",
          90
        ),
        location: normalizeMediaMetadataText(inputContext.location || independent?.build?.service_area || "", 90),
        primary_keyword: normalizeMediaMetadataText(
          inputContext.primary_keyword || independent?.business?.type_final || independent?.business?.type || "",
          90
        ),
      };
      const openAiKey = await resolveOpenAiApiKeyForDependent(dependent);

      const items = [];
      const failed = [];
      for (const asset of assets) {
        const assetUrl = String(asset?.url || "").trim();
        if (!assetUrl) continue;
        const assetHost = normalizeHostOrNull(assetUrl);
        if (siteHost && assetHost && assetHost !== siteHost) {
          failed.push({
            url: assetUrl,
            attachment_id: Number.isFinite(Number(asset?.attachment_id)) ? Math.round(Number(asset.attachment_id)) : null,
            error: "host_mismatch",
          });
          continue;
        }

        const fallback = buildFallbackMediaMetadata(asset, context);
        const aiMeta = await inferMediaMetadataWithOpenAI(asset, context, openAiKey);
        const metadata = mergeMediaMetadataWithFallback(aiMeta, fallback);
        items.push({
          url: assetUrl,
          attachment_id: Number.isFinite(Number(asset?.attachment_id)) ? Math.round(Number(asset.attachment_id)) : null,
          source: aiMeta ? "openai" : "fallback",
          metadata,
        });
      }

      dependent.plugin.media_offload = dependent.plugin.media_offload || {};
      dependent.plugin.media_offload.last_ai_enrichment_at = now();
      dependent.plugin.media_offload.last_ai_enrichment_count = items.length;
      dependent.plugin.media_offload.last_ai_enrichment_failed = failed.length;
      await upsertSessionVars(session_id, "onboarding_v8", independent, dependent);

      return json({
        ok: true,
        session_id,
        openai_configured: Boolean(openAiKey),
        processed_count: items.length,
        failed_count: failed.length,
        items: items.slice(0, 120),
        failed: failed.slice(0, 20),
      });
    }

    if (request.method === "POST" && url.pathname === "/plugin/wp/media/offload") {
      if (!consumeEndpointRateLimit(clientIp, "wp_media_offload", now(), 60 * 1000, 40)) {
        return json({ ok: false, error: "Too many media offload requests. Please slow down." }, 429);
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
      const siteUrl = toHttpsUrl(body?.site_url);
      const mediaPublicBaseRaw = String(body?.media_public_base_url || "").trim().replace(/\/+$/, "");
      let mediaPublicBaseUrl = "";
      if (mediaPublicBaseRaw) {
        try {
          const parsedPublic = new URL(mediaPublicBaseRaw);
          if (/^https?:$/i.test(parsedPublic.protocol)) {
            mediaPublicBaseUrl = mediaPublicBaseRaw;
          }
        } catch {}
      }
      const assets = sanitizeMediaAssetBatch(body?.assets, 80);
      if (!session_id) return json({ ok: false, error: "session_id required." }, 400);
      if (!assets.length) return json({ ok: false, error: "assets batch is empty." }, 400);

      const loaded = await loadSessionVars(session_id, "onboarding_v8");
      if (!loaded) return json({ ok: false, error: "Unknown session_id" }, 404);

      const bucket = convoBucket();
      if (!bucket) return json({ ok: false, error: "R2 bucket is not configured." }, 503);

      const independent = loaded.independent || {};
      const dependent = loaded.dependent || {};
      ensurePluginState(dependent);
      const siteHost = normalizeHostOrNull(siteUrl || independent?.business?.own_site_url || "");
      const cacheControl = "public, max-age=31536000, immutable";

      const processed = [];
      const failed = [];
      let maxAttachmentId = 0;
      for (const asset of assets) {
        const assetUrl = String(asset.url || "").trim();
        const attachmentId = Number.isFinite(Number(asset.attachment_id)) ? Math.max(0, Math.round(Number(asset.attachment_id))) : 0;
        if (attachmentId > maxAttachmentId) maxAttachmentId = attachmentId;
        try {
          const parsed = new URL(assetUrl);
          const host = (parsed.hostname || "").toLowerCase();
          if (siteHost && host !== siteHost) {
            failed.push({ url: assetUrl, attachment_id: attachmentId || null, error: "host_mismatch" });
            continue;
          }
          const r = await fetch(assetUrl, { method: "GET" });
          if (!r.ok) {
            failed.push({ url: assetUrl, attachment_id: attachmentId || null, error: `fetch_${r.status}` });
            continue;
          }
          const contentType = String(r.headers.get("content-type") || "").trim();
          if (!/^image\//i.test(contentType)) {
            failed.push({ url: assetUrl, attachment_id: attachmentId || null, error: "not_image_content_type" });
            continue;
          }
          const bytes = new Uint8Array(await r.arrayBuffer());
          if (bytes.byteLength <= 0) {
            failed.push({ url: assetUrl, attachment_id: attachmentId || null, error: "empty_body" });
            continue;
          }
          if (bytes.byteLength > 15 * 1024 * 1024) {
            failed.push({ url: assetUrl, attachment_id: attachmentId || null, error: "file_too_large" });
            continue;
          }
          const ext = imageExtFromUrlOrContentType(assetUrl, contentType);
          const idPart = attachmentId > 0 ? `att_${attachmentId}` : `u_${(await sha256Hex(assetUrl)).slice(0, 16)}`;
          const requestedKey = sanitizeMediaObjectKey(asset.r2_key || "");
          let key = requestedKey || `wp-media-cache/${session_id}/${siteHost || host || "site"}/${idPart}.${ext}`;
          if (!/\.[a-z0-9]{2,5}$/i.test(key)) {
            key = `${key}.${ext}`;
          }
          await bucket.put(key, bytes, {
            httpMetadata: { contentType, cacheControl },
          });
          processed.push({
            url: assetUrl,
            attachment_id: attachmentId || null,
            key,
            public_url: mediaPublicBaseUrl ? `${mediaPublicBaseUrl}/${key}` : null,
            bytes: bytes.byteLength,
            content_type: contentType,
          });
        } catch (error) {
          failed.push({
            url: assetUrl,
            attachment_id: attachmentId || null,
            error: String(error?.message || error || "fetch_failed").slice(0, 160),
          });
        }
      }

      const manifest = {
        session_id,
        site_url: siteUrl || independent?.business?.own_site_url || null,
        generated_at: new Date().toISOString(),
        processed_count: processed.length,
        failed_count: failed.length,
        max_attachment_id: maxAttachmentId,
        processed,
        failed,
      };

      const safeHost = String(siteHost || "site").replace(/[^a-z0-9.-]/gi, "-").toLowerCase();
      const manifestR2Key = `wp-media-cache/${session_id}/manifests/${Date.now()}_${safeHost}.json`;
      await bucket.put(manifestR2Key, JSON.stringify(manifest, null, 2), {
        httpMetadata: { contentType: "application/json" },
      });

      let githubManifestPath = null;
      let githubManifestStatus = "skipped";
      let githubManifestError = null;
      if (dependent?.plugin?.github_vault?.connected && dependent?.plugin?.github_vault?.token_cipher) {
        const repo = parseGitHubRepoSlug(dependent.plugin.github_vault.repo_slug);
        if (repo) {
          try {
            const token = await decryptSecretFromVault(dependent.plugin.github_vault.token_cipher);
            const datePart = new Date().toISOString().slice(0, 10);
            const ghPath = `sitebuilder-media-manifests/${safeHost}/${datePart}/${Date.now()}.json`;
            const branch = String(dependent.plugin.github_vault.branch || "main").trim() || "main";
            const ghPush = await pushSnapshotToGitHub(
              token,
              repo,
              ghPath,
              JSON.stringify(manifest, null, 2),
              `chore: media manifest ${safeHost} ${manifest.generated_at}`,
              branch
            );
            if (ghPush?.ok) {
              githubManifestStatus = "ok";
              githubManifestPath = ghPush.content_path || ghPath;
            } else {
              githubManifestStatus = "error";
              githubManifestError = String(ghPush?.error || "github_manifest_push_failed");
            }
          } catch (error) {
            githubManifestStatus = "error";
            githubManifestError = String(error?.message || error || "github_manifest_push_failed");
          }
        } else {
          githubManifestStatus = "error";
          githubManifestError = "github_repo_not_configured";
        }
      }

      dependent.plugin.media_offload.enabled = true;
      dependent.plugin.media_offload.last_run_at = now();
      dependent.plugin.media_offload.last_status = failed.length > 0 ? (processed.length > 0 ? "partial" : "error") : "ok";
      dependent.plugin.media_offload.last_message =
        failed.length > 0
          ? `Offloaded ${processed.length} image(s), failed ${failed.length}.`
          : `Offloaded ${processed.length} image(s) to R2.`;
      dependent.plugin.media_offload.last_manifest_r2_key = manifestR2Key;
      dependent.plugin.media_offload.last_processed_count = processed.length;
      dependent.plugin.media_offload.last_failed_count = failed.length;
      dependent.plugin.media_offload.last_max_attachment_id = maxAttachmentId;
      dependent.plugin.media_offload.total_processed =
        Math.max(0, Number(dependent.plugin.media_offload.total_processed || 0)) + processed.length;
      dependent.plugin.media_offload.total_failed =
        Math.max(0, Number(dependent.plugin.media_offload.total_failed || 0)) + failed.length;
      dependent.plugin.media_offload.last_github_manifest_status = githubManifestStatus;
      dependent.plugin.media_offload.last_github_manifest_path = githubManifestPath;
      dependent.plugin.media_offload.last_github_manifest_error = githubManifestError;

      await upsertSessionVars(session_id, "onboarding_v8", independent, dependent);
      return json({
        ok: true,
        session_id,
        processed_count: processed.length,
        failed_count: failed.length,
        max_attachment_id: maxAttachmentId,
        manifest_r2_key: manifestR2Key,
        github_manifest: {
          status: githubManifestStatus,
          path: githubManifestPath,
          error: githubManifestError,
        },
        media_public_base_url: mediaPublicBaseUrl || null,
        processed: processed.slice(0, 300),
        failed: failed.slice(0, 20),
        message:
          failed.length > 0
            ? `Offloaded ${processed.length} image(s), failed ${failed.length}.`
            : `Offloaded ${processed.length} image(s) to R2.`,
      });
    }

    if (request.method === "POST" && url.pathname === "/plugin/wp/agent/chat") {
      if (!consumeEndpointRateLimit(clientIp, "wp_agent_chat", now(), 60 * 1000, 90)) {
        return json({ ok: false, error: "Too many chat requests. Please slow down." }, 429);
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
      const question = String(body?.question || "").trim();
      if (!session_id) return json({ ok: false, error: "session_id required." }, 400);
      if (question.length < 3) return json({ ok: false, error: "question is too short." }, 400);
      if (question.length > 1500) return json({ ok: false, error: "question is too long." }, 413);

      const loaded = await loadSessionVars(session_id, "onboarding_v8");
      if (!loaded) return json({ ok: false, error: "Unknown session_id" }, 404);

      const independent = loaded.independent || {};
      const dependent = loaded.dependent || {};
      ensurePluginState(dependent);

      const plan = buildPluginOptimizationPlan(dependent.plugin);
      dependent.plugin.optimization.last_generated_at = now();
      dependent.plugin.optimization.last_status = "ok";
      dependent.plugin.optimization.last_summary = plan.summary;
      dependent.plugin.optimization.plan = plan;

      const evidence = buildPluginAgentEvidenceCatalog(independent, dependent);
      const scoredProofs = selectAgentProofs(question, evidence, 6);
      const answer = buildAgentAnswerFromProofs(question, scoredProofs, dependent);
      const proofs = scoredProofs.map((row) => ({
        title: row.title,
        value: row.value,
        source_path: row.source_path,
        confidence: Math.max(0.1, Math.min(1, Number((row.score / 8).toFixed(3)))),
      }));
      const askedAt = now();

      dependent.plugin.agent_chat.last_question = question.slice(0, 1500);
      dependent.plugin.agent_chat.last_answer = String(answer || "").slice(0, 4000);
      dependent.plugin.agent_chat.last_asked_at = askedAt;
      dependent.plugin.agent_chat.last_proofs = proofs.slice(0, 10);
      const historyEntry = {
        asked_at: askedAt,
        question: question.slice(0, 500),
        answer: String(answer || "").slice(0, 1200),
        proofs: proofs.slice(0, 5),
      };
      dependent.plugin.agent_chat.history = [historyEntry].concat(Array.isArray(dependent.plugin.agent_chat.history) ? dependent.plugin.agent_chat.history : []).slice(0, 15);

      await upsertSessionVars(session_id, "onboarding_v8", independent, dependent);
      return json({
        ok: true,
        session_id,
        asked_at: askedAt,
        answer,
        proofs,
        proof_count: proofs.length,
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
      if (dependent.plugin.optimization && typeof dependent.plugin.optimization === "object") {
        const currentPlan = dependent.plugin.optimization.plan && typeof dependent.plugin.optimization.plan === "object"
          ? dependent.plugin.optimization.plan
          : {};
        currentPlan.clone_status = githubPush?.ok ? "ready" : dependent?.plugin?.github_vault?.connected ? "pending_first_snapshot" : "missing_github_connection";
        currentPlan.clone_summary = githubPush?.ok
          ? "GitHub baseline snapshot is present."
          : (githubError || "GitHub snapshot unavailable.");
        dependent.plugin.optimization.plan = currentPlan;
        dependent.plugin.optimization.last_generated_at = now();
        dependent.plugin.optimization.last_status = githubPush?.ok ? "ok" : "warning";
        dependent.plugin.optimization.last_summary = currentPlan.clone_summary;
      }
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
          github_required_for_activation: true,
          scoped_cloudflare_token_required: true,
        },
        guidance:
          "Install TollDNS first for the free plugin tier. Then connect a scoped Cloudflare API token. " +
          "GitHub token vault connection is required before plugin activation so AI workers can run sandbox backups before update operations. " +
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
      if (github_connected !== true || !github_repo) {
        return json(
          {
            ok: false,
            error: "GitHub token vault connection is required before activation.",
            requirement: "github_token_required",
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

      const loginMethod = String(body?.login_method || "name")
        .trim()
        .toLowerCase();
      let first_name = null;
      let last_name = null;
      let greeting_name = null;
      let person_auth_method = "name";
      let person_wallet = null;

      if (loginMethod === "wallet") {
        const verifiedWallet = await verifyWalletStartPayload(body, url.host, now());
        if (!verifiedWallet.ok) {
          return json({ ok: false, error: verifiedWallet.error || "Wallet authentication failed." }, verifiedWallet.status || 401);
        }
        first_name = "Web3";
        last_name = "User";
        greeting_name = String(verifiedWallet.greeting_name || "").trim() || "wallet user";
        person_auth_method = String(verifiedWallet?.person?.auth_method || "wallet");
        person_wallet = verifiedWallet?.person?.wallet || null;
      } else {
        first_name = cleanHumanName(body?.FirstName || body?.first_name);
        last_name = cleanHumanName(body?.LastName || body?.last_name);

        const firstCheck = analyzeHumanName(first_name, "FirstName", 2);
        if (!firstCheck.ok) return json({ ok: false, error: firstCheck.error }, 400);
        const lastCheck = analyzeHumanName(last_name, "LastName", 4);
        if (!lastCheck.ok) return json({ ok: false, error: lastCheck.error }, 400);
      }

      let user_id = newId("usr");
      if (loginMethod === "wallet") {
        const walletAddress = String(person_wallet?.address || "").trim();
        const derivedWalletUserId = await deriveWalletUserId(walletAddress);
        if (derivedWalletUserId) user_id = derivedWalletUserId;
      }
      const session_id = newId("ses");
      const session_created_at = now();
      const clientGeo = readClientGeo(request);

      await insertUserRow(user_id, first_name, session_created_at);
      await insertSessionRow(session_id, user_id, session_created_at);

      const independent = {
        session_created_at,
        person: {
          first_name,
          last_name,
          geo: clientGeo,
          auth_method: person_auth_method,
          wallet: person_wallet,
        },
        account: {
          user_id,
          auth_method: person_auth_method,
        },

        business: {
          description_raw: null,
          type_final: null,
          type_secondary: [],
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
              a_record_primary_ip: null,
              a_record_ips: [],
              hosting_company: null,
              hosting_type_hint: null,
              hosting_cost_estimate: null,
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
          q2_palette: null,
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
        draft: { type_guess: null, type_secondary: [], type_candidates: [], type_source: null },
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
          user_reference_url: null,
          same_zip_as_reference: null,
          reference_location: null,
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
          reference_feedback: [],
          palette_options: [],
          selected_palette: null,
          profile: null,
        },
        analysis: {
          turns_processed: 0,
          preference_events: 0,
          preference_shifts: 0,
          frustration_signals: 0,
          positive_signals: 0,
          clarification_requests: 0,
          last_user_input: "",
          last_summary: "",
          last_updated_at: null,
        },
        build_brief: {
          persona: null,
          audience: null,
          primary_goal: null,
          secondary_goal: null,
          tertiary_goal: null,
          offer_type: null,
          repo_sale_model: null,
          payment_provider: null,
          style_pref: null,
          dark_mode_friendly: true,
          lead_capture: true,
          stack_preference: null,
          stack_choice: null,
          stacks: [],
          trust_signals: [],
          ask_only_if_required: ["name_or_brand", "preferred_colors", "payment_provider"],
          compiled_prompt: null,
          compiled_summary: null,
          compiled_at: null,
          version: 1,
        },
        billing: {
          model: "hybrid_spl_points_v1",
          spl_symbol: premiumSplTokenSymbol(),
          points_symbol: premiumPointsSymbol(),
          tokens_per_spl: normalizedTokensPerSpl(),
          points_per_token: normalizedPointsPerToken(),
          free_tokens: normalizedPremiumFreeTokens(),
          free_points: normalizedPremiumFreePoints(),
          token_balance: null,
          points_balance: null,
          tokens_spent: 0,
          points_spent: 0,
          premium_enabled: false,
          wallet_required: premiumWalletRequired(),
          wallet_verified: false,
          points_enabled: premiumPointsEnabled(),
          free_granted_at: null,
          free_points_granted_at: null,
          pending_quote: null,
          last_quote: null,
          last_charge: null,
          last_credit: null,
          last_points_credit: null,
          topup_url: premiumTopupUrl(),
          points_topup_url: premiumPointsTopupUrl(),
          active_unit: "tokens",
          updated_at: now(),
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
      ensureBillingState(independent, dependent);

      await upsertSessionVars(session_id, "onboarding_v8", independent, dependent);

      const helloName = greeting_name || `${first_name} ${last_name}`.trim();
      const prompt = `Hello ${helloName}, Could you please describe your business to me briefly?`;

      const t = await nextTurnId(env.DB, session_id);
      await logEvent(env.DB, session_id, t, "assistant", "Q1_DESCRIBE", prompt);
      await flushSessionToR2(env.DB, session_id, session_created_at);

      const billingSnapshot = {
        model: dependent?.billing?.model || "hybrid_spl_points_v1",
        spl_symbol: dependent?.billing?.spl_symbol || premiumSplTokenSymbol(),
        points_symbol: dependent?.billing?.points_symbol || premiumPointsSymbol(),
        wallet_required: dependent?.billing?.wallet_required === true,
        wallet_verified: dependent?.billing?.wallet_verified === true,
        points_enabled: dependent?.billing?.points_enabled === true,
        free_tokens: Number(dependent?.billing?.free_tokens || 0),
        free_points: Number(dependent?.billing?.free_points || 0),
        token_balance: Number(dependent?.billing?.token_balance || 0),
        points_balance: Number(dependent?.billing?.points_balance || 0),
        llm_backend: dependent?.billing?.llm_backend || resolvePremiumLlmBackend(),
        gpu_billing_enabled: dependent?.billing?.gpu_billing_enabled === true,
        gpu_endpoint: dependent?.billing?.gpu_endpoint || resolvePremiumGpuEndpoint(),
        pricing_model: {
          base_tokens: normalizedPremiumBaseCost(),
          per_page_tokens: normalizedPremiumPerPageCost(),
          per_30_words_tokens: normalizedPremiumPerWordCost(),
          per_complexity_unit_tokens: normalizedPremiumComplexityCost(),
        },
        topup_url: dependent?.billing?.topup_url || premiumTopupUrl(),
        points_topup_url: dependent?.billing?.points_topup_url || premiumPointsTopupUrl(),
      };

      return json({ ok: true, user_id, session_id, next_state: "Q1_DESCRIBE", prompt, billing: billingSnapshot });
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
      ensureDesignState(dependent);
      ensureResearchState(dependent);
      ensurePatternAnalysisState(dependent);
      ensureBuildBriefState(dependent);
      ensureBillingState(independent, dependent);
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
      if (typeof dependent.flow.plugin_install_requested !== "boolean") dependent.flow.plugin_install_requested = false;
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
        refreshSessionInsights(state, answerText, independent, dependent);
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
        const sites = normalizeReferenceSites(Array.isArray(dependent?.research?.sites) ? dependent.research.sites : []);
        dependent.research = dependent.research || {};
        dependent.research.sites = sites;
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
          const nextUrl = sanitizeReferenceUrl(nextSite?.url);
          if (!nextUrl) {
            dependent.research.current_site_index = nextIdx;
            return await handleReferenceMismatch("invalid_reference_url");
          }
          dependent.research.current_site_index = nextIdx;
          independent.demo.last_demo_url = nextUrl;
          return await reply({
            ok: true,
            next_state: "Q3_VIEWING_DEMO",
            prompt:
              `Understood — that one missed the mark. Try this example instead: ${nextUrl}\n\n` +
              "I’ll ask what you like/dislike in about 20 seconds.",
            open_url: nextUrl,
            demo_url: nextUrl,
            auto_advance_after_seconds: 20,
            auto_advance_answer: "__AUTO_AFTER_20S__",
          });
        }

        const previousUrls = Array.from(
          new Set(
            [
              ...sites.map((s) => sanitizeReferenceUrl(s?.url)),
              ...dependent.design.reference_feedback.map((f) => sanitizeReferenceUrl(f?.site_url)),
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
          const freshSites = normalizeReferenceSites(market?.sites, previousUrls);
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

        const fallbackDemoUrl = sanitizeReferenceUrl(independent?.demo?.last_demo_url) || PLACEHOLDER_DEMO_URL;
        return await reply({
          ok: true,
          next_state: "Q3_VIEWING_DEMO",
          prompt:
            "I couldn’t fetch a better match right now. Paste a direct website URL you want to use as reference, " +
            `or try this link: ${fallbackDemoUrl}`,
          open_url: fallbackDemoUrl,
          demo_url: fallbackDemoUrl,
        });
      };

      if (state === "Q_PREMIUM_CONFIRM") {
        const billing = ensureBillingState(independent, dependent);
        const pending = billing.pending_quote && typeof billing.pending_quote === "object" ? billing.pending_quote : null;
        const gpuBilling = billing.gpu_billing_enabled === true;
        const waiveBilling = pending?.billing_waived === true || !gpuBilling;
        if (!pending) {
          const fallbackState = dependent?.flow?.resume_state || "DONE";
          return await reply({
            ok: true,
            next_state: fallbackState,
            prompt: "Premium quote is no longer pending. Continue with your normal flow.",
          });
        }

        const decision = yesNoMaybe(answerText);
        if (decision === "no") {
          const resumeState = pending.state_to_resume || "DONE";
          billing.pending_quote = null;
          billing.updated_at = now();
          return await reply({
            ok: true,
            next_state: resumeState,
            prompt: "No problem — premium build request cancelled. We can continue with the standard flow.",
          });
        }

        if (decision !== "yes") {
          if (waiveBilling) {
            return await reply({
              ok: true,
              next_state: "Q_PREMIUM_CONFIRM",
              prompt:
                "Premium build request detected. This run does not use GPU LLM resources, so no token charge will be applied.\n" +
                "Reply yes to continue, or no to cancel.",
            });
          }

          const quote = buildPremiumQuoteSnapshot(pending, billing);
          const topupUrl = getPremiumActiveTopupUrl(billing);
          return await reply({
            ok: true,
            next_state: "Q_PREMIUM_CONFIRM",
            prompt:
              `Premium quote: ${quote.charge_amount} ${quote.charge_symbol} for ~${pending.page_count} page(s).\n` +
              `Current balance: ${quote.active_balance} ${quote.charge_symbol}.\n` +
              (quote.shortfall_amount > 0
                ? `Shortfall: ${quote.shortfall_amount} ${quote.charge_symbol}.`
                : "Reply yes to run this premium build request, or no to cancel."),
            topup_url: topupUrl,
            premium_quote: {
              page_count: pending.page_count,
              complexity_units: pending.complexity_units,
              charge_unit: quote.charge_unit,
              charge_amount: quote.charge_amount,
              charge_symbol: quote.charge_symbol,
              shortfall_amount: quote.shortfall_amount,
            },
            token_balance: quote.token_balance,
            points_balance: quote.points_balance,
            active_balance: quote.active_balance,
            active_unit: quote.charge_unit,
            active_symbol: quote.charge_symbol,
          });
        }

        if (!waiveBilling) {
          const useCheck = canUsePremiumBuilder(independent, dependent);
          if (!useCheck.ok) {
            return await reply({
              ok: true,
              next_state: "Q_PREMIUM_CONFIRM",
              prompt: `${useCheck.reason}\n\nReply no to cancel, or top up and then reply yes.`,
            });
          }
        }

        const charge = applyPremiumTokenCharge(independent, dependent, pending.tokens, {
          mode: "premium_builder",
          page_count: pending.page_count,
          complexity_units: pending.complexity_units,
          source: "chat_confirmed_quote",
          waive: waiveBilling,
        });
        if (!charge.ok) {
          if (!waiveBilling) {
            const quote = buildPremiumQuoteSnapshot(pending, billing);
            const topupUrl = getPremiumActiveTopupUrl(billing);
            return await reply({
              ok: true,
              next_state: "Q_PREMIUM_CONFIRM",
              prompt:
                `Insufficient ${quote.charge_symbol}. Needed ${quote.charge_amount}, available ${quote.active_balance}. ` +
                `Top up and reply yes again.`,
              topup_url: topupUrl,
            });
          }
        }

        billing.premium_enabled = true;
        billing.last_quote = {
          tokens: pending.tokens,
          page_count: pending.page_count,
          complexity_units: pending.complexity_units,
          quoted_at: pending.quoted_at || now(),
        };
        const requestText = String(pending.request_text || "").slice(0, 8000);
        billing.pending_quote = null;
        billing.updated_at = now();

        inferBuildBriefSignalsFromText(independent, dependent, "Q_PREMIUM_CONFIRM", requestText);
        const compiled = compileBuildBrief(independent, dependent);
        const resumeState = pending.state_to_resume || "DONE";
        return await reply({
          ok: true,
          next_state: resumeState,
          prompt:
            (waiveBilling
              ? "Premium mode activated. No GPU token charge applied for this run.\n\n"
              : `Premium mode activated. Charged ${charge.charged_amount} ${charge.unit === "points" ? billing.points_symbol : "tokens"}. ` +
                `Remaining balance: ${charge.balance} ${charge.unit === "points" ? billing.points_symbol : "tokens"}.\n\n`) +
            (compiled
              ? `${compiled.summary}\n\nSend your next premium instruction and I’ll keep processing with token metering.`
              : "Send your premium build instruction and I’ll process it with token metering."),
          premium_mode: true,
          active_unit: charge.unit,
          active_symbol: charge.unit === "points" ? billing.points_symbol : "tokens",
          active_balance: charge.balance,
          token_balance: billing.token_balance,
          points_balance: billing.points_balance,
          charged_tokens: pending.tokens,
          charged_amount: charge.charged_amount,
        });
      }

      if (isPremiumBuilderRequest(answerText)) {
        const billing = ensureBillingState(independent, dependent);
        const gpuBilling = billing.gpu_billing_enabled === true;
        const estimate = estimatePremiumTokenCost(answerText);
        billing.pending_quote = {
          ...estimate,
          request_text: answerText.slice(0, 8000),
          state_to_resume: state,
          quoted_at: now(),
          billing_waived: !gpuBilling,
        };
        billing.updated_at = now();

        if (!gpuBilling) {
          return await reply({
            ok: true,
            next_state: "Q_PREMIUM_CONFIRM",
            prompt:
              `Premium build request detected (~${estimate.page_count} page(s), complexity ${estimate.complexity_units}).\n` +
              "This run does not use GPU LLM resources, so no token charge will be applied.\n" +
              "Reply yes to run this premium request, or no to cancel.",
          });
        }

        const quote = buildPremiumQuoteSnapshot(estimate, billing);
        billing.last_quote = { ...quote, request_preview: answerText.slice(0, 280), quoted_at: now() };
        const useCheck = canUsePremiumBuilder(independent, dependent);
        const topupUrl = getPremiumActiveTopupUrl(billing);
        const topupLine = topupUrl ? `\nTop up: ${topupUrl}` : "";
        return await reply({
          ok: true,
          next_state: "Q_PREMIUM_CONFIRM",
          prompt:
            `Premium build request detected (~${estimate.page_count} page(s), complexity ${estimate.complexity_units}).\n` +
            `Quote: ${quote.charge_amount} ${quote.charge_symbol}.\n` +
            `Current balance: ${quote.active_balance} ${quote.charge_symbol}.\n` +
            (useCheck.ok
              ? `Reply yes to run this premium request, or no to cancel.`
              : `${useCheck.reason}\nReply yes after you meet requirements, or no to cancel.`) +
            topupLine,
          topup_url: topupUrl,
          premium_quote: {
            page_count: estimate.page_count,
            complexity_units: estimate.complexity_units,
            charge_unit: quote.charge_unit,
            charge_amount: quote.charge_amount,
            charge_symbol: quote.charge_symbol,
            shortfall_amount: quote.shortfall_amount,
          },
          token_balance: billing.token_balance,
          points_balance: billing.points_balance,
          active_balance: quote.active_balance,
          active_unit: quote.charge_unit,
        });
      }

      // DONE: handle email requests
      if (state === "DONE") {
        const txt = answerText;
        const email = extractEmailFromText(txt);
        const followupRequested = wantsEmailFollowup(txt);
        const dualServerRequested = wantsDualServerUpgradeInfo(txt);
        const pluginInstallRequested = wantsPluginInstall(txt) || /\bok(?:ay)?\s+and\s+the\s+plugin\b/.test(String(txt || "").toLowerCase());
        const pluginStepChoice = parseSingleDigitChoice(txt);

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
          return await reply(buildPluginInstallReplyPayload(independent, dependent));
        }

        if (pluginStepChoice) {
          const installPayload = buildPluginInstallReplyPayload(independent, dependent);
          const steps = Array.isArray(installPayload?.plugin_step_actions) ? installPayload.plugin_step_actions : [];
          const chosen = steps[pluginStepChoice - 1] || null;
          if (chosen?.url) {
            return await reply({
              ...installPayload,
              prompt:
                `Opening step ${pluginStepChoice}: ${chosen.label}\n` +
                `If it didn’t open, use this link: ${chosen.url}`,
              open_url: chosen.url,
            });
          }
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

        const openAiKey = await resolveOpenAiApiKeyForDependent(dependent);
        const resolved = await resolveBusinessTypeCandidates(desc, openAiKey);
        const canonicalCandidates = Array.from(
          new Set(
            (resolved.candidates || [])
              .map((x) => canonicalizeBusinessTypeLabel(x))
              .filter(Boolean)
          )
        );
        dependent.draft.type_candidates = canonicalCandidates;
        dependent.draft.type_source = resolved.source;
        dependent.draft.type_guess = canonicalCandidates[0] || "local business";

        if (canonicalCandidates.length > 1) {
          const numbered = canonicalCandidates.map((c, i) => `${i + 1}) ${c}`).join("\n");
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
        const candidates = Array.isArray(dependent?.draft?.type_candidates) ? dependent.draft.type_candidates : [];
        let picked = null;
        let pickedSecondary = [];
        const choice = parseSingleDigitChoice(answerText);
        if (choice) {
          const idx = choice - 1;
          if (candidates[idx]) picked = candidates[idx];
        }
        if (!picked) {
          const multi = parseMultipleDigitChoices(answerText, candidates.length);
          if (multi.length) {
            const labels = multi.map((n) => candidates[n - 1]).filter(Boolean);
            if (labels.length) {
              picked = labels[0];
              pickedSecondary = labels.slice(1);
            }
          }
        }
        if (!picked) {
          const normalizedAnswer = normalizeBusinessTypeLabel(answerText);
          if (normalizedAnswer) {
            const matchedCandidate = candidates.find((c) => normalizeBusinessTypeLabel(c) === normalizedAnswer);
            if (matchedCandidate) picked = matchedCandidate;
          }
        }
        if (!picked && isLikelyBusinessTypeLabel(answerText)) {
          picked = canonicalizeBusinessTypeLabel(answerText);
        }
        if (!picked) {
          return json(
            {
              ok: false,
              error:
                'Please choose 1/2/3, or type a short business type label (example: "home hobbyist").',
            },
            400
          );
        }

        picked = canonicalizeBusinessTypeLabel(picked);
        pickedSecondary = (pickedSecondary || [])
          .map((x) => canonicalizeBusinessTypeLabel(x))
          .filter(Boolean)
          .filter((x) => x !== picked);

        dependent.draft.type_guess = picked;
        dependent.draft.type_secondary = pickedSecondary;
        if (pickedSecondary.length) {
          const secondaryLabel = pickedSecondary.join('", "');
          return await reply({
            ok: true,
            next_state: "Q1_CONFIRM_TYPE",
            prompt: `Just to confirm before I save this: I’m going to label your primary business type as "${picked}" and also note "${secondaryLabel}". Is that correct?`,
          });
        }
        return await reply({
          ok: true,
          next_state: "Q1_CONFIRM_TYPE",
          prompt: `Just to confirm before I save this: I’m going to label your business type as "${picked}". Is that correct?`,
        });
      }

      if (state === "Q1_CONFIRM_TYPE") {
        const correctedType = extractManualTypeFromNoAnswer(answerText);
        if (correctedType) {
          dependent.draft.type_guess = correctedType;
          dependent.draft.type_source = "manual";
          dependent.draft.type_secondary = [];
          return await reply({
            ok: true,
            next_state: "Q1_CONFIRM_TYPE",
            prompt: `Perfect — I’ll label your business type as "${correctedType}". Is that correct?`,
          });
        }

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

        independent.business.type_final = canonicalizeBusinessTypeLabel(dependent.draft.type_guess);
        independent.business.type_secondary = Array.isArray(dependent?.draft?.type_secondary)
          ? dependent.draft.type_secondary
          : [];
        await rememberBusinessType(independent.business.description_raw, independent.business.type_final, dependent?.draft?.type_source || "user_confirmed");

        return await reply({
          ok: true,
          next_state: "Q2_PASTE_URL_OR_NO",
          prompt:
            "Please paste your website URL (if you have one), a website similar to what you want, " +
            "or tell me to start picking example sites so we can see what you like and dislike.",
        });
      }

      if (state === "Q1_TYPE_MANUAL") {
        if (!isLikelyBusinessTypeLabel(answerText)) {
          return json(
            {
              ok: false,
              error:
                'Please provide a short business type label (example: "home hobbyist"), not a full sentence.',
            },
            400
          );
        }
        const t = canonicalizeBusinessTypeLabel(answerText);
        if (!t) return json({ ok: false, error: "Please provide a business type label." }, 400);
        dependent.draft.type_guess = t;
        dependent.draft.type_source = "manual";
        dependent.draft.type_secondary = [];
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
        const referenceUrl = sanitizeReferenceUrl(foundUrl);
        const sameLocationIntent = /\b(same location|same area|same zip|same zipcode|same zip code|same city|same town)\b/i.test(text);

        if (v === "no" || noCurrentSite) {
          independent.business.own_site_url = null;
          independent.business.own_site_confirmed = false;
          dependent.research = dependent.research || {};
          if (referenceUrl) dependent.research.user_reference_url = referenceUrl;
          let locationScanLine = "";
          if (referenceUrl && sameLocationIntent) {
            const denied = ensureExpensiveActionAllowed(dependent);
            if (denied) return denied;
            try {
              const started = await startSiteScan(session_id, referenceUrl);
              const refVars = deriveReferenceLocationVars(started?.result || null, referenceUrl);
              dependent.research.reference_location = refVars;
              if (refVars?.zip_code) dependent.research.same_zip_as_reference = refVars.zip_code;
              if (refVars?.location_hint) dependent.research.location_hint = refVars.location_hint;
              if (refVars?.summary) locationScanLine = `${refVars.summary}\n\n`;
            } catch {}
          }
          const intentSourceText = referenceUrl ? String(text || "").replace(foundUrl, " ").trim() : text;
          const impliedIntent = extractIntentFromNoSiteReply(intentSourceText);
          const referenceLine = referenceUrl
            ? `Thanks — I’ll use ${referenceUrl} as a reference example (not as your website).\n\n`
            : "";
          if (impliedIntent) {
            const businessType = independent.business.type_final || dependent?.draft?.type_guess || "local business";
            const locationHint = dependent?.research?.location_hint || geoToLocationText(independent?.person?.geo) || "";
            const openAiKey = await resolveOpenAiApiKeyForDependent(dependent);
            const resolved = await resolveWebsiteIntentFocus(impliedIntent, businessType, locationHint, openAiKey);
            dependent.research = dependent.research || {};
            dependent.research.intent_raw = resolved.raw || impliedIntent;
            dependent.research.intent_draft = resolved.focus || impliedIntent;
            dependent.research.intent_source = resolved.source || "user";
            return await reply({
              ok: true,
              next_state: "Q2_SITE_INTENT_CONFIRM",
              prompt: `${referenceLine}${locationScanLine}Perfect — I’ll search examples for "${dependent.research.intent_draft}". Right?`,
            });
          }
          return await reply({
            ok: true,
            next_state: "Q2_SITE_INTENT",
            prompt:
              `${referenceLine}${locationScanLine}No problem. What type of website do you want? ` +
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
        const openAiKey = await resolveOpenAiApiKeyForDependent(dependent);
        const resolved = await resolveWebsiteIntentFocus(rawIntent, businessType, locationHint, openAiKey);
        dependent.research = dependent.research || {};
        dependent.research.intent_raw = resolved.raw || rawIntent;
        dependent.research.intent_draft = resolved.focus || rawIntent;
        dependent.research.intent_source = resolved.source || "user";

        return await reply({
          ok: true,
          next_state: "Q2_SITE_INTENT_CONFIRM",
          prompt: `Perfect — I’ll search examples for "${dependent.research.intent_draft}". Right?`,
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
          const referenceUrl = sanitizeReferenceUrl(independent?.business?.own_site_url);
          independent.business.own_site_confirmed = false;
          independent.business.own_site_url = null;
          if (referenceUrl) {
            dependent.research = dependent.research || {};
            dependent.research.user_reference_url = referenceUrl;
            const mergedSites = normalizeReferenceSites(
              [{ title: "Reference you shared", url: referenceUrl }, ...(dependent.research.sites || [])]
            );
            dependent.research.sites = mergedSites;
            dependent.research.current_site_index = 0;
            dependent.research.source = mergedSites.length ? "user_reference_seed" : dependent.research.source || "user_reference_seed";
            independent.demo = independent.demo || {};
            independent.demo.last_demo_url = referenceUrl;
            return await reply({
              ok: true,
              next_state: "Q3_FEEDBACK_OPEN",
              prompt:
                `Perfect — I’ll use ${referenceUrl} as a reference site for your design direction.\n\n` +
                "What do you like most about it, and what would you change first?",
              open_url: referenceUrl,
              demo_url: referenceUrl,
              reference_sites: mergedSites,
            });
          }
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
              "I detected your site is on WordPress. I can run a free security + speed + schema audit now and show where your site is doing well and where it can improve.\n\n" +
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
          if (result) {
            applyScanResultToSession(independent, dependent, result);
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
            "Saved. I stored this schema profile for your site build plan.\n" +
            "When ready, I can use it in your generated site JSON-LD.\n\n" +
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
        if (wantsHelpWithWebsiteChanges(answer)) {
          independent.business.happy_with_site_and_cost = false;
          await upsertSessionVars(session_id, "onboarding_v8", independent, dependent);
          return await reply({
            ok: true,
            next_state: "Q3_VIEW_EXAMPLES_YN",
            prompt:
              "Absolutely — I can help with that. Let’s review a few example sites so I can learn your direction and then map the changes step-by-step.",
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
              ? "Great. If it helps, we can review a few example sites together so I can learn what you like and dislike."
              : "If it helps, we can review a few example sites together and compare them to your current site.",
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
        if (wantsHelpWithWebsiteChanges(answer)) {
          independent.business.happy_with_site_and_cost = false;
          await upsertSessionVars(session_id, "onboarding_v8", independent, dependent);
          return await reply({
            ok: true,
            next_state: "Q3_VIEW_EXAMPLES_YN",
            prompt:
              "Absolutely — I can help with those changes. Let’s review a few example sites so I can capture your preferences and build the right revision plan.",
          });
        }
        if (v !== "yes" && v !== "no") return json({ ok: false, error: 'Please answer "yes" or "no".' }, 400);

        independent.business.happy_with_site_and_cost = (v === "yes");
        await upsertSessionVars(session_id, "onboarding_v8", independent, dependent);

        return await reply({
          ok: true,
          next_state: "Q3_VIEW_EXAMPLES_YN",
          prompt:
            v === "yes"
              ? "Great. If it helps, we can review a few example sites together so I can learn what you like and dislike."
              : "If it helps, we can review a few example sites together and compare them to your current site.",
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
          prompt: "If it helps, would you like to review a few example sites together and tell me what you like or don’t like?",
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
              "Good question — examples help me understand your taste so I can make better recommendations and avoid wasting your time. " +
              "Would reviewing a couple examples be helpful?",
          });
        }

        if (v === "howknow") {
          return await reply({
            ok: true,
            next_state: "Q3_VIEW_EXAMPLES_YN",
            prompt:
              "Totally fair — we can start with one or two examples first, then decide next steps based on what you like. " +
              "Would you like to try that?",
          });
        }

        if (v !== "yes" && v !== "no") return json({ ok: false, error: 'Please answer "yes" or "no".' }, 400);

        if (v === "no") {
          return await reply({
            ok: true,
            next_state: "Q_BUILD_TRIAL_YN",
            prompt:
              "No problem. If helpful, I can still draft a sample site from your goals so you can react to something concrete. Want me to do that?",
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
              .map((f) => sanitizeReferenceUrl(f?.site_url))
              .filter(Boolean)
          )
        );
        const userReferenceUrl = sanitizeReferenceUrl(dependent?.research?.user_reference_url);
        let demoUrl = PLACEHOLDER_DEMO_URL;
        let source = "fallback_demo";
        let sites = [];

        try {
          const market = await searchNearbyReferenceSites(session_id, businessType, locationHint, intentText || null, excludedUrls);
          sites = normalizeReferenceSites(market?.sites, excludedUrls);
          source = market?.source || "inspector_market_search";
          if (sites.length) demoUrl = sites[0].url;
        } catch (error) {
          sites = [];
          source = "fallback_demo";
        }

        if (userReferenceUrl) {
          sites = normalizeReferenceSites(
            [{ title: "Reference you shared", url: userReferenceUrl }, ...sites],
            excludedUrls
          );
          if (sites.length && sites[0]?.url === userReferenceUrl) {
            source = source === "fallback_demo" ? "user_reference_seed" : `user_reference_seed+${source}`;
          }
        }

        if (!sites.length && userReferenceUrl) {
          sites = [{ title: "Reference you shared", url: userReferenceUrl }];
          source = "user_reference_seed";
        }
        if (sites.length) demoUrl = sites[0].url;

        demoUrl = sanitizeReferenceUrl(demoUrl) || PLACEHOLDER_DEMO_URL;

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
        const introLine = userReferenceUrl && sites[0]?.url === userReferenceUrl
          ? "Thanks — I’ll start with the reference you shared. "
          : "";
        return await reply({
          ok: true,
          next_state: "Q3_VIEWING_DEMO",
          prompt:
            `${introLine}I found a reference site${scopeLine}. Open this link in a new tab: ` +
            `${demoUrl}\n\nTake about 20–30 seconds to look it over, then come back and tell me when you’re ready.`,
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
        const demoUrl = sanitizeReferenceUrl(independent?.demo?.last_demo_url) || PLACEHOLDER_DEMO_URL;
        const suggestedUrl = sanitizeReferenceUrl(extractUrlFromText(txt));

        if (suggestedUrl) {
          dependent.research = dependent.research || {};
          const sites = normalizeReferenceSites(dependent.research.sites || []);
          const idxRaw = Number(dependent?.research?.current_site_index ?? 0);
          const idx = Number.isFinite(idxRaw) ? Math.max(0, idxRaw) : 0;
          const nextSites = [...sites];
          nextSites[idx] = {
            ...(nextSites[idx] || {}),
            url: suggestedUrl,
            title: (nextSites[idx]?.title || "User selected reference").slice(0, 160),
          };
          dependent.research.sites = normalizeReferenceSites(nextSites);
          dependent.research.current_site_index = Math.min(idx, Math.max(0, dependent.research.sites.length - 1));
          independent.demo.last_demo_url = suggestedUrl;
          return await reply({
            ok: true,
            next_state: "Q3_VIEWING_DEMO",
            prompt:
              `Great choice — let’s use this reference site: ${suggestedUrl}\n\n` +
              'Reply "opened" once you’ve viewed it for ~20–30 seconds.',
            open_url: suggestedUrl,
            demo_url: suggestedUrl,
          });
        }

        if (cannotAccessDemoSite(txt)) {
          return await handleReferenceMismatch(txt || "could_not_open_reference_site");
        }

        if (/\b(help|stuck|confused)\b/.test(String(txt || "").toLowerCase())) {
          return await reply({
            ok: true,
            next_state: "Q3_VIEWING_DEMO",
            prompt:
              "No problem. If that link is bad, paste a direct website URL you want to use as the reference (for example: https://www.hertz.com/...). " +
              'Or reply "different site" and I will pick another one.',
          });
        }
        if (/\b(different site|another site|new site|skip this)\b/.test(String(txt || "").toLowerCase())) {
          return await handleReferenceMismatch(txt || "request_different_site");
        }

        if (!isReadyAfterOpeningDemo(txt) && yesNoMaybe(txt) !== "yes") {
          return await reply({
            ok: true,
            next_state: "Q3_VIEWING_DEMO",
            prompt:
              `When you're ready, open this link: ${demoUrl}\n\n` +
              "If the tab did not open, paste this link directly in your browser. Reply \"opened\" once you've seen it for 20–30 seconds.",
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
        const demoUrl = sanitizeReferenceUrl(independent?.demo?.last_demo_url) || PLACEHOLDER_DEMO_URL;
        const suggestedUrl = sanitizeReferenceUrl(extractUrlFromText(txt));

        if (suggestedUrl) {
          independent.demo.last_demo_url = suggestedUrl;
          return await reply({
            ok: true,
            next_state: "Q3_DEMO_Q1",
            prompt:
              `Perfect — we’ll use your chosen reference site: ${suggestedUrl}\n\n` +
              'First impression: did this example feel more "modern/clean" or more "bold/flashy"? (modern / bold)',
            open_url: suggestedUrl,
            demo_url: suggestedUrl,
          });
        }

        if (cannotAccessDemoSite(txt)) {
          return await handleReferenceMismatch(txt || "could_not_open_reference_site");
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
          palette_options: [],
          selected_palette: null,
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
        const demoUrl = sanitizeReferenceUrl(independent?.demo?.last_demo_url) || PLACEHOLDER_DEMO_URL;

        if (cannotAccessDemoSite(t)) {
          return await handleReferenceMismatch(t || "could_not_open_reference_site");
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
        if (/^(ok|okay|fine|good|alright|all right)$/.test(t.trim())) {
          independent.demo.q1_vibe = "neutral";
          dependent.design = dependent.design || {};
          dependent.design.layout_hints = Array.from(new Set([...(dependent.design.layout_hints || []), "balanced"]));
          await upsertSessionVars(session_id, "onboarding_v8", independent, dependent);
          return await reply({
            ok: true,
            next_state: "Q3_DEMO_Q2",
            prompt: "No problem — what did you think about the colors? (too bright / too dark / just right)",
          });
        }

        const businessType = independent?.business?.type_final || dependent?.draft?.type_guess || "";
        if (userRejectedReferenceSite(t, businessType)) {
          return await handleReferenceMismatch(t);
        }

        const modern = t.includes("modern");
        const modernSyn = /\b(clean|minimal|sleek|simple)\b/.test(t);
        const bold = t.includes("bold");
        const boldSyn = /\b(flashy|loud|dramatic|vibrant|high contrast)\b/.test(t);
        const useModern = modern || modernSyn;
        const useBold = bold || boldSyn;
        if (!useModern && !useBold) return json({ ok: false, error: 'Please reply "modern" or "bold".' }, 400);

        independent.demo.q1_vibe = useModern ? "modern" : "bold";
        dependent.design = dependent.design || {};
        dependent.design.layout_hints = Array.from(
          new Set([...(dependent.design.layout_hints || []), useModern ? "clean_modern" : "bold_visual"])
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
        const ok = /(too bright|too dark|just right|about right|looks right|right level|perfect|looks good|good|fine)/.test(t);
        if (!ok) return json({ ok: false, error: 'Please reply "too bright", "too dark", or "just right".' }, 400);

        independent.demo.q2_colors = t.includes("bright") ? "too bright" : t.includes("dark") ? "too dark" : "just right";
        dependent.design = dependent.design || {};
        if (t.includes("bright")) dependent.design.palette_hints = Array.from(new Set([...(dependent.design.palette_hints || []), "avoid_too_bright"]));
        if (t.includes("dark")) dependent.design.palette_hints = Array.from(new Set([...(dependent.design.palette_hints || []), "avoid_too_dark"]));
        if (t.includes("just right")) dependent.design.palette_hints = Array.from(new Set([...(dependent.design.palette_hints || []), "balanced_contrast"]));
        const paletteOptions = buildPaletteChoiceOptions(independent, dependent);
        dependent.design.palette_options = paletteOptions;
        await upsertSessionVars(session_id, "onboarding_v8", independent, dependent);

        return await reply({
          ok: true,
          next_state: "Q3_PALETTE_PICK",
          prompt:
            "Great — I put together 3 full color palettes. Which one fits your brand best? (A / B / C)\n" +
            "Tip: each option is a full 5-color palette, not a single color.",
          palette_options: paletteOptions,
        });
      }

      if (state === "Q3_PALETTE_PICK") {
        const options = Array.isArray(dependent?.design?.palette_options) && dependent.design.palette_options.length
          ? dependent.design.palette_options
          : buildPaletteChoiceOptions(independent, dependent);
        const selected = parsePaletteChoice(answerText, options);
        if (!selected) {
          return json({ ok: false, error: 'Please choose palette "A", "B", or "C".' }, 400);
        }

        dependent.design = dependent.design || {};
        dependent.design.palette_options = options;
        dependent.design.selected_palette = selected;
        dependent.design.palette_hints = Array.from(
          new Set([...(dependent.design.palette_hints || []), ...(Array.isArray(selected.hints) ? selected.hints : [])])
        ).slice(0, 20);
        independent.demo = independent.demo || {};
        independent.demo.q2_palette = selected.id;
        independent.build = independent.build || {};
        independent.build.colors = `${selected.name}: ${(Array.isArray(selected.colors) ? selected.colors : []).join(", ")}`.slice(0, 200);
        await upsertSessionVars(session_id, "onboarding_v8", independent, dependent);

        return await reply({
          ok: true,
          next_state: "Q3_DEMO_Q3",
          prompt: `Perfect — I saved palette ${selected.id} (${selected.name}). How did the layout feel? (easy to read / cluttered / too empty)`,
        });
      }

      if (state === "Q3_DEMO_Q3") {
        const t = String(answer || "").trim().toLowerCase();
        const ok = /(easy to read|easy|clear|hard to read|cluttered|busy|crowded|too empty|empty|sparse)/.test(t);
        if (!ok) return json({ ok: false, error: 'Please reply "easy to read", "cluttered", or "too empty".' }, 400);

        independent.demo.q3_layout = t.includes("easy") || t.includes("clear") ? "easy to read" : t.includes("clutter") || t.includes("busy") || t.includes("crowded") || t.includes("hard to read") ? "cluttered" : "too empty";
        dependent.design = dependent.design || {};
        if (t.includes("easy")) dependent.design.layout_hints = Array.from(new Set([...(dependent.design.layout_hints || []), "readable"]));
        if (t.includes("clutter")) dependent.design.layout_hints = Array.from(new Set([...(dependent.design.layout_hints || []), "avoid_clutter"]));
        if (t.includes("too empty")) dependent.design.layout_hints = Array.from(new Set([...(dependent.design.layout_hints || []), "denser_sections"]));
        await upsertSessionVars(session_id, "onboarding_v8", independent, dependent);
        await persistPreferenceSnapshot(session_id, independent, dependent);

        return await reply({
          ok: true,
          next_state: "Q3_NEXT_REFERENCE_YN",
          prompt: "Want to review one more reference site before I draft a sample page for you? (yes/no)",
        });
      }

      if (state === "Q3_NEXT_REFERENCE_YN") {
        const v = yesNoMaybe(answer);
        if (v !== "yes" && v !== "no") return json({ ok: false, error: 'Please answer "yes" or "no".' }, 400);

        const sites = normalizeReferenceSites(Array.isArray(dependent?.research?.sites) ? dependent.research.sites : []);
        dependent.research = dependent.research || {};
        dependent.research.sites = sites;
        const idxRaw = Number(dependent?.research?.current_site_index ?? 0);
        const idx = Number.isFinite(idxRaw) ? idxRaw : 0;
        const nextIdx = idx + 1;

        if (v === "yes" && nextIdx < sites.length) {
          const nextSite = sites[nextIdx];
          const nextUrl = sanitizeReferenceUrl(nextSite?.url);
          if (!nextUrl) {
            dependent.research.current_site_index = nextIdx;
            return await handleReferenceMismatch("invalid_reference_url");
          }
          dependent.research.current_site_index = nextIdx;
          independent.demo.last_demo_url = nextUrl;

          return await reply({
            ok: true,
            next_state: "Q3_VIEWING_DEMO",
            prompt:
              "Great — here’s the next reference site. Open this in a new tab: " +
              `${nextUrl}\n\nI’ll ask you what you like most in about 20 seconds.`,
            open_url: nextUrl,
            demo_url: nextUrl,
            auto_advance_after_seconds: 20,
            auto_advance_answer: "__AUTO_AFTER_20S__",
          });
        }

        if (v === "yes" && nextIdx >= sites.length) {
          return await handleReferenceMismatch("requested_more_reference_sites");
        }

        return await reply({
          ok: true,
          next_state: "Q_BUILD_TRIAL_YN",
          prompt: "Thanks — based on your feedback, would you like me to draft a sample site so you can see your direction in practice? (yes/no)",
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
                "I’ll use those insights while we continue. If helpful, we can review a few example sites together and capture what you like/dislike.",
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
          prompt: "No problem. If helpful, would you like to review a few example sites together and tell me what you like or don’t like?",
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
              "If helpful, would you like to review a few example sites together and tell me what you like or don’t like?",
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
              "Totally fair — I can draft a simple sample based on your goals, and you can tell me what to change. No commitment needed. Want me to build that?",
          });
        }

        if (v === "maybe") {
          const funnelSummary = buildFunnelCtaActions(dependent);
          return await reply({
            ok: true,
            next_state: "DONE",
            prompt: "No problem — we can skip the sample for now. If you want help later, just come back and I’ll help you plan the next step.",
            funnel_stage: funnelSummary.stage,
            upgrade_score: funnelSummary.score,
            cta_actions: funnelSummary.actions,
          });
        }

        if (v !== "yes" && v !== "no") return json({ ok: false, error: 'Please answer "yes" or "no".' }, 400);

        independent.business.wants_free_trial_build = (v === "yes");
        await upsertSessionVars(session_id, "onboarding_v8", independent, dependent);

        if (v === "no") {
          return await reply({ ok: true, next_state: "DONE", prompt: "No problem. If you want help later, I’m here." });
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
        if (connectAction?.url) extraLines.push(`Connect Cloudflare when you're ready to publish and manage setup: ${connectAction.url}`);
        if (migrateAction?.url) extraLines.push(`If you ever want managed migration help, this is available: ${migrateAction.url}`);
        const ctaText = extraLines.length ? `\n\n${extraLines.join("\n")}` : "";

        return await reply({
          ok: true,
          next_state: "DONE",
          prompt:
            demo?.url
              ? `Perfect. Your first demo site is ready: ${demo.url} . I tuned it to the preferences you shared so far. Review it and reply with edits, and I’ll iterate from your feedback.${ctaText}`
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
