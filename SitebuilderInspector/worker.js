const inspectorRateLimitMap = new Map();

function consumeInspectorRateLimit(ip, bucket, ts, windowMs, max) {
  const ipKey = String(ip || "anon").trim() || "anon";
  const key = `${bucket}:${ipKey}`;
  const nowTs = Number(ts) || Date.now();
  const cutoff = nowTs - windowMs;
  const prev = inspectorRateLimitMap.get(key) || [];
  const recent = prev.filter((x) => x > cutoff);
  recent.push(nowTs);
  inspectorRateLimitMap.set(key, recent);

  if (inspectorRateLimitMap.size > 10000) {
    for (const [k, arr] of inspectorRateLimitMap.entries()) {
      if (!arr.some((x) => x > cutoff)) inspectorRateLimitMap.delete(k);
    }
  }

  return recent.length <= max;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

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
      /^https:\/\/[a-z0-9-]+\.sitebuilder1-03\.pages\.dev$/.test(origin) ||
      /^https:\/\/[a-z0-9-]+\.cardetailingreno\.com$/.test(origin);

    const corsHeaders = {
      "Access-Control-Allow-Origin": allowed ? origin : "null",
      "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
      "Access-Control-Max-Age": "86400",
      Vary: "Origin",
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
    const newId = (p) => `${p}_${crypto.randomUUID()}`;
    const clientIp =
      String(request.headers.get("CF-Connecting-IP") || "").trim() ||
      String(request.headers.get("x-forwarded-for") || "").split(",")[0].trim() ||
      "anon";
    const toHttpsUrl = (raw) => {
      const s = String(raw || "").trim();
      if (!s) return null;
      if (s.startsWith("http://") || s.startsWith("https://")) return s;
      return `https://${s}`;
    };

    function extractBasics(html) {
      const title = (html.match(/<title[^>]*>([^<]*)<\/title>/i)?.[1] || "").trim().slice(0, 200);
      const h1 = (html.match(/<h1[^>]*>([\s\S]*?)<\/h1>/i)?.[1] || "")
        .replace(/<[^>]+>/g, "")
        .trim()
        .slice(0, 200);

      const meta_description =
        (html.match(/<meta[^>]+name=["']description["'][^>]+content=["']([^"']+)["']/i)?.[1] || "")
          .trim()
          .slice(0, 300);

      const emails = Array.from(new Set((html.match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi) || []).slice(0, 20)));
      const phones = Array.from(
        new Set((html.match(/(\+?1?[\s.-]?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4})/g) || []).slice(0, 20))
      );
      const addresses = [];

      const socials = [];
      const socialHosts = ["instagram.com", "facebook.com", "tiktok.com", "youtube.com", "twitter.com", "x.com", "linkedin.com"];
      for (const host of socialHosts) {
        const re = new RegExp(`https?:\\\\/\\\\/(?:www\\\\.)?${host.replace(".", "\\\\.")}[^"'\\s>]+`, "ig");
        const found = html.match(re) || [];
        for (const f of found) socials.push(f);
      }

      const lower = html.toLowerCase();
      let platform_hint = null;
      if (lower.includes("wp-content") || lower.includes("wordpress")) platform_hint = "wordpress";
      else if (lower.includes("wixstatic") || lower.includes("wix.com")) platform_hint = "wix";
      else if (lower.includes("squarespace")) platform_hint = "squarespace";
      else if (lower.includes("cdn.shopify.com") || lower.includes("shopify")) platform_hint = "shopify";
      else if (lower.includes("webflow")) platform_hint = "webflow";

      const schema_types = [];
      const ldBlocks = html.match(/<script[^>]+type=["']application\/ld\+json["'][^>]*>[\s\S]*?<\/script>/gi) || [];
      for (const block of ldBlocks.slice(0, 8)) {
        const jsonText = block.replace(/^[\s\S]*?>/,"").replace(/<\/script>$/i,"");
        try {
          const parsed = JSON.parse(jsonText);
          const items = Array.isArray(parsed) ? parsed : [parsed];
          for (const it of items) {
            const t = it?.["@type"];
            if (t) schema_types.push(t);
            const addr = it?.address;
            if (typeof addr === "string") {
              addresses.push(addr);
            } else if (addr && typeof addr === "object") {
              const bits = [
                addr.streetAddress,
                addr.addressLocality,
                addr.addressRegion,
                addr.postalCode
              ]
                .filter(Boolean)
                .map((x) => String(x).trim());
              if (bits.length) addresses.push(bits.join(", "));
            }
          }
        } catch {}
      }

      const addressRe = /\d{1,6}\s+[A-Za-z0-9.#\-\s]{3,80}\s(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Circle|Cir)\b[^\n<]{0,120}/gi;
      for (const m of html.match(addressRe) || []) {
        addresses.push(m.replace(/\s+/g, " ").trim());
      }

      return {
        title,
        h1,
        meta_description,
        emails,
        phones,
        addresses: Array.from(new Set(addresses)).slice(0, 20),
        socials: Array.from(new Set(socials)).slice(0, 20),
        platform_hint,
        schema_types: Array.from(new Set(schema_types)).slice(0, 20),
        raw_size: html.length,
      };
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

    async function dnsQuery(name, type) {
      const u = new URL("https://cloudflare-dns.com/dns-query");
      u.searchParams.set("name", String(name || ""));
      u.searchParams.set("type", String(type || "A"));
      try {
        const r = await fetch(u.toString(), {
          headers: { accept: "application/dns-json", "User-Agent": "Mozilla/5.0 (compatible; SiteInspector/1.0)" },
        });
        if (!r.ok) return [];
        const data = await r.json().catch(() => null);
        const answers = Array.isArray(data?.Answer) ? data.Answer : [];
        return answers.map((x) => String(x?.data || "").trim()).filter(Boolean);
      } catch {
        return [];
      }
    }

    function inferEmailProvider(mxHosts) {
      const hosts = (Array.isArray(mxHosts) ? mxHosts : []).map((x) => String(x || "").toLowerCase());
      if (!hosts.length) return null;
      if (hosts.some((h) => h.includes("google.com") || h.includes("googlemail.com"))) return "Google Workspace";
      if (hosts.some((h) => h.includes("outlook.com") || h.includes("protection.outlook.com") || h.includes("office365"))) {
        return "Microsoft 365";
      }
      if (hosts.some((h) => h.includes("zoho."))) return "Zoho Mail";
      if (hosts.some((h) => h.includes("protonmail."))) return "Proton Mail";
      if (hosts.some((h) => h.includes("fastmail."))) return "Fastmail";
      if (hosts.some((h) => h.includes("secureserver.net"))) return "GoDaddy Email";
      return "Other/Unknown";
    }

    function guessHostingCompanyFromSignals(signals) {
      const hay = String(signals || "").toLowerCase();
      if (!hay) return null;
      const map = [
        ["cloudflare", "Cloudflare"],
        ["vercel", "Vercel"],
        ["netlify", "Netlify"],
        ["wpengine", "WP Engine"],
        ["kinsta", "Kinsta"],
        ["digitalocean", "DigitalOcean"],
        ["linode", "Linode / Akamai"],
        ["aws", "Amazon Web Services"],
        ["amazon", "Amazon Web Services"],
        ["azure", "Microsoft Azure"],
        ["google", "Google Cloud"],
        ["siteground", "SiteGround"],
        ["godaddy", "GoDaddy"],
        ["hostgator", "HostGator"],
        ["bluehost", "Bluehost"],
      ];
      for (const [needle, label] of map) {
        if (hay.includes(needle)) return label;
      }
      return null;
    }

    function inferServerHardwareHints(responseHeaders, rdapIp = null, hostingCompany = null) {
      const serverHeader = String(responseHeaders?.get("server") || "").trim();
      const poweredBy = String(responseHeaders?.get("x-powered-by") || "").trim();
      const via = String(responseHeaders?.get("via") || "").trim();
      const edge = String(responseHeaders?.get("cf-ray") || "").trim() ? "Cloudflare" : null;
      const stackTokens = [];
      const hay = `${serverHeader} ${poweredBy} ${via}`.toLowerCase();
      if (/\bnginx\b/.test(hay)) stackTokens.push("nginx");
      if (/\bapache\b/.test(hay)) stackTokens.push("apache");
      if (/\blitespeed\b/.test(hay)) stackTokens.push("litespeed");
      if (/\biis\b/.test(hay)) stackTokens.push("iis");
      if (/\bphp\b/.test(hay)) stackTokens.push("php");
      if (/\bopenresty\b/.test(hay)) stackTokens.push("openresty");

      return {
        edge_network: edge,
        hosting_provider_hint: hostingCompany || null,
        server_stack_hints: Array.from(new Set(stackTokens)).slice(0, 8),
        rdap_network_name: rdapIp?.name || null,
        rdap_country: rdapIp?.country || null,
        cpu_model: null,
        memory_gb: null,
        disk_gb: null,
        visibility: "public_scan_limited",
        source: "headers_dns_rdap",
      };
    }

    async function fetchRdapDomain(domain) {
      const d = String(domain || "").trim().toLowerCase();
      if (!d) return null;
      try {
        const r = await fetch(`https://rdap.org/domain/${encodeURIComponent(d)}`, {
          headers: { "User-Agent": "Mozilla/5.0 (compatible; SiteInspector/1.0)" },
        });
        if (!r.ok) return null;
        const data = await r.json().catch(() => null);
        if (!data || typeof data !== "object") return null;
        let registrar = null;
        const entities = Array.isArray(data.entities) ? data.entities : [];
        for (const e of entities) {
          const roles = Array.isArray(e?.roles) ? e.roles.map((x) => String(x || "").toLowerCase()) : [];
          if (!roles.includes("registrar")) continue;
          const vcard = Array.isArray(e?.vcardArray?.[1]) ? e.vcardArray[1] : [];
          for (const item of vcard) {
            if (!Array.isArray(item) || item[0] !== "fn") continue;
            registrar = String(item[3] || "").trim() || null;
            if (registrar) break;
          }
          if (registrar) break;
        }
        let expiresAt = null;
        const events = Array.isArray(data.events) ? data.events : [];
        for (const ev of events) {
          const action = String(ev?.eventAction || "").toLowerCase();
          if (action.includes("expiration") || action.includes("expiry") || action.includes("expired")) {
            const rawDate = String(ev?.eventDate || "").trim();
            if (rawDate) {
              expiresAt = rawDate;
              break;
            }
          }
        }
        return {
          registrar,
          handle: data.handle || null,
          ldhName: data.ldhName || d,
          expires_at: expiresAt,
        };
      } catch {
        return null;
      }
    }

    function extractInternalLinks(finalUrl, html, maxLinks = 30) {
      const out = [];
      const seen = new Set();
      const base = new URL(finalUrl);
      const re = /<a[^>]+href=["']([^"']+)["']/gi;
      let m;
      while ((m = re.exec(html)) && out.length < maxLinks) {
        const href = String(m[1] || "").trim();
        if (!href) continue;
        if (/^(#|mailto:|tel:|javascript:|data:)/i.test(href)) continue;
        let target;
        try {
          target = new URL(href, base);
        } catch {
          continue;
        }
        if (target.hostname !== base.hostname) continue;
        target.hash = "";
        const normalized = target.toString();
        if (seen.has(normalized)) continue;
        seen.add(normalized);
        out.push(normalized);
      }
      return out;
    }

    async function fetchLinkStatus(url) {
      try {
        const head = await fetch(url, {
          method: "HEAD",
          headers: { "User-Agent": "Mozilla/5.0 (compatible; SiteInspector/1.0)" },
        });
        if (head.status === 405 || head.status === 501) {
          const getResp = await fetch(url, {
            method: "GET",
            headers: { "User-Agent": "Mozilla/5.0 (compatible; SiteInspector/1.0)" },
          });
          return { ok: getResp.ok, status: getResp.status };
        }
        return { ok: head.ok, status: head.status };
      } catch {
        return { ok: false, status: 0 };
      }
    }

    async function auditBrokenInternalLinks(finalUrl, html) {
      const candidates = extractInternalLinks(finalUrl, html, 30);
      const broken = [];
      for (const u of candidates) {
        const status = await fetchLinkStatus(u);
        if (status.ok && status.status < 400) continue;
        try {
          const p = new URL(u);
          const path = `${p.pathname || "/"}${p.search || ""}`;
          if (path && path !== "/" && !broken.includes(path)) broken.push(path);
        } catch {
          // ignore malformed URL parse after fetch fallback
        }
      }
      return {
        checked_count: candidates.length,
        broken_count: broken.length,
        broken_paths: broken.slice(0, 200),
      };
    }

    async function fetchRdapIp(ip) {
      const v = String(ip || "").trim();
      if (!v) return null;
      try {
        const r = await fetch(`https://rdap.org/ip/${encodeURIComponent(v)}`, {
          headers: { "User-Agent": "Mozilla/5.0 (compatible; SiteInspector/1.0)" },
        });
        if (!r.ok) return null;
        const data = await r.json().catch(() => null);
        if (!data || typeof data !== "object") return null;
        return {
          name: data.name || null,
          handle: data.handle || null,
          country: data.country || null,
        };
      } catch {
        return null;
      }
    }

    function detectThirdPartyVendors(html) {
      const lower = String(html || "").toLowerCase();
      const vendors = {
        crm: [],
        merchanting: [],
        booking: [],
        email_marketing: [],
        analytics: [],
        chat_support: [],
        other: [],
      };
      const seen = new Set();
      const add = (bucket, label) => {
        const key = `${bucket}:${label}`;
        if (seen.has(key)) return;
        seen.add(key);
        vendors[bucket].push(label);
      };

      const checks = [
        ["crm", "HubSpot", /hubspot|hs-scripts|hsforms/],
        ["crm", "Salesforce", /salesforce|pardot|force\.com/],
        ["crm", "GoHighLevel", /gohighlevel|leadconnector/],
        ["merchanting", "Stripe", /stripe\.com|js\.stripe\.com|stripe/],
        ["merchanting", "PayPal", /paypal\.com|braintree/],
        ["merchanting", "Square", /squareup|square\.com/],
        ["merchanting", "Authorize.Net", /authorize\.net/],
        ["booking", "Calendly", /calendly/],
        ["booking", "Acuity", /acuityscheduling|acuity/],
        ["booking", "Booksy", /booksy/],
        ["booking", "Mindbody", /mindbody/],
        ["booking", "OpenTable", /opentable/],
        ["email_marketing", "Mailchimp", /mailchimp|list-manage/],
        ["email_marketing", "Klaviyo", /klaviyo/],
        ["email_marketing", "Constant Contact", /constantcontact/],
        ["analytics", "Google Analytics", /googletagmanager|google-analytics|gtag\(/],
        ["analytics", "Meta Pixel", /connect\.facebook\.net\/.*fbevents|fbq\(/],
        ["analytics", "Hotjar", /hotjar/],
        ["chat_support", "Intercom", /intercom/],
        ["chat_support", "Drift", /drift\.com|drift/],
        ["chat_support", "Zendesk", /zdassets|zendesk/],
      ];
      for (const [bucket, label, re] of checks) {
        if (re.test(lower)) add(bucket, label);
      }

      if (/\bshopify\b/.test(lower)) add("other", "Shopify");
      if (/\bwoocommerce\b/.test(lower)) add("other", "WooCommerce");
      if (/\belementor\b/.test(lower)) add("other", "Elementor");
      if (/\bgravity forms\b|gravityforms/.test(lower)) add("other", "Gravity Forms");
      if (/\bcontact form 7\b|wpcf7/.test(lower)) add("other", "Contact Form 7");

      return vendors;
    }

    async function buildDnsAndInfraProfile(finalUrl, responseHeaders, html) {
      try {
        const parsed = new URL(finalUrl);
        const hostname = parsed.hostname;
        const domain = rootDomainFromHostname(hostname) || hostname;

        const [aRecords, aaaaRecords, cnameRecords, nsRecords, mxRecords, txtRecords, rdapDomain] = await Promise.all([
          dnsQuery(hostname, "A"),
          dnsQuery(hostname, "AAAA"),
          dnsQuery(hostname, "CNAME"),
          dnsQuery(domain, "NS"),
          dnsQuery(domain, "MX"),
          dnsQuery(domain, "TXT"),
          fetchRdapDomain(domain),
        ]);

        let rdapIp = null;
        const firstIp = aRecords[0] || aaaaRecords[0] || null;
        if (firstIp) rdapIp = await fetchRdapIp(firstIp);

        const serverHeader = String(responseHeaders?.get("server") || "").trim() || null;
        const poweredBy = String(responseHeaders?.get("x-powered-by") || "").trim() || null;
        const providerSignals = [
          serverHeader,
          poweredBy,
          cnameRecords.join(" "),
          nsRecords.join(" "),
          rdapIp?.name || "",
          html.slice(0, 6000),
        ]
          .filter(Boolean)
          .join(" ");

        const hostingCompany = guessHostingCompanyFromSignals(providerSignals) || rdapIp?.name || null;
        const emailProvider = inferEmailProvider(mxRecords);
        const vendors = detectThirdPartyVendors(html);
        const serverHardwareHints = inferServerHardwareHints(responseHeaders, rdapIp, hostingCompany);

        return {
          dns_profile: {
            hostname,
            domain,
            a_records: aRecords.slice(0, 12),
            aaaa_records: aaaaRecords.slice(0, 12),
            cname_records: cnameRecords.slice(0, 12),
            ns_records: nsRecords.slice(0, 12),
            mx_records: mxRecords.slice(0, 12),
            txt_records: txtRecords.slice(0, 20),
            email_provider: emailProvider,
          },
          infrastructure: {
            registrar: rdapDomain?.registrar || null,
            domain_expires_at: rdapDomain?.expires_at || null,
            server_header: serverHeader,
            powered_by: poweredBy,
            ip_addresses: [...aRecords, ...aaaaRecords].slice(0, 12),
            hosting_company: hostingCompany,
            rdap_domain: rdapDomain || null,
            rdap_ip: rdapIp || null,
            server_hardware_hints: serverHardwareHints,
          },
          vendors,
        };
      } catch {
        return {
          dns_profile: null,
          infrastructure: null,
          vendors: detectThirdPartyVendors(html),
        };
      }
    }

    function decodeHtmlEntitiesMinimal(text) {
      return String(text || "")
        .replace(/&amp;/g, "&")
        .replace(/&quot;/g, '"')
        .replace(/&#39;/g, "'")
        .replace(/&lt;/g, "<")
        .replace(/&gt;/g, ">");
    }

    async function extractCssTexts(html, baseUrl) {
      const hrefs = [];
      const linkRe = /<link[^>]+rel=["'][^"']*stylesheet[^"']*["'][^>]*href=["']([^"']+)["']/gi;
      let m;
      while ((m = linkRe.exec(html)) && hrefs.length < 5) {
        hrefs.push(m[1]);
      }

      const cssTexts = [];
      const inlineRe = /<style[^>]*>([\s\S]*?)<\/style>/gi;
      while ((m = inlineRe.exec(html)) && cssTexts.length < 5) {
        cssTexts.push(m[1]);
      }

      const base = toHttpsUrl(baseUrl);
      if (!base) return cssTexts;

      for (const href of hrefs.slice(0, 3)) {
        try {
          const url = new URL(href, base).toString();
          const r = await fetch(url, { headers: { "User-Agent": "Mozilla/5.0 (compatible; SiteInspector/1.0)" } });
          if (!r.ok) continue;
          const contentType = String(r.headers.get("content-type") || "");
          if (!contentType.includes("text/css")) continue;
          cssTexts.push(await r.text());
        } catch {}
      }

      return cssTexts;
    }

    function extractDesignSignals(html, cssTexts = []) {
      const combined = [html, ...cssTexts].join("\n");

      const fontSet = new Set();
      const fontRe = /font-family\s*:\s*([^;}{]+);/gi;
      let fm;
      while ((fm = fontRe.exec(combined)) && fontSet.size < 20) {
        const raw = fm[1];
        for (const part of raw.split(",")) {
          const cleaned = part.replace(/['"]/g, "").trim().toLowerCase();
          if (!cleaned) continue;
          if (/(serif|sans-serif|monospace|system-ui|inherit|initial|unset)/.test(cleaned)) continue;
          fontSet.add(cleaned);
          if (fontSet.size >= 20) break;
        }
      }

      const colorCounts = new Map();
      const colorRe = /#(?:[0-9a-fA-F]{3,8})\b|rgba?\([^)]+\)/g;
      let cm;
      while ((cm = colorRe.exec(combined))) {
        const c = String(cm[0]).toLowerCase();
        colorCounts.set(c, (colorCounts.get(c) || 0) + 1);
      }
      const colors = Array.from(colorCounts.entries())
        .sort((a, b) => b[1] - a[1])
        .slice(0, 8)
        .map(([c]) => c);

      const layoutHints = [];
      const lower = combined.toLowerCase();
      if (/display\s*:\s*grid/.test(lower)) layoutHints.push("grid");
      if (/display\s*:\s*flex/.test(lower)) layoutHints.push("flex");
      if (/<header|class=["'][^"']*hero/.test(lower)) layoutHints.push("hero_section");
      if (/<nav|class=["'][^"']*nav/.test(lower)) layoutHints.push("nav_menu");
      if (/<section/g.test(lower)) layoutHints.push("multi_section");
      if (/<form/g.test(lower)) layoutHints.push("contact_form");
      if (/gallery|portfolio/.test(lower)) layoutHints.push("gallery");

      return {
        fonts: Array.from(fontSet).slice(0, 6),
        colors,
        layout_hints: Array.from(new Set(layoutHints)).slice(0, 6),
      };
    }

    async function runScan(targetUrl, options = {}) {
      const deepIntelligence = options?.deepIntelligence !== false;
      const includeLinkAudit = options?.includeLinkAudit !== false;
      const r = await fetch(targetUrl, {
        headers: { "User-Agent": "Mozilla/5.0 (compatible; SiteInspector/1.0)" },
      });
      const final_url = r.url || targetUrl;
      const html = await r.text();
      const basics = extractBasics(html);
      const cssTexts = await extractCssTexts(html, final_url);
      const design_signals = extractDesignSignals(html, cssTexts);
      let dns_profile = null;
      let infrastructure = null;
      let vendors = detectThirdPartyVendors(html);
      let link_audit = { checked_count: 0, broken_count: 0, broken_paths: [] };
      if (deepIntelligence) {
        const intel = await buildDnsAndInfraProfile(final_url, r.headers, html);
        dns_profile = intel?.dns_profile || null;
        infrastructure = intel?.infrastructure || null;
        vendors = intel?.vendors || vendors;
      }
      if (includeLinkAudit) {
        link_audit = await auditBrokenInternalLinks(final_url, html);
      }
      return { final_url, ...basics, design_signals, dns_profile, infrastructure, vendors, link_audit };
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

    async function searchWithOpenAI(query, limit = 3) {
      if (!env.OPENAI_API_KEY) return null;

      try {
        const r = await fetch("https://api.openai.com/v1/responses", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            authorization: `Bearer ${env.OPENAI_API_KEY}`,
          },
          body: JSON.stringify({
            model: "gpt-4.1-mini",
            tools: [{ type: "web_search_preview" }],
            input:
              `Find top ${limit} business websites for this market query: ${query}\n` +
              `Return strict JSON array only with objects: [{"title":"","url":"","snippet":""}]`,
          }),
        });

        if (!r.ok) return null;
        const data = await r.json();
        const text =
          data?.output_text ||
          data?.output?.map((o) => o?.content?.map((c) => c?.text || "").join("\n") || "").join("\n") ||
          "";

        const arr = extractJsonArrayFromText(text);
        if (!arr) return null;
        return arr
          .map((x) => ({
            title: String(x?.title || "").slice(0, 180),
            url: toHttpsUrl(x?.url),
            snippet: String(x?.snippet || "").slice(0, 300),
          }))
          .filter((x) => x.url)
          .slice(0, limit);
      } catch {
        return null;
      }
    }

    async function searchWithDuckDuckGo(query, limit = 3) {
      const u = new URL("https://duckduckgo.com/html/");
      u.searchParams.set("q", query);

      const r = await fetch(u.toString(), {
        headers: { "User-Agent": "Mozilla/5.0 (compatible; SiteInspector/1.0)" },
      });
      if (!r.ok) return [];

      const html = await r.text();
      const results = [];
      const linkRe = /<a[^>]+class="result__a"[^>]+href="([^"]+)"[^>]*>([\s\S]*?)<\/a>/gi;
      let m;
      while ((m = linkRe.exec(html)) && results.length < limit) {
        let href = m[1];
        let title = String(m[2] || "").replace(/<[^>]+>/g, "").trim();
        if (!title) title = "Website";

        try {
          const parsed = new URL(href, "https://duckduckgo.com");
          const uddg = parsed.searchParams.get("uddg");
          href = uddg ? decodeURIComponent(uddg) : parsed.toString();
        } catch {}

        const urlNorm = toHttpsUrl(href);
        if (!urlNorm) continue;
        results.push({ title: title.slice(0, 180), url: urlNorm, snippet: "" });
      }

      return results;
    }

    function isAggregatorHost(hostname) {
      const h = String(hostname || "").toLowerCase();
      return (
        h.endsWith("yelp.com") ||
        h.endsWith("tripadvisor.com") ||
        h.endsWith("yellowpages.com") ||
        h.endsWith("mapquest.com") ||
        h.endsWith("foursquare.com") ||
        h.includes("visit") ||
        h.includes("tourism") ||
        h.includes("chamber") ||
        h.endsWith(".gov")
      );
    }

    function isDirectoryLikePathname(pathname) {
      const p = String(pathname || "").toLowerCase();
      return (
        p.startsWith("/search") ||
        p.includes("/list") ||
        p.includes("/directory") ||
        p.includes("/biz") ||
        p.includes("/attractions") ||
        p.includes("/things-to-do") ||
        p.includes("/business-listing")
      );
    }

    function isUsableBusinessWebsite(rawUrl) {
      try {
        const u = new URL(toHttpsUrl(rawUrl));
        if (!/^https?:$/.test(u.protocol)) return false;
        if (isAggregatorHost(u.hostname)) return false;
        if (isDirectoryLikePathname(u.pathname) && u.searchParams.toString()) return false;
        return true;
      } catch {
        return false;
      }
    }

    function looksLikeDirectoryContent(url, title, h1) {
      const t = `${String(url || "")} ${String(title || "")} ${String(h1 || "")}`.toLowerCase();
      return (
        /\bdirectory\b/.test(t) ||
        /\battractions?\b/.test(t) ||
        /\bthings to do\b/.test(t) ||
        /\btravel guide\b/.test(t) ||
        /\bvisit\b/.test(t) ||
        /\bbusiness listing\b/.test(t)
      );
    }

    function canonicalizeUrl(rawUrl) {
      try {
        const u = new URL(toHttpsUrl(rawUrl));
        u.hash = "";
        const normalized = u.toString().replace(/\/$/, "");
        return normalized;
      } catch {
        return null;
      }
    }

    function tokenizeForIntent(text) {
      const stopWords = new Set([
        "the", "and", "for", "with", "from", "this", "that", "your", "you", "near", "around", "website",
        "websites", "site", "services", "service", "business", "company", "official"
      ]);
      return String(text || "")
        .toLowerCase()
        .replace(/[^a-z0-9\s-]/g, " ")
        .split(/\s+/)
        .map((x) => x.trim())
        .filter((x) => x.length >= 3 && !stopWords.has(x))
        .slice(0, 20);
    }

    function scoreIntentMatch(site, context) {
      const intentText = String(context?.intent_text || "").toLowerCase();
      const intentTokens = Array.isArray(context?.intent_tokens) ? context.intent_tokens : [];
      const businessTokens = Array.isArray(context?.business_tokens) ? context.business_tokens : [];
      const hay = [
        site?.title,
        site?.snippet,
        site?.url,
        site?.snapshot?.title,
        site?.snapshot?.h1,
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();

      let score = 0;
      for (const t of intentTokens) {
        if (hay.includes(t)) score += t.length >= 7 ? 2 : 1;
      }
      for (const t of businessTokens) {
        if (hay.includes(t)) score += 1;
      }

      if (/\b(directory|attractions?|things to do|travel guide|business listing)\b/.test(hay)) score -= 8;
      if (/\b(visit|tourism|chamber)\b/.test(hay)) score -= 5;

      const wantsGuide = /\b(guide|guiding|tour|lesson|instruction|teach)\b/.test(intentText);
      const wantsShop = /\b(shop|store|retail|gear|equipment|merch)\b/.test(intentText);
      if (wantsGuide && /\b(shop|store|retail|gear|equipment|merch)\b/.test(hay)) score -= 3;
      if (wantsShop && /\b(guide|guiding|tour|lesson|instruction)\b/.test(hay)) score -= 2;

      if (/\b(book|booking|reserve|services?)\b/.test(hay)) score += 1;
      return score;
    }

    function rankSitesByIntent(sites, business_type, intent_text) {
      const intentTokens = tokenizeForIntent(intent_text || "");
      const businessTokens = tokenizeForIntent(business_type || "");
      const ctx = {
        intent_text: intent_text || "",
        intent_tokens: intentTokens,
        business_tokens: businessTokens,
      };

      return (Array.isArray(sites) ? sites : [])
        .map((s) => ({ ...s, relevance_score: scoreIntentMatch(s, ctx) }))
        .sort((a, b) => (b.relevance_score || 0) - (a.relevance_score || 0));
    }

    async function rerankSitesWithOpenAI(candidates, business_type, location, intent_text, limit = 3) {
      if (!env.OPENAI_API_KEY) return null;
      const list = Array.isArray(candidates) ? candidates.slice(0, 8) : [];
      if (list.length < 2) return null;

      try {
        const compact = list.map((s, id) => ({
          id,
          title: s?.title || "",
          url: s?.url || "",
          snippet: s?.snippet || "",
          page_title: s?.snapshot?.title || "",
          h1: s?.snapshot?.h1 || "",
        }));

        const r = await fetch("https://api.openai.com/v1/responses", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            authorization: `Bearer ${env.OPENAI_API_KEY}`,
          },
          body: JSON.stringify({
            model: "gpt-4.1-mini",
            input:
              `Pick the best ${limit} websites for this onboarding context.\n` +
              `Business type: ${business_type}\n` +
              `Location: ${location || "unknown"}\n` +
              `Desired website intent: ${intent_text || "not provided"}\n` +
              `Candidates JSON:\n${JSON.stringify(compact)}\n` +
              "Return strict JSON array of candidate ids ordered best to worst, e.g. [2,0,1].",
          }),
        });
        if (!r.ok) return null;
        const data = await r.json();
        const output =
          data?.output_text ||
          data?.output?.map((o) => o?.content?.map((c) => c?.text || "").join("\n") || "").join("\n") ||
          "";
        const arr = extractJsonArrayFromText(output);
        if (!arr || !arr.length) return null;

        const ordered = [];
        const seen = new Set();
        for (const raw of arr) {
          const idx = Number(raw);
          if (!Number.isInteger(idx) || idx < 0 || idx >= list.length || seen.has(idx)) continue;
          seen.add(idx);
          ordered.push(list[idx]);
        }
        if (!ordered.length) return null;
        for (let i = 0; i < list.length; i += 1) {
          if (!seen.has(i)) ordered.push(list[i]);
        }
        return ordered;
      } catch {
        return null;
      }
    }

    async function extractWebsiteFromYelpBizPage(bizUrl) {
      try {
        const r = await fetch(bizUrl, {
          headers: { "User-Agent": "Mozilla/5.0 (compatible; SiteInspector/1.0)" },
        });
        if (!r.ok) return null;
        const html = await r.text();

        const redirRe = /href="([^"]*\/biz_redir\?[^"]*url=[^"&]+[^"]*)"/gi;
        let m;
        while ((m = redirRe.exec(html))) {
          const href = decodeHtmlEntitiesMinimal(m[1]);
          try {
            const u = new URL(href, "https://www.yelp.com");
            const raw = u.searchParams.get("url");
            const decoded = raw ? decodeURIComponent(raw) : null;
            const out = toHttpsUrl(decoded);
            if (out) return out;
          } catch {}
        }

        const websiteJson = html.match(/"website"\s*:\s*"([^"]+)"/i)?.[1];
        if (websiteJson) {
          const decoded = decodeHtmlEntitiesMinimal(websiteJson.replace(/\\\//g, "/"));
          const out = toHttpsUrl(decoded);
          if (out) return out;
        }
      } catch {}
      return null;
    }

    async function searchWithYelpBusinessSites(businessType, location, limit = 3) {
      const u = new URL("https://www.yelp.com/search");
      u.searchParams.set("find_desc", businessType || "local business");
      if (location) u.searchParams.set("find_loc", location);

      const r = await fetch(u.toString(), {
        headers: { "User-Agent": "Mozilla/5.0 (compatible; SiteInspector/1.0)" },
      });
      if (!r.ok) return [];
      const html = await r.text();

      const bizPaths = [];
      const bizRe = /href="(\/biz\/[^"?#]+)"/gi;
      let m;
      while ((m = bizRe.exec(html)) && bizPaths.length < 12) {
        const p = m[1];
        if (!p || p.includes("/biz_photos")) continue;
        bizPaths.push(p);
      }

      const uniqueBizPaths = Array.from(new Set(bizPaths)).slice(0, 8);
      const results = [];
      for (const path of uniqueBizPaths) {
        const bizUrl = `https://www.yelp.com${path}`;
        const website = await extractWebsiteFromYelpBizPage(bizUrl);
        if (!website || !isUsableBusinessWebsite(website)) continue;
        const title = decodeHtmlEntitiesMinimal(path.split("/").pop() || "business").replace(/-/g, " ");
        results.push({
          title: title.slice(0, 180),
          url: website,
          snippet: `Found via Yelp listing: ${bizUrl}`,
          yelp_url: bizUrl,
        });
        if (results.length >= limit) break;
      }

      return results;
    }

    async function persistMarketSearch(request_id, session_id, business_type, location, source, sites) {
      try {
        await env.DB.prepare(
          `INSERT OR REPLACE INTO market_search_results(
            request_id, session_id, business_type, location, source, results_json, created_at
          ) VALUES (?,?,?,?,?,?,?)`
        )
          .bind(
            request_id,
            session_id,
            business_type,
            location || null,
            source,
            JSON.stringify(sites || []),
            now()
          )
          .run();
      } catch {
        // If table does not exist yet, do not fail the request.
      }
    }

    function parseJsonField(text, fallback = []) {
      if (!text) return fallback;
      try {
        const parsed = JSON.parse(text);
        return Array.isArray(parsed) ? parsed : fallback;
      } catch {
        return fallback;
      }
    }

    // Health
    if (request.method === "GET" && url.pathname === "/") {
      return json({ ok: true, service: "Inspector Worker", time: new Date().toISOString() });
    }

    // POST /inspect
    // { session_id, url, request_id? }
    if (request.method === "POST" && url.pathname === "/inspect") {
      if (!consumeInspectorRateLimit(clientIp, "inspect", now(), 60 * 1000, 20)) {
        return json({ ok: false, error: "Too many inspect requests. Please wait and try again." }, 429);
      }
      let body;
      try { body = await request.json(); }
      catch { return json({ ok: false, error: "Invalid JSON" }, 400); }

      const session_id = String(body?.session_id || "").trim();
      const target = toHttpsUrl(body?.url);
      const request_id = String(body?.request_id || "").trim() || newId("scan");

      if (!session_id || !target) return json({ ok: false, error: "session_id and url required" }, 400);

      // mark request row (queued->running)
      await env.DB.prepare(
        "INSERT OR REPLACE INTO site_scan_requests(request_id,session_id,url,status,created_at,started_at) VALUES (?,?,?,?,?,?)"
      ).bind(request_id, session_id, target, "running", now(), now()).run();

      try {
        const res = await runScan(target);

        try {
          await env.DB.prepare(
            `INSERT OR REPLACE INTO site_scan_results(
              request_id, session_id, url, final_url, title, h1, meta_description,
              emails_json, phones_json, addresses_json, socials_json, platform_hint, schema_types_json,
              dns_json, infrastructure_json, vendors_json, link_audit_json, raw_size, created_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
          )
            .bind(
              request_id,
              session_id,
              target,
              res.final_url || null,
              res.title || null,
              res.h1 || null,
              res.meta_description || null,
              JSON.stringify(res.emails || []),
              JSON.stringify(res.phones || []),
              JSON.stringify(res.addresses || []),
              JSON.stringify(res.socials || []),
              res.platform_hint || null,
              JSON.stringify(res.schema_types || []),
              JSON.stringify(res.dns_profile || null),
              JSON.stringify(res.infrastructure || null),
              JSON.stringify(res.vendors || null),
              JSON.stringify(res.link_audit || null),
              res.raw_size || 0,
              now()
            )
            .run();
        } catch {
          // Backward compatibility for older schemas.
          await env.DB.prepare(
            `INSERT OR REPLACE INTO site_scan_results(
              request_id, session_id, url, final_url, title, h1, meta_description,
              emails_json, phones_json, socials_json, platform_hint, schema_types_json,
              raw_size, created_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
          )
            .bind(
              request_id,
              session_id,
              target,
              res.final_url || null,
              res.title || null,
              res.h1 || null,
              res.meta_description || null,
              JSON.stringify(res.emails || []),
              JSON.stringify(res.phones || []),
              JSON.stringify(res.socials || []),
              res.platform_hint || null,
              JSON.stringify(res.schema_types || []),
              res.raw_size || 0,
              now()
            )
            .run();
        }

        await env.DB.prepare(
          "UPDATE site_scan_requests SET status=?, finished_at=?, error=NULL WHERE request_id=?"
        ).bind("done", now(), request_id).run();

        return json({ ok: true, request_id, status: "done", result: res });
      } catch (e) {
        await env.DB.prepare(
          "UPDATE site_scan_requests SET status=?, finished_at=?, error=? WHERE request_id=?"
        ).bind("failed", now(), String(e?.message || e), request_id).run();

        return json({ ok: false, request_id, status: "failed", error: String(e?.message || e) }, 500);
      }
    }

    // POST /market/nearby
    // { session_id, business_type, location, intent_text?, exclude_urls?, limit? }
    if (request.method === "POST" && url.pathname === "/market/nearby") {
      if (!consumeInspectorRateLimit(clientIp, "market_nearby", now(), 60 * 1000, 30)) {
        return json({ ok: false, error: "Too many market searches. Please wait and try again." }, 429);
      }
      let body;
      try {
        body = await request.json();
      } catch {
        return json({ ok: false, error: "Invalid JSON" }, 400);
      }

      const session_id = String(body?.session_id || "").trim();
      const business_type = String(body?.business_type || "").trim() || "local business";
      const location = String(body?.location || "").trim();
      const intent_text = String(body?.intent_text || "").trim();
      const excludeUrls = Array.isArray(body?.exclude_urls) ? body.exclude_urls : [];
      const excludeSet = new Set(excludeUrls.map((u) => canonicalizeUrl(u)).filter(Boolean));
      const limitRaw = Number(body?.limit || 3);
      const limit = Number.isFinite(limitRaw) ? Math.min(Math.max(limitRaw, 1), 5) : 3;
      if (!session_id) return json({ ok: false, error: "session_id required" }, 400);

      const yelpDescriptor = intent_text || business_type;
      const query =
        (`top ${business_type} business websites` +
          (intent_text ? ` focused on ${intent_text}` : "") +
          (location ? ` near ${location}` : "")) +
        " -site:yelp.com -site:tripadvisor.com -site:yellowpages.com -site:visit*.com";
      const request_id = newId("market");

      let source = "duckduckgo";
      let sites = await searchWithYelpBusinessSites(yelpDescriptor, location, Math.max(limit * 2, 5));
      if (sites && sites.length) {
        source = "yelp_business_sites";
      } else {
        sites = await searchWithOpenAI(query, Math.max(limit * 2, 5));
        if (!sites || !sites.length) {
          sites = await searchWithDuckDuckGo(query, Math.max(limit * 2, 5));
        } else {
          source = "openai_web_search";
        }
      }

      const unique = [];
      const seen = new Set();
      for (const s of sites || []) {
        const u = toHttpsUrl(s?.url);
        const canon = canonicalizeUrl(u);
        if (!u || !canon || !isUsableBusinessWebsite(u) || seen.has(canon) || excludeSet.has(canon)) continue;
        seen.add(canon);
        unique.push({
          title: String(s?.title || "Website").slice(0, 180),
          url: u,
          snippet: String(s?.snippet || "").slice(0, 300),
          yelp_url: s?.yelp_url ? String(s.yelp_url).slice(0, 300) : null,
        });
      }

      // Pre-enrich candidate sites with basic scan/design signals for smarter follow-up questions.
      for (const item of unique.slice(0, 8)) {
        try {
          const scan = await runScan(item.url, { deepIntelligence: false, includeLinkAudit: false });
          if (looksLikeDirectoryContent(scan.final_url || item.url, scan.title, scan.h1)) {
            item.snapshot = null;
            item._exclude_reason = "directory_content";
            continue;
          }
          item.snapshot = {
            title: scan.title || null,
            h1: scan.h1 || null,
            platform_hint: scan.platform_hint || null,
            design_signals: scan.design_signals || { fonts: [], colors: [], layout_hints: [] },
          };
        } catch {
          item.snapshot = null;
        }
      }

      const filtered = unique.filter((x) => !x._exclude_reason);
      let ranked = rankSitesByIntent(filtered, business_type, intent_text);
      const aiRanked = await rerankSitesWithOpenAI(ranked, business_type, location, intent_text, limit);
      if (aiRanked && aiRanked.length) ranked = aiRanked;
      const finalSites = ranked.slice(0, limit);

      await persistMarketSearch(request_id, session_id, business_type, location, source, finalSites);
      return json({ ok: true, request_id, source, query, intent_text: intent_text || null, sites: finalSites });
    }

    // GET /inspect/status?session_id=...  (latest)
    if (request.method === "GET" && url.pathname === "/inspect/status") {
      if (!consumeInspectorRateLimit(clientIp, "inspect_status", now(), 60 * 1000, 120)) {
        return json({ ok: false, error: "Too many status checks. Please slow down." }, 429);
      }
      const session_id = (url.searchParams.get("session_id") || "").trim();
      if (!session_id) return json({ ok: false, error: "session_id required" }, 400);

      const row = await env.DB.prepare(
        "SELECT * FROM site_scan_requests WHERE session_id=? ORDER BY created_at DESC LIMIT 1"
      ).bind(session_id).first();

      if (!row) return json({ ok: true, status: "none" });

      let result = null;
      if (row.status === "done") {
        const raw = await env.DB.prepare(
          "SELECT * FROM site_scan_results WHERE request_id=?"
        ).bind(row.request_id).first();

        if (raw) {
          const parseObjectField = (text) => {
            if (!text) return null;
            try {
              const parsed = JSON.parse(text);
              return parsed && typeof parsed === "object" ? parsed : null;
            } catch {
              return null;
            }
          };
          result = {
            request_id: raw.request_id,
            session_id: raw.session_id,
            url: raw.url,
            final_url: raw.final_url,
            title: raw.title,
            h1: raw.h1,
            meta_description: raw.meta_description,
            emails: parseJsonField(raw.emails_json),
            phones: parseJsonField(raw.phones_json),
            addresses: parseJsonField(raw.addresses_json),
            socials: parseJsonField(raw.socials_json),
            platform_hint: raw.platform_hint,
            schema_types: parseJsonField(raw.schema_types_json),
            dns_profile: parseObjectField(raw.dns_json),
            infrastructure: parseObjectField(raw.infrastructure_json),
            vendors: parseObjectField(raw.vendors_json),
            link_audit: parseObjectField(raw.link_audit_json),
            raw_size: raw.raw_size,
            created_at: raw.created_at,
          };
        }
      }

      return json({ ok: true, request: row, result });
    }

    return json({ ok: false, error: "Not Found" }, 404);
  },
};
