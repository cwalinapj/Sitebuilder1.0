export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    const json = (obj, status = 200) =>
      new Response(JSON.stringify(obj, null, 2), {
        status,
        headers: { "content-type": "application/json" },
      });

    const now = () => Date.now();
    const newId = (p) => `${p}_${crypto.randomUUID()}`;

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
          }
        } catch {}
      }

      return {
        title,
        h1,
        meta_description,
        emails,
        phones,
        socials: Array.from(new Set(socials)).slice(0, 20),
        platform_hint,
        schema_types: Array.from(new Set(schema_types)).slice(0, 20),
        raw_size: html.length,
      };
    }

    async function runScan(targetUrl) {
      const r = await fetch(targetUrl, {
        headers: { "User-Agent": "Mozilla/5.0 (compatible; SiteInspector/1.0)" },
      });
      const final_url = r.url;
      const html = await r.text();
      const basics = extractBasics(html);
      return { final_url, ...basics };
    }

    // Health
    if (request.method === "GET" && url.pathname === "/") {
      return json({ ok: true, service: "Inspector Worker", time: new Date().toISOString() });
    }

    // POST /inspect
    // { session_id, url, request_id? }
    if (request.method === "POST" && url.pathname === "/inspect") {
      let body;
      try { body = await request.json(); }
      catch { return json({ ok: false, error: "Invalid JSON" }, 400); }

      const session_id = String(body?.session_id || "").trim();
      const target = String(body?.url || "").trim();
      const request_id = String(body?.request_id || "").trim() || newId("scan");

      if (!session_id || !target) return json({ ok: false, error: "session_id and url required" }, 400);

      // mark request row (queued->running)
      await env.DB.prepare(
        "INSERT OR REPLACE INTO site_scan_requests(request_id,session_id,url,status,created_at,started_at) VALUES (?,?,?,?,?,?)"
      ).bind(request_id, session_id, target, "running", now(), now()).run();

      try {
        const res = await runScan(target);

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

    // GET /inspect/status?session_id=...  (latest)
    if (request.method === "GET" && url.pathname === "/inspect/status") {
      const session_id = (url.searchParams.get("session_id") || "").trim();
      if (!session_id) return json({ ok: false, error: "session_id required" }, 400);

      const row = await env.DB.prepare(
        "SELECT * FROM site_scan_requests WHERE session_id=? ORDER BY created_at DESC LIMIT 1"
      ).bind(session_id).first();

      if (!row) return json({ ok: true, status: "none" });

      let result = null;
      if (row.status === "done") {
        result = await env.DB.prepare(
          "SELECT * FROM site_scan_results WHERE request_id=?"
        ).bind(row.request_id).first();
      }

      return json({ ok: true, request: row, result });
    }

    return json({ ok: false, error: "Not Found" }, 404);
  },
};
