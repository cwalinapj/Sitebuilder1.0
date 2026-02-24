export interface Env {
  DB: D1Database;
  USER_MEM: VectorizeIndex;
  GLOBAL_TRENDS: VectorizeIndex;
  DESIGN_CATALOG: VectorizeIndex;
  AI: any;
}

type DesignSampleType = "template" | "real_site";
type LicensePolicy = "internal_ok" | "demo_only" | "link_only";

interface DesignSample {
  id: string;
  type: DesignSampleType;
  url?: string;
  template_id?: string;
  tags?: string[];
  tech_fingerprint?: string;
  font_guess?: string;
  palette?: string[];
  screenshot?: string;
  license_policy: LicensePolicy;
}

function now() { return Date.now(); }
function id(prefix: string) { return `${prefix}_${crypto.randomUUID()}`; }

async function embed(env: Env, text: string): Promise<number[]> {
  // bge-base-en-v1.5 outputs 768 dims  [oai_citation:7‡Cloudflare Docs](https://developers.cloudflare.com/workers-ai/models/bge-base-en-v1.5/?utm_source=chatgpt.com)
  const res = await env.AI.run("@cf/baai/bge-base-en-v1.5", { text });
  return res.data[0];
}

async function insertMemory(index: VectorizeIndex, vec: number[], meta: Record<string, any>) {
  await index.insert([{
    id: meta.id,
    values: vec,
    metadata: meta,
  }]);
}

async function queryIndex(index: VectorizeIndex, vec: number[], topK: number, filter?: any) {
  // Vectorize query() usage  [oai_citation:8‡Cloudflare Docs](https://developers.cloudflare.com/vectorize/best-practices/query-vectors/?utm_source=chatgpt.com)
  return index.query(vec, { topK, filter });
}

const TRACKED_EVENT_TYPES = new Set([
  "like",
  "dislike",
  "font_pref",
  "palette_pref",
  "layout_pref",
  "upsell_shown",
  "upsell_accepted",
  "question_answer"
]);

function normalizeTags(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value
    .map((item) => `${item}`.trim().toLowerCase())
    .filter(Boolean);
}

function normalizeDesignSample(raw: any): DesignSample {
  const sample: DesignSample = {
    id: `${raw?.id ?? ""}`.trim(),
    type: raw?.type,
    license_policy: raw?.license_policy,
    url: raw?.url ? `${raw.url}`.trim() : undefined,
    template_id: raw?.template_id ? `${raw.template_id}`.trim() : undefined,
    tags: normalizeTags(raw?.tags),
    tech_fingerprint: raw?.tech_fingerprint ? `${raw.tech_fingerprint}`.trim() : undefined,
    font_guess: raw?.font_guess ? `${raw.font_guess}`.trim() : undefined,
    palette: normalizeTags(raw?.palette),
    screenshot: raw?.screenshot ? `${raw.screenshot}`.trim() : undefined
  };

  if (!sample.id) throw new Error("id is required");
  if (sample.type !== "template" && sample.type !== "real_site") throw new Error("type must be template or real_site");
  if (sample.license_policy !== "internal_ok" && sample.license_policy !== "demo_only" && sample.license_policy !== "link_only") {
    throw new Error("license_policy must be internal_ok, demo_only, or link_only");
  }
  if (sample.type === "real_site" && !sample.url) throw new Error("url is required for real_site");
  if (sample.type === "template" && !sample.template_id) throw new Error("template_id is required for template");

  return sample;
}

function designSampleText(sample: DesignSample): string {
  const pointer = sample.type === "real_site" ? `real site ${sample.url}` : `template ${sample.template_id}`;
  return [
    sample.id,
    pointer,
    `tags:${(sample.tags ?? []).join(",")}`,
    `font:${sample.font_guess ?? ""}`,
    `palette:${(sample.palette ?? []).join(",")}`,
    `tech:${sample.tech_fingerprint ?? ""}`,
    `license:${sample.license_policy}`
  ].join(" ");
}

function deriveStructuredTags(eventType: string, payload: Record<string, any>): string[] {
  if (Array.isArray(payload.structured_tags)) {
    return normalizeTags(payload.structured_tags);
  }

  if (eventType === "font_pref" && payload.choice) {
    return [`prefers_font_${`${payload.choice}`.toLowerCase()}`];
  }
  if (eventType === "palette_pref" && payload.choice) {
    return [`prefers_palette_${`${payload.choice}`.toLowerCase()}`];
  }
  if (eventType === "layout_pref" && payload.choice) {
    return [`prefers_layout_${`${payload.choice}`.toLowerCase()}`];
  }
  return normalizeTags(payload.tags);
}

function memorySentence(eventType: string, structuredTags: string[], payload: Record<string, any>): string {
  if (payload.memory_sentence) {
    return `${payload.memory_sentence}`.slice(0, 2000);
  }
  const likes = structuredTags.length ? `prefers: ${structuredTags.join(", ")}` : "no explicit preference tags";
  const context = payload.reason ? ` reason: ${payload.reason}` : "";
  return `User ${likes}; event: ${eventType}.${context}`.slice(0, 2000);
}

function pickDiverse(matches: any[], limit = 3) {
  const selected: any[] = [];
  const seenTypes = new Set<string>();
  const seenTags = new Set<string>();

  for (const match of matches) {
    if (selected.length >= limit) break;
    const meta = match.metadata ?? {};
    const tags = normalizeTags(meta.tags);
    const hasNewType = meta.type && !seenTypes.has(meta.type);
    const hasNewTag = tags.some((tag) => !seenTags.has(tag));
    if (selected.length < 2 || hasNewType || hasNewTag) {
      selected.push(match);
      if (meta.type) seenTypes.add(meta.type);
      for (const tag of tags) seenTags.add(tag);
    }
  }

  for (const match of matches) {
    if (selected.length >= limit) break;
    if (!selected.includes(match)) selected.push(match);
  }

  return selected.slice(0, limit);
}

function compareQuestion(candidates: any[]) {
  if (candidates.length < 2) {
    return "Do you prefer cleaner typography or richer color contrast next?";
  }
  const a = candidates[0].meta ?? candidates[0].metadata ?? {};
  const b = candidates[1].meta ?? candidates[1].metadata ?? {};
  if (a.font_guess && b.font_guess && a.font_guess !== b.font_guess) {
    return `Font preference: ${a.font_guess} vs ${b.font_guess}?`;
  }
  const pa = (a.palette ?? []).join(", ");
  const pb = (b.palette ?? []).join(", ");
  if (pa && pb && pa !== pb) {
    return `Palette preference: ${pa} vs ${pb}?`;
  }
  return "Do you prefer the cleaner option A or the bolder option B?";
}

function shouldOfferIsotope(userSignals: any[]): boolean {
  // Offer only after repeated portfolio/sort/filter signals.
  const hay = JSON.stringify(userSignals).toLowerCase();
  const matches = hay.match(/\b(portfolio|filter|isotope|sortable|masonry)\b/g) ?? [];
  return matches.length >= 2;
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);

    if (req.method === "POST" && url.pathname === "/design-sample") {
      try {
        const sample = normalizeDesignSample(await req.json());
        const vec = await embed(env, designSampleText(sample));
        await insertMemory(env.DESIGN_CATALOG, vec, sample);
        return Response.json({ ok: true, design_sample_id: sample.id });
      } catch (error: any) {
        return Response.json({ ok: false, error: error?.message ?? "Invalid design sample" }, { status: 400 });
      }
    }

    if (req.method === "POST" && url.pathname === "/event") {
      const body = await req.json();
      const user_id = body.user_id as string;
      const session_id = body.session_id as string | undefined;
      const event_type = body.event_type as string;
      const payload = body.payload ?? {};
      const structuredTags = deriveStructuredTags(event_type, payload);

      const event_id = id("evt");
      await env.DB.prepare(
        "INSERT INTO events(event_id,user_id,session_id,event_type,payload_json,created_at) VALUES (?,?,?,?,?,?)"
      ).bind(event_id, user_id, session_id ?? null, event_type, JSON.stringify(payload), now()).run();

      // Build a semantic “memory sentence”
      const memoryText = memorySentence(event_type, structuredTags, payload);
      const vec = await embed(env, memoryText);

      // per-user memory
      await insertMemory(env.USER_MEM, vec, {
        id: `${user_id}:${event_id}`,
        user_id,
        session_id: session_id ?? "",
        event_type,
        ts: now(),
        tags: structuredTags,
        business_type: body.business_type ?? payload.business_type ?? "",
        device: body.device ?? payload.device ?? ""
      });

      if (TRACKED_EVENT_TYPES.has(event_type)) {
        await insertMemory(env.GLOBAL_TRENDS, vec, {
          id: `trend:${event_id}`,
          event_type,
          tags: structuredTags,
          business_type: body.business_type ?? payload.business_type ?? "",
          device: body.device ?? payload.device ?? "",
          ts: now()
        });
      }

      return Response.json({ ok: true, event_id });
    }

    if (req.method === "POST" && url.pathname === "/recommend") {
      const body = await req.json();
      const user_id = body.user_id as string;
      const prompt = (body.prompt as string) ?? "";
      const filters = body.filters;

      // Query user semantic memories
      const qvec = await embed(env, prompt || `recommend next designs for user ${user_id}`);
      const userRes = await queryIndex(env.USER_MEM, qvec, 8, { user_id });
      const userSignals = (userRes.matches ?? []).map((m: any) => m.metadata);

      // Query global trends
      const trendRes = await queryIndex(env.GLOBAL_TRENDS, qvec, 5);
      const trendSignals = (trendRes.matches ?? []).map((m: any) => m.metadata);

      // Query design catalog (templates/variants already embedded)
      const designRes = await queryIndex(env.DESIGN_CATALOG, qvec, 12, filters);
      const diverse = pickDiverse(designRes.matches ?? [], 3);
      const candidates = diverse.map((m: any) => ({
        design_id: m.id,
        score: m.score,
        meta: m.metadata
      }));

      const offerPremiumIsotope = shouldOfferIsotope([...userSignals, ...trendSignals]);

      return Response.json({
        ok: true,
        next: candidates,
        questions: [
          "Which of these do you prefer and why?",
          compareQuestion(candidates)
        ],
        upsell: offerPremiumIsotope ? {
          sku: "premium_isotope",
          label: "Premium Filterable Portfolio (licensed add-on)",
          price_usd: 25
        } : null
      });
    }

    return new Response("Not Found", { status: 404 });
  }
};
