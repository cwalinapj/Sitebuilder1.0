export interface Env {
  DB: D1Database;
  USER_MEM: VectorizeIndex;
  GLOBAL_TRENDS: VectorizeIndex;
  DESIGN_CATALOG: VectorizeIndex;
  AI: any;
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

function shouldOfferIsotope(userSignals: any[]): boolean {
  // Simple V1 heuristic: offer if user asked for filterable portfolio / sortable grid
  const hay = JSON.stringify(userSignals).toLowerCase();
  return hay.includes("portfolio") || hay.includes("filter") || hay.includes("isotope") || hay.includes("sortable");
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);

    if (req.method === "POST" && url.pathname === "/event") {
      const body = await req.json();
      const user_id = body.user_id as string;
      const session_id = body.session_id as string | undefined;
      const event_type = body.event_type as string;
      const payload = body.payload ?? {};

      const event_id = id("evt");
      await env.DB.prepare(
        "INSERT INTO events(event_id,user_id,session_id,event_type,payload_json,created_at) VALUES (?,?,?,?,?,?)"
      ).bind(event_id, user_id, session_id ?? null, event_type, JSON.stringify(payload), now()).run();

      // Build a semantic “memory sentence”
      const memoryText = `event:${event_type} user:${user_id} ${JSON.stringify(payload)}`.slice(0, 2000);
      const vec = await embed(env, memoryText);

      // per-user memory
      await insertMemory(env.USER_MEM, vec, {
        id: `${user_id}:${event_id}`,
        user_id,
        session_id: session_id ?? "",
        event_type,
        ts: now(),
        tags: payload.tags ?? []
      });

      return Response.json({ ok: true, event_id });
    }

    if (req.method === "POST" && url.pathname === "/recommend") {
      const body = await req.json();
      const user_id = body.user_id as string;
      const prompt = (body.prompt as string) ?? "";

      // Query user semantic memories
      const qvec = await embed(env, prompt || `recommend next designs for user ${user_id}`);
      const userRes = await queryIndex(env.USER_MEM, qvec, 8, { user_id });
      const userSignals = (userRes.matches ?? []).map((m: any) => m.metadata);

      // Query global trends
      const trendRes = await queryIndex(env.GLOBAL_TRENDS, qvec, 5);
      const trendSignals = (trendRes.matches ?? []).map((m: any) => m.metadata);

      // Query design catalog (templates/variants already embedded)
      const designRes = await queryIndex(env.DESIGN_CATALOG, qvec, 10);
      const candidates = (designRes.matches ?? []).slice(0, 3).map((m: any) => ({
        design_id: m.id,
        score: m.score,
        meta: m.metadata
      }));

      const offerPremiumIsotope = shouldOfferIsotope([...userSignals, ...trendSignals]);

      return Response.json({
        ok: true,
        next: candidates,
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
