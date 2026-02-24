import { EVENT_TYPES } from '../src/eventsEmitter.js';

const EVENT_COUNTER_COLUMNS = {
  [EVENT_TYPES.DEMO_LIKE]: 'likes',
  [EVENT_TYPES.DEMO_DISLIKE]: 'dislikes',
  [EVENT_TYPES.PALETTE_CHANGE]: 'palette_changes',
  [EVENT_TYPES.FONT_CHANGE]: 'font_changes',
  [EVENT_TYPES.LAYOUT_CHANGE]: 'layout_changes',
  [EVENT_TYPES.TEMPLATE_CHOOSE]: 'templates_chosen',
  [EVENT_TYPES.BUILD_PUBLISH]: 'builds_published',
  [EVENT_TYPES.PORTFOLIO_FILTERABLE_VIEW]: 'portfolio_views'
};

async function storeSemanticMemory(db, { userId, type, payload, timestamp }) {
  await db
    .prepare(
      'INSERT INTO semantic_memory (user_id, event_type, payload, occurred_at) VALUES (?1, ?2, ?3, ?4)'
    )
    .bind(userId, type, JSON.stringify(payload ?? {}), timestamp)
    .run();
}

async function updateTasteProfile(db, { userId, type, timestamp }) {
  const counterColumn = EVENT_COUNTER_COLUMNS[type];
  if (!counterColumn) {
    return;
  }

  const seedValues = Object.values(EVENT_COUNTER_COLUMNS).map((column) =>
    column === counterColumn ? 1 : 0
  );

  await db
    .prepare(
      `INSERT INTO taste_profile (
          user_id,
          likes,
          dislikes,
          palette_changes,
          font_changes,
          layout_changes,
          templates_chosen,
          builds_published,
          portfolio_views,
          last_event_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
        ON CONFLICT(user_id) DO UPDATE SET
          likes = taste_profile.likes + excluded.likes,
          dislikes = taste_profile.dislikes + excluded.dislikes,
          palette_changes = taste_profile.palette_changes + excluded.palette_changes,
          font_changes = taste_profile.font_changes + excluded.font_changes,
          layout_changes = taste_profile.layout_changes + excluded.layout_changes,
          templates_chosen = taste_profile.templates_chosen + excluded.templates_chosen,
          builds_published = taste_profile.builds_published + excluded.builds_published,
          portfolio_views = taste_profile.portfolio_views + excluded.portfolio_views,
          last_event_at = excluded.last_event_at`
    )
    .bind(userId, ...seedValues, timestamp)
    .run();
}

async function getPremiumSku(db, sku) {
  return db
    .prepare(
      'SELECT sku, price_cents, patron_reward_cents, patron_cap_cents FROM premium_skus WHERE sku = ?1'
    )
    .bind(sku)
    .first();
}

async function getPatronRewardTotal(db, { patronUserId, sku }) {
  const row = await db
    .prepare(
      "SELECT COALESCE(SUM(delta_cents), 0) AS total_rewarded FROM credits_ledger WHERE user_id = ?1 AND reason = 'patron_reward' AND ref_id = ?2"
    )
    .bind(patronUserId, sku)
    .first();
  return Number(row?.total_rewarded || 0);
}

async function createPremiumPurchase(db, { userId, sku, patronUserId, createdAt }) {
  const premiumSku = await getPremiumSku(db, sku);
  if (!premiumSku) {
    throw new Error('Unknown premium sku');
  }

  const purchaseId = crypto.randomUUID();
  await db
    .prepare(
      'INSERT INTO purchases (purchase_id, user_id, sku, amount_usd_cents, status, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)'
    )
    .bind(purchaseId, userId, sku, premiumSku.price_cents, 'paid', createdAt)
    .run();

  let patronRewardCents = 0;
  if (patronUserId) {
    const totalRewarded = await getPatronRewardTotal(db, { patronUserId, sku });
    const rewardRemaining = Math.max(0, premiumSku.patron_cap_cents - totalRewarded);
    patronRewardCents = Math.min(premiumSku.patron_reward_cents, rewardRemaining);

    if (patronRewardCents > 0) {
      await db
        .prepare(
          'INSERT INTO credits_ledger (ledger_id, user_id, reason, delta_cents, ref_id, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)'
        )
        .bind(
          crypto.randomUUID(),
          patronUserId,
          'patron_reward',
          patronRewardCents,
          sku,
          createdAt
        )
        .run();
    }
  }

  return {
    purchaseId,
    amountCents: premiumSku.price_cents,
    patronRewardCents
  };
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method !== 'POST') {
      return new Response('Not found', { status: 404 });
    }

    if (url.pathname === '/purchase') {
      const body = await request.json();
      const userId = body.userId || 'anonymous';
      const sku = body.sku || 'premium_isotope';
      const patronUserId = body.patronUserId || null;
      const createdAt = Number(body.createdAt) || Date.now();

      try {
        const purchase = await createPremiumPurchase(env.DB, {
          userId,
          sku,
          patronUserId,
          createdAt
        });
        return new Response(JSON.stringify({ ok: true, ...purchase }), {
          status: 200,
          headers: { 'content-type': 'application/json' }
        });
      } catch (error) {
        return new Response(
          JSON.stringify({ ok: false, error: 'Failed to persist purchase', detail: error.message }),
          {
            status: 500,
            headers: { 'content-type': 'application/json' }
          }
        );
      }
    }

    if (url.pathname !== '/events') {
      return new Response('Not found', { status: 404 });
    }

    const body = await request.json();
    const event = {
      userId: body.userId || 'anonymous',
      type: body.type,
      payload: body.payload || {},
      timestamp: body.timestamp || new Date().toISOString()
    };

    if (!EVENT_COUNTER_COLUMNS[event.type]) {
      return new Response(JSON.stringify({ ok: false, error: 'Invalid event type' }), {
        status: 400,
        headers: { 'content-type': 'application/json' }
      });
    }

    try {
      await storeSemanticMemory(env.DB, event);
      await updateTasteProfile(env.DB, event);
    } catch (error) {
      return new Response(
        JSON.stringify({ ok: false, error: 'Failed to persist event', detail: error.message }),
        {
          status: 500,
          headers: { 'content-type': 'application/json' }
        }
      );
    }

    return new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { 'content-type': 'application/json' }
    });
  }
};

export {
  storeSemanticMemory,
  updateTasteProfile,
  EVENT_COUNTER_COLUMNS,
  getPremiumSku,
  getPatronRewardTotal,
  createPremiumPurchase
};
