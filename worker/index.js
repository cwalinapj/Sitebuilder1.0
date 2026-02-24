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

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method !== 'POST' || url.pathname !== '/events') {
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

export { storeSemanticMemory, updateTasteProfile, EVENT_COUNTER_COLUMNS };
