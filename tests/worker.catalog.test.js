import assert from 'node:assert/strict';
import test from 'node:test';

import worker from '../src/worker.ts';

function createMockDb() {
  const statements = [];
  return {
    statements,
    prepare(sql) {
      return {
        bind(...params) {
          return {
            async run() {
              statements.push({ sql, params });
              return { success: true };
            }
          };
        }
      };
    }
  };
}

function createMockIndex({ matches = [] } = {}) {
  return {
    inserts: [],
    lastQuery: null,
    async insert(items) {
      this.inserts.push(...items);
    },
    async query(vec, options) {
      this.lastQuery = { vec, options };
      return { matches };
    }
  };
}

function createEnv({ userMatches = [], trendMatches = [], designMatches = [] } = {}) {
  const USER_MEM = createMockIndex({ matches: userMatches });
  const GLOBAL_TRENDS = createMockIndex({ matches: trendMatches });
  const DESIGN_CATALOG = createMockIndex({ matches: designMatches });
  return {
    DB: createMockDb(),
    USER_MEM,
    GLOBAL_TRENDS,
    DESIGN_CATALOG,
    AI: {
      async run() {
        return { data: [[0.1, 0.2, 0.3]] };
      }
    }
  };
}

test('worker upserts template design sample into catalog index', async () => {
  const env = createEnv();
  const req = new Request('https://worker.example/design-sample', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      id: 'sample-template-a',
      type: 'template',
      template_id: 'template-a',
      tags: ['modern', 'minimal'],
      font_guess: 'Inter',
      palette: ['#111111', '#ffffff'],
      screenshot: 'https://img.example/s1.png',
      license_policy: 'internal_ok'
    })
  });

  const response = await worker.fetch(req, env);
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.ok, true);
  assert.equal(env.DESIGN_CATALOG.inserts.length, 1);
  assert.equal(env.DESIGN_CATALOG.inserts[0].metadata.type, 'template');
  assert.equal(env.DESIGN_CATALOG.inserts[0].metadata.template_id, 'template-a');
});

test('worker rejects invalid real site sample without url', async () => {
  const env = createEnv();
  const req = new Request('https://worker.example/design-sample', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      id: 'sample-real-a',
      type: 'real_site',
      tags: ['warm'],
      license_policy: 'link_only'
    })
  });

  const response = await worker.fetch(req, env);
  const body = await response.json();
  assert.equal(response.status, 400);
  assert.equal(body.ok, false);
});

test('recommend returns drill-down questions, honors filters, and can trigger isotope upsell', async () => {
  const env = createEnv({
    userMatches: [{ metadata: { note: 'wants filterable portfolio' } }],
    trendMatches: [{ metadata: { note: 'sortable grid preferred' } }],
    designMatches: [
      { id: 'd1', score: 0.9, metadata: { type: 'template', tags: ['modern'], font_guess: 'Inter', palette: ['#111'] } },
      { id: 'd2', score: 0.8, metadata: { type: 'real_site', tags: ['warm'], font_guess: 'Lato', palette: ['#f90'] } },
      { id: 'd3', score: 0.7, metadata: { type: 'template', tags: ['bold'], font_guess: 'Poppins', palette: ['#09f'] } }
    ]
  });

  const req = new Request('https://worker.example/recommend', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      user_id: 'u-1',
      prompt: 'restaurant with gallery and booking CTA',
      filters: { tags: { $in: ['restaurant'] } }
    })
  });

  const response = await worker.fetch(req, env);
  const body = await response.json();

  assert.equal(response.status, 200);
  assert.equal(body.next.length, 3);
  assert.equal(body.questions[0], 'Which of these do you prefer and why?');
  assert.match(body.questions[1], /Font preference:/);
  assert.equal(env.DESIGN_CATALOG.lastQuery.options.filter.tags.$in[0], 'restaurant');
  assert.equal(body.upsell?.sku, 'premium_isotope');
});

test('event stores semantic memory with derived structured tags and updates global trends', async () => {
  const env = createEnv();
  const req = new Request('https://worker.example/event', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      user_id: 'u-22',
      event_type: 'font_pref',
      payload: { choice: 'sans_serif' },
      business_type: 'restaurant',
      device: 'mobile'
    })
  });

  const response = await worker.fetch(req, env);
  const body = await response.json();
  const userInsert = env.USER_MEM.inserts[0];
  const trendInsert = env.GLOBAL_TRENDS.inserts[0];

  assert.equal(response.status, 200);
  assert.equal(body.ok, true);
  assert.equal(env.DB.statements.length, 1);
  assert.match(env.DB.statements[0].sql, /INSERT INTO events/);
  assert.deepEqual(userInsert.metadata.tags, ['prefers_font_sans_serif']);
  assert.equal(userInsert.metadata.business_type, 'restaurant');
  assert.equal(trendInsert.metadata.event_type, 'font_pref');
});
