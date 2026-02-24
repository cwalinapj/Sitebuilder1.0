import assert from 'node:assert/strict';
import test from 'node:test';

import worker, { EVENT_COUNTER_COLUMNS } from '../worker/index.js';

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

test('worker stores semantic memory and updates taste profile for tracked events', async () => {
  const db = createMockDb();
  const req = new Request('https://worker.example/events', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      userId: 'u55',
      type: 'builder.palette.change',
      payload: { value: 'forest' },
      timestamp: '2026-01-01T00:00:00.000Z'
    })
  });

  const response = await worker.fetch(req, { DB: db });

  assert.equal(response.status, 200);
  assert.equal(db.statements.length, 2);
  assert.match(db.statements[0].sql, /INSERT INTO semantic_memory/);
  assert.match(db.statements[1].sql, /INSERT INTO taste_profile/);
  assert.deepEqual(Object.keys(EVENT_COUNTER_COLUMNS).length, 8);
});

test('worker rejects unsupported event types', async () => {
  const db = createMockDb();
  const req = new Request('https://worker.example/events', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      userId: 'u55',
      type: 'unknown.event'
    })
  });

  const response = await worker.fetch(req, { DB: db });
  const body = await response.json();

  assert.equal(response.status, 400);
  assert.equal(body.error, 'Invalid event type');
  assert.equal(db.statements.length, 0);
});
