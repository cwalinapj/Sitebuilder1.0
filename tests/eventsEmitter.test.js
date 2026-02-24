import assert from 'node:assert/strict';
import test from 'node:test';

import { EventsEmitter, EVENT_TYPES } from '../src/eventsEmitter.js';

test('events emitter posts like/dislike, builder, template, publish, and portfolio view events', async () => {
  const calls = [];
  const emitter = new EventsEmitter({
    workerApiUrl: 'https://example.workers.dev/events',
    fetchImpl: async (url, options) => {
      calls.push({ url, options });
      return { ok: true };
    }
  });

  await emitter.trackDemoPreference({ userId: 'u1', demoId: 'demo-a', liked: true });
  await emitter.trackDemoPreference({ userId: 'u1', demoId: 'demo-a', liked: false });
  await emitter.trackBuilderChange({ userId: 'u1', field: 'palette', value: 'midnight' });
  await emitter.trackBuilderChange({ userId: 'u1', field: 'font', value: 'inter' });
  await emitter.trackBuilderChange({ userId: 'u1', field: 'layout', value: 'grid' });
  await emitter.trackTemplateChosen({ userId: 'u1', templateId: 'template-pro' });
  await emitter.trackBuildPublished({ userId: 'u1', buildId: 'build-7' });
  await emitter.trackFilterablePortfolioViewed({ userId: 'u1' });

  const parsed = calls.map((call) => JSON.parse(call.options.body));
  assert.deepEqual(
    parsed.map((entry) => entry.type),
    [
      EVENT_TYPES.DEMO_LIKE,
      EVENT_TYPES.DEMO_DISLIKE,
      EVENT_TYPES.PALETTE_CHANGE,
      EVENT_TYPES.FONT_CHANGE,
      EVENT_TYPES.LAYOUT_CHANGE,
      EVENT_TYPES.TEMPLATE_CHOOSE,
      EVENT_TYPES.BUILD_PUBLISH,
      EVENT_TYPES.PORTFOLIO_FILTERABLE_VIEW
    ]
  );
});
