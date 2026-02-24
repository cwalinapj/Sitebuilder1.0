# Sitebuilder1.0
AI static site builder with AI agents

## Event emitter + Worker taste memory

This repository includes a minimal events emitter (`src/eventsEmitter.js`) that sends POST requests to a Worker API whenever a user:
- likes/dislikes a demo
- changes palette/font/layout
- chooses a template
- publishes a build
- views filterable portfolio features

The Worker endpoint (`worker/index.js`) accepts `POST /events`, stores each event as a semantic memory row (`semantic_memory` table), and updates per-user counters in `taste_profile` (D1).
