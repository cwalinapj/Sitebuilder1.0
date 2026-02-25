# Sitebuilder1.0

## Overview

Static site builder that reads `business_profile.json`, auto-categorizes the business, and renders a deployable site into `/site`.

## Build

```bash
python3 src/build.py
```

Build guided demo preview pages from `session_state.json` candidates:

```bash
python3 src/build_preview.py
```

## Test

```bash
python3 -m unittest discover -s src/tests -t . -p 'test_*.py'
npm test
```

## Categories

`src/categorize.py` returns one of: `plumber`, `electrician`, `barber`, `restaurant`, `general`.

## Deploy

GitHub Actions workflow at `.github/workflows/pages.yml` builds `/site` and deploys to Cloudflare Pages when the required secrets are configured:

- `CLOUDFLARE_API_TOKEN`
- `CLOUDFLARE_ACCOUNT_ID`
- `CLOUDFLARE_PROJECT_NAME` (Cloudflare Pages project name)

## Vectorize index creation

Before first deploy, create the Vectorize indexes (768 dimensions, cosine metric):

```bash
npm run vectorize:create
```

Worker API supports:
- `POST /design-sample` to insert template or real-site `DesignSample` entries into the `DESIGN_CATALOG` Vectorize index.
- `POST /event` to persist preference events in D1 and semantic memory in `USER_MEM`/`GLOBAL_TRENDS`.
- `POST /recommend` to retrieve the next 2–3 diverse catalog candidates with drill-down questions and optional upsell metadata.
