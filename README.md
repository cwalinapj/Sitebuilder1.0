# Sitebuilder1.0

Static site builder that reads `business_profile.json`, auto-categorizes the business, and renders a deployable site into `/site`.

## Build

```bash
python3 src/build.py
```

## Test

```bash
python3 -m unittest discover -s src/tests -t . -p 'test_*.py'
```

## Categories

`src/categorize.py` returns one of: `plumber`, `electrician`, `barber`, `restaurant`, `general`.

## Deployment

GitHub Actions workflow at `.github/workflows/pages.yml` builds `/site` and deploys to Cloudflare Pages when the required secrets are configured.

### Deploy Worker

```bash
npx wrangler deploy
```

### Smoke test

```bash
curl -s -X POST "https://YOUR_WORKER_URL/event" \
  -H "content-type: application/json" \
  -d '{"user_id":"u1","session_id":"s1","event_type":"like","payload":{"tags":["portfolio","filterable_grid"]}}'

curl -s -X POST "https://YOUR_WORKER_URL/recommend" \
  -H "content-type: application/json" \
  -d '{"user_id":"u1","prompt":"show me more modern portfolio grids with filtering"}'
```
