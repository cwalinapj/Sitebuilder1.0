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

## Cloudflare D1 setup

Migrations live in `migrations/*.sql` and are applied with Wrangler:

```bash
npx wrangler d1 create sitebuilder
# copy the printed database_id into wrangler.toml (database_id=...)
npx wrangler d1 migrations apply sitebuilder
```
