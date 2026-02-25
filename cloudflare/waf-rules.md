# Cloudflare WAF + Rate Limit Rules

Apply these in Cloudflare Dashboard for the zone that serves `sitebuilder1-03.pages.dev` and your Worker routes.

## Custom WAF Rules (Managed Challenge)

1. Challenge high-risk start floods
- Expression:
```
(http.request.uri.path eq "/q1/start" and http.request.method eq "POST" and not cf.client.bot)
```

2. Challenge direct API scraping without your Pages origin
- Expression:
```
(
  http.request.uri.path in {"/q1/start" "/q1/answer" "/q1/scan/start" "/q1/scan/status"}
  and not http.request.headers["origin"][0] contains "sitebuilder1-03.pages.dev"
)
```

3. Block obvious non-browser automation user agents
- Expression:
```
(
  lower(http.user_agent) contains "python-requests"
  or lower(http.user_agent) contains "curl/"
  or lower(http.user_agent) contains "wget"
  or lower(http.user_agent) contains "httpclient"
)
```

## Rate Limiting Rules

1. `/q1/start` POST: 12 req / 60s per IP, action: Managed Challenge
2. `/q1/answer` POST: 120 req / 60s per IP, action: Block or Challenge
3. `/q1/scan/start` POST: 20 req / 60s per IP, action: Block
4. `/market/nearby` POST: 30 req / 60s per IP, action: Block

Notes:
- The repo also enforces in-worker rate limits as a fallback.
- WAF/Rate Limiting at Cloudflare edge remains the primary control for multi-isolate/global consistency.
