# DNSBL PHP Checker

A single-file PHP app to check an IP address (IPv4/IPv6) or domain against common DNS blocklists (DNSBL). Includes a clean Bootstrap UI and a simple GET-based API.

## Features
- Validates IPv4, IPv6, or domain (IDN-aware when `intl` is available)
- Resolves domains to A (IPv4) and AAAA (IPv6) and checks each IP
- Queries common DNSBL zones; choose custom zones via `dnsbl[]`
- Optional Spamhaus DQS support via a key (redacted in output)
- Optional forced resolver (e.g., 127.0.0.1) to avoid public/open resolvers
- JSON API with `?format=json`
- Basic security headers and sane DNS timeouts
- Optional per-IP rate limiting (default: 10 requests/hour via APCu or file fallback)

## Quickstart
Requirements: PHP 8+ with DNS access from the host; outbound UDP/TCP 53 to your resolver.

```bash
php -S localhost:8000
# open http://localhost:8000
```

## Usage
- Web UI: open `/?lookup=8.8.8.8`
- GET API (JSON): `/?lookup=8.8.8.8&format=json`
- Choose DNSBLs:
  - UI checkboxes (defaults provided)
  - GET: `&dnsbl[]=zen.spamhaus.org&dnsbl[]=dnsbl.sorbs.net`

Example:
```bash
curl -s "http://localhost:8000/?lookup=google.com&dnsbl[]=zen.spamhaus.org&format=json" | jq
```

## Configuration
You can configure by environment variables or by creating a `config.php` from the provided template.

1) Copy the example and edit:
```bash
cp config.example.php config.php
$EDITOR config.php
```

Config keys (array returned by `config.php`):
- `DNSBL_ZONES`: Array of DNSBL zones to use by default (overrides built-ins). DQS mapping still applies to Spamhaus zones when `SPAMHAUS_DQS_KEY` is set.
- `ALLOW_CUSTOM_ZONES`: When `true`, users may override zones via `dnsbl[]` query. When `false`, the app uses only configured/default zones.
- `FORCE_DNSBL_ZONES`: When `true`, always ignore `dnsbl[]` query and use only configured/default zones (overrides `ALLOW_CUSTOM_ZONES`).
- `SPAMHAUS_DQS_KEY`: Spamhaus DQS key. When set, the app maps common Spamhaus zones to DQS (e.g., `zen.spamhaus.org` → `<key>.zen.dq.spamhaus.net`). The key is redacted in displayed queries.
- `DNSBL_RESOLVER`: Force all DNS queries through a specific resolver (e.g., `127.0.0.1`). Useful to ensure queries do not go through public/open resolvers.
- `RATE_LIMIT_IP_ALLOWLIST`: Optional array of IPs/CIDRs that bypass rate limiting (e.g., `["127.0.0.1", "::1", "10.0.0.0/8"]).
- `ADMIN_API_TOKEN`: Strong secret to enable admin endpoints (e.g., rate-limit reset). Leave empty to disable admin API.
- `ACCESS_ALLOW_ONLY_ALLOWLIST`: When `true`, only IPs/CIDRs in the allowlist can use the app; others get HTTP 403.

Environment variable equivalents:
- `DNSBL_ZONES` (comma-separated)
- `ALLOW_CUSTOM_ZONES` (true/false)
- `FORCE_DNSBL_ZONES` (true/false)
- `SPAMHAUS_DQS_KEY` or `SPAMHAUS_DQS`
- `DNSBL_RESOLVER` or `DNSBL_NAMESERVER`
- `RATE_LIMIT_ALLOWLIST` (comma-separated IPs/CIDRs)
- `ADMIN_API_TOKEN`
- `ACCESS_ALLOW_ONLY_ALLOWLIST` (true/false)

The app reads `config.php` first, then falls back to environment variables.

### Rate Limiting
Per-IP rate limiting is enabled by default: 10 requests per hour. It uses APCu when available; otherwise, it falls back to a lock file in the system temp directory.

Config keys:
- `RATE_LIMIT_ENABLED`: `true|false` (default `true`)
- `RATE_LIMIT_COUNT`: requests allowed per window (default `10`)
- `RATE_LIMIT_WINDOW`: window in seconds (default `3600`, min `5`, max `86400`)
- `RATE_LIMIT_IP_ALLOWLIST`: array of exact IPs or CIDRs to bypass the limiter

Proxy setups:
- If you run behind a reverse proxy and want to rate-limit by the original client IP, set:
  - `TRUST_PROXY: true`
  - `TRUSTED_PROXIES: ["<proxy-ip>", ...]`

When rate-limited, the app returns HTTP 429 with `Retry-After` and a minimal HTML or JSON body.

### Admin API (reset rate limit)
Enable by setting `ADMIN_API_TOKEN` in `config.php` or as an environment variable (min 12 characters). If unset, the admin API is disabled.

Reset the rate limit window for a specific IP (JSON only):

```bash
curl -s "http://localhost:8000/?admin=reset_rate_limit&ip=8.8.8.8&token=<ADMIN_API_TOKEN>" | jq
# alias:
curl -s "http://localhost:8000/?admin=reset_rl&ip=2001:4860:4860::8888&token=<ADMIN_API_TOKEN>" | jq
```

Response (example):

```json
{
  "ok": true,
  "ip": "8.8.8.8",
  "result": { "backend": "apcu", "removed": true, "keys": ["dnsblrl:...:ts","dnsblrl:...:ct"] }
}
```

## Spamhaus Notes
- Spamhaus blocks DNSBL queries over public/open resolvers. Use a closed local resolver (preferred) and/or DQS.
- DQS setup:
  - Get a key from Spamhaus DQS
  - Configure `SPAMHAUS_DQS_KEY` in `config.php` or as an env var
  - Query the app as usual; the mapping happens internally.

## Local Resolver (Recommended)
Use a local, closed recursive resolver (e.g., Unbound) so DNSBL queries originate from your server and not a public/open resolver. Point your OS (or `DNSBL_RESOLVER`) to the local resolver. Avoid public/open resolvers for DNSBL use.

## API Examples
```bash
# HTML
curl -s "http://localhost:8000/?lookup=8.8.8.8"

# JSON
curl -s "http://localhost:8000/?lookup=8.8.8.8&format=json" | jq

# Custom zones
curl -s "http://localhost:8000/?lookup=8.8.8.8&dnsbl[]=zen.spamhaus.org&dnsbl[]=dnsbl.sorbs.net&format=json" | jq
```

## Security & Limits
- Input validation for IPs/domains (IDN → ASCII).
- All HTML output is escaped.
- Security headers: CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy.
- Sane limits: `lookup` length capped; max 15 DNSBL zones per request.
- Timeouts: socket default ~3s; script time limit ~10s.

## Notes
- Some DNSBL providers (e.g., Barracuda) may require registration and will return NXDOMAIN/empty answers until allowed.
- Caching is not implemented; consider adding APCu or file cache for high traffic.
