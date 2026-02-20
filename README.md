# DNSBL PHP Checker

A single-file PHP app to check an IP address (IPv4/IPv6) or domain against common DNS blocklists (DNSBL). Includes a clean Bootstrap UI and a simple GET-based API.

## Features
- Validates IPv4, IPv6, or domain (IDN-aware when `intl` is available)
- Resolves domains to A (IPv4) and AAAA (IPv6) and checks each IP
- Queries common DNSBL zones; choose custom zones via `dnsbl[]`
- Optional Spamhaus DQS support via a key (redacted in output)
- Optional forced resolver (e.g., 127.0.0.1) to avoid public/open resolvers
- JSON API with `?format=json`
- Parallel DNS (optional, via Amp) with per-op timeouts and one-shot retry
- Completeness guarantee: automatic fallback to sequential if parallel is incomplete
- JSON summary with totals and per-IP/per-zone breakdowns
- Basic security headers and sane DNS timeouts
- Optional per-IP rate limiting (default: 10 requests/hour via APCu or file fallback)
- Lightweight caching for A-record responses (APCu preferred, file fallback)

## Quickstart
Requirements: PHP 8+ with DNS access from the host; outbound UDP/TCP 53 to your resolver.

```bash
php -S localhost:8000
# open http://localhost:8000
```

Optional: enable faster parallel DNS with Amp (Composer):

```bash
composer require "amphp/amp:^3" "amphp/dns:^2" "amphp/sync:^2"
```

When Composer autoload is available and `PARALLEL_MODE=amp`, the app will use Amp for concurrent DNS lookups.

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
  - If you list `*.dq.spamhaus.net` zones without a key prefix (e.g., `dbl.dq.spamhaus.net`) the app will automatically prefix them with your key: `<key>.dbl.dq.spamhaus.net`.
- `DNSBL_RESOLVER`: Force all DNS queries through a specific resolver (e.g., `127.0.0.1`). Useful to ensure queries do not go through public/open resolvers.
- `PARALLEL_MODE`: `'amp'` to enable Amp-based parallel DNS, `'off'` for sequential (default `'off'`). Automatically disabled if `DNSBL_RESOLVER` is set.
- `PARALLEL_CONCURRENCY`: Max concurrent DNS tasks when in Amp mode (1–32, default `6`).
- `DNS_TIMEOUT_MS`: Per-DNS operation timeout in milliseconds (100–30000, default `5000`).
- `CACHE_TTL`: Seconds to cache A answers (default `300`). Cached empty string means “not listed”.
- `RATE_LIMIT_IP_ALLOWLIST`: Optional array of IPs/CIDRs that bypass rate limiting (e.g., `["127.0.0.1", "::1", "10.0.0.0/8"]).
- `ADMIN_API_TOKEN`: Strong secret to enable admin endpoints (e.g., rate-limit reset). Leave empty to disable admin API.
- `ACCESS_ALLOW_ONLY_ALLOWLIST`: When `true`, only IPs/CIDRs in the allowlist can use the app; others get HTTP 403.

Environment variable equivalents:
- `DNSBL_ZONES` (comma-separated)
- `ALLOW_CUSTOM_ZONES` (true/false)
- `FORCE_DNSBL_ZONES` (true/false)
- `SPAMHAUS_DQS_KEY` or `SPAMHAUS_DQS`
- `DNSBL_RESOLVER` or `DNSBL_NAMESERVER`
- `PARALLEL_MODE` (`amp`/`off`), `PARALLEL_CONCURRENCY`, `DNS_TIMEOUT_MS`, `CACHE_TTL`
- `RATE_LIMIT_ALLOWLIST` (comma-separated IPs/CIDRs)
- `ADMIN_API_TOKEN`
- `ACCESS_ALLOW_ONLY_ALLOWLIST` (true/false)

The app reads `config.php` first, then falls back to environment variables.

### Parallel Execution (Amp)
- When `PARALLEL_MODE=amp` and Composer autoload is available, DNS A/TXT lookups run concurrently with a semaphore-limited concurrency.
- Each A/TXT query has a per-operation timeout and a one-shot retry (two attempts total) to handle transient resolver hiccups.
- Completeness is guaranteed: if the parallel batch returns fewer results than expected, the app automatically reruns the full matrix sequentially and returns the complete results.
- If `DNSBL_RESOLVER` is configured, Amp mode is disabled to ensure all queries use your forced resolver.

Diagnostics (useful during setup):
- Response headers include `X-App-Build` (last app mtime), `X-Parallel-Mode` (`amp` or `off`), and `X-Parallel-Fallback` (`1` if a sequential fallback was performed).
- JSON includes `parallel: { mode, fallback }` and a `complete` flag with `expected_checks` and `actual_checks`.

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
  - If you configure `zen.spamhaus.org`, `pbl.spamhaus.org`, `sbl-xbl.spamhaus.org`, `sbl.spamhaus.org`, `xbl.spamhaus.org`, `dbl.spamhaus.org`, or `zrd.spamhaus.org`, they are automatically mapped to the DQS hostname with your key.

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

### API Response Schema (high level)
```jsonc
{
  "timestamp": "2026-02-20T00:00:00Z",
  "input": "8.8.8.8",
  "input_type": "ipv4|ipv6|domain",
  "zones": ["zen.spamhaus.org", "dnsbl.sorbs.net"],
  "errors": [],
  "resolved_ips": { "ipv4": ["8.8.8.8"], "ipv6": [] },
  "results": {
    "8.8.8.8": {
      "zen.spamhaus.org": { "listed": false, "response": null, "txt": null, "query": "...", "error": null },
      "dnsbl.sorbs.net": { "listed": false, "response": null, "txt": null, "query": "...", "error": null }
    }
  },
  "parallel": { "mode": "amp|off", "fallback": false },
  "summary": {
    "total_ips": 1,
    "total_zones": 2,
    "total_checks": 2,
    "total_listed": 0,
    "any_listed": false,
    "listed_ips": [],
    "clean_ips": ["8.8.8.8"],
    "listed_by_ip": {},
    "listed_by_zone": { "zen.spamhaus.org": {"count": 0, "ips": []}, "dnsbl.sorbs.net": {"count": 0, "ips": []} }
  },
  "complete": true,
  "expected_checks": 2,
  "actual_checks": 2
}
```

### Response Headers (selected)
- `X-App-Build`: ISO8601 timestamp of the current app build (based on file mtime)
- `X-Parallel-Mode`: `amp` or `off`
- `X-Parallel-Fallback`: `1` when parallel fell back to sequential to ensure completeness
- `Retry-After`: present on HTTP 429 responses

## Security & Limits
- Input validation for IPs/domains (IDN → ASCII).
- All HTML output is escaped.
- Security headers: CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy.
- Sane limits: `lookup` length capped; max 15 DNSBL zones per request.
- Timeouts: socket default ~5s; script time limit ~30s; per-DNS op timeout configurable via `DNS_TIMEOUT_MS`.
- Caching: A-record responses are cached for `CACHE_TTL` seconds (APCu preferred, file fallback). TXT is not cached.

## Notes
- Some DNSBL providers (e.g., Barracuda) may require registration and will return NXDOMAIN/empty answers until allowed.
- For best results, run with a local recursive resolver or DQS when using Spamhaus zones.

## Troubleshooting
- Verify the running build and execution path:
  ```bash
  curl -sD - -o /dev/null "http://localhost:8000/?lookup=8.8.8.8" | grep -i -E "x-app-build|x-parallel"
  ```
- If you see `X-Parallel-Fallback: 1` frequently, consider:
  - Increasing `DNS_TIMEOUT_MS` (e.g., 7000–10000)
  - Adjusting `PARALLEL_CONCURRENCY` to match your resolver capacity
  - Setting `PARALLEL_MODE=off` to compare sequential behavior
  - Configuring `DNSBL_RESOLVER` to a local closed resolver
- Rate limited? Use the admin reset endpoint after setting `ADMIN_API_TOKEN`:
  ```bash
  curl -s "http://localhost:8000/?admin=reset_rate_limit&ip=127.0.0.1&token=<ADMIN_API_TOKEN>" | jq
  ```
