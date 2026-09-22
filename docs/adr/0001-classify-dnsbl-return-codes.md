# 1. Classify DNSBL return codes instead of treating any A record as a listing

Date: 2026-09-22

## Status

Accepted

## Context

`check_dnsbl` treated any A record as "listed". Spamhaus answers errors in
`127.255.255.0/24` — notably `127.255.255.254` when the query comes from a
public/open resolver — and the app rendered those as LISTED. Results flipped
between listed and not listed depending on which resolver answered, and
resolvers that hijack NXDOMAIN made every check look listed.

The resolver seam also collapsed NXDOMAIN (not listed) and query failure into
the same empty result, and timeout detection guessed from wall-clock time
(`a_ms >= 3000`), so fast failures rendered as a green "not listed".

## Decision

- `DnsResolver::query` returns `['records' => list<string>, 'status' => 'ok'|'timeout'|'error']`;
  `ok` includes NXDOMAIN, so callers can tell "no record" from "no answer".
- `classify_dnsbl_response` interprets the A answer: `127.0.0.0/8` is a
  listing, `127.255.255.0/24` is an error, anything else is an unexpected
  answer (resolver hijacking).
- `check_dnsbl` derives `listed` and `error` from those two signals; wall-clock
  time is reported in `a_ms`/`txt_ms` but no longer drives classification.

## Consequences

- Spamhaus open-resolver/limit/typo codes report `unknown (DNSBL error code)`
  with the zone TXT when available, never LISTED.
- Failed or unreachable queries report `unknown`, never a green "not listed".
- Resolvers that suppress listings (e.g. Google Public DNS returns NXDOMAIN
  for listed Spamhaus test points) still produce false negatives; using a
  local resolver or DQS remains the only remedy.
- JSON consumers get new `summary.total_errors` and `summary.unknown_ips`
  counters; `summary.clean_ips` now lists only IPs whose checks all answered
  without a listing.
