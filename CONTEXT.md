# DNSBL Checker

Checks whether an IP address or domain is listed by DNS blocklists.

## Language

**Lookup**:
One user request to check an input (IP address or domain) against a set of zones.
_Avoid_: query, scan

**Zone**:
A DNS blocklist identified by its zone name, e.g. `zen.spamhaus.org`.
_Avoid_: blocklist, blacklist

**Check**:
The evaluation of one IP address against one zone.
_Avoid_: query, test

**Query name**:
The name a check resolves: the IP reversed under the zone (`4.3.2.1.zen.spamhaus.org`), nibble-reversed with an `ip6.` label for IPv6.
_Avoid_: lookup name

**Return code**:
The A record a zone answers with. Listings are in `127.0.0.0/8`; Spamhaus uses `127.255.255.0/24` for errors (e.g. query via public/open resolver) that do not imply a listing.
_Avoid_: response

**Listed**:
A check outcome where the query name returns a listing return code — the IP is on that zone. NXDOMAIN means not listed, and error return codes are not listings.
_Avoid_: blacklisted, blocked

**Unknown**:
A check outcome where the resolver gave no answer (timeout/failure) or the zone returned an error return code. Neither listed nor not listed.
_Avoid_: error

**Resolver**:
The DNS server that answers the app's queries. A forced resolver is one set by configuration instead of the system default. Every query answers with records and a status (`ok`, `timeout`, `error`); `ok` includes NXDOMAIN.
_Avoid_: nameserver, DNS server
