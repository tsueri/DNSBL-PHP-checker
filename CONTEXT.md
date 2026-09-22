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

**Listed**:
A check outcome where the query name returns an A record — the IP is on that zone. No A record means not listed.
_Avoid_: blacklisted, blocked

**Resolver**:
The DNS server that answers the app's queries. A forced resolver is one set by configuration instead of the system default.
_Avoid_: nameserver, DNS server
