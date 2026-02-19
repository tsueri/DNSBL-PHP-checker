<?php
return [
    // DNSBL zones: override the built-in defaults by listing the zones here.
    // DQS mapping still applies to Spamhaus zones when SPAMHAUS_DQS_KEY is set.
    // Example:
    // 'DNSBL_ZONES' => [
    //     'zen.spamhaus.org',
    //     'b.barracudacentral.org',
    //     'dnsbl.sorbs.net',
    //     'bl.spamcop.net',
    // ],

    // Spamhaus DQS
    'SPAMHAUS_DQS_KEY' => '',

    // Force a specific resolver (e.g., local Unbound)
    'DNSBL_RESOLVER' => '', // e.g., '127.0.0.1'

    // Admin API token for maintenance actions (e.g., resetting rate limits).
    // Set a strong random string (min 12 chars). Leave empty to disable admin API.
    'ADMIN_API_TOKEN' => '',

    // Access control: when true, ONLY IPs/CIDRs in RATE_LIMIT_IP_ALLOWLIST
    // are allowed to use the app. Others receive HTTP 403.
    'ACCESS_ALLOW_ONLY_ALLOWLIST' => false,

    // Zones configuration
    // When set, this list replaces the built-in default zones.
    // 'DNSBL_ZONES' => [
    //     'zen.spamhaus.org',
    //     'b.barracudacentral.org',
    //     'dnsbl.sorbs.net',
    //     'bl.spamcop.net',
    // ],
    // Allow overriding zones via GET ?dnsbl[]=... (default: true)
    'ALLOW_CUSTOM_ZONES' => true,
    // Force using only the configured/default zones and ignore GET overrides
    'FORCE_DNSBL_ZONES' => false,

    // Rate limiting (defaults: enabled, 60s)
    'RATE_LIMIT_ENABLED' => true,
    // Allow N lookups per window per IP
    'RATE_LIMIT_COUNT' => 10,
    'RATE_LIMIT_WINDOW' => 3600, // seconds (e.g., 3600 = 1 hour)
    // Allowlisted IPs or CIDRs that bypass rate limiting entirely
    // Examples: '127.0.0.1', '::1', '10.0.0.0/8', '2001:db8::/32'
    'RATE_LIMIT_IP_ALLOWLIST' => [
        // '127.0.0.1',
        // '::1',
    ],

    // Only if you run behind a trusted reverse proxy
    'TRUST_PROXY' => false,
    'TRUSTED_PROXIES' => ['127.0.0.1', '::1'],
];
