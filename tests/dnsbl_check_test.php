<?php
declare(strict_types=1);

// Test harness for the resolver seam and the DNSBL check.
// Run: php tests/dnsbl_check_test.php

$bootstrapOutput = '';
ob_start();
require __DIR__ . '/../index.php';
$bootstrapOutput = ob_get_clean();

final class InMemoryResolver implements DnsResolver {
	/** @var array<string, array<int, list<string>>> */
	private array $answers = [];
	/** @var list<array{name: string, type: int}> */
	public array $calls = [];
	public int $aDelayMicros = 0;
	public string $status = 'ok';

	/** @param list<string> $values */
	public function set(string $name, int $type, array $values): void {
		$this->answers[$name][$type] = $values;
	}

	public function query(string $name, int $type): array {
		$this->calls[] = ['name' => $name, 'type' => $type];
		if ($type === DNS_A && $this->aDelayMicros > 0) {
			usleep($this->aDelayMicros);
		}
		return [
			'records' => $this->answers[$name][$type] ?? [],
			'status' => $type === DNS_A ? $this->status : 'ok',
		];
	}

	/** @return list<string> */
	public function queryNamesOfType(int $type): array {
		$names = [];
		foreach ($this->calls as $call) {
			if ($call['type'] === $type) $names[] = $call['name'];
		}
		return $names;
	}
}

final class InMemoryAnswerCache implements AnswerCache {
	/** @var array<string, array{records: list<string>, status: string}> */
	public array $store = [];
	/** @var list<array{key: string, ttl: int}> */
	public array $sets = [];

	public function get(string $key): ?array {
		return $this->store[$key] ?? null;
	}

	public function set(string $key, array $answer, int $ttl): void {
		$this->sets[] = ['key' => $key, 'ttl' => $ttl];
		$this->store[$key] = $answer;
	}
}

$GLOBALS['__checks'] = 0;
$GLOBALS['__failures'] = 0;

function assert_same(string $label, mixed $expected, mixed $actual): void {
	$GLOBALS['__checks']++;
	if ($expected === $actual) {
		echo "ok   - {$label}\n";
		return;
	}
	$GLOBALS['__failures']++;
	echo "FAIL - {$label}\n";
	echo '  expected: ' . var_export($expected, true) . "\n";
	echo '  actual:   ' . var_export($actual, true) . "\n";
}

// --- Bootstrap guard ---
assert_same('requiring index.php does not run the controller', '', $bootstrapOutput);

// --- Query names ---
assert_same('ipv4 query name', '4.3.2.1.zen.spamhaus.org', dnsbl_query_name('1.2.3.4', 'zen.spamhaus.org'));
assert_same(
	'ipv6 query name',
	'1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.zen.spamhaus.org',
	dnsbl_query_name('2001:db8::1', 'zen.spamhaus.org')
);
assert_same('non-ip has no query name', null, dnsbl_query_name('not-an-ip', 'zen.spamhaus.org'));

// --- Domain resolution goes through the resolver ---
$dns = new InMemoryResolver();
$dns->set('example.com', DNS_A, ['1.2.3.4', '1.2.3.4', '5.6.7.8']);
$dns->set('example.com', DNS_AAAA, ['2001:db8::1', '2001:db8::1']);
$resolved = resolve_domain_ips($dns, 'example.com');
assert_same('resolves ipv4 records', ['1.2.3.4', '5.6.7.8'], $resolved['ipv4']);
assert_same('resolves ipv6 records', ['2001:db8::1'], $resolved['ipv6']);
assert_same('queries A through the resolver', ['example.com'], $dns->queryNamesOfType(DNS_A));
assert_same('queries AAAA through the resolver', ['example.com'], $dns->queryNamesOfType(DNS_AAAA));

// --- Resolver factory honours the forced resolver ---
putenv('DNSBL_RESOLVER=127.0.0.1');
putenv('CACHE_TTL=0');
assert_same('forced resolver selects DigResolver', DigResolver::class, get_class(dns_resolver()));
putenv('DNSBL_RESOLVER');
assert_same('no forced resolver selects NativeResolver', NativeResolver::class, get_class(dns_resolver()));
putenv('CACHE_TTL');
putenv('CACHE_TTL=300');
assert_same('caching wraps the resolver when a ttl is set', CachedResolver::class, get_class(dns_resolver()));
putenv('CACHE_TTL');

// --- DNS timeout config ---
putenv('DNS_TIMEOUT_MS=12000');
assert_same('dns timeout is configurable', 12000, get_dns_timeout_ms());
putenv('DNS_TIMEOUT_MS=1');
assert_same('dns timeout is clamped to 100ms', 100, get_dns_timeout_ms());
putenv('DNS_TIMEOUT_MS=999999');
assert_same('dns timeout is capped at 30000ms', 30000, get_dns_timeout_ms());
putenv('DNS_TIMEOUT_MS');
assert_same('dns timeout defaults to 3000ms', 3000, get_dns_timeout_ms());

// --- Zone allowlist ---
putenv('DNSBL_ZONE_ALLOWLIST=zen.spamhaus.org, bl.spamcop.net');
$_GET['dnsbl'] = ['evil.example', 'zen.spamhaus.org'];
assert_same('zone allowlist keeps permitted custom zones', ['zen.spamhaus.org'], parse_dnsbls_from_get());
$_GET['dnsbl'] = ['evil.example'];
assert_same('zone allowlist falls back to defaults', get_default_dnsbls(), parse_dnsbls_from_get());
putenv('DNSBL_ZONE_ALLOWLIST');
$_GET['dnsbl'] = ['zen.spamhaus.org'];
assert_same('without an allowlist custom zones pass', ['zen.spamhaus.org'], parse_dnsbls_from_get());
unset($_GET['dnsbl']);

// --- Rate limit subject (IPv6 /64) ---
assert_same('ipv4 subject is the address', '1.2.3.4', rate_limit_subject('1.2.3.4'));
assert_same('ipv6 addresses in one /64 share a subject', rate_limit_subject('2001:db8::1'), rate_limit_subject('2001:db8::beef'));
assert_same('different ipv6 /64s get different subjects', false, rate_limit_subject('2001:db8:0:1::1') === rate_limit_subject('2001:db8::1'));
assert_same('ipv4-mapped ipv6 maps to the ipv4 subject', '1.2.3.4', rate_limit_subject('::ffff:1.2.3.4'));

// --- Checks through the seam ---
$dns = new InMemoryResolver();
$dns->set('4.3.2.1.zen.spamhaus.org', DNS_A, ['127.0.0.2']);
$dns->set('4.3.2.1.zen.spamhaus.org', DNS_TXT, ['Listed by Example', 'https://example.test']);
$check = check_dnsbl($dns, '1.2.3.4', 'zen.spamhaus.org');
assert_same('listed check is listed', true, $check['listed']);
assert_same('listed check response', '127.0.0.2', $check['response']);
assert_same('listed check has no error', null, $check['error']);
assert_same('listed check displays the query', '4.3.2.1.zen.spamhaus.org', $check['query']);
assert_same('txt records are joined', 'Listed by Example | https://example.test', $check['txt']);
assert_same('txt queried once when listed', ['4.3.2.1.zen.spamhaus.org'], $dns->queryNamesOfType(DNS_TXT));
assert_same('total_ms is a_ms + txt_ms', $check['a_ms'] + $check['txt_ms'], $check['total_ms']);

$dns = new InMemoryResolver();
$check = check_dnsbl($dns, '1.2.3.4', 'zen.spamhaus.org');
assert_same('unlisted check is not listed', false, $check['listed']);
assert_same('unlisted check has no error', null, $check['error']);
assert_same('unlisted check skips TXT', 0, count($dns->queryNamesOfType(DNS_TXT)));

$dns = new InMemoryResolver();
$dns->set('4.3.2.1.zen.spamhaus.org', DNS_A, ['127.0.0.2']);
$check = check_dnsbl($dns, '1.2.3.4', 'zen.spamhaus.org');
assert_same('listed without txt stays null', null, $check['txt']);
assert_same('listed without txt has no error', null, $check['error']);

$dns = new InMemoryResolver();
$check = check_dnsbl($dns, 'not-an-ip', 'zen.spamhaus.org');
assert_same('invalid ip reports bad_qname', 'bad_qname', $check['error']);
assert_same('invalid ip makes no query', [], $dns->calls);

$dns = new InMemoryResolver();
$dns->status = 'timeout';
$dns->aDelayMicros = 3_100_000;
$check = check_dnsbl($dns, '1.2.3.4', 'zen.spamhaus.org');
assert_same('slow unanswered check reports timeout', 'timeout', $check['error']);
assert_same('timeout explains itself in txt', 'No DNS answer (timeout or unreachable resolver)', $check['txt']);
assert_same('timed out check is not listed', false, $check['listed']);
assert_same('timed out check does not query TXT', 0, count($dns->queryNamesOfType(DNS_TXT)));

$dns = new InMemoryResolver();
$dns->status = 'error';
$check = check_dnsbl($dns, '1.2.3.4', 'zen.spamhaus.org');
assert_same('resolver failure reports dns_error', 'dns_error', $check['error']);
assert_same('resolver failure reports its own txt', 'DNS query failed', $check['txt']);
assert_same('failed check is not listed', false, $check['listed']);

// --- Answer cache ---
$inner = new InMemoryResolver();
$inner->set('4.3.2.1.zen.spamhaus.org', DNS_A, ['127.0.0.2']);
$cache = new InMemoryAnswerCache();
$dns = new CachedResolver($inner, $cache, 300);
$first = $dns->query('4.3.2.1.zen.spamhaus.org', DNS_A);
$second = $dns->query('4.3.2.1.zen.spamhaus.org', DNS_A);
assert_same('cached resolver returns the inner answer', ['records' => ['127.0.0.2'], 'status' => 'ok'], $first);
assert_same('cached resolver serves the second lookup from cache', $first, $second);
assert_same('cache hit avoids the inner query', 1, count($inner->queryNamesOfType(DNS_A)));
assert_same('ok answers are stored with the ttl', 300, $cache->sets[0]['ttl']);

$inner = new InMemoryResolver();
$inner->status = 'timeout';
$cache = new InMemoryAnswerCache();
$dns = new CachedResolver($inner, $cache, 300);
$dns->query('4.3.2.1.zen.spamhaus.org', DNS_A);
$dns->query('4.3.2.1.zen.spamhaus.org', DNS_A);
assert_same('resolver failures are not cached', 2, count($inner->queryNamesOfType(DNS_A)));
assert_same('resolver failures write nothing to cache', 0, count($cache->sets));

$inner = new InMemoryResolver();
$cache = new InMemoryAnswerCache();
$dns = new CachedResolver($inner, $cache, 300);
$dns->query('4.3.2.1.zen.spamhaus.org', DNS_TXT);
assert_same('TXT answers are not cached', 0, count($cache->sets));

$inner = new InMemoryResolver();
$cache = new InMemoryAnswerCache();
$dns = new CachedResolver($inner, $cache, 0);
$dns->query('4.3.2.1.zen.spamhaus.org', DNS_A);
assert_same('zero ttl disables caching', 0, count($cache->sets));

// --- Return-code classification ---
assert_same(
	'127.0.0.2 is a listing',
	['listed' => true, 'error' => null, 'message' => null],
	classify_dnsbl_response('127.0.0.2')
);
assert_same(
	'127.255.255.254 is a resolver error, not a listing',
	['listed' => false, 'error' => 'dnsbl_error', 'message' => 'DNSBL refuses queries from this resolver (public/open resolver?)'],
	classify_dnsbl_response('127.255.255.254')
);
assert_same(
	'127.255.255.252 reports the zone-name typo code',
	'DNSBL rejected the query name (zone name typo?)',
	classify_dnsbl_response('127.255.255.252')['message']
);
assert_same(
	'127.255.255.255 reports the query-limit code',
	'DNSBL query limit exceeded',
	classify_dnsbl_response('127.255.255.255')['message']
);
assert_same(
	'non-loopback answers are not listings',
	['listed' => false, 'error' => 'unexpected_response', 'message' => 'Unexpected DNSBL answer (resolver hijacking?)'],
	classify_dnsbl_response('93.184.216.34')
);
assert_same(
	'no answer is neither listed nor an error',
	['listed' => false, 'error' => null, 'message' => null],
	classify_dnsbl_response(null)
);

$dns = new InMemoryResolver();
$dns->set('4.3.2.1.zen.spamhaus.org', DNS_A, ['127.255.255.254']);
$dns->set('4.3.2.1.zen.spamhaus.org', DNS_TXT, ['Error: open resolver; https://check.spamhaus.org/returnc/pub/']);
$check = check_dnsbl($dns, '1.2.3.4', 'zen.spamhaus.org');
assert_same('spamhaus open-resolver code is not listed', false, $check['listed']);
assert_same('spamhaus open-resolver code keeps the response for display', '127.255.255.254', $check['response']);
assert_same('spamhaus open-resolver code reports dnsbl_error', 'dnsbl_error', $check['error']);
assert_same('error codes still surface the zone TXT', 'Error: open resolver; https://check.spamhaus.org/returnc/pub/', $check['txt']);

$dns = new InMemoryResolver();
$dns->set('4.3.2.1.zen.spamhaus.org', DNS_A, ['93.184.216.34']);
$check = check_dnsbl($dns, '1.2.3.4', 'zen.spamhaus.org');
assert_same('hijacked answer is not listed', false, $check['listed']);
assert_same('hijacked answer reports unexpected_response', 'unexpected_response', $check['error']);

// --- Result summary keeps unknown apart from clean ---
$results = [
	'1.2.3.4' => [
		'zone-a' => ['listed' => false, 'error' => 'timeout'],
		'zone-b' => ['listed' => false, 'error' => null],
	],
	'5.6.7.8' => [
		'zone-a' => ['listed' => true, 'error' => null],
		'zone-b' => ['listed' => false, 'error' => 'dnsbl_error'],
	],
	'9.9.9.9' => [
		'zone-a' => ['listed' => false, 'error' => null],
		'zone-b' => ['listed' => false, 'error' => null],
	],
];
$summary = build_results_summary($results, ['zone-a', 'zone-b']);
assert_same('summary counts error checks', 2, $summary['total_errors']);
assert_same('summary counts listings', 1, $summary['total_listed']);
assert_same('IP with an error and no listing is unknown', ['1.2.3.4'], $summary['unknown_ips']);
assert_same('only fully answered non-listed IPs are clean', ['9.9.9.9'], $summary['clean_ips']);

// --- Summary ---
echo "\n{$GLOBALS['__checks']} checks, {$GLOBALS['__failures']} failures\n";
exit($GLOBALS['__failures'] === 0 ? 0 : 1);
