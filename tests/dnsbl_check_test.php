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

	/** @param list<string> $values */
	public function set(string $name, int $type, array $values): void {
		$this->answers[$name][$type] = $values;
	}

	public function query(string $name, int $type): array {
		$this->calls[] = ['name' => $name, 'type' => $type];
		if ($type === DNS_A && $this->aDelayMicros > 0) {
			usleep($this->aDelayMicros);
		}
		return $this->answers[$name][$type] ?? [];
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
assert_same('forced resolver selects DigResolver', DigResolver::class, get_class(dns_resolver()));
putenv('DNSBL_RESOLVER');
assert_same('no forced resolver selects NativeResolver', NativeResolver::class, get_class(dns_resolver()));

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
$dns->aDelayMicros = 3_100_000;
$check = check_dnsbl($dns, '1.2.3.4', 'zen.spamhaus.org');
assert_same('slow unanswered check reports timeout', 'timeout', $check['error']);
assert_same('timeout explains itself in txt', 'Timeout after 3s', $check['txt']);
assert_same('timed out check is not listed', false, $check['listed']);

// --- Summary ---
echo "\n{$GLOBALS['__checks']} checks, {$GLOBALS['__failures']} failures\n";
exit($GLOBALS['__failures'] === 0 ? 0 : 1);
