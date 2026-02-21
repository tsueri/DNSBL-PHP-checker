<?php
declare(strict_types=1);
// DNSBL Checker - Single file app with UI + GET API
// Requirements: PHP 8+, DNS resolution available on host

// -------------------- Helpers --------------------
// HTML escape helper that safely accepts any type.
// Arrays are joined with spaces, objects are JSON-encoded, everything else is cast to string.
function h($s): string {
	if (is_array($s)) {
		$s = implode(' ', array_map('strval', $s));
	} elseif (is_object($s)) {
		$json = @json_encode($s, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
		$s = $json !== false ? $json : (string)$s;
	} elseif (!is_string($s)) {
		$s = (string)$s;
	}
	return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}
function detect_wants_json(): bool {
		if (isset($_GET['format']) && strtolower((string)$_GET['format']) === 'json') return true;
		$accept = $_SERVER['HTTP_ACCEPT'] ?? '';
		return stripos($accept, 'application/json') !== false;
}

// -------------------- App/config helpers and DNS utils --------------------

function load_app_config(): array {
	static $cfg = null;
	if ($cfg !== null) return $cfg;
	$cfg = [];
	$file = __DIR__ . '/config.php';
	if (is_file($file)) {
		$data = @include $file;
		if (is_array($data)) $cfg = $data;
	}
	return $cfg;
}

function csp_nonce(): string {
	static $nonce = null;
	if ($nonce !== null) return $nonce;
	$nonce = bin2hex(random_bytes(16));
	return $nonce;
}

function normalize_input(string $raw): string {
	$s = trim($raw);
	if (strlen($s) > 2 && $s[0] === '[' && substr($s, -1) === ']') {
		$s = substr($s, 1, -1);
	}
	return $s;
}

function is_valid_ip(string $input): bool {
	return filter_var($input, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_IPV6) !== false;
}

function to_ascii_domain(string $host): ?string {
	$host = rtrim($host, '.');
	if ($host === '' || strlen($host) > 253) return null;
	if (function_exists('idn_to_ascii')) {
		if (defined('INTL_IDNA_VARIANT_UTS46') && PHP_VERSION_ID < 80300) {
			$ascii = idn_to_ascii($host, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);
		} else {
			$ascii = idn_to_ascii($host, IDNA_DEFAULT);
		}
		if ($ascii === false) return null;
		return strtolower($ascii);
	}
	return strtolower($host);
}

function is_valid_domain(string $input): bool {
	$ascii = to_ascii_domain($input);
	if ($ascii === null) return false;
	return filter_var($ascii, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) !== false;
}

function get_configured_dnsbls(): array {
	$cfg = load_app_config();
	$candidates = [
		'DNSBL_ZONES', 'dnsbl_zones', 'DNSBLS', 'DNSBL_LIST', 'DEFAULT_DNSBLS', 'DEFAULT_DNSBL_ZONES'
	];
	$raw = null;
	foreach ($candidates as $k) {
		if (array_key_exists($k, $cfg)) { $raw = $cfg[$k]; break; }
	}
	if ($raw === null) return [];
	$items = [];
	if (is_string($raw)) {
		$items = array_map('trim', explode(',', $raw));
	} elseif (is_array($raw)) {
		$items = array_map(static function($v){ return trim((string)$v); }, $raw);
	} else {
		return [];
	}
	$out = [];
	foreach ($items as $z) {
		$z = strtolower(trim($z, ". "));
		if ($z === '' || strlen($z) > 253) continue;
		if (is_valid_domain($z)) $out[] = $z;
	}
	return array_values(array_unique($out));
}

function get_default_dnsbls(): array {
	$fromCfg = get_configured_dnsbls();
	if ($fromCfg) return $fromCfg;
	return [
		'zen.spamhaus.org',
		'pbl.spamhaus.org',
		'sbl-xbl.spamhaus.org',
		'b.barracudacentral.org',
		'bl.spamcop.net',
		'multi.surbl.org',
		'spamscamalot.com',
		'dnsbl.sorbs.net',
	];
}

function allow_custom_zones(): bool {
	$cfg = load_app_config();
	$force = $cfg['FORCE_DNSBL_ZONES'] ?? getenv('FORCE_DNSBL_ZONES') ?? null;
	if ($force !== null && filter_var((string)$force, FILTER_VALIDATE_BOOLEAN)) {
		return false;
	}
	$allow = $cfg['ALLOW_CUSTOM_ZONES'] ?? getenv('ALLOW_CUSTOM_ZONES') ?? '1';
	return filter_var((string)$allow, FILTER_VALIDATE_BOOLEAN);
}

function get_spamhaus_dqs_key(): ?string {
	$cfg = load_app_config();
	$key = $cfg['SPAMHAUS_DQS_KEY'] ?? $cfg['spamhaus_dqs_key'] ?? null;
	if (!$key) $key = getenv('SPAMHAUS_DQS_KEY');
	if (!$key) $key = getenv('SPAMHAUS_DQS');
	if (!$key) return null;
	$key = trim($key);
	if (!preg_match('/^[A-Za-z0-9_-]{6,128}$/', $key)) return null;
	return $key;
}

function map_zone_for_query(string $zone): string {
	$key = get_spamhaus_dqs_key();
	$z = strtolower(trim($zone, '.'));
	if ($key === null) return $z;
	if (str_ends_with($z, '.dq.spamhaus.net')) {
		if (stripos($z, strtolower($key) . '.') === 0) return $z;
		return $key . '.' . $z;
	}
	$map = [
		'zen.spamhaus.org' => 'zen.dq.spamhaus.net',
		'pbl.spamhaus.org' => 'pbl.dq.spamhaus.net',
		'sbl-xbl.spamhaus.org' => 'sbl-xbl.dq.spamhaus.net',
		'sbl.spamhaus.org' => 'sbl.dq.spamhaus.net',
		'xbl.spamhaus.org' => 'xbl.dq.spamhaus.net',
		'dbl.spamhaus.org' => 'dbl.dq.spamhaus.net',
		'zrd.spamhaus.org' => 'zrd.dq.spamhaus.net',
	];
	if (isset($map[$z])) return $key . '.' . $map[$z];
	return $z;
}

function redact_dqs_in_query(string $s): string {
	$key = get_spamhaus_dqs_key();
	if ($key === null || $key === '') return $s;
	return str_replace($key . '.', '****' . '.', $s);
}

function is_shell_exec_available(): bool {
	if (!function_exists('shell_exec')) return false;
	$disabled = (string)(ini_get('disable_functions') ?? '');
	if ($disabled !== '') {
		$list = array_map('trim', explode(',', $disabled));
		if (in_array('shell_exec', $list, true)) return false;
	}
	return true;
}

function parse_dnsbls_from_get(): array {
	$zones = [];
	if (allow_custom_zones() && isset($_GET['dnsbl'])) {
		$raw = $_GET['dnsbl'];
		if (is_array($raw)) {
			foreach ($raw as $z) {
				$z = strtolower(trim((string)$z));
				if ($z !== '' && strlen($z) <= 253 && is_valid_domain($z)) $zones[] = $z;
			}
		} else {
			$z = strtolower(trim((string)$raw));
			if ($z !== '' && strlen($z) <= 253 && is_valid_domain($z)) $zones[] = $z;
		}
	}
	if (!$zones) $zones = get_default_dnsbls();
	$zones = array_values(array_unique($zones));
	if (count($zones) > 15) $zones = array_slice($zones, 0, 15);
	return $zones;
}

function get_forced_resolver(): ?string {
	$cfg = load_app_config();
	$v = $cfg['DNSBL_RESOLVER'] ?? getenv('DNSBL_RESOLVER') ?? getenv('DNSBL_NAMESERVER') ?? null;
	if (!$v) return null;
	$v = trim((string)$v);
	if (filter_var($v, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_IPV6) || is_valid_domain($v)) {
		return $v;
	}
	return null;
}

function dnsbl_query_name(string $ip, string $zone): ?string {
	$zone = rtrim($zone, '.');
	if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
		$parts = array_reverse(explode('.', $ip));
		return implode('.', $parts) . '.' . $zone;
	}
	if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
		$bin = inet_pton($ip);
		if ($bin === false) return null;
		$hex = unpack('H*', $bin)[1];
		$nibbles = str_split(strrev($hex));
		return implode('.', $nibbles) . '.ip6.' . $zone;
	}
	return null;
}

function resolve_domain_ips(string $domain): array {
	$out = ['ipv4' => [], 'ipv6' => []];
	$ascii = to_ascii_domain($domain);
	if ($ascii === null) return $out;
	$a = @dns_get_record($ascii, DNS_A);
	if (is_array($a)) {
		foreach ($a as $rec) if (!empty($rec['ip'])) $out['ipv4'][] = $rec['ip'];
	}
	$aaaa = @dns_get_record($ascii, DNS_AAAA);
	if (is_array($aaaa)) {
		foreach ($aaaa as $rec) if (!empty($rec['ipv6'])) $out['ipv6'][] = $rec['ipv6'];
	}
	$out['ipv4'] = array_values(array_unique($out['ipv4']));
	$out['ipv6'] = array_values(array_unique($out['ipv6']));
	return $out;
}

function dig_lookup_a_txt(string $qname, string $server): array {
	if (!is_shell_exec_available()) return [null, null];
	if (!preg_match('/^[A-Za-z0-9:\\.-]+$/', $server)) return [null, null];
	$serverArg = '@' . $server;
	$qArg = escapeshellarg($qname);
	$cmdA = "dig +time=3 +tries=1 +retry=0 +short $serverArg $qArg A 2>/dev/null";
	$outA = @shell_exec($cmdA);
	$aIp = null;
	if (is_string($outA)) {
		foreach (preg_split('/\r?\n/', trim($outA)) as $line) {
			$line = trim($line, '" \t\r\n');
			if ($line === '') continue;
			if (filter_var($line, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_IPV6)) { $aIp = $line; break; }
		}
	}
	$cmdT = "dig +time=3 +tries=1 +retry=0 +short $serverArg $qArg TXT 2>/dev/null";
	$outT = @shell_exec($cmdT);
	$txt = null;
	if (is_string($outT) && trim($outT) !== '') {
		$parts = [];
		foreach (preg_split('/\r?\n/', trim($outT)) as $line) {
			$line = trim($line);
			$line = preg_replace('/^\"|\"$/', '', $line);
			$line = str_replace('" "', ' ', $line);
			$line = trim($line, '"');
			if ($line !== '') $parts[] = $line;
		}
		if ($parts) $txt = implode(' | ', $parts);
	}
	return [$aIp, $txt];
}

function check_dnsbl(string $ip, string $zoneEff): array {
	$qname = dnsbl_query_name($ip, $zoneEff);
	if ($qname === null) return ['listed'=>false,'response'=>null,'txt'=>null,'query'=>'','error'=>'bad_qname','a_ms'=>0,'txt_ms'=>0,'total_ms'=>0];
	$qDisp = redact_dqs_in_query($qname);
	$server = get_forced_resolver();
	$aStart = microtime(true);
	$aIp = null; $txt = null; $aMs = 0; $tMs = 0; $timeout = false;
	if ($server) {
		[$aIp, $txt] = dig_lookup_a_txt($qname, $server);
		$aMs = (int) round((microtime(true) - $aStart) * 1000);
		// dig_lookup returns both; we count total as a_ms when txt included
		if ($aIp !== null && $txt === null) {
			// fetch TXT separately if listed
			$ts = microtime(true);
			[$dummy, $txt2] = dig_lookup_a_txt($qname, $server);
			$tMs = (int) round((microtime(true) - $ts) * 1000);
			if ($txt2 !== null) $txt = $txt2;
		}
		// Timeout heuristic for forced resolver path: no data and near timeout budget
		if ($aIp === null && $txt === null && $aMs >= 3000) {
			$timeout = true;
		}
	} else {
		$recs = @dns_get_record($qname, DNS_A);
		if (is_array($recs) && $recs) {
			foreach ($recs as $rec) {
				if (!empty($rec['ip']) && filter_var($rec['ip'], FILTER_VALIDATE_IP)) { $aIp = $rec['ip']; break; }
			}
		}
		$aMs = (int) round((microtime(true) - $aStart) * 1000);
		if ($aIp === null && $aMs >= 3000) {
			$timeout = true;
		}
		if ($aIp !== null) {
			$ts = microtime(true);
			$txtRecs = @dns_get_record($qname, DNS_TXT);
			if (is_array($txtRecs)) {
				$parts = [];
				foreach ($txtRecs as $rec) {
					if (!empty($rec['txt'])) $parts[] = (string)$rec['txt'];
				}
				if ($parts) $txt = implode(' | ', $parts);
			}
			$tMs = (int) round((microtime(true) - $ts) * 1000);
		}
	}
	$total = $aMs + $tMs;
	$err = null;
	if ($timeout) {
		$err = 'timeout';
		if ($txt === null) { $txt = 'Timeout after 3s'; }
	}
	return [
		'listed' => $aIp !== null,
		'response' => $aIp,
		'txt' => $txt,
		'query' => $qDisp,
		'error' => $err,
		'a_ms' => $aMs,
		'txt_ms' => $tMs,
		'total_ms' => $total,
	];
}

function send_security_headers(bool $json): void {
	header('Referrer-Policy: no-referrer');
	header('X-Content-Type-Options: nosniff');
	header('X-Frame-Options: DENY');
	$mtime = @filemtime(__FILE__);
	if ($mtime) header('X-App-Build: '.gmdate('c', (int)$mtime));
	if ($json) return;
	$nonce = csp_nonce();
	$csp = [
		"default-src 'none'",
		"style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'",
		"script-src 'self' https://cdn.jsdelivr.net 'nonce-".$nonce."'",
		"img-src 'self' data:",
		"font-src 'self' https://cdn.jsdelivr.net",
		"connect-src 'self'",
		"base-uri 'none'",
		"form-action 'self'",
		"frame-ancestors 'none'",
	];
	header('Content-Security-Policy: '.implode('; ', $csp));
}

// -------------------- Results summary (for JSON API) --------------------
function build_results_summary(array $results, array $zones): array {
	$ips = array_keys($results);
	$totalIps = count($ips);
	$totalZones = count($zones);
	$totalChecks = $totalIps * $totalZones;
	$totalListed = 0;
	$listedIps = [];
	$cleanIps = [];
	$listedByIp = [];
	$listedByZone = [];
	foreach ($zones as $z) {
		$listedByZone[$z] = ['count' => 0, 'ips' => []];
	}

	foreach ($results as $ip => $zoneRes) {
		$ipZones = [];
		foreach ($zones as $z) {
			if (!isset($zoneRes[$z])) continue;
			$entry = $zoneRes[$z];
			if (!empty($entry['listed'])) {
				$totalListed++;
				$ipZones[] = $z;
				$listedByZone[$z]['count']++;
				$listedByZone[$z]['ips'][] = $ip;
			}
		}
		if ($ipZones) {
			$listedIps[] = $ip;
			$listedByIp[$ip] = ['count' => count($ipZones), 'zones' => $ipZones];
		} else {
			$cleanIps[] = $ip;
		}
	}

	foreach ($listedByZone as $z => $data) {
		if (!empty($data['ips'])) {
			$listedByZone[$z]['ips'] = array_values(array_unique($data['ips']));
		}
	}

	return [
		'total_ips' => $totalIps,
		'total_zones' => $totalZones,
		'total_checks' => $totalChecks,
		'total_listed' => $totalListed,
		'any_listed' => $totalListed > 0,
		'listed_ips' => array_values(array_unique($listedIps)),
		'clean_ips' => array_values($cleanIps),
		'listed_by_ip' => $listedByIp,
		'listed_by_zone' => $listedByZone,
	];
}

// Determine if results cover all IP x zone combinations
function results_completeness(array $results, array $zones, array $ipsByFam): array {
	$ips = array_merge($ipsByFam['ipv4'] ?? [], $ipsByFam['ipv6'] ?? []);
	$expected = count($ips) * count($zones);
	$actual = 0;
	foreach ($results as $ip => $zoneRes) {
		$actual += count($zoneRes);
	}
	return [
		'expected' => $expected,
		'actual' => $actual,
		'complete' => ($expected === $actual),
	];
}

// Backfill any missing IP×zone entries sequentially to ensure completeness
function fill_missing_results(array $results, array $zonesDisplay, array $ipsByFam): array {
	foreach (['ipv4','ipv6'] as $fam) {
		foreach (($ipsByFam[$fam] ?? []) as $ip) {
			foreach ($zonesDisplay as $zoneDisplay) {
				if (isset($results[$ip][$zoneDisplay])) continue;
				$zoneEff = map_zone_for_query($zoneDisplay);
				$results[$ip][$zoneDisplay] = check_dnsbl($ip, $zoneEff);
			}
		}
	}
	return $results;
}

// -------------------- Rate limiting (per client IP) --------------------
// Simple 1-request-per-window (default 60s). Uses APCu when available,
// otherwise a file lock in the system temp directory.

function get_client_ip(): string {
	$remote = $_SERVER['REMOTE_ADDR'] ?? '';
	$cfg = load_app_config();
	$trustProxy = filter_var($cfg['TRUST_PROXY'] ?? false, FILTER_VALIDATE_BOOLEAN);
	$trusted = $cfg['TRUSTED_PROXIES'] ?? [];
	if ($trustProxy && $remote && in_array($remote, (array)$trusted, true)) {
		if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
			$xff = (string)($_SERVER['HTTP_X_FORWARDED_FOR'] ?? '');
			$parts = array_map('trim', explode(',', $xff));
			$first = $parts[0] ?? '';
			if (filter_var($first, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_IPV6)) {
				return $first;
			}
		}
	}
	return is_string($remote) && $remote !== '' ? $remote : 'unknown';
}

function is_rate_limit_enabled(): bool {
	$cfg = load_app_config();
	$v = $cfg['RATE_LIMIT_ENABLED'] ?? getenv('RATE_LIMIT_ENABLED');
	if ($v === null || $v === false) return true; // default ON
	return filter_var((string)$v, FILTER_VALIDATE_BOOLEAN);
}

function get_rate_limit_window(): int {
	$cfg = load_app_config();
	$v = $cfg['RATE_LIMIT_WINDOW'] ?? getenv('RATE_LIMIT_WINDOW') ?? 3600;
	$w = (int)$v;
	if ($w < 5) $w = 5;
	if ($w > 86400) $w = 86400; // cap at 24h
	return $w;
}

function get_rate_limit_count(): int {
	$cfg = load_app_config();
	$v = $cfg['RATE_LIMIT_COUNT'] ?? getenv('RATE_LIMIT_COUNT') ?? 10;
	$c = (int)$v;
	if ($c < 1) $c = 1;
	if ($c > 1000) $c = 1000;
	return $c;
}

// -------------------- Access control (optional: only allow allowlist) --------------------
function is_access_only_allowlist(): bool {
	$cfg = load_app_config();
	$v = $cfg['ACCESS_ALLOW_ONLY_ALLOWLIST']
		?? $cfg['ACCESS_ONLY_ALLOWLIST']
		?? getenv('ACCESS_ALLOW_ONLY_ALLOWLIST')
		?? getenv('ACCESS_ONLY_ALLOWLIST');
	if ($v === null || $v === false) return false;
	return filter_var((string)$v, FILTER_VALIDATE_BOOLEAN);
}

function enforce_access_allowlist(bool $wantsJson): void {
	if (!is_access_only_allowlist()) return;
	$ip = get_client_ip();
	if (is_rate_limit_allowlisted($ip)) return;
	http_response_code(403);
	send_security_headers($wantsJson);
	if ($wantsJson) {
		header('Content-Type: application/json; charset=utf-8');
		echo json_encode([
			'error' => 'forbidden',
			'message' => 'Access restricted to allowlisted IPs',
			'client_ip' => $ip,
		], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
	} else {
		echo '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">';
		echo '<link href="css/bootstrap.min.css" rel="stylesheet">';
		echo '<title>Forbidden</title></head><body class="p-4"><main id="main-content" class="container">';
		echo '<div class="alert alert-danger">Access restricted to allowlisted IPs. Your IP: '.h($ip).'</div>';
		echo '</main></body></html>';
	}
	exit;
}

// -------------------- Admin helpers (rate limit reset) --------------------
function admin_api_token(): ?string {
	$cfg = load_app_config();
	$tok = $cfg['ADMIN_API_TOKEN'] ?? getenv('ADMIN_API_TOKEN') ?? null;
	if (!$tok) return null;
	$tok = trim((string)$tok);
	// Basic token sanity (at least 12 non-space chars)
	if (strlen($tok) < 12) return null;
	return $tok;
}

function admin_require_token(): void {
	$need = admin_api_token();
	if ($need === null) {
		http_response_code(403);
		header('Content-Type: application/json; charset=utf-8');
		echo json_encode(['error' => 'forbidden', 'message' => 'Admin API disabled'], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
		exit;
	}
	$got = isset($_GET['token']) ? (string)$_GET['token'] : '';
	if (!hash_equals($need, $got)) {
		http_response_code(403);
		header('Content-Type: application/json; charset=utf-8');
		echo json_encode(['error' => 'forbidden', 'message' => 'Invalid token'], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
		exit;
	}
}

function rate_limit_reset_for_ip(string $ip): array {
	$keyBase = 'dnsblrl:' . hash('sha256', $ip);
	$apcuOn = function_exists('apcu_delete') && filter_var(ini_get('apcu.enabled') ?: ini_get('apc.enabled') ?: '0', FILTER_VALIDATE_BOOLEAN);
	if ($apcuOn) {
		$tsKey = $keyBase . ':ts';
		$ctKey = $keyBase . ':ct';
		$a = @apcu_delete($tsKey);
		$b = @apcu_delete($ctKey);
		return ['backend' => 'apcu', 'removed' => ($a || $b), 'keys' => [$tsKey, $ctKey]];
	}
	$dir = rtrim(sys_get_temp_dir(), '/').'/dnsbl_php_checker_rl';
	if (is_link($dir)) {
    // Fail-open if path is a symlink
    return [true, 0];
}
if (!is_dir($dir)) {
    @mkdir($dir, 0700, true);
}
	$path = $dir.'/'.substr($keyBase, 7).'.dat';
	$ok = @unlink($path);
	return ['backend' => 'file', 'removed' => $ok, 'path' => $path];
}

/**
 * Returns [allowed(bool), retry_after(int seconds)]
 */
function rate_limit_check_and_consume(int $window): array {
	$ip = get_client_ip();
	$key = 'dnsblrl:' . hash('sha256', $ip);
	$now = time();
	$limit = get_rate_limit_count();

	$apcuOn = function_exists('apcu_fetch') && filter_var(ini_get('apcu.enabled') ?: ini_get('apc.enabled') ?: '0', FILTER_VALIDATE_BOOLEAN);

	if ($apcuOn) {
		$tsKey = $key . ':ts';
		$ctKey = $key . ':ct';
		$ts = apcu_fetch($tsKey, $okTs);
		$ct = apcu_fetch($ctKey, $okCt);
		if ($okTs && is_int($ts)) {
			$elapsed = $now - $ts;
			if ($elapsed < $window) {
				if ($okCt && is_int($ct) && $ct >= $limit) {
					$retry = max(1, $window - $elapsed);
					return [false, $retry, 0];
				}
				// increment count
				$newCt = (int)$ct + 1;
				@apcu_store($ctKey, $newCt, $window - $elapsed);
				return [true, 0, max(0, $limit - $newCt)];
			}
		}
		// New window
		@apcu_store($tsKey, $now, $window);
		@apcu_store($ctKey, 1, $window);
		return [true, 0, max(0, $limit - 1)];
	}

	$dir = rtrim(sys_get_temp_dir(), '/').'/dnsbl_php_checker_rl';
	if (!is_dir($dir)) {
		@mkdir($dir, 0700, true);
	}
	$path = $dir.'/'.substr($key, 7).'.dat';

	$fh = @fopen($path, 'c+');
	if (!$fh) {
		// Fail-open if filesystem is unavailable
		return [true, 0, max(0, $limit - 1)];
	}
	@flock($fh, LOCK_EX);
	$size = @filesize($path);
	$ts = null; $ct = 0;
	if ($size && $size > 0) {
		$data = @fread($fh, 64);
		if ($data !== false) {
			$data = trim($data);
			if ($data !== '') {
				if (strpos($data, ':') !== false) {
					[$tsStr, $ctStr] = array_pad(explode(':', $data, 2), 2, '0');
					$ts = (int)$tsStr; $ct = (int)$ctStr;
				} else {
					$ts = (int)$data; $ct = 1; // backward compatible
				}
			}
		}
	}
	if (is_int($ts) && $ts > 0) {
		$elapsed = $now - $ts;
		if ($elapsed < $window) {
			if ($ct >= $limit) {
				$retry = max(1, $window - $elapsed);
				@flock($fh, LOCK_UN);
				@fclose($fh);
				return [false, $retry, 0];
			}
			$ct++;
			@ftruncate($fh, 0);
			@rewind($fh);
			@fwrite($fh, (string)$ts . ':' . (string)$ct);
			@fflush($fh);
			@flock($fh, LOCK_UN);
			@fclose($fh);
			return [true, 0, max(0, $limit - $ct)];
		}
	}
	// New window
	@ftruncate($fh, 0);
	@rewind($fh);
	@fwrite($fh, (string)$now . ':1');
	@fflush($fh);
	@flock($fh, LOCK_UN);
	@fclose($fh);
	@chmod($path, 0600);
	return [true, 0, max(0, $limit - 1)];
}

function enforce_rate_limit(bool $wantsJson, bool $hasLookup): void {
	if (!$hasLookup || !is_rate_limit_enabled()) return;
	// Allowlist bypass
	$client = get_client_ip();
	if (is_rate_limit_allowlisted($client)) return;
	$window = get_rate_limit_window();
	[$allowed, $retry, $remaining] = rate_limit_check_and_consume($window);
	if ($allowed) return;

	http_response_code(429);
	header('Retry-After: '.$retry);
	send_security_headers($wantsJson);

	if ($wantsJson) {
		header('Content-Type: application/json; charset=utf-8');
		echo json_encode([
			'error' => 'rate_limited',
			'message' => 'Too many requests. Please try again later.',
			'retry_after' => $retry,
			'window_seconds' => $window,
			'limit' => get_rate_limit_count(),
			'remaining' => $remaining,
			'client_ip' => get_client_ip(),
		], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
		exit;
	}

	// Minimal HTML response
	echo '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">';
	echo '<link href="css/bootstrap.min.css" rel="stylesheet">';
	echo '<title>Too Many Requests</title></head><body class="p-4"><main id="main-content" class="container"><div class="alert alert-warning">';
	echo 'Too many requests from your IP. Try again in '.h((string)$retry).'s.';
	echo '</div><a class="btn btn-secondary" href="/">Back</a></main></body></html>';
	exit;
}

/**
 * Peek remaining seconds in the current window without consuming the token.
 * Returns 0 when not limited.
 */
function rate_limit_peek_status(int $window, int $limit): array {
	$ip = get_client_ip();
	if (is_rate_limit_allowlisted($ip)) return ['remaining' => $limit, 'resetIn' => 0];
	$key = 'dnsblrl:' . hash('sha256', $ip);
	$now = time();
	$apcuOn = function_exists('apcu_fetch') && filter_var(ini_get('apcu.enabled') ?: ini_get('apc.enabled') ?: '0', FILTER_VALIDATE_BOOLEAN);
	if ($apcuOn) {
		$ts = apcu_fetch($key . ':ts', $okTs);
		$ct = apcu_fetch($key . ':ct', $okCt);
		if ($okTs && is_int($ts)) {
			$elapsed = $now - $ts;
			if ($elapsed < $window) {
				$used = is_int($ct) ? max(0, (int)$ct) : 0;
				$remaining = max(0, $limit - $used);
				return ['remaining' => $remaining, 'resetIn' => max(1, $window - $elapsed)];
			}
		}
		return ['remaining' => $limit, 'resetIn' => $window];
	}
	$dir = rtrim(sys_get_temp_dir(), '/').'/dnsbl_php_checker_rl';
	$path = $dir.'/'.substr($key, 7).'.dat';
	if (!is_file($path)) return ['remaining' => $limit, 'resetIn' => $window];
	$fh = @fopen($path, 'r');
	if (!$fh) return ['remaining' => $limit, 'resetIn' => $window];
	@flock($fh, LOCK_SH);
	$data = @fread($fh, 64);
	@flock($fh, LOCK_UN);
	@fclose($fh);
	$ts = 0; $ct = 0;
	if (is_string($data)) {
		$data = trim($data);
		if ($data !== '') {
			if (strpos($data, ':') !== false) {
				[$tsStr, $ctStr] = array_pad(explode(':', $data, 2), 2, '0');
				$ts = (int)$tsStr; $ct = (int)$ctStr;
			} else {
				$ts = (int)$data; $ct = 1;
			}
		}
	}
	if ($ts > 0) {
		$elapsed = $now - $ts;
		if ($elapsed < $window) {
			$remaining = max(0, $limit - max(0, $ct));
			return ['remaining' => $remaining, 'resetIn' => max(1, $window - $elapsed)];
		}
	}
	return ['remaining' => $limit, 'resetIn' => $window];
}

// ------------- Allowlist for skipping rate limiting -------------
function get_rate_limit_allowlist(): array {
	$cfg = load_app_config();
	$list = $cfg['RATE_LIMIT_IP_ALLOWLIST']
		?? $cfg['RATE_LIMIT_ALLOWLIST']
		?? $cfg['ALLOWLIST_IPS']
		?? getenv('RATE_LIMIT_ALLOWLIST')
		?? [];
	if (is_string($list)) {
		$items = array_map('trim', explode(',', $list));
	} elseif (is_array($list)) {
		$items = array_map(static function($v){ return trim((string)$v); }, $list);
	} else {
		$items = [];
	}
	// Normalize and keep only plausible tokens (IP or CIDR)
	$out = [];
	foreach ($items as $tok) {
		if ($tok === '') continue;
		if (strpos($tok, '/') !== false) {
			// CIDR
			[$sub, $mask] = array_pad(explode('/', $tok, 2), 2, null);
			if ($sub && $mask !== null && filter_var($sub, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_IPV6) !== false) {
				$m = (int)$mask;
				$max = strpos($sub, ':') !== false ? 128 : 32;
				if ($m >= 0 && $m <= $max) $out[] = $sub . '/' . $m;
			}
		} else {
			if (filter_var($tok, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_IPV6) !== false) $out[] = $tok;
		}
	}
	return array_values(array_unique($out));
}

function cidr_match_ip(string $ip, string $cidr): bool {
	if (strpos($cidr, '/') === false) return false;
	[$subnet, $mask] = explode('/', $cidr, 2);
	$mask = (int)$mask;
	$ipBin = @inet_pton($ip);
	$subBin = @inet_pton($subnet);
	if ($ipBin === false || $subBin === false || strlen($ipBin) !== strlen($subBin)) return false;
	$len = strlen($ipBin);
	$fullBytes = intdiv($mask, 8);
	$remBits = $mask % 8;
	// Compare full bytes
	if ($fullBytes > 0 && strncmp($ipBin, $subBin, $fullBytes) !== 0) return false;
	if ($remBits === 0) return true;
	$maskByte = chr(0xFF << (8 - $remBits) & 0xFF);
	return ($ipBin[$fullBytes] & $maskByte) === ($subBin[$fullBytes] & $maskByte);
}

function is_rate_limit_allowlisted(string $ip): bool {
	$list = get_rate_limit_allowlist();
	if (!$list) return false;
	foreach ($list as $item) {
		if (strpos($item, '/') !== false) {
			if (cidr_match_ip($ip, $item)) return true;
		} else {
			if (strcasecmp($ip, $item) === 0) return true;
		}
	}
	return false;
}

// -------------------- Controller --------------------
// Reduce potential long-blocking DNS calls, but allow more time for first run
@ini_set('default_socket_timeout', '3');
@set_time_limit(30);

$wantsJson = detect_wants_json();

// Admin endpoint: reset rate limit for a given IP (requires ADMIN_API_TOKEN)
if (isset($_GET['admin']) && in_array($_GET['admin'], ['reset_rate_limit','reset_rl'], true)) {
	send_security_headers(true);
	header('Content-Type: application/json; charset=utf-8');
	admin_require_token();
	$ip = isset($_GET['ip']) ? normalize_input((string)$_GET['ip']) : '';
	if ($ip === '' || filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_IPV6) === false) {
		http_response_code(400);
		echo json_encode(['error' => 'bad_request', 'message' => 'Provide a valid IPv4/IPv6 in ip param'], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
		exit;
	}
	$res = rate_limit_reset_for_ip($ip);
	echo json_encode(['ok' => true, 'ip' => $ip, 'result' => $res], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
	exit;
}

$wantsJson = detect_wants_json();
// Enforce access control (if configured) after admin endpoint handling
enforce_access_allowlist($wantsJson);

$queryInput = isset($_GET['lookup']) ? normalize_input((string)$_GET['lookup']) : '';
if ($queryInput !== '' && strlen($queryInput) > 255) {
	// Guard against pathological inputs
	$queryInput = substr($queryInput, 0, 255);
}
$zones = parse_dnsbls_from_get();
$now = gmdate('c');
$errors = [];
$resolved = [
		'input_type' => null,
		'ips' => [ 'ipv4' => [], 'ipv6' => [] ],
];

// Enforce rate limit only when a lookup is attempted
enforce_rate_limit($wantsJson, $queryInput !== '');

if ($queryInput !== '') {
		if (is_valid_ip($queryInput)) {
				$resolved['input_type'] = strpos($queryInput, ':') !== false ? 'ipv6' : 'ipv4';
				if ($resolved['input_type'] === 'ipv4') $resolved['ips']['ipv4'][] = $queryInput;
				else $resolved['ips']['ipv6'][] = $queryInput;
		} elseif (is_valid_domain($queryInput)) {
				$resolved['input_type'] = 'domain';
				$ips = resolve_domain_ips($queryInput);
				$resolved['ips']['ipv4'] = $ips['ipv4'] ?? [];
				$resolved['ips']['ipv6'] = $ips['ipv6'] ?? [];
				if (!$resolved['ips']['ipv4'] && !$resolved['ips']['ipv6']) {
						$errors[] = 'The domain did not resolve to any A or AAAA records.';
				}
		} else {
				$errors[] = 'Please enter a valid IPv4, IPv6, or domain name.';
		}
}

$results = [];
if ($queryInput !== '' && !$errors) {
	foreach (['ipv4','ipv6'] as $fam) {
		foreach ($resolved['ips'][$fam] as $ip) {
			foreach ($zones as $zoneDisplay) {
				$zoneEff = map_zone_for_query($zoneDisplay);
				$results[$ip][$zoneDisplay] = check_dnsbl($ip, $zoneEff);
			}
		}
	}
}

// -------------------- API (JSON) --------------------
if ($queryInput !== '' && detect_wants_json()) {
    send_security_headers(true);
	header('Content-Type: application/json; charset=utf-8');
    $completeInfo = results_completeness($results, $zones, $resolved['ips']);
		echo json_encode([
				'timestamp' => $now,
				'input' => $queryInput,
				'input_type' => $resolved['input_type'],
		'zones' => $zones,
				'errors' => $errors,
				'resolved_ips' => $resolved['ips'],
		'results' => $results,
	'summary' => build_results_summary($results, $zones),
	'complete' => $completeInfo['complete'],
	'expected_checks' => $completeInfo['expected'],
	'actual_checks' => $completeInfo['actual'],
		], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
		exit;
}

// -------------------- UI (HTML) --------------------
send_security_headers(false);
?>
<!doctype html>
<html lang="en">
<head>
	<meta charset="utf-8">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<title>DNSBL Checker</title>
	<link href="css/bootstrap.min.css" rel="stylesheet">
	<style>
		body { padding-top: 2rem; }
		.result-listed { color: #b02a37; font-weight: 600; }
		.result-clean { color: #13795b; font-weight: 600; }
		.dnsbl-zone { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; }
		.ip-badge { font-family: ui-monospace, monospace; }
	</style>
	<meta name="robots" content="nofollow">
	<meta name="description" content="Check an IP address or domain against common DNS blocklists (DNSBLs) to see if it's listed for spam or abuse.">
</head>
<body>
<main id="main-content" class="container">
	<div class="row justify-content-center">
		<div class="col-lg-9">
			<h1 class="mb-3">DNSBL Checker</h1>
			<p class="text-muted">Check an IPv4/IPv6 or domain against common DNS blocklists.</p>

			<form method="get" class="card mb-4 shadow-sm">
				<div class="card-body">


					<?php 
						$rlEnabled = is_rate_limit_enabled();
						$rlWindow = get_rate_limit_window();
						$rlLimit = get_rate_limit_count();
						$rlStat = $rlEnabled ? rate_limit_peek_status($rlWindow, $rlLimit) : ['remaining'=>0,'resetIn'=>0];
						$clientIp = get_client_ip();
						$rlBypass = is_rate_limit_allowlisted($clientIp);
					?>
					<div class="mb-3 small text-muted">
						<strong>Rate limit:</strong>
						<?php if ($rlEnabled): ?>
							<?= h((string)$rlLimit) ?> request<?= $rlLimit===1?'':'s' ?> per <?= h((string)$rlWindow) ?>s per IP.
							<?php if ($rlBypass): ?>
								<span class="ms-2">for <span class="ip-badge"><?= h($clientIp) ?></span></span>
								<span class="ms-2 badge text-bg-success">Allowlisted IP</span>
							<?php else: ?>
								<span class="ms-2">Remaining: <span class="badge text-bg-secondary" id="rl-remaining-count"><?= h((string)$rlStat['remaining']) ?></span></span>
								<span id="rl-next" class="ms-2 <?= ($rlStat['remaining']>0?'text-muted':'text-danger') ?>">Resets in <span id="rl-reset-remaining" data-remaining="<?= h((string)$rlStat['resetIn']) ?>"><?= h((string)$rlStat['resetIn']) ?></span>s.</span>
								<span class="ms-2">for <span class="ip-badge"><?= h($clientIp) ?></span></span>
							<?php endif; ?>
						<?php else: ?>
							Disabled.
						<?php endif; ?>
					</div>
                    
					<div class="mb-3">
						<label for="lookup" class="form-label">IP address or Domain</label>
						<input type="text" class="form-control" id="lookup" name="lookup" placeholder="ip or domain" value="<?= h($queryInput) ?>" required>
						<div class="form-text">Domains will be resolved to A (IPv4) and AAAA (IPv6) and each IP will be checked.</div>
					</div>

					<div class="mb-2"><strong>DNSBLs to query</strong></div>
					<div class="row g-2">
						<?php $defaults = get_default_dnsbls(); $selected = $zones; ?>
						<?php foreach ($defaults as $zone): ?>
							<div class="col-sm-6 col-lg-4">
								<div class="form-check">
									<input class="form-check-input" type="checkbox" value="<?= h($zone) ?>" id="dnsbl_<?= h(strtr($zone, ['.'=>'_'])) ?>" name="dnsbl[]" <?= in_array($zone, $selected, true) ? 'checked' : '' ?>>
									<label class="form-check-label dnsbl-zone" for="dnsbl_<?= h(strtr($zone, ['.'=>'_'])) ?>"><?= h($zone) ?></label>
								</div>
							</div>
						<?php endforeach; ?>
					</div>

					<?php if ($zones): ?>
						<?php // Preserve any custom zones passed in GET that aren't in defaults ?>
						<?php foreach ($zones as $z) if (!in_array($z, $defaults, true)): ?>
							<input type="hidden" name="dnsbl[]" value="<?= h($z) ?>">
						<?php endif; ?>
					<?php endif; ?>

					<div class="mt-3 d-flex gap-2">
						<button type="submit" class="btn btn-primary">Check</button>
						<a href="/" class="btn btn-outline-secondary">Clear</a>
						<?php if ($queryInput !== ''): ?>
							<a class="btn btn-outline-dark" href="?<?= http_build_query(['lookup'=>$queryInput, 'dnsbl'=>$zones, 'format'=>'json']) ?>">View JSON</a>
						<?php endif; ?>
					</div>
				</div>
			</form>

			<?php if ($errors): ?>
				<div class="alert alert-danger" role="alert">
					<ul class="mb-0">
						<?php foreach ($errors as $e): ?><li><?= h($e) ?></li><?php endforeach; ?>
					</ul>
				</div>
			<?php endif; ?>

			<?php if ($queryInput !== ''): ?>
				<h2 class="h4 mb-3">Lookup Result:</h2>
				<div class="card mb-4">
					<div class="card-body">
						<div class="mb-2"><strong>Submitted:</strong> <span class="ip-badge"><?= h($queryInput) ?></span></div>
						<div class="mb-0 text-muted">UTC: <?= h($now) ?></div>
					</div>
				</div>

				<?php $completeInfo = results_completeness($results, $zones, $resolved['ips']); ?>
				<?php if (!$completeInfo['complete']): ?>
					<div class="alert alert-warning" role="alert">
						The check did not complete for all zones (<?= h((string)$completeInfo['actual']) ?>/<?= h((string)$completeInfo['expected']) ?>). Please try again.
					</div>
				<?php endif; ?>

				<?php if ($resolved['input_type'] === 'domain'): ?>
					<div class="card mb-4">
						<div class="card-header bg-light">Resolved IPs for <span class="ip-badge"><?= h($queryInput) ?></span></div>
						<div class="card-body">
							<div class="row">
								<div class="col-md-6">
									<h3 class="h6">IPv4 (A)</h3>
									<?php if ($resolved['ips']['ipv4']): ?>
										<ul class="mb-0">
											<?php foreach ($resolved['ips']['ipv4'] as $ip): ?><li class="ip-badge"><?= h($ip) ?></li><?php endforeach; ?>
										</ul>
									<?php else: ?>
										<div class="text-muted">No A records</div>
									<?php endif; ?>
								</div>
								<div class="col-md-6">
									<h3 class="h6">IPv6 (AAAA)</h3>
									<?php if ($resolved['ips']['ipv6']): ?>
										<ul class="mb-0">
											<?php foreach ($resolved['ips']['ipv6'] as $ip): ?><li class="ip-badge"><?= h($ip) ?></li><?php endforeach; ?>
										</ul>
									<?php else: ?>
										<div class="text-muted">No AAAA records</div>
									<?php endif; ?>
								</div>
							</div>
						</div>
					</div>
				<?php endif; ?>

				<?php if ($results && $completeInfo['complete']): ?>
					<div class="mb-3 small text-muted">
						<strong>Status legend:</strong>
						<span class="ms-2 result-listed">LISTED</span>
						<span class="ms-2 result-clean">not listed</span>
						<span class="ms-2 text-warning fw-semibold">unknown (timeout)</span>
						<span class="ms-1">= DNSBL query timed out (~3s).</span>
					</div>
					<?php foreach ($results as $ip => $zonesResults): ?>
						<div class="card mb-4 shadow-sm">
							<div class="card-header d-flex justify-content-between align-items-center">
								<div>
									<strong>Results for</strong> <span class="ip-badge"><?= h($ip) ?></span>
								</div>
								<?php
									$anyListed = false;
									foreach ($zonesResults as $zr) { if ($zr['listed']) { $anyListed = true; break; } }
								?>
								<span class="badge <?= $anyListed ? 'bg-danger' : 'bg-success' ?>">
									<?= $anyListed ? 'Listed' : 'Not Listed' ?>
								</span>
							</div>
							<div class="table-responsive">
							<table class="table table-sm align-middle mb-0">
								<thead class="table-light">
									<tr>
										<th>DNSBL</th>
										<th>Query</th>
										<th>Status</th>
										<th>Return</th>
										<th>TXT</th>
									</tr>
								</thead>
								<tbody>
									<?php foreach ($zonesResults as $zone => $out): ?>
										<tr>
											<td class="dnsbl-zone"><?= h($zone) ?></td>
											<?php $qv = $out['query'] ?? ''; if (is_array($qv)) { $qv = implode(' ', array_map('strval', $qv)); } else { $qv = (string)$qv; } ?>
											<td class="text-muted small"><span class="dnsbl-zone"><?= h($qv) ?></span></td>
											<td>
												<?php if (!empty($out['error']) && $out['error'] === 'timeout'): ?>
													<span class="text-warning fw-semibold">unknown (timeout)</span>
												<?php elseif ($out['listed']): ?>
													<span class="result-listed">LISTED</span>
												<?php else: ?>
													<span class="result-clean">not listed</span>
												<?php endif; ?>
											</td>
											<?php $rv = $out['response'] ?? ''; if (is_array($rv)) { $rv = implode(' ', array_map('strval', $rv)); } else { $rv = (string)$rv; } ?>
											<td class="ip-badge small"><?= h($rv) ?></td>
											<td class="small">
												<?php if (!empty($out['txt'])): ?>
													<?php $tv = $out['txt']; if (is_array($tv)) { $tv = implode(' | ', array_map('strval', $tv)); } else { $tv = (string)$tv; } ?>
													<?= h($tv) ?>
												<?php else: ?>
													<span class="text-muted">&mdash;</span>
												<?php endif; ?>
											</td>
										</tr>
									<?php endforeach; ?>
								</tbody>
							</table>
							</div>
						</div>
					<?php endforeach; ?>
				<?php elseif ($queryInput !== '' && !$errors && empty($resolved['ips']['ipv4']) && empty($resolved['ips']['ipv6'])): ?>
					<div class="alert alert-info">No IPs to check.</div>
				<?php endif; ?>
			<?php endif; ?>

			<footer class="mt-5 text-muted small">
				<div class="d-flex justify-content-between align-items-center">
					<div>Tip: Use GET like <span class="dnsbl-zone">?lookup=8.8.8.8</span> or add <span class="dnsbl-zone">&format=json</span> for API JSON.</div>
					<a href="https://github.com/tsueri/DNSBL-PHP-checker" class="text-muted ms-3" aria-label="View repository on GitHub" title="View repository on GitHub">
						<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" fill="currentColor" viewBox="0 0 16 16" aria-hidden="true" role="img">
							<path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.01.08-2.11 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.91.08 2.11.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.19 0 .21.15.46.55.38A8.013 8.013 0 0 0 16 8c0-4.42-3.58-8-8-8z"/>
						</svg>
					</a>
				</div>
			</footer>
		</div>
	</div>
</div>
</main>
<script src="js/bootstrap.bundle.min.js"></script>
<script nonce="<?= h(csp_nonce()) ?>">
(function(){
	var span = document.getElementById('rl-reset-remaining');
	var container = document.getElementById('rl-next');
	if (!span || !container) return;
	var n = parseInt(span.getAttribute('data-remaining') || '0', 10);
	if (!isFinite(n) || n <= 0) return;
	var timer = setInterval(function(){
		n -= 1;
		if (n > 0) {
			span.textContent = String(n);
		} else {
			clearInterval(timer);
			container.classList.remove('text-danger');
			container.classList.remove('text-muted');
			container.classList.add('text-success');
			container.textContent = 'Window reset. You can run more tests now.';
		}
	}, 1000);
})();
</script>
</body>
</html>

