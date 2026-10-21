<?php
/**
 * Aurelia Bank — Shared Helper Functions
 * -----------------------------------------------------------------------------
 * Small, reusable, side-effect-free helpers used across the application.
 * Security-relevant helpers (output escaping) live here so every page uses the
 * same, correct implementation.
 */

declare(strict_types=1);

/**
 * Escape a string for safe output in HTML context.
 * Use this for EVERY dynamic value printed into a page.
 */
function e(?string $value): string
{
    return htmlspecialchars($value ?? '', ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

/**
 * Build a root-relative URL for the application.
 *
 * Auto-detects the app's web base path from DOCUMENT_ROOT so links work whether
 * the app lives at the web root (Hostinger) or in a subfolder (local XAMPP).
 * Override by defining APP_BASE_URL in config.local.php.
 */
function base_url(string $path = ''): string
{
    static $base = null;

    if ($base === null) {
        if (defined('APP_BASE_URL')) {
            $base = rtrim((string) APP_BASE_URL, '/');
        } else {
            $root    = str_replace('\\', '/', ROOT_PATH);
            $docRoot = str_replace('\\', '/', rtrim($_SERVER['DOCUMENT_ROOT'] ?? '', '/'));

            if ($docRoot !== '' && str_starts_with($root, $docRoot)) {
                $base = substr($root, strlen($docRoot));
            } else {
                $base = '';
            }
            $base = rtrim($base, '/');
        }
    }

    return $base . '/' . ltrim($path, '/');
}

/**
 * Convenience wrapper for asset URLs (CSS, JS, images).
 */
function asset(string $path): string
{
    return base_url('assets/' . ltrim($path, '/'));
}

/**
 * Redirect to an application path and stop execution.
 */
function redirect(string $path): never
{
    header('Location: ' . base_url($path));
    exit;
}

/**
 * Store a one-time flash message to display after a redirect.
 * $type is a semantic class: success | error | info | warning
 */
function set_flash(string $type, string $message): void
{
    if (session_status() === PHP_SESSION_ACTIVE) {
        $_SESSION['_flash'][] = ['type' => $type, 'message' => $message];
    }
}

/**
 * Retrieve and clear all pending flash messages.
 *
 * @return array<int, array{type:string, message:string}>
 */
function get_flashes(): array
{
    $flashes = $_SESSION['_flash'] ?? [];
    unset($_SESSION['_flash']);
    return $flashes;
}

/**
 * Format a decimal amount as currency for display.
 */
function format_money(float|string $amount, string $currency = 'USD'): string
{
    $symbols = ['USD' => '$', 'EUR' => '€', 'GBP' => '£'];
    $symbol  = $symbols[$currency] ?? ($currency . ' ');
    return $symbol . number_format((float) $amount, 2);
}

/**
 * Format a datetime string for display.
 */
function format_date(string $datetime, string $format = 'M j, Y'): string
{
    $ts = strtotime($datetime);
    return $ts ? date($format, $ts) : $datetime;
}

/**
 * Parse a user-entered money amount into a positive float with 2 decimals.
 * Accepts values like "100", "100.50" or "1,000.50". Returns null if the input
 * is not a valid, positive amount.
 */
function parse_amount(string $input): ?float
{
    $clean = str_replace([',', ' '], '', trim($input));
    if ($clean === '' || !is_numeric($clean)) {
        return null;
    }
    $value = round((float) $clean, 2);
    return $value > 0 ? $value : null;
}

/**
 * Mask an account number for compact display, showing only the last 4 chars.
 */
function mask_account(string $accountNumber): string
{
    $last4 = substr($accountNumber, -4);
    return '•••• ' . $last4;
}

/**
 * Validate a 'YYYY-MM-DD' date string. Returns true only for a real calendar
 * date in that exact format.
 */
function is_valid_date(string $value): bool
{
    $d = DateTimeImmutable::createFromFormat('!Y-m-d', $value);
    return $d !== false && $d->format('Y-m-d') === $value;
}

/**
 * Render a simple pagination control.
 *
 * @param int                  $current  1-based current page
 * @param int                  $total    total number of pages
 * @param array<string,scalar> $params   query params to preserve (minus 'page')
 * @param string               $script   target script (defaults to current)
 */
function render_pagination(int $current, int $total, array $params = [], string $script = ''): string
{
    if ($total <= 1) {
        return '';
    }

    $script = $script !== '' ? $script : basename($_SERVER['SCRIPT_NAME'] ?? '');
    unset($params['page']);

    $link = static function (int $page) use ($params, $script): string {
        $params['page'] = $page;
        return e($script . '?' . http_build_query($params));
    };

    $html  = '<nav class="pagination" aria-label="Pagination">';
    $html .= $current > 1
        ? '<a class="pagination__link" href="' . $link($current - 1) . '" rel="prev">&larr; Prev</a>'
        : '<span class="pagination__link is-disabled">&larr; Prev</span>';
    $html .= '<span class="pagination__status">Page ' . $current . ' of ' . $total . '</span>';
    $html .= $current < $total
        ? '<a class="pagination__link" href="' . $link($current + 1) . '" rel="next">Next &rarr;</a>'
        : '<span class="pagination__link is-disabled">Next &rarr;</span>';
    $html .= '</nav>';

    return $html;
}

/**
 * The client's IP address, honouring a forwarding header ONLY when the request
 * arrived from a configured trusted proxy (see TRUSTED_PROXIES in config.php).
 *
 * Without trusted proxies this is simply REMOTE_ADDR — the address of whoever
 * opened the TCP connection, which a client cannot forge. X-Forwarded-For is
 * client-controlled, so blindly reading it would let an attacker pick a fresh
 * "IP" per request and slip past per-IP rate limits.
 *
 * With trusted proxies, the forwarding header is walked right-to-left (newest
 * hop first), skipping hops that are themselves trusted proxies; the first
 * untrusted hop is the client. The special value '*' trusts the immediate peer
 * whatever its address and takes the right-most hop it reported — use it only
 * on platforms that overwrite the header themselves (e.g. Vercel).
 */
function client_ip(): string
{
    return resolve_client_ip($_SERVER, (string) TRUSTED_PROXIES, (string) TRUSTED_PROXY_HEADER);
}

/**
 * The logic behind client_ip(), with its inputs passed in (so it can be tested
 * against different proxy configurations).
 *
 * @param array<string,mixed> $server          $_SERVER-shaped request data
 * @param string              $trustedProxies  comma-separated IPs/CIDRs, or '*'
 * @param string              $header          forwarding header name, e.g. 'X-Forwarded-For'
 */
function resolve_client_ip(array $server, string $trustedProxies, string $header): string
{
    $remote = (string) ($server['REMOTE_ADDR'] ?? '');
    if (filter_var($remote, FILTER_VALIDATE_IP) === false) {
        return 'unknown';
    }

    $trusted = trusted_proxy_entries($trustedProxies);
    $trustAnyPeer = in_array('*', $trusted, true);
    $isTrusted = static function (string $ip) use ($trusted): bool {
        foreach ($trusted as $cidr) {
            if ($cidr !== '*' && ip_in_cidr($ip, $cidr)) {
                return true;
            }
        }
        return false;
    };

    if (!$trustAnyPeer && !$isTrusted($remote)) {
        return $remote;   // direct connection, or an untrusted "proxy": ignore headers
    }

    $serverKey = 'HTTP_' . strtoupper(str_replace('-', '_', $header));
    $hops = array_map('trim', explode(',', (string) ($server[$serverKey] ?? '')));

    $client = $remote;
    foreach (array_reverse($hops) as $hop) {
        if (filter_var($hop, FILTER_VALIDATE_IP) === false) {
            break;        // malformed chain: fall back to the last hop we could verify
        }
        $client = $hop;
        if ($trustAnyPeer || !$isTrusted($hop)) {
            break;        // first untrusted hop (or the peer-reported hop for '*')
        }
    }
    return $client;
}

/**
 * The usable entries of a TRUSTED_PROXIES setting: '*' and well-formed
 * IPs/CIDRs. Malformed entries are dropped — never trusted — and reported once
 * per process to the error log so the misconfiguration gets noticed.
 *
 * @return list<string>
 */
function trusted_proxy_entries(string $setting): array
{
    static $reported = [];
    $entries = [];
    foreach (array_filter(array_map('trim', explode(',', $setting)), 'strlen') as $entry) {
        if ($entry === '*' || parse_cidr($entry) !== null) {
            $entries[] = $entry;
        } elseif (!isset($reported[$entry])) {
            $reported[$entry] = true;
            error_log('[Aurelia Bank] Ignoring malformed TRUSTED_PROXIES entry: ' . $entry);
        }
    }
    return $entries;
}

/**
 * Parse 'a.b.c.d', 'a.b.c.d/n', an IPv6 address or 'ipv6/n' into its packed
 * address and prefix length, or null if malformed.
 *
 * The prefix must be plain decimal digits within range. Casting with (int)
 * instead would read '', 'abc', '-0' or '0x8' as /0 — a range that matches
 * every address, i.e. a typo would silently mean "trust everyone".
 *
 * @return array{0:string, 1:int}|null
 */
function parse_cidr(string $cidr): ?array
{
    $parts = explode('/', $cidr);
    if (count($parts) > 2) {
        return null;
    }
    $subnetBin = @inet_pton($parts[0]);
    if ($subnetBin === false) {
        return null;
    }
    $maxBits = strlen($subnetBin) * 8;
    if (count($parts) === 1) {
        return [$subnetBin, $maxBits];
    }
    $prefix = $parts[1];
    if ($prefix === '' || strlen($prefix) > 3 || !ctype_digit($prefix) || (int) $prefix > $maxBits) {
        return null;
    }
    return [$subnetBin, (int) $prefix];
}

/**
 * Whether an IP address falls inside a CIDR range ('10.0.0.0/8', '2001:db8::/32')
 * or equals a bare address ('203.0.113.7'). A malformed range matches nothing.
 */
function ip_in_cidr(string $ip, string $cidr): bool
{
    $parsed = parse_cidr($cidr);
    $ipBin  = @inet_pton($ip);
    if ($parsed === null || $ipBin === false || strlen($ipBin) !== strlen($parsed[0])) {
        return false;
    }
    [$subnetBin, $bits] = $parsed;

    $fullBytes = intdiv($bits, 8);
    if (substr($ipBin, 0, $fullBytes) !== substr($subnetBin, 0, $fullBytes)) {
        return false;
    }
    $remainder = $bits % 8;
    if ($remainder === 0) {
        return true;
    }
    $mask = (0xFF << (8 - $remainder)) & 0xFF;
    return (ord($ipBin[$fullBytes]) & $mask) === (ord($subnetBin[$fullBytes]) & $mask);
}

const USERNAME_LOOKUP_MAX_CHARS = 255;

function username_lookup_allowed(string $username): bool
{
    return mb_check_encoding($username, 'UTF-8')
        && mb_strlen($username, 'UTF-8') <= USERNAME_LOOKUP_MAX_CHARS;
}

/**
 * Map a record status to a badge CSS modifier class.
 */
function status_badge_class(string $status): string
{
    return match ($status) {
        'active', 'completed'         => 'badge--success',
        'pending'                     => 'badge--warning',
        'locked', 'frozen', 'failed', 'disabled', 'closed' => 'badge--danger',
        default                       => '',
    };
}
