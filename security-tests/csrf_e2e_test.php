<?php
/**
 * Aurelia Bank — End-to-end (black-box) CSRF defence test
 * -----------------------------------------------------------------------------
 * Drives the LIVE running website over HTTP exactly as an attacker's forged
 * page would, and proves the CSRF defence holds:
 *
 *   1. Log in as a real seeded customer (jdoe) and keep the session cookie.
 *   2. ATTACK  — POST the forged "profile update" to customer/profile.php with
 *      the victim's session cookie but NO csrf_token (byte-for-byte what
 *      security-tests/csrf_poc.html sends). Assert the database row is
 *      UNCHANGED → the forgery was rejected before any write.
 *   3. CONTROL — POST a legitimate update WITH the page's real csrf_token.
 *      Assert it succeeds → the endpoint still works for genuine requests, so
 *      step 2 proves a real defence, not a broken page.
 *   4. Restore the record.
 *
 * Cookie handling note: the hardened session cookie is `Secure`, so a strict
 * HTTP cookie jar would refuse to resend it over plain http://. Real browsers
 * DO send Secure cookies to `localhost` (it is a secure context), so this
 * harness manages the cookie manually to match real browser-on-localhost
 * behaviour. (SameSite is a browser-enforced rule that HTTP clients cannot
 * replicate; it is covered by the white-box test csrf_test.php. This e2e test
 * verifies the server-side synchroniser-token layer against the real app.)
 *
 * PREREQUISITES (the test checks these and tells you if missing):
 *   - MySQL up, aurelia_bank seeded:  php database/seed_users.php
 *   - App served:  php -S 127.0.0.1:8088 -t <project root>
 *
 * Run:
 *   /c/xampp/php/php.exe security-tests/csrf_e2e_test.php
 *   (optional:  BASE_URL=http://127.0.0.1:8088  as an env var)
 *
 * Exit 0 = CSRF defended end-to-end, 1 = a check failed / setup missing.
 */

declare(strict_types=1);

$BASE   = rtrim(getenv('BASE_URL') ?: 'http://127.0.0.1:8088', '/');
$USER   = 'jdoe';
$PASS   = 'Password@123';
$ORIGINAL_NAME  = 'John Doe';
$ORIGINAL_EMAIL = 'john.doe@example.test';

$pass = 0; $fail = 0;
function check(string $label, bool $cond): void {
    global $pass, $fail;
    echo ($cond ? "  [PASS] " : "  [FAIL] ") . $label . "\n";
    $cond ? $pass++ : $fail++;
}
function fatal(string $msg): void {
    echo "\n  SETUP ERROR: {$msg}\n";
    echo "  (Need MySQL seeded + `php -S 127.0.0.1:8088 -t <root>` running.)\n";
    exit(1);
}

/**
 * Minimal HTTP client with a manual cookie jar (ignores the Secure flag, like a
 * browser on localhost). Returns [status, headers, body, cookies].
 */
function http(string $method, string $url, array $cookies = [], array $post = null): array {
    $ch = curl_init($url);
    $headers = [];
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => false,            // inspect the redirect ourselves
        CURLOPT_CUSTOMREQUEST  => $method,
        CURLOPT_HEADERFUNCTION => function ($ch, $line) use (&$headers) {
            $headers[] = trim($line);
            return strlen($line);
        },
    ]);
    if ($cookies) {
        $pairs = [];
        foreach ($cookies as $k => $v) { $pairs[] = "$k=$v"; }
        curl_setopt($ch, CURLOPT_COOKIE, implode('; ', $pairs));
    }
    if ($post !== null) {
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($post));
    }
    $body = curl_exec($ch);
    if ($body === false) { fatal('cannot reach app at ' . $url . ' — ' . curl_error($ch)); }
    $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    // Parse Set-Cookie headers into name=>value.
    $setCookies = [];
    foreach ($headers as $h) {
        if (stripos($h, 'Set-Cookie:') === 0) {
            $kv = trim(substr($h, strlen('Set-Cookie:')));
            $kv = explode(';', $kv)[0];
            if (strpos($kv, '=') !== false) {
                [$n, $val] = explode('=', $kv, 2);
                $setCookies[trim($n)] = trim($val);
            }
        }
    }
    return [$status, $headers, (string) $body, $setCookies];
}

/** Authoritative read of the victim's stored name, straight from the DB. */
function db_name(string $username): string {
    try {
        $pdo = new PDO('mysql:host=127.0.0.1;port=3306;dbname=aurelia_bank;charset=utf8mb4', 'root', '', [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        ]);
    } catch (Throwable $e) {
        fatal('cannot connect to MySQL (aurelia_bank): ' . $e->getMessage());
    }
    $stmt = $pdo->prepare('SELECT full_name FROM users WHERE username = ?');
    $stmt->execute([$username]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    if ($row === false) { fatal("user '{$username}' not found — run database/seed_users.php"); }
    return (string) $row['full_name'];
}
function db_set_name(string $username, string $name): void {
    $pdo = new PDO('mysql:host=127.0.0.1;port=3306;dbname=aurelia_bank;charset=utf8mb4', 'root', '', [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    ]);
    $pdo->prepare('UPDATE users SET full_name = ? WHERE username = ?')->execute([$name, $username]);
}

echo "Target: {$BASE}\n";
echo "Ensuring victim '{$USER}' starts from a known name...\n";
db_set_name($USER, $ORIGINAL_NAME);

// -----------------------------------------------------------------------------
echo "\nSTEP 1 — Log in as the victim ({$USER})\n";
// -----------------------------------------------------------------------------
[$st, $hdr, $body, $setc] = http('POST', "{$BASE}/auth/login.php", [], [
    'username' => $USER,
    'password' => $PASS,
]);
$session = $setc['AURELIA_SESSION'] ?? null;
check('login returned a redirect (authenticated)', $st === 302 || $st === 303);
check('server issued a session cookie', $session !== null && $session !== '');
if (!$session) { fatal('no session cookie from login — cannot continue'); }
$jar = ['AURELIA_SESSION' => $session];

// Confirm the session is really authenticated by loading the profile page,
// and scrape the real CSRF token the server put in the form.
[$st, $hdr, $profileHtml, $_] = http('GET', "{$BASE}/customer/profile.php", $jar);
check('profile page loads for the logged-in session (HTTP 200)', $st === 200);
check('profile shows the victim (not logged out)', strpos($profileHtml, $ORIGINAL_NAME) !== false);
preg_match('/name="csrf_token"\s+value="([0-9a-f]{64})"/', $profileHtml, $m);
$realToken = $m[1] ?? '';
check('profile form carries a CSRF token', $realToken !== '');

// -----------------------------------------------------------------------------
echo "\nSTEP 2 — ATTACK: forged cross-site POST with NO token\n";
// -----------------------------------------------------------------------------
$forgedName = 'Compromised by CSRF PoC';
[$st, $hdr, $body, $_] = http('POST', "{$BASE}/customer/profile.php", $jar, [
    'form'      => 'profile',
    'full_name' => $forgedName,
    'email'     => 'attacker-controlled@csrf-demo.test',
    'phone'     => '',
    'address'   => '',
    // NOTE: no csrf_token — exactly like security-tests/csrf_poc.html
]);
$nameAfterAttack = db_name($USER);
check('forged request did NOT return success-with-write', $nameAfterAttack !== $forgedName);
check('victim name UNCHANGED in the database after the attack',
    $nameAfterAttack === $ORIGINAL_NAME);
echo "        (stored name is still: \"{$nameAfterAttack}\")\n";

// -----------------------------------------------------------------------------
echo "\nSTEP 3 — CONTROL: legitimate POST WITH the real token\n";
// -----------------------------------------------------------------------------
$legitName = 'John Doe (legit edit)';
[$st, $hdr, $body, $_] = http('POST', "{$BASE}/customer/profile.php", $jar, [
    'csrf_token' => $realToken,
    'form'       => 'profile',
    'full_name'  => $legitName,
    'email'      => $ORIGINAL_EMAIL,
    'phone'      => '',
    'address'    => '',
]);
$nameAfterLegit = db_name($USER);
check('legitimate tokened request was accepted and wrote the change',
    $nameAfterLegit === $legitName);

// -----------------------------------------------------------------------------
echo "\nCLEANUP — restore the victim record\n";
// -----------------------------------------------------------------------------
db_set_name($USER, $ORIGINAL_NAME);
check('record restored to original', db_name($USER) === $ORIGINAL_NAME);

// -----------------------------------------------------------------------------
echo "\n" . str_repeat('=', 56) . "\n";
if ($fail === 0) {
    echo "RESULT: {$pass} passed, 0 failed\n";
    echo "The live site REJECTED the forged request and accepted only the\n";
    echo "token-bearing one  —  CSRF is defended end-to-end.\n";
    exit(0);
}
echo "RESULT: {$pass} passed, {$fail} FAILED  —  CSRF defence is NOT holding!\n";
exit(1);
