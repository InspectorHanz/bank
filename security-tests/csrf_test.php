<?php
/**
 * Aurelia Bank — Automated CSRF defence test
 * -----------------------------------------------------------------------------
 * Proves the Phase 7 CSRF hardening is in place. Runs with PHP alone — no
 * database and no running web server required, so it is deterministic and
 * repeatable in CI.
 *
 * It checks the two independent defence layers added in the hardening phase:
 *   LAYER 1  synchroniser token  (includes/csrf.php, enforced by profile.php)
 *   LAYER 2  SameSite=Lax cookie (includes/session.php)
 * plus that profile.php actually wires the token check in before any DB write.
 *
 * Run:
 *   /c/xampp/php/php.exe security-tests/csrf_test.php
 *   (or:  C:\xampp\php\php.exe security-tests\csrf_test.php)
 *
 * Exit code 0 = all passed (CSRF defended), 1 = a defence is missing.
 */

declare(strict_types=1);

$root = dirname(__DIR__);
$pass = 0;
$fail = 0;

function check(string $label, bool $cond): void
{
    global $pass, $fail;
    if ($cond) {
        $pass++;
        echo "  [PASS] {$label}\n";
    } else {
        $fail++;
        echo "  [FAIL] {$label}\n";
    }
}

// The token helpers read/write the $_SESSION superglobal. In CLI there is no
// real session, so we stand one in — this represents the logged-in victim.
$_SESSION = [];
require $root . '/includes/csrf.php';

// -----------------------------------------------------------------------------
echo "LAYER 1 — Synchroniser token (csrf_verify)\n";
// -----------------------------------------------------------------------------

// Victim is logged in: their session already holds a CSRF token.
$realToken = csrf_token();

// (a) The actual attack — forged cross-site POST with NO token field at all
//     (exactly what security-tests/csrf_poc.html sends).
$_POST = ['form' => 'profile', 'full_name' => 'Compromised by CSRF PoC'];
check('forged POST with NO token is rejected', csrf_verify() === false);

// (b) Attacker sends a guessed / wrong token.
$_POST['csrf_token'] = 'wrong-token-guess';
check('POST with WRONG token is rejected', csrf_verify() === false);

// (c) Legitimate request — the real session token is echoed back by the form.
$_POST['csrf_token'] = $realToken;
check('POST with CORRECT token is accepted', csrf_verify() === true);

// (d) The token must be unpredictable: 32 random bytes = 64 hex chars.
check('token is 64-char cryptographic hex', (bool) preg_match('/^[0-9a-f]{64}$/', $realToken));

// -----------------------------------------------------------------------------
echo "\nLAYER 2 — SameSite=Lax session cookie\n";
// -----------------------------------------------------------------------------
$session = (string) file_get_contents($root . '/includes/session.php');
check("samesite is 'Lax' (cookie not sent on cross-site POST)",
    preg_match("/'samesite'\\s*=>\\s*'Lax'/", $session) === 1
    && preg_match("/'samesite'\\s*=>\\s*'None'/", $session) === 0);
check("httponly => true (JS cannot read the cookie)",
    preg_match("/'httponly'\\s*=>\\s*true/", $session) === 1);
check("secure => true (HTTPS only)",
    preg_match("/'secure'\\s*=>\\s*true/", $session) === 1);

// -----------------------------------------------------------------------------
echo "\nWIRING — profile.php enforces the token before any DB write\n";
// -----------------------------------------------------------------------------
$profile = (string) file_get_contents($root . '/customer/profile.php');
check('profile.php requires includes/csrf.php',
    str_contains($profile, 'includes/csrf.php'));
check('profile.php calls csrf_verify() on POST',
    preg_match('/if\s*\(\s*!\s*csrf_verify\(\)\s*\)/', $profile) === 1);
check('both forms emit csrf_field()',
    substr_count($profile, 'csrf_field()') >= 2);

$guardPos  = strpos($profile, 'csrf_verify()');
$updatePos = strpos($profile, 'UPDATE users');
check('csrf_verify() guard runs BEFORE the first UPDATE',
    $guardPos !== false && $updatePos !== false && $guardPos < $updatePos);

// -----------------------------------------------------------------------------
echo "\n" . str_repeat('=', 52) . "\n";
if ($fail === 0) {
    echo "RESULT: {$pass} passed, 0 failed  —  CSRF is DEFENDED.\n";
    exit(0);
}
echo "RESULT: {$pass} passed, {$fail} FAILED  —  a CSRF defence is missing!\n";
exit(1);
