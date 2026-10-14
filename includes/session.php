<?php
/**
 * Aurelia Bank — Session Bootstrap
 * -----------------------------------------------------------------------------
 * Starts a PHP session with cookie parameters.
 *
 *   - HttpOnly  : JavaScript cannot read the session cookie
 *   - Secure    : true — required for SameSite=None to be honoured at all (see below)
 *   - SameSite  : INTENTIONALLY 'None' — Phase 7 CSRF demonstration point
 *
 * CSRF DEMONSTRATION (Phase 7): customer/profile.php's "personal details" form
 * has no CSRF token by design (see that file's docblock) — but a missing token
 * alone no longer gets you a working CSRF demo in a modern browser, because the
 * `SameSite=Lax` default already blocks the session cookie from being attached
 * to a cross-site POST (Lax only allows cross-site *GET* top-level navigation).
 * Setting SameSite explicitly to 'None' removes that extra, incidental layer of
 * protection so a forged cross-origin <form method="POST"> (see
 * security-tests/csrf_poc.html) actually carries the victim's session cookie,
 * same as it would have before browsers started defaulting cookies to Lax.
 * `Secure=true` is required here — browsers silently reject `SameSite=None`
 * cookies that aren't also `Secure` — which is fine since the deployment
 * target is HTTPS-only. The hardened counterpart restores `SameSite=Lax` (or
 * adds a CSRF token to the form, or both). See README "Security notes" /
 * plan.md Phase 7.
 *
 * Note: this repo's earlier MITM-over-plain-HTTP demo (hard-coding `Secure`
 * false) is superseded here — it isn't exploitable against an HTTPS-only host
 * anyway (there is no plaintext connection to intercept), so that cookie knob
 * is now used for the CSRF demo instead. See README for the current status.
 */

declare(strict_types=1);

require_once __DIR__ . '/../config/config.php';

if (session_status() === PHP_SESSION_NONE) {
    session_set_cookie_params([
        'lifetime' => 0,
        'path'     => '/',
        'httponly' => true,
        'secure'   => true,   // required for 'samesite' => 'None' below to be honoured
        'samesite' => 'None', // Phase 7 CSRF demo — see comment above.
    ]);

    session_name(SESSION_NAME);
    session_start();
}
