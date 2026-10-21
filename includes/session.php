<?php
/**
 * Aurelia Bank — Session Bootstrap
 * -----------------------------------------------------------------------------
 * Starts a PHP session with hardened cookie parameters.
 *
 *   - HttpOnly  : JavaScript cannot read the session cookie
 *   - Secure    : true — cookie is only ever sent over HTTPS
 *   - SameSite  : 'Lax' — the cookie is NOT attached to cross-site POSTs
 *
 * CSRF HARDENING (Phase 7 — fixed): this is the first of two defence-in-depth
 * layers against Cross-Site Request Forgery. With `SameSite=Lax`, the browser
 * refuses to attach this session cookie to a forged cross-site <form
 * method="POST"> (Lax only allows the cookie on top-level cross-site *GET*
 * navigations). So the attack in security-tests/csrf_poc.html now arrives at
 * the server with NO session — the victim is effectively anonymous and the
 * request is rejected before any state change.
 *
 * The second layer is the synchroniser CSRF token now required by
 * customer/profile.php (see includes/csrf.php + that file's POST handler).
 * Either layer alone stops the attack; together they are defence-in-depth.
 *
 * (Previously this was set to 'None' to deliberately re-enable the CSRF demo;
 * restoring 'Lax' is the hardened counterpart. See README "Security notes".)
 */

declare(strict_types=1);

require_once __DIR__ . '/../config/config.php';

if (session_status() === PHP_SESSION_NONE) {
    session_set_cookie_params([
        'lifetime' => 0,
        'path'     => '/',
        'httponly' => true,
        'secure'   => true,  // cookie only sent over HTTPS
        'samesite' => 'Lax', // CSRF defence: not attached to cross-site POSTs
    ]);

    session_name(SESSION_NAME);
    session_start();
}
