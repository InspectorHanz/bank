<?php
/**
 * Aurelia Bank — Authentication & Authorization Helpers
 * -----------------------------------------------------------------------------
 * Central place for everything related to "who is signed in and what may they
 * do". Kept deliberately small and readable so the mechanics are easy to follow
 * (and so later phases can target the *real* login flow for the controlled
 * security demonstrations).
 *
 * Responsibilities:
 *   - Look up a user for authentication (prepared statement).
 *   - Establish / destroy an authenticated session (with fixation protection).
 *   - Expose the current user and role to the rest of the app.
 *   - Provide guards: require_login() and require_role().
 *   - Record every login attempt (audit trail).
 *   - Rate-limit password guessing via includes/throttle.php (Phase 9
 *     hardening of the Phase 7 brute-force demo, which had no throttling).
 */

declare(strict_types=1);

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/functions.php';
require_once __DIR__ . '/throttle.php';

/**
 * Return the currently authenticated user as a small session snapshot, or null.
 *
 * @return array{id:int, username:string, full_name:string, role:string}|null
 */
function current_user(): ?array
{
    if (empty($_SESSION['user']) || !is_array($_SESSION['user'])) {
        return null;
    }
    return $_SESSION['user'];
}

/** Whether there is an authenticated user in the current session. */
function is_logged_in(): bool
{
    return current_user() !== null;
}

/** The current user's role ('customer' | 'admin'), or null if not logged in. */
function current_user_role(): ?string
{
    return current_user()['role'] ?? null;
}

/**
 * Look up a user by username for authentication.
 * Uses a prepared statement (parameterised query) — the correct, safe default.
 * Input that username_lookup_allowed() rejects is treated as not found, so it
 * can never reach an account the throttle would key differently.
 *
 * @return array<string,mixed>|null  The full user row, or null if not found.
 */
function find_user_by_username(string $username): ?array
{
    if (!username_lookup_allowed($username)) {
        return null;
    }
    $stmt = db()->prepare(
        'SELECT id, username, email, password_hash, full_name, role, status
           FROM users
          WHERE username = :username
          LIMIT 1'
    );
    $stmt->execute([':username' => $username]);
    $user = $stmt->fetch();

    return $user !== false ? $user : null;
}

/**
 * Authenticate a username/password pair, optionally requiring a specific role
 * so the customer and staff portals each only accept their own kind of account.
 *
 * Centralising this here means both login pages share ONE authentication path,
 * and therefore one brute-force budget: alternating between the customer and
 * staff portals does not buy an attacker extra guesses.
 *
 * Rate limiting happens BEFORE the password is checked (see throttle.php): a
 * refused attempt never reaches password_verify(), so it reveals nothing about
 * the password, and the refusal looks the same for real and unknown usernames.
 *
 * Records every attempt (audit trail) and returns a generic result so callers
 * show a single, non-enumerating error message.
 *
 * @return array{ok:bool, user?:array<string,mixed>, error?:string, throttled?:bool, retry_after?:int}
 */
function authenticate(string $username, string $password, ?string $requireRole = null): array
{
    $ticket = throttle_reserve('login', login_throttle_subjects($username, client_ip()));
    if (!$ticket['allowed']) {
        record_login_attempt($username, false, true);
        return [
            'ok'          => false,
            'throttled'   => true,
            'retry_after' => $ticket['retry_after'],
            'error'       => throttle_message($ticket['retry_after']),
        ];
    }

    $user = find_user_by_username($username);

    // Always run a hash check (a dummy when no user exists) so response timing
    // does not reveal whether the username exists.
    $knownHash = $user['password_hash']
        ?? '$2y$10$usesomesillystringforsalttttttttttttttttttttttttttttte';
    $passwordOk = password_verify($password, $knownHash);

    // A wrong-portal credential (e.g. an admin on the customer login) fails the
    // same generic way as a wrong password — no cross-portal enumeration.
    $roleOk = $requireRole === null || ($user !== null && $user['role'] === $requireRole);

    // An inactive account fails the same generic way too: a distinct "account
    // disabled" message would confirm to an attacker that they had guessed the
    // right password (and that the username exists).
    $authenticated = $user !== null && $passwordOk && $roleOk && $user['status'] === 'active';
    record_login_attempt($username, $authenticated);

    if (!$authenticated) {
        throttle_failure($ticket, $user !== null ? (int) $user['id'] : null);
        return ['ok' => false, 'error' => 'Invalid username or password.'];
    }
    throttle_success($ticket);
    return ['ok' => true, 'user' => $user];
}

/**
 * Establish an authenticated session for the given user row.
 *
 * Security:
 *   - Regenerates the session id to defeat session fixation on privilege change.
 *   - Stores only a minimal snapshot in the session (never the password hash).
 */
function login_user(array $user): void
{
    // A brand-new session id the moment privileges change.
    session_regenerate_id(true);

    $_SESSION['user'] = [
        'id'        => (int) $user['id'],
        'username'  => (string) $user['username'],
        'full_name' => (string) $user['full_name'],
        'role'      => (string) $user['role'],
    ];
    $_SESSION['logged_in_at'] = time();
}

/**
 * Completely tear down the authenticated session (data + cookie).
 */
function logout_user(): void
{
    $_SESSION = [];

    // Expire the session cookie in the browser as well as clearing server state.
    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', [
            'expires'  => time() - 42000,
            'path'     => $params['path'],
            'domain'   => $params['domain'],
            'secure'   => $params['secure'],
            'httponly' => $params['httponly'],
            'samesite' => $params['samesite'] ?? 'Lax',
        ]);
    }

    session_destroy();
}

/**
 * Create a new customer user and return its id. Caller is responsible for
 * validation and (typically) wrapping this in a transaction alongside opening
 * the customer's first account. The password is hashed here — never stored raw.
 *
 * @param array{username:string,email:string,password:string,full_name:string,phone?:?string,address?:?string} $data
 */
function create_customer(array $data): int
{
    $stmt = db()->prepare(
        'INSERT INTO users (username, email, password_hash, full_name, role, phone, address, status)
         VALUES (:username, :email, :password_hash, :full_name, \'customer\', :phone, :address, \'active\')'
    );
    $stmt->execute([
        ':username'      => $data['username'],
        ':email'         => $data['email'],
        ':password_hash' => password_hash($data['password'], PASSWORD_DEFAULT),
        ':full_name'     => $data['full_name'],
        ':phone'         => ($data['phone'] ?? '') !== '' ? $data['phone'] : null,
        ':address'       => ($data['address'] ?? '') !== '' ? $data['address'] : null,
    ]);
    return (int) db()->lastInsertId();
}

/** Whether a username already exists (case-insensitive via the column collation). */
function username_exists(string $username): bool
{
    $stmt = db()->prepare('SELECT 1 FROM users WHERE username = :u LIMIT 1');
    $stmt->execute([':u' => $username]);
    return $stmt->fetchColumn() !== false;
}

/** Whether an email is already registered. */
function email_exists(string $email): bool
{
    $stmt = db()->prepare('SELECT 1 FROM users WHERE email = :e LIMIT 1');
    $stmt->execute([':e' => $email]);
    return $stmt->fetchColumn() !== false;
}

/**
 * Look up a full user record by id (e.g. to load the profile-edit form).
 *
 * @return array<string,mixed>|null
 */
function find_user_by_id(int $id): ?array
{
    $stmt = db()->prepare(
        'SELECT id, username, email, password_hash, full_name, role, phone, address, status
           FROM users
          WHERE id = :id
          LIMIT 1'
    );
    $stmt->execute([':id' => $id]);
    $user = $stmt->fetch();

    return $user !== false ? $user : null;
}

/**
 * Record an authentication attempt for auditing.
 *
 * This is an audit trail (evidence for the brute-force demonstration and its
 * retest); enforcement is done by throttle.php. Only the attempted username is
 * stored — never the password. It never blocks the login flow: any failure
 * here is logged and swallowed.
 *
 * @param bool $throttled  The attempt was refused by rate limiting (no password check).
 */
function record_login_attempt(?string $username, bool $success, bool $throttled = false): void
{
    try {
        $stmt = db()->prepare(
            'INSERT INTO login_attempts (username, ip_address, user_agent, successful, throttled)
             VALUES (:username, :ip, :ua, :ok, :throttled)'
        );
        $stmt->execute([
            // Scrubbed so malformed UTF-8 is still recorded instead of failing the insert.
            ':username'  => $username !== null ? mb_substr(mb_scrub($username, 'UTF-8'), 0, 50) : null,
            ':ip'        => client_ip(),
            ':ua'        => isset($_SERVER['HTTP_USER_AGENT'])
                ? mb_substr((string) $_SERVER['HTTP_USER_AGENT'], 0, 255)
                : null,
            ':ok'        => $success ? 1 : 0,
            ':throttled' => $throttled ? 1 : 0,
        ]);
    } catch (Throwable $e) {
        error_log('[Aurelia Bank] Failed to record login attempt: ' . $e->getMessage());
    }
}

/**
 * The landing page a given role should be sent to after logging in.
 */
function role_home(?string $role): string
{
    return $role === 'admin' ? 'admin/dashboard.php' : 'customer/dashboard.php';
}

/**
 * The correct login page for the area being requested: the staff portal for
 * anything under /admin/, the customer login otherwise. Keeps unauthenticated
 * admin-area hits from bouncing to (and thus advertising) the wrong portal.
 */
function login_url_for_area(): string
{
    $script = str_replace('\\', '/', (string) ($_SERVER['SCRIPT_NAME'] ?? ''));
    return str_contains($script, '/admin/') ? 'admin/login.php' : 'auth/login.php';
}

/**
 * Guard: require an authenticated session. If absent, remember where the user
 * was heading and redirect them to the appropriate login page.
 */
function require_login(): void
{
    if (!is_logged_in()) {
        // Remember the intended destination (same-origin path) for after login.
        $_SESSION['_return_to'] = $_SERVER['REQUEST_URI'] ?? '';
        set_flash('info', 'Please log in to continue.');
        redirect(login_url_for_area());
    }
}

/**
 * Guard: require an authenticated session AND a specific role. A logged-in user
 * with the wrong role is sent to their own area rather than shown someone
 * else's (authorization, not just authentication).
 */
function require_role(string $role): void
{
    require_login();
    if (current_user_role() !== $role) {
        redirect(role_home(current_user_role()));
    }
}
