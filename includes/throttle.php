<?php
/**
 * Aurelia Bank — Authentication Throttling (brute-force hardening, Phase 9)
 * -----------------------------------------------------------------------------
 * Limits how many password guesses (and account-existence probes) any one
 * client, account, or client+account pair can make, using temporary,
 * progressively longer cooldowns. It never locks an account permanently —
 * every cooldown expires on its own, so an attacker cannot use it to shut a
 * customer out for good.
 *
 * HOW AN ATTEMPT FLOWS
 *   1. throttle_reserve()  BEFORE the password is checked. Atomically books the
 *      attempt as PENDING on every key for the scope, or refuses it if any key
 *      is cooling down or has no budget left (completed + pending >= limit).
 *   2. Check the password (only if the reservation was allowed).
 *   3. throttle_success() or throttle_failure() with the reservation "ticket":
 *      the pending booking is released and, if the outcome is the kind the key
 *      counts, recorded as COMPLETED.
 *
 * Booking an attempt BEFORE checking the password is what makes this safe
 * against concurrency: a burst of 50 parallel requests cannot all pass a "not
 * locked yet?" check and then all be verified — at most `limit` of them get a
 * reservation, and the rest are refused without touching password_verify().
 *
 * Pending and completed outcomes are tracked separately, so only COMPLETED
 * failures can start a cooldown: one wrong password racing nineteen correct
 * ones does not lock anyone out, and a success never erases a cooldown that
 * other requests' failures have already earned.
 *
 * A request that never reports back is still accounted for: unresolved tickets
 * are recorded as failures at script shutdown (fatal error, timeout), and a
 * booking left by a killed process expires after AUTH_THROTTLE_PENDING_TTL and
 * is then counted as consumed. Either way it fails safe.
 *
 * STORAGE
 *   The `auth_throttle` table (see database/schema.sql). State lives in the
 *   shared database rather than the PHP session (which an attacker simply
 *   discards) or in-process memory (which multiple instances don't share).
 *   Rows are read and written under SELECT ... FOR UPDATE in a transaction, so
 *   concurrent requests on any number of instances serialise per key.
 *
 *   Keys are SHA-256(scope, kind, subject) for a fixed-width primary key. That is
 *   not a privacy measure — usernames and IPs are already in login_attempts.
 */

declare(strict_types=1);

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/functions.php';
require_once __DIR__ . '/audit.php';

/**
 * Per-scope policies. Each kind is an independent counter; an attempt is
 * refused if ANY of its keys is over budget.
 *
 *   limit             completed outcomes allowed per window
 *   window            seconds the count accumulates over
 *   counts            'failure' = count failed attempts; reaching the limit
 *                                 starts an escalating cooldown
 *                     'success' = count successful actions (a quota); reaching
 *                                 the limit refuses until the window ends
 *   reset_on_success  ('failure' counters) true = a success clears the count,
 *                     unless a cooldown is already running; false = a success
 *                     only releases its own booking (so logging into your OWN
 *                     account between guesses does not wipe a per-IP counter)
 *
 * login.account_ip  — one client hammering one account (the classic attack).
 * login.account     — many clients hammering one account (distributed). Higher
 *                     than account_ip so a single client never trips it alone,
 *                     limiting how easily an attacker can lock a victim out.
 * login.ip          — one client trying many accounts (password spraying).
 */
const AUTH_THROTTLE_POLICIES = [
    'login' => [
        'account_ip' => ['limit' => 5,  'window' => 900, 'counts' => 'failure', 'reset_on_success' => true],
        'account'    => ['limit' => 10, 'window' => 900, 'counts' => 'failure', 'reset_on_success' => true],
        'ip'         => ['limit' => 20, 'window' => 900, 'counts' => 'failure', 'reset_on_success' => false],
    ],
    // Re-entering the current password on the profile page (stolen-session guessing).
    'password_change' => [
        'account' => ['limit' => 5, 'window' => 900, 'counts' => 'failure', 'reset_on_success' => true],
    ],
    // Changing the profile email answers "is this address registered?" when it
    // is taken. A failure = a duplicate was found. Successes never reset it.
    'email_change' => [
        'account' => ['limit' => 5,  'window' => 3600, 'counts' => 'failure', 'reset_on_success' => false],
        'ip'      => ['limit' => 10, 'window' => 3600, 'counts' => 'failure', 'reset_on_success' => false],
    ],
    // Registration: failed submissions (which may reveal a taken username or
    // email) and accounts actually opened are budgeted separately, so neither
    // probing nor mass sign-ups are unlimited.
    'register' => [
        'ip'             => ['limit' => 10, 'window' => 900,  'counts' => 'failure', 'reset_on_success' => false],
        'ip_new_account' => ['limit' => 10, 'window' => 3600, 'counts' => 'success', 'reset_on_success' => false],
    ],
];

/** First cooldown; each consecutive cooldown on a key doubles it ... */
const AUTH_THROTTLE_BASE_COOLDOWN = 30;
/** ... up to this ceiling (15 minutes). */
const AUTH_THROTTLE_MAX_COOLDOWN = 900;
/** After this long without a cooldown, a key's escalation level resets. */
const AUTH_THROTTLE_LEVEL_DECAY = 3600;
/** A pending booking older than this (its process died) counts as consumed. */
const AUTH_THROTTLE_PENDING_TTL = 120;

/**
 * Cooldown length for the Nth consecutive cooldown (level is 1-based).
 */
function throttle_cooldown_seconds(int $level): int
{
    $doublings = min(max($level - 1, 0), 16);
    return min(AUTH_THROTTLE_BASE_COOLDOWN << $doublings, AUTH_THROTTLE_MAX_COOLDOWN);
}

/** Fixed-width primary key for one (scope, kind, subject) counter. */
function throttle_key(string $scope, string $kind, string $subject): string
{
    return hash('sha256', $scope . "\0" . $kind . "\0" . $subject);
}

/**
 * Reduce an IP to the unit an attacker actually controls: IPv4 as-is, IPv6 by
 * its /64 (a single customer is routinely handed a whole /64, so per-address
 * limits on IPv6 would be trivial to rotate around).
 */
function throttle_ip_subject(string $ip): string
{
    $bin = @inet_pton($ip);
    if ($bin === false) {
        return 'unknown';
    }
    if (strlen($bin) === 16) {
        // IPv4-mapped IPv6 (::ffff:a.b.c.d) is really an IPv4 client.
        if (str_starts_with($bin, str_repeat("\0", 10) . "\xFF\xFF")) {
            return (string) inet_ntop(substr($bin, 12));
        }
        return inet_ntop(substr($bin, 0, 8) . str_repeat("\0", 8)) . '/64';
    }
    return (string) inet_ntop($bin);
}

/**
 * Fold a username exactly the way the `users.username` column compares it
 * (utf8mb4_unicode_ci), so every spelling that logs into the same account —
 * 'jdoe', 'JDOE', 'jdoé', 'ｊｄｏｅ', 'j\u{200B}doe', 'jdoe \u{200B}' — shares one
 * counter. Folding in PHP (e.g. strtolower) would miss most of these and let an
 * attacker rotate spellings to dodge the per-account limit.
 *
 * The WHOLE value is folded (no truncation): the collation can make a string
 * of any length equal to a short username. Values username_lookup_allowed()
 * rejects are never looked up, so they cannot reach an account; they get a
 * key of their own, exactly as an unknown username would.
 *
 * The collation is PAD SPACE: trailing spaces are insignificant, and since
 * ignorable characters have no weight, so are spaces followed only by them
 * ('jdoe \u{200B}'). WEIGHT_STRING() keeps those space weights, so they are
 * stripped from the end of the weight string — the same thing the server's
 * comparison does.
 */
function throttle_fold_username(string $username): string
{
    if (!username_lookup_allowed($username)) {
        return 'unlookable:' . hash('sha256', $username);
    }
    $stmt = db()->prepare(
        "SELECT HEX(WEIGHT_STRING(CONVERT(:u USING utf8mb4) COLLATE utf8mb4_unicode_ci)) AS w,
                HEX(WEIGHT_STRING(_utf8mb4' ' COLLATE utf8mb4_unicode_ci)) AS sp"
    );
    $stmt->execute([':u' => $username]);
    $row = $stmt->fetch();
    $weights = (string) $row['w'];
    $space   = (string) $row['sp'];
    if ($space !== '') {
        while (str_ends_with($weights, $space)) {
            $weights = substr($weights, 0, -strlen($space));
        }
    }
    return 'w:' . $weights;
}

/**
 * Subjects for a login attempt: the folded username, the client IP, and both.
 *
 * @return array{account:string, ip:string, account_ip:string}
 */
function login_throttle_subjects(string $username, string $ip): array
{
    $account = throttle_fold_username($username);
    $ipKey   = throttle_ip_subject($ip);
    return [
        'account'    => $account,
        'ip'         => $ipKey,
        'account_ip' => $account . '|' . $ipKey,
    ];
}

/**
 * Atomically reserve one attempt for $scope, or refuse it.
 *
 * @param array<string,string> $subjects  kind => subject, for EVERY kind in the
 *                                        scope's policy (a missing kind throws,
 *                                        so a caller cannot silently skip a limit)
 * @return array{allowed:bool, retry_after:int, denied:list<string>, id:string, scope:string, keys:array<string,array<string,mixed>>}
 *         `denied` lists the counter kinds that refused the attempt.
 */
function throttle_reserve(string $scope, array $subjects, ?int $now = null): array
{
    $now ??= time();
    $keys = throttle_keys_for($scope, $subjects);
    $ticket = [
        'allowed' => false, 'retry_after' => 0, 'denied' => [],
        'id' => bin2hex(random_bytes(8)), 'scope' => $scope, 'keys' => $keys,
    ];

    throttle_maybe_prune($now);

    [$ticket, $started] = throttle_transaction($keys, $now, static function (array $rows) use ($keys, $now, $ticket): array {
        $started = [];
        $states = [];
        foreach ($keys as $key => $rule) {
            [$state, $cooldown] = throttle_normalize($rows[$key], $rule, $now);
            if ($cooldown !== null) {
                $started[] = $cooldown;
            }
            $states[$key] = $state;

            $refusal = throttle_refusal($state, $rule, $now);
            if ($refusal > 0) {
                $ticket['retry_after'] = max($ticket['retry_after'], $refusal);
                $ticket['denied'][] = $rule['kind'];
            }
        }

        // All-or-nothing: a refused attempt books nothing on any key. Expired
        // bookings / windows found above are still saved either way.
        if ($ticket['denied'] === []) {
            $ticket['allowed'] = true;
            foreach ($states as &$state) {
                $state['pending']++;
                $state['pending_expires_at'] = $now + AUTH_THROTTLE_PENDING_TTL;
            }
            unset($state);
        }
        return [$states, [$ticket, $started]];
    });

    throttle_log_cooldowns($ticket['scope'], $started, null);
    if ($ticket['allowed']) {
        throttle_track($ticket);
    }
    return $ticket;
}

/**
 * The reserved attempt failed. Records the failure on every key that counts
 * failures, and starts a cooldown on any whose budget of COMPLETED failures is
 * now used up. Logs one audit event per cooldown started (never per attempt,
 * so an attack cannot flood the audit log through this path).
 *
 * @param int|null $auditUserId  Account the attempt targeted, if known (logging only).
 * @return list<array{kind:string, level:int, seconds:int}>  cooldowns started
 */
function throttle_failure(array $ticket, ?int $auditUserId = null, ?int $now = null): array
{
    return throttle_resolve($ticket, 'failure', $auditUserId, $now);
}

/**
 * The reserved attempt succeeded: release its booking, count it on quota
 * keys, and clear failure counts where the policy says so — but never while a
 * cooldown is running (that cooldown was earned by other requests).
 */
function throttle_success(array $ticket, ?int $now = null): void
{
    throttle_resolve($ticket, 'success', null, $now);
}

/**
 * Record every still-unresolved ticket of this request as a failure. Runs
 * automatically at shutdown, so a fatal error or timeout between reserving and
 * resolving cannot be used to get guesses for free.
 */
function throttle_resolve_abandoned(): void
{
    foreach (throttle_open_tickets() as $ticket) {
        try {
            throttle_failure($ticket);
        } catch (Throwable $e) {
            error_log('[Aurelia Bank] Could not resolve abandoned throttle ticket: ' . $e->getMessage());
        }
    }
}

/**
 * The user-facing message for a refused attempt. Deliberately identical for
 * existing and non-existent accounts.
 */
function throttle_message(int $retryAfter, string $what = 'sign-in attempts'): string
{
    return 'Too many ' . $what . '. Please wait ' . format_wait($retryAfter) . ' and try again.';
}

/** Send 429 + Retry-After so scripted clients get the same answer as the form. */
function send_throttle_headers(int $retryAfter): void
{
    if (!headers_sent()) {
        http_response_code(429);
        header('Retry-After: ' . max(1, $retryAfter));
    }
}

/** "45 seconds", "1 minute", "15 minutes" (rounded up, never "0 seconds"). */
function format_wait(int $seconds): string
{
    $seconds = max(1, $seconds);
    if ($seconds < 60) {
        return $seconds . ($seconds === 1 ? ' second' : ' seconds');
    }
    $minutes = (int) ceil($seconds / 60);
    return $minutes . ($minutes === 1 ? ' minute' : ' minutes');
}

// -----------------------------------------------------------------------------
// Internals
// -----------------------------------------------------------------------------

/**
 * @return list<array{kind:string, level:int, seconds:int}>
 */
function throttle_resolve(array $ticket, string $outcome, ?int $auditUserId, ?int $now): array
{
    // Only a ticket this request booked and has not resolved yet: resolving
    // twice (or a refused / forged ticket) must not move any counter.
    if (empty($ticket['allowed']) || !throttle_untrack($ticket)) {
        return [];
    }
    $now ??= time();
    $keys = $ticket['keys'];

    $started = throttle_transaction($keys, $now, static function (array $rows) use ($keys, $now, $outcome): array {
        $started = [];
        $states = [];
        foreach ($keys as $key => $rule) {
            [$state, $cooldown] = throttle_normalize($rows[$key], $rule, $now);
            if ($cooldown !== null) {
                $started[] = $cooldown;
            }

            $state['pending'] = max(0, $state['pending'] - 1);
            if ($state['pending'] === 0) {
                $state['pending_expires_at'] = null;
            }

            $coolingDown = $state['locked_until'] !== null && $state['locked_until'] > $now;
            if ($outcome === $rule['counts']) {
                $state['completed']++;
                $cooldown = throttle_start_cooldown($state, $rule, $now);
                if ($cooldown !== null) {
                    $started[] = $cooldown;
                }
            } elseif ($outcome === 'success' && $rule['reset_on_success'] && !$coolingDown) {
                $state['completed'] = 0;
                $state['lock_level'] = 0;
            }
            $states[$key] = $state;
        }
        return [$states, $started];
    });

    throttle_log_cooldowns($ticket['scope'], $started, $auditUserId);
    return $started;
}

/**
 * Bring a locked row up to date at $now: count expired bookings as consumed,
 * decay old escalation, and open a fresh window once the old one (or the last
 * cooldown) is over. May start a cooldown if expired bookings fill the budget.
 *
 * @return array{0:array<string,?int>, 1:array{kind:string,level:int,seconds:int}|null}
 */
function throttle_normalize(array $row, array $rule, int $now): array
{
    $int = static fn ($v): ?int => $v === null ? null : (int) $v;
    $s = [
        'completed'          => (int) $row['completed'],
        'pending'            => (int) $row['pending'],
        'pending_expires_at' => $int($row['pending_expires_at']),
        'window_started_at'  => (int) $row['window_started_at'],
        'locked_until'       => $int($row['locked_until']),
        'lock_level'         => (int) $row['lock_level'],
    ];

    // Bookings whose request never reported back: count them, fail safe.
    if ($s['pending'] > 0 && $s['pending_expires_at'] !== null && $s['pending_expires_at'] <= $now) {
        $s['completed'] += $s['pending'];
        $s['pending'] = 0;
        $s['pending_expires_at'] = null;
    }
    // A quiet spell since the last cooldown resets the escalation.
    if ($s['lock_level'] > 0 && $s['locked_until'] !== null && $now - $s['locked_until'] >= AUTH_THROTTLE_LEVEL_DECAY) {
        $s['lock_level'] = 0;
    }
    // Fresh budget once the window has passed or a cooldown has ended.
    $coolingDown = $s['locked_until'] !== null && $s['locked_until'] > $now;
    if (!$coolingDown) {
        $cooldownEnded = $s['locked_until'] !== null && $s['locked_until'] > $s['window_started_at'];
        if ($now - $s['window_started_at'] >= $rule['window'] || $cooldownEnded) {
            $s['completed'] = 0;
            $s['window_started_at'] = $now;
        }
    }
    return [$s, throttle_start_cooldown($s, $rule, $now)];
}

/**
 * Start a cooldown on a failure-counting key whose COMPLETED failures have
 * reached the limit (pending bookings never trigger one).
 *
 * @return array{kind:string, level:int, seconds:int}|null
 */
function throttle_start_cooldown(array &$s, array $rule, int $now): ?array
{
    $coolingDown = $s['locked_until'] !== null && $s['locked_until'] > $now;
    if ($rule['counts'] !== 'failure' || $coolingDown || $s['completed'] < $rule['limit']) {
        return null;
    }
    $s['lock_level'] = min($s['lock_level'] + 1, 255);
    $seconds = throttle_cooldown_seconds($s['lock_level']);
    $s['locked_until'] = $now + $seconds;
    return ['kind' => $rule['kind'], 'level' => $s['lock_level'], 'seconds' => $seconds];
}

/** Seconds until a key would accept a new booking, or 0 if it would now. */
function throttle_refusal(array $s, array $rule, int $now): int
{
    if ($s['locked_until'] !== null && $s['locked_until'] > $now) {
        return $s['locked_until'] - $now;
    }
    if ($s['completed'] + $s['pending'] < $rule['limit']) {
        return 0;
    }
    $windowLeft = $s['window_started_at'] + $rule['window'] - $now;
    if ($rule['counts'] === 'success' && $s['completed'] >= $rule['limit']) {
        return max(1, $windowLeft);   // quota used up: wait for the window
    }
    // Budget full of in-flight attempts that have not resolved yet (concurrent
    // burst): refuse for about as long as the next cooldown would be.
    return max(1, min($windowLeft, throttle_cooldown_seconds($s['lock_level'] + 1)));
}

/** @param list<array{kind:string,level:int,seconds:int}> $started */
function throttle_log_cooldowns(string $scope, array $started, ?int $auditUserId): void
{
    foreach ($started as $c) {
        log_audit($auditUserId, 'auth.throttle.cooldown', sprintf(
            'scope=%s kind=%s level=%d cooldown=%ds',
            $scope, $c['kind'], $c['level'], $c['seconds']
        ));
    }
}

/**
 * Tickets this request has booked but not resolved yet (by ticket id).
 *
 * @return array<string, array<string,mixed>>
 */
function &throttle_open_tickets(): array
{
    static $open = [];
    return $open;
}

function throttle_track(array $ticket): void
{
    static $hooked = false;
    if (!$hooked) {
        register_shutdown_function('throttle_resolve_abandoned');
        $hooked = true;
    }
    $open = &throttle_open_tickets();
    $open[$ticket['id']] = $ticket;
}

/** Stop tracking a ticket; false if it was not open (already resolved / never booked). */
function throttle_untrack(array $ticket): bool
{
    $open = &throttle_open_tickets();
    if (!isset($ticket['id'], $open[$ticket['id']])) {
        return false;
    }
    unset($open[$ticket['id']]);
    return true;
}

/**
 * @return array<string, array<string,mixed>>  sorted by key
 */
function throttle_keys_for(string $scope, array $subjects): array
{
    $policy = AUTH_THROTTLE_POLICIES[$scope] ?? null;
    if ($policy === null) {
        throw new InvalidArgumentException("Unknown throttle scope '$scope'.");
    }
    $keys = [];
    foreach ($policy as $kind => $rule) {
        if (!isset($subjects[$kind]) || $subjects[$kind] === '') {
            throw new InvalidArgumentException("Throttle scope '$scope' requires a '$kind' subject.");
        }
        $keys[throttle_key($scope, $kind, $subjects[$kind])] = ['scope' => $scope, 'kind' => $kind] + $rule;
    }
    // A consistent lock order across requests avoids deadlocks between them.
    ksort($keys);
    return $keys;
}

/**
 * Lock the rows for $keys (creating any that are missing), let $work compute
 * their new state, save it and commit.
 *
 * $work receives the locked rows (by key) and returns [new states by key,
 * result]; this function returns that result.
 *
 * Rows are created with INSERT IGNORE in autocommit mode BEFORE the transaction
 * starts: inserting inside it would take a shared lock that two concurrent
 * requests would then both try to upgrade for FOR UPDATE — a deadlock. Locks
 * are taken in key order, and InnoDB deadlock / lock-wait errors (expected
 * under a concurrent burst) are retried.
 *
 * @template T
 * @param callable(array<string, array<string,mixed>>): array{0:array<string,array<string,?int>>, 1:T} $work
 * @return T
 */
function throttle_transaction(array $keys, int $now, callable $work): mixed
{
    $pdo = db();
    if ($pdo->inTransaction()) {
        throw new LogicException('Throttle operations must not run inside another transaction.');
    }

    $insert = $pdo->prepare(
        'INSERT IGNORE INTO auth_throttle
             (throttle_key, scope, kind, completed, pending, window_started_at, lock_level, updated_at)
         VALUES (:k, :scope, :kind, 0, 0, :window_start, 0, :now)'
    );
    $params = [];
    foreach (array_keys($keys) as $i => $key) {
        $params[':k' . $i] = $key;
    }
    $select = $pdo->prepare(
        'SELECT throttle_key, completed, pending, pending_expires_at,
                window_started_at, locked_until, lock_level
           FROM auth_throttle
          WHERE throttle_key IN (' . implode(', ', array_keys($params)) . ')
          ORDER BY throttle_key
            FOR UPDATE'
    );
    $update = $pdo->prepare(
        'UPDATE auth_throttle
            SET completed = :completed, pending = :pending, pending_expires_at = :pending_expires,
                window_started_at = :window_start, locked_until = :locked_until,
                lock_level = :level, updated_at = :now
          WHERE throttle_key = :k'
    );

    for ($try = 1; ; $try++) {
        try {
            foreach ($keys as $key => $rule) {
                $insert->execute([
                    ':k' => $key, ':scope' => $rule['scope'], ':kind' => $rule['kind'],
                    ':window_start' => $now, ':now' => $now,
                ]);
            }

            $pdo->beginTransaction();
            $select->execute($params);
            $rows = [];
            foreach ($select->fetchAll() as $row) {
                $rows[$row['throttle_key']] = $row;
            }
            if (count($rows) !== count($keys)) {
                // A row was pruned between the insert and the lock: go round again.
                $pdo->rollBack();
                if ($try >= 5) {
                    throw new RuntimeException('Could not acquire throttle rows.');
                }
                continue;
            }

            [$states, $result] = $work($rows);
            foreach ($states as $key => $s) {
                $update->execute([
                    ':completed' => $s['completed'], ':pending' => $s['pending'],
                    ':pending_expires' => $s['pending_expires_at'],
                    ':window_start' => $s['window_started_at'], ':locked_until' => $s['locked_until'],
                    ':level' => $s['lock_level'], ':now' => $now, ':k' => $key,
                ]);
            }
            $pdo->commit();
            return $result;
        } catch (PDOException $e) {
            if ($pdo->inTransaction()) {
                $pdo->rollBack();
            }
            $retryable = in_array((int) ($e->errorInfo[1] ?? 0), [1205, 1213], true);
            if (!$retryable || $try >= 5) {
                throw $e;
            }
            usleep(random_int(5_000, 25_000) * $try);
        } catch (Throwable $e) {
            if ($pdo->inTransaction()) {
                $pdo->rollBack();
            }
            throw $e;
        }
    }
}

/**
 * Occasionally delete rows nobody has touched for a day and that are not
 * cooling down or holding bookings, so the table does not grow without bound.
 */
function throttle_maybe_prune(int $now): void
{
    if (random_int(1, 100) !== 1) {
        return;
    }
    try {
        $stmt = db()->prepare(
            'DELETE FROM auth_throttle
              WHERE updated_at < :cutoff
                AND pending = 0
                AND (locked_until IS NULL OR locked_until < :now)'
        );
        $stmt->execute([':cutoff' => $now - 86400, ':now' => $now]);
    } catch (Throwable $e) {
        error_log('[Aurelia Bank] Throttle prune failed: ' . $e->getMessage());
    }
}
