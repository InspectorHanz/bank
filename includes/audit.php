<?php
/**
 * Aurelia Bank — Audit Logging
 * -----------------------------------------------------------------------------
 * Records high-level, security-relevant actions (profile changes, admin actions)
 * to the audit_logs table. Useful operational hygiene now, and evidence during
 * the later CSRF demonstration.
 *
 * Logging must never break the action it is recording: failures are logged to
 * the PHP error log and swallowed.
 */

declare(strict_types=1);

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/functions.php';

/**
 * Write an audit entry.
 *
 * @param int|null $userId  The acting user (nullable for anonymous events).
 * @param string   $action  Short machine-ish label, e.g. 'profile.update'.
 * @param string|null $details  Optional human-readable detail.
 */
function log_audit(?int $userId, string $action, ?string $details = null): void
{
    try {
        $stmt = db()->prepare(
            'INSERT INTO audit_logs (user_id, action, details, ip_address)
             VALUES (:uid, :action, :details, :ip)'
        );
        $stmt->execute([
            ':uid'     => $userId,
            ':action'  => mb_substr($action, 0, 80),
            ':details' => $details !== null ? mb_substr($details, 0, 2000) : null,
            ':ip'      => client_ip(),
        ]);
    } catch (Throwable $e) {
        error_log('[Aurelia Bank] Failed to write audit log: ' . $e->getMessage());
    }
}
