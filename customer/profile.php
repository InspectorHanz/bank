<?php
/**
 * Aurelia Bank — Profile & Account Settings (Phase 5)
 * -----------------------------------------------------------------------------
 * Two independent settings forms:
 *   1. Personal details  (name, email, phone, address)  — update processing
 *   2. Change password   (current + new + confirm)
 *
 * Both use server-side validation (authoritative) plus client-side validation
 * (convenience, in assets/js/app.js), output escaping, prepared statements, and
 * the Post/Redirect/Get pattern so a refresh does not resubmit.
 *
 * CSRF HARDENING (Phase 7 — fixed):
 *   The "personal details" (and password) updates are state-changing actions
 *   that were the CSRF demonstration target. They are now protected with a
 *   synchroniser CSRF token (see includes/csrf.php): every POST must carry the
 *   session's token, and a forged cross-site request cannot read it. Combined
 *   with the SameSite=Lax session cookie (see includes/session.php), the attack
 *   in security-tests/csrf_poc.html no longer works.
 */

declare(strict_types=1);

require_once __DIR__ . '/../includes/bootstrap.php';
require_once __DIR__ . '/../includes/csrf.php';
require_once __DIR__ . '/../includes/audit.php';

require_role('customer');

$sessionUser = current_user();
$userId      = $sessionUser['id'];

// Load the authoritative record from the database.
$record = find_user_by_id($userId);
if ($record === null) {
    logout_user();
    redirect('auth/login.php');
}

$profileErrors = [];
$passwordErrors = [];

// Values shown in the profile form (DB values by default; POSTed on error).
$fullName = $record['full_name'];
$email    = $record['email'];
$phone    = (string) ($record['phone'] ?? '');
$address  = (string) ($record['address'] ?? '');

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // CSRF defence: reject any POST that does not carry the session's token.
    // A forged cross-site request cannot read this token, so it is stopped here
    // before any database update happens.
    if (!csrf_verify()) {
        set_flash('error', 'Your session has expired or the request could not be verified. Please try again.');
        redirect('customer/profile.php');
    }

    $form = (string) ($_POST['form'] ?? '');

    // -------------------------------------------------------------------------
    // 1. Personal details
    // -------------------------------------------------------------------------
    if ($form === 'profile') {
        $fullName = trim((string) ($_POST['full_name'] ?? ''));
        $email    = trim((string) ($_POST['email'] ?? ''));
        $phone    = trim((string) ($_POST['phone'] ?? ''));
        $address  = trim((string) ($_POST['address'] ?? ''));

        if ($fullName === '' || mb_strlen($fullName) < 2 || mb_strlen($fullName) > 120) {
            $profileErrors['full_name'] = 'Please enter your full name (2–120 characters).';
        }
        if ($email === '' || !filter_var($email, FILTER_VALIDATE_EMAIL) || mb_strlen($email) > 255) {
            $profileErrors['email'] = 'Please enter a valid email address.';
        }
        if ($phone !== '' && !preg_match('/^[0-9 +()\-]{6,30}$/', $phone)) {
            $profileErrors['phone'] = 'Please enter a valid phone number.';
        }
        if (mb_strlen($address) > 255) {
            $profileErrors['address'] = 'Address is too long (max 255 characters).';
        }

        // Email must be unique across other users. "Already in use" confirms
        // that some other customer has that address, so the check only runs
        // when it is needed (everything else valid, address actually changing)
        // and those probes are rate-limited per account and per client IP.
        if (!$profileErrors && strcasecmp($email, (string) $record['email']) !== 0) {
            $ticket = throttle_reserve('email_change', [
                'account' => 'user:' . $userId,
                'ip'      => throttle_ip_subject(client_ip()),
            ]);
            if (!$ticket['allowed']) {
                send_throttle_headers($ticket['retry_after']);
                $profileErrors['email'] = throttle_message($ticket['retry_after'], 'email address changes');
            } else {
                $chk = db()->prepare('SELECT id FROM users WHERE email = :email AND id <> :id LIMIT 1');
                $chk->execute([':email' => $email, ':id' => $userId]);
                if ($chk->fetch() !== false) {
                    throttle_failure($ticket, $userId);
                    $profileErrors['email'] = 'That email address is already in use.';
                } else {
                    throttle_success($ticket);
                }
            }
        }

        if (!$profileErrors) {
            $stmt = db()->prepare(
                'UPDATE users
                    SET full_name = :full_name, email = :email,
                        phone = :phone, address = :address
                  WHERE id = :id'
            );
            $stmt->execute([
                ':full_name' => $fullName,
                ':email'     => $email,
                ':phone'     => $phone !== '' ? $phone : null,
                ':address'   => $address !== '' ? $address : null,
                ':id'        => $userId,
            ]);

            // Keep the session snapshot in step with the updated name.
            $_SESSION['user']['full_name'] = $fullName;

            log_audit($userId, 'profile.update', 'Updated personal details');
            set_flash('success', 'Your details have been updated.');
            redirect('customer/profile.php');
        }
    }

    // -------------------------------------------------------------------------
    // 2. Change password
    // -------------------------------------------------------------------------
    if ($form === 'password') {
        $current = (string) ($_POST['current_password'] ?? '');
        $new     = (string) ($_POST['new_password'] ?? '');
        $confirm = (string) ($_POST['confirm_password'] ?? '');

        // Re-checking the current password is itself a guessing oracle (e.g. for
        // someone holding a stolen session), so it is throttled per account.
        if ($current === '') {
            $passwordErrors['current_password'] = 'Your current password is incorrect.';
        } else {
            $ticket = throttle_reserve('password_change', ['account' => 'user:' . $userId]);
            if (!$ticket['allowed']) {
                send_throttle_headers($ticket['retry_after']);
                $passwordErrors['current_password'] = throttle_message($ticket['retry_after'], 'incorrect password attempts');
            } elseif (password_verify($current, $record['password_hash'])) {
                throttle_success($ticket);
            } else {
                throttle_failure($ticket, $userId);
                $passwordErrors['current_password'] = 'Your current password is incorrect.';
            }
        }
        if (mb_strlen($new) < 8) {
            $passwordErrors['new_password'] = 'New password must be at least 8 characters.';
        }
        if ($new !== $confirm) {
            $passwordErrors['confirm_password'] = 'The new passwords do not match.';
        }
        if (!isset($passwordErrors['new_password']) && !isset($passwordErrors['current_password']) && $new === $current) {
            $passwordErrors['new_password'] = 'Please choose a password different from your current one.';
        }

        if (!$passwordErrors) {
            $stmt = db()->prepare('UPDATE users SET password_hash = :hash WHERE id = :id');
            $stmt->execute([
                ':hash' => password_hash($new, PASSWORD_DEFAULT),
                ':id'   => $userId,
            ]);

            log_audit($userId, 'password.change', 'Changed account password');
            set_flash('success', 'Your password has been changed.');
            redirect('customer/profile.php');
        }
    }
}

$pageTitle = 'Profile & settings';
$activeNav = 'profile';

require __DIR__ . '/../includes/header.php';
?>

<section class="section">
    <div class="container">
        <div class="page-header">
            <div>
                <h1 class="mt-0">Profile &amp; settings</h1>
                <p class="text-muted mb-0">Manage your personal details and password.</p>
            </div>
        </div>

        <div class="grid grid--2" style="margin-top:1.5rem; align-items:start;">
            <!-- Personal details ----------------------------------------->
            <div class="card">
                <h2 class="card__title mt-0">Personal details</h2>

                <form method="post" action="<?= e(base_url('customer/profile.php')) ?>" novalidate data-validate>
                    <?= csrf_field() ?>
                    <input type="hidden" name="form" value="profile">

                    <div class="form-group">
                        <label class="label" for="username">Username</label>
                        <input class="input" type="text" id="username" value="<?= e($record['username']) ?>" disabled>
                        <p class="field-hint">Your username cannot be changed.</p>
                    </div>

                    <div class="form-group">
                        <label class="label" for="full_name">Full name</label>
                        <input class="input<?= isset($profileErrors['full_name']) ? ' input--error' : '' ?>"
                               type="text" id="full_name" name="full_name"
                               value="<?= e($fullName) ?>" required minlength="2" maxlength="120">
                        <?php if (isset($profileErrors['full_name'])): ?>
                            <p class="field-error"><?= e($profileErrors['full_name']) ?></p>
                        <?php endif; ?>
                    </div>

                    <div class="form-group">
                        <label class="label" for="email">Email</label>
                        <input class="input<?= isset($profileErrors['email']) ? ' input--error' : '' ?>"
                               type="email" id="email" name="email"
                               value="<?= e($email) ?>" required maxlength="255">
                        <?php if (isset($profileErrors['email'])): ?>
                            <p class="field-error"><?= e($profileErrors['email']) ?></p>
                        <?php endif; ?>
                    </div>

                    <div class="form-group">
                        <label class="label" for="phone">Phone <span class="text-muted">(optional)</span></label>
                        <input class="input<?= isset($profileErrors['phone']) ? ' input--error' : '' ?>"
                               type="tel" id="phone" name="phone" value="<?= e($phone) ?>" maxlength="30">
                        <?php if (isset($profileErrors['phone'])): ?>
                            <p class="field-error"><?= e($profileErrors['phone']) ?></p>
                        <?php endif; ?>
                    </div>

                    <div class="form-group">
                        <label class="label" for="address">Address <span class="text-muted">(optional)</span></label>
                        <textarea class="textarea<?= isset($profileErrors['address']) ? ' input--error' : '' ?>"
                                  id="address" name="address" rows="2" maxlength="255"><?= e($address) ?></textarea>
                        <?php if (isset($profileErrors['address'])): ?>
                            <p class="field-error"><?= e($profileErrors['address']) ?></p>
                        <?php endif; ?>
                    </div>

                    <button type="submit" class="btn btn--primary">Save changes</button>
                </form>
            </div>

            <!-- Change password ------------------------------------------>
            <div class="card">
                <h2 class="card__title mt-0">Change password</h2>

                <form method="post" action="<?= e(base_url('customer/profile.php')) ?>" novalidate data-validate>
                    <?= csrf_field() ?>
                    <input type="hidden" name="form" value="password">

                    <div class="form-group">
                        <label class="label" for="current_password">Current password</label>
                        <input class="input<?= isset($passwordErrors['current_password']) ? ' input--error' : '' ?>"
                               type="password" id="current_password" name="current_password"
                               autocomplete="current-password" required>
                        <?php if (isset($passwordErrors['current_password'])): ?>
                            <p class="field-error"><?= e($passwordErrors['current_password']) ?></p>
                        <?php endif; ?>
                    </div>

                    <div class="form-group">
                        <label class="label" for="new_password">New password</label>
                        <input class="input<?= isset($passwordErrors['new_password']) ? ' input--error' : '' ?>"
                               type="password" id="new_password" name="new_password"
                               autocomplete="new-password" required minlength="8">
                        <?php if (isset($passwordErrors['new_password'])): ?>
                            <p class="field-error"><?= e($passwordErrors['new_password']) ?></p>
                        <?php else: ?>
                            <p class="field-hint">At least 8 characters.</p>
                        <?php endif; ?>
                    </div>

                    <div class="form-group">
                        <label class="label" for="confirm_password">Confirm new password</label>
                        <input class="input<?= isset($passwordErrors['confirm_password']) ? ' input--error' : '' ?>"
                               type="password" id="confirm_password" name="confirm_password"
                               autocomplete="new-password" required data-match="#new_password">
                        <?php if (isset($passwordErrors['confirm_password'])): ?>
                            <p class="field-error"><?= e($passwordErrors['confirm_password']) ?></p>
                        <?php endif; ?>
                    </div>

                    <button type="submit" class="btn btn--primary">Update password</button>
                </form>
            </div>
        </div>
    </div>
</section>

<?php require __DIR__ . '/../includes/footer.php'; ?>
