<?php
/**
 * Aurelia Bank — Customer Login (page + processing)
 * -----------------------------------------------------------------------------
 * The public online-banking login. It authenticates CUSTOMER accounts only —
 * staff sign in through the separate admin portal (admin/login.php), which is
 * not linked from the public site. Authorization (require_role) remains the real
 * boundary; the separate URL is defense-in-depth, not the primary control.
 *
 * This is the customer-facing authentication flow and the primary target for
 * the later brute-force demonstration (no separate "attack" page). It shares the
 * authenticate() helper with the admin portal.
 *
 * Clean, secure defaults used here:
 *   - Prepared statement to look up the user (see includes/auth.php).
 *   - password_verify() against a password_hash() hash — never plaintext.
 *   - A single GENERIC error for bad username OR bad password (and for an admin
 *     credential used here), so the form reveals nothing about which accounts
 *     exist or which portal they belong to.
 *   - session_regenerate_id() on success (session-fixation protection).
 *   - Account status checked (locked/disabled accounts cannot sign in).
 *   - Brute-force throttling inside authenticate() (includes/throttle.php):
 *     repeated failures earn temporary, escalating cooldowns, answered with
 *     HTTP 429 + Retry-After and a "please wait N minutes" message.
 */

declare(strict_types=1);

require_once __DIR__ . '/../includes/bootstrap.php';

// Already signed in? Skip the form and go to the right dashboard.
if (is_logged_in()) {
    redirect(role_home(current_user_role()));
}

$errors   = [];          // field-level validation errors
$formError = '';         // top-level (generic) authentication error
$username = '';          // preserved so the field is not cleared on error

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // 1. Read + normalise input.
    $username = trim((string) ($_POST['username'] ?? ''));
    $password = (string) ($_POST['password'] ?? '');

    // 2. Server-side validation (never trust the client).
    if ($username === '') {
        $errors['username'] = 'Please enter your username.';
    }
    if ($password === '') {
        $errors['password'] = 'Please enter your password.';
    }

    // 3. Attempt authentication (customer accounts only) if the form is valid.
    if (!$errors) {
        $result = authenticate($username, $password, 'customer');

        if (!$result['ok']) {
            $formError = $result['error'];
            if (!empty($result['throttled'])) {
                send_throttle_headers($result['retry_after']);
            }
        } else {
            $user = $result['user'];

            // Success — establish the session.
            login_user($user);

            // Return the user to where they were heading, if that was a safe,
            // same-origin path; otherwise their dashboard.
            $returnTo = (string) ($_SESSION['_return_to'] ?? '');
            unset($_SESSION['_return_to']);

            if ($returnTo !== ''
                && str_starts_with($returnTo, '/')
                && !str_starts_with($returnTo, '//')
            ) {
                header('Location: ' . $returnTo);
                exit;
            }

            set_flash('success', 'Welcome back, ' . $user['full_name'] . '.');
            redirect(role_home($user['role']));
        }
    }
}

$pageTitle = 'Log in';
$activeNav = '';

require __DIR__ . '/../includes/header.php';
?>

<section class="section">
    <div class="container">
        <div class="auth-wrap">
            <div class="auth-card card">
                <div class="auth-card__head">
                    <h1 class="mt-0">Online banking</h1>
                    <p class="text-muted mb-0">Log in to view your accounts and recent activity.</p>
                </div>

                <?php if ($formError !== ''): ?>
                    <div class="alert alert--error" role="alert"><?= e($formError) ?></div>
                <?php endif; ?>

                <form method="post" action="<?= e(base_url('auth/login.php')) ?>"
                      novalidate data-validate>
                    <div class="form-group">
                        <label class="label" for="username">Username</label>
                        <input
                            class="input<?= isset($errors['username']) ? ' input--error' : '' ?>"
                            type="text" id="username" name="username"
                            value="<?= e($username) ?>"
                            autocomplete="username" required autofocus>
                        <?php if (isset($errors['username'])): ?>
                            <p class="field-error"><?= e($errors['username']) ?></p>
                        <?php endif; ?>
                    </div>

                    <div class="form-group">
                        <label class="label" for="password">Password</label>
                        <input
                            class="input<?= isset($errors['password']) ? ' input--error' : '' ?>"
                            type="password" id="password" name="password"
                            autocomplete="current-password" required>
                        <?php if (isset($errors['password'])): ?>
                            <p class="field-error"><?= e($errors['password']) ?></p>
                        <?php endif; ?>
                    </div>

                    <button type="submit" class="btn btn--primary btn--block">Log in</button>
                </form>

                <p class="text-center mt-2 mb-0" style="font-size:.9rem;">
                    New to Aurelia Bank? <a href="<?= e(base_url('auth/register.php')) ?>">Open an account</a>
                </p>
                <p class="text-muted text-center mb-0" style="font-size:.85rem;">
                    Fictional demo bank · use only your provided test credentials.
                </p>
            </div>
        </div>
    </div>
</section>

<?php require __DIR__ . '/../includes/footer.php'; ?>
