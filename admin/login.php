<?php
/**
 * Aurelia Bank — Staff (Admin) Login
 * -----------------------------------------------------------------------------
 * A SEPARATE login portal for administrators, deliberately not linked from any
 * public page so its URL is known only to staff. This is defense-in-depth /
 * obscurity — the real access control is require_role('admin') on every admin
 * page, which is enforced regardless of how someone reaches this form.
 *
 * It authenticates ADMIN accounts only: a customer credential entered here fails
 * with the same generic message as a wrong password (no cross-portal
 * enumeration). It shares the authenticate() helper — and therefore the same
 * brute-force throttle budget — with the customer login.
 */

declare(strict_types=1);

require_once __DIR__ . '/../includes/bootstrap.php';

// Already signed in? Send them to the right home for their role.
if (is_logged_in()) {
    redirect(role_home(current_user_role()));
}

$formError = '';
$username  = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim((string) ($_POST['username'] ?? ''));
    $password = (string) ($_POST['password'] ?? '');

    $errors = [];
    if ($username === '') {
        $errors['username'] = 'Please enter your username.';
    }
    if ($password === '') {
        $errors['password'] = 'Please enter your password.';
    }

    if (!$errors) {
        $result = authenticate($username, $password, 'admin');

        if (!$result['ok']) {
            $formError = $result['error'];
            if (!empty($result['throttled'])) {
                send_throttle_headers($result['retry_after']);
            }
        } else {
            login_user($result['user']);

            $returnTo = (string) ($_SESSION['_return_to'] ?? '');
            unset($_SESSION['_return_to']);

            if ($returnTo !== ''
                && str_starts_with($returnTo, '/')
                && !str_starts_with($returnTo, '//')
            ) {
                header('Location: ' . $returnTo);
                exit;
            }

            set_flash('success', 'Signed in to the admin area.');
            redirect('admin/dashboard.php');
        }
    } else {
        $formError = 'Please enter your username and password.';
    }
}

$pageTitle = 'Staff sign in';
$hideNav   = true;   // austere staff portal — no public nav / CTAs

require __DIR__ . '/../includes/header.php';
?>

<section class="section">
    <div class="container">
        <div class="auth-wrap">
            <div class="auth-card card">
                <div class="auth-card__head">
                    <h1 class="mt-0">Staff sign in</h1>
                    <p class="text-muted mb-0">Authorized administrators only.</p>
                </div>

                <?php if ($formError !== ''): ?>
                    <div class="alert alert--error" role="alert"><?= e($formError) ?></div>
                <?php endif; ?>

                <form method="post" action="<?= e(base_url('admin/login.php')) ?>" novalidate data-validate>
                    <div class="form-group">
                        <label class="label" for="username">Username</label>
                        <input class="input" type="text" id="username" name="username"
                               value="<?= e($username) ?>" autocomplete="username" required autofocus>
                    </div>

                    <div class="form-group">
                        <label class="label" for="password">Password</label>
                        <input class="input" type="password" id="password" name="password"
                               autocomplete="current-password" required>
                    </div>

                    <button type="submit" class="btn btn--primary btn--block">Sign in</button>
                </form>
            </div>
        </div>
    </div>
</section>

<?php require __DIR__ . '/../includes/footer.php'; ?>
