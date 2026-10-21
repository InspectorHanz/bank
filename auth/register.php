<?php
/**
 * Aurelia Bank — Open an Account (Registration)
 * -----------------------------------------------------------------------------
 * Public self-service registration. On success it creates the customer AND opens
 * their first (checking) account in a single database transaction, then signs
 * them in and sends them to their dashboard, where they can fund the account
 * via the Deposit page.
 *
 * Clean, secure defaults:
 *   - Server-side validation (authoritative) + client-side validation (app.js).
 *   - password_hash() for the password; uniqueness enforced by DB constraints
 *     and checked up front for friendly messages.
 *   - Prepared statements throughout; output escaping on redisplay.
 *
 * (No CSRF token here, consistent with the login form: a forged registration
 * creates an account the attacker controls, which is not a meaningful attack.
 * The money-movement forms are the ones that carry CSRF tokens.)
 *
 * The "username already taken" / "email already registered" answers
 * necessarily reveal that an account exists. To keep that from becoming a free
 * enumeration tool (includes/throttle.php, scope 'register'):
 *   - they are only given for an otherwise valid submission — so every probe
 *     either fails (spending the per-IP failed-submission budget) or really
 *     opens an account (spending the per-IP new-account quota);
 *   - both budgets are per client IP; neither is refunded by the other.
 */

declare(strict_types=1);

require_once __DIR__ . '/../includes/bootstrap.php';
require_once __DIR__ . '/../includes/banking.php';
require_once __DIR__ . '/../includes/audit.php';

// Already signed in? No need to register.
if (is_logged_in()) {
    redirect(role_home(current_user_role()));
}

/**
 * Server-side format validation for the registration form (no database
 * lookups — see registration_conflicts()).
 *
 * @return array<string,string>  field => error message (empty when valid)
 */
function validate_registration(
    string $fullName, string $username, string $email, string $phone, string $password, string $confirm
): array {
    $errors = [];
    if ($fullName === '' || mb_strlen($fullName) < 2 || mb_strlen($fullName) > 120) {
        $errors['full_name'] = 'Please enter your full name (2–120 characters).';
    }
    if (!preg_match('/^[a-zA-Z0-9._]{3,50}$/', $username)) {
        $errors['username'] = 'Username must be 3–50 characters: letters, numbers, dot or underscore.';
    }
    if ($email === '' || !filter_var($email, FILTER_VALIDATE_EMAIL) || mb_strlen($email) > 255) {
        $errors['email'] = 'Please enter a valid email address.';
    }
    if ($phone !== '' && !preg_match('/^[0-9 +()\-]{6,30}$/', $phone)) {
        $errors['phone'] = 'Please enter a valid phone number.';
    }
    if (mb_strlen($password) < 8) {
        $errors['password'] = 'Password must be at least 8 characters.';
    }
    if ($password !== $confirm) {
        $errors['confirm_password'] = 'The passwords do not match.';
    }
    return $errors;
}

/**
 * Uniqueness checks. Only called for an otherwise valid submission, so that
 * an "already taken" answer always costs a failed (rate-limited) attempt.
 *
 * @return array<string,string>
 */
function registration_conflicts(string $username, string $email): array
{
    $errors = [];
    if (username_exists($username)) {
        $errors['username'] = 'That username is already taken.';
    }
    if (email_exists($email)) {
        $errors['email'] = 'That email address is already registered.';
    }
    return $errors;
}

$errors = [];
// Sticky values (never echo the password back).
$fullName = trim((string) ($_POST['full_name'] ?? ''));
$username = trim((string) ($_POST['username'] ?? ''));
$email    = trim((string) ($_POST['email'] ?? ''));
$phone    = trim((string) ($_POST['phone'] ?? ''));

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $password = (string) ($_POST['password'] ?? '');
    $confirm  = (string) ($_POST['confirm_password'] ?? '');

    // Throttled clients skip validation entirely (it would answer "is this taken?").
    $ip = throttle_ip_subject(client_ip());
    $ticket = throttle_reserve('register', ['ip' => $ip, 'ip_new_account' => $ip]);
    if (!$ticket['allowed']) {
        send_throttle_headers($ticket['retry_after']);
        $errors['form'] = in_array('ip_new_account', $ticket['denied'], true)
            ? 'Too many accounts have been opened from your network recently. Please wait '
              . format_wait($ticket['retry_after']) . ' and try again.'
            : throttle_message($ticket['retry_after'], 'registration attempts');
    } else {
        $errors = validate_registration($fullName, $username, $email, $phone, $password, $confirm)
            ?: registration_conflicts($username, $email);
    }

    if (!$errors) {
        $pdo = db();
        try {
            $pdo->beginTransaction();

            $userId = create_customer([
                'username'  => $username,
                'email'    => $email,
                'password' => $password,
                'full_name' => $fullName,
                'phone'    => $phone,
            ]);
            $account = open_account_for_user($userId, 'checking');

            $pdo->commit();
            throttle_success($ticket);

            log_audit($userId, 'auth.register', 'New customer registered; opened account ' . $account['account_number']);

            // Sign the new customer in and take them to their dashboard.
            login_user([
                'id'        => $userId,
                'username'  => $username,
                'full_name' => $fullName,
                'role'      => 'customer',
            ]);
            set_flash('success', 'Welcome to Aurelia Bank! Your account ' . $account['account_number'] . ' is ready.');
            redirect('customer/dashboard.php');
        } catch (Throwable $e) {
            if ($pdo->inTransaction()) {
                $pdo->rollBack();
            }
            error_log('[Aurelia Bank] Registration failed: ' . $e->getMessage());
            $errors['form'] = 'We could not complete your registration. Please try again.';
        }
    }

    if ($errors) {
        throttle_failure($ticket);   // no-op when the attempt was throttled
    }
}

$pageTitle = 'Open an account';
$activeNav = '';

require __DIR__ . '/../includes/header.php';
?>

<section class="section">
    <div class="container">
        <div class="auth-wrap">
            <div class="auth-card card form-narrow">
                <div class="auth-card__head">
                    <h1 class="mt-0">Open an account</h1>
                    <p class="text-muted mb-0">Join Aurelia Bank in a couple of minutes.</p>
                </div>

                <?php if (isset($errors['form'])): ?>
                    <div class="alert alert--error" role="alert"><?= e($errors['form']) ?></div>
                <?php endif; ?>

                <form method="post" action="<?= e(base_url('auth/register.php')) ?>" novalidate data-validate>
                    <div class="form-group">
                        <label class="label" for="full_name">Full name</label>
                        <input class="input<?= isset($errors['full_name']) ? ' input--error' : '' ?>"
                               type="text" id="full_name" name="full_name"
                               value="<?= e($fullName) ?>" required minlength="2" maxlength="120" autofocus>
                        <?php if (isset($errors['full_name'])): ?><p class="field-error"><?= e($errors['full_name']) ?></p><?php endif; ?>
                    </div>

                    <div class="form-group">
                        <label class="label" for="username">Username</label>
                        <input class="input<?= isset($errors['username']) ? ' input--error' : '' ?>"
                               type="text" id="username" name="username"
                               value="<?= e($username) ?>" required minlength="3" maxlength="50" autocomplete="username">
                        <?php if (isset($errors['username'])): ?><p class="field-error"><?= e($errors['username']) ?></p>
                        <?php else: ?><p class="field-hint">Letters, numbers, dot or underscore.</p><?php endif; ?>
                    </div>

                    <div class="form-group">
                        <label class="label" for="email">Email</label>
                        <input class="input<?= isset($errors['email']) ? ' input--error' : '' ?>"
                               type="email" id="email" name="email"
                               value="<?= e($email) ?>" required maxlength="255" autocomplete="email">
                        <?php if (isset($errors['email'])): ?><p class="field-error"><?= e($errors['email']) ?></p><?php endif; ?>
                    </div>

                    <div class="form-group">
                        <label class="label" for="phone">Phone <span class="text-muted">(optional)</span></label>
                        <input class="input<?= isset($errors['phone']) ? ' input--error' : '' ?>"
                               type="tel" id="phone" name="phone" value="<?= e($phone) ?>" maxlength="30">
                        <?php if (isset($errors['phone'])): ?><p class="field-error"><?= e($errors['phone']) ?></p><?php endif; ?>
                    </div>

                    <div class="form-group">
                        <label class="label" for="password">Password</label>
                        <input class="input<?= isset($errors['password']) ? ' input--error' : '' ?>"
                               type="password" id="password" name="password"
                               required minlength="8" autocomplete="new-password">
                        <?php if (isset($errors['password'])): ?><p class="field-error"><?= e($errors['password']) ?></p>
                        <?php else: ?><p class="field-hint">At least 8 characters.</p><?php endif; ?>
                    </div>

                    <div class="form-group">
                        <label class="label" for="confirm_password">Confirm password</label>
                        <input class="input<?= isset($errors['confirm_password']) ? ' input--error' : '' ?>"
                               type="password" id="confirm_password" name="confirm_password"
                               required autocomplete="new-password" data-match="#password">
                        <?php if (isset($errors['confirm_password'])): ?><p class="field-error"><?= e($errors['confirm_password']) ?></p><?php endif; ?>
                    </div>

                    <button type="submit" class="btn btn--primary btn--block">Open my account</button>
                </form>

                <p class="text-center mt-2 mb-0" style="font-size:.9rem;">
                    Already have an account? <a href="<?= e(base_url('auth/login.php')) ?>">Log in</a>
                </p>
            </div>
        </div>
    </div>
</section>

<?php require __DIR__ . '/../includes/footer.php'; ?>
