<?php
/**
 * Aurelia Bank — Public Landing Page
 * -----------------------------------------------------------------------------
 * Marketing-style homepage for the fictional bank. In development it also shows
 * a small "system status" panel so you can verify the Phase 1 foundation
 * (PHP, database connection, schema) is working. That panel is hidden in
 * production (APP_ENV = 'production').
 */

declare(strict_types=1);

require_once __DIR__ . '/includes/bootstrap.php';

/**
 * Gather a lightweight system status for the development panel.
 * We deliberately keep this defensive so the homepage never crashes just
 * because the database is not set up yet.
 */
function system_status(): array
{
    $status = [
        'php_version' => PHP_VERSION,
        'app_env'     => APP_ENV,
        'db_ok'       => false,
        'db_message'  => '',
        'db_name'     => DB_NAME,
        'table_count' => 0,
    ];

    try {
        $pdo = db();
        $stmt = $pdo->query(
            'SELECT COUNT(*) AS c
               FROM information_schema.tables
              WHERE table_schema = DATABASE()'
        );
        $status['table_count'] = (int) ($stmt->fetch()['c'] ?? 0);
        $status['db_ok']       = true;
        $status['db_message']  = 'Connected';
    } catch (Throwable $e) {
        $status['db_message'] = $e->getMessage();
    }

    return $status;
}

$pageTitle = 'Home';
$activeNav = 'home';

require __DIR__ . '/includes/header.php';
?>

<!-- Hero -------------------------------------------------------------------->
<section class="hero">
    <div class="container hero__inner">
        <div>
            <span class="hero__eyebrow">Personal &amp; Business Banking</span>
            <h1>Banking made brilliantly simple.</h1>
            <p class="lead">
                Aurelia Bank brings your everyday accounts, savings and spending
                together in one clear, secure place — so you always know where
                you stand.
            </p>
            <div class="hero__actions">
                <a class="btn btn--gold" href="<?= e(base_url('auth/register.php')) ?>">Open an account</a>
                <a class="btn btn--ghost" href="<?= e(base_url('auth/login.php')) ?>">Log in to online banking</a>
            </div>
        </div>

        <div>
            <div class="hero__card" aria-hidden="true">
                <div class="hero__card-chip"></div>
                <div class="hero__card-number">4921&nbsp; 08•• &nbsp;•••• &nbsp;7043</div>
                <div class="hero__card-row">
                    <span>Aurelia Everyday</span>
                    <span>VALID 09/29</span>
                </div>
            </div>
        </div>
    </div>
</section>

<!-- Features ---------------------------------------------------------------->
<section class="section" id="features">
    <div class="container">
        <div class="section-head">
            <h2 id="personal">Everything you need, nothing you don't</h2>
            <p>A focused set of tools to help you manage money with confidence.</p>
        </div>

        <div class="grid grid--3">
            <article class="feature">
                <div class="feature__icon" aria-hidden="true">💳</div>
                <h3>Accounts &amp; balances</h3>
                <p>See your available balance and account details at a glance from a clean, uncluttered dashboard.</p>
            </article>
            <article class="feature">
                <div class="feature__icon" aria-hidden="true">🔎</div>
                <h3>Search transactions</h3>
                <p>Find any transaction fast with search and filtering by type, description or date range.</p>
            </article>
            <article class="feature">
                <div class="feature__icon" aria-hidden="true">🛡️</div>
                <h3>Secure by design</h3>
                <p>Protected sign-in, encrypted sessions and careful handling of your information as standard.</p>
            </article>
            <article class="feature" id="business">
                <div class="feature__icon" aria-hidden="true">📈</div>
                <h3>Business ready</h3>
                <p>Clear statements and transaction history built for sole traders and small businesses.</p>
            </article>
            <article class="feature">
                <div class="feature__icon" aria-hidden="true">⚙️</div>
                <h3>Profile &amp; settings</h3>
                <p>Keep your contact details and preferences up to date from one simple settings area.</p>
            </article>
            <article class="feature" id="support">
                <div class="feature__icon" aria-hidden="true">💬</div>
                <h3>Here to help</h3>
                <p>Guidance when you need it, with a support experience designed to be genuinely helpful.</p>
            </article>
        </div>
    </div>
</section>

<!-- CTA --------------------------------------------------------------------->
<section class="section--tight">
    <div class="container">
        <div class="card" style="text-align:center;">
            <h2 class="mt-0">Ready when you are</h2>
            <p class="text-muted">Log in to your online banking to view your accounts and recent activity.</p>
            <a class="btn btn--primary" href="<?= e(base_url('auth/login.php')) ?>">Log in</a>
        </div>
    </div>
</section>

<?php if (APP_ENV === 'development'): ?>
<!-- Development-only foundation check (hidden in production) ----------------->
<?php $status = system_status(); ?>
<section class="section--tight">
    <div class="container">
        <div class="sys-status">
            <h3 class="mt-0">Phase 1 · System status <span class="badge">development only</span></h3>
            <p class="text-muted" style="margin-bottom:1.25rem;">
                This panel confirms the foundation is wired up correctly. It is
                automatically hidden when <code>APP_ENV</code> is set to
                <code>production</code>.
            </p>
            <div class="sys-status__grid">
                <div class="sys-status__item">
                    <p class="stat-card__label">PHP version</p>
                    <p class="stat-card__value"><?= e($status['php_version']) ?></p>
                </div>
                <div class="sys-status__item">
                    <p class="stat-card__label">Environment</p>
                    <p class="stat-card__value"><?= e($status['app_env']) ?></p>
                </div>
                <div class="sys-status__item">
                    <p class="stat-card__label">Database (<?= e($status['db_name']) ?>)</p>
                    <p class="stat-card__value">
                        <span class="dot <?= $status['db_ok'] ? 'dot--ok' : 'dot--bad' ?>"></span>
                        <?= $status['db_ok'] ? 'Connected' : 'Not connected' ?>
                    </p>
                </div>
                <div class="sys-status__item">
                    <p class="stat-card__label">Tables found</p>
                    <p class="stat-card__value"><?= (int) $status['table_count'] ?> / 6</p>
                </div>
            </div>
            <?php if (!$status['db_ok']): ?>
                <div class="alert alert--warning" style="margin-top:1.25rem;">
                    Database not connected: <?= e($status['db_message']) ?><br>
                    Check <code>config/config.local.php</code> and import
                    <code>database/schema.sql</code>.
                </div>
            <?php elseif ($status['table_count'] < 6): ?>
                <div class="alert alert--info" style="margin-top:1.25rem;">
                    Connected, but only <?= (int) $status['table_count'] ?> of 6 expected tables
                    were found. Import <code>database/schema.sql</code> (or run <code>database/migrations/</code>) to create them.
                </div>
            <?php else: ?>
                <div class="alert alert--success" style="margin-top:1.25rem;">
                    Foundation looks good — PHP, database and schema are all in place.
                </div>
            <?php endif; ?>
        </div>
    </div>
</section>
<?php endif; ?>

<?php require __DIR__ . '/includes/footer.php'; ?>
