# Aurelia Bank

A fictional mini online-banking web application built with **plain PHP + MySQL**
for an **academic cybersecurity project**. It is developed first as a normal,
functional banking website. Controlled, clearly-isolated vulnerabilities
(Brute Force, SQL Injection, CSRF) are introduced only in later phases for
demonstration in an authorized test environment, then remediated.

> ⚠️ Everything here is fictional. There are no real accounts, real money, or
> real personal data. Use only against this application in an environment you
> control and are authorized to test.

---

## Tech stack

- **PHP** (no framework — plain, readable code so the mechanics are visible)
- **MySQL / MariaDB** (InnoDB, utf8mb4)
- **HTML / CSS / JavaScript** (vanilla, progressive enhancement)
- Target deployment: **Hostinger** shared hosting (Apache/LiteSpeed + MySQL)

## Requirements

- PHP 8.1+ (uses typed helpers, `str_starts_with`, `never` return type)
- MySQL 5.7+/8.0+ or MariaDB 10.2+
- Local dev: **XAMPP** (recommended on Windows), or PHP's built-in server

---

## Project structure

```text
aurelia-bank/
├── assets/                 # Front-end static assets
│   ├── css/styles.css      # Design system / foundation stylesheet
│   ├── js/app.js           # Foundation JavaScript (progressive enhancement)
│   └── images/
├── config/
│   ├── config.php          # Loads config, defines constants, error strategy
│   ├── config.local.sample.php  # Template — copy to config.local.php
│   └── .htaccess           # Denies direct web access
├── includes/
│   ├── bootstrap.php       # Single entry point (config+functions+session+db+auth)
│   ├── db.php              # PDO connection (db())
│   ├── session.php         # Secure session bootstrap
│   ├── auth.php            # Auth/authorization helpers + guards   (Phase 2)
│   ├── banking.php         # Accounts, transactions, money movement, admin
│   ├── csrf.php            # CSRF token helpers (money-movement forms)
│   ├── audit.php           # Audit-log helper (log_audit)          (Phase 5–6)
│   ├── functions.php       # Shared helpers (e(), base_url(), money, pagination)
│   ├── header.php          # Common header / top navigation (auth-aware)
│   ├── footer.php          # Common footer
│   └── .htaccess           # Denies direct web access
├── database/
│   ├── schema.sql          # Database structure (Phase 1)
│   ├── seed_users.php      # Dev seeder: fictional test users       (Phase 2)
│   ├── seed_banking.php    # Dev seeder: accounts + transactions    (Phase 3–6)
│   └── .htaccess           # Denies direct web access
├── auth/
│   ├── register.php        # Open an account (creates user + account)
│   ├── login.php           # Login page + processing                (Phase 2)
│   └── logout.php          # POST-only logout                       (Phase 2)
├── customer/
│   ├── dashboard.php       # Balance, accounts, recent activity     (Phase 3)
│   ├── transactions.php    # Search / filter / paginate history     (Phase 4)
│   ├── transaction.php     # Single transaction detail              (Phase 4)
│   ├── transfer.php        # Transfer to another account (CSRF-safe)
│   ├── deposit.php         # Deposit into own account (CSRF-safe)
│   ├── withdraw.php        # Withdraw from own account (CSRF-safe)
│   └── profile.php         # Profile + password settings            (Phase 5)
├── admin/
│   ├── login.php           # Separate staff login portal (unlinked)
│   ├── dashboard.php       # Bank-wide overview                     (Phase 6)
│   ├── customers.php       # Customer list + search                 (Phase 6)
│   ├── customer.php        # Customer detail + status management    (Phase 6)
│   └── transactions.php    # Bank-wide transaction overview         (Phase 6)
├── index.php               # Public landing page (+ dev system-status panel)
├── 404.php                 # Custom not-found page
├── .htaccess               # Root Apache config / security headers
├── .gitignore
└── README.md
```

### Why this structure

- **Feature folders** (`auth/`, `customer/`, `admin/`) keep each area of the
  site isolated and make later phases easy to slot in without touching others.
- **`includes/` for shared logic** and a single **`bootstrap.php`** enforce
  separation of concerns and one correct startup order for every page.
- **`config/` split** (`config.php` committed, `config.local.php` gitignored)
  keeps **secrets out of the repository** while still working out-of-the-box
  locally via safe defaults.
- **Root-relative URLs** via `base_url()` auto-detect the app's location, so the
  exact same code runs from a subfolder locally (`/aurelia-bank/`) and from the
  web root on Hostinger.
- **Flat, `.php`-file routing** (no front controller) matches how PHP works on
  Hostinger shared hosting and keeps each endpoint (e.g. `login.php`) explicit —
  which matters because later phases target real endpoints.

---

## Local setup (XAMPP on Windows)

1. **Copy the project** into your web root, e.g.
   `C:\xampp\htdocs\aurelia-bank`.

2. **Start Apache and MySQL** from the XAMPP Control Panel.

3. **Create the database** by importing the schema:
   - Open <http://localhost/phpmyadmin>
   - *Import* → choose `database/schema.sql` → *Go*
   - This creates the `aurelia_bank` database and its 5 tables.

   *(CLI alternative:)*
   ```bash
   mysql -u root -p < database/schema.sql
   ```

4. **Create your local config** from the template:
   ```bash
   cp config/config.local.sample.php config/config.local.php
   ```
   Then edit `config/config.local.php` if your MySQL credentials differ from the
   defaults (XAMPP default is user `root` with an empty password).
   > If you skip this step, the app falls back to safe local defaults
   > (`127.0.0.1`, `root`, empty password, database `aurelia_bank`).

5. **Open the site:** <http://localhost/aurelia-bank/>

### Alternative: PHP built-in server

From the project directory (requires PHP on your PATH and a reachable MySQL):

```bash
php -S localhost:8000
```
Then visit <http://localhost:8000/>. Note: `.htaccess` rules do **not** apply to
the built-in server, so prefer XAMPP for behavior closest to Hostinger.

---

## Verifying Phase 1

Open the homepage. In development you'll see a **"Phase 1 · System status"**
panel at the bottom. Confirm:

- **PHP version** is shown (8.0+).
- **Environment** = `development`.
- **Database** shows a green dot and “Connected”.
- **Tables found** = **5 / 5** (`users`, `accounts`, `transactions`,
  `login_attempts`, `audit_logs`).
- A green “Foundation looks good” message appears.

Also check:
- Navigation, hero, features and footer render with styling (CSS is loading).
- The mobile menu button appears and toggles the nav at narrow widths (JS works).
- Visiting a non-existent URL (e.g. `/nope.php` under XAMPP) shows the styled
  404 page.

The status panel disappears automatically when `APP_ENV` is `production`.

---

## Authentication (Phase 2)

Phase 2 adds a real login system used by both customers and administrators.

### Seed the test users (one-time)

The schema creates structure only. Create the fictional test accounts by running
the seeder (it hashes each password with `password_hash()` — no plaintext):

```bash
"C:\xampp\php\php.exe" database\seed_users.php      # Windows / XAMPP
php database/seed_users.php                          # if php is on your PATH
```

Then seed accounts + a transaction ledger for those customers (needed from
Phase 3 onward):

```bash
"C:\xampp\php\php.exe" database\seed_banking.php
php database/seed_banking.php
```

### Test credentials (fictional)

| Username   | Password       | Role     |
|------------|----------------|----------|
| `admin`    | `Admin@12345`  | admin    |
| `jdoe`     | `Password@123` | customer |
| `msanders` | `Password@123` | customer |

> These are placeholder demo credentials for an academic project — not real.

You can also **open a new account** yourself at `auth/register.php` ("Open
account" in the header). Registration creates the customer and their first
(checking) account with a zero balance in one transaction, signs you in, and
drops you on the dashboard — fund it from the **Deposit** page. The seed data
above is just ready-made demo data, not a prerequisite for using the app.

### Verifying Phase 2

1. Visit **`/aurelia-bank/auth/login.php`**.
2. Log in as `jdoe` → you land on the **customer dashboard**; the top nav shows
   your name and a **Log out** button.
3. Log in as `admin` at the **staff portal `/aurelia-bank/admin/login.php`** →
   you land on the **admin dashboard**. (The `admin` account will *not* work on
   the public customer login, and vice-versa.)
4. **Authorization:** while logged in as a customer, visiting
   `/aurelia-bank/admin/dashboard.php` bounces you back to the customer
   dashboard. Visiting any dashboard while logged out sends you to the login
   page (and returns you there after login).
5. **Bad credentials** show a single generic message ("Invalid username or
   password") — the form never reveals which usernames exist.
6. Every attempt is recorded in the `login_attempts` table (audit trail).

### Two login portals

- **Customer login — `auth/login.php`** (public): authenticates **customer**
  accounts only and is the primary target for the later brute-force demo.
- **Staff login — `admin/login.php`** (not linked anywhere): authenticates
  **admin** accounts only. Its URL is known only to staff.

A credential used on the wrong portal fails with the same generic "Invalid
username or password" message (no cross-portal enumeration). Both portals share
one `authenticate()` helper — the single place the brute-force hardening will
later add rate limiting.

> The separate admin URL is **defense-in-depth / obscurity, not the real
> control**. The actual boundary is `require_role('admin')` on every admin page:
> a logged-in customer who guesses an admin URL is bounced to their own
> dashboard, and an unauthenticated hit on any `/admin/` page is sent to the
> staff login (everything else goes to the customer login).

### How the login is built (and why)

- **Role-scoped authentication** shared by both portals, with a role-based
  redirect afterwards — one genuine login flow per audience.
- **`includes/auth.php`** holds all auth logic: `find_user_by_username()`
  (prepared statement), `login_user()` / `logout_user()`, `current_user()`, and
  the guards `require_login()` / `require_role()`.
- **Secure defaults now:** `password_verify()` against a bcrypt hash;
  `session_regenerate_id()` on login (fixation protection); generic auth errors
  (no user enumeration); POST-only logout; account `status` checked.
- **Deliberately deferred:** login attempts are *recorded but not throttled*.
  Rate limiting / temporary lockout is introduced later as the **hardened**
  counterpart, so the vulnerable vs. hardened login can be compared directly.
  CSRF tokens are introduced with the profile/settings work (their designated
  demonstration point), keeping each phase's security topic isolated.

---

## Banking application (Phases 3–6)

With authentication in place, Phases 3–6 build the normal, functional bank.

**Customer area**
- **Dashboard** (`customer/dashboard.php`) — total balance, per-account cards,
  and recent activity, all scoped to the signed-in user.
- **Transactions** (`customer/transactions.php`) — history with free-text
  search, type/category/date filters, per-account scoping and pagination.
- **Transaction detail** (`customer/transaction.php`) — full detail for one
  transaction, looked up with an ownership check.
- **Profile & settings** (`customer/profile.php`) — edit personal details and
  change password, with server-side *and* client-side validation.

**Money movement** (fictional funds, all internal — no real gateways)
- **Transfer** (`customer/transfer.php`) — send money to another account (your
  own or another customer's) by account number; creates a matched debit+credit
  pair.
- **Deposit / Withdraw** (`customer/deposit.php`, `customer/withdraw.php`) — add
  or remove funds from your own accounts.
- All three run inside a **database transaction with row locking**
  (`SELECT … FOR UPDATE`), re-check funds against the live balance, write a
  `balance_after` snapshot, and are **CSRF-protected** with a synchroniser token
  (`includes/csrf.php`). Reachable from the dashboard quick actions and the
  Transfer nav item.

> Try a transfer with these seeded account numbers:
> `AUREL1000000011` (John Doe · checking), `AUREL1000000029` (John Doe ·
> savings), `AUREL1000000037` (Maria Sanders · checking).

**Admin area** (`admin/…`) — bank-wide overview, searchable/paginated customer
list, per-customer detail (profile, accounts, recent transactions) with a basic
status-management control, and a bank-wide transaction browser.

### Security notes for these phases

- **Authorization in the query, not the UI.** Every customer read is scoped by
  `user_id` (`includes/banking.php`), so requesting another customer's account
  or transaction id returns "not found" rather than leaking data.
- **Prepared statements almost everywhere.** The one deliberate exception is
  the transaction search's free-text term (`customer/transactions.php` →
  `build_transaction_filters()` in `includes/banking.php`), which is the
  *Phase 7 SQL-injection demonstration point*: that single clause concatenates
  the search term into the query instead of binding it. Every other filter,
  and every other query in the app, still uses bound parameters.
- **Brute force is intentionally unthrottled.** `authenticate()` records every
  attempt to `login_attempts` (audit trail) but nothing currently checks that
  table — there is no lockout or rate limit on either login form. This is the
  Phase 7 brute-force demonstration point.
- **Session cookie `SameSite` is intentionally `None` (`includes/session.php`),
  paired with `Secure=true`.** Earlier in Phase 7 this cookie's `Secure` flag
  was hard-coded `false` as a MITM-over-plain-HTTP demo; that isn't exploitable
  against an HTTPS-only host (no plaintext connection exists to intercept), so
  the live demo target is now CSRF instead — see the next bullet. Note the
  `.htaccess` security headers (HSTS included) only apply on Apache/Hostinger —
  they are not sent at all on the Vercel deployment, which has no equivalent
  config in this repo.
- **CSRF: money movement is protected; the profile update is not (by design).**
  Deposit/withdraw/transfer carry a CSRF token from the outset because they are
  financial actions. The profile-settings update is deliberately left *without*
  a token as the designated, controlled CSRF demonstration point — the roadmap
  explicitly says the CSRF demo must not target a financial action. Note that a
  missing token alone isn't enough to exploit this in a modern browser: the
  `SameSite=Lax` default already blocks a forged cross-site POST from carrying
  the session cookie. The cookie above is set to `SameSite=None` (which
  requires `Secure=true`) specifically so the PoC at
  `security-tests/csrf_poc.html` demonstrates a real, working bypass rather
  than a silently-blocked one. The hardening phase restores `SameSite=Lax`
  and/or applies the same `csrf.php` helper used by the money-movement forms.
- **Audit trail:** profile changes, password changes and admin actions are
  written to `audit_logs` via `log_audit()`.

> Note: with native prepared statements (`EMULATE_PREPARES = false`) a named
> placeholder may only appear once per query, so multi-column `LIKE` searches
> bind the term to several distinct placeholders (see `banking.php`).

---

## Security posture during normal development

Even before the demonstration phases, the app is built cleanly and securely:

- **PDO with real prepared statements** (`EMULATE_PREPARES = false`) so
  parameterised queries are the natural default.
- **Output escaping** everywhere via `e()`.
- **Secure sessions**: `HttpOnly`, `Secure` (auto on HTTPS), `SameSite=Lax`.
- **No secrets in the repo**: real credentials live only in the gitignored
  `config/config.local.php`.
- **Environment-aware error handling**: verbose locally, logged-not-shown in
  production.
- **Defense in depth**: `.htaccess` denies direct access to `config/`,
  `includes/`, `database/`, blocks `.sql`/`.md`/dotfiles, disables directory
  listing, and sets baseline security headers.

The intentional vulnerabilities in later phases will be **clearly commented and
isolated** so they can be toggled/reverted, and each has a hardened counterpart.

---

## Development roadmap

| Phase | Focus | Status |
|------:|-------|--------|
| 1 | Project foundation (structure, config, DB, layout, CSS/JS) | ✅ Done |
| 2 | Authentication (login/logout, hashing, roles, sessions) | ✅ Done |
| 3 | Customer dashboard (balance, account info, recent activity) | ✅ Done |
| 4 | Transaction system (history, search, filter, pagination, details) | ✅ Done |
| 5 | Profile & account settings (view/edit, validation) | ✅ Done |
| 6 | Administrator area (customers, accounts, transactions) | ✅ Done |
| 7 | Controlled vulnerabilities (Brute Force / SQLi / CSRF) | ✅ Done |
| 8 | Security testing documentation | — |
| 9 | Security hardening (remediated versions) | — |
| 10 | Final functional + security testing | — |
| 11 | Hostinger deployment | — |

---

## License / use

Academic use only — a classroom pentesting exercise against test/fictional
data only. This app, including the public Vercel deployment, intentionally
contains the Phase 7 vulnerabilities described above (unthrottled login,
concatenated SQL in the transaction search, non-Secure session cookie). Never
point it at real accounts, real personal data, or real money, and never reuse
this code's login, search-filter, or session-cookie logic in a non-academic
project without first restoring the bound-parameter / rate-limiting /
Secure-cookie versions.
