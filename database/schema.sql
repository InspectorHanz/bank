-- =============================================================================
-- Aurelia Bank — Database Schema (Phase 1)
-- -----------------------------------------------------------------------------
-- Fictional mini banking application for an academic cybersecurity project.
-- Engine: InnoDB (foreign keys, transactions).  Charset: utf8mb4.
--
-- IMPORTANT: This file creates STRUCTURE only. Seed data (fictional users,
-- accounts, transactions) is added in later phases alongside the features that
-- use it. No passwords or personal data are stored here.
--
-- Import (local, XAMPP):
--   mysql -u root -p < database/schema.sql
-- or import via phpMyAdmin (Import tab).
-- =============================================================================

CREATE DATABASE IF NOT EXISTS `aurelia_bank`
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE `aurelia_bank`;

-- Drop in dependency order so the script is re-runnable during development.
DROP TABLE IF EXISTS `auth_throttle`;
DROP TABLE IF EXISTS `audit_logs`;
DROP TABLE IF EXISTS `login_attempts`;
DROP TABLE IF EXISTS `transactions`;
DROP TABLE IF EXISTS `accounts`;
DROP TABLE IF EXISTS `users`;

-- -----------------------------------------------------------------------------
-- users — customers and administrators (distinguished by `role`)
-- -----------------------------------------------------------------------------
CREATE TABLE `users` (
    `id`            INT UNSIGNED NOT NULL AUTO_INCREMENT,
    `username`      VARCHAR(50)  NOT NULL,
    `email`         VARCHAR(255) NOT NULL,
    `password_hash` VARCHAR(255) NOT NULL,           -- bcrypt/argon2 via password_hash()
    `full_name`     VARCHAR(120) NOT NULL,
    `role`          ENUM('customer','admin') NOT NULL DEFAULT 'customer',
    `phone`         VARCHAR(30)  DEFAULT NULL,
    `address`       VARCHAR(255) DEFAULT NULL,
    `status`        ENUM('active','locked','disabled') NOT NULL DEFAULT 'active',
    `created_at`    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at`    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uq_users_username` (`username`),
    UNIQUE KEY `uq_users_email` (`email`),
    KEY `idx_users_role` (`role`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- -----------------------------------------------------------------------------
-- accounts — one user may hold several accounts
-- -----------------------------------------------------------------------------
CREATE TABLE `accounts` (
    `id`             INT UNSIGNED NOT NULL AUTO_INCREMENT,
    `user_id`        INT UNSIGNED NOT NULL,
    `account_number` VARCHAR(20)  NOT NULL,
    `account_type`   ENUM('checking','savings') NOT NULL DEFAULT 'checking',
    `balance`        DECIMAL(15,2) NOT NULL DEFAULT 0.00,
    `currency`       CHAR(3) NOT NULL DEFAULT 'USD',
    `status`         ENUM('active','frozen','closed') NOT NULL DEFAULT 'active',
    `opened_at`      DATE DEFAULT NULL,             -- set by the app on account creation
    `created_at`     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at`     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uq_accounts_number` (`account_number`),
    KEY `idx_accounts_user` (`user_id`),
    CONSTRAINT `fk_accounts_user`
        FOREIGN KEY (`user_id`) REFERENCES `users` (`id`)
        ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- -----------------------------------------------------------------------------
-- transactions — ledger entries belonging to an account
--   type            credit (money in) / debit (money out)
--   category        deposit, withdrawal, transfer, payment, fee, interest ...
--   balance_after   running balance snapshot for display convenience
-- -----------------------------------------------------------------------------
CREATE TABLE `transactions` (
    `id`            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `account_id`    INT UNSIGNED NOT NULL,
    `reference`     VARCHAR(30)  NOT NULL,
    `type`          ENUM('credit','debit') NOT NULL,
    `category`      VARCHAR(40)  NOT NULL DEFAULT 'general',
    `amount`        DECIMAL(15,2) NOT NULL,
    `balance_after` DECIMAL(15,2) DEFAULT NULL,
    `description`   VARCHAR(255) NOT NULL,
    `counterparty`  VARCHAR(120) DEFAULT NULL,
    `status`        ENUM('completed','pending','failed') NOT NULL DEFAULT 'completed',
    `transacted_at` DATETIME NOT NULL,
    `created_at`    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uq_transactions_reference` (`reference`),
    KEY `idx_transactions_account` (`account_id`),
    KEY `idx_transactions_date` (`transacted_at`),
    KEY `idx_transactions_type` (`type`),
    KEY `idx_transactions_category` (`category`),
    CONSTRAINT `fk_transactions_account`
        FOREIGN KEY (`account_id`) REFERENCES `accounts` (`id`)
        ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- -----------------------------------------------------------------------------
-- login_attempts — records every authentication attempt (audit trail /
-- evidence). Enforcement lives in `auth_throttle` below.
-- -----------------------------------------------------------------------------
CREATE TABLE `login_attempts` (
    `id`           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `username`     VARCHAR(50)  DEFAULT NULL,       -- the username that was tried
    `ip_address`   VARCHAR(45)  DEFAULT NULL,       -- IPv4/IPv6 (INET6-capable width)
    `user_agent`   VARCHAR(255) DEFAULT NULL,
    `successful`   TINYINT(1) NOT NULL DEFAULT 0,
    `throttled`    TINYINT(1) NOT NULL DEFAULT 0,   -- refused by rate limiting (password not checked)
    `attempted_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    KEY `idx_attempts_username_time` (`username`, `attempted_at`),
    KEY `idx_attempts_ip_time` (`ip_address`, `attempted_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- -----------------------------------------------------------------------------
-- audit_logs — high-level record of sensitive actions (profile changes, admin
-- actions). Useful as evidence during the CSRF demonstration.
-- -----------------------------------------------------------------------------
CREATE TABLE `audit_logs` (
    `id`         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `user_id`    INT UNSIGNED DEFAULT NULL,
    `action`     VARCHAR(80)  NOT NULL,
    `details`    TEXT DEFAULT NULL,
    `ip_address` VARCHAR(45)  DEFAULT NULL,
    `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    KEY `idx_audit_user` (`user_id`),
    KEY `idx_audit_action` (`action`),
    CONSTRAINT `fk_audit_user`
        FOREIGN KEY (`user_id`) REFERENCES `users` (`id`)
        ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- -----------------------------------------------------------------------------
-- auth_throttle — brute-force rate-limit counters (includes/throttle.php).
-- One row per (scope, kind, subject), e.g. login attempts for one username from
-- one IP. Lives in the database so every app instance shares it, and is updated
-- under row locks so concurrent requests cannot race past a limit.
-- Times are unix timestamps (app clock) so the cooldown maths stays in PHP.
-- -----------------------------------------------------------------------------
CREATE TABLE `auth_throttle` (
    `throttle_key`       CHAR(64)         NOT NULL,   -- SHA-256(scope, kind, subject)
    `scope`              VARCHAR(32)      NOT NULL,   -- login | password_change | email_change | register
    `kind`               VARCHAR(16)      NOT NULL,   -- account | ip | account_ip | ip_new_account
    `completed`          INT UNSIGNED     NOT NULL DEFAULT 0,   -- counted outcomes this window (failures, or successes for quotas)
    `pending`            INT UNSIGNED     NOT NULL DEFAULT 0,   -- reserved attempts not resolved yet
    `pending_expires_at` INT UNSIGNED     DEFAULT NULL,         -- after this, pending counts as completed
    `window_started_at`  INT UNSIGNED     NOT NULL,
    `locked_until`       INT UNSIGNED     DEFAULT NULL,         -- end of current/last cooldown
    `lock_level`         TINYINT UNSIGNED NOT NULL DEFAULT 0,   -- consecutive cooldowns (escalation)
    `updated_at`         INT UNSIGNED     NOT NULL,
    PRIMARY KEY (`throttle_key`),
    KEY `idx_throttle_updated` (`updated_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
