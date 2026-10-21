-- =============================================================================
-- Aurelia Bank — Migration 001: brute-force throttling (Phase 9 hardening)
-- -----------------------------------------------------------------------------
-- For databases created from an OLDER schema.sql. A fresh import of the current
-- schema.sql already contains these changes — do not run this on top of it.
--
-- Run ONCE against the application database (select it first):
--   mysql -u <user> -p <database_name> < database/migrations/001_auth_throttle.sql
-- or phpMyAdmin: select the database -> Import -> this file.
-- (No USE statement on purpose: on Hostinger the database name differs.)
-- =============================================================================

CREATE TABLE IF NOT EXISTS `auth_throttle` (
    `throttle_key`      CHAR(64)         NOT NULL,
    `scope`             VARCHAR(32)      NOT NULL,
    `kind`              VARCHAR(16)      NOT NULL,
    `attempts`          INT UNSIGNED     NOT NULL DEFAULT 0,
    `window_started_at` INT UNSIGNED     NOT NULL,
    `locked_until`      INT UNSIGNED     DEFAULT NULL,
    `lock_level`        TINYINT UNSIGNED NOT NULL DEFAULT 0,
    `updated_at`        INT UNSIGNED     NOT NULL,
    PRIMARY KEY (`throttle_key`),
    KEY `idx_throttle_updated` (`updated_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

ALTER TABLE `login_attempts`
    ADD COLUMN `throttled` TINYINT(1) NOT NULL DEFAULT 0 AFTER `successful`;
