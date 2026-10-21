-- =============================================================================
-- Aurelia Bank — Migration 002: separate pending from completed attempts
-- -----------------------------------------------------------------------------
-- For databases that already ran 001_auth_throttle.sql. A fresh import of the
-- current schema.sql already contains these changes — do not run this on top
-- of it.
--
-- Run ONCE against the application database (select it first), after 001:
--   mysql -u <user> -p <database_name> < database/migrations/002_auth_throttle_pending.sql
--
-- Existing counts are kept as "completed" (they may include in-flight attempts
-- from the old code; counting them is the fail-safe direction).
-- =============================================================================

ALTER TABLE `auth_throttle`
    CHANGE COLUMN `attempts` `completed` INT UNSIGNED NOT NULL DEFAULT 0,
    ADD COLUMN `pending` INT UNSIGNED NOT NULL DEFAULT 0 AFTER `completed`,
    ADD COLUMN `pending_expires_at` INT UNSIGNED DEFAULT NULL AFTER `pending`;
