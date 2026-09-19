<?php

/*
 * ITFlow (NDB Innovations fork) - Database update to version 2.7.8.1 (from 2.7.8)
 * Included by admin/database_updates.php - do not access directly
 *
 * Fork migrations use a fourth version segment so they sort after the upstream
 * release they were built on and before the next one (2.7.8 < 2.7.8.1 < 2.7.9).
 * Upstream's own 2.7.9 therefore still runs after this one. Each change is
 * guarded so the file is safe to re-run.
 */

defined('FROM_DB_UPDATER') || die("Direct file access is not allowed");

    // Generic OpenID Connect SSO for the client portal (client/login_oidc.php)
    $itflow_oidc_columns = [
        'config_oidc_issuer'                 => "varchar(500) DEFAULT NULL",
        'config_oidc_client_id'              => "varchar(500) DEFAULT NULL",
        'config_oidc_client_secret'          => "varchar(500) DEFAULT NULL",
        'config_oidc_display_name'           => "varchar(200) DEFAULT NULL",
        'config_oidc_email_claim'            => "varchar(100) NOT NULL DEFAULT 'email'",
        'config_oidc_require_verified_email' => "tinyint(1) NOT NULL DEFAULT 1",
    ];

    foreach ($itflow_oidc_columns as $itflow_column => $itflow_definition) {
        $itflow_column_exists = mysqli_query($mysqli, "SELECT 1 FROM information_schema.COLUMNS
            WHERE TABLE_SCHEMA = DATABASE()
            AND TABLE_NAME = 'settings'
            AND COLUMN_NAME = '$itflow_column'
            LIMIT 1");

        if (!$itflow_column_exists || mysqli_num_rows($itflow_column_exists) === 0) {
            mysqli_query($mysqli, "ALTER TABLE `settings` ADD `$itflow_column` $itflow_definition");
        }
    }

    unset($itflow_oidc_columns, $itflow_column, $itflow_definition, $itflow_column_exists);
