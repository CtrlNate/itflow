<?php
/*
 * Client Portal
 * SSO-only login page - the single sign-on button and nothing else
 *
 * Point clients here (/client/login_sso.php) instead of the unified /login.php
 * when they should all authenticate through the OpenID Connect provider.
 * Failed SSO attempts started from this page come back here too.
 * A small "Sign in with password" link leads to /login.php for contacts not yet moved to SSO.
 */

header("Content-Security-Policy: default-src 'self'");

if (!file_exists('../config.php')) {
    header("Location: /setup");
    exit();
}

require_once '../config.php';
require_once '../functions.php';

require_once __DIR__ . "/../includes/session_init.php";

if (!isset($config_enable_setup) || $config_enable_setup == 1) {
    header("Location: /setup");
    exit();
}

// Already signed in - straight to the portal
if (!empty($_SESSION['client_logged_in'])) {
    header("Location: index.php");
    exit();
}

$sql_settings = mysqli_query($mysqli, "
    SELECT settings.config_client_portal_enable, settings.config_login_message, settings.config_whitelabel_enabled,
        companies.company_name, companies.company_logo
    FROM settings
    LEFT JOIN companies ON settings.company_id = companies.company_id
    WHERE settings.company_id = 1
");
$row = mysqli_fetch_assoc($sql_settings);

$company_name = $row['company_name'];
$company_logo = $row['company_logo'];
$config_login_message = escapeHtml($row['config_login_message']);
$config_client_portal_enable = intval($row['config_client_portal_enable']);
$config_whitelabel_enabled = intval($row['config_whitelabel_enabled']);

$oidc_settings = oidcGetSettings();
$sso_available = $config_client_portal_enable == 1 && oidcIsConfigured($oidc_settings);

?>
<!DOCTYPE html>
<html lang="en" data-bs-theme="light" data-lte-color-mode="off">
<head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <title><?= escapeHtml($company_name) ?> | Client Portal Login</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="robots" content="noindex">

    <link rel="stylesheet" href="/libs/fontawesome-free/css/all.min.css">

    <?php if (file_exists('../uploads/favicon.ico')) { ?>
        <link rel="icon" type="image/x-icon" href="/uploads/favicon.ico">
    <?php } ?>

    <link rel="stylesheet" href="/libs/adminlte/css/adminlte.min.css">
    <link rel="stylesheet" href="/css/itflow_custom.css">
</head>
<body class="hold-transition login-page">

<div class="login-box">
    <div class="login-logo">
        <?php if (!empty($company_logo)) { ?>
            <img alt="<?= escapeHtml($company_name) ?> logo" height="110" width="380" class="img-fluid" src="/uploads/settings/<?= escapeHtml($company_logo) ?>">
        <?php } else { ?>
            <span class="text-primary text-bold"><i class="fas fa-paper-plane me-2"></i>IT</span>Flow
        <?php } ?>
    </div>

    <div class="card">
        <div class="card-body login-card-body">

            <?php if (!empty($config_login_message)) { ?>
                <p class="login-box-msg px-0"><?= nl2br($config_login_message) ?></p>
            <?php } ?>

            <?php if (!empty($_SESSION['login_message'])) { ?>
                <div class="alert alert-danger"><?= escapeHtml($_SESSION['login_message']) ?></div>
                <?php unset($_SESSION['login_message']); ?>
            <?php } ?>

            <?php if ($sso_available) { ?>
                <p class="login-box-msg px-0">Sign in to the client portal</p>
                <a href="login_oidc.php?from=sso" class="btn btn-dark w-100">
                    <i class="fas fa-fw fa-id-badge me-2"></i>Login with <?= escapeHtml(oidcDisplayName($oidc_settings)) ?>
                </a>
            <?php } else { ?>
                <div class="alert alert-secondary mb-0">Single sign-on is not currently available. Please contact support.</div>
            <?php } ?>

            <div class="text-center mt-3">
                <a href="/login.php" class="small text-secondary">Sign in with password</a>
            </div>

        </div>
    </div>
</div>

<?php if (!$config_whitelabel_enabled) { ?>
    <small class="text-muted">Powered by ITFlow</small>
<?php } ?>

</body>
</html>
