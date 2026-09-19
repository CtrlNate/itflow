<?php

defined('FROM_POST_HANDLER') || die("Direct file access is not allowed");

if (isset($_POST['edit_identity_provider'])) {

    validateCSRFToken();

    $azure_client_id = escapeSql($_POST['azure_client_id']);
    $azure_client_secret = escapeSql($_POST['azure_client_secret']);

    mysqli_query($mysqli,"UPDATE settings SET config_azure_client_id = '$azure_client_id', config_azure_client_secret = '$azure_client_secret' WHERE company_id = 1");

    logAudit("Settings", "Edit", "$session_name edited identity provider settings");

    flashAlert("Identity Provider Settings updated");

    redirect();

}

if (isset($_POST['edit_oidc_provider'])) {

    validateCSRFToken();

    $oidc_issuer = trim($_POST['oidc_issuer'] ?? '');
    $oidc_client_id = escapeSql(trim($_POST['oidc_client_id'] ?? ''));
    $oidc_display_name = escapeSql(trim($_POST['oidc_display_name'] ?? ''));
    $oidc_email_claim = trim($_POST['oidc_email_claim'] ?? '');
    $oidc_require_verified_email = intval($_POST['oidc_require_verified_email'] ?? 0);

    if ($oidc_issuer !== '' && !oidcIssuerIsAcceptable($oidc_issuer)) {
        flashAlert("The OIDC Issuer URL must be a valid https:// URL", 'danger');
        redirect();
    }
    $oidc_issuer = escapeSql($oidc_issuer);

    if (!preg_match('/^[A-Za-z0-9_:.\-]{1,100}$/', $oidc_email_claim)) {
        $oidc_email_claim = 'email';
    }
    $oidc_email_claim = escapeSql($oidc_email_claim);

    // A blank secret field keeps the saved secret - it is never sent back to the browser
    $oidc_secret_sql = "";
    if (!empty($_POST['oidc_clear_client_secret'])) {
        $oidc_secret_sql = ", config_oidc_client_secret = NULL";
    } elseif (($_POST['oidc_client_secret'] ?? '') !== '') {
        $oidc_client_secret = escapeSql($_POST['oidc_client_secret']);
        $oidc_secret_sql = ", config_oidc_client_secret = '$oidc_client_secret'";
    }

    mysqli_query($mysqli, "UPDATE settings SET config_oidc_issuer = '$oidc_issuer', config_oidc_client_id = '$oidc_client_id', config_oidc_display_name = '$oidc_display_name', config_oidc_email_claim = '$oidc_email_claim', config_oidc_require_verified_email = $oidc_require_verified_email $oidc_secret_sql WHERE company_id = 1");

    logAudit("Settings", "Edit", "$session_name edited OpenID Connect identity provider settings");

    // Check the issuer now, so a typo shows up here rather than on a client's first login
    if ($oidc_issuer !== '') {
        try {
            oidcDiscover(trim($_POST['oidc_issuer']));
        } catch (Throwable $e) {
            flashAlert("OpenID Connect settings saved, but the provider could not be verified: " . escapeHtml($e->getMessage()), 'warning');
            redirect();
        }
    }

    flashAlert("OpenID Connect settings updated");

    redirect();

}
