<?php
/*
 * Client Portal
 * Login via a generic OpenID Connect identity provider
 *
 * Authorization code flow with PKCE and nonce. The provider is configured under
 * Admin > Identity Providers; the helpers live in functions/oidc.php.
 */

require_once '../config.php';
require_once '../functions.php';

require_once __DIR__ . "/../includes/session_init.php";

// Set Timezone after session starts
require_once "../includes/inc_set_timezone.php";

$session_ip = escapeSql(getIP());
$session_user_agent = escapeSql($_SERVER['HTTP_USER_AGENT'] ?? '');

// Sends the user back to the login page with a message. $log_detail goes to
// the app log only - it can name the misconfiguration, the user never sees it.
function oidcLoginFail($user_message, $log_detail = null) {
    if ($log_detail) {
        error_log("ITFlow: client portal OIDC login failed: $log_detail");
    }
    $_SESSION['login_message'] = "Something went wrong with logging you in: $user_message";
    header("Location: ../login.php");
    exit();
}

$sql_settings = mysqli_query($mysqli, "SELECT config_client_portal_enable FROM settings WHERE company_id = 1");
$portal_settings = mysqli_fetch_assoc($sql_settings);

$oidc_settings = oidcGetSettings();

if (intval($portal_settings['config_client_portal_enable'] ?? 0) !== 1 || !oidcIsConfigured($oidc_settings)) {
    oidcLoginFail("single sign-on is not enabled.");
}

$redirect_uri = "https://$config_base_url/client/login_oidc.php";
$provider_name = oidcDisplayName($oidc_settings);

try {
    $discovery = oidcDiscover($oidc_settings['issuer']);
} catch (Throwable $e) {
    oidcLoginFail("could not reach $provider_name. Please try again later.", $e->getMessage());
}

// Initial request - send the user to the provider
if ($_SERVER['REQUEST_METHOD'] == "GET" && !isset($_GET['code']) && !isset($_GET['error'])) {

    // Single-use values held server side (never the session ID)
    $state = bin2hex(random_bytes(32));
    $nonce = bin2hex(random_bytes(32));
    $code_verifier = oidcBase64UrlEncode(random_bytes(48));

    $_SESSION['oidc_login'] = [
        'state'         => $state,
        'nonce'         => $nonce,
        'code_verifier' => $code_verifier,
        'expires_at'    => time() + 600,
    ];

    $params = [
        'response_type'         => 'code',
        'client_id'             => $oidc_settings['client_id'],
        'redirect_uri'          => $redirect_uri,
        'scope'                 => 'openid email profile',
        'state'                 => $state,
        'nonce'                 => $nonce,
        'code_challenge'        => oidcBase64UrlEncode(hash('sha256', $code_verifier, true)),
        'code_challenge_method' => 'S256',
        // Top-level GET back to us - a SameSite=Lax cookie is not sent on a cross-site POST
        'response_mode'         => 'query',
    ];

    $auth_url = $discovery['authorization_endpoint'];
    $auth_url .= (str_contains($auth_url, '?') ? '&' : '?') . http_build_query($params);

    header("Location: $auth_url");
    exit();

}

// Provider has redirected back with an authorization code (or an error)
if (isset($_GET['code']) || isset($_GET['error'])) {

    $pending = $_SESSION['oidc_login'] ?? [];

    // Single use, consumed whether or not it validates
    unset($_SESSION['oidc_login']);

    if (!empty($_GET['error'])) {
        $provider_error = is_string($_GET['error']) ? $_GET['error'] : 'unknown';
        oidcLoginFail("$provider_name returned an error. Please try again.", "provider returned error '$provider_error'");
    }

    $state = is_string($_GET['state'] ?? null) ? $_GET['state'] : '';
    $code = is_string($_GET['code'] ?? null) ? $_GET['code'] : '';

    if (empty($state) || empty($pending['state']) || !hash_equals($pending['state'], $state) || time() > intval($pending['expires_at'] ?? 0)) {
        oidcLoginFail("the sign-in request could not be verified. Please try again.");
    }

    if ($code === '') {
        oidcLoginFail("$provider_name did not return an authorization code. Please try again.");
    }

    try {
        $tokens = oidcExchangeCode($discovery, $oidc_settings, $code, $redirect_uri, $pending['code_verifier']);
        $claims = oidcValidateIdToken($tokens['id_token'], $discovery, $oidc_settings, $pending['nonce']);

        $email_claim = $oidc_settings['email_claim'];
        if (empty($claims[$email_claim]) || ($oidc_settings['require_verified_email'] && !isset($claims['email_verified']))) {
            $claims = oidcMergeUserinfo($claims, $discovery, $tokens['access_token'] ?? '');
        }
    } catch (Throwable $e) {
        oidcLoginFail("your identity could not be verified with $provider_name. Please try again.", $e->getMessage());
    }

    $email = $claims[$email_claim] ?? '';
    if (!is_string($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        oidcLoginFail("$provider_name did not provide an email address for your account.", "claim '$email_claim' missing or not an email for sub " . $claims['sub']);
    }

    $email_sql = escapeSql($email);
    $provider_name_sql = escapeSql($provider_name);

    // Some providers send the boolean as a string
    $email_verified = $claims['email_verified'] ?? false;
    if ($oidc_settings['require_verified_email'] && $email_verified !== true && $email_verified !== 'true') {
        logAudit("Client Login", "Failed", "OIDC login refused for $email_sql - email address not verified by the identity provider");
        oidcLoginFail("your email address has not been verified with $provider_name.");
    }

    $sql = mysqli_query($mysqli, "SELECT contact_client_id, contact_id, user_auth_method, user_email, user_id FROM users
        LEFT JOIN contacts ON user_id = contact_user_id
        LEFT JOIN clients ON contact_client_id = client_id
        WHERE user_email = '$email_sql'
        AND user_archived_at IS NULL
        AND client_archived_at IS NULL
        AND user_type = 2
        AND user_status = 1
        LIMIT 1"
    );
    $row = mysqli_fetch_assoc($sql);

    $client_id = intval($row['contact_client_id'] ?? 0);
    $user_id = intval($row['user_id'] ?? 0);
    $contact_id = intval($row['contact_id'] ?? 0);
    $user_auth_method = $row['user_auth_method'] ?? '';
    $session_user_id = $user_id; // to pass the user_id to logAudit function

    if (!$client_id || !$contact_id || $user_auth_method !== 'oidc') {
        logAudit("Client Login", "Failed", "OIDC login refused for $email_sql - no active contact configured for OIDC SSO", $client_id, $user_id);
        oidcLoginFail("your account is not configured for $provider_name sign-in. Please ensure you are set up in ITFlow as a contact with single sign-on enabled.");
    }

    // New session ID for the authenticated session (CWE-384)
    session_regenerate_id(true);

    $_SESSION['client_logged_in'] = true;
    $_SESSION['client_id'] = $client_id;
    $_SESSION['user_id'] = $user_id;
    $_SESSION['user_type'] = 2;
    $_SESSION['contact_id'] = $contact_id;
    $_SESSION['csrf_token'] = randomString(32);
    $_SESSION['login_method'] = "oidc";

    logAudit("Client Login", "Success", "Client contact $email_sql successfully logged in via OIDC ($provider_name_sql)", $client_id, $user_id);

    header("Location: index.php");
    exit();

}

// If the user is just sat on the page, send them back to log in to try again
header("Location: ../login.php");
exit();
