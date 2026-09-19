<?php
require_once "includes/inc_all_admin.php";

$oidc_settings = oidcGetSettings();
$oidc_redirect_uri = "https://$config_base_url/client/login_oidc.php";
$oidc_sso_login_url = "https://$config_base_url/client/login_sso.php";
 ?>

<div class="card card-dark">
    <div class="card-header py-3">
        <h3 class="card-title"><i class="fas fa-fw fa-fingerprint me-2"></i>Identity Providers</h3>
    </div>
    <div class="card-body">
        <form action="post.php" method="post" autocomplete="off">
            <input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token'] ?>">

            <h4>Client Portal SSO via Microsoft Entra</h4>

            <div class="mb-3">
                <label>Identity Provider <small class='text-secondary'>(Currently only works with Microsoft Entra ID/AAD)</small></label>
                <div class="input-group">
                        <span class="input-group-text"><i class="fa fa-fw fa-fingerprint"></i></span>
                    <select class="form-select select2" readonly>
                        <option <?php if (empty($config_azure_client_id)) { echo "selected"; } ?>>Disabled</option>
                        <option <?php if ($config_azure_client_id) { echo "selected"; } ?>>Microsoft Entra</option>
                        <option>Google (WIP)</option>
                    </select>
                </div>
            </div>

            <div class="mb-3">
                <label>MS Entra OAuth App (Client) ID</label>
                <div class="input-group">
                        <span class="input-group-text"><i class="fa fa-fw fa-user"></i></span>
                    <input type="text" class="form-control" name="azure_client_id" placeholder="e721e3b6-01d6-50e8-7f22-c84d951a52e7" maxlength="200" value="<?= escapeHtml($config_azure_client_id) ?>">
                </div>
            </div>

            <div class="mb-3">
                <label>MS Entra OAuth Secret</label>
                <div class="input-group">
                        <span class="input-group-text"><i class="fa fa-fw fa-key"></i></span>
                    <input type="password" class="form-control" name="azure_client_secret" placeholder="Auto-generated from App Registration" maxlength="200" value="<?= escapeHtml($config_azure_client_secret) ?>" autocomplete="new-password">
                </div>
            </div>

            <hr>

            <button type="submit" name="edit_identity_provider" class="btn btn-primary text-bold"><i class="fa fa-check me-2"></i>Save</button>

        </form>
    </div>
</div>

<div class="card card-dark">
    <div class="card-header py-3">
        <h3 class="card-title"><i class="fas fa-fw fa-id-badge me-2"></i>Client Portal SSO via OpenID Connect</h3>
    </div>
    <div class="card-body">
        <form action="post.php" method="post" autocomplete="off">
            <input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token'] ?>">

            <p class="text-secondary">
                Works with any OpenID Connect provider (Authentik, Keycloak, Okta, Auth0, Google Workspace, JumpCloud, Entra ID, ...).
                Contacts set to <strong>OpenID Connect</strong> portal authentication are matched to their ITFlow contact by email address.
                Leave the Issuer URL blank to disable.
            </p>

            <div class="mb-3">
                <label>Redirect URI <small class="text-secondary">(register this with your provider)</small></label>
                <div class="input-group">
                    <span class="input-group-text"><i class="fa fa-fw fa-link"></i></span>
                    <input type="text" class="form-control" value="<?= escapeHtml($oidc_redirect_uri) ?>" readonly>
                    <button type="button" class="btn btn-default clipboardjs" data-clipboard-text="<?= escapeHtml($oidc_redirect_uri) ?>"><i class="fa fa-fw fa-copy"></i></button>
                </div>
            </div>

            <div class="mb-3">
                <label>SSO-only Client Login Page <small class="text-secondary">(share with clients - shows only the SSO button)</small></label>
                <div class="input-group">
                    <span class="input-group-text"><i class="fa fa-fw fa-sign-in-alt"></i></span>
                    <input type="text" class="form-control" value="<?= escapeHtml($oidc_sso_login_url) ?>" readonly>
                    <button type="button" class="btn btn-default clipboardjs" data-clipboard-text="<?= escapeHtml($oidc_sso_login_url) ?>"><i class="fa fa-fw fa-copy"></i></button>
                </div>
            </div>

            <div class="mb-3">
                <label>Issuer URL <small class="text-secondary">(/.well-known/openid-configuration is appended automatically)</small></label>
                <div class="input-group">
                    <span class="input-group-text"><i class="fa fa-fw fa-globe"></i></span>
                    <input type="url" class="form-control" name="oidc_issuer" placeholder="https://auth.example.com/application/o/itflow/" maxlength="500" value="<?= escapeHtml($oidc_settings['issuer']) ?>">
                </div>
            </div>

            <div class="mb-3">
                <label>Client ID</label>
                <div class="input-group">
                    <span class="input-group-text"><i class="fa fa-fw fa-user"></i></span>
                    <input type="text" class="form-control" name="oidc_client_id" placeholder="itflow" maxlength="500" value="<?= escapeHtml($oidc_settings['client_id']) ?>">
                </div>
            </div>

            <div class="mb-3">
                <label>Client Secret <small class="text-secondary">(<?= $oidc_settings['client_secret'] === '' ? 'not set - leave blank for a public client using PKCE only' : 'saved - leave blank to keep the current secret' ?>)</small></label>
                <div class="input-group">
                    <span class="input-group-text"><i class="fa fa-fw fa-key"></i></span>
                    <input type="password" class="form-control" name="oidc_client_secret" placeholder="<?= $oidc_settings['client_secret'] === '' ? '' : '********' ?>" maxlength="500" autocomplete="new-password">
                </div>
                <?php if ($oidc_settings['client_secret'] !== '') { ?>
                    <div class="form-check mt-1">
                        <input type="checkbox" class="form-check-input" name="oidc_clear_client_secret" value="1" id="oidcClearSecret">
                        <label class="form-check-label" for="oidcClearSecret">Clear saved secret</label>
                    </div>
                <?php } ?>
            </div>

            <div class="mb-3">
                <label>Login Button Label</label>
                <div class="input-group">
                    <span class="input-group-text"><i class="fa fa-fw fa-tag"></i></span>
                    <input type="text" class="form-control" name="oidc_display_name" placeholder="Single Sign-On" maxlength="200" value="<?= escapeHtml($oidc_settings['display_name']) ?>">
                </div>
            </div>

            <div class="mb-3">
                <label>Email Claim <small class="text-secondary">(claim matched against the contact's email - usually <code>email</code>; <code>preferred_username</code> or <code>upn</code> for Entra)</small></label>
                <div class="input-group">
                    <span class="input-group-text"><i class="fa fa-fw fa-envelope"></i></span>
                    <input type="text" class="form-control" name="oidc_email_claim" placeholder="email" maxlength="100" pattern="[A-Za-z0-9_:.\-]+" value="<?= escapeHtml($oidc_settings['email_claim']) ?>">
                </div>
            </div>

            <div class="form-check form-switch mb-3">
                <input type="checkbox" class="form-check-input" name="oidc_require_verified_email" value="1" id="oidcRequireVerified" <?php if ($oidc_settings['require_verified_email']) { echo "checked"; } ?>>
                <label class="form-check-label" for="oidcRequireVerified">Require <code>email_verified</code> to be true <small class="text-secondary">(recommended - turn off only for providers that never send it, e.g. Entra ID)</small></label>
            </div>

            <hr>

            <button type="submit" name="edit_oidc_provider" class="btn btn-primary text-bold"><i class="fa fa-check me-2"></i>Save</button>

        </form>
    </div>
</div>

<?php require_once "../includes/footer.php";
