<?php

/*
 * ITFlow - Generic OpenID Connect (OIDC) helpers
 *
 * Backs client portal SSO against any standards-compliant OIDC provider
 * (Authentik, Keycloak, Okta, Auth0, Google, Entra ID, JumpCloud, ...).
 * client/login_oidc.php drives the flow; everything here is stateless.
 *
 * Flow: authorization code + PKCE (S256) + nonce. The ID token is validated
 * locally - signature against the provider's JWKS, then iss / aud / azp / exp /
 * iat / nonce - so we never trust claims we did not verify.
 *
 * No third-party JWT library: RS*, ES* and HS* are verified with ext-openssl and
 * hash_hmac. JWKs are converted to PEM by hand-rolling the small amount of
 * DER needed for a SubjectPublicKeyInfo.
 */

// Signing algorithms we accept on an ID token. 'none' is never accepted.
DEFINE("OIDC_ALLOWED_ALGS", ['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512', 'HS256', 'HS384', 'HS512']);

// Tolerance for clock drift between us and the provider when checking exp/iat
DEFINE("OIDC_CLOCK_LEEWAY", 120);

/*
 * OIDC settings, read with SELECT * so a missing column (migration not yet run)
 * reads as "not configured" instead of taking the page down. Cached per request.
 */
function oidcGetSettings($refresh = false) {
    global $mysqli;
    static $settings = null;

    if ($settings !== null && !$refresh) {
        return $settings;
    }

    $sql = mysqli_query($mysqli, "SELECT * FROM settings WHERE company_id = 1");
    $row = $sql ? mysqli_fetch_assoc($sql) : [];

    return $settings = [
        'issuer'                => trim((string) ($row['config_oidc_issuer'] ?? '')),
        'client_id'             => trim((string) ($row['config_oidc_client_id'] ?? '')),
        'client_secret'         => (string) ($row['config_oidc_client_secret'] ?? ''),
        'display_name'          => trim((string) ($row['config_oidc_display_name'] ?? '')),
        'email_claim'           => trim((string) ($row['config_oidc_email_claim'] ?? '')) ?: 'email',
        'require_verified_email' => intval($row['config_oidc_require_verified_email'] ?? 1),
    ];
}

// True when enough is configured to attempt a login
function oidcIsConfigured($settings = null) {
    $settings = $settings ?? oidcGetSettings();
    return !empty($settings['issuer']) && !empty($settings['client_id']);
}

// Label for the login button / profile page
function oidcDisplayName($settings = null) {
    $settings = $settings ?? oidcGetSettings();
    return $settings['display_name'] ?: 'Single Sign-On';
}

/*
 * Issuer must be https - the discovery document tells us where to send the
 * client secret and which keys to trust, so it cannot come over plain HTTP.
 * http://localhost is allowed for local testing against a dev IdP.
 */
function oidcIssuerIsAcceptable($issuer) {
    $parts = parse_url($issuer);
    if (!$parts || empty($parts['scheme']) || empty($parts['host'])) {
        return false;
    }
    if ($parts['scheme'] === 'https') {
        return true;
    }
    return $parts['scheme'] === 'http' && in_array($parts['host'], ['localhost', '127.0.0.1', '::1'], true);
}

function oidcBase64UrlEncode($data) {
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

function oidcBase64UrlDecode($data) {
    $data = strtr((string) $data, '-_', '+/');
    $pad = strlen($data) % 4;
    if ($pad) {
        $data .= str_repeat('=', 4 - $pad);
    }
    return base64_decode($data, true);
}

/*
 * Minimal HTTP client for the back-channel calls. Returns
 * ['status' => int, 'json' => array|null] or throws on transport failure.
 */
function oidcHttpRequest($url, $post_fields = null, $headers = []) {
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 15,
        CURLOPT_CONNECTTIMEOUT => 10,
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_PROTOCOLS      => CURLPROTO_HTTPS | CURLPROTO_HTTP,
        CURLOPT_HTTPHEADER     => array_merge(['Accept: application/json'], $headers),
    ]);

    if ($post_fields !== null) {
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($post_fields, '', '&'));
    }

    $body = curl_exec($ch);
    $status = intval(curl_getinfo($ch, CURLINFO_HTTP_CODE));
    $error = curl_error($ch);

    if ($body === false) {
        throw new RuntimeException("HTTP request to $url failed: $error");
    }

    $json = json_decode($body, true);

    return ['status' => $status, 'json' => is_array($json) ? $json : null];
}

/*
 * Fetches and sanity checks /.well-known/openid-configuration.
 * The issuer in the document must match the configured issuer (OIDC Discovery
 * 4.3) - otherwise a misconfigured or hostile document could vouch for tokens
 * from somewhere else.
 */
function oidcDiscover($issuer) {
    if (!oidcIssuerIsAcceptable($issuer)) {
        throw new RuntimeException("Issuer URL must use https");
    }

    $url = rtrim($issuer, '/') . '/.well-known/openid-configuration';
    $response = oidcHttpRequest($url);

    if ($response['status'] !== 200 || !$response['json']) {
        throw new RuntimeException("Discovery document at $url returned HTTP " . $response['status']);
    }

    $doc = $response['json'];

    foreach (['issuer', 'authorization_endpoint', 'token_endpoint', 'jwks_uri'] as $required) {
        if (empty($doc[$required]) || !is_string($doc[$required])) {
            throw new RuntimeException("Discovery document is missing $required");
        }
    }

    // Tolerate a trailing slash difference in what the admin typed, nothing more
    if (rtrim($doc['issuer'], '/') !== rtrim($issuer, '/')) {
        throw new RuntimeException("Discovery issuer '" . $doc['issuer'] . "' does not match configured issuer '$issuer'");
    }

    foreach (['authorization_endpoint', 'token_endpoint', 'jwks_uri'] as $endpoint) {
        if (!oidcIssuerIsAcceptable($doc[$endpoint])) {
            throw new RuntimeException("Discovery $endpoint must use https");
        }
    }

    return $doc;
}

/*
 * Exchanges an authorization code for tokens. Uses client_secret_basic unless
 * the provider only advertises client_secret_post. With no secret configured
 * (a public client) PKCE alone protects the code.
 */
function oidcExchangeCode($discovery, $settings, $code, $redirect_uri, $code_verifier) {
    $fields = [
        'grant_type'    => 'authorization_code',
        'code'          => $code,
        'redirect_uri'  => $redirect_uri,
        'code_verifier' => $code_verifier,
    ];
    $headers = [];

    $auth_methods = $discovery['token_endpoint_auth_methods_supported'] ?? ['client_secret_basic'];

    if ($settings['client_secret'] === '') {
        $fields['client_id'] = $settings['client_id'];
    } elseif (in_array('client_secret_basic', $auth_methods, true)) {
        // RFC 6749 2.3.1 - both halves are form-encoded before being joined
        $headers[] = 'Authorization: Basic ' . base64_encode(urlencode($settings['client_id']) . ':' . urlencode($settings['client_secret']));
    } else {
        $fields['client_id'] = $settings['client_id'];
        $fields['client_secret'] = $settings['client_secret'];
    }

    $response = oidcHttpRequest($discovery['token_endpoint'], $fields, $headers);

    if ($response['status'] !== 200 || empty($response['json']['id_token'])) {
        $error = $response['json']['error'] ?? 'no id_token';
        throw new RuntimeException("Token endpoint returned HTTP " . $response['status'] . " ($error)");
    }

    return $response['json'];
}

/*
 * DER helpers - just enough ASN.1 to wrap a JWK as a SubjectPublicKeyInfo PEM
 */
function oidcDerLength($length) {
    if ($length < 0x80) {
        return chr($length);
    }
    $bytes = ltrim(pack('N', $length), "\x00");
    return chr(0x80 | strlen($bytes)) . $bytes;
}

function oidcDer($tag, $contents) {
    return chr($tag) . oidcDerLength(strlen($contents)) . $contents;
}

// Unsigned big-endian integer -> DER INTEGER (leading 0x00 if the high bit is set)
function oidcDerInteger($bytes) {
    $bytes = ltrim($bytes, "\x00");
    if ($bytes === '' || (ord($bytes[0]) & 0x80)) {
        $bytes = "\x00" . $bytes;
    }
    return oidcDer(0x02, $bytes);
}

function oidcPem($spki) {
    return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($spki), 64, "\n") . "-----END PUBLIC KEY-----\n";
}

// JWK (kty RSA or EC) -> PEM public key, or null if unsupported
function oidcJwkToPem($jwk) {
    $kty = $jwk['kty'] ?? '';

    if ($kty === 'RSA' && !empty($jwk['n']) && !empty($jwk['e'])) {
        $n = oidcBase64UrlDecode($jwk['n']);
        $e = oidcBase64UrlDecode($jwk['e']);
        if ($n === false || $e === false) {
            return null;
        }
        $rsa_public_key = oidcDer(0x30, oidcDerInteger($n) . oidcDerInteger($e));
        // rsaEncryption OID 1.2.840.113549.1.1.1 + NULL params
        $algorithm = oidcDer(0x30, "\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01" . "\x05\x00");
        return oidcPem(oidcDer(0x30, $algorithm . oidcDer(0x03, "\x00" . $rsa_public_key)));
    }

    if ($kty === 'EC' && !empty($jwk['x']) && !empty($jwk['y'])) {
        $curves = [
            'P-256' => ["\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07", 32],
            'P-384' => ["\x06\x05\x2b\x81\x04\x00\x22", 48],
            'P-521' => ["\x06\x05\x2b\x81\x04\x00\x23", 66],
        ];
        $crv = $jwk['crv'] ?? '';
        if (!isset($curves[$crv])) {
            return null;
        }
        [$curve_oid, $size] = $curves[$crv];
        $x = oidcBase64UrlDecode($jwk['x']);
        $y = oidcBase64UrlDecode($jwk['y']);
        if ($x === false || $y === false) {
            return null;
        }
        $x = str_pad($x, $size, "\x00", STR_PAD_LEFT);
        $y = str_pad($y, $size, "\x00", STR_PAD_LEFT);
        // id-ecPublicKey OID 1.2.840.10045.2.1
        $algorithm = oidcDer(0x30, "\x06\x07\x2a\x86\x48\xce\x3d\x02\x01" . $curve_oid);
        return oidcPem(oidcDer(0x30, $algorithm . oidcDer(0x03, "\x00\x04" . $x . $y)));
    }

    return null;
}

// JWS ES* signatures are raw r||s; openssl_verify wants a DER ECDSA-Sig-Value
function oidcEcdsaRawToDer($signature, $size) {
    if (strlen($signature) !== $size * 2) {
        return null;
    }
    $r = substr($signature, 0, $size);
    $s = substr($signature, $size);
    return oidcDer(0x30, oidcDerInteger($r) . oidcDerInteger($s));
}

/*
 * Picks the JWK that should have signed a token with this header. Matches on
 * kid when the token has one; otherwise only if exactly one key fits the alg.
 */
function oidcFindJwk($jwks, $header) {
    $alg = $header['alg'];
    $kty = str_starts_with($alg, 'RS') ? 'RSA' : 'EC';
    $candidates = [];

    foreach ($jwks['keys'] ?? [] as $jwk) {
        if (!is_array($jwk) || ($jwk['kty'] ?? '') !== $kty) {
            continue;
        }
        if (isset($jwk['use']) && $jwk['use'] !== 'sig') {
            continue;
        }
        if (isset($jwk['alg']) && $jwk['alg'] !== $alg) {
            continue;
        }
        if (isset($header['kid'])) {
            if (($jwk['kid'] ?? null) === $header['kid']) {
                return $jwk;
            }
            continue;
        }
        $candidates[] = $jwk;
    }

    return count($candidates) === 1 ? $candidates[0] : null;
}

/*
 * Verifies an ID token's signature and standard claims (OIDC Core 3.1.3.7).
 * Returns the claims array, or throws with a reason suitable for the app log.
 */
function oidcValidateIdToken($id_token, $discovery, $settings, $expected_nonce) {
    $parts = explode('.', (string) $id_token);
    if (count($parts) !== 3) {
        throw new RuntimeException("ID token is not a JWS compact serialization");
    }
    [$header_b64, $payload_b64, $signature_b64] = $parts;

    $header = json_decode((string) oidcBase64UrlDecode($header_b64), true);
    $claims = json_decode((string) oidcBase64UrlDecode($payload_b64), true);
    $signature = oidcBase64UrlDecode($signature_b64);

    if (!is_array($header) || !is_array($claims) || $signature === false) {
        throw new RuntimeException("ID token could not be decoded");
    }

    $alg = $header['alg'] ?? '';
    if (!in_array($alg, OIDC_ALLOWED_ALGS, true)) {
        throw new RuntimeException("ID token alg '$alg' is not allowed");
    }

    $signing_input = "$header_b64.$payload_b64";
    $hash_bits = substr($alg, 2);

    if (str_starts_with($alg, 'HS')) {
        // Symmetric - keyed with the client secret, so only valid for a confidential client
        if ($settings['client_secret'] === '') {
            throw new RuntimeException("ID token uses $alg but no client secret is configured");
        }
        $expected = hash_hmac("sha$hash_bits", $signing_input, $settings['client_secret'], true);
        if (!hash_equals($expected, $signature)) {
            throw new RuntimeException("ID token signature is invalid");
        }
    } else {
        $jwks_response = oidcHttpRequest($discovery['jwks_uri']);
        if ($jwks_response['status'] !== 200 || !$jwks_response['json']) {
            throw new RuntimeException("JWKS endpoint returned HTTP " . $jwks_response['status']);
        }

        $jwk = oidcFindJwk($jwks_response['json'], $header);
        $pem = $jwk ? oidcJwkToPem($jwk) : null;
        if (!$pem) {
            throw new RuntimeException("No usable signing key in JWKS for kid '" . ($header['kid'] ?? '') . "'");
        }

        if (str_starts_with($alg, 'ES')) {
            $ec_sizes = ['256' => 32, '384' => 48, '512' => 66];
            $signature = oidcEcdsaRawToDer($signature, $ec_sizes[$hash_bits]);
            if ($signature === null) {
                throw new RuntimeException("ID token signature has the wrong length for $alg");
            }
        }

        $openssl_algs = ['256' => OPENSSL_ALGO_SHA256, '384' => OPENSSL_ALGO_SHA384, '512' => OPENSSL_ALGO_SHA512];
        if (openssl_verify($signing_input, $signature, $pem, $openssl_algs[$hash_bits]) !== 1) {
            throw new RuntimeException("ID token signature is invalid");
        }
    }

    // Claims
    $now = time();

    if (($claims['iss'] ?? null) !== $discovery['issuer']) {
        throw new RuntimeException("ID token iss does not match the provider");
    }

    $aud = $claims['aud'] ?? [];
    $aud = is_array($aud) ? $aud : [$aud];
    if (!in_array($settings['client_id'], $aud, true)) {
        throw new RuntimeException("ID token aud does not include our client ID");
    }
    if ((count($aud) > 1 || isset($claims['azp'])) && ($claims['azp'] ?? null) !== $settings['client_id']) {
        throw new RuntimeException("ID token azp is not our client ID");
    }

    if (!isset($claims['exp']) || !is_numeric($claims['exp']) || $now > intval($claims['exp']) + OIDC_CLOCK_LEEWAY) {
        throw new RuntimeException("ID token has expired");
    }
    if (isset($claims['iat']) && is_numeric($claims['iat']) && intval($claims['iat']) > $now + OIDC_CLOCK_LEEWAY) {
        throw new RuntimeException("ID token was issued in the future");
    }

    if (!isset($claims['nonce']) || !is_string($claims['nonce']) || !hash_equals($expected_nonce, $claims['nonce'])) {
        throw new RuntimeException("ID token nonce does not match");
    }

    if (empty($claims['sub'])) {
        throw new RuntimeException("ID token has no sub");
    }

    return $claims;
}

/*
 * Some providers leave email/email_verified out of the ID token and only
 * return them from the UserInfo endpoint. Merge those in, but only after
 * checking the UserInfo sub matches the verified ID token (OIDC Core 5.3.2).
 */
function oidcMergeUserinfo($claims, $discovery, $access_token) {
    if (empty($discovery['userinfo_endpoint']) || empty($access_token) || !oidcIssuerIsAcceptable($discovery['userinfo_endpoint'])) {
        return $claims;
    }

    $response = oidcHttpRequest($discovery['userinfo_endpoint'], null, ['Authorization: Bearer ' . $access_token]);

    if ($response['status'] !== 200 || !$response['json']) {
        return $claims;
    }

    if (($response['json']['sub'] ?? null) !== $claims['sub']) {
        throw new RuntimeException("UserInfo sub does not match ID token sub");
    }

    // ID token values win - they are the ones we verified the signature on
    return $claims + $response['json'];
}
