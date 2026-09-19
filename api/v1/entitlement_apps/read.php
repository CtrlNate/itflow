<?php

/*
 * API - entitlement_apps/read.php
 *
 * Lists every app defined as an "app:<slug>" tag, so a sync can create the
 * matching IdP groups before it assigns anyone to them. Companion to
 * entitlements/read.php, which is where the per-contact grants live.
 *
 * Its own resource directory rather than entitlements/apps.php: the RBAC
 * enforcer grades permission by file name and only read.php means "read"
 * (level 1). Any other name would default to level 2 - write permission - to
 * read a list.
 *
 * has_client_tag / has_contact_tag exist because an app needs the tag on BOTH
 * sides to be grantable (Client tag = the client opted in, Contact tag = this
 * person may use it). An app showing false for either is half-created in
 * Admin > Tags and can never produce effective access, which is otherwise a
 * confusing thing to debug.
 */

require_once '../validate_api_key.php';

require_once '../require_get_method.php';

DEFINE("ENTITLEMENT_TAG_PREFIX", "app:");
$prefix = ENTITLEMENT_TAG_PREFIX;
$prefix_len = strlen($prefix) + 1; // SUBSTRING() is 1-indexed

// Tag types, per admin/tags.php: 1 = Client, 3 = Contact
$sql = mysqli_query($mysqli, "SELECT SUBSTRING(tag_name, $prefix_len) AS app,
        tag_name AS tag,
        MAX(CASE WHEN tag_type = 1 THEN 1 ELSE 0 END) AS has_client_tag,
        MAX(CASE WHEN tag_type = 3 THEN 1 ELSE 0 END) AS has_contact_tag
    FROM tags
    WHERE tag_name LIKE '$prefix%'
    AND tag_archived_at IS NULL
    GROUP BY tag_name
    ORDER BY tag_name LIMIT $limit OFFSET $offset");

// Output - as in entitlements/read.php, the flags are cast to booleans rather
// than passed through as MySQL's 1/0 strings
if ($sql && mysqli_num_rows($sql) > 0) {

    $return_arr['success'] = "True";
    $return_arr['count'] = mysqli_num_rows($sql);

    while ($row = mysqli_fetch_assoc($sql)) {
        $row['has_client_tag'] = (bool) intval($row['has_client_tag']);
        $row['has_contact_tag'] = (bool) intval($row['has_contact_tag']);
        $return_arr['data'][] = $row;
    }

    echo json_encode($return_arr);
    exit();

} else {

    $return_arr['success'] = "False";
    $return_arr['message'] = "No resource (for this client and company) with the specified parameter(s).";

    logApp("API", "Error", "Read query failed on API call to " . escapeSql(parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH)) . " containing " . count($_GET) . " GET variables" . " via API key " . escapeSql($api_key_name) . " from IP " . escapeSql(getIP()) . " with agent " . escapeSql(getUserAgent()));

    if (mysqli_error($mysqli)) {
        error_log("API Database Error: " . mysqli_error($mysqli));
    }

    echo json_encode($return_arr);
    exit();

}
