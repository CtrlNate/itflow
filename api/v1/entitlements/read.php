<?php

/*
 * API - entitlements/read.php
 *
 * Feeds an external identity provider (Authentik) the app access each client
 * contact has, so ITFlow stays the source of truth and no code change is needed
 * to add an app.
 *
 * Apps are modelled as tags named "app:<slug>", created twice in Admin > Tags:
 * once as a Client tag (type 1) and once as a Contact tag (type 3).
 *
 * Access is a ceiling checked at both levels. The client tag says the client has
 * opted into the app; the contact tag says this person may use it. Effective
 * access is the intersection, matched on tag name because the two tags are
 * separate rows of different types. Removing the client's tag therefore revokes
 * the app for everyone there in one step.
 *
 * Returned per contact:
 *   apps         - effective access, the only field a sync should act on
 *   client_apps  - what the client has opted into
 *   contact_apps - what the contact is tagged with, granted or not
 * The last two make "why can't this person reach the app?" answerable from the
 * feed alone: a contact tag with no matching client tag shows up in contact_apps
 * and not in apps.
 *
 * By default only contacts with at least one effective app are returned, since
 * those are the ones the IdP needs an account for - a contact does NOT need an
 * ITFlow portal login to be granted an app. Pass include_all=1 to list every
 * contact regardless, which is what you want when troubleshooting a grant.
 *
 * Archived contacts and contacts of archived clients are returned with
 * active = false rather than dropped, so the sync can deactivate them instead of
 * losing track of them.
 *
 * There is deliberately no updated_since filter: tagging a contact does not touch
 * contact_updated_at, so such a filter would silently miss the exact changes this
 * endpoint exists to report. The sync does a full reconcile each run instead.
 */

require_once '../validate_api_key.php';

require_once '../require_get_method.php';

// "app:" - tag names are matched on this prefix and it is stripped from the output
DEFINE("ENTITLEMENT_TAG_PREFIX", "app:");
$prefix = ENTITLEMENT_TAG_PREFIX;
$prefix_len = strlen($prefix) + 1; // SUBSTRING() is 1-indexed

$include_all = !empty($_GET['include_all']);

// Optional single-contact lookup (client_id filtering is handled by apiClientScopeSql)
$contact_filter = "";
if (isset($_GET['contact_email'])) {
    $contact_email = escapeSql($_GET['contact_email']);
    $contact_filter = " AND contacts.contact_email = '$contact_email'";
} elseif (isset($_GET['contact_id'])) {
    $contact_filter = " AND contacts.contact_id = " . intval($_GET['contact_id']);
}

// The client's opted-in apps
$client_apps_sql = "(SELECT GROUP_CONCAT(DISTINCT SUBSTRING(client_tag.tag_name, $prefix_len) ORDER BY client_tag.tag_name SEPARATOR ',')
    FROM client_tags
    JOIN tags AS client_tag ON client_tag.tag_id = client_tags.tag_id
    WHERE client_tags.client_id = clients.client_id
    AND client_tag.tag_name LIKE '$prefix%'
    AND client_tag.tag_archived_at IS NULL)";

// What the contact is tagged with, whether or not the client has the app
$contact_apps_sql = "(SELECT GROUP_CONCAT(DISTINCT SUBSTRING(contact_tag.tag_name, $prefix_len) ORDER BY contact_tag.tag_name SEPARATOR ',')
    FROM contact_tags
    JOIN tags AS contact_tag ON contact_tag.tag_id = contact_tags.tag_id
    WHERE contact_tags.contact_id = contacts.contact_id
    AND contact_tag.tag_name LIKE '$prefix%'
    AND contact_tag.tag_archived_at IS NULL)";

// Effective access: contact tags that the client has also opted into (matched by name)
$apps_sql = "(SELECT GROUP_CONCAT(DISTINCT SUBSTRING(contact_tag.tag_name, $prefix_len) ORDER BY contact_tag.tag_name SEPARATOR ',')
    FROM contact_tags
    JOIN tags AS contact_tag ON contact_tag.tag_id = contact_tags.tag_id
    WHERE contact_tags.contact_id = contacts.contact_id
    AND contact_tag.tag_name LIKE '$prefix%'
    AND contact_tag.tag_archived_at IS NULL
    AND EXISTS (
        SELECT 1 FROM client_tags
        JOIN tags AS client_tag ON client_tag.tag_id = client_tags.tag_id
        WHERE client_tags.client_id = clients.client_id
        AND client_tag.tag_name = contact_tag.tag_name
        AND client_tag.tag_archived_at IS NULL
    ))";

// A contact with no portal user still gets an entry - the LEFT JOIN leaves
// auth_method null and active then rests on the contact and client alone
$active_sql = "CASE WHEN contacts.contact_archived_at IS NULL
    AND clients.client_archived_at IS NULL
    AND (contacts.contact_user_id = 0 OR (users.user_status = 1 AND users.user_archived_at IS NULL))
    THEN 1 ELSE 0 END";

$having = $include_all ? "" : "HAVING apps IS NOT NULL";

$sql = mysqli_query($mysqli, "SELECT contacts.contact_id, contacts.contact_name, contacts.contact_email,
        contacts.contact_client_id AS client_id, clients.client_name,
        users.user_auth_method AS auth_method,
        $active_sql AS active,
        $apps_sql AS apps,
        $client_apps_sql AS client_apps,
        $contact_apps_sql AS contact_apps
    FROM contacts
    JOIN clients ON clients.client_id = contacts.contact_client_id
    LEFT JOIN users ON users.user_id = contacts.contact_user_id AND users.user_type = 2
    WHERE 1=1 " . apiClientScopeSql('contacts.contact_client_id') . "
    $contact_filter
    $having
    ORDER BY contacts.contact_id LIMIT $limit OFFSET $offset");

// Output
// Not read_output.php: that echoes rows as they come out of MySQL, and the three
// app columns are GROUP_CONCAT strings that belong in the response as arrays.
if ($sql && mysqli_num_rows($sql) > 0) {

    $return_arr['success'] = "True";
    $return_arr['count'] = mysqli_num_rows($sql);

    while ($row = mysqli_fetch_assoc($sql)) {
        // mysqli hands back every column as a string - ids and flags are typed
        // here so the sync can compare them without casting each one itself
        $row['contact_id'] = intval($row['contact_id']);
        $row['client_id'] = intval($row['client_id']);
        $row['active'] = (bool) intval($row['active']);
        foreach (['apps', 'client_apps', 'contact_apps'] as $app_field) {
            $row[$app_field] = empty($row[$app_field]) ? [] : explode(',', $row[$app_field]);
        }
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
