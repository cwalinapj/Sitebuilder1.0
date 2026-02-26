<?php
/**
 * Plugin Name: TollDNS
 * Description: DNS readiness checks and points ledger for the AI WebAdmin free-tier workflow.
 * Version: 0.1.2
 * Author: Sitebuilder
 * License: GPLv2 or later
 * Update URI: https://app.cardetailingreno.com/plugin-updates/tolldns.json
 */

if (!defined("ABSPATH")) {
    exit;
}

define("TOLLDNS_OPTION_KEY", "tolldns_settings");
define("TOLLDNS_LEDGER_TABLE", "tolldns_points_ledger");
define("TOLLDNS_CRON_HOOK", "tolldns_hourly_check_event");
define("TOLLDNS_VERSION", "0.1.2");
define("TOLLDNS_PLUGIN_BASENAME", plugin_basename(__FILE__));
define("TOLLDNS_PLUGIN_SLUG", "tolldns");
define("TOLLDNS_UPDATE_META_URL", "https://app.cardetailingreno.com/plugin-updates/tolldns.json");
define("TOLLDNS_UPDATE_META_CACHE_KEY", "tolldns_remote_update_meta");

function tolldns_default_settings() {
    $host = wp_parse_url(home_url("/"), PHP_URL_HOST);
    if (!is_string($host) || $host === "") {
        $host = "";
    }
    return [
        "monitored_domain" => strtolower(trim((string)$host)),
        "expected_ns1" => "",
        "expected_ns2" => "",
        "ingest_shared_secret" => "",
        "owner_reward_points_per_paid_toll" => 1,
        "points_total" => 0,
        "last_check_at" => 0,
        "last_check_status" => "not_checked",
        "last_check_message" => "",
        "last_check_delta" => 0,
    ];
}

function tolldns_get_settings() {
    $defaults = tolldns_default_settings();
    $stored = get_option(TOLLDNS_OPTION_KEY, []);
    if (!is_array($stored)) {
        $stored = [];
    }
    return array_merge($defaults, $stored);
}

function tolldns_save_settings($input) {
    $current = tolldns_get_settings();
    $next = [
        "monitored_domain" => tolldns_normalize_domain($input["monitored_domain"] ?? $current["monitored_domain"]),
        "expected_ns1" => tolldns_normalize_ns($input["expected_ns1"] ?? $current["expected_ns1"]),
        "expected_ns2" => tolldns_normalize_ns($input["expected_ns2"] ?? $current["expected_ns2"]),
        "ingest_shared_secret" => isset($input["ingest_shared_secret"])
            ? sanitize_text_field(trim((string)$input["ingest_shared_secret"]))
            : sanitize_text_field((string)($current["ingest_shared_secret"] ?? "")),
        "owner_reward_points_per_paid_toll" => max(1, min(100000, (int)($input["owner_reward_points_per_paid_toll"] ?? $current["owner_reward_points_per_paid_toll"]))),
        "points_total" => (int)($current["points_total"] ?? 0),
        "last_check_at" => (int)($current["last_check_at"] ?? 0),
        "last_check_status" => sanitize_text_field((string)($current["last_check_status"] ?? "not_checked")),
        "last_check_message" => sanitize_text_field((string)($current["last_check_message"] ?? "")),
        "last_check_delta" => (int)($current["last_check_delta"] ?? 0),
    ];
    update_option(TOLLDNS_OPTION_KEY, $next, false);
    return $next;
}

function tolldns_normalize_domain($value) {
    $raw = strtolower(trim((string)$value));
    $raw = preg_replace('#^https?://#', '', $raw);
    $raw = trim((string)$raw, "/ ");
    if ($raw === "") {
        return "";
    }
    if (!preg_match('/^[a-z0-9.-]+$/', $raw)) {
        return "";
    }
    return $raw;
}

function tolldns_normalize_ns($value) {
    $raw = strtolower(trim((string)$value));
    $raw = trim($raw, ". ");
    if ($raw === "") {
        return "";
    }
    if (!preg_match('/^[a-z0-9.-]+$/', $raw)) {
        return "";
    }
    return $raw;
}

function tolldns_ledger_table() {
    global $wpdb;
    return $wpdb->prefix . TOLLDNS_LEDGER_TABLE;
}

function tolldns_ensure_schema() {
    global $wpdb;
    require_once ABSPATH . "wp-admin/includes/upgrade.php";
    $table = tolldns_ledger_table();
    $charset = $wpdb->get_charset_collate();
    $sql = "CREATE TABLE {$table} (
        id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
        event_type varchar(64) NOT NULL,
        points_delta int NOT NULL,
        meta_json longtext NULL,
        created_at datetime NOT NULL,
        PRIMARY KEY  (id),
        KEY event_type (event_type),
        KEY created_at (created_at)
    ) {$charset};";
    dbDelta($sql);
}

function tolldns_add_points_entry($eventType, $delta, $meta = []) {
    global $wpdb;
    $delta = (int)$delta;
    $eventType = sanitize_key((string)$eventType);
    if ($eventType === "") {
        $eventType = "manual";
    }

    $table = tolldns_ledger_table();
    $wpdb->insert(
        $table,
        [
            "event_type" => $eventType,
            "points_delta" => $delta,
            "meta_json" => wp_json_encode(is_array($meta) ? $meta : []),
            "created_at" => gmdate("Y-m-d H:i:s"),
        ],
        ["%s", "%d", "%s", "%s"]
    );

    $settings = tolldns_get_settings();
    $settings["points_total"] = max(0, (int)$settings["points_total"] + $delta);
    $settings["last_check_delta"] = $delta;
    update_option(TOLLDNS_OPTION_KEY, $settings, false);
}

function tolldns_get_recent_ledger($limit = 20) {
    global $wpdb;
    $limit = max(1, min(100, (int)$limit));
    $table = tolldns_ledger_table();
    $rows = $wpdb->get_results(
        $wpdb->prepare("SELECT id, event_type, points_delta, meta_json, created_at FROM {$table} ORDER BY id DESC LIMIT %d", $limit),
        ARRAY_A
    );
    return is_array($rows) ? $rows : [];
}

function tolldns_points_metrics_window($windowSeconds = DAY_IN_SECONDS) {
    global $wpdb;
    $table = tolldns_ledger_table();
    $window = max(60, min(365 * DAY_IN_SECONDS, (int)$windowSeconds));
    $since = gmdate("Y-m-d H:i:s", time() - $window);
    $totals = $wpdb->get_row(
        $wpdb->prepare(
            "SELECT COUNT(*) AS events_count, COALESCE(SUM(points_delta), 0) AS points_sum
             FROM {$table}
             WHERE event_type = %s AND created_at >= %s",
            "visitor_toll_paid",
            $since
        ),
        ARRAY_A
    );
    $last = $wpdb->get_var(
        $wpdb->prepare(
            "SELECT created_at FROM {$table} WHERE event_type = %s ORDER BY id DESC LIMIT 1",
            "visitor_toll_paid"
        )
    );
    $lastTs = 0;
    if (is_string($last) && trim($last) !== "") {
        $parsed = strtotime($last . " UTC");
        if ($parsed !== false) {
            $lastTs = (int)$parsed;
        }
    }
    return [
        "window_seconds" => $window,
        "paid_toll_events_count" => is_array($totals) ? max(0, (int)($totals["events_count"] ?? 0)) : 0,
        "owner_points_from_paid_tolls" => is_array($totals) ? (int)($totals["points_sum"] ?? 0) : 0,
        "last_paid_toll_at" => $lastTs,
    ];
}

function tolldns_verify_ingest_signature($rawBody, $timestampHeader, $signatureHeader, $secret) {
    $secret = trim((string)$secret);
    if ($secret === "") {
        return new WP_Error("tolldns_missing_secret", "TollDNS ingest secret is not configured.");
    }
    $tsRaw = trim((string)$timestampHeader);
    $sigRaw = trim((string)$signatureHeader);
    if ($tsRaw === "" || $sigRaw === "") {
        return new WP_Error("tolldns_missing_signature", "Missing TollDNS signature headers.");
    }
    if (!preg_match('/^\d{10,13}$/', $tsRaw)) {
        return new WP_Error("tolldns_invalid_timestamp", "Invalid TollDNS timestamp.");
    }
    $ts = (int)$tsRaw;
    if (strlen($tsRaw) === 13) {
        $ts = (int)floor($ts / 1000);
    }
    if (abs(time() - $ts) > 5 * MINUTE_IN_SECONDS) {
        return new WP_Error("tolldns_expired_timestamp", "TollDNS signature timestamp expired.");
    }
    $expected = hash_hmac("sha256", $tsRaw . "." . (string)$rawBody, $secret);
    if (!hash_equals(strtolower($expected), strtolower($sigRaw))) {
        return new WP_Error("tolldns_invalid_signature", "Invalid TollDNS request signature.");
    }
    return true;
}

function tolldns_ingest_event_seen($eventId) {
    global $wpdb;
    $eventId = sanitize_text_field((string)$eventId);
    if ($eventId === "") {
        return false;
    }
    $table = tolldns_ledger_table();
    $needle = '%"event_id":"' . $wpdb->esc_like($eventId) . '"%';
    $id = $wpdb->get_var(
        $wpdb->prepare(
            "SELECT id FROM {$table} WHERE meta_json LIKE %s ORDER BY id DESC LIMIT 1",
            $needle
        )
    );
    return !empty($id);
}

function tolldns_detect_nameservers($domain) {
    $domain = tolldns_normalize_domain($domain);
    if ($domain === "") {
        return [];
    }

    if (!function_exists("dns_get_record")) {
        return [];
    }

    $records = @dns_get_record($domain, DNS_NS);
    if (!is_array($records)) {
        return [];
    }

    $nameservers = [];
    foreach ($records as $record) {
        if (!is_array($record)) {
            continue;
        }
        $target = isset($record["target"]) ? strtolower(trim((string)$record["target"], ". ")) : "";
        if ($target !== "") {
            $nameservers[$target] = true;
        }
    }
    return array_values(array_keys($nameservers));
}

function tolldns_run_nameserver_check($source = "manual") {
    $settings = tolldns_get_settings();
    $domain = tolldns_normalize_domain($settings["monitored_domain"] ?? "");
    if ($domain === "") {
        $settings["last_check_at"] = time();
        $settings["last_check_status"] = "error";
        $settings["last_check_message"] = "Set a monitored domain before running checks.";
        $settings["last_check_delta"] = 0;
        update_option(TOLLDNS_OPTION_KEY, $settings, false);
        return $settings;
    }

    $detected = tolldns_detect_nameservers($domain);
    $expected = [];
    $ns1 = tolldns_normalize_ns($settings["expected_ns1"] ?? "");
    $ns2 = tolldns_normalize_ns($settings["expected_ns2"] ?? "");
    if ($ns1 !== "") {
        $expected[] = $ns1;
    }
    if ($ns2 !== "") {
        $expected[] = $ns2;
    }

    $delta = 0;
    $status = "warning";
    $message = "No nameservers detected yet.";

    if (count($detected) === 0) {
        $delta = -5;
        $status = "warning";
        $message = "No NS records were detected for {$domain}.";
    } elseif (count($expected) === 0) {
        if (count($detected) >= 2) {
            $delta = 8;
            $status = "ok";
            $message = "Detected " . count($detected) . " nameservers. Add expected NS values to enforce strict matching.";
        } else {
            $delta = 2;
            $status = "warning";
            $message = "Detected only " . count($detected) . " nameserver(s). Two are recommended.";
        }
    } else {
        $missing = [];
        foreach ($expected as $ns) {
            if (!in_array($ns, $detected, true)) {
                $missing[] = $ns;
            }
        }
        if (empty($missing)) {
            $delta = 15;
            $status = "ok";
            $message = "Nameserver match complete for {$domain}.";
        } else {
            $delta = -8;
            $status = "warning";
            $message = "Missing expected nameserver(s): " . implode(", ", $missing);
        }
    }

    $settings["last_check_at"] = time();
    $settings["last_check_status"] = $status;
    $settings["last_check_message"] = sanitize_text_field($message);
    update_option(TOLLDNS_OPTION_KEY, $settings, false);

    tolldns_add_points_entry("ns_check_" . sanitize_key((string)$source), $delta, [
        "domain" => $domain,
        "detected" => $detected,
        "expected" => $expected,
        "status" => $status,
    ]);

    return tolldns_get_settings();
}

function tolldns_settings_page_url() {
    return admin_url("options-general.php?page=tolldns");
}

function tolldns_auto_update_link_html() {
    if (!current_user_can("update_plugins")) {
        return "";
    }
    if (!function_exists("wp_is_auto_update_enabled_for_type") || !wp_is_auto_update_enabled_for_type("plugin")) {
        return "";
    }
    if (function_exists("wp_is_auto_update_forced_for_item")) {
        $forced = wp_is_auto_update_forced_for_item("plugin", (object)[
            "plugin" => TOLLDNS_PLUGIN_BASENAME,
            "slug" => TOLLDNS_PLUGIN_SLUG,
        ]);
        if ($forced === true) {
            return esc_html__("Auto-updates enabled by policy", "tolldns");
        }
        if ($forced === false) {
            return esc_html__("Auto-updates disabled by policy", "tolldns");
        }
    }
    $enabled = in_array(TOLLDNS_PLUGIN_BASENAME, (array)get_site_option("auto_update_plugins", []), true);
    $action = $enabled ? "disable-auto-update" : "enable-auto-update";
    $label = $enabled ? "Disable auto-updates" : "Enable auto-updates";
    $url = add_query_arg([
        "action" => $action,
        "plugin" => TOLLDNS_PLUGIN_BASENAME,
    ], admin_url("plugins.php"));
    return '<a href="' . esc_url(wp_nonce_url($url, "updates")) . '">' . esc_html($label) . "</a>";
}

function tolldns_plugin_action_links($links) {
    if (current_user_can("manage_options")) {
        array_unshift($links, '<a href="' . esc_url(tolldns_settings_page_url()) . '">Settings</a>');
    }
    $autoUpdate = tolldns_auto_update_link_html();
    if ($autoUpdate !== "") {
        $links[] = $autoUpdate;
    }
    return $links;
}
add_filter("plugin_action_links_" . TOLLDNS_PLUGIN_BASENAME, "tolldns_plugin_action_links");

function tolldns_get_remote_update_metadata($forceRefresh = false) {
    if (!$forceRefresh) {
        $cached = get_site_transient(TOLLDNS_UPDATE_META_CACHE_KEY);
        if (is_array($cached) && !empty($cached["version"]) && !empty($cached["download_url"])) {
            return $cached;
        }
    }
    $response = wp_remote_get(TOLLDNS_UPDATE_META_URL, [
        "timeout" => 8,
        "redirection" => 3,
    ]);
    if (is_wp_error($response)) {
        return null;
    }
    $statusCode = (int)wp_remote_retrieve_response_code($response);
    if ($statusCode < 200 || $statusCode > 299) {
        return null;
    }
    $decoded = json_decode((string)wp_remote_retrieve_body($response), true);
    if (!is_array($decoded)) {
        return null;
    }
    $meta = [
        "name" => sanitize_text_field((string)($decoded["name"] ?? "TollDNS")),
        "slug" => sanitize_key((string)($decoded["slug"] ?? TOLLDNS_PLUGIN_SLUG)),
        "version" => sanitize_text_field((string)($decoded["version"] ?? "")),
        "requires" => sanitize_text_field((string)($decoded["requires"] ?? "")),
        "tested" => sanitize_text_field((string)($decoded["tested"] ?? "")),
        "requires_php" => sanitize_text_field((string)($decoded["requires_php"] ?? "")),
        "homepage" => esc_url_raw((string)($decoded["homepage"] ?? "https://app.cardetailingreno.com/tolldns-install/")),
        "download_url" => esc_url_raw((string)($decoded["download_url"] ?? "")),
        "description" => wp_kses_post((string)($decoded["description"] ?? "")),
        "changelog" => wp_kses_post((string)($decoded["changelog"] ?? "")),
        "last_updated" => sanitize_text_field((string)($decoded["last_updated"] ?? "")),
    ];
    if ($meta["version"] === "" || $meta["download_url"] === "") {
        return null;
    }
    set_site_transient(TOLLDNS_UPDATE_META_CACHE_KEY, $meta, HOUR_IN_SECONDS);
    return $meta;
}

function tolldns_build_update_payload($meta) {
    return (object)[
        "id" => TOLLDNS_UPDATE_META_URL,
        "slug" => TOLLDNS_PLUGIN_SLUG,
        "plugin" => TOLLDNS_PLUGIN_BASENAME,
        "new_version" => (string)($meta["version"] ?? TOLLDNS_VERSION),
        "url" => (string)($meta["homepage"] ?? "https://app.cardetailingreno.com/tolldns-install/"),
        "package" => (string)($meta["download_url"] ?? ""),
        "tested" => (string)($meta["tested"] ?? ""),
        "requires" => (string)($meta["requires"] ?? ""),
        "requires_php" => (string)($meta["requires_php"] ?? ""),
    ];
}

function tolldns_inject_update_plugins_transient($transient) {
    if (!is_object($transient)) {
        $transient = new stdClass();
    }
    if (!isset($transient->checked) || !is_array($transient->checked)) {
        return $transient;
    }
    $meta = tolldns_get_remote_update_metadata(false);
    if (!is_array($meta)) {
        return $transient;
    }
    $currentVersion = (string)($transient->checked[TOLLDNS_PLUGIN_BASENAME] ?? TOLLDNS_VERSION);
    $item = tolldns_build_update_payload($meta);
    if (version_compare((string)$meta["version"], $currentVersion, ">")) {
        if (!isset($transient->response) || !is_array($transient->response)) {
            $transient->response = [];
        }
        $transient->response[TOLLDNS_PLUGIN_BASENAME] = $item;
        if (isset($transient->no_update[TOLLDNS_PLUGIN_BASENAME])) {
            unset($transient->no_update[TOLLDNS_PLUGIN_BASENAME]);
        }
    } else {
        if (!isset($transient->no_update) || !is_array($transient->no_update)) {
            $transient->no_update = [];
        }
        $transient->no_update[TOLLDNS_PLUGIN_BASENAME] = $item;
    }
    return $transient;
}
add_filter("pre_set_site_transient_update_plugins", "tolldns_inject_update_plugins_transient");

function tolldns_plugins_api_info($result, $action, $args) {
    if ($action !== "plugin_information" || !isset($args->slug) || (string)$args->slug !== TOLLDNS_PLUGIN_SLUG) {
        return $result;
    }
    $meta = tolldns_get_remote_update_metadata(false);
    if (!is_array($meta)) {
        return $result;
    }
    return (object)[
        "name" => (string)($meta["name"] ?? "TollDNS"),
        "slug" => TOLLDNS_PLUGIN_SLUG,
        "version" => (string)$meta["version"],
        "author" => "<a href='https://app.cardetailingreno.com/'>Sitebuilder</a>",
        "homepage" => (string)($meta["homepage"] ?? "https://app.cardetailingreno.com/tolldns-install/"),
        "requires" => (string)($meta["requires"] ?? ""),
        "tested" => (string)($meta["tested"] ?? ""),
        "requires_php" => (string)($meta["requires_php"] ?? ""),
        "last_updated" => (string)($meta["last_updated"] ?? ""),
        "sections" => [
            "description" => (string)($meta["description"] ?? "TollDNS provides DNS readiness checks and points."),
            "changelog" => (string)($meta["changelog"] ?? ""),
        ],
        "download_link" => (string)($meta["download_url"] ?? ""),
    ];
}
add_filter("plugins_api", "tolldns_plugins_api_info", 10, 3);

function tolldns_admin_menu() {
    add_options_page("TollDNS", "TollDNS", "manage_options", "tolldns", "tolldns_render_settings_page");
}
add_action("admin_menu", "tolldns_admin_menu");

function tolldns_handle_settings_submit() {
    if (!isset($_POST["tolldns_settings_submit"])) {
        return;
    }
    if (!current_user_can("manage_options")) {
        return;
    }
    check_admin_referer("tolldns_settings_save", "tolldns_nonce");

    $input = [
        "monitored_domain" => isset($_POST["monitored_domain"]) ? wp_unslash($_POST["monitored_domain"]) : "",
        "expected_ns1" => isset($_POST["expected_ns1"]) ? wp_unslash($_POST["expected_ns1"]) : "",
        "expected_ns2" => isset($_POST["expected_ns2"]) ? wp_unslash($_POST["expected_ns2"]) : "",
        "ingest_shared_secret" => isset($_POST["ingest_shared_secret"]) ? wp_unslash($_POST["ingest_shared_secret"]) : "",
        "owner_reward_points_per_paid_toll" => isset($_POST["owner_reward_points_per_paid_toll"]) ? wp_unslash($_POST["owner_reward_points_per_paid_toll"]) : "",
    ];
    tolldns_save_settings($input);
    add_settings_error("tolldns_messages", "tolldns_saved", "Settings saved.", "updated");

    if (isset($_POST["tolldns_run_check_now"])) {
        $settings = tolldns_run_nameserver_check("manual");
        $msg = "Nameserver check completed. Status: " . sanitize_text_field((string)($settings["last_check_status"] ?? "unknown"));
        add_settings_error("tolldns_messages", "tolldns_checked", $msg, "updated");
    }
}
add_action("admin_init", "tolldns_handle_settings_submit");

function tolldns_render_settings_page() {
    if (!current_user_can("manage_options")) {
        return;
    }
    $settings = tolldns_get_settings();
    $ledger = tolldns_get_recent_ledger(20);
    $rewardMetrics = tolldns_points_metrics_window(DAY_IN_SECONDS);
    $lastPaidTollAt = max(0, (int)($rewardMetrics["last_paid_toll_at"] ?? 0));
    settings_errors("tolldns_messages");
    ?>
    <div class="wrap">
      <h1>TollDNS</h1>
      <p>Configure DNS checks and track TollDNS points for free-tier readiness.</p>
      <form method="post">
        <?php wp_nonce_field("tolldns_settings_save", "tolldns_nonce"); ?>
        <input type="hidden" name="tolldns_settings_submit" value="1" />
        <table class="form-table" role="presentation">
          <tr>
            <th scope="row"><label for="monitored_domain">Monitored Domain</label></th>
            <td>
              <input name="monitored_domain" id="monitored_domain" type="text" class="regular-text" value="<?php echo esc_attr((string)($settings["monitored_domain"] ?? "")); ?>" />
              <p class="description">Example: <code>example.com</code> (no protocol).</p>
            </td>
          </tr>
          <tr>
            <th scope="row"><label for="expected_ns1">Expected Nameserver 1</label></th>
            <td><input name="expected_ns1" id="expected_ns1" type="text" class="regular-text" value="<?php echo esc_attr((string)($settings["expected_ns1"] ?? "")); ?>" /></td>
          </tr>
          <tr>
            <th scope="row"><label for="expected_ns2">Expected Nameserver 2</label></th>
            <td><input name="expected_ns2" id="expected_ns2" type="text" class="regular-text" value="<?php echo esc_attr((string)($settings["expected_ns2"] ?? "")); ?>" /></td>
          </tr>
          <tr>
            <th scope="row"><label for="ingest_shared_secret">Ingest Shared Secret</label></th>
            <td>
              <input name="ingest_shared_secret" id="ingest_shared_secret" type="text" class="regular-text" value="<?php echo esc_attr((string)($settings["ingest_shared_secret"] ?? "")); ?>" />
              <p class="description">Set this secret in your TollDNS edge Worker. Each paid-toll visit can post a signed event to <code>/wp-json/tolldns/v1/ingest</code>, and the domain owner gets points.</p>
            </td>
          </tr>
          <tr>
            <th scope="row"><label for="owner_reward_points_per_paid_toll">Owner Reward Points Per Paid Toll</label></th>
            <td><input name="owner_reward_points_per_paid_toll" id="owner_reward_points_per_paid_toll" type="number" min="1" max="100000" value="<?php echo esc_attr((string)($settings["owner_reward_points_per_paid_toll"] ?? 1)); ?>" /></td>
          </tr>
          <tr>
            <th scope="row">Points Status</th>
            <td>
              <p>Total points: <strong><?php echo esc_html((string)(int)($settings["points_total"] ?? 0)); ?></strong></p>
              <p>Last check: <strong><?php echo esc_html((int)($settings["last_check_at"] ?? 0) > 0 ? gmdate("Y-m-d H:i:s", (int)$settings["last_check_at"]) . " UTC" : "Not run yet"); ?></strong></p>
              <p>Last status: <strong><?php echo esc_html((string)($settings["last_check_status"] ?? "not_checked")); ?></strong></p>
              <p>Last message: <?php echo esc_html((string)($settings["last_check_message"] ?? "")); ?></p>
              <p>Last points delta: <strong><?php echo esc_html((string)(int)($settings["last_check_delta"] ?? 0)); ?></strong></p>
              <p>Paid-toll visits (24h): <strong><?php echo esc_html((string)max(0, (int)($rewardMetrics["paid_toll_events_count"] ?? 0))); ?></strong></p>
              <p>Owner points from paid tolls (24h): <strong><?php echo esc_html((string)(int)($rewardMetrics["owner_points_from_paid_tolls"] ?? 0)); ?></strong></p>
              <p>Last paid-toll event: <strong><?php echo esc_html($lastPaidTollAt > 0 ? gmdate("Y-m-d H:i:s", $lastPaidTollAt) . " UTC" : "Not received yet"); ?></strong></p>
            </td>
          </tr>
        </table>
        <p class="submit">
          <button type="submit" class="button button-primary">Save Settings</button>
          <button type="submit" name="tolldns_run_check_now" class="button">Run Nameserver Check Now</button>
        </p>
      </form>

      <h2>Recent Points Ledger</h2>
      <table class="widefat striped">
        <thead>
          <tr>
            <th>ID</th>
            <th>Event</th>
            <th>Delta</th>
            <th>Created (UTC)</th>
          </tr>
        </thead>
        <tbody>
          <?php if (empty($ledger)): ?>
            <tr><td colspan="4">No entries yet.</td></tr>
          <?php else: ?>
            <?php foreach ($ledger as $row): ?>
              <tr>
                <td><?php echo esc_html((string)($row["id"] ?? "")); ?></td>
                <td><?php echo esc_html((string)($row["event_type"] ?? "")); ?></td>
                <td><?php echo esc_html((string)($row["points_delta"] ?? "0")); ?></td>
                <td><?php echo esc_html((string)($row["created_at"] ?? "")); ?></td>
              </tr>
            <?php endforeach; ?>
          <?php endif; ?>
        </tbody>
      </table>
    </div>
    <?php
}

function tolldns_activate() {
    tolldns_ensure_schema();
    $settings = tolldns_get_settings();
    update_option(TOLLDNS_OPTION_KEY, $settings, false);

    if (!wp_next_scheduled(TOLLDNS_CRON_HOOK)) {
        wp_schedule_event(time() + 60, "hourly", TOLLDNS_CRON_HOOK);
    }

    if (!get_option("tolldns_activation_points_awarded", false)) {
        tolldns_add_points_entry("activation_bonus", 50, ["reason" => "plugin_activation"]);
        update_option("tolldns_activation_points_awarded", 1, false);
    }

    tolldns_run_nameserver_check("activation");
}
register_activation_hook(__FILE__, "tolldns_activate");

function tolldns_deactivate() {
    $ts = wp_next_scheduled(TOLLDNS_CRON_HOOK);
    if ($ts) {
        wp_unschedule_event($ts, TOLLDNS_CRON_HOOK);
    }
}
register_deactivation_hook(__FILE__, "tolldns_deactivate");

function tolldns_cron_runner() {
    tolldns_run_nameserver_check("cron");
}
add_action(TOLLDNS_CRON_HOOK, "tolldns_cron_runner");

function tolldns_points_summary() {
    $settings = tolldns_get_settings();
    $metrics24h = tolldns_points_metrics_window(DAY_IN_SECONDS);
    return [
        "points_total" => (int)($settings["points_total"] ?? 0),
        "last_check_at" => (int)($settings["last_check_at"] ?? 0),
        "last_check_status" => (string)($settings["last_check_status"] ?? "not_checked"),
        "last_check_message" => (string)($settings["last_check_message"] ?? ""),
        "last_check_delta" => (int)($settings["last_check_delta"] ?? 0),
        "paid_toll_events_24h" => (int)($metrics24h["paid_toll_events_count"] ?? 0),
        "owner_points_from_paid_tolls_24h" => (int)($metrics24h["owner_points_from_paid_tolls"] ?? 0),
        "last_paid_toll_at" => (int)($metrics24h["last_paid_toll_at"] ?? 0),
    ];
}

function tolldns_register_rest_routes() {
    register_rest_route("tolldns/v1", "/points", [
        "methods" => "GET",
        "callback" => function () {
            return rest_ensure_response([
                "ok" => true,
                "summary" => tolldns_points_summary(),
            ]);
        },
        "permission_callback" => function () {
            return current_user_can("manage_options");
        },
    ]);

    register_rest_route("tolldns/v1", "/ingest", [
        "methods" => "POST",
        "callback" => function (WP_REST_Request $request) {
            $settings = tolldns_get_settings();
            $secret = (string)($settings["ingest_shared_secret"] ?? "");
            $rawBody = (string)$request->get_body();
            $verify = tolldns_verify_ingest_signature(
                $rawBody,
                (string)$request->get_header("x-tolldns-timestamp"),
                (string)$request->get_header("x-tolldns-signature"),
                $secret
            );
            if (is_wp_error($verify)) {
                return new WP_REST_Response([
                    "ok" => false,
                    "error" => $verify->get_error_message(),
                ], 401);
            }
            $payload = json_decode($rawBody, true);
            if (!is_array($payload)) {
                return new WP_REST_Response(["ok" => false, "error" => "Invalid JSON body."], 400);
            }
            $eventId = sanitize_text_field((string)($payload["event_id"] ?? ""));
            if ($eventId !== "" && tolldns_ingest_event_seen($eventId)) {
                return rest_ensure_response([
                    "ok" => true,
                    "duplicate" => true,
                    "event_id" => $eventId,
                    "summary" => tolldns_points_summary(),
                ]);
            }
            $eventType = sanitize_key((string)($payload["event_type"] ?? "visitor_toll_paid"));
            if ($eventType === "") {
                $eventType = "visitor_toll_paid";
            }
            $defaultReward = max(1, (int)($settings["owner_reward_points_per_paid_toll"] ?? 1));
            $ownerDelta = isset($payload["owner_points_delta"]) ? (int)$payload["owner_points_delta"] : null;
            if ($ownerDelta === null) {
                $ownerDelta = ($eventType === "visitor_toll_paid")
                    ? $defaultReward
                    : max(0, (int)($payload["points_delta"] ?? 0));
            }
            $ownerDelta = max(-1000000, min(1000000, (int)$ownerDelta));
            $meta = [
                "event_id" => $eventId,
                "domain" => tolldns_normalize_domain((string)($payload["domain"] ?? "")),
                "visitor_hash" => sanitize_text_field((string)($payload["visitor_hash"] ?? "")),
                "toll_points_paid" => max(0, (int)($payload["toll_points_paid"] ?? 0)),
                "toll_amount_usd_cents" => max(0, (int)($payload["toll_amount_usd_cents"] ?? 0)),
                "source" => sanitize_text_field((string)($payload["source"] ?? "tolldns_edge")),
            ];
            tolldns_add_points_entry($eventType, $ownerDelta, $meta);
            return rest_ensure_response([
                "ok" => true,
                "event_type" => $eventType,
                "owner_points_delta" => $ownerDelta,
                "summary" => tolldns_points_summary(),
            ]);
        },
        "permission_callback" => "__return_true",
    ]);
}
add_action("rest_api_init", "tolldns_register_rest_routes");
