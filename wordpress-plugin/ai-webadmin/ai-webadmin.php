<?php
/**
 * Plugin Name: AI WebAdmin (Cloudflare Worker)
 * Description: Connects WordPress to AI WebAdmin workers for comment moderation, security workflows, and guided Cloudflare onboarding.
 * Version: 0.2.25
 * Author: Sitebuilder
 * License: GPLv2 or later
 * Update URI: https://app.cardetailingreno.com/plugin-updates/ai-webadmin.json
 */

if (!defined("ABSPATH")) {
    exit;
}

define("AI_WEBADMIN_OPTION_KEY", "ai_webadmin_settings");
define("AI_WEBADMIN_DEFAULT_WORKER_BASE", "https://sitebuilder-agent.96psxbzqk2.workers.dev");
define("AI_WEBADMIN_TOLLDNS_PLUGIN_SLUG", "tolldns/tolldns.php");
define("AI_WEBADMIN_HTACCESS_MARKER", "AI WebAdmin Hardening");
define("AI_WEBADMIN_VERSION", "0.2.25");
define("AI_WEBADMIN_PLUGIN_BASENAME", plugin_basename(__FILE__));
define("AI_WEBADMIN_PLUGIN_SLUG", "ai-webadmin");
define("AI_WEBADMIN_UPDATE_META_URL", "https://app.cardetailingreno.com/plugin-updates/ai-webadmin.json");
define("AI_WEBADMIN_UPDATE_META_CACHE_KEY", "ai_webadmin_remote_update_meta");
define("AI_WEBADMIN_TOLLDNS_INSTALL_URL", "https://app.cardetailingreno.com/tolldns-install/");

function ai_webadmin_register_wp_consent_api_compliance() {
    $filterName = "wp_consent_api_registered_" . AI_WEBADMIN_PLUGIN_BASENAME;
    add_filter($filterName, "__return_true");
}
add_action("plugins_loaded", "ai_webadmin_register_wp_consent_api_compliance", 2);

function ai_webadmin_default_settings() {
    return [
        "worker_base_url" => AI_WEBADMIN_DEFAULT_WORKER_BASE,
        "plugin_shared_secret" => "",
        "onboarding_session_id" => "",
        "cloudflare_account_id" => "",
        "cloudflare_connected" => 0,
        "cloudflare_token_masked" => "",
        "cloudflare_last_connected_at" => 0,
        "cloudflare_last_error" => "",
        "branding_favicon_url" => "",
        "branding_inject_favicon" => 1,
        "branding_admin_menu_icon_url" => "",
        "enable_comment_moderation" => 1,
        "enable_schema_injection" => 1,
        "enable_broken_link_redirects" => 1,
        "require_tolldns" => 1,
        "sandbox_dry_run_enabled" => 1,
        "sandbox_last_run_at" => 0,
        "sandbox_last_status" => "",
        "sandbox_last_message" => "",
        "sandbox_last_risk_level" => "",
        "sandbox_last_report_id" => "",
        "sandbox_last_outdated_count" => 0,
        "worker_secret_vault_last_at" => 0,
        "worker_secret_vault_last_status" => "",
        "worker_secret_vault_last_message" => "",
        "worker_secret_cloudflare_masked" => "",
        "worker_secret_github_masked" => "",
        "worker_secret_hosting_masked" => "",
        "worker_secret_openai_masked" => "",
        "enable_media_r2_offload" => 1,
        "media_public_base_url" => "",
        "media_rewrite_attachment_urls" => 1,
        "media_offload_batch_size" => 25,
        "media_seo_autofill_enabled" => 1,
        "media_ai_enrichment_enabled" => 1,
        "media_force_metadata_refresh" => 1,
        "media_assign_to_primary_admin" => 1,
        "media_optimize_images" => 1,
        "media_max_dimension_px" => 1400,
        "media_image_quality" => 78,
        "media_target_max_bytes" => 1572864,
        "media_offload_cursor_attachment_id" => 0,
        "media_offload_last_run_at" => 0,
        "media_offload_last_status" => "",
        "media_offload_last_message" => "",
        "media_offload_last_manifest_r2_key" => "",
        "media_offload_last_github_status" => "",
        "media_offload_last_github_path" => "",
        "media_offload_last_mapped_count" => 0,
        "media_offload_total_processed" => 0,
        "media_offload_total_failed" => 0,
        "media_offload_last_max_attachment_id" => 0,
        "github_signup_url" => "https://github.com/signup",
        "enable_builtin_page_cache" => 1,
        "page_cache_ttl_seconds" => 600,
        "page_cache_excluded_paths" => "/wp-login.php\n/wp-admin/\n/cart/\n/checkout/\n/my-account/",
        "page_cache_last_cleared_at" => 0,
        "page_cache_last_clear_reason" => "",
        "autoload_cleanup_enabled" => 1,
        "autoload_last_cleanup_at" => 0,
        "autoload_last_cleanup_summary" => "",
        "seo_primary_keywords" => "",
        "seo_secondary_keywords" => "",
        "seo_target_locations" => "",
        "seo_offer_summary" => "",
        "seo_brand_voice" => "",
        "seo_last_updated_at" => 0,
        "premium_upgrade_url" => "https://app.cardetailingreno.com/upgrade/",
        "premium_feature_ai_competitor_monitoring" => 0,
        "premium_feature_daily_page_speed_paths" => 0,
        "premium_feature_auto_seo_briefs" => 0,
        "vps_upgrade_url" => "https://app.cardetailingreno.com/upgrade/vps",
        "cache_accelerator_upgrade_url" => "https://app.cardetailingreno.com/upgrade/cache",
        "allow_tolldns_points_payment" => 1,
        "tolldns_points_per_usd_cents" => 100,
        "tolldns_vps_upgrade_points_cost" => 800,
        "tolldns_cache_upgrade_points_cost" => 500,
        "enable_security_hardening" => 1,
        "disable_xmlrpc" => 1,
        "prevent_email_display_name" => 1,
        "enforce_single_admin" => 1,
        "normalize_editor_generic_emails_to_admin" => 1,
        "block_file_manager_plugins" => 1,
        "enable_login_rate_limit" => 1,
        "login_rate_limit_attempts" => 5,
        "login_rate_limit_window_minutes" => 15,
        "login_rate_limit_lockout_minutes" => 15,
        "enforce_admin_sso" => 0,
        "require_admin_unlock_factor" => 1,
        "admin_sso_header_name" => "CF-Access-Authenticated-User-Email",
        "apply_htaccess_hardening" => 1,
        "enable_plugin_rationalization" => 1,
        "license_hygiene_enabled" => 1,
        "license_expected_email" => "",
        "license_hygiene_last_run_at" => 0,
        "license_hygiene_last_status" => "",
        "license_hygiene_last_message" => "",
        "license_hygiene_last_ai_summary" => "",
        "license_hygiene_last_deleted_json" => "[]",
        "remove_migration_replication_plugins" => 1,
        "auto_remove_failed_static_export_plugins" => 1,
        "static_export_last_status" => "",
        "static_export_last_error_message" => "",
        "static_export_last_error_source" => "",
        "static_export_last_error_at" => 0,
        "static_export_last_removed_json" => "[]",
        "static_export_last_fingerprint" => "",
        "auto_uninstall_inactive_plugins" => 1,
        "inactive_plugin_delete_limit" => 8,
        "inactive_plugin_protected_slugs" => "ai-webadmin/ai-webadmin.php\ntolldns/tolldns.php",
        "auto_uninstall_inactive_themes" => 1,
        "inactive_theme_delete_limit" => 3,
        "inactive_theme_protected_slugs" => "twentytwentyfive",
        "enable_inactive_user_cleanup" => 1,
        "inactive_user_days" => 365,
        "inactive_user_delete_limit" => 50,
        "github_backup_enabled" => 1,
        "github_backup_repo" => "",
        "github_backup_branch" => "main",
        "github_backup_manifest_max_files" => 5000,
        "github_vault_connected" => 0,
        "github_vault_token_masked" => "",
        "github_vault_last_connected_at" => 0,
        "github_backup_last_snapshot_at" => 0,
        "github_backup_last_status" => "",
        "github_backup_last_message" => "",
        "optimization_plan_last_generated_at" => 0,
        "optimization_plan_last_summary" => "",
        "optimization_plan_remove_now_json" => "[]",
        "optimization_plan_remove_after_r2_json" => "[]",
        "optimization_plan_clone_status" => "",
        "optimization_plan_clone_summary" => "",
        "agent_chat_last_question" => "",
        "agent_chat_last_answer" => "",
        "agent_chat_last_proofs_json" => "[]",
        "agent_chat_history_json" => "[]",
        "agent_chat_last_asked_at" => 0,
        "enable_passcode_unlock" => 0,
        "unlock_passcode_hash" => "",
        "require_hardware_key_unlock" => 0,
        "require_wallet_signature_unlock" => 0,
        "wallet_unlock_message_prefix" => "AI WebAdmin Login Challenge",
        "wallet_unlock_chain_id" => 1,
        "wallet_unlock_nonce_ttl_minutes" => 10,
        "enable_email_forwarding_via_worker" => 1,
        "remove_smtp_plugins" => 1,
        "lead_forward_email" => "",
        "suppress_local_lead_mail" => 1,
        "lead_forward_verification_status" => "not_started",
        "lead_forward_verification_email" => "",
        "lead_forward_verification_sent_at" => 0,
        "lead_forward_verification_confirmed_at" => 0,
        "lead_forward_verification_last_error" => "",
        "lead_forward_verification_last_check_at" => 0,
        "lead_forward_verification_last_link_url" => "",
    ];
}

function ai_webadmin_get_settings() {
    $defaults = ai_webadmin_default_settings();
    $stored = get_option(AI_WEBADMIN_OPTION_KEY, []);
    if (!is_array($stored)) {
        $stored = [];
    }
    return array_merge($defaults, $stored);
}

function ai_webadmin_save_settings($input) {
    $current = ai_webadmin_get_settings();
    $next = [
        "worker_base_url" => isset($input["worker_base_url"]) ? esc_url_raw(trim((string)$input["worker_base_url"])) : $current["worker_base_url"],
        "plugin_shared_secret" => isset($input["plugin_shared_secret"]) ? trim((string)$input["plugin_shared_secret"]) : $current["plugin_shared_secret"],
        "onboarding_session_id" => isset($input["onboarding_session_id"]) ? sanitize_text_field(trim((string)$input["onboarding_session_id"])) : $current["onboarding_session_id"],
        "cloudflare_account_id" => isset($input["cloudflare_account_id"]) ? sanitize_text_field(trim((string)$input["cloudflare_account_id"])) : (string)($current["cloudflare_account_id"] ?? ""),
        "cloudflare_connected" => !empty($current["cloudflare_connected"]) ? 1 : 0,
        "cloudflare_token_masked" => sanitize_text_field((string)($current["cloudflare_token_masked"] ?? "")),
        "cloudflare_last_connected_at" => (int)($current["cloudflare_last_connected_at"] ?? 0),
        "cloudflare_last_error" => sanitize_text_field((string)($current["cloudflare_last_error"] ?? "")),
        "branding_favicon_url" => isset($input["branding_favicon_url"])
            ? esc_url_raw(trim((string)$input["branding_favicon_url"]))
            : (string)($current["branding_favicon_url"] ?? ""),
        "branding_inject_favicon" => !empty($input["branding_inject_favicon"]) ? 1 : 0,
        "branding_admin_menu_icon_url" => isset($input["branding_admin_menu_icon_url"])
            ? esc_url_raw(trim((string)$input["branding_admin_menu_icon_url"]))
            : (string)($current["branding_admin_menu_icon_url"] ?? ""),
        "enable_comment_moderation" => !empty($input["enable_comment_moderation"]) ? 1 : 0,
        "enable_schema_injection" => !empty($input["enable_schema_injection"]) ? 1 : 0,
        "enable_broken_link_redirects" => !empty($input["enable_broken_link_redirects"]) ? 1 : 0,
        "require_tolldns" => !empty($input["require_tolldns"]) ? 1 : 0,
        "sandbox_dry_run_enabled" => !empty($input["sandbox_dry_run_enabled"]) ? 1 : 0,
        "sandbox_last_run_at" => (int)($current["sandbox_last_run_at"] ?? 0),
        "sandbox_last_status" => sanitize_text_field((string)($current["sandbox_last_status"] ?? "")),
        "sandbox_last_message" => sanitize_text_field((string)($current["sandbox_last_message"] ?? "")),
        "sandbox_last_risk_level" => sanitize_text_field((string)($current["sandbox_last_risk_level"] ?? "")),
        "sandbox_last_report_id" => sanitize_text_field((string)($current["sandbox_last_report_id"] ?? "")),
        "sandbox_last_outdated_count" => max(0, (int)($current["sandbox_last_outdated_count"] ?? 0)),
        "worker_secret_vault_last_at" => (int)($current["worker_secret_vault_last_at"] ?? 0),
        "worker_secret_vault_last_status" => sanitize_text_field((string)($current["worker_secret_vault_last_status"] ?? "")),
        "worker_secret_vault_last_message" => sanitize_text_field((string)($current["worker_secret_vault_last_message"] ?? "")),
        "worker_secret_cloudflare_masked" => sanitize_text_field((string)($current["worker_secret_cloudflare_masked"] ?? "")),
        "worker_secret_github_masked" => sanitize_text_field((string)($current["worker_secret_github_masked"] ?? "")),
        "worker_secret_hosting_masked" => sanitize_text_field((string)($current["worker_secret_hosting_masked"] ?? "")),
        "worker_secret_openai_masked" => sanitize_text_field((string)($current["worker_secret_openai_masked"] ?? "")),
        "enable_media_r2_offload" => !empty($input["enable_media_r2_offload"]) ? 1 : 0,
        "media_public_base_url" => isset($input["media_public_base_url"])
            ? ai_webadmin_normalize_media_public_base_url((string)$input["media_public_base_url"])
            : (string)($current["media_public_base_url"] ?? ""),
        "media_rewrite_attachment_urls" => !empty($input["media_rewrite_attachment_urls"]) ? 1 : 0,
        "media_offload_batch_size" => max(5, min(100, (int)($input["media_offload_batch_size"] ?? $current["media_offload_batch_size"]))),
        "media_seo_autofill_enabled" => !empty($input["media_seo_autofill_enabled"]) ? 1 : 0,
        "media_ai_enrichment_enabled" => !empty($input["media_ai_enrichment_enabled"]) ? 1 : 0,
        "media_force_metadata_refresh" => !empty($input["media_force_metadata_refresh"]) ? 1 : 0,
        "media_assign_to_primary_admin" => !empty($input["media_assign_to_primary_admin"]) ? 1 : 0,
        "media_optimize_images" => !empty($input["media_optimize_images"]) ? 1 : 0,
        "media_max_dimension_px" => max(640, min(4096, (int)($input["media_max_dimension_px"] ?? $current["media_max_dimension_px"]))),
        "media_image_quality" => max(40, min(95, (int)($input["media_image_quality"] ?? $current["media_image_quality"]))),
        "media_target_max_bytes" => max(262144, min(20971520, (int)($input["media_target_max_bytes"] ?? $current["media_target_max_bytes"]))),
        "media_offload_cursor_attachment_id" => max(0, (int)($current["media_offload_cursor_attachment_id"] ?? 0)),
        "media_offload_last_run_at" => (int)($current["media_offload_last_run_at"] ?? 0),
        "media_offload_last_status" => sanitize_text_field((string)($current["media_offload_last_status"] ?? "")),
        "media_offload_last_message" => sanitize_text_field((string)($current["media_offload_last_message"] ?? "")),
        "media_offload_last_manifest_r2_key" => sanitize_text_field((string)($current["media_offload_last_manifest_r2_key"] ?? "")),
        "media_offload_last_github_status" => sanitize_text_field((string)($current["media_offload_last_github_status"] ?? "")),
        "media_offload_last_github_path" => sanitize_text_field((string)($current["media_offload_last_github_path"] ?? "")),
        "media_offload_last_mapped_count" => max(0, (int)($current["media_offload_last_mapped_count"] ?? 0)),
        "media_offload_total_processed" => max(0, (int)($current["media_offload_total_processed"] ?? 0)),
        "media_offload_total_failed" => max(0, (int)($current["media_offload_total_failed"] ?? 0)),
        "media_offload_last_max_attachment_id" => max(0, (int)($current["media_offload_last_max_attachment_id"] ?? 0)),
        "github_signup_url" => isset($input["github_signup_url"]) ? esc_url_raw(trim((string)$input["github_signup_url"])) : $current["github_signup_url"],
        "enable_builtin_page_cache" => !empty($input["enable_builtin_page_cache"]) ? 1 : 0,
        "page_cache_ttl_seconds" => max(60, min(86400, (int)($input["page_cache_ttl_seconds"] ?? $current["page_cache_ttl_seconds"]))),
        "page_cache_excluded_paths" => isset($input["page_cache_excluded_paths"])
            ? sanitize_textarea_field((string)$input["page_cache_excluded_paths"])
            : (string)($current["page_cache_excluded_paths"] ?? ""),
        "page_cache_last_cleared_at" => (int)($current["page_cache_last_cleared_at"] ?? 0),
        "page_cache_last_clear_reason" => sanitize_text_field((string)($current["page_cache_last_clear_reason"] ?? "")),
        "autoload_cleanup_enabled" => !empty($input["autoload_cleanup_enabled"]) ? 1 : 0,
        "autoload_last_cleanup_at" => (int)($current["autoload_last_cleanup_at"] ?? 0),
        "autoload_last_cleanup_summary" => sanitize_text_field((string)($current["autoload_last_cleanup_summary"] ?? "")),
        "seo_primary_keywords" => isset($input["seo_primary_keywords"])
            ? sanitize_textarea_field((string)$input["seo_primary_keywords"])
            : (string)($current["seo_primary_keywords"] ?? ""),
        "seo_secondary_keywords" => isset($input["seo_secondary_keywords"])
            ? sanitize_textarea_field((string)$input["seo_secondary_keywords"])
            : (string)($current["seo_secondary_keywords"] ?? ""),
        "seo_target_locations" => isset($input["seo_target_locations"])
            ? sanitize_textarea_field((string)$input["seo_target_locations"])
            : (string)($current["seo_target_locations"] ?? ""),
        "seo_offer_summary" => isset($input["seo_offer_summary"])
            ? sanitize_textarea_field((string)$input["seo_offer_summary"])
            : (string)($current["seo_offer_summary"] ?? ""),
        "seo_brand_voice" => isset($input["seo_brand_voice"])
            ? sanitize_text_field((string)$input["seo_brand_voice"])
            : (string)($current["seo_brand_voice"] ?? ""),
        "seo_last_updated_at" => (int)($current["seo_last_updated_at"] ?? 0),
        "premium_upgrade_url" => isset($input["premium_upgrade_url"])
            ? esc_url_raw(trim((string)$input["premium_upgrade_url"]))
            : (string)($current["premium_upgrade_url"] ?? "https://app.cardetailingreno.com/upgrade/"),
        "premium_feature_ai_competitor_monitoring" => !empty($input["premium_feature_ai_competitor_monitoring"]) ? 1 : 0,
        "premium_feature_daily_page_speed_paths" => !empty($input["premium_feature_daily_page_speed_paths"]) ? 1 : 0,
        "premium_feature_auto_seo_briefs" => !empty($input["premium_feature_auto_seo_briefs"]) ? 1 : 0,
        "vps_upgrade_url" => isset($input["vps_upgrade_url"])
            ? esc_url_raw(trim((string)$input["vps_upgrade_url"]))
            : (string)($current["vps_upgrade_url"] ?? "https://app.cardetailingreno.com/upgrade/vps"),
        "cache_accelerator_upgrade_url" => isset($input["cache_accelerator_upgrade_url"])
            ? esc_url_raw(trim((string)$input["cache_accelerator_upgrade_url"]))
            : (string)($current["cache_accelerator_upgrade_url"] ?? "https://app.cardetailingreno.com/upgrade/cache"),
        "allow_tolldns_points_payment" => !empty($input["allow_tolldns_points_payment"]) ? 1 : 0,
        "tolldns_points_per_usd_cents" => max(1, min(100000, (int)($input["tolldns_points_per_usd_cents"] ?? $current["tolldns_points_per_usd_cents"]))),
        "tolldns_vps_upgrade_points_cost" => max(1, min(1000000, (int)($input["tolldns_vps_upgrade_points_cost"] ?? $current["tolldns_vps_upgrade_points_cost"]))),
        "tolldns_cache_upgrade_points_cost" => max(1, min(1000000, (int)($input["tolldns_cache_upgrade_points_cost"] ?? $current["tolldns_cache_upgrade_points_cost"]))),
        "enable_security_hardening" => !empty($input["enable_security_hardening"]) ? 1 : 0,
        "disable_xmlrpc" => !empty($input["disable_xmlrpc"]) ? 1 : 0,
        "prevent_email_display_name" => !empty($input["prevent_email_display_name"]) ? 1 : 0,
        "enforce_single_admin" => !empty($input["enforce_single_admin"]) ? 1 : 0,
        "normalize_editor_generic_emails_to_admin" => !empty($input["normalize_editor_generic_emails_to_admin"]) ? 1 : 0,
        "block_file_manager_plugins" => !empty($input["block_file_manager_plugins"]) ? 1 : 0,
        "enable_login_rate_limit" => !empty($input["enable_login_rate_limit"]) ? 1 : 0,
        "login_rate_limit_attempts" => max(3, min(20, (int)($input["login_rate_limit_attempts"] ?? $current["login_rate_limit_attempts"]))),
        "login_rate_limit_window_minutes" => max(1, min(60, (int)($input["login_rate_limit_window_minutes"] ?? $current["login_rate_limit_window_minutes"]))),
        "login_rate_limit_lockout_minutes" => max(1, min(240, (int)($input["login_rate_limit_lockout_minutes"] ?? $current["login_rate_limit_lockout_minutes"]))),
        "enforce_admin_sso" => !empty($input["enforce_admin_sso"]) ? 1 : 0,
        "require_admin_unlock_factor" => !empty($input["require_admin_unlock_factor"]) ? 1 : 0,
        "admin_sso_header_name" => isset($input["admin_sso_header_name"]) ? sanitize_text_field(trim((string)$input["admin_sso_header_name"])) : $current["admin_sso_header_name"],
        "apply_htaccess_hardening" => !empty($input["apply_htaccess_hardening"]) ? 1 : 0,
        "enable_plugin_rationalization" => !empty($input["enable_plugin_rationalization"]) ? 1 : 0,
        "license_hygiene_enabled" => !empty($input["license_hygiene_enabled"]) ? 1 : 0,
        "license_expected_email" => isset($input["license_expected_email"])
            ? sanitize_email(trim((string)$input["license_expected_email"]))
            : (string)($current["license_expected_email"] ?? ""),
        "license_hygiene_last_run_at" => (int)($current["license_hygiene_last_run_at"] ?? 0),
        "license_hygiene_last_status" => sanitize_text_field((string)($current["license_hygiene_last_status"] ?? "")),
        "license_hygiene_last_message" => sanitize_text_field((string)($current["license_hygiene_last_message"] ?? "")),
        "license_hygiene_last_ai_summary" => sanitize_textarea_field((string)($current["license_hygiene_last_ai_summary"] ?? "")),
        "license_hygiene_last_deleted_json" => (string)($current["license_hygiene_last_deleted_json"] ?? "[]"),
        "remove_migration_replication_plugins" => !empty($input["remove_migration_replication_plugins"]) ? 1 : 0,
        "auto_remove_failed_static_export_plugins" => !empty($input["auto_remove_failed_static_export_plugins"]) ? 1 : 0,
        "static_export_last_status" => sanitize_text_field((string)($current["static_export_last_status"] ?? "")),
        "static_export_last_error_message" => sanitize_text_field((string)($current["static_export_last_error_message"] ?? "")),
        "static_export_last_error_source" => sanitize_text_field((string)($current["static_export_last_error_source"] ?? "")),
        "static_export_last_error_at" => (int)($current["static_export_last_error_at"] ?? 0),
        "static_export_last_removed_json" => (string)($current["static_export_last_removed_json"] ?? "[]"),
        "static_export_last_fingerprint" => sanitize_text_field((string)($current["static_export_last_fingerprint"] ?? "")),
        "auto_uninstall_inactive_plugins" => !empty($input["auto_uninstall_inactive_plugins"]) ? 1 : 0,
        "inactive_plugin_delete_limit" => max(1, min(100, (int)($input["inactive_plugin_delete_limit"] ?? $current["inactive_plugin_delete_limit"]))),
        "inactive_plugin_protected_slugs" => isset($input["inactive_plugin_protected_slugs"])
            ? sanitize_textarea_field((string)$input["inactive_plugin_protected_slugs"])
            : (string)($current["inactive_plugin_protected_slugs"] ?? ""),
        "auto_uninstall_inactive_themes" => !empty($input["auto_uninstall_inactive_themes"]) ? 1 : 0,
        "inactive_theme_delete_limit" => max(1, min(20, (int)($input["inactive_theme_delete_limit"] ?? $current["inactive_theme_delete_limit"]))),
        "inactive_theme_protected_slugs" => isset($input["inactive_theme_protected_slugs"])
            ? sanitize_textarea_field((string)$input["inactive_theme_protected_slugs"])
            : (string)($current["inactive_theme_protected_slugs"] ?? ""),
        "enable_inactive_user_cleanup" => !empty($input["enable_inactive_user_cleanup"]) ? 1 : 0,
        "inactive_user_days" => max(30, min(3650, (int)($input["inactive_user_days"] ?? $current["inactive_user_days"]))),
        "inactive_user_delete_limit" => max(1, min(500, (int)($input["inactive_user_delete_limit"] ?? $current["inactive_user_delete_limit"]))),
        "github_backup_enabled" => !empty($input["github_backup_enabled"]) ? 1 : 0,
        "github_backup_repo" => isset($input["github_backup_repo"]) ? sanitize_text_field(trim((string)$input["github_backup_repo"])) : $current["github_backup_repo"],
        "github_backup_branch" => isset($input["github_backup_branch"]) ? sanitize_text_field(trim((string)$input["github_backup_branch"])) : $current["github_backup_branch"],
        "github_backup_manifest_max_files" => max(500, min(12000, (int)($input["github_backup_manifest_max_files"] ?? $current["github_backup_manifest_max_files"]))),
        "github_vault_connected" => !empty($current["github_vault_connected"]) ? 1 : 0,
        "github_vault_token_masked" => (string)($current["github_vault_token_masked"] ?? ""),
        "github_vault_last_connected_at" => (int)($current["github_vault_last_connected_at"] ?? 0),
        "github_backup_last_snapshot_at" => (int)($current["github_backup_last_snapshot_at"] ?? 0),
        "github_backup_last_status" => sanitize_text_field((string)($current["github_backup_last_status"] ?? "")),
        "github_backup_last_message" => sanitize_text_field((string)($current["github_backup_last_message"] ?? "")),
        "optimization_plan_last_generated_at" => (int)($current["optimization_plan_last_generated_at"] ?? 0),
        "optimization_plan_last_summary" => sanitize_text_field((string)($current["optimization_plan_last_summary"] ?? "")),
        "optimization_plan_remove_now_json" => (string)($current["optimization_plan_remove_now_json"] ?? "[]"),
        "optimization_plan_remove_after_r2_json" => (string)($current["optimization_plan_remove_after_r2_json"] ?? "[]"),
        "optimization_plan_clone_status" => sanitize_text_field((string)($current["optimization_plan_clone_status"] ?? "")),
        "optimization_plan_clone_summary" => sanitize_text_field((string)($current["optimization_plan_clone_summary"] ?? "")),
        "agent_chat_last_question" => sanitize_text_field((string)($current["agent_chat_last_question"] ?? "")),
        "agent_chat_last_answer" => sanitize_textarea_field((string)($current["agent_chat_last_answer"] ?? "")),
        "agent_chat_last_proofs_json" => (string)($current["agent_chat_last_proofs_json"] ?? "[]"),
        "agent_chat_history_json" => (string)($current["agent_chat_history_json"] ?? "[]"),
        "agent_chat_last_asked_at" => (int)($current["agent_chat_last_asked_at"] ?? 0),
        "enable_passcode_unlock" => !empty($input["enable_passcode_unlock"]) ? 1 : 0,
        "unlock_passcode_hash" => (string)($current["unlock_passcode_hash"] ?? ""),
        "require_hardware_key_unlock" => !empty($input["require_hardware_key_unlock"]) ? 1 : 0,
        "require_wallet_signature_unlock" => !empty($input["require_wallet_signature_unlock"]) ? 1 : 0,
        "wallet_unlock_message_prefix" => isset($input["wallet_unlock_message_prefix"])
            ? sanitize_text_field(trim((string)$input["wallet_unlock_message_prefix"]))
            : (string)($current["wallet_unlock_message_prefix"] ?? "AI WebAdmin Login Challenge"),
        "wallet_unlock_chain_id" => max(1, min(999999, (int)($input["wallet_unlock_chain_id"] ?? $current["wallet_unlock_chain_id"]))),
        "wallet_unlock_nonce_ttl_minutes" => max(3, min(30, (int)($input["wallet_unlock_nonce_ttl_minutes"] ?? $current["wallet_unlock_nonce_ttl_minutes"]))),
        "enable_email_forwarding_via_worker" => !empty($input["enable_email_forwarding_via_worker"]) ? 1 : 0,
        "remove_smtp_plugins" => !empty($input["remove_smtp_plugins"]) ? 1 : 0,
        "lead_forward_email" => isset($input["lead_forward_email"]) ? sanitize_email(trim((string)$input["lead_forward_email"])) : (string)($current["lead_forward_email"] ?? ""),
        "suppress_local_lead_mail" => !empty($input["suppress_local_lead_mail"]) ? 1 : 0,
        "lead_forward_verification_status" => sanitize_text_field((string)($current["lead_forward_verification_status"] ?? "not_started")),
        "lead_forward_verification_email" => sanitize_email((string)($current["lead_forward_verification_email"] ?? "")),
        "lead_forward_verification_sent_at" => (int)($current["lead_forward_verification_sent_at"] ?? 0),
        "lead_forward_verification_confirmed_at" => (int)($current["lead_forward_verification_confirmed_at"] ?? 0),
        "lead_forward_verification_last_error" => sanitize_text_field((string)($current["lead_forward_verification_last_error"] ?? "")),
        "lead_forward_verification_last_check_at" => (int)($current["lead_forward_verification_last_check_at"] ?? 0),
        "lead_forward_verification_last_link_url" => esc_url_raw((string)($current["lead_forward_verification_last_link_url"] ?? "")),
    ];

    $newPasscode = isset($input["unlock_passcode"]) ? trim((string)$input["unlock_passcode"]) : "";
    $clearPasscode = !empty($input["clear_unlock_passcode"]);
    if ($clearPasscode) {
        $next["unlock_passcode_hash"] = "";
    } elseif ($newPasscode !== "") {
        $next["unlock_passcode_hash"] = wp_hash_password($newPasscode);
    }

    update_option(AI_WEBADMIN_OPTION_KEY, $next, false);
    return $next;
}

function ai_webadmin_hardening_enabled() {
    $settings = ai_webadmin_get_settings();
    return !empty($settings["enable_security_hardening"]);
}

function ai_webadmin_blocked_plugin_slugs() {
    return [
        "wp-file-manager/file_folder_manager.php",
        "file-manager/file-manager.php",
        "wp-file-manager-pro/file_folder_manager.php",
    ];
}

function ai_webadmin_migration_replication_plugin_slugs() {
    return [
        "all-in-one-wp-migration/all-in-one-wp-migration.php",
        "all-in-one-wp-migration-unlimited-extension/all-in-one-wp-migration-unlimited-extension.php",
        "wp-migrate-db/wp-migrate-db.php",
        "wp-migrate-db-pro/wp-migrate-db-pro.php",
        "wpvivid-backuprestore/wpvivid-backuprestore.php",
        "duplicator/duplicator.php",
        "updraftplus/updraftplus.php",
        "backupbuddy/backupbuddy.php",
    ];
}

function ai_webadmin_static_export_plugin_slugs() {
    return [
        "simply-static/simply-static.php",
        "simply-static-pro/simply-static-pro.php",
        "wp2static/wp2static.php",
        "static-html-output-plugin/static-html-output-plugin.php",
    ];
}

function ai_webadmin_smtp_email_plugin_slugs() {
    return [
        "wp-mail-smtp/wp_mail_smtp.php",
        "easy-wp-smtp/easy-wp-smtp.php",
        "post-smtp/postman-smtp.php",
        "fluent-smtp/fluent-smtp.php",
        "smtp-mailer/main.php",
        "gmail-smtp/main.php",
        "mail-bank/wp-mail-bank.php",
    ];
}

function ai_webadmin_parse_repo_slug($raw) {
    $slug = trim((string)$raw);
    $slug = preg_replace("#^https?://github\.com/#i", "", $slug);
    $slug = trim((string)$slug, "/");
    if (!preg_match('#^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$#', $slug)) {
        return null;
    }
    return strtolower($slug);
}

function ai_webadmin_client_ip() {
    $keys = ["HTTP_CF_CONNECTING_IP", "HTTP_X_FORWARDED_FOR", "REMOTE_ADDR"];
    foreach ($keys as $key) {
        if (empty($_SERVER[$key])) {
            continue;
        }
        $raw = trim((string)$_SERVER[$key]);
        if ($raw === "") {
            continue;
        }
        $candidate = $raw;
        if ($key === "HTTP_X_FORWARDED_FOR" && strpos($raw, ",") !== false) {
            $parts = explode(",", $raw);
            $candidate = trim((string)$parts[0]);
        }
        if (filter_var($candidate, FILTER_VALIDATE_IP)) {
            return $candidate;
        }
    }
    return "0.0.0.0";
}

function ai_webadmin_login_throttle_key($ip) {
    return "ai_webadmin_login_" . md5((string)$ip);
}

function ai_webadmin_lockout_key($ip) {
    return "ai_webadmin_lockout_" . md5((string)$ip);
}

function ai_webadmin_access_header_value($settings) {
    $headerName = trim((string)($settings["admin_sso_header_name"] ?? "CF-Access-Authenticated-User-Email"));
    if ($headerName === "") {
        $headerName = "CF-Access-Authenticated-User-Email";
    }
    $serverKey = "HTTP_" . strtoupper(str_replace("-", "_", $headerName));
    if (!empty($_SERVER[$serverKey])) {
        return trim((string)$_SERVER[$serverKey]);
    }
    return "";
}

function ai_webadmin_unlock_enabled($settings = null) {
    if (!is_array($settings)) {
        $settings = ai_webadmin_get_settings();
    }
    return (
        !empty($settings["enable_passcode_unlock"]) ||
        !empty($settings["require_hardware_key_unlock"]) ||
        !empty($settings["require_wallet_signature_unlock"])
    );
}

function ai_webadmin_wallet_nonce_key($nonce) {
    return "ai_webadmin_wallet_nonce_" . md5((string)$nonce);
}

function ai_webadmin_issue_wallet_login_challenge($settings) {
    $nonce = wp_generate_password(24, false, false);
    $issuedAt = gmdate("c");
    $chainId = max(1, (int)($settings["wallet_unlock_chain_id"] ?? 1));
    $prefix = trim((string)($settings["wallet_unlock_message_prefix"] ?? "AI WebAdmin Login Challenge"));
    if ($prefix === "") {
        $prefix = "AI WebAdmin Login Challenge";
    }
    $siteHost = wp_parse_url(home_url("/"), PHP_URL_HOST);
    if (!is_string($siteHost) || $siteHost === "") {
        $siteHost = "unknown-site";
    }
    $message = $prefix .
        "\nSite: " . $siteHost .
        "\nChain ID: " . $chainId .
        "\nNonce: " . $nonce .
        "\nIssued At: " . $issuedAt;
    $ttlSeconds = max(180, min(1800, ((int)($settings["wallet_unlock_nonce_ttl_minutes"] ?? 10)) * 60));
    set_transient(ai_webadmin_wallet_nonce_key($nonce), [
        "nonce" => $nonce,
        "message" => $message,
        "issued_at" => $issuedAt,
        "ip" => ai_webadmin_client_ip(),
    ], $ttlSeconds);

    return [
        "nonce" => $nonce,
        "issued_at" => $issuedAt,
        "message" => $message,
        "chain_id" => $chainId,
    ];
}

function ai_webadmin_wallet_verify_with_worker($settings, $user, $address, $signature, $message, $nonce) {
    if (!ai_webadmin_features_enabled()) {
        return new WP_Error("ai_webadmin_wallet_worker_unavailable", "Wallet unlock requires Worker API configuration.");
    }
    $sessionId = trim((string)($settings["onboarding_session_id"] ?? ""));
    if ($sessionId === "") {
        return new WP_Error("ai_webadmin_wallet_missing_session", "Wallet unlock requires Onboarding Session ID in plugin settings.");
    }
    $nonce = trim((string)$nonce);
    $nonceRecord = get_transient(ai_webadmin_wallet_nonce_key($nonce));
    if (!is_array($nonceRecord) || empty($nonceRecord["nonce"])) {
        return new WP_Error("ai_webadmin_wallet_nonce_invalid", "Wallet challenge expired. Reload login page and try again.");
    }
    delete_transient(ai_webadmin_wallet_nonce_key($nonce));

    $response = ai_webadmin_signed_post($settings, "plugin/wp/auth/wallet/verify", [
        "session_id" => $sessionId,
        "site_url" => home_url("/"),
        "user_id" => (int)$user->ID,
        "user_login" => (string)$user->user_login,
        "user_email" => (string)$user->user_email,
        "wallet_address" => (string)$address,
        "wallet_signature" => (string)$signature,
        "wallet_message" => (string)$message,
        "wallet_nonce" => $nonce,
        "wallet_chain_id" => (int)($settings["wallet_unlock_chain_id"] ?? 1),
        "wallet_challenge_issued_at" => (string)($nonceRecord["issued_at"] ?? ""),
    ], 20);

    if (is_wp_error($response)) {
        return new WP_Error("ai_webadmin_wallet_verify_failed", "Wallet verification request failed.");
    }
    $code = (int)wp_remote_retrieve_response_code($response);
    $body = wp_remote_retrieve_body($response);
    $decoded = json_decode($body, true);
    if ($code < 200 || $code >= 300 || !is_array($decoded) || empty($decoded["ok"]) || empty($decoded["verified"])) {
        $messageText = "Wallet signature verification failed.";
        if (is_array($decoded) && !empty($decoded["error"])) {
            $messageText = sanitize_text_field((string)$decoded["error"]);
        }
        return new WP_Error("ai_webadmin_wallet_verify_denied", $messageText);
    }
    update_user_meta((int)$user->ID, "ai_webadmin_last_wallet_unlock", time());
    update_user_meta((int)$user->ID, "ai_webadmin_wallet_address", sanitize_text_field((string)($decoded["wallet_address"] ?? $address)));
    return true;
}

function ai_webadmin_detect_hardware_key_provider() {
    $activePlugins = (array)get_option("active_plugins", []);
    $candidates = [
        "wp-webauthn/wp-webauthn.php",
        "passwordless-login/passwordless-login.php",
        "miniorange-2-factor-authentication/miniorange_2_factor_settings.php",
        "two-factor/two-factor.php",
    ];
    foreach ($candidates as $slug) {
        if (in_array($slug, $activePlugins, true)) {
            return $slug;
        }
    }
    return null;
}

function ai_webadmin_is_tolldns_active() {
    $activePlugins = (array)get_option("active_plugins", []);
    if (in_array(AI_WEBADMIN_TOLLDNS_PLUGIN_SLUG, $activePlugins, true)) {
        return true;
    }
    if (is_multisite()) {
        $networkPlugins = (array)get_site_option("active_sitewide_plugins", []);
        return isset($networkPlugins[AI_WEBADMIN_TOLLDNS_PLUGIN_SLUG]);
    }
    return false;
}

function ai_webadmin_missing_activation_requirements($settings = null) {
    if (!is_array($settings)) {
        $settings = ai_webadmin_get_settings();
    }
    $missing = [];
    if (empty($settings["worker_base_url"])) {
        $missing[] = "Worker Base URL";
    }
    if (empty($settings["plugin_shared_secret"])) {
        $missing[] = "Plugin Shared Secret";
    }
    if (empty($settings["onboarding_session_id"])) {
        $missing[] = "Onboarding Session ID";
    }
    if (!empty($settings["require_tolldns"]) && !ai_webadmin_is_tolldns_active()) {
        $missing[] = "TollDNS (installed + active)";
    }
    if (empty($settings["cloudflare_connected"]) || empty($settings["cloudflare_token_masked"])) {
        $missing[] = "Cloudflare token verified in plugin";
    }
    if (empty($settings["github_vault_connected"]) || empty($settings["github_vault_token_masked"])) {
        $missing[] = "GitHub token verified in plugin";
    }
    if (empty($settings["worker_secret_cloudflare_masked"])) {
        $missing[] = "Cloudflare token uploaded to Worker vault";
    }
    if (empty($settings["worker_secret_github_masked"])) {
        $missing[] = "GitHub token uploaded to Worker vault";
    }
    return $missing;
}

function ai_webadmin_features_enabled() {
    $settings = ai_webadmin_get_settings();
    $missing = ai_webadmin_missing_activation_requirements($settings);
    return empty($missing);
}

function ai_webadmin_user_display_name_is_email($displayName, $email) {
    $display = trim((string)$displayName);
    if ($display === "") {
        return false;
    }
    if (function_exists("is_email") && is_email($display)) {
        return true;
    }
    if ($email !== "" && strtolower($display) === strtolower((string)$email)) {
        return true;
    }
    return false;
}

function ai_webadmin_set_safe_display_name($userId) {
    $settings = ai_webadmin_get_settings();
    if (!ai_webadmin_hardening_enabled() || empty($settings["prevent_email_display_name"])) {
        return;
    }
    $userId = (int)$userId;
    if ($userId <= 0) {
        return;
    }
    $user = get_userdata($userId);
    if (!$user) {
        return;
    }
    $displayName = (string)$user->display_name;
    $email = (string)$user->user_email;
    if (!ai_webadmin_user_display_name_is_email($displayName, $email)) {
        return;
    }

    $fallback = trim((string)$user->nickname);
    if ($fallback === "") {
        $fallback = trim((string)$user->user_login);
    }
    if ($fallback === "") {
        $fallback = "User-" . $userId;
    }
    if ($fallback === $displayName) {
        return;
    }
    wp_update_user([
        "ID" => $userId,
        "display_name" => $fallback,
    ]);
}

function ai_webadmin_find_primary_admin_id() {
    $admins = get_users([
        "role" => "Administrator",
        "fields" => ["ID", "user_login"],
        "orderby" => "ID",
        "order" => "ASC",
    ]);
    if (empty($admins)) {
        return 0;
    }
    $preferredId = (int)get_option("ai_webadmin_primary_admin_id", 0);
    if ($preferredId > 0) {
        foreach ($admins as $admin) {
            if ((int)$admin->ID === $preferredId) {
                return $preferredId;
            }
        }
    }
    $primary = (int)$admins[0]->ID;
    update_option("ai_webadmin_primary_admin_id", $primary, false);
    return $primary;
}

function ai_webadmin_enforce_single_admin_role() {
    if (is_multisite()) {
        return;
    }
    $settings = ai_webadmin_get_settings();
    if (!ai_webadmin_hardening_enabled() || empty($settings["enforce_single_admin"])) {
        return;
    }

    $admins = get_users([
        "role" => "Administrator",
        "fields" => ["ID"],
        "orderby" => "ID",
        "order" => "ASC",
    ]);
    if (count($admins) <= 1) {
        return;
    }

    $primaryId = ai_webadmin_find_primary_admin_id();
    if ($primaryId <= 0) {
        return;
    }

    foreach ($admins as $admin) {
        $userId = (int)$admin->ID;
        if ($userId <= 0 || $userId === $primaryId) {
            continue;
        }
        $user = new WP_User($userId);
        if (!$user || !$user->exists()) {
            continue;
        }
        if (in_array("administrator", (array)$user->roles, true)) {
        $user->set_role("editor");
    }
}

function ai_webadmin_is_google_workspace_provider($providerHint) {
    $hint = strtolower(trim((string)$providerHint));
    return (strpos($hint, "google workspace") !== false || strpos($hint, "google") !== false);
}

function ai_webadmin_domains_look_related($a, $b) {
    $x = strtolower(trim((string)$a, "."));
    $y = strtolower(trim((string)$b, "."));
    if ($x === "" || $y === "") {
        return false;
    }
    if ($x === $y) {
        return true;
    }
    if (substr($x, -strlen("." . $y)) === "." . $y) {
        return true;
    }
    if (substr($y, -strlen("." . $x)) === "." . $x) {
        return true;
    }
    return false;
}

function ai_webadmin_is_generic_editor_mailbox($email, $siteHost = "") {
    $candidate = strtolower(trim((string)$email));
    if (!is_email($candidate)) {
        return false;
    }
    $parts = explode("@", $candidate, 2);
    if (count($parts) !== 2) {
        return false;
    }
    $local = $parts[0];
    $domain = $parts[1];
    $genericLocals = [
        "wordpress",
        "wp",
        "admin",
        "webmaster",
        "contact",
        "info",
        "hello",
        "support",
        "sales",
        "office",
        "team",
        "noreply",
        "no-reply",
        "mail",
    ];
    $isGenericLocal = in_array($local, $genericLocals, true) || strpos($local, "wordpress") === 0;
    if (!$isGenericLocal) {
        return false;
    }
    $host = strtolower(trim((string)$siteHost, "."));
    if ($host === "") {
        return true;
    }
    return ai_webadmin_domains_look_related($domain, $host);
}

function ai_webadmin_build_admin_plus_alias($adminEmail, $userId) {
    $email = strtolower(trim((string)$adminEmail));
    if (!is_email($email)) {
        return "";
    }
    $parts = explode("@", $email, 2);
    if (count($parts) !== 2) {
        return "";
    }
    $local = trim((string)$parts[0]);
    $domain = trim((string)$parts[1]);
    if ($local === "" || $domain === "") {
        return "";
    }
    $localBase = explode("+", $local)[0];
    $alias = $localBase . "+wpeditor" . max(1, (int)$userId) . "@" . $domain;
    $alias = sanitize_email($alias);
    return is_email($alias) ? strtolower($alias) : "";
}

function ai_webadmin_normalize_editor_generic_emails() {
    $settings = ai_webadmin_get_settings();
    if (!ai_webadmin_hardening_enabled() || empty($settings["normalize_editor_generic_emails_to_admin"])) {
        return [
            "ok" => true,
            "changed_count" => 0,
            "candidate_count" => 0,
            "failed_count" => 0,
            "message" => "Editor email normalization is disabled.",
        ];
    }

    $mx = ai_webadmin_collect_mx_profile();
    if (!ai_webadmin_is_google_workspace_provider($mx["email_provider_hint"] ?? "")) {
        $summary = [
            "ok" => true,
            "changed_count" => 0,
            "candidate_count" => 0,
            "failed_count" => 0,
            "provider_hint" => sanitize_text_field((string)($mx["email_provider_hint"] ?? "")),
            "message" => "Skipped editor email normalization because Google Workspace was not detected.",
            "ran_at" => time(),
        ];
        update_option("ai_webadmin_editor_email_sync_last", $summary, false);
        return $summary;
    }

    $primaryAdminId = ai_webadmin_find_primary_admin_id();
    $adminUser = $primaryAdminId > 0 ? get_userdata($primaryAdminId) : null;
    $adminEmail = $adminUser ? sanitize_email((string)$adminUser->user_email) : "";
    if (!is_email($adminEmail)) {
        $summary = [
            "ok" => false,
            "changed_count" => 0,
            "candidate_count" => 0,
            "failed_count" => 1,
            "message" => "Primary admin email is missing or invalid.",
            "ran_at" => time(),
        ];
        update_option("ai_webadmin_editor_email_sync_last", $summary, false);
        return $summary;
    }

    $siteHost = wp_parse_url(home_url("/"), PHP_URL_HOST);
    $siteHost = is_string($siteHost) ? strtolower(trim($siteHost, ".")) : "";
    $editors = get_users([
        "role" => "Editor",
        "fields" => ["ID", "user_email", "user_login"],
        "orderby" => "ID",
        "order" => "ASC",
    ]);
    if (!is_array($editors) || empty($editors)) {
        $summary = [
            "ok" => true,
            "changed_count" => 0,
            "candidate_count" => 0,
            "failed_count" => 0,
            "message" => "No editor accounts found for normalization.",
            "ran_at" => time(),
        ];
        update_option("ai_webadmin_editor_email_sync_last", $summary, false);
        return $summary;
    }

    $changed = [];
    $failed = [];
    $candidates = 0;
    foreach ($editors as $editor) {
        $userId = (int)($editor->ID ?? 0);
        $currentEmail = sanitize_email((string)($editor->user_email ?? ""));
        if ($userId <= 0 || !is_email($currentEmail)) {
            continue;
        }
        if (!ai_webadmin_is_generic_editor_mailbox($currentEmail, $siteHost)) {
            continue;
        }

        $candidates += 1;
        $targetEmail = strtolower($adminEmail);
        $existingForTarget = email_exists($targetEmail);
        if ($existingForTarget && (int)$existingForTarget !== $userId) {
            $aliasEmail = ai_webadmin_build_admin_plus_alias($adminEmail, $userId);
            if ($aliasEmail === "") {
                $failed[] = [
                    "user_id" => $userId,
                    "from" => $currentEmail,
                    "reason" => "admin_email_alias_build_failed",
                ];
                continue;
            }
            $existingAlias = email_exists($aliasEmail);
            if ($existingAlias && (int)$existingAlias !== $userId) {
                $failed[] = [
                    "user_id" => $userId,
                    "from" => $currentEmail,
                    "reason" => "admin_email_alias_conflict",
                ];
                continue;
            }
            $targetEmail = $aliasEmail;
        }
        if (strtolower($currentEmail) === strtolower($targetEmail)) {
            continue;
        }
        $updated = wp_update_user([
            "ID" => $userId,
            "user_email" => $targetEmail,
        ]);
        if (is_wp_error($updated)) {
            $failed[] = [
                "user_id" => $userId,
                "from" => $currentEmail,
                "to" => $targetEmail,
                "reason" => sanitize_text_field($updated->get_error_message()),
            ];
            continue;
        }
        update_user_meta($userId, "ai_webadmin_email_normalized_to_admin", time());
        $changed[] = [
            "user_id" => $userId,
            "from" => $currentEmail,
            "to" => $targetEmail,
        ];
    }

    $summary = [
        "ok" => true,
        "changed_count" => count($changed),
        "candidate_count" => $candidates,
        "failed_count" => count($failed),
        "provider_hint" => sanitize_text_field((string)($mx["email_provider_hint"] ?? "")),
        "admin_email" => sanitize_email($adminEmail),
        "changed" => array_slice($changed, 0, 30),
        "failed" => array_slice($failed, 0, 30),
        "message" => sprintf(
            "Editor email normalization finished. Candidates %d, changed %d, failed %d.",
            $candidates,
            count($changed),
            count($failed)
        ),
        "ran_at" => time(),
    ];
    update_option("ai_webadmin_editor_email_sync_last", $summary, false);
    return $summary;
}
}

function ai_webadmin_filter_blocked_active_plugins($newValue, $oldValue) {
    $settings = ai_webadmin_get_settings();
    if (!ai_webadmin_hardening_enabled() || empty($settings["block_file_manager_plugins"])) {
        return $newValue;
    }
    if (!is_array($newValue)) {
        return $newValue;
    }
    $blocked = ai_webadmin_blocked_plugin_slugs();
    return array_values(array_diff($newValue, $blocked));
}

function ai_webadmin_filter_blocked_network_plugins($newValue, $oldValue) {
    $settings = ai_webadmin_get_settings();
    if (!ai_webadmin_hardening_enabled() || empty($settings["block_file_manager_plugins"])) {
        return $newValue;
    }
    if (!is_array($newValue)) {
        return $newValue;
    }
    $blocked = ai_webadmin_blocked_plugin_slugs();
    foreach ($blocked as $slug) {
        if (isset($newValue[$slug])) {
            unset($newValue[$slug]);
        }
    }
    return $newValue;
}

function ai_webadmin_disable_blocked_plugins_runtime() {
    $settings = ai_webadmin_get_settings();
    if (!ai_webadmin_hardening_enabled() || empty($settings["block_file_manager_plugins"])) {
        return;
    }
    if (!function_exists("deactivate_plugins")) {
        require_once ABSPATH . "wp-admin/includes/plugin.php";
    }
    $activePlugins = (array)get_option("active_plugins", []);
    $blocked = ai_webadmin_blocked_plugin_slugs();
    $toDeactivate = array_values(array_intersect($blocked, $activePlugins));
    if (!empty($toDeactivate)) {
        deactivate_plugins($toDeactivate, true, false);
        update_option("ai_webadmin_blocked_plugins_last", $toDeactivate, false);
    }

    if (is_multisite()) {
        $networkActive = (array)get_site_option("active_sitewide_plugins", []);
        foreach ($blocked as $slug) {
            if (isset($networkActive[$slug])) {
                deactivate_plugins($slug, true, true);
            }
        }
    }
}

function ai_webadmin_remove_migration_plugins_runtime() {
    $settings = ai_webadmin_get_settings();
    if (!ai_webadmin_hardening_enabled()) {
        return;
    }
    if (empty($settings["enable_plugin_rationalization"]) || empty($settings["remove_migration_replication_plugins"])) {
        return;
    }

    $targets = ai_webadmin_migration_replication_plugin_slugs();
    if (!function_exists("deactivate_plugins")) {
        require_once ABSPATH . "wp-admin/includes/plugin.php";
    }
    $active = (array)get_option("active_plugins", []);
    $toDeactivate = array_values(array_intersect($targets, $active));
    if (!empty($toDeactivate)) {
        deactivate_plugins($toDeactivate, true, false);
    }

    if (!function_exists("delete_plugins")) {
        require_once ABSPATH . "wp-admin/includes/plugin.php";
        require_once ABSPATH . "wp-admin/includes/file.php";
    }
    $all = function_exists("get_plugins") ? get_plugins() : [];
    $toDelete = [];
    foreach ($targets as $slug) {
        if (isset($all[$slug])) {
            $toDelete[] = $slug;
        }
    }
    if (!empty($toDelete)) {
        $result = delete_plugins($toDelete);
        if (!is_wp_error($result)) {
            update_option("ai_webadmin_removed_migration_plugins_last", $toDelete, false);
        }
    }
}

function ai_webadmin_read_file_tail($path, $maxBytes = 262144) {
    $file = (string)$path;
    if ($file === "" || !is_readable($file)) {
        return "";
    }
    $limit = max(4096, min(1024 * 1024, (int)$maxBytes));
    $size = @filesize($file);
    if (!is_numeric($size) || (int)$size <= 0) {
        $raw = @file_get_contents($file);
        if (!is_string($raw)) {
            return "";
        }
        return substr($raw, -$limit);
    }
    $size = (int)$size;
    $offset = max(0, $size - $limit);
    $handle = @fopen($file, "rb");
    if (!$handle) {
        $raw = @file_get_contents($file);
        if (!is_string($raw)) {
            return "";
        }
        return substr($raw, -$limit);
    }
    if ($offset > 0) {
        @fseek($handle, $offset);
    }
    $buf = @fread($handle, $limit);
    @fclose($handle);
    return is_string($buf) ? $buf : "";
}

function ai_webadmin_extract_static_export_error_line($text) {
    $raw = (string)$text;
    if ($raw === "") {
        return "";
    }
    if (preg_match_all('/^.*allowed memory size.*$/im', $raw, $matches) && !empty($matches[0])) {
        $line = trim((string)end($matches[0]));
        if ($line !== "") {
            return sanitize_text_field(substr($line, 0, 500));
        }
    }
    return sanitize_text_field(substr(trim($raw), 0, 500));
}

function ai_webadmin_detect_static_export_memory_failure($settings = null) {
    if (!is_array($settings)) {
        $settings = ai_webadmin_get_settings();
    }
    $memoryRegex = '/allowed memory size\s+\d+\s+byte/i';
    $contextRegex = '/simply[\s_-]*static|author urls crawler|wp2static|static html output/i';

    $globPatterns = [
        trailingslashit(WP_CONTENT_DIR) . "uploads/simply-static/*.log",
        trailingslashit(WP_CONTENT_DIR) . "uploads/simply-static/logs/*.log",
        trailingslashit(WP_CONTENT_DIR) . "uploads/simply-static/temp-files/*.log",
        trailingslashit(WP_CONTENT_DIR) . "uploads/wp2static/*.log",
        trailingslashit(WP_CONTENT_DIR) . "uploads/static-html-output-plugin/*.log",
        trailingslashit(WP_CONTENT_DIR) . "debug.log",
    ];

    $candidates = [];
    foreach ($globPatterns as $pattern) {
        $matches = glob($pattern);
        if (!is_array($matches)) {
            continue;
        }
        foreach ($matches as $path) {
            if (!is_string($path) || !is_file($path)) {
                continue;
            }
            $mtime = @filemtime($path);
            $candidates[] = [
                "path" => $path,
                "mtime" => is_numeric($mtime) ? (int)$mtime : 0,
            ];
        }
    }
    usort($candidates, function ($a, $b) {
        return (int)($b["mtime"] ?? 0) <=> (int)($a["mtime"] ?? 0);
    });

    foreach (array_slice($candidates, 0, 12) as $candidate) {
        $path = (string)($candidate["path"] ?? "");
        if ($path === "") {
            continue;
        }
        $tail = ai_webadmin_read_file_tail($path, 280000);
        if ($tail === "") {
            continue;
        }
        if (!preg_match($memoryRegex, $tail)) {
            continue;
        }
        if (!preg_match($contextRegex, $tail)) {
            continue;
        }
        $line = ai_webadmin_extract_static_export_error_line($tail);
        return [
            "detected" => true,
            "source" => "log_file:" . basename($path),
            "source_path" => $path,
            "message" => $line,
            "fingerprint" => sha1($path . "|" . $line),
        ];
    }

    global $wpdb;
    if ($wpdb) {
        $rows = $wpdb->get_results(
            "SELECT option_name, option_value FROM {$wpdb->options} WHERE option_name LIKE '%simply_static%' OR option_name LIKE '%wp2static%' ORDER BY option_id DESC LIMIT 60",
            ARRAY_A
        );
        if (is_array($rows)) {
            foreach ($rows as $row) {
                $name = sanitize_text_field((string)($row["option_name"] ?? ""));
                $value = (string)($row["option_value"] ?? "");
                if ($value === "") {
                    continue;
                }
                if (!preg_match($memoryRegex, $value)) {
                    continue;
                }
                if (!preg_match($contextRegex, $name . "\n" . $value)) {
                    continue;
                }
                $line = ai_webadmin_extract_static_export_error_line($value);
                return [
                    "detected" => true,
                    "source" => "option:" . $name,
                    "source_path" => $name,
                    "message" => $line,
                    "fingerprint" => sha1($name . "|" . $line),
                ];
            }
        }
    }

    return [
        "detected" => false,
        "source" => "",
        "source_path" => "",
        "message" => "",
        "fingerprint" => "",
    ];
}

function ai_webadmin_remove_failed_static_export_plugins_runtime() {
    $settings = ai_webadmin_get_settings();
    if (!ai_webadmin_hardening_enabled()) {
        return ["detected" => false, "removed" => []];
    }
    if (empty($settings["enable_plugin_rationalization"]) || empty($settings["auto_remove_failed_static_export_plugins"])) {
        return ["detected" => false, "removed" => []];
    }

    if (!function_exists("get_plugins")) {
        require_once ABSPATH . "wp-admin/includes/plugin.php";
    }
    $all = function_exists("get_plugins") ? get_plugins() : [];
    if (!is_array($all) || empty($all)) {
        return ["detected" => false, "removed" => []];
    }
    $knownTargets = ai_webadmin_static_export_plugin_slugs();
    $targetLookup = array_fill_keys($knownTargets, true);
    $installedTargets = [];
    foreach ($all as $slug => $_data) {
        $slug = (string)$slug;
        if ($slug === "") {
            continue;
        }
        if (isset($targetLookup[$slug]) || preg_match('#^(simply-static|wp2static|static-html-output-plugin)/#i', $slug)) {
            $installedTargets[] = $slug;
        }
    }
    $installedTargets = array_values(array_unique($installedTargets));
    if (empty($installedTargets)) {
        return ["detected" => false, "removed" => []];
    }

    $failure = ai_webadmin_detect_static_export_memory_failure($settings);
    if (empty($failure["detected"])) {
        return ["detected" => false, "removed" => []];
    }

    $fingerprint = sanitize_text_field((string)($failure["fingerprint"] ?? ""));

    if (!function_exists("deactivate_plugins")) {
        require_once ABSPATH . "wp-admin/includes/plugin.php";
    }
    $active = (array)get_option("active_plugins", []);
    $toDeactivate = array_values(array_intersect($installedTargets, $active));
    if (!empty($toDeactivate)) {
        deactivate_plugins($toDeactivate, true, false);
    }
    if (is_multisite()) {
        $networkActive = (array)get_site_option("active_sitewide_plugins", []);
        foreach ($installedTargets as $slug) {
            if (isset($networkActive[$slug])) {
                deactivate_plugins($slug, true, true);
            }
        }
    }

    if (!function_exists("delete_plugins")) {
        require_once ABSPATH . "wp-admin/includes/plugin.php";
        require_once ABSPATH . "wp-admin/includes/file.php";
    }
    $deleteResult = delete_plugins($installedTargets);
    $removed = is_wp_error($deleteResult) ? [] : $installedTargets;

    $message = sanitize_text_field((string)($failure["message"] ?? ""));
    $source = sanitize_text_field((string)($failure["source"] ?? ""));
    $summary = [
        "detected" => true,
        "removed" => $removed,
        "candidate_count" => count($installedTargets),
        "error_message" => $message,
        "error_source" => $source,
        "fingerprint" => $fingerprint,
        "ran_at" => time(),
    ];
    update_option("ai_webadmin_static_export_failure_last", $summary, false);
    ai_webadmin_save_runtime_settings_patch([
        "static_export_last_status" => !empty($removed) ? "removed_after_memory_error" : "detected_no_remove",
        "static_export_last_error_message" => $message,
        "static_export_last_error_source" => $source,
        "static_export_last_error_at" => time(),
        "static_export_last_removed_json" => wp_json_encode($removed),
        "static_export_last_fingerprint" => $fingerprint,
    ]);
    return $summary;
}

function ai_webadmin_remove_smtp_plugins_runtime() {
    $settings = ai_webadmin_get_settings();
    if (empty($settings["enable_email_forwarding_via_worker"]) || empty($settings["remove_smtp_plugins"])) {
        return;
    }
    $targets = ai_webadmin_smtp_email_plugin_slugs();
    if (!function_exists("deactivate_plugins")) {
        require_once ABSPATH . "wp-admin/includes/plugin.php";
    }
    $active = (array)get_option("active_plugins", []);
    $toDeactivate = array_values(array_intersect($targets, $active));
    if (!empty($toDeactivate)) {
        deactivate_plugins($toDeactivate, true, false);
    }
    if (is_multisite()) {
        $networkActive = (array)get_site_option("active_sitewide_plugins", []);
        foreach ($targets as $slug) {
            if (isset($networkActive[$slug])) {
                deactivate_plugins($slug, true, true);
            }
        }
    }

    if (!function_exists("delete_plugins")) {
        require_once ABSPATH . "wp-admin/includes/plugin.php";
        require_once ABSPATH . "wp-admin/includes/file.php";
    }
    $all = function_exists("get_plugins") ? get_plugins() : [];
    $toDelete = [];
    foreach ($targets as $slug) {
        if (isset($all[$slug])) {
            $toDelete[] = $slug;
        }
    }
    if (!empty($toDelete)) {
        $result = delete_plugins($toDelete);
        if (!is_wp_error($result)) {
            update_option("ai_webadmin_removed_smtp_plugins_last", $toDelete, false);
        }
    }
}

function ai_webadmin_inactive_plugin_protected_slugs($settings = null) {
    if (!is_array($settings)) {
        $settings = ai_webadmin_get_settings();
    }
    $base = [
        AI_WEBADMIN_PLUGIN_BASENAME,
        AI_WEBADMIN_TOLLDNS_PLUGIN_SLUG,
    ];
    $raw = (string)($settings["inactive_plugin_protected_slugs"] ?? "");
    $tokens = preg_split('/[\r\n,]+/', $raw);
    if (!is_array($tokens)) {
        $tokens = [];
    }
    foreach ($tokens as $slug) {
        $clean = sanitize_text_field(trim((string)$slug));
        if ($clean !== "") {
            $base[] = $clean;
        }
    }
    $base = array_values(array_unique(array_filter($base, function ($slug) {
        return is_string($slug) && trim($slug) !== "";
    })));
    return $base;
}

function ai_webadmin_remove_inactive_plugins_runtime() {
    $settings = ai_webadmin_get_settings();
    if (!ai_webadmin_hardening_enabled()) {
        return ["deleted" => [], "candidate_count" => 0, "protected_count" => 0];
    }
    if (empty($settings["enable_plugin_rationalization"]) || empty($settings["auto_uninstall_inactive_plugins"])) {
        return ["deleted" => [], "candidate_count" => 0, "protected_count" => 0];
    }

    if (!function_exists("get_plugins")) {
        require_once ABSPATH . "wp-admin/includes/plugin.php";
    }
    if (!function_exists("delete_plugins")) {
        require_once ABSPATH . "wp-admin/includes/plugin.php";
        require_once ABSPATH . "wp-admin/includes/file.php";
    }

    $all = function_exists("get_plugins") ? get_plugins() : [];
    if (!is_array($all) || empty($all)) {
        return ["deleted" => [], "candidate_count" => 0, "protected_count" => 0];
    }
    $active = (array)get_option("active_plugins", []);
    $activeLookup = array_fill_keys(array_values($active), true);
    $networkActive = is_multisite() ? (array)get_site_option("active_sitewide_plugins", []) : [];
    $protected = ai_webadmin_inactive_plugin_protected_slugs($settings);
    $protectedLookup = array_fill_keys($protected, true);
    $limit = max(1, min(100, (int)($settings["inactive_plugin_delete_limit"] ?? 8)));

    $candidates = [];
    $protectedHits = 0;
    foreach ($all as $slug => $_pluginData) {
        $slug = (string)$slug;
        if ($slug === "") {
            continue;
        }
        if (isset($activeLookup[$slug])) {
            continue;
        }
        if (is_multisite() && isset($networkActive[$slug])) {
            continue;
        }
        if (isset($protectedLookup[$slug])) {
            $protectedHits += 1;
            continue;
        }
        $candidates[] = $slug;
        if (count($candidates) >= $limit) {
            break;
        }
    }

    if (empty($candidates)) {
        update_option("ai_webadmin_removed_inactive_plugins_last", [
            "deleted" => [],
            "candidate_count" => 0,
            "protected_count" => $protectedHits,
            "ran_at" => time(),
        ], false);
        return ["deleted" => [], "candidate_count" => 0, "protected_count" => $protectedHits];
    }

    $deleted = [];
    foreach ($candidates as $slug) {
        $result = delete_plugins([$slug]);
        if (!is_wp_error($result)) {
            $deleted[] = $slug;
        }
    }
    $summary = [
        "deleted" => $deleted,
        "candidate_count" => count($candidates),
        "protected_count" => $protectedHits,
        "ran_at" => time(),
    ];
    update_option("ai_webadmin_removed_inactive_plugins_last", $summary, false);
    return $summary;
}

function ai_webadmin_inactive_theme_protected_slugs($settings = null) {
    if (!is_array($settings)) {
        $settings = ai_webadmin_get_settings();
    }
    $base = [
        "twentytwentyfive",
    ];
    $activeStylesheet = sanitize_key((string)get_option("stylesheet", ""));
    $activeTemplate = sanitize_key((string)get_option("template", ""));
    if ($activeStylesheet !== "") {
        $base[] = $activeStylesheet;
    }
    if ($activeTemplate !== "") {
        $base[] = $activeTemplate;
    }
    $raw = (string)($settings["inactive_theme_protected_slugs"] ?? "");
    $tokens = preg_split('/[\r\n,]+/', $raw);
    if (!is_array($tokens)) {
        $tokens = [];
    }
    foreach ($tokens as $slug) {
        $clean = sanitize_key(trim((string)$slug));
        if ($clean !== "") {
            $base[] = $clean;
        }
    }
    $base = array_values(array_unique(array_filter($base, function ($slug) {
        return is_string($slug) && trim($slug) !== "";
    })));
    return $base;
}

function ai_webadmin_remove_inactive_themes_runtime() {
    $settings = ai_webadmin_get_settings();
    if (!ai_webadmin_hardening_enabled()) {
        return ["deleted" => [], "candidate_count" => 0, "protected_count" => 0];
    }
    if (empty($settings["enable_plugin_rationalization"]) || empty($settings["auto_uninstall_inactive_themes"])) {
        return ["deleted" => [], "candidate_count" => 0, "protected_count" => 0];
    }
    if (!function_exists("wp_get_themes") || !function_exists("delete_theme")) {
        require_once ABSPATH . "wp-admin/includes/theme.php";
    }
    $themes = function_exists("wp_get_themes") ? wp_get_themes() : [];
    if (!is_array($themes) || empty($themes)) {
        return ["deleted" => [], "candidate_count" => 0, "protected_count" => 0];
    }

    $protectedLookup = array_fill_keys(ai_webadmin_inactive_theme_protected_slugs($settings), true);
    $limit = max(1, min(20, (int)($settings["inactive_theme_delete_limit"] ?? 3)));
    $candidates = [];
    $protectedHits = 0;
    foreach ($themes as $slug => $themeObj) {
        $themeSlug = sanitize_key((string)$slug);
        if ($themeSlug === "") {
            continue;
        }
        if (isset($protectedLookup[$themeSlug])) {
            $protectedHits += 1;
            continue;
        }
        $candidates[] = $themeSlug;
        if (count($candidates) >= $limit) {
            break;
        }
    }

    if (empty($candidates)) {
        update_option("ai_webadmin_removed_inactive_themes_last", [
            "deleted" => [],
            "candidate_count" => 0,
            "protected_count" => $protectedHits,
            "ran_at" => time(),
        ], false);
        return ["deleted" => [], "candidate_count" => 0, "protected_count" => $protectedHits];
    }

    $deleted = [];
    foreach ($candidates as $themeSlug) {
        $result = delete_theme($themeSlug);
        if (!is_wp_error($result)) {
            $deleted[] = $themeSlug;
        }
    }
    $summary = [
        "deleted" => $deleted,
        "candidate_count" => count($candidates),
        "protected_count" => $protectedHits,
        "ran_at" => time(),
    ];
    update_option("ai_webadmin_removed_inactive_themes_last", $summary, false);
    return $summary;
}

function ai_webadmin_license_option_name_is_ignored($optionName) {
    $name = strtolower(trim((string)$optionName));
    if ($name === "") {
        return true;
    }
    $exact = [
        AI_WEBADMIN_OPTION_KEY,
        "active_plugins",
        "siteurl",
        "home",
        "admin_email",
    ];
    if (in_array($name, $exact, true)) {
        return true;
    }
    $prefixes = [
        "_transient_",
        "_site_transient_",
        "_transient_timeout_",
        "_site_transient_timeout_",
    ];
    foreach ($prefixes as $prefix) {
        if (strpos($name, $prefix) === 0) {
            return true;
        }
    }
    return false;
}

function ai_webadmin_license_value_to_text($value, $depth = 0) {
    if ($depth > 4) {
        return "";
    }
    if ($value === null) {
        return "";
    }
    if (is_bool($value)) {
        return $value ? "true" : "false";
    }
    if (is_scalar($value)) {
        return (string)$value;
    }
    if (is_object($value)) {
        $value = get_object_vars($value);
    }
    if (!is_array($value)) {
        return "";
    }
    $parts = [];
    $count = 0;
    foreach ($value as $key => $item) {
        $count += 1;
        if ($count > 80) {
            $parts[] = "...truncated...";
            break;
        }
        $k = is_scalar($key) ? (string)$key : "item";
        $txt = ai_webadmin_license_value_to_text($item, $depth + 1);
        if ($txt === "") {
            continue;
        }
        $parts[] = $k . ": " . $txt;
    }
    return implode("\n", $parts);
}

function ai_webadmin_license_extract_emails($text) {
    $input = (string)$text;
    if ($input === "") {
        return [];
    }
    if (!preg_match_all('/[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}/i', $input, $matches)) {
        return [];
    }
    $emails = [];
    foreach ((array)$matches[0] as $raw) {
        $email = sanitize_email((string)$raw);
        if (is_email($email)) {
            $emails[] = strtolower($email);
        }
    }
    return array_values(array_unique($emails));
}

function ai_webadmin_license_expected_email($settings = null) {
    if (!is_array($settings)) {
        $settings = ai_webadmin_get_settings();
    }
    $candidate = sanitize_email((string)($settings["license_expected_email"] ?? ""));
    if (is_email($candidate)) {
        return strtolower($candidate);
    }
    $candidate = sanitize_email((string)ai_webadmin_effective_forward_email($settings));
    if (is_email($candidate)) {
        return strtolower($candidate);
    }
    $candidate = sanitize_email((string)get_option("admin_email", ""));
    if (is_email($candidate)) {
        return strtolower($candidate);
    }
    return "";
}

function ai_webadmin_license_email_is_expected($email, $expectedEmail, $siteHost) {
    $candidate = strtolower(sanitize_email((string)$email));
    if (!is_email($candidate)) {
        return false;
    }
    $expected = strtolower(sanitize_email((string)$expectedEmail));
    if ($expected !== "" && $candidate === $expected) {
        return true;
    }
    $domain = strtolower((string)substr(strrchr($candidate, "@"), 1));
    if ($domain === "") {
        return false;
    }
    $expectedDomain = $expected !== "" ? strtolower((string)substr(strrchr($expected, "@"), 1)) : "";
    if ($expectedDomain !== "" && $domain === $expectedDomain) {
        return true;
    }
    $host = strtolower(trim((string)$siteHost, "."));
    if ($host !== "") {
        if ($domain === $host) {
            return true;
        }
        if (preg_match('/(^|\\.)' . preg_quote($domain, "/") . '$/i', $host)) {
            return true;
        }
        if (preg_match('/(^|\\.)' . preg_quote($host, "/") . '$/i', $domain)) {
            return true;
        }
    }
    return false;
}

function ai_webadmin_collect_license_option_candidates($limit = 220) {
    global $wpdb;
    if (!$wpdb) {
        return [];
    }
    $max = max(20, min(1000, (int)$limit));
    $sql = $wpdb->prepare(
        "SELECT option_name, option_value
         FROM {$wpdb->options}
         WHERE option_name LIKE %s
            OR option_name LIKE %s
            OR option_name LIKE %s
            OR option_name LIKE %s
            OR option_name LIKE %s
         ORDER BY option_name ASC
         LIMIT %d",
        "%license%",
        "%licence%",
        "%subscription%",
        "%purchase_code%",
        "%serial%",
        $max
    );
    $rows = $wpdb->get_results($sql, ARRAY_A);
    return is_array($rows) ? $rows : [];
}

function ai_webadmin_license_hygiene_fallback_summary($report) {
    $reviewed = max(0, (int)($report["reviewed_count"] ?? 0));
    $flagged = max(0, (int)($report["flagged_count"] ?? 0));
    $deleted = max(0, (int)($report["deleted_count"] ?? 0));
    $unexpectedEmails = max(0, (int)($report["unexpected_email_count"] ?? 0));
    if ($deleted > 0) {
        return "Removed {$deleted} suspicious license setting(s) after reviewing {$reviewed} records. " .
            "These records were flagged for canceled/expired status or mismatched emails ({$unexpectedEmails} mismatches).";
    }
    if ($flagged > 0) {
        return "Found {$flagged} suspicious license record(s), but nothing was deleted.";
    }
    return "Reviewed {$reviewed} license-related setting(s). No suspicious canceled-license email mismatches were found.";
}

function ai_webadmin_license_hygiene_ai_summary($report, $settings = null) {
    if (!is_array($settings)) {
        $settings = ai_webadmin_get_settings();
    }
    if (!ai_webadmin_can_use_signed_worker_calls($settings)) {
        return "";
    }
    $deleted = isset($report["deleted_options"]) && is_array($report["deleted_options"]) ? $report["deleted_options"] : [];
    $deletedNames = [];
    foreach (array_slice($deleted, 0, 8) as $item) {
        if (!is_array($item)) {
            continue;
        }
        $name = sanitize_text_field((string)($item["option_name"] ?? ""));
        if ($name !== "") {
            $deletedNames[] = $name;
        }
    }
    $payload = [
        "reviewed_count" => max(0, (int)($report["reviewed_count"] ?? 0)),
        "flagged_count" => max(0, (int)($report["flagged_count"] ?? 0)),
        "deleted_count" => max(0, (int)($report["deleted_count"] ?? 0)),
        "unexpected_email_count" => max(0, (int)($report["unexpected_email_count"] ?? 0)),
        "deleted_option_names" => $deletedNames,
    ];
    $question =
        "Create a plain-English 2 sentence admin note for a small-business owner. " .
        "Explain what suspicious WordPress license settings were cleaned and why this protects them. " .
        "Data: " . wp_json_encode($payload);
    if (strlen($question) > 1400) {
        $question = substr($question, 0, 1400);
    }
    $chat = ai_webadmin_agent_chat($question);
    if (!is_array($chat) || empty($chat["ok"])) {
        return "";
    }
    $answer = sanitize_textarea_field((string)($chat["answer"] ?? ""));
    return trim($answer);
}

function ai_webadmin_run_license_hygiene($args = []) {
    $settings = ai_webadmin_get_settings();
    $defaults = [
        "force" => false,
        "delete" => true,
        "max_options" => 220,
        "use_ai" => true,
    ];
    $opts = wp_parse_args(is_array($args) ? $args : [], $defaults);
    $force = !empty($opts["force"]);
    $deleteMode = !empty($opts["delete"]);
    if (empty($settings["license_hygiene_enabled"]) && !$force) {
        return [
            "ok" => true,
            "status" => "disabled",
            "reviewed_count" => 0,
            "flagged_count" => 0,
            "deleted_count" => 0,
            "unexpected_email_count" => 0,
            "deleted_options" => [],
            "message" => "License hygiene is disabled in settings.",
        ];
    }

    $rows = ai_webadmin_collect_license_option_candidates((int)$opts["max_options"]);
    $expectedEmail = ai_webadmin_license_expected_email($settings);
    $siteHost = wp_parse_url(home_url("/"), PHP_URL_HOST);
    $siteHost = is_string($siteHost) ? strtolower(trim($siteHost, ".")) : "";

    $reviewedCount = 0;
    $flaggedCount = 0;
    $deletedCount = 0;
    $unexpectedEmailCount = 0;
    $deletedOptions = [];
    $flaggedOptions = [];

    foreach ($rows as $row) {
        if (!is_array($row)) {
            continue;
        }
        $optionName = sanitize_text_field((string)($row["option_name"] ?? ""));
        if ($optionName === "" || ai_webadmin_license_option_name_is_ignored($optionName)) {
            continue;
        }

        $rawOptionValue = isset($row["option_value"]) ? maybe_unserialize($row["option_value"]) : "";
        $text = ai_webadmin_license_value_to_text($rawOptionValue);
        if ($text === "") {
            continue;
        }
        $reviewedCount += 1;
        if (strlen($text) > 70000) {
            $text = substr($text, 0, 70000);
        }
        $combined = strtolower($optionName . "\n" . $text);
        $isLicenseLike = (preg_match('/\b(license|licence|subscription|serial|purchase|activation)\b/i', $combined) === 1);
        if (!$isLicenseLike) {
            continue;
        }
        $hasCanceled = (preg_match('/\b(cancelled|canceled|expired|inactive|revoked|suspended|terminated)\b/i', $combined) === 1);
        $emails = ai_webadmin_license_extract_emails($text);
        $unexpectedEmails = [];
        foreach ($emails as $email) {
            if (!ai_webadmin_license_email_is_expected($email, $expectedEmail, $siteHost)) {
                $unexpectedEmails[] = $email;
            }
        }
        $unexpectedEmails = array_values(array_unique($unexpectedEmails));
        $unexpectedEmailCount += count($unexpectedEmails);
        $isSuspicious = ($hasCanceled || !empty($unexpectedEmails));
        if (!$isSuspicious) {
            continue;
        }

        $flaggedCount += 1;
        $reasons = [];
        if ($hasCanceled) {
            $reasons[] = "canceled_or_expired_status_detected";
        }
        if (!empty($unexpectedEmails)) {
            $reasons[] = "unexpected_license_email_detected";
        }
        $record = [
            "option_name" => $optionName,
            "reasons" => $reasons,
            "emails" => array_slice($emails, 0, 10),
            "unexpected_emails" => array_slice($unexpectedEmails, 0, 10),
        ];

        if ($deleteMode) {
            $deleted = delete_option($optionName);
            if (!$deleted && is_multisite()) {
                $deleted = delete_site_option($optionName);
            }
            if ($deleted) {
                $deletedCount += 1;
                $deletedOptions[] = $record;
                continue;
            }
            $record["delete_error"] = "delete_failed";
        }
        $flaggedOptions[] = $record;
    }

    $message = "Reviewed {$reviewedCount} license-related setting(s). Flagged {$flaggedCount}. Deleted {$deletedCount}.";
    $summary = ai_webadmin_license_hygiene_fallback_summary([
        "reviewed_count" => $reviewedCount,
        "flagged_count" => $flaggedCount,
        "deleted_count" => $deletedCount,
        "unexpected_email_count" => $unexpectedEmailCount,
    ]);
    if (!empty($opts["use_ai"]) && ($flaggedCount > 0 || $deletedCount > 0)) {
        $aiSummary = ai_webadmin_license_hygiene_ai_summary([
            "reviewed_count" => $reviewedCount,
            "flagged_count" => $flaggedCount,
            "deleted_count" => $deletedCount,
            "unexpected_email_count" => $unexpectedEmailCount,
            "deleted_options" => $deletedOptions,
        ], $settings);
        if ($aiSummary !== "") {
            $summary = $aiSummary;
        }
    }

    $snapshotStatus = "skipped";
    $snapshotMessage = "No records deleted.";
    if ($deleteMode && $deletedCount > 0) {
        $before = ai_webadmin_get_settings();
        $beforeTs = (int)($before["github_backup_last_snapshot_at"] ?? 0);
        ai_webadmin_send_backup_snapshot();
        $after = ai_webadmin_get_settings();
        $afterTs = (int)($after["github_backup_last_snapshot_at"] ?? 0);
        if ($afterTs > $beforeTs) {
            $snapshotStatus = sanitize_text_field((string)($after["github_backup_last_status"] ?? "unknown"));
            $snapshotMessage = sanitize_text_field((string)($after["github_backup_last_message"] ?? ""));
        } else {
            $snapshotStatus = "not_configured";
            $snapshotMessage = "GitHub snapshot skipped (complete token + repo setup first).";
        }
    }

    ai_webadmin_save_runtime_settings_patch([
        "license_hygiene_last_run_at" => time(),
        "license_hygiene_last_status" => ($flaggedCount > 0 ? "issues_found" : "clean"),
        "license_hygiene_last_message" => sanitize_text_field($message),
        "license_hygiene_last_ai_summary" => sanitize_textarea_field($summary),
        "license_hygiene_last_deleted_json" => wp_json_encode(array_slice($deletedOptions, 0, 50)),
    ]);

    $report = [
        "ok" => true,
        "status" => ($flaggedCount > 0 ? "issues_found" : "clean"),
        "reviewed_count" => $reviewedCount,
        "flagged_count" => $flaggedCount,
        "deleted_count" => $deletedCount,
        "unexpected_email_count" => $unexpectedEmailCount,
        "deleted_options" => $deletedOptions,
        "flagged_options" => $flaggedOptions,
        "ai_summary" => $summary,
        "message" => $message,
        "github_snapshot_status" => $snapshotStatus,
        "github_snapshot_message" => $snapshotMessage,
        "ran_at" => time(),
    ];
    update_option("ai_webadmin_license_hygiene_last", $report, false);
    return $report;
}

function ai_webadmin_count_active_smtp_plugins($activePluginSlugs) {
    $targets = ai_webadmin_smtp_email_plugin_slugs();
    return count(array_intersect(array_values((array)$activePluginSlugs), $targets));
}

function ai_webadmin_effective_forward_email($settings = null) {
    if (!is_array($settings)) {
        $settings = ai_webadmin_get_settings();
    }
    $candidate = sanitize_email((string)($settings["lead_forward_email"] ?? ""));
    if (is_email($candidate)) {
        return $candidate;
    }
    $primaryAdminId = ai_webadmin_find_primary_admin_id();
    if ($primaryAdminId > 0) {
        $adminUser = get_userdata($primaryAdminId);
        if ($adminUser && is_email((string)$adminUser->user_email)) {
            return (string)$adminUser->user_email;
        }
    }
    $adminEmail = sanitize_email((string)get_option("admin_email", ""));
    if (is_email($adminEmail)) {
        return $adminEmail;
    }
    return "";
}

function ai_webadmin_collect_mx_profile() {
    $host = wp_parse_url(home_url("/"), PHP_URL_HOST);
    if (!is_string($host) || trim($host) === "") {
        return [
            "host" => null,
            "has_mx_records" => null,
            "mx_records" => [],
            "email_provider_hint" => null,
        ];
    }
    $host = trim($host);
    $records = [];
    if (function_exists("dns_get_record")) {
        $dns = @dns_get_record($host, DNS_MX);
        if (is_array($dns)) {
            foreach ($dns as $row) {
                if (!is_array($row)) {
                    continue;
                }
                $target = strtolower(trim((string)($row["target"] ?? "")));
                if ($target === "") {
                    continue;
                }
                $records[] = [
                    "target" => $target,
                    "pri" => isset($row["pri"]) ? (int)$row["pri"] : null,
                ];
            }
        }
    }
    usort($records, function ($a, $b) {
        return (int)($a["pri"] ?? 9999) <=> (int)($b["pri"] ?? 9999);
    });
    $targets = array_map(function ($x) {
        return (string)($x["target"] ?? "");
    }, $records);
    $targetsText = implode(" ", $targets);
    $provider = null;
    if (strpos($targetsText, "google.com") !== false || strpos($targetsText, "googlemail.com") !== false) $provider = "Google Workspace";
    if (strpos($targetsText, "outlook.com") !== false || strpos($targetsText, "protection.outlook.com") !== false) $provider = "Microsoft 365";
    if (strpos($targetsText, "zoho.com") !== false) $provider = "Zoho Mail";
    if (strpos($targetsText, "icloud.com") !== false || strpos($targetsText, "me.com") !== false) $provider = "iCloud Mail";
    if (strpos($targetsText, "cloudflare.net") !== false) $provider = "Cloudflare Email Routing";

    return [
        "host" => $host,
        "has_mx_records" => !empty($records),
        "mx_records" => array_slice($records, 0, 20),
        "email_provider_hint" => $provider,
    ];
}

function ai_webadmin_is_lead_forward_verified($settings = null) {
    if (!is_array($settings)) {
        $settings = ai_webadmin_get_settings();
    }
    return ((string)($settings["lead_forward_verification_status"] ?? "") === "verified");
}

function ai_webadmin_apply_worker_email_forwarding_state($workerState) {
    if (!is_array($workerState)) {
        return;
    }
    $verification = isset($workerState["verification"]) && is_array($workerState["verification"]) ? $workerState["verification"] : [];
    $status = sanitize_text_field((string)($verification["status"] ?? ""));
    if ($status === "") {
        $status = sanitize_text_field((string)($workerState["verification_status"] ?? ""));
    }
    $allowed = ["not_started", "unverified", "pending", "verified", "failed"];
    if (!in_array($status, $allowed, true)) {
        $status = "not_started";
    }

    $verificationEmail = sanitize_email((string)($verification["email"] ?? ""));
    if ($verificationEmail === "") {
        $verificationEmail = sanitize_email((string)($workerState["forward_to_email"] ?? ""));
    }

    $sentAtRaw = isset($verification["sent_at"]) ? $verification["sent_at"] : null;
    $confirmedAtRaw = isset($verification["confirmed_at"]) ? $verification["confirmed_at"] : null;
    $sentAt = is_numeric($sentAtRaw) ? (int)$sentAtRaw : (is_string($sentAtRaw) ? strtotime($sentAtRaw) : 0);
    $confirmedAt = is_numeric($confirmedAtRaw) ? (int)$confirmedAtRaw : (is_string($confirmedAtRaw) ? strtotime($confirmedAtRaw) : 0);
    if (!is_numeric($sentAt) || $sentAt < 0) {
        $sentAt = 0;
    }
    if (!is_numeric($confirmedAt) || $confirmedAt < 0) {
        $confirmedAt = 0;
    }

    $patch = [
        "lead_forward_verification_status" => $status,
        "lead_forward_verification_email" => $verificationEmail,
        "lead_forward_verification_sent_at" => (int)$sentAt,
        "lead_forward_verification_confirmed_at" => (int)$confirmedAt,
        "lead_forward_verification_last_error" => sanitize_text_field((string)($verification["last_error"] ?? "")),
        "lead_forward_verification_last_check_at" => time(),
    ];
    ai_webadmin_save_runtime_settings_patch($patch);
}

function ai_webadmin_refresh_lead_forward_verification_status() {
    $settings = ai_webadmin_get_settings();
    if (empty($settings["enable_email_forwarding_via_worker"])) {
        return ["ok" => false, "error" => "email_forwarding_disabled"];
    }
    $sessionId = trim((string)($settings["onboarding_session_id"] ?? ""));
    if ($sessionId === "") {
        return ["ok" => false, "error" => "missing_session_id"];
    }
    $response = ai_webadmin_signed_post($settings, "plugin/wp/email/forward/verification/status", [
        "session_id" => $sessionId,
        "site_url" => home_url("/"),
    ], 20);
    if (is_wp_error($response)) {
        return ["ok" => false, "error" => $response->get_error_message()];
    }
    $code = (int)wp_remote_retrieve_response_code($response);
    $body = json_decode((string)wp_remote_retrieve_body($response), true);
    if ($code < 200 || $code >= 300 || !is_array($body) || empty($body["ok"])) {
        $msg = is_array($body) && !empty($body["error"]) ? (string)$body["error"] : "verification_status_failed";
        return ["ok" => false, "error" => $msg];
    }
    if (isset($body["verification"]) && is_array($body["verification"])) {
        ai_webadmin_apply_worker_email_forwarding_state(["verification" => $body["verification"]]);
    }
    return ["ok" => true, "verification" => $body["verification"] ?? null];
}

function ai_webadmin_send_lead_forward_verification_email() {
    $settings = ai_webadmin_get_settings();
    if (empty($settings["enable_email_forwarding_via_worker"])) {
        return ["ok" => false, "error" => "email_forwarding_disabled"];
    }
    if (!ai_webadmin_features_enabled()) {
        return ["ok" => false, "error" => "activation_lock_not_complete"];
    }
    $sessionId = trim((string)($settings["onboarding_session_id"] ?? ""));
    if ($sessionId === "") {
        return ["ok" => false, "error" => "missing_session_id"];
    }
    $forwardEmail = ai_webadmin_effective_forward_email($settings);
    if (!is_email($forwardEmail)) {
        return ["ok" => false, "error" => "invalid_forward_email"];
    }

    $response = ai_webadmin_signed_post($settings, "plugin/wp/email/forward/verification/start", [
        "session_id" => $sessionId,
        "site_url" => home_url("/"),
        "forward_to_email" => $forwardEmail,
        "source" => "wp_admin_verification_test",
    ], 20);
    if (is_wp_error($response)) {
        return ["ok" => false, "error" => $response->get_error_message()];
    }
    $code = (int)wp_remote_retrieve_response_code($response);
    $body = json_decode((string)wp_remote_retrieve_body($response), true);
    if ($code < 200 || $code >= 300 || !is_array($body) || empty($body["ok"])) {
        $msg = is_array($body) && !empty($body["error"]) ? (string)$body["error"] : "verification_start_failed";
        return ["ok" => false, "error" => $msg];
    }

    $verificationUrl = esc_url_raw((string)($body["verification_url"] ?? ""));
    if ($verificationUrl === "") {
        return ["ok" => false, "error" => "verification_link_missing"];
    }

    $subject = "Confirm AI WebAdmin lead-form forwarding test";
    $message =
        "We received your request to verify lead-form forwarding through Cloudflare Worker.\n\n" .
        "Click this verification link:\n" .
        $verificationUrl . "\n\n" .
        "After clicking, return to WordPress > Settings > AI WebAdmin and click \"Refresh Verification Status\".\n";
    $sent = wp_mail($forwardEmail, $subject, $message);
    if (!$sent) {
        return ["ok" => false, "error" => "wp_mail_failed_sending_verification"];
    }

    ai_webadmin_apply_worker_email_forwarding_state([
        "verification" => isset($body["verification"]) && is_array($body["verification"]) ? $body["verification"] : [],
        "forward_to_email" => $forwardEmail,
    ]);
    ai_webadmin_save_runtime_settings_patch([
        "lead_forward_verification_last_link_url" => $verificationUrl,
        "lead_forward_verification_last_check_at" => time(),
    ]);
    return [
        "ok" => true,
        "verification_url" => $verificationUrl,
        "forward_to_email" => $forwardEmail,
        "verification" => $body["verification"] ?? null,
    ];
}

function ai_webadmin_sync_email_forwarding_profile() {
    $settings = ai_webadmin_get_settings();
    if (empty($settings["enable_email_forwarding_via_worker"])) {
        return;
    }
    if (!ai_webadmin_features_enabled()) {
        return;
    }
    $sessionId = trim((string)($settings["onboarding_session_id"] ?? ""));
    if ($sessionId === "") {
        return;
    }

    $forwardEmail = ai_webadmin_effective_forward_email($settings);
    $mx = ai_webadmin_collect_mx_profile();
    $response = ai_webadmin_signed_post($settings, "plugin/wp/email/forward/config", [
        "session_id" => $sessionId,
        "site_url" => home_url("/"),
        "forward_to_email" => $forwardEmail,
        "has_mx_records" => $mx["has_mx_records"],
        "mx_records" => $mx["mx_records"],
        "email_provider_hint" => $mx["email_provider_hint"],
        "source" => "plugin_sync",
    ], 20);
    if (is_wp_error($response)) {
        return;
    }
    $status = (int)wp_remote_retrieve_response_code($response);
    if ($status < 200 || $status >= 300) {
        return;
    }
    $decoded = json_decode((string)wp_remote_retrieve_body($response), true);
    if (!is_array($decoded) || empty($decoded["ok"])) {
        return;
    }
    if (isset($decoded["email_forwarding"]) && is_array($decoded["email_forwarding"])) {
        ai_webadmin_apply_worker_email_forwarding_state($decoded["email_forwarding"]);
    }
}

function ai_webadmin_is_lead_mail_payload($atts) {
    if (!is_array($atts)) {
        return false;
    }
    $subject = strtolower((string)($atts["subject"] ?? ""));
    $message = strtolower((string)($atts["message"] ?? ""));
    $text = $subject . "\n" . $message;
    if ($text === "") {
        return false;
    }
    if (preg_match('/\b(password reset|reset your password|new user|verification code|2fa|otp|login)\b/i', $text)) {
        return false;
    }
    if (preg_match('/\b(contact|lead|inquiry|enquiry|new message|form submission|new submission|quote request|book(ing|ed)?|appointment)\b/i', $text)) {
        return true;
    }
    return false;
}

function ai_webadmin_forward_lead_mail_to_worker($atts) {
    $settings = ai_webadmin_get_settings();
    if (empty($settings["enable_email_forwarding_via_worker"])) {
        return false;
    }
    if (!ai_webadmin_features_enabled()) {
        return false;
    }
    if (!ai_webadmin_is_lead_mail_payload($atts)) {
        return false;
    }
    $sessionId = trim((string)($settings["onboarding_session_id"] ?? ""));
    if ($sessionId === "") {
        return false;
    }
    $forwardEmail = ai_webadmin_effective_forward_email($settings);
    if (!is_email($forwardEmail)) {
        return false;
    }
    $mx = ai_webadmin_collect_mx_profile();

    $payload = [
        "session_id" => $sessionId,
        "site_url" => home_url("/"),
        "forward_to_email" => $forwardEmail,
        "subject" => (string)($atts["subject"] ?? ""),
        "message" => (string)($atts["message"] ?? ""),
        "to" => $atts["to"] ?? null,
        "headers" => $atts["headers"] ?? null,
        "attachments" => $atts["attachments"] ?? null,
        "source" => "wp_mail_hook",
        "has_mx_records" => $mx["has_mx_records"],
        "mx_records" => $mx["mx_records"],
        "email_provider_hint" => $mx["email_provider_hint"],
    ];
    $response = ai_webadmin_signed_post($settings, "plugin/wp/lead/forward", $payload, 20);
    if (is_wp_error($response)) {
        return false;
    }
    $status = (int)wp_remote_retrieve_response_code($response);
    if ($status < 200 || $status >= 300) {
        return false;
    }
    $decoded = json_decode((string)wp_remote_retrieve_body($response), true);
    if (is_array($decoded) && !empty($decoded["ok"])) {
        if (isset($decoded["verification"]) && is_array($decoded["verification"])) {
            ai_webadmin_apply_worker_email_forwarding_state([
                "verification" => $decoded["verification"],
                "forward_to_email" => $forwardEmail,
            ]);
        }
    }
    return true;
}

function ai_webadmin_pre_wp_mail_filter($preempt, $atts) {
    if ($preempt !== null) {
        return $preempt;
    }
    $forwarded = ai_webadmin_forward_lead_mail_to_worker($atts);
    if (!$forwarded) {
        return null;
    }
    $settings = ai_webadmin_get_settings();
    if (!empty($settings["suppress_local_lead_mail"]) && ai_webadmin_is_lead_forward_verified($settings)) {
        return true;
    }
    return null;
}

function ai_webadmin_user_last_login_ts($userId, $userRegistered = "") {
    $meta = (int)get_user_meta((int)$userId, "ai_webadmin_last_login_at", true);
    if ($meta > 0) {
        return $meta;
    }
    $registeredTs = strtotime((string)$userRegistered);
    if (is_numeric($registeredTs) && $registeredTs > 0) {
        return (int)$registeredTs;
    }
    return 0;
}

function ai_webadmin_purge_inactive_users() {
    $settings = ai_webadmin_get_settings();
    if (empty($settings["enable_inactive_user_cleanup"])) {
        return ["candidate_count" => 0, "deleted_count" => 0, "deleted_user_ids" => []];
    }

    $cutoffDays = max(30, (int)$settings["inactive_user_days"]);
    $cutoffTs = time() - ($cutoffDays * DAY_IN_SECONDS);
    $deleteLimit = max(1, (int)$settings["inactive_user_delete_limit"]);
    $primaryAdminId = ai_webadmin_find_primary_admin_id();

    $users = get_users([
        "fields" => ["ID", "user_registered", "roles"],
        "orderby" => "ID",
        "order" => "ASC",
    ]);

    $candidates = [];
    foreach ($users as $user) {
        $userId = (int)$user->ID;
        if ($userId <= 0) {
            continue;
        }
        if ($userId === $primaryAdminId) {
            continue;
        }
        $roles = is_array($user->roles) ? $user->roles : [];
        if (in_array("administrator", $roles, true)) {
            continue;
        }

        $lastLoginTs = ai_webadmin_user_last_login_ts($userId, (string)$user->user_registered);
        if ($lastLoginTs > 0 && $lastLoginTs < $cutoffTs) {
            $candidates[] = $userId;
        }
    }

    $deleted = [];
    if (!empty($candidates)) {
        if (!function_exists("wp_delete_user")) {
            require_once ABSPATH . "wp-admin/includes/user.php";
        }
        foreach (array_slice($candidates, 0, $deleteLimit) as $userId) {
            $ok = wp_delete_user((int)$userId, $primaryAdminId > 0 ? $primaryAdminId : null);
            if ($ok) {
                $deleted[] = (int)$userId;
            }
        }
    }

    $summary = [
        "candidate_count" => count($candidates),
        "deleted_count" => count($deleted),
        "deleted_user_ids" => $deleted,
        "ran_at" => time(),
        "cutoff_days" => $cutoffDays,
    ];
    update_option("ai_webadmin_inactive_user_cleanup_last", $summary, false);
    return $summary;
}

function ai_webadmin_should_skip_backup_path($relativePath) {
    $rel = ltrim(str_replace("\\", "/", (string)$relativePath), "/");
    if ($rel === "") {
        return true;
    }
    $skipPrefixes = [
        ".git/",
        "node_modules/",
        "wp-content/cache/",
        "wp-content/uploads/cache/",
        "wp-content/upgrade/",
    ];
    foreach ($skipPrefixes as $prefix) {
        if (strpos($rel, $prefix) === 0) {
            return true;
        }
    }
    return false;
}

function ai_webadmin_collect_site_manifest($maxFiles = 10000) {
    $root = rtrim((string)ABSPATH, "/\\");
    $maxFiles = max(500, min(30000, (int)$maxFiles));
    $entries = [];
    $scanned = 0;
    $truncated = false;
    $maxHashBytes = 5 * 1024 * 1024;

    try {
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS | FilesystemIterator::CURRENT_AS_FILEINFO),
            RecursiveIteratorIterator::LEAVES_ONLY
        );
    } catch (Exception $e) {
        return [
            "generated_at" => gmdate("c"),
            "root" => $root,
            "scanned_files" => 0,
            "manifest_count" => 0,
            "truncated" => false,
            "error" => "manifest_iterator_error",
            "files" => [],
        ];
    }

    foreach ($iterator as $fileInfo) {
        if (!($fileInfo instanceof SplFileInfo) || !$fileInfo->isFile()) {
            continue;
        }
        $fullPath = (string)$fileInfo->getPathname();
        $relative = ltrim(str_replace("\\", "/", substr($fullPath, strlen($root))), "/");
        if (ai_webadmin_should_skip_backup_path($relative)) {
            continue;
        }
        $scanned += 1;
        if (count($entries) >= $maxFiles) {
            $truncated = true;
            break;
        }
        $size = (int)$fileInfo->getSize();
        $mtime = (int)$fileInfo->getMTime();
        $hash = null;
        if ($size >= 0 && $size <= $maxHashBytes && is_readable($fullPath)) {
            $hash = @hash_file("sha256", $fullPath) ?: null;
        }
        $entries[] = [
            "path" => $relative,
            "size" => $size,
            "mtime" => $mtime,
            "sha256" => $hash,
        ];
    }

    return [
        "generated_at" => gmdate("c"),
        "root" => $root,
        "scanned_files" => $scanned,
        "manifest_count" => count($entries),
        "truncated" => $truncated,
        "files" => $entries,
    ];
}

function ai_webadmin_htaccess_rules() {
    return [
        "<IfModule mod_authz_core.c>",
        "  <Files \"xmlrpc.php\">",
        "    Require all denied",
        "  </Files>",
        "  <FilesMatch \"^(wp-config\\.php|readme\\.html|license\\.txt)$\">",
        "    Require all denied",
        "  </FilesMatch>",
        "</IfModule>",
        "<IfModule !mod_authz_core.c>",
        "  <Files \"xmlrpc.php\">",
        "    Order Deny,Allow",
        "    Deny from all",
        "  </Files>",
        "  <FilesMatch \"^(wp-config\\.php|readme\\.html|license\\.txt)$\">",
        "    Order Deny,Allow",
        "    Deny from all",
        "  </FilesMatch>",
        "</IfModule>",
    ];
}

function ai_webadmin_sync_htaccess_rules() {
    $settings = ai_webadmin_get_settings();
    if (!ai_webadmin_hardening_enabled()) {
        return;
    }
    if (!empty($settings["apply_htaccess_hardening"])) {
        if (!function_exists("insert_with_markers")) {
            require_once ABSPATH . "wp-admin/includes/misc.php";
        }
        $path = trailingslashit(ABSPATH) . ".htaccess";
        if (file_exists($path) && is_writable($path)) {
            insert_with_markers($path, AI_WEBADMIN_HTACCESS_MARKER, ai_webadmin_htaccess_rules());
        }
        return;
    }
    if (!function_exists("insert_with_markers")) {
        require_once ABSPATH . "wp-admin/includes/misc.php";
    }
    $path = trailingslashit(ABSPATH) . ".htaccess";
    if (file_exists($path) && is_writable($path)) {
        insert_with_markers($path, AI_WEBADMIN_HTACCESS_MARKER, []);
    }
}

function ai_webadmin_block_xmlrpc_request() {
    $settings = ai_webadmin_get_settings();
    if (!ai_webadmin_hardening_enabled() || empty($settings["disable_xmlrpc"])) {
        return;
    }
    $requestUri = isset($_SERVER["REQUEST_URI"]) ? (string)$_SERVER["REQUEST_URI"] : "";
    if ($requestUri === "") {
        return;
    }
    $path = wp_parse_url($requestUri, PHP_URL_PATH);
    if (!is_string($path)) {
        return;
    }
    if (preg_match("#/xmlrpc\.php$#i", $path)) {
        status_header(403);
        nocache_headers();
        exit("XML-RPC disabled.");
    }
}

function ai_webadmin_login_rate_limit_pre_auth($user, $username, $password) {
    $settings = ai_webadmin_get_settings();
    if (!ai_webadmin_hardening_enabled() || empty($settings["enable_login_rate_limit"])) {
        return $user;
    }
    if ((string)$username === "" && (string)$password === "") {
        return $user;
    }
    $ip = ai_webadmin_client_ip();
    $lockoutUntil = (int)get_transient(ai_webadmin_lockout_key($ip));
    if ($lockoutUntil > time()) {
        $waitSeconds = max(1, $lockoutUntil - time());
        $waitMinutes = max(1, (int)ceil($waitSeconds / 60));
        return new WP_Error("ai_webadmin_login_locked", sprintf("Too many login attempts. Try again in %d minute(s).", $waitMinutes));
    }
    if ($lockoutUntil > 0) {
        delete_transient(ai_webadmin_lockout_key($ip));
    }
    return $user;
}

function ai_webadmin_login_failed($username, $error = null) {
    $settings = ai_webadmin_get_settings();
    if (!ai_webadmin_hardening_enabled() || empty($settings["enable_login_rate_limit"])) {
        return;
    }
    $ip = ai_webadmin_client_ip();
    $attempts = max(0, (int)get_transient(ai_webadmin_login_throttle_key($ip)));
    $attempts += 1;
    $windowSeconds = max(60, ((int)$settings["login_rate_limit_window_minutes"]) * 60);
    set_transient(ai_webadmin_login_throttle_key($ip), $attempts, $windowSeconds);

    $maxAttempts = max(3, (int)$settings["login_rate_limit_attempts"]);
    if ($attempts >= $maxAttempts) {
        $lockoutSeconds = max(60, ((int)$settings["login_rate_limit_lockout_minutes"]) * 60);
        set_transient(ai_webadmin_lockout_key($ip), time() + $lockoutSeconds, $lockoutSeconds);
    }
}

function ai_webadmin_login_success($userLogin, $user) {
    $settings = ai_webadmin_get_settings();
    $ip = ai_webadmin_client_ip();
    if (ai_webadmin_hardening_enabled() && !empty($settings["enable_login_rate_limit"])) {
        delete_transient(ai_webadmin_login_throttle_key($ip));
        delete_transient(ai_webadmin_lockout_key($ip));
    }
    if ($user instanceof WP_User) {
        update_user_meta((int)$user->ID, "ai_webadmin_last_login_at", time());
    }
}

function ai_webadmin_enforce_admin_sso_login($user, $username, $password) {
    if (is_wp_error($user) || !($user instanceof WP_User)) {
        return $user;
    }
    $settings = ai_webadmin_get_settings();
    if (!ai_webadmin_hardening_enabled() || empty($settings["enforce_admin_sso"])) {
        return $user;
    }
    if (!in_array("administrator", (array)$user->roles, true)) {
        return $user;
    }
    $identityEmail = ai_webadmin_access_header_value($settings);
    if ($identityEmail === "") {
        return new WP_Error("ai_webadmin_admin_sso_required", "Administrator login requires SSO.");
    }
    if (strcasecmp(trim((string)$user->user_email), $identityEmail) !== 0) {
        return new WP_Error("ai_webadmin_admin_sso_mismatch", "Administrator SSO identity does not match this account.");
    }
    return $user;
}

function ai_webadmin_run_hardening_pass($force = false) {
    if (!ai_webadmin_hardening_enabled()) {
        return;
    }
    if (!$force) {
        $lastRun = (int)get_transient("ai_webadmin_hardening_pass_last");
        if ($lastRun > 0 && (time() - $lastRun) < 300) {
            return;
        }
    }
    set_transient("ai_webadmin_hardening_pass_last", time(), 300);
    $currentUserId = get_current_user_id();
    if ($currentUserId > 0) {
        ai_webadmin_set_safe_display_name($currentUserId);
    }
    ai_webadmin_disable_blocked_plugins_runtime();
    ai_webadmin_remove_smtp_plugins_runtime();
    ai_webadmin_remove_migration_plugins_runtime();
    ai_webadmin_remove_failed_static_export_plugins_runtime();
    ai_webadmin_remove_inactive_plugins_runtime();
    ai_webadmin_remove_inactive_themes_runtime();
    ai_webadmin_normalize_editor_generic_emails();
    ai_webadmin_enforce_single_admin_role();
    ai_webadmin_sync_htaccess_rules();
}

function ai_webadmin_sweep_email_display_names($maxUsers = 300) {
    $settings = ai_webadmin_get_settings();
    if (!ai_webadmin_hardening_enabled() || empty($settings["prevent_email_display_name"])) {
        return;
    }
    $maxUsers = max(10, min(2000, (int)$maxUsers));
    $users = get_users([
        "number" => $maxUsers,
        "fields" => ["ID"],
        "orderby" => "ID",
        "order" => "ASC",
    ]);
    foreach ($users as $user) {
        ai_webadmin_set_safe_display_name((int)$user->ID);
    }
}

function ai_webadmin_boot_hardening_hooks() {
    $settings = ai_webadmin_get_settings();
    if (!ai_webadmin_hardening_enabled()) {
        return;
    }
    if (!defined("DISALLOW_FILE_EDIT")) {
        define("DISALLOW_FILE_EDIT", true);
    }
    if (!empty($settings["disable_xmlrpc"])) {
        add_filter("xmlrpc_enabled", "__return_false");
        add_filter("xmlrpc_methods", "__return_empty_array");
        add_filter("wp_headers", function ($headers) {
            if (is_array($headers) && isset($headers["X-Pingback"])) {
                unset($headers["X-Pingback"]);
            }
            return $headers;
        });
    }
}
add_action("plugins_loaded", "ai_webadmin_boot_hardening_hooks", 5);

function ai_webadmin_render_unlock_login_fields() {
    $settings = ai_webadmin_get_settings();
    if (!ai_webadmin_unlock_enabled($settings)) {
        return;
    }
    $challenge = null;
    if (!empty($settings["require_wallet_signature_unlock"])) {
        $challenge = ai_webadmin_issue_wallet_login_challenge($settings);
    }
    ?>
    <p>
      <strong>AI WebAdmin Unlock</strong><br/>
      <span class="description">Complete enabled unlock checks before login.</span>
    </p>
    <?php if (!empty($settings["enable_passcode_unlock"])): ?>
      <p>
        <label for="ai_webadmin_passcode">Passcode</label><br/>
        <input type="password" name="ai_webadmin_passcode" id="ai_webadmin_passcode" class="input" autocomplete="one-time-code" />
      </p>
    <?php endif; ?>
    <?php if (!empty($settings["require_hardware_key_unlock"])): ?>
      <p>
        <label>
          <input type="checkbox" name="ai_webadmin_hardware_key_confirmed" value="1" />
          I completed hardware key/passkey verification
        </label><br/>
        <span class="description">This requires an installed WebAuthn/passkey plugin integration.</span>
      </p>
    <?php endif; ?>
    <?php if (!empty($settings["require_wallet_signature_unlock"]) && is_array($challenge)): ?>
      <p>
        <label for="ai_webadmin_wallet_address">Wallet Address</label><br/>
        <input type="text" name="ai_webadmin_wallet_address" id="ai_webadmin_wallet_address" class="input" value="" autocomplete="off" />
      </p>
      <input type="hidden" name="ai_webadmin_wallet_signature" id="ai_webadmin_wallet_signature" value="" />
      <input type="hidden" name="ai_webadmin_wallet_message" id="ai_webadmin_wallet_message" value="<?php echo esc_attr($challenge["message"]); ?>" />
      <input type="hidden" name="ai_webadmin_wallet_nonce" id="ai_webadmin_wallet_nonce" value="<?php echo esc_attr($challenge["nonce"]); ?>" />
      <p>
        <button type="button" id="ai-webadmin-wallet-sign" class="button button-secondary">Sign Wallet Challenge</button><br/>
        <span id="ai-webadmin-wallet-status" class="description">Not signed yet.</span>
      </p>
      <script>
      (function() {
        var btn = document.getElementById("ai-webadmin-wallet-sign");
        if (!btn) return;
        var status = document.getElementById("ai-webadmin-wallet-status");
        var addrField = document.getElementById("ai_webadmin_wallet_address");
        var sigField = document.getElementById("ai_webadmin_wallet_signature");
        var msgField = document.getElementById("ai_webadmin_wallet_message");
        var setStatus = function(text) { if (status) status.textContent = text; };
        btn.addEventListener("click", async function() {
          try {
            if (!window.ethereum || !window.ethereum.request) {
              setStatus("No wallet detected in browser.");
              return;
            }
            const accounts = await window.ethereum.request({ method: "eth_requestAccounts" });
            const account = Array.isArray(accounts) && accounts.length ? accounts[0] : "";
            if (!account) {
              setStatus("No wallet account selected.");
              return;
            }
            var message = msgField ? msgField.value : "";
            let signature;
            try {
              signature = await window.ethereum.request({ method: "personal_sign", params: [message, account] });
            } catch (err) {
              signature = await window.ethereum.request({ method: "personal_sign", params: [account, message] });
            }
            if (addrField) addrField.value = account;
            if (sigField) sigField.value = signature || "";
            setStatus(signature ? "Wallet challenge signed." : "Wallet signature failed.");
          } catch (err) {
            setStatus("Wallet signature failed.");
          }
        });
      })();
      </script>
    <?php endif; ?>
    <?php
}
add_action("login_form", "ai_webadmin_render_unlock_login_fields", 15);

function ai_webadmin_validate_unlock_factors($user, $username, $password) {
    if (is_wp_error($user) || !($user instanceof WP_User)) {
        return $user;
    }
    $settings = ai_webadmin_get_settings();
    $hasUnlockFactor =
        !empty($settings["enable_passcode_unlock"]) ||
        !empty($settings["require_hardware_key_unlock"]) ||
        !empty($settings["require_wallet_signature_unlock"]);
    $isAdmin = in_array("administrator", (array)$user->roles, true);

    if ($isAdmin && !empty($settings["require_admin_unlock_factor"]) && !$hasUnlockFactor) {
        return new WP_Error(
            "ai_webadmin_admin_unlock_factor_required",
            "Administrator login requires at least one unlock factor (passcode, hardware key/passkey, or wallet signature)."
        );
    }

    if (!$hasUnlockFactor) {
        return $user;
    }

    if (!empty($settings["enable_passcode_unlock"])) {
        $passcodeHash = (string)($settings["unlock_passcode_hash"] ?? "");
        if ($passcodeHash === "") {
            return new WP_Error("ai_webadmin_passcode_missing", "Passcode unlock is enabled but no passcode is configured.");
        }
        $submittedPasscode = isset($_POST["ai_webadmin_passcode"]) ? (string)wp_unslash($_POST["ai_webadmin_passcode"]) : "";
        if ($submittedPasscode === "" || !wp_check_password($submittedPasscode, $passcodeHash)) {
            return new WP_Error("ai_webadmin_passcode_invalid", "Invalid unlock passcode.");
        }
    }

    if (!empty($settings["require_hardware_key_unlock"])) {
        $provider = ai_webadmin_detect_hardware_key_provider();
        if ($provider === null) {
            return new WP_Error("ai_webadmin_hardware_key_provider_missing", "Hardware key unlock requires a WebAuthn/passkey plugin.");
        }
        $verified = apply_filters("ai_webadmin_hardware_key_verified", null, $user, $provider);
        if ($verified !== true) {
            return new WP_Error("ai_webadmin_hardware_key_not_verified", "Hardware key verification was not confirmed.");
        }
    }

    if (!empty($settings["require_wallet_signature_unlock"])) {
        $address = isset($_POST["ai_webadmin_wallet_address"]) ? trim((string)wp_unslash($_POST["ai_webadmin_wallet_address"])) : "";
        $signature = isset($_POST["ai_webadmin_wallet_signature"]) ? trim((string)wp_unslash($_POST["ai_webadmin_wallet_signature"])) : "";
        $message = isset($_POST["ai_webadmin_wallet_message"]) ? (string)wp_unslash($_POST["ai_webadmin_wallet_message"]) : "";
        $nonce = isset($_POST["ai_webadmin_wallet_nonce"]) ? (string)wp_unslash($_POST["ai_webadmin_wallet_nonce"]) : "";
        if ($address === "" || $signature === "" || $message === "" || $nonce === "") {
            return new WP_Error("ai_webadmin_wallet_missing_fields", "Wallet unlock requires address + signature.");
        }
        $walletResult = ai_webadmin_wallet_verify_with_worker($settings, $user, $address, $signature, $message, $nonce);
        if (is_wp_error($walletResult)) {
            return $walletResult;
        }
    }

    return $user;
}
add_filter("authenticate", "ai_webadmin_validate_unlock_factors", 55, 3);

add_action("init", "ai_webadmin_block_xmlrpc_request", 0);
add_action("admin_init", "ai_webadmin_run_hardening_pass", 5);
add_action("user_register", "ai_webadmin_set_safe_display_name", 20, 1);
add_action("profile_update", "ai_webadmin_set_safe_display_name", 20, 1);
add_filter("pre_update_option_active_plugins", "ai_webadmin_filter_blocked_active_plugins", 10, 2);
add_filter("pre_update_site_option_active_sitewide_plugins", "ai_webadmin_filter_blocked_network_plugins", 10, 2);
add_filter("authenticate", "ai_webadmin_login_rate_limit_pre_auth", 15, 3);
add_filter("authenticate", "ai_webadmin_enforce_admin_sso_login", 40, 3);
add_filter("pre_wp_mail", "ai_webadmin_pre_wp_mail_filter", 10, 2);
add_action("wp_login_failed", "ai_webadmin_login_failed", 10, 2);
add_action("wp_login", "ai_webadmin_login_success", 10, 2);

function ai_webadmin_admin_notice() {
    if (!current_user_can("manage_options")) {
        return;
    }
    $settings = ai_webadmin_get_settings();
    $missingActivation = ai_webadmin_missing_activation_requirements($settings);
    if (!empty($missingActivation)) {
        $list = implode(" | ", array_map("esc_html", $missingActivation));
        $guide = esc_url("https://app.cardetailingreno.com/guides/fine-token/");
        echo '<div class="notice notice-warning"><p><strong>AI WebAdmin activation lock:</strong> Plugin features stay disabled until all required items are complete: ' . $list . '. <a href="' . $guide . '" target="_blank" rel="noopener noreferrer">Open step-by-step token guide</a>.</p></div>';
    }
    if (!empty($settings["enable_security_hardening"]) && !empty($settings["enforce_admin_sso"])) {
        echo '<div class="notice notice-info"><p><strong>AI WebAdmin:</strong> Administrator SSO enforcement is active. Non-admin users can still sign in with username/password.</p></div>';
    }
    if (!empty($settings["require_hardware_key_unlock"]) && ai_webadmin_detect_hardware_key_provider() === null) {
        echo '<div class="notice notice-warning"><p><strong>AI WebAdmin:</strong> Hardware key unlock is enabled but no WebAuthn/passkey plugin was detected.</p></div>';
    }
    if (!empty($settings["require_wallet_signature_unlock"]) && empty($settings["onboarding_session_id"])) {
        echo '<div class="notice notice-warning"><p><strong>AI WebAdmin:</strong> Wallet unlock requires an Onboarding Session ID so Worker verification can run.</p></div>';
    }
    if (!empty($settings["require_admin_unlock_factor"]) && !ai_webadmin_unlock_enabled($settings)) {
        echo '<div class="notice notice-error"><p><strong>AI WebAdmin:</strong> Administrator protection requires at least one unlock factor. Enable passcode, hardware key/passkey, or wallet signature in Settings.</p></div>';
    }
    $recentBlocked = get_option("ai_webadmin_blocked_plugins_last", []);
    if (is_array($recentBlocked) && !empty($recentBlocked)) {
        $list = implode(", ", array_map("esc_html", $recentBlocked));
        echo '<div class="notice notice-warning"><p><strong>AI WebAdmin:</strong> Blocked risky plugin(s) were disabled: ' . $list . '.</p></div>';
        delete_option("ai_webadmin_blocked_plugins_last");
    }
    if (!empty($settings["enable_security_hardening"]) && !empty($settings["apply_htaccess_hardening"])) {
        $path = trailingslashit(ABSPATH) . ".htaccess";
        if (!file_exists($path) || !is_writable($path)) {
            echo '<div class="notice notice-warning"><p><strong>AI WebAdmin:</strong> `.htaccess` hardening is enabled but the file is missing or not writable.</p></div>';
        }
    }
    $removedMigration = get_option("ai_webadmin_removed_migration_plugins_last", []);
    if (is_array($removedMigration) && !empty($removedMigration)) {
        $list = implode(", ", array_map("esc_html", $removedMigration));
        echo '<div class="notice notice-warning"><p><strong>AI WebAdmin:</strong> Removed migration/replication plugin(s): ' . $list . '.</p></div>';
        delete_option("ai_webadmin_removed_migration_plugins_last");
    }
    $removedSmtp = get_option("ai_webadmin_removed_smtp_plugins_last", []);
    if (is_array($removedSmtp) && !empty($removedSmtp)) {
        $list = implode(", ", array_map("esc_html", $removedSmtp));
        echo '<div class="notice notice-warning"><p><strong>AI WebAdmin:</strong> Removed SMTP/email plugin(s): ' . $list . '.</p></div>';
        delete_option("ai_webadmin_removed_smtp_plugins_last");
    }
    $staticExportFailure = get_option("ai_webadmin_static_export_failure_last", []);
    if (is_array($staticExportFailure) && !empty($staticExportFailure["detected"])) {
        $removed = isset($staticExportFailure["removed"]) && is_array($staticExportFailure["removed"]) ? $staticExportFailure["removed"] : [];
        $msg = '<strong>AI WebAdmin:</strong> Static export memory failure detected';
        if (!empty($staticExportFailure["error_source"])) {
            $msg .= ' (' . esc_html((string)$staticExportFailure["error_source"]) . ')';
        }
        if (!empty($staticExportFailure["error_message"])) {
            $msg .= ': ' . esc_html((string)$staticExportFailure["error_message"]);
        } else {
            $msg .= '.';
        }
        if (!empty($removed)) {
            $msg .= ' Removed plugin(s): ' . esc_html(implode(", ", $removed)) . '.';
        }
        echo '<div class="notice notice-warning"><p>' . $msg . '</p></div>';
        delete_option("ai_webadmin_static_export_failure_last");
    }
    $removedInactive = get_option("ai_webadmin_removed_inactive_plugins_last", []);
    if (is_array($removedInactive) && !empty($removedInactive["deleted"]) && is_array($removedInactive["deleted"])) {
        $list = implode(", ", array_map("esc_html", $removedInactive["deleted"]));
        $candidateCount = max(0, (int)($removedInactive["candidate_count"] ?? 0));
        $protectedCount = max(0, (int)($removedInactive["protected_count"] ?? 0));
        echo '<div class="notice notice-info"><p><strong>AI WebAdmin:</strong> Removed inactive plugin(s): ' . $list . '. Candidates reviewed: ' . esc_html((string)$candidateCount) . ', protected skipped: ' . esc_html((string)$protectedCount) . '.</p></div>';
        delete_option("ai_webadmin_removed_inactive_plugins_last");
    }
    $removedInactiveThemes = get_option("ai_webadmin_removed_inactive_themes_last", []);
    if (is_array($removedInactiveThemes) && !empty($removedInactiveThemes["deleted"]) && is_array($removedInactiveThemes["deleted"])) {
        $list = implode(", ", array_map("esc_html", $removedInactiveThemes["deleted"]));
        $candidateCount = max(0, (int)($removedInactiveThemes["candidate_count"] ?? 0));
        $protectedCount = max(0, (int)($removedInactiveThemes["protected_count"] ?? 0));
        echo '<div class="notice notice-info"><p><strong>AI WebAdmin:</strong> Removed inactive theme(s): ' . $list . '. Candidates reviewed: ' . esc_html((string)$candidateCount) . ', protected skipped: ' . esc_html((string)$protectedCount) . '.</p></div>';
        delete_option("ai_webadmin_removed_inactive_themes_last");
    }
    $editorEmailSync = get_option("ai_webadmin_editor_email_sync_last", []);
    if (is_array($editorEmailSync) && !empty($editorEmailSync["ran_at"])) {
        $changed = max(0, (int)($editorEmailSync["changed_count"] ?? 0));
        $candidates = max(0, (int)($editorEmailSync["candidate_count"] ?? 0));
        $failed = max(0, (int)($editorEmailSync["failed_count"] ?? 0));
        if ($candidates > 0 || $changed > 0 || $failed > 0) {
            $klass = ($failed > 0) ? "notice-warning" : "notice-info";
            echo '<div class="notice ' . esc_attr($klass) . '"><p><strong>AI WebAdmin:</strong> Editor email normalization reviewed ' .
                esc_html((string)$candidates) . ' candidate account(s), changed ' .
                esc_html((string)$changed) . ', failed ' . esc_html((string)$failed) . '.</p></div>';
        }
        delete_option("ai_webadmin_editor_email_sync_last");
    }
    $licenseCleanup = get_option("ai_webadmin_license_hygiene_last", []);
    if (is_array($licenseCleanup) && !empty($licenseCleanup["ran_at"])) {
        $reviewed = max(0, (int)($licenseCleanup["reviewed_count"] ?? 0));
        $flagged = max(0, (int)($licenseCleanup["flagged_count"] ?? 0));
        $deleted = max(0, (int)($licenseCleanup["deleted_count"] ?? 0));
        $klass = ($deleted > 0 || $flagged > 0) ? "notice-warning" : "notice-success";
        echo '<div class="notice ' . esc_attr($klass) . '"><p><strong>AI WebAdmin:</strong> License hygiene reviewed ' .
            esc_html((string)$reviewed) . ' record(s), flagged ' . esc_html((string)$flagged) .
            ', deleted ' . esc_html((string)$deleted) . '.</p></div>';
        delete_option("ai_webadmin_license_hygiene_last");
    }
    $commentBacklog = get_option("ai_webadmin_comment_backlog_last", []);
    if (is_array($commentBacklog) && !empty($commentBacklog["ran_at"])) {
        $processed = max(0, (int)($commentBacklog["processed"] ?? 0));
        $trash = max(0, (int)($commentBacklog["trash"] ?? 0));
        $spam = max(0, (int)($commentBacklog["spam"] ?? 0));
        $hold = max(0, (int)($commentBacklog["hold"] ?? 0));
        if ($processed > 0) {
            echo '<div class="notice notice-info"><p><strong>AI WebAdmin:</strong> Comment backlog run processed ' .
                esc_html((string)$processed) . ' (trash ' . esc_html((string)$trash) . ', spam ' . esc_html((string)$spam) .
                ', hold ' . esc_html((string)$hold) . ').</p></div>';
        }
        delete_option("ai_webadmin_comment_backlog_last");
    }
    $cleanup = get_option("ai_webadmin_inactive_user_cleanup_last", []);
    if (is_array($cleanup) && !empty($cleanup["deleted_count"])) {
        $count = (int)$cleanup["deleted_count"];
        echo '<div class="notice notice-info"><p><strong>AI WebAdmin:</strong> Inactive user cleanup removed ' . esc_html((string)$count) . ' account(s) on the last run.</p></div>';
    }
    if (!empty($settings["github_backup_last_snapshot_at"])) {
        $status = (string)($settings["github_backup_last_status"] ?? "unknown");
        $msg = (string)($settings["github_backup_last_message"] ?? "");
        $when = gmdate("Y-m-d H:i:s", (int)$settings["github_backup_last_snapshot_at"]) . " UTC";
        $klass = ($status === "ok") ? "notice-success" : "notice-warning";
        echo '<div class="notice ' . esc_attr($klass) . '"><p><strong>AI WebAdmin:</strong> Last Worker backup snapshot at ' . esc_html($when) . ' (' . esc_html($status) . '). ' . esc_html($msg) . '</p></div>';
    }
}
add_action("admin_notices", "ai_webadmin_admin_notice");

function ai_webadmin_default_menu_icon_data_uri() {
    $svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20"><path fill="#ff4f1f" d="M11.1 1.2a1 1 0 0 0-2 0v1.4a7.2 7.2 0 0 0-2 .8L6 2.3a1 1 0 1 0-1.4 1.4l1.1 1.1c-.3.6-.6 1.3-.7 2H3.5a1 1 0 0 0 0 2H5c.1.7.4 1.4.7 2L4.6 12a1 1 0 1 0 1.4 1.4l1.1-1.1c.6.3 1.3.6 2 .8v1.4a1 1 0 0 0 2 0V13c.7-.1 1.4-.4 2-.8l1.1 1.1a1 1 0 0 0 1.4-1.4l-1.1-1.1c.3-.6.6-1.3.7-2h1.5a1 1 0 0 0 0-2H15c-.1-.7-.4-1.4-.7-2l1.1-1.1A1 1 0 1 0 14 2.3l-1.1 1.1a7.2 7.2 0 0 0-2-.8V1.2z"/><path fill="#ffffff" d="M6.7 12.8a.9.9 0 0 1 0-1.3l5.3-5.3a.9.9 0 1 1 1.3 1.3L8 12.8a.9.9 0 0 1-1.3 0z"/><path fill="#ffffff" d="M8.3 6.5c.5 0 .9.4.9.9v4.8a.9.9 0 1 1-1.8 0V7.4c0-.5.4-.9.9-.9z"/><path fill="#ffffff" d="M12.1 7.6c.5 0 .9.4.9.9v3.7a.9.9 0 1 1-1.8 0V8.5c0-.5.4-.9.9-.9z"/></svg>';
    return "data:image/svg+xml;base64," . base64_encode($svg);
}

function ai_webadmin_admin_menu_icon_url($settings = null) {
    if (!is_array($settings)) {
        $settings = ai_webadmin_get_settings();
    }
    $url = esc_url_raw((string)($settings["branding_admin_menu_icon_url"] ?? ""));
    if ($url !== "") {
        return $url;
    }
    $faviconUrl = esc_url_raw((string)($settings["branding_favicon_url"] ?? ""));
    if ($faviconUrl !== "") {
        return $faviconUrl;
    }
    return ai_webadmin_default_menu_icon_data_uri();
}

function ai_webadmin_tolldns_points_summary() {
    if (!ai_webadmin_is_tolldns_active()) {
        return null;
    }
    if (function_exists("tolldns_points_summary")) {
        $summary = tolldns_points_summary();
        if (is_array($summary)) {
            return $summary;
        }
    }
    $settings = get_option("tolldns_settings", []);
    if (is_array($settings)) {
        return [
            "points_total" => max(0, (int)($settings["points_total"] ?? 0)),
            "last_check_at" => max(0, (int)($settings["last_check_at"] ?? 0)),
            "last_check_status" => sanitize_text_field((string)($settings["last_check_status"] ?? "not_checked")),
            "last_check_message" => sanitize_text_field((string)($settings["last_check_message"] ?? "")),
            "last_check_delta" => (int)($settings["last_check_delta"] ?? 0),
        ];
    }
    return null;
}

function ai_webadmin_redeem_tolldns_points($settings, $upgradeType) {
    $type = sanitize_key((string)$upgradeType);
    $cost = ($type === "cache")
        ? max(1, (int)($settings["tolldns_cache_upgrade_points_cost"] ?? 500))
        : max(1, (int)($settings["tolldns_vps_upgrade_points_cost"] ?? 800));
    if (!ai_webadmin_is_tolldns_active()) {
        return ["ok" => false, "error" => "TollDNS plugin is not active."];
    }
    if (!function_exists("tolldns_add_points_entry") || !function_exists("tolldns_points_summary")) {
        return ["ok" => false, "error" => "TollDNS points functions are unavailable."];
    }
    $summary = tolldns_points_summary();
    $total = is_array($summary) ? max(0, (int)($summary["points_total"] ?? 0)) : 0;
    if ($total < $cost) {
        return ["ok" => false, "error" => "Not enough TollDNS points. Needed: {$cost}, available: {$total}."];
    }
    $eventType = ($type === "cache") ? "ai_webadmin_cache_upgrade_redeem" : "ai_webadmin_vps_upgrade_redeem";
    $meta = [
        "upgrade_type" => $type,
        "points_cost" => $cost,
        "site_url" => home_url("/"),
        "requested_at" => gmdate("c"),
    ];
    tolldns_add_points_entry($eventType, -1 * $cost, $meta);
    do_action("ai_webadmin_tolldns_upgrade_redeemed", $type, $cost, $meta);
    return ["ok" => true, "cost" => $cost];
}

function ai_webadmin_output_custom_favicon() {
    $settings = ai_webadmin_get_settings();
    if (empty($settings["branding_inject_favicon"])) {
        return;
    }
    $faviconUrl = esc_url((string)($settings["branding_favicon_url"] ?? ""));
    if ($faviconUrl === "") {
        return;
    }
    echo '<link rel="icon" href="' . esc_url($faviconUrl) . "\" />\n";
    echo '<link rel="shortcut icon" href="' . esc_url($faviconUrl) . "\" />\n";
    echo '<link rel="apple-touch-icon" href="' . esc_url($faviconUrl) . "\" />\n";
}
add_action("wp_head", "ai_webadmin_output_custom_favicon", 3);
add_action("admin_head", "ai_webadmin_output_custom_favicon", 3);

function ai_webadmin_admin_menu() {
    $settings = ai_webadmin_get_settings();
    add_menu_page(
        "AI WebAdmin",
        "AI WebAdmin",
        "manage_options",
        "ai-webadmin",
        "ai_webadmin_render_settings_page",
        ai_webadmin_admin_menu_icon_url($settings),
        58
    );
    add_options_page(
        "AI WebAdmin",
        "AI WebAdmin",
        "manage_options",
        "ai-webadmin",
        "ai_webadmin_render_settings_page"
    );
}
add_action("admin_menu", "ai_webadmin_admin_menu");

function ai_webadmin_settings_page_url() {
    return admin_url("admin.php?page=ai-webadmin");
}

function ai_webadmin_auto_update_link_html() {
    if (!current_user_can("update_plugins")) {
        return "";
    }
    if (!function_exists("wp_is_auto_update_enabled_for_type") || !wp_is_auto_update_enabled_for_type("plugin")) {
        return "";
    }
    if (function_exists("wp_is_auto_update_forced_for_item")) {
        $forced = wp_is_auto_update_forced_for_item("plugin", (object)[
            "plugin" => AI_WEBADMIN_PLUGIN_BASENAME,
            "slug" => AI_WEBADMIN_PLUGIN_SLUG,
        ]);
        if ($forced === true) {
            return esc_html__("Auto-updates enabled by policy", "ai-webadmin");
        }
        if ($forced === false) {
            return esc_html__("Auto-updates disabled by policy", "ai-webadmin");
        }
    }

    $enabled = in_array(
        AI_WEBADMIN_PLUGIN_BASENAME,
        (array)get_site_option("auto_update_plugins", []),
        true
    );
    $action = $enabled ? "disable-auto-update" : "enable-auto-update";
    $label = $enabled ? "Disable auto-updates" : "Enable auto-updates";
    $url = add_query_arg([
        "action" => $action,
        "plugin" => AI_WEBADMIN_PLUGIN_BASENAME,
    ], admin_url("plugins.php"));
    return '<a href="' . esc_url(wp_nonce_url($url, "updates")) . '">' . esc_html($label) . "</a>";
}

function ai_webadmin_plugin_action_links($links) {
    if (!current_user_can("manage_options")) {
        return $links;
    }
    array_unshift($links, '<a href="' . esc_url(ai_webadmin_settings_page_url()) . '">Settings</a>');
    $autoUpdate = ai_webadmin_auto_update_link_html();
    if ($autoUpdate !== "") {
        $links[] = $autoUpdate;
    }
    return $links;
}
add_filter("plugin_action_links_" . AI_WEBADMIN_PLUGIN_BASENAME, "ai_webadmin_plugin_action_links");

function ai_webadmin_media_single_action_url($attachmentId) {
    $id = max(0, (int)$attachmentId);
    if ($id <= 0) {
        return "";
    }
    $url = add_query_arg([
        "action" => "ai_webadmin_media_offload_single",
        "attachment_id" => $id,
    ], admin_url("admin-post.php"));
    return wp_nonce_url($url, "ai_webadmin_media_offload_single_" . $id);
}

function ai_webadmin_add_media_row_action($actions, $post, $detached = false) {
    if (!current_user_can("upload_files")) {
        return $actions;
    }
    $attachmentId = ($post instanceof WP_Post) ? (int)$post->ID : 0;
    if ($attachmentId <= 0) {
        return $actions;
    }
    if ((string)get_post_type($attachmentId) !== "attachment") {
        return $actions;
    }
    $mime = strtolower((string)get_post_mime_type($attachmentId));
    if (strpos($mime, "image/") !== 0) {
        return $actions;
    }
    $url = ai_webadmin_media_single_action_url($attachmentId);
    if ($url === "") {
        return $actions;
    }
    $actions["ai_webadmin_media_offload_single"] = '<a href="' . esc_url($url) . '">AI Optimize + Offload to R2</a>';
    return $actions;
}
add_filter("media_row_actions", "ai_webadmin_add_media_row_action", 20, 3);

function ai_webadmin_add_media_attachment_sidebar_action($formFields, $post) {
    if (!current_user_can("upload_files")) {
        return $formFields;
    }
    $attachmentId = ($post instanceof WP_Post) ? (int)$post->ID : 0;
    if ($attachmentId <= 0) {
        return $formFields;
    }
    $mime = strtolower((string)get_post_mime_type($attachmentId));
    if (strpos($mime, "image/") !== 0) {
        return $formFields;
    }
    $url = ai_webadmin_media_single_action_url($attachmentId);
    if ($url === "") {
        return $formFields;
    }
    $formFields["ai_webadmin_media_offload_single"] = [
        "label" => "AI WebAdmin",
        "input" => "html",
        "html" => '<a class="button button-secondary" href="' . esc_url($url) . '">AI Optimize + Offload to R2</a>' .
            '<p class="help">Generates title/alt/caption/description with AI, then uploads to R2 and maps URL.</p>',
    ];
    return $formFields;
}
add_filter("attachment_fields_to_edit", "ai_webadmin_add_media_attachment_sidebar_action", 20, 2);

function ai_webadmin_register_media_bulk_action($bulkActions) {
    if (!current_user_can("upload_files")) {
        return $bulkActions;
    }
    $bulkActions["ai_webadmin_media_optimize_offload"] = "AI Optimize + Offload to R2";
    return $bulkActions;
}
add_filter("bulk_actions-upload", "ai_webadmin_register_media_bulk_action");

function ai_webadmin_handle_media_bulk_action($redirectTo, $action, $postIds) {
    if ($action !== "ai_webadmin_media_optimize_offload") {
        return $redirectTo;
    }
    if (!current_user_can("upload_files")) {
        return add_query_arg([
            "ai_webadmin_media_action" => "bulk",
            "ai_webadmin_media_status" => "error",
            "ai_webadmin_media_message" => "You do not have permission to run media offload actions.",
        ], $redirectTo);
    }
    $processed = 0;
    $failed = 0;
    $checked = 0;
    $ids = is_array($postIds) ? array_slice(array_map("intval", $postIds), 0, 60) : [];
    foreach ($ids as $id) {
        if ($id <= 0 || (string)get_post_type($id) !== "attachment") {
            continue;
        }
        $mime = strtolower((string)get_post_mime_type($id));
        if (strpos($mime, "image/") !== 0) {
            continue;
        }
        $checked += 1;
        $result = ai_webadmin_run_media_r2_offload_for_attachment($id);
        if (!empty($result["ok"])) {
            $processed += 1;
        } else {
            $failed += 1;
        }
    }
    $status = ($failed > 0 && $processed > 0) ? "partial" : (($failed > 0) ? "error" : "ok");
    $message = "Bulk media run: {$processed} processed";
    if ($failed > 0) {
        $message .= ", {$failed} failed";
    }
    if ($checked === 0) {
        $status = "error";
        $message = "No image attachments selected for AI media offload.";
    } else {
        $message .= " out of {$checked} selected image(s).";
    }
    return add_query_arg([
        "ai_webadmin_media_action" => "bulk",
        "ai_webadmin_media_status" => $status,
        "ai_webadmin_media_message" => $message,
    ], $redirectTo);
}
add_filter("handle_bulk_actions-upload", "ai_webadmin_handle_media_bulk_action", 10, 3);

function ai_webadmin_handle_media_single_action() {
    if (!current_user_can("upload_files")) {
        wp_die("Insufficient permissions.", 403);
    }
    $attachmentId = isset($_GET["attachment_id"]) ? (int)$_GET["attachment_id"] : 0;
    check_admin_referer("ai_webadmin_media_offload_single_" . $attachmentId);
    $result = ai_webadmin_run_media_r2_offload_for_attachment($attachmentId);
    $status = !empty($result["ok"]) ? "ok" : "error";
    $message = !empty($result["ok"])
        ? ("Image processed and offloaded to R2 (attachment #" . (int)$attachmentId . ").")
        : ("Image offload failed: " . sanitize_text_field((string)($result["error"] ?? "unknown_error")));
    $redirectTo = wp_get_referer();
    if (!is_string($redirectTo) || $redirectTo === "") {
        $redirectTo = admin_url("upload.php");
    }
    $redirectTo = add_query_arg([
        "ai_webadmin_media_action" => "single",
        "ai_webadmin_media_status" => $status,
        "ai_webadmin_media_message" => $message,
    ], $redirectTo);
    wp_safe_redirect($redirectTo);
    exit;
}
add_action("admin_post_ai_webadmin_media_offload_single", "ai_webadmin_handle_media_single_action");

function ai_webadmin_render_media_action_notice() {
    if (!is_admin() || !current_user_can("upload_files")) {
        return;
    }
    $action = isset($_GET["ai_webadmin_media_action"]) ? sanitize_key((string)wp_unslash($_GET["ai_webadmin_media_action"])) : "";
    $status = isset($_GET["ai_webadmin_media_status"]) ? sanitize_key((string)wp_unslash($_GET["ai_webadmin_media_status"])) : "";
    if ($action === "" || $status === "") {
        return;
    }
    $rawMessage = isset($_GET["ai_webadmin_media_message"]) ? (string)wp_unslash($_GET["ai_webadmin_media_message"]) : "";
    $message = sanitize_text_field($rawMessage);
    if ($message === "") {
        $message = "AI media action completed.";
    }
    $class = "notice notice-success";
    if ($status === "error") {
        $class = "notice notice-error";
    } elseif ($status === "partial") {
        $class = "notice notice-warning";
    }
    echo '<div class="' . esc_attr($class) . ' is-dismissible"><p>' . esc_html($message) . "</p></div>";
}
add_action("admin_notices", "ai_webadmin_render_media_action_notice");

function ai_webadmin_get_remote_update_metadata($forceRefresh = false) {
    if (!$forceRefresh) {
        $cached = get_site_transient(AI_WEBADMIN_UPDATE_META_CACHE_KEY);
        if (is_array($cached) && !empty($cached["version"]) && !empty($cached["download_url"])) {
            return $cached;
        }
    }

    $response = wp_remote_get(AI_WEBADMIN_UPDATE_META_URL, [
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
        "name" => sanitize_text_field((string)($decoded["name"] ?? "AI WebAdmin (Cloudflare Worker)")),
        "slug" => sanitize_key((string)($decoded["slug"] ?? AI_WEBADMIN_PLUGIN_SLUG)),
        "version" => sanitize_text_field((string)($decoded["version"] ?? "")),
        "requires" => sanitize_text_field((string)($decoded["requires"] ?? "")),
        "tested" => sanitize_text_field((string)($decoded["tested"] ?? "")),
        "requires_php" => sanitize_text_field((string)($decoded["requires_php"] ?? "")),
        "homepage" => esc_url_raw((string)($decoded["homepage"] ?? "https://app.cardetailingreno.com/plugin-free/")),
        "download_url" => esc_url_raw((string)($decoded["download_url"] ?? "")),
        "description" => wp_kses_post((string)($decoded["description"] ?? "")),
        "changelog" => wp_kses_post((string)($decoded["changelog"] ?? "")),
        "last_updated" => sanitize_text_field((string)($decoded["last_updated"] ?? "")),
    ];
    if ($meta["version"] === "" || $meta["download_url"] === "") {
        return null;
    }

    set_site_transient(AI_WEBADMIN_UPDATE_META_CACHE_KEY, $meta, HOUR_IN_SECONDS);
    return $meta;
}

function ai_webadmin_build_update_payload($meta, $version) {
    return (object)[
        "id" => AI_WEBADMIN_UPDATE_META_URL,
        "slug" => AI_WEBADMIN_PLUGIN_SLUG,
        "plugin" => AI_WEBADMIN_PLUGIN_BASENAME,
        "new_version" => (string)$version,
        "url" => (string)($meta["homepage"] ?? "https://app.cardetailingreno.com/plugin-free/"),
        "package" => (string)($meta["download_url"] ?? ""),
        "tested" => (string)($meta["tested"] ?? ""),
        "requires" => (string)($meta["requires"] ?? ""),
        "requires_php" => (string)($meta["requires_php"] ?? ""),
    ];
}

function ai_webadmin_inject_update_plugins_transient($transient) {
    if (!is_object($transient)) {
        $transient = new stdClass();
    }
    if (!isset($transient->checked) || !is_array($transient->checked)) {
        return $transient;
    }

    $meta = ai_webadmin_get_remote_update_metadata(false);
    if (!is_array($meta)) {
        return $transient;
    }
    $currentVersion = (string)($transient->checked[AI_WEBADMIN_PLUGIN_BASENAME] ?? AI_WEBADMIN_VERSION);
    $item = ai_webadmin_build_update_payload($meta, (string)$meta["version"]);

    if (version_compare((string)$meta["version"], $currentVersion, ">")) {
        if (!isset($transient->response) || !is_array($transient->response)) {
            $transient->response = [];
        }
        $transient->response[AI_WEBADMIN_PLUGIN_BASENAME] = $item;
        if (isset($transient->no_update[AI_WEBADMIN_PLUGIN_BASENAME])) {
            unset($transient->no_update[AI_WEBADMIN_PLUGIN_BASENAME]);
        }
    } else {
        if (!isset($transient->no_update) || !is_array($transient->no_update)) {
            $transient->no_update = [];
        }
        $transient->no_update[AI_WEBADMIN_PLUGIN_BASENAME] = $item;
    }

    return $transient;
}
add_filter("pre_set_site_transient_update_plugins", "ai_webadmin_inject_update_plugins_transient");

function ai_webadmin_plugins_api_info($result, $action, $args) {
    if ($action !== "plugin_information" || !isset($args->slug) || (string)$args->slug !== AI_WEBADMIN_PLUGIN_SLUG) {
        return $result;
    }
    $meta = ai_webadmin_get_remote_update_metadata(false);
    if (!is_array($meta)) {
        return $result;
    }

    $description = (string)($meta["description"] ?? "");
    if ($description === "") {
        $description = "Connects WordPress to AI WebAdmin workers for moderation, hardening, and automation workflows.";
    }
    $changelog = (string)($meta["changelog"] ?? "");
    if ($changelog === "") {
        $changelog = "Current version: " . esc_html((string)$meta["version"]);
    }

    return (object)[
        "name" => (string)($meta["name"] ?? "AI WebAdmin (Cloudflare Worker)"),
        "slug" => AI_WEBADMIN_PLUGIN_SLUG,
        "version" => (string)$meta["version"],
        "author" => "<a href='https://app.cardetailingreno.com/'>Sitebuilder</a>",
        "homepage" => (string)($meta["homepage"] ?? "https://app.cardetailingreno.com/plugin-free/"),
        "requires" => (string)($meta["requires"] ?? ""),
        "tested" => (string)($meta["tested"] ?? ""),
        "requires_php" => (string)($meta["requires_php"] ?? ""),
        "last_updated" => (string)($meta["last_updated"] ?? ""),
        "sections" => [
            "description" => $description,
            "changelog" => $changelog,
        ],
        "download_link" => (string)$meta["download_url"],
    ];
}
add_filter("plugins_api", "ai_webadmin_plugins_api_info", 10, 3);

function ai_webadmin_settings_tabs() {
    return [
        "general" => "General",
        "integrations" => "Integration",
        "audit" => "Audit & Cache",
        "seo" => "SEO",
        "logs" => "Logs",
        "sandbox" => "Sandbox & Secrets",
        "security" => "Security",
        "automation" => "Automation",
        "premium" => "Premium",
        "agent" => "AI Agent Chat",
    ];
}

function ai_webadmin_get_active_settings_tab() {
    $tabs = ai_webadmin_settings_tabs();
    $active = isset($_GET["tab"]) ? sanitize_key((string)wp_unslash($_GET["tab"])) : "general";
    if (!isset($tabs[$active])) {
        $active = "general";
    }
    return $active;
}

function ai_webadmin_tab_row_attrs($activeTab, $tabSlugs) {
    $slugs = [];
    foreach ((array)$tabSlugs as $slug) {
        $slug = sanitize_key((string)$slug);
        if ($slug !== "") {
            $slugs[] = $slug;
        }
    }
    if (empty($slugs)) {
        $slugs = ["general"];
    }
    $classes = ["ai-webadmin-setting-row"];
    foreach ($slugs as $slug) {
        $classes[] = "ai-webadmin-tab-" . $slug;
    }
    $visible = in_array($activeTab, $slugs, true);
    $attrs = ' class="' . esc_attr(implode(" ", $classes)) . '"';
    if (!$visible) {
        $attrs .= ' style="display:none;"';
    }
    return $attrs;
}

function ai_webadmin_benchmark_option_key() {
    return "ai_webadmin_last_benchmark_snapshot";
}

function ai_webadmin_get_last_benchmark_snapshot() {
    $snapshot = get_option(ai_webadmin_benchmark_option_key(), []);
    return is_array($snapshot) ? $snapshot : [];
}

function ai_webadmin_capture_benchmark_snapshot() {
    $metrics = ai_webadmin_collect_audit_metrics();
    $start = microtime(true);
    $response = wp_remote_get(home_url("/"), [
        "timeout" => 12,
        "redirection" => 3,
    ]);
    $durationMs = (int)round((microtime(true) - $start) * 1000);
    $statusCode = is_wp_error($response) ? 0 : (int)wp_remote_retrieve_response_code($response);
    $bodyBytes = is_wp_error($response) ? 0 : strlen((string)wp_remote_retrieve_body($response));
    $error = is_wp_error($response) ? sanitize_text_field($response->get_error_message()) : "";

    $snapshot = [
        "captured_at" => time(),
        "home_fetch_ms" => max(0, $durationMs),
        "home_status_code" => max(0, $statusCode),
        "home_body_bytes" => max(0, (int)$bodyBytes),
        "metrics" => $metrics,
        "error" => $error,
    ];
    update_option(ai_webadmin_benchmark_option_key(), $snapshot, false);
    return $snapshot;
}

function ai_webadmin_format_utc_timestamp($ts) {
    $stamp = (int)$ts;
    if ($stamp <= 0) {
        return "Not yet";
    }
    return gmdate("Y-m-d H:i:s", $stamp) . " UTC";
}

function ai_webadmin_build_settings_runtime_log($settings, $lastBenchmark = []) {
    $lines = [];
    $push = function ($title, $ts, $details = "") use (&$lines) {
        $stamp = ai_webadmin_format_utc_timestamp((int)$ts);
        $line = "[" . $stamp . "] " . sanitize_text_field((string)$title);
        $detailText = sanitize_text_field((string)$details);
        if ($detailText !== "") {
            $line .= " - " . $detailText;
        }
        $lines[] = $line;
    };

    $push("Audit Sync", (int)wp_next_scheduled("ai_webadmin_sync_audit_metrics_event"), "next scheduled run");
    $push("Hardening Pass", (int)wp_next_scheduled("ai_webadmin_daily_hardening_event"), "next scheduled run");
    $push("Sandbox Preflight", (int)($settings["sandbox_last_run_at"] ?? 0), (string)($settings["sandbox_last_message"] ?? ""));
    $push("Media Offload", (int)($settings["media_offload_last_run_at"] ?? 0), (string)($settings["media_offload_last_message"] ?? ""));
    $push("GitHub Backup", (int)($settings["github_backup_last_snapshot_at"] ?? 0), (string)($settings["github_backup_last_status"] ?? ""));
    $push("Lead Forward Verify", (int)($settings["lead_forward_verification_last_check_at"] ?? 0), (string)($settings["lead_forward_verification_status"] ?? ""));
    $push("SEO Profile", (int)($settings["seo_last_updated_at"] ?? 0), "last updated");
    $push("Page Cache Clear", (int)($settings["page_cache_last_cleared_at"] ?? 0), (string)($settings["page_cache_last_clear_reason"] ?? ""));
    $push("Autoload Cleanup", (int)($settings["autoload_last_cleanup_at"] ?? 0), (string)($settings["autoload_last_cleanup_summary"] ?? ""));
    if (is_array($lastBenchmark) && !empty($lastBenchmark["captured_at"])) {
        $benchmarkDetails = "home_fetch_ms=" . (int)($lastBenchmark["home_fetch_ms"] ?? 0) .
            ", home_status=" . (int)($lastBenchmark["home_status_code"] ?? 0) .
            ", bytes=" . (int)($lastBenchmark["home_body_bytes"] ?? 0);
        $push("Benchmark", (int)$lastBenchmark["captured_at"], $benchmarkDetails);
    }

    $lines = array_filter(array_map("trim", $lines));
    if (empty($lines)) {
        return "No runtime log entries available yet.";
    }
    return implode("\n", array_slice($lines, 0, 40));
}

function ai_webadmin_page_cache_base_dir() {
    return trailingslashit(WP_CONTENT_DIR) . "cache/ai-webadmin-page-cache";
}

function ai_webadmin_page_cache_ttl_seconds($settings = null) {
    if (!is_array($settings)) {
        $settings = ai_webadmin_get_settings();
    }
    return max(60, min(86400, (int)($settings["page_cache_ttl_seconds"] ?? 600)));
}

function ai_webadmin_page_cache_enabled($settings = null) {
    if (!is_array($settings)) {
        $settings = ai_webadmin_get_settings();
    }
    return !empty($settings["enable_builtin_page_cache"]);
}

function ai_webadmin_page_cache_excluded_prefixes($settings = null) {
    if (!is_array($settings)) {
        $settings = ai_webadmin_get_settings();
    }
    $raw = (string)($settings["page_cache_excluded_paths"] ?? "");
    $lines = preg_split('/\r\n|\r|\n/', $raw);
    if (!is_array($lines)) {
        $lines = [];
    }
    $prefixes = [];
    foreach ($lines as $line) {
        $path = trim((string)$line);
        if ($path === "") {
            continue;
        }
        if ($path[0] !== "/") {
            $path = "/" . $path;
        }
        $prefixes[] = rtrim($path, "/") . "/";
    }
    return array_slice(array_values(array_unique($prefixes)), 0, 60);
}

function ai_webadmin_page_cache_current_path() {
    $uri = isset($_SERVER["REQUEST_URI"]) ? (string)wp_unslash($_SERVER["REQUEST_URI"]) : "/";
    $path = wp_parse_url($uri, PHP_URL_PATH);
    if (!is_string($path) || $path === "") {
        $path = "/";
    }
    if ($path[0] !== "/") {
        $path = "/" . $path;
    }
    return $path;
}

function ai_webadmin_page_cache_bypass_reason($settings = null) {
    if (!is_array($settings)) {
        $settings = ai_webadmin_get_settings();
    }
    if (!ai_webadmin_page_cache_enabled($settings)) {
        return "disabled";
    }
    if (is_admin() || (defined("REST_REQUEST") && REST_REQUEST)) {
        return "admin_or_rest";
    }
    if ((defined("DOING_AJAX") && DOING_AJAX) || (defined("DOING_CRON") && DOING_CRON)) {
        return "ajax_or_cron";
    }
    $method = isset($_SERVER["REQUEST_METHOD"]) ? strtoupper((string)$_SERVER["REQUEST_METHOD"]) : "GET";
    if ($method !== "GET") {
        return "non_get";
    }
    if (is_user_logged_in()) {
        return "logged_in";
    }
    if (defined("DONOTCACHEPAGE") && DONOTCACHEPAGE) {
        return "donotcachepage";
    }
    $query = isset($_SERVER["QUERY_STRING"]) ? (string)$_SERVER["QUERY_STRING"] : "";
    if (trim($query) !== "") {
        return "query_string";
    }
    $path = ai_webadmin_page_cache_current_path();
    $pathNorm = rtrim($path, "/") . "/";
    foreach (ai_webadmin_page_cache_excluded_prefixes($settings) as $prefix) {
        if ($prefix === "/" || strpos($pathNorm, $prefix) === 0) {
            return "excluded_path";
        }
    }
    if (
        (function_exists("is_feed") && is_feed()) ||
        (function_exists("is_search") && is_search()) ||
        (function_exists("is_preview") && is_preview()) ||
        (function_exists("is_trackback") && is_trackback()) ||
        (function_exists("is_robots") && is_robots()) ||
        (function_exists("is_404") && is_404())
    ) {
        return "dynamic_view";
    }
    if (
        (function_exists("is_cart") && is_cart()) ||
        (function_exists("is_checkout") && is_checkout()) ||
        (function_exists("is_account_page") && is_account_page())
    ) {
        return "woocommerce_session_page";
    }
    $cookieHeader = isset($_SERVER["HTTP_COOKIE"]) ? (string)$_SERVER["HTTP_COOKIE"] : "";
    if ($cookieHeader !== "") {
        if (preg_match('/wordpress_logged_in_|comment_author_|wp-postpass_/i', $cookieHeader)) {
            return "session_cookie";
        }
        if (preg_match('/woocommerce_items_in_cart|woocommerce_cart_hash|wp_woocommerce_session_/i', $cookieHeader)) {
            return "woocommerce_cookie";
        }
    }
    return "";
}

function ai_webadmin_page_cache_file_for_request($settings = null) {
    if (!is_array($settings)) {
        $settings = ai_webadmin_get_settings();
    }
    $host = isset($_SERVER["HTTP_HOST"]) ? strtolower(sanitize_text_field((string)$_SERVER["HTTP_HOST"])) : "default";
    $path = ai_webadmin_page_cache_current_path();
    $key = sha1($host . "|" . $path);
    return trailingslashit(ai_webadmin_page_cache_base_dir()) . $key . ".html";
}

function ai_webadmin_page_cache_send_headers($etag, $mtime, $ttl, $age = 0) {
    if (headers_sent()) {
        return;
    }
    $safeEtag = '"' . trim((string)$etag, '"') . '"';
    $maxAge = max(60, (int)$ttl);
    $safeAge = max(0, (int)$age);
    $staleWhileRevalidate = min(600, max(60, (int)floor($maxAge / 2)));
    $staleIfError = max(3600, $maxAge * 24);
    header("X-Cache-Enabled: AI-WebAdmin-Page-Cache");
    header(
        "Cache-Control: public, max-age=" . $maxAge .
        ", s-maxage=" . $maxAge .
        ", stale-while-revalidate=" . $staleWhileRevalidate .
        ", stale-if-error=" . $staleIfError
    );
    header("ETag: " . $safeEtag);
    header("Last-Modified: " . gmdate("D, d M Y H:i:s", max(0, (int)$mtime)) . " GMT");
    header("Expires: " . gmdate("D, d M Y H:i:s", time() + $maxAge) . " GMT");
    header("Age: " . $safeAge);
    header("X-AI-WebAdmin-Cache: " . ($safeAge > 0 ? "HIT" : "MISS"));
}

function ai_webadmin_page_cache_serve_or_start_buffer() {
    $settings = ai_webadmin_get_settings();
    if (!ai_webadmin_page_cache_enabled($settings)) {
        return;
    }
    $bypass = ai_webadmin_page_cache_bypass_reason($settings);
    if ($bypass !== "") {
        return;
    }

    $cacheFile = ai_webadmin_page_cache_file_for_request($settings);
    $ttl = ai_webadmin_page_cache_ttl_seconds($settings);
    if (is_file($cacheFile)) {
        $mtime = @filemtime($cacheFile);
        $age = time() - (int)$mtime;
        if ($mtime && $age >= 0 && $age <= $ttl) {
            $contents = @file_get_contents($cacheFile);
            if (is_string($contents) && $contents !== "") {
                $etag = md5($contents);
                ai_webadmin_page_cache_send_headers($etag, (int)$mtime, $ttl, (int)$age);
                echo $contents;
                exit;
            }
        }
    }

    if (!isset($GLOBALS["ai_webadmin_page_cache_ctx"]) || !is_array($GLOBALS["ai_webadmin_page_cache_ctx"])) {
        $GLOBALS["ai_webadmin_page_cache_ctx"] = [];
    }
    $GLOBALS["ai_webadmin_page_cache_ctx"] = [
        "enabled" => true,
        "cache_file" => $cacheFile,
        "ttl" => $ttl,
        "start" => microtime(true),
    ];
    ob_start("ai_webadmin_page_cache_capture_html");
}

function ai_webadmin_page_cache_capture_html($html) {
    $ctx = isset($GLOBALS["ai_webadmin_page_cache_ctx"]) && is_array($GLOBALS["ai_webadmin_page_cache_ctx"])
        ? $GLOBALS["ai_webadmin_page_cache_ctx"]
        : [];
    if (empty($ctx["enabled"])) {
        return $html;
    }
    if (!is_string($html) || trim($html) === "") {
        return $html;
    }
    $statusCode = function_exists("http_response_code") ? (int)http_response_code() : 200;
    if ($statusCode >= 300 || $statusCode < 200) {
        return $html;
    }
    if (stripos($html, "<html") === false) {
        return $html;
    }

    $cacheFile = sanitize_text_field((string)($ctx["cache_file"] ?? ""));
    if ($cacheFile === "") {
        return $html;
    }
    $dir = dirname($cacheFile);
    if (!is_dir($dir)) {
        wp_mkdir_p($dir);
    }
    if (is_dir($dir) && is_writable($dir)) {
        @file_put_contents($cacheFile, $html, LOCK_EX);
        $mtime = @filemtime($cacheFile);
        if (!$mtime) {
            $mtime = time();
        }
        $etag = md5($html);
        ai_webadmin_page_cache_send_headers($etag, (int)$mtime, max(60, (int)($ctx["ttl"] ?? 600)), 0);
    }
    return $html;
}

function ai_webadmin_clear_page_cache($reason = "manual") {
    $baseDir = ai_webadmin_page_cache_base_dir();
    $deleted = 0;
    if (is_dir($baseDir)) {
        $it = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($baseDir, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::CHILD_FIRST
        );
        foreach ($it as $file) {
            if ($file->isFile()) {
                if (@unlink($file->getPathname())) {
                    $deleted += 1;
                }
            } elseif ($file->isDir()) {
                @rmdir($file->getPathname());
            }
        }
        @rmdir($baseDir);
    }
    ai_webadmin_save_runtime_settings_patch([
        "page_cache_last_cleared_at" => time(),
        "page_cache_last_clear_reason" => sanitize_text_field((string)$reason),
    ]);
    return $deleted;
}

function ai_webadmin_clear_page_cache_on_content_change($postId = 0) {
    $id = (int)$postId;
    if ($id > 0 && wp_is_post_revision($id)) {
        return;
    }
    ai_webadmin_clear_page_cache("content_change");
}

function ai_webadmin_collect_autoload_option_stats($topLimit = 20) {
    global $wpdb;
    if (!$wpdb) {
        return [
            "autoload_option_count" => null,
            "autoload_total_bytes" => null,
            "autoload_total_kb" => null,
            "autoload_top_options" => [],
        ];
    }

    $totals = $wpdb->get_row(
        "SELECT COUNT(*) AS c, COALESCE(SUM(LENGTH(option_value)),0) AS b FROM {$wpdb->options} WHERE autoload IN ('yes','on','true','1')",
        ARRAY_A
    );
    $count = is_array($totals) ? max(0, (int)($totals["c"] ?? 0)) : 0;
    $bytes = is_array($totals) ? max(0, (int)($totals["b"] ?? 0)) : 0;
    $limit = max(5, min(80, (int)$topLimit));
    $rows = $wpdb->get_results(
        $wpdb->prepare(
            "SELECT option_name, LENGTH(option_value) AS bytes FROM {$wpdb->options} WHERE autoload IN ('yes','on','true','1') ORDER BY bytes DESC LIMIT %d",
            $limit
        ),
        ARRAY_A
    );
    $top = [];
    if (is_array($rows)) {
        foreach ($rows as $row) {
            $name = sanitize_text_field((string)($row["option_name"] ?? ""));
            if ($name === "") {
                continue;
            }
            $top[] = [
                "name" => $name,
                "bytes" => max(0, (int)($row["bytes"] ?? 0)),
            ];
        }
    }
    return [
        "autoload_option_count" => $count,
        "autoload_total_bytes" => $bytes,
        "autoload_total_kb" => (int)round($bytes / 1024),
        "autoload_top_options" => $top,
    ];
}

function ai_webadmin_run_safe_autoload_cleanup($limit = 200) {
    $settings = ai_webadmin_get_settings();
    if (empty($settings["autoload_cleanup_enabled"])) {
        return [
            "ok" => false,
            "error" => "Autoload cleanup is disabled.",
            "deleted_options" => 0,
            "autoload_flag_updates" => 0,
        ];
    }
    global $wpdb;
    if (!$wpdb) {
        return [
            "ok" => false,
            "error" => "Database not available.",
            "deleted_options" => 0,
            "autoload_flag_updates" => 0,
        ];
    }

    $max = max(20, min(1000, (int)$limit));
    $now = time();
    $deleted = 0;
    $autoloadUpdated = 0;

    $timeoutRows = $wpdb->get_results(
        $wpdb->prepare(
            "SELECT option_name, option_value FROM {$wpdb->options}
             WHERE option_name LIKE '\\_transient\\_timeout\\_%' ESCAPE '\\'
                OR option_name LIKE '\\_site\\_transient\\_timeout\\_%' ESCAPE '\\'
             LIMIT %d",
            $max
        ),
        ARRAY_A
    );
    if (is_array($timeoutRows)) {
        foreach ($timeoutRows as $row) {
            $name = (string)($row["option_name"] ?? "");
            $timeout = (int)($row["option_value"] ?? 0);
            if ($name === "" || $timeout <= 0 || $timeout >= $now) {
                continue;
            }
            $deleted += (int)$wpdb->delete($wpdb->options, ["option_name" => $name], ["%s"]);
            if (strpos($name, "_transient_timeout_") === 0) {
                $valueName = str_replace("_transient_timeout_", "_transient_", $name);
                $deleted += (int)$wpdb->delete($wpdb->options, ["option_name" => $valueName], ["%s"]);
            } elseif (strpos($name, "_site_transient_timeout_") === 0) {
                $valueName = str_replace("_site_transient_timeout_", "_site_transient_", $name);
                $deleted += (int)$wpdb->delete($wpdb->options, ["option_name" => $valueName], ["%s"]);
            }
        }
    }

    $autoloadTransientRows = $wpdb->get_results(
        $wpdb->prepare(
            "SELECT option_name FROM {$wpdb->options}
             WHERE autoload IN ('yes','on','true','1')
               AND (option_name LIKE '\\_transient\\_%' ESCAPE '\\' OR option_name LIKE '\\_site\\_transient\\_%' ESCAPE '\\')
             LIMIT %d",
            $max
        ),
        ARRAY_A
    );
    if (is_array($autoloadTransientRows)) {
        foreach ($autoloadTransientRows as $row) {
            $name = sanitize_text_field((string)($row["option_name"] ?? ""));
            if ($name === "") {
                continue;
            }
            $autoloadUpdated += (int)$wpdb->update(
                $wpdb->options,
                ["autoload" => "no"],
                ["option_name" => $name],
                ["%s"],
                ["%s"]
            );
        }
    }

    $summary = "deleted_expired=" . (int)$deleted . ", autoload_flag_updates=" . (int)$autoloadUpdated;
    ai_webadmin_save_runtime_settings_patch([
        "autoload_last_cleanup_at" => time(),
        "autoload_last_cleanup_summary" => sanitize_text_field($summary),
    ]);
    ai_webadmin_clear_page_cache("autoload_cleanup");

    return [
        "ok" => true,
        "deleted_options" => (int)$deleted,
        "autoload_flag_updates" => (int)$autoloadUpdated,
        "summary" => $summary,
    ];
}

function ai_webadmin_collect_page_cache_health_snapshot($force = false) {
    $cacheKey = "ai_webadmin_page_cache_health_snapshot_v1";
    if (!$force) {
        $cached = get_transient($cacheKey);
        if (is_array($cached) && !empty($cached["checked_at"])) {
            return $cached;
        }
    }

    $headersFound = [];
    $durations = [];
    $statusCodes = [];
    $home = home_url("/");
    $headerCandidates = [
        "cache-control",
        "expires",
        "age",
        "last-modified",
        "etag",
        "x-cache-enabled",
        "x-cache-disabled",
        "x-srcache-store-status",
        "x-srcache-fetch-status",
        "x-ai-webadmin-cache",
    ];
    for ($i = 0; $i < 3; $i++) {
        $start = microtime(true);
        $response = wp_remote_get($home, [
            "timeout" => 12,
            "redirection" => 3,
            "headers" => [
                "accept" => "text/html,application/xhtml+xml",
            ],
        ]);
        $durations[] = (int)round((microtime(true) - $start) * 1000);
        if (!is_wp_error($response)) {
            $statusCodes[] = (int)wp_remote_retrieve_response_code($response);
            $h = wp_remote_retrieve_headers($response);
            foreach ($headerCandidates as $headerName) {
                $value = "";
                if (is_array($h) && isset($h[$headerName])) {
                    $value = (string)$h[$headerName];
                } elseif (is_object($h) && method_exists($h, "offsetGet")) {
                    $v = $h->offsetGet($headerName);
                    $value = is_array($v) ? implode(", ", $v) : (string)$v;
                }
                if (trim($value) !== "") {
                    $headersFound[strtolower($headerName)] = true;
                }
            }
        } else {
            $statusCodes[] = 0;
        }
    }
    sort($durations);
    $medianMs = !empty($durations) ? (int)$durations[(int)floor((count($durations) - 1) / 2)] : null;

    $active = (array)get_option("active_plugins", []);
    $pluginDetected = false;
    foreach ($active as $slug) {
        $s = strtolower((string)$slug);
        if (preg_match('/cache|rocket|litespeed|wp-super-cache|w3-total-cache|cache-enabler/', $s)) {
            $pluginDetected = true;
            break;
        }
    }

    $settings = ai_webadmin_get_settings();
    $builtinEnabled = ai_webadmin_page_cache_enabled($settings);
    $hasHeaders = !empty($headersFound);
    $status = "good";
    if (!$hasHeaders || !($pluginDetected || $builtinEnabled)) {
        $status = "critical";
    } elseif ($medianMs !== null && $medianMs > 1200) {
        $status = "critical";
    } elseif ($medianMs !== null && $medianMs > 600) {
        $status = "warning";
    }

    $snapshot = [
        "checked_at" => time(),
        "header_detected" => $hasHeaders ? 1 : 0,
        "header_names" => array_values(array_keys($headersFound)),
        "plugin_detected" => $pluginDetected ? 1 : 0,
        "builtin_enabled" => $builtinEnabled ? 1 : 0,
        "median_ttfb_ms" => $medianMs,
        "status" => $status,
        "status_codes" => array_slice(array_map("intval", $statusCodes), 0, 3),
    ];
    set_transient($cacheKey, $snapshot, 15 * MINUTE_IN_SECONDS);
    return $snapshot;
}

function ai_webadmin_handle_settings_submit() {
    if (!isset($_POST["ai_webadmin_settings_submit"])) {
        return;
    }
    if (!current_user_can("manage_options")) {
        return;
    }
    check_admin_referer("ai_webadmin_settings_save", "ai_webadmin_nonce");
    $beforeSettings = ai_webadmin_get_settings();
    $input = [
        "worker_base_url" => isset($_POST["worker_base_url"]) ? wp_unslash($_POST["worker_base_url"]) : "",
        "plugin_shared_secret" => isset($_POST["plugin_shared_secret"]) ? wp_unslash($_POST["plugin_shared_secret"]) : "",
        "onboarding_session_id" => isset($_POST["onboarding_session_id"]) ? wp_unslash($_POST["onboarding_session_id"]) : "",
        "cloudflare_account_id" => isset($_POST["cloudflare_account_id"]) ? wp_unslash($_POST["cloudflare_account_id"]) : "",
        "branding_favicon_url" => isset($_POST["branding_favicon_url"]) ? wp_unslash($_POST["branding_favicon_url"]) : "",
        "branding_inject_favicon" => isset($_POST["branding_inject_favicon"]) ? 1 : 0,
        "branding_admin_menu_icon_url" => isset($_POST["branding_admin_menu_icon_url"]) ? wp_unslash($_POST["branding_admin_menu_icon_url"]) : "",
        "enable_comment_moderation" => isset($_POST["enable_comment_moderation"]) ? 1 : 0,
        "enable_schema_injection" => isset($_POST["enable_schema_injection"]) ? 1 : 0,
        "enable_broken_link_redirects" => isset($_POST["enable_broken_link_redirects"]) ? 1 : 0,
        "require_tolldns" => isset($_POST["require_tolldns"]) ? 1 : 0,
        "sandbox_dry_run_enabled" => isset($_POST["sandbox_dry_run_enabled"]) ? 1 : 0,
        "enable_media_r2_offload" => isset($_POST["enable_media_r2_offload"]) ? 1 : 0,
        "media_public_base_url" => isset($_POST["media_public_base_url"]) ? wp_unslash($_POST["media_public_base_url"]) : "",
        "media_rewrite_attachment_urls" => isset($_POST["media_rewrite_attachment_urls"]) ? 1 : 0,
        "media_offload_batch_size" => isset($_POST["media_offload_batch_size"]) ? wp_unslash($_POST["media_offload_batch_size"]) : "",
        "media_seo_autofill_enabled" => isset($_POST["media_seo_autofill_enabled"]) ? 1 : 0,
        "media_ai_enrichment_enabled" => isset($_POST["media_ai_enrichment_enabled"]) ? 1 : 0,
        "media_force_metadata_refresh" => isset($_POST["media_force_metadata_refresh"]) ? 1 : 0,
        "media_assign_to_primary_admin" => isset($_POST["media_assign_to_primary_admin"]) ? 1 : 0,
        "media_optimize_images" => isset($_POST["media_optimize_images"]) ? 1 : 0,
        "media_max_dimension_px" => isset($_POST["media_max_dimension_px"]) ? wp_unslash($_POST["media_max_dimension_px"]) : "",
        "media_image_quality" => isset($_POST["media_image_quality"]) ? wp_unslash($_POST["media_image_quality"]) : "",
        "media_target_max_bytes" => isset($_POST["media_target_max_bytes"]) ? wp_unslash($_POST["media_target_max_bytes"]) : "",
        "github_signup_url" => isset($_POST["github_signup_url"]) ? wp_unslash($_POST["github_signup_url"]) : "",
        "enable_builtin_page_cache" => isset($_POST["enable_builtin_page_cache"]) ? 1 : 0,
        "page_cache_ttl_seconds" => isset($_POST["page_cache_ttl_seconds"]) ? wp_unslash($_POST["page_cache_ttl_seconds"]) : "",
        "page_cache_excluded_paths" => isset($_POST["page_cache_excluded_paths"]) ? wp_unslash($_POST["page_cache_excluded_paths"]) : "",
        "autoload_cleanup_enabled" => isset($_POST["autoload_cleanup_enabled"]) ? 1 : 0,
        "seo_primary_keywords" => isset($_POST["seo_primary_keywords"]) ? wp_unslash($_POST["seo_primary_keywords"]) : "",
        "seo_secondary_keywords" => isset($_POST["seo_secondary_keywords"]) ? wp_unslash($_POST["seo_secondary_keywords"]) : "",
        "seo_target_locations" => isset($_POST["seo_target_locations"]) ? wp_unslash($_POST["seo_target_locations"]) : "",
        "seo_offer_summary" => isset($_POST["seo_offer_summary"]) ? wp_unslash($_POST["seo_offer_summary"]) : "",
        "seo_brand_voice" => isset($_POST["seo_brand_voice"]) ? wp_unslash($_POST["seo_brand_voice"]) : "",
        "premium_upgrade_url" => isset($_POST["premium_upgrade_url"]) ? wp_unslash($_POST["premium_upgrade_url"]) : "",
        "premium_feature_ai_competitor_monitoring" => isset($_POST["premium_feature_ai_competitor_monitoring"]) ? 1 : 0,
        "premium_feature_daily_page_speed_paths" => isset($_POST["premium_feature_daily_page_speed_paths"]) ? 1 : 0,
        "premium_feature_auto_seo_briefs" => isset($_POST["premium_feature_auto_seo_briefs"]) ? 1 : 0,
        "vps_upgrade_url" => isset($_POST["vps_upgrade_url"]) ? wp_unslash($_POST["vps_upgrade_url"]) : "",
        "cache_accelerator_upgrade_url" => isset($_POST["cache_accelerator_upgrade_url"]) ? wp_unslash($_POST["cache_accelerator_upgrade_url"]) : "",
        "allow_tolldns_points_payment" => isset($_POST["allow_tolldns_points_payment"]) ? 1 : 0,
        "tolldns_points_per_usd_cents" => isset($_POST["tolldns_points_per_usd_cents"]) ? wp_unslash($_POST["tolldns_points_per_usd_cents"]) : "",
        "tolldns_vps_upgrade_points_cost" => isset($_POST["tolldns_vps_upgrade_points_cost"]) ? wp_unslash($_POST["tolldns_vps_upgrade_points_cost"]) : "",
        "tolldns_cache_upgrade_points_cost" => isset($_POST["tolldns_cache_upgrade_points_cost"]) ? wp_unslash($_POST["tolldns_cache_upgrade_points_cost"]) : "",
        "enable_security_hardening" => isset($_POST["enable_security_hardening"]) ? 1 : 0,
        "disable_xmlrpc" => isset($_POST["disable_xmlrpc"]) ? 1 : 0,
        "prevent_email_display_name" => isset($_POST["prevent_email_display_name"]) ? 1 : 0,
        "enforce_single_admin" => isset($_POST["enforce_single_admin"]) ? 1 : 0,
        "normalize_editor_generic_emails_to_admin" => isset($_POST["normalize_editor_generic_emails_to_admin"]) ? 1 : 0,
        "block_file_manager_plugins" => isset($_POST["block_file_manager_plugins"]) ? 1 : 0,
        "enable_login_rate_limit" => isset($_POST["enable_login_rate_limit"]) ? 1 : 0,
        "login_rate_limit_attempts" => isset($_POST["login_rate_limit_attempts"]) ? wp_unslash($_POST["login_rate_limit_attempts"]) : "",
        "login_rate_limit_window_minutes" => isset($_POST["login_rate_limit_window_minutes"]) ? wp_unslash($_POST["login_rate_limit_window_minutes"]) : "",
        "login_rate_limit_lockout_minutes" => isset($_POST["login_rate_limit_lockout_minutes"]) ? wp_unslash($_POST["login_rate_limit_lockout_minutes"]) : "",
        "enforce_admin_sso" => isset($_POST["enforce_admin_sso"]) ? 1 : 0,
        "require_admin_unlock_factor" => isset($_POST["require_admin_unlock_factor"]) ? 1 : 0,
        "admin_sso_header_name" => isset($_POST["admin_sso_header_name"]) ? wp_unslash($_POST["admin_sso_header_name"]) : "",
        "apply_htaccess_hardening" => isset($_POST["apply_htaccess_hardening"]) ? 1 : 0,
        "enable_plugin_rationalization" => isset($_POST["enable_plugin_rationalization"]) ? 1 : 0,
        "license_hygiene_enabled" => isset($_POST["license_hygiene_enabled"]) ? 1 : 0,
        "license_expected_email" => isset($_POST["license_expected_email"]) ? wp_unslash($_POST["license_expected_email"]) : "",
        "remove_migration_replication_plugins" => isset($_POST["remove_migration_replication_plugins"]) ? 1 : 0,
        "auto_remove_failed_static_export_plugins" => isset($_POST["auto_remove_failed_static_export_plugins"]) ? 1 : 0,
        "auto_uninstall_inactive_plugins" => isset($_POST["auto_uninstall_inactive_plugins"]) ? 1 : 0,
        "inactive_plugin_delete_limit" => isset($_POST["inactive_plugin_delete_limit"]) ? wp_unslash($_POST["inactive_plugin_delete_limit"]) : "",
        "inactive_plugin_protected_slugs" => isset($_POST["inactive_plugin_protected_slugs"]) ? wp_unslash($_POST["inactive_plugin_protected_slugs"]) : "",
        "auto_uninstall_inactive_themes" => isset($_POST["auto_uninstall_inactive_themes"]) ? 1 : 0,
        "inactive_theme_delete_limit" => isset($_POST["inactive_theme_delete_limit"]) ? wp_unslash($_POST["inactive_theme_delete_limit"]) : "",
        "inactive_theme_protected_slugs" => isset($_POST["inactive_theme_protected_slugs"]) ? wp_unslash($_POST["inactive_theme_protected_slugs"]) : "",
        "enable_inactive_user_cleanup" => isset($_POST["enable_inactive_user_cleanup"]) ? 1 : 0,
        "inactive_user_days" => isset($_POST["inactive_user_days"]) ? wp_unslash($_POST["inactive_user_days"]) : "",
        "inactive_user_delete_limit" => isset($_POST["inactive_user_delete_limit"]) ? wp_unslash($_POST["inactive_user_delete_limit"]) : "",
        "github_backup_enabled" => isset($_POST["github_backup_enabled"]) ? 1 : 0,
        "github_backup_repo" => isset($_POST["github_backup_repo"]) ? wp_unslash($_POST["github_backup_repo"]) : "",
        "github_backup_branch" => isset($_POST["github_backup_branch"]) ? wp_unslash($_POST["github_backup_branch"]) : "",
        "github_backup_manifest_max_files" => isset($_POST["github_backup_manifest_max_files"]) ? wp_unslash($_POST["github_backup_manifest_max_files"]) : "",
        "enable_passcode_unlock" => isset($_POST["enable_passcode_unlock"]) ? 1 : 0,
        "unlock_passcode" => isset($_POST["unlock_passcode"]) ? wp_unslash($_POST["unlock_passcode"]) : "",
        "clear_unlock_passcode" => isset($_POST["clear_unlock_passcode"]) ? 1 : 0,
        "require_hardware_key_unlock" => isset($_POST["require_hardware_key_unlock"]) ? 1 : 0,
        "require_wallet_signature_unlock" => isset($_POST["require_wallet_signature_unlock"]) ? 1 : 0,
        "wallet_unlock_message_prefix" => isset($_POST["wallet_unlock_message_prefix"]) ? wp_unslash($_POST["wallet_unlock_message_prefix"]) : "",
        "wallet_unlock_chain_id" => isset($_POST["wallet_unlock_chain_id"]) ? wp_unslash($_POST["wallet_unlock_chain_id"]) : "",
        "wallet_unlock_nonce_ttl_minutes" => isset($_POST["wallet_unlock_nonce_ttl_minutes"]) ? wp_unslash($_POST["wallet_unlock_nonce_ttl_minutes"]) : "",
        "enable_email_forwarding_via_worker" => isset($_POST["enable_email_forwarding_via_worker"]) ? 1 : 0,
        "remove_smtp_plugins" => isset($_POST["remove_smtp_plugins"]) ? 1 : 0,
        "lead_forward_email" => isset($_POST["lead_forward_email"]) ? wp_unslash($_POST["lead_forward_email"]) : "",
        "suppress_local_lead_mail" => isset($_POST["suppress_local_lead_mail"]) ? 1 : 0,
    ];
    $cloudflareToken = isset($_POST["cloudflare_api_token"]) ? trim((string)wp_unslash($_POST["cloudflare_api_token"])) : "";
    $githubToken = isset($_POST["github_classic_token"]) ? trim((string)wp_unslash($_POST["github_classic_token"])) : "";
    $vaultCloudflareToken = isset($_POST["vault_cloudflare_api_token"]) ? trim((string)wp_unslash($_POST["vault_cloudflare_api_token"])) : "";
    $vaultGithubToken = isset($_POST["vault_github_token"]) ? trim((string)wp_unslash($_POST["vault_github_token"])) : "";
    $vaultHostingToken = isset($_POST["vault_hosting_provider_token"]) ? trim((string)wp_unslash($_POST["vault_hosting_provider_token"])) : "";
    $vaultOpenAiToken = isset($_POST["vault_openai_api_token"]) ? trim((string)wp_unslash($_POST["vault_openai_api_token"])) : "";
    $agentChatQuestion = isset($_POST["agent_chat_question"]) ? trim((string)wp_unslash($_POST["agent_chat_question"])) : "";
    $cacheConfigChanged =
        (int)$input["enable_builtin_page_cache"] !== (int)($beforeSettings["enable_builtin_page_cache"] ?? 0) ||
        (int)$input["page_cache_ttl_seconds"] !== (int)($beforeSettings["page_cache_ttl_seconds"] ?? 0) ||
        sanitize_textarea_field((string)$input["page_cache_excluded_paths"]) !== sanitize_textarea_field((string)($beforeSettings["page_cache_excluded_paths"] ?? ""));
    ai_webadmin_save_settings($input);
    $seoChanged =
        sanitize_textarea_field((string)$input["seo_primary_keywords"]) !== sanitize_textarea_field((string)($beforeSettings["seo_primary_keywords"] ?? "")) ||
        sanitize_textarea_field((string)$input["seo_secondary_keywords"]) !== sanitize_textarea_field((string)($beforeSettings["seo_secondary_keywords"] ?? "")) ||
        sanitize_textarea_field((string)$input["seo_target_locations"]) !== sanitize_textarea_field((string)($beforeSettings["seo_target_locations"] ?? "")) ||
        sanitize_textarea_field((string)$input["seo_offer_summary"]) !== sanitize_textarea_field((string)($beforeSettings["seo_offer_summary"] ?? "")) ||
        sanitize_text_field((string)$input["seo_brand_voice"]) !== sanitize_text_field((string)($beforeSettings["seo_brand_voice"] ?? ""));
    if ($seoChanged) {
        ai_webadmin_save_runtime_settings_patch([
            "seo_last_updated_at" => time(),
        ]);
    }
    if ($cacheConfigChanged) {
        ai_webadmin_clear_page_cache("settings_change");
        ai_webadmin_collect_page_cache_health_snapshot(true);
    }
    ai_webadmin_run_hardening_pass(true);
    ai_webadmin_sync_email_forwarding_profile();
    ai_webadmin_sweep_email_display_names(500);
    ai_webadmin_purge_inactive_users();
    $latestSettings = ai_webadmin_get_settings();
    if (!empty($latestSettings["require_admin_unlock_factor"]) && !ai_webadmin_unlock_enabled($latestSettings)) {
        add_settings_error(
            "ai_webadmin_messages",
            "ai_webadmin_unlock_factor_required",
            "Administrator protection is enabled. Turn on at least one unlock factor: passcode, hardware key/passkey, or wallet signature.",
            "error"
        );
    }

    if ($cloudflareToken !== "") {
        $connectCf = ai_webadmin_connect_cloudflare($cloudflareToken);
        if (!empty($connectCf["ok"])) {
            add_settings_error("ai_webadmin_messages", "ai_webadmin_cf_connected", "Cloudflare API token verified and connected.", "updated");
        } else {
            $msg = "Cloudflare connect failed: " . sanitize_text_field((string)($connectCf["error"] ?? "unknown_error"));
            add_settings_error("ai_webadmin_messages", "ai_webadmin_cf_failed", $msg, "error");
        }
    }

    if ($githubToken !== "") {
        $connect = ai_webadmin_connect_github_vault($githubToken);
        if (!empty($connect["ok"])) {
            add_settings_error("ai_webadmin_messages", "ai_webadmin_github_connected", "GitHub token stored in Cloudflare vault successfully.", "updated");
            if (ai_webadmin_features_enabled()) {
                ai_webadmin_send_backup_snapshot();
                $latest = ai_webadmin_get_settings();
                $snapshotStatus = sanitize_text_field((string)($latest["github_backup_last_status"] ?? ""));
                $snapshotMessage = sanitize_text_field((string)($latest["github_backup_last_message"] ?? ""));
                if ($snapshotStatus === "ok") {
                    add_settings_error(
                        "ai_webadmin_messages",
                        "ai_webadmin_bootstrap_snapshot_ok",
                        "Initial site snapshot cloned to GitHub successfully.",
                        "updated"
                    );
                } elseif ($snapshotMessage !== "") {
                    add_settings_error(
                        "ai_webadmin_messages",
                        "ai_webadmin_bootstrap_snapshot_warn",
                        "GitHub was connected, but initial snapshot clone needs retry: " . $snapshotMessage,
                        "error"
                    );
                }
            } else {
                add_settings_error(
                    "ai_webadmin_messages",
                    "ai_webadmin_bootstrap_snapshot_locked",
                    "GitHub connected. Initial clone will run automatically once activation lock requirements are complete.",
                    "updated"
                );
            }
        } else {
            $msg = "GitHub token sync failed: " . sanitize_text_field((string)($connect["error"] ?? "unknown_error"));
            add_settings_error("ai_webadmin_messages", "ai_webadmin_github_failed", $msg, "error");
        }
    }

    if (isset($_POST["ai_webadmin_upload_secrets_now"])) {
        $uploaded = 0;
        $errors = [];
        if ($vaultCloudflareToken !== "") {
            $result = ai_webadmin_push_secret_to_worker_vault("cloudflare_api_token", $vaultCloudflareToken, "Cloudflare API Token");
            if (!empty($result["ok"])) {
                $uploaded += 1;
            } else {
                $errors[] = "Cloudflare token: " . sanitize_text_field((string)($result["error"] ?? "upload_failed"));
            }
        }
        if ($vaultGithubToken !== "") {
            $result = ai_webadmin_push_secret_to_worker_vault("github_token", $vaultGithubToken, "GitHub Fine-Grained Token");
            if (!empty($result["ok"])) {
                $uploaded += 1;
            } else {
                $errors[] = "GitHub token: " . sanitize_text_field((string)($result["error"] ?? "upload_failed"));
            }
        }
        if ($vaultHostingToken !== "") {
            $result = ai_webadmin_push_secret_to_worker_vault("hosting_provider_api_token", $vaultHostingToken, "Hosting Provider API Token");
            if (!empty($result["ok"])) {
                $uploaded += 1;
            } else {
                $errors[] = "Hosting token: " . sanitize_text_field((string)($result["error"] ?? "upload_failed"));
            }
        }
        if ($vaultOpenAiToken !== "") {
            $result = ai_webadmin_push_secret_to_worker_vault("openai_api_key", $vaultOpenAiToken, "OpenAI API Key");
            if (!empty($result["ok"])) {
                $uploaded += 1;
            } else {
                $errors[] = "OpenAI key: " . sanitize_text_field((string)($result["error"] ?? "upload_failed"));
            }
        }
        if ($uploaded > 0) {
            add_settings_error(
                "ai_webadmin_messages",
                "ai_webadmin_vault_uploaded",
                sprintf("Uploaded %d secret(s) to Worker vault.", (int)$uploaded),
                "updated"
            );
        }
        if (empty($errors) && $uploaded === 0) {
            add_settings_error("ai_webadmin_messages", "ai_webadmin_vault_none", "No secret values were entered to upload.", "error");
        } elseif (!empty($errors)) {
            add_settings_error("ai_webadmin_messages", "ai_webadmin_vault_errors", implode(" | ", $errors), "error");
        }
    }

    if (isset($_POST["ai_webadmin_run_sandbox_preflight_now"])) {
        $sandbox = ai_webadmin_run_sandbox_preflight();
        if (!empty($sandbox["ok"])) {
            $report = isset($sandbox["sandbox_report"]) && is_array($sandbox["sandbox_report"]) ? $sandbox["sandbox_report"] : [];
            $message = "Sandbox preflight completed.";
            if (!empty($report["risk_level"])) {
                $message .= " Risk: " . sanitize_text_field((string)$report["risk_level"]) . ".";
            }
            if (isset($report["outdated_plugin_count"])) {
                $message .= " Outdated plugins reviewed: " . (int)$report["outdated_plugin_count"] . ".";
            }
            add_settings_error("ai_webadmin_messages", "ai_webadmin_sandbox_ok", $message, "updated");
        } else {
            $msg = "Sandbox preflight failed: " . sanitize_text_field((string)($sandbox["error"] ?? "unknown_error"));
            add_settings_error("ai_webadmin_messages", "ai_webadmin_sandbox_failed", $msg, "error");
        }
    }

    if (isset($_POST["ai_webadmin_send_lead_forward_verification_email"])) {
        $verificationStart = ai_webadmin_send_lead_forward_verification_email();
        if (!empty($verificationStart["ok"])) {
            $targetEmail = sanitize_email((string)($verificationStart["forward_to_email"] ?? ""));
            $msg = "Verification email sent.";
            if (is_email($targetEmail)) {
                $msg .= " Check " . $targetEmail . " and click the link, then refresh verification status.";
            }
            add_settings_error("ai_webadmin_messages", "ai_webadmin_email_forward_verify_sent", $msg, "updated");
        } else {
            $msg = "Verification email failed: " . sanitize_text_field((string)($verificationStart["error"] ?? "unknown_error"));
            add_settings_error("ai_webadmin_messages", "ai_webadmin_email_forward_verify_send_failed", $msg, "error");
        }
    }

    if (isset($_POST["ai_webadmin_refresh_lead_forward_verification"])) {
        $verificationStatus = ai_webadmin_refresh_lead_forward_verification_status();
        if (!empty($verificationStatus["ok"])) {
            $statusText = sanitize_text_field((string)($verificationStatus["verification"]["status"] ?? "not_started"));
            add_settings_error(
                "ai_webadmin_messages",
                "ai_webadmin_email_forward_verify_refreshed",
                "Lead-forward verification status refreshed: " . $statusText . ".",
                "updated"
            );
        } else {
            $msg = "Verification status check failed: " . sanitize_text_field((string)($verificationStatus["error"] ?? "unknown_error"));
            add_settings_error("ai_webadmin_messages", "ai_webadmin_email_forward_verify_refresh_failed", $msg, "error");
        }
    }

    if (isset($_POST["ai_webadmin_run_audit_now"])) {
        ai_webadmin_send_audit_metrics();
        add_settings_error("ai_webadmin_messages", "ai_webadmin_audit_now", "Audit sync triggered.", "updated");
    }
    if (isset($_POST["ai_webadmin_refresh_page_cache_health_now"])) {
        $snapshot = ai_webadmin_collect_page_cache_health_snapshot(true);
        $status = sanitize_text_field((string)($snapshot["status"] ?? "unknown"));
        $median = isset($snapshot["median_ttfb_ms"]) && $snapshot["median_ttfb_ms"] !== null ? (int)$snapshot["median_ttfb_ms"] : null;
        $msg = "Page-cache health snapshot refreshed";
        if ($status !== "") {
            $msg .= " (status: " . $status . ")";
        }
        if ($median !== null) {
            $msg .= ", median response " . $median . " ms";
        }
        add_settings_error("ai_webadmin_messages", "ai_webadmin_cache_health_refreshed", $msg . ".", "updated");
    }
    if (isset($_POST["ai_webadmin_clear_page_cache_now"])) {
        $deleted = ai_webadmin_clear_page_cache("manual_settings_clear");
        ai_webadmin_collect_page_cache_health_snapshot(true);
        add_settings_error(
            "ai_webadmin_messages",
            "ai_webadmin_cache_cleared",
            "Built-in page cache cleared (" . (int)$deleted . " cached file(s) removed).",
            "updated"
        );
    }
    if (isset($_POST["ai_webadmin_run_autoload_cleanup_now"])) {
        $cleanup = ai_webadmin_run_safe_autoload_cleanup(350);
        if (!empty($cleanup["ok"])) {
            add_settings_error(
                "ai_webadmin_messages",
                "ai_webadmin_autoload_cleanup_ok",
                "Autoload cleanup complete: " . sanitize_text_field((string)($cleanup["summary"] ?? "")),
                "updated"
            );
        } else {
            $msg = "Autoload cleanup skipped: " . sanitize_text_field((string)($cleanup["error"] ?? "unknown_error"));
            add_settings_error("ai_webadmin_messages", "ai_webadmin_autoload_cleanup_failed", $msg, "error");
        }
    }
    if (isset($_POST["ai_webadmin_refresh_cache_now"])) {
        ai_webadmin_fetch_schema_profile();
        ai_webadmin_fetch_redirect_profile();
        add_settings_error("ai_webadmin_messages", "ai_webadmin_cache_now", "Schema and redirect caches refreshed.", "updated");
    }
    if (isset($_POST["ai_webadmin_run_sync_now"])) {
        ai_webadmin_sync_worker_data();
        add_settings_error("ai_webadmin_messages", "ai_webadmin_sync_now", "Full worker sync triggered.", "updated");
    }
    if (isset($_POST["ai_webadmin_run_benchmark_now"])) {
        $snapshot = ai_webadmin_capture_benchmark_snapshot();
        $msg = "Benchmark captured";
        if (!empty($snapshot["home_fetch_ms"])) {
            $msg .= " (" . (int)$snapshot["home_fetch_ms"] . " ms home fetch)";
        }
        add_settings_error("ai_webadmin_messages", "ai_webadmin_benchmark_now", $msg . ".", "updated");
    }
    if (isset($_POST["ai_webadmin_process_comment_queue_now"])) {
        $summary = ai_webadmin_process_pending_comment_backlog_now(220);
        $msg = sprintf(
            "Comment backlog processed: %d total (trash %d, spam %d, approved %d, hold %d).",
            (int)($summary["processed"] ?? 0),
            (int)($summary["trash"] ?? 0),
            (int)($summary["spam"] ?? 0),
            (int)($summary["approved"] ?? 0),
            (int)($summary["hold"] ?? 0)
        );
        add_settings_error("ai_webadmin_messages", "ai_webadmin_comment_backlog_now", $msg, "updated");
    }
    if (isset($_POST["ai_webadmin_run_media_offload_now"])) {
        $offload = ai_webadmin_run_media_r2_offload_batch();
        if (!empty($offload["ok"])) {
            $msg = "Media offload complete: " . (int)($offload["processed_count"] ?? 0) . " processed";
            $failed = (int)($offload["failed_count"] ?? 0);
            if ($failed > 0) {
                $msg .= ", " . $failed . " failed";
            }
            $msg .= ".";
            add_settings_error("ai_webadmin_messages", "ai_webadmin_media_offload_ok", $msg, "updated");
        } else {
            $msg = "Media offload failed: " . sanitize_text_field((string)($offload["error"] ?? "unknown_error"));
            add_settings_error("ai_webadmin_messages", "ai_webadmin_media_offload_failed", $msg, "error");
        }
    }
    if (isset($_POST["ai_webadmin_run_media_offload_full_now"])) {
        $offload = ai_webadmin_run_media_r2_offload_until_complete(30, 100);
        if (!empty($offload["ok"])) {
            $msg = "Full media run: " . (int)($offload["processed_count"] ?? 0) . " processed";
            $failed = (int)($offload["failed_count"] ?? 0);
            if ($failed > 0) {
                $msg .= ", " . $failed . " failed";
            }
            $mapped = (int)($offload["mapped_count"] ?? 0);
            if ($mapped > 0) {
                $msg .= ", " . $mapped . " mapped to R2 URLs";
            }
            $passes = (int)($offload["passes"] ?? 0);
            if ($passes > 0) {
                $msg .= " across " . $passes . " batch run(s)";
            }
            if (empty($offload["complete"])) {
                $msg .= " (partial pass; click again to continue)";
            }
            $msg .= ".";
            add_settings_error("ai_webadmin_messages", "ai_webadmin_media_offload_full_ok", $msg, "updated");
        } else {
            $msg = "Full media run failed: " . sanitize_text_field((string)($offload["error"] ?? "unknown_error"));
            add_settings_error("ai_webadmin_messages", "ai_webadmin_media_offload_full_failed", $msg, "error");
        }
    }
    if (isset($_POST["ai_webadmin_reset_media_offload_cursor"])) {
        ai_webadmin_save_runtime_settings_patch([
            "media_offload_cursor_attachment_id" => 0,
            "media_offload_last_message" => "Media offload cursor reset to 0. Next run will reprocess all attachments.",
            "media_offload_last_status" => "ready",
            "media_offload_last_mapped_count" => 0,
        ]);
        add_settings_error(
            "ai_webadmin_messages",
            "ai_webadmin_media_cursor_reset",
            "Media offload cursor reset. Run Media Offload Batch to remap all image URLs to R2/CDN.",
            "updated"
        );
    }
    if (isset($_POST["ai_webadmin_run_license_hygiene_now"])) {
        $cleanup = ai_webadmin_run_license_hygiene([
            "force" => true,
            "delete" => true,
            "use_ai" => true,
        ]);
        if (!empty($cleanup["ok"])) {
            $msg = "License cleanup reviewed " . (int)($cleanup["reviewed_count"] ?? 0) .
                ", flagged " . (int)($cleanup["flagged_count"] ?? 0) .
                ", deleted " . (int)($cleanup["deleted_count"] ?? 0) . ".";
            $snapshotStatus = sanitize_text_field((string)($cleanup["github_snapshot_status"] ?? ""));
            if ($snapshotStatus !== "" && $snapshotStatus !== "skipped") {
                $msg .= " GitHub snapshot: " . $snapshotStatus . ".";
            }
            add_settings_error("ai_webadmin_messages", "ai_webadmin_license_cleanup_ok", $msg, "updated");
        } else {
            $msg = "License cleanup failed: " . sanitize_text_field((string)($cleanup["error"] ?? "unknown_error"));
            add_settings_error("ai_webadmin_messages", "ai_webadmin_license_cleanup_failed", $msg, "error");
        }
    }
    if (isset($_POST["ai_webadmin_redeem_vps_points_now"])) {
        $redeem = ai_webadmin_redeem_tolldns_points(ai_webadmin_get_settings(), "vps");
        if (!empty($redeem["ok"])) {
            add_settings_error(
                "ai_webadmin_messages",
                "ai_webadmin_redeem_vps_ok",
                "TollDNS points redeemed for VPS upgrade queue: -" . (int)($redeem["cost"] ?? 0) . " points.",
                "updated"
            );
        } else {
            $msg = "VPS points redemption failed: " . sanitize_text_field((string)($redeem["error"] ?? "unknown_error"));
            add_settings_error("ai_webadmin_messages", "ai_webadmin_redeem_vps_failed", $msg, "error");
        }
    }
    if (isset($_POST["ai_webadmin_redeem_cache_points_now"])) {
        $redeem = ai_webadmin_redeem_tolldns_points(ai_webadmin_get_settings(), "cache");
        if (!empty($redeem["ok"])) {
            add_settings_error(
                "ai_webadmin_messages",
                "ai_webadmin_redeem_cache_ok",
                "TollDNS points redeemed for cache accelerator queue: -" . (int)($redeem["cost"] ?? 0) . " points.",
                "updated"
            );
        } else {
            $msg = "Cache points redemption failed: " . sanitize_text_field((string)($redeem["error"] ?? "unknown_error"));
            add_settings_error("ai_webadmin_messages", "ai_webadmin_redeem_cache_failed", $msg, "error");
        }
    }
    if (isset($_POST["ai_webadmin_agent_chat_ask"])) {
        if ($agentChatQuestion === "") {
            add_settings_error("ai_webadmin_messages", "ai_webadmin_agent_chat_empty", "Please enter a question for AI Agent Chat.", "error");
        } else {
            $chat = ai_webadmin_agent_chat($agentChatQuestion);
            if (!empty($chat["ok"])) {
                $proofCount = is_array($chat["proofs"] ?? null) ? count($chat["proofs"]) : 0;
                add_settings_error(
                    "ai_webadmin_messages",
                    "ai_webadmin_agent_chat_ok",
                    sprintf("Agent replied with %d proof item(s).", (int)$proofCount),
                    "updated"
                );
            } else {
                $msg = "Agent chat failed: " . sanitize_text_field((string)($chat["error"] ?? "unknown_error"));
                add_settings_error("ai_webadmin_messages", "ai_webadmin_agent_chat_failed", $msg, "error");
            }
        }
    }
    add_settings_error("ai_webadmin_messages", "ai_webadmin_saved", "Settings saved.", "updated");
}
add_action("admin_init", "ai_webadmin_handle_settings_submit");

function ai_webadmin_render_settings_page() {
    if (!current_user_can("manage_options")) {
        return;
    }
    $settings = ai_webadmin_get_settings();
    $tabs = ai_webadmin_settings_tabs();
    $activeTab = ai_webadmin_get_active_settings_tab();
    $missingActivation = ai_webadmin_missing_activation_requirements($settings);
    $pluginActivated = empty($missingActivation);
    $tolldnsActive = ai_webadmin_is_tolldns_active();
    $tolldnsInstallUrl = esc_url(AI_WEBADMIN_TOLLDNS_INSTALL_URL);
    $tokenGuideUrl = esc_url("https://app.cardetailingreno.com/guides/fine-token/");
    $premiumUpgradeUrl = esc_url((string)($settings["premium_upgrade_url"] ?? "https://app.cardetailingreno.com/upgrade/"));
    $vpsUpgradeUrl = esc_url((string)($settings["vps_upgrade_url"] ?? "https://app.cardetailingreno.com/upgrade/vps"));
    $cacheUpgradeUrl = esc_url((string)($settings["cache_accelerator_upgrade_url"] ?? "https://app.cardetailingreno.com/upgrade/cache"));
    $tolldnsSummary = ai_webadmin_tolldns_points_summary();
    $tolldnsPointsTotal = is_array($tolldnsSummary) ? max(0, (int)($tolldnsSummary["points_total"] ?? 0)) : 0;
    $tolldnsPointsPerUsdCents = max(1, (int)($settings["tolldns_points_per_usd_cents"] ?? 100));
    $tolldnsUsdApprox = round($tolldnsPointsTotal / $tolldnsPointsPerUsdCents, 2);
    $tolldnsVpsCost = max(1, (int)($settings["tolldns_vps_upgrade_points_cost"] ?? 800));
    $tolldnsCacheCost = max(1, (int)($settings["tolldns_cache_upgrade_points_cost"] ?? 500));
    $brandingFaviconUrl = esc_url((string)($settings["branding_favicon_url"] ?? ""));
    $seoPrimaryKeywords = sanitize_textarea_field((string)($settings["seo_primary_keywords"] ?? ""));
    $seoSecondaryKeywords = sanitize_textarea_field((string)($settings["seo_secondary_keywords"] ?? ""));
    $seoTargetLocations = sanitize_textarea_field((string)($settings["seo_target_locations"] ?? ""));
    $seoOfferSummary = sanitize_textarea_field((string)($settings["seo_offer_summary"] ?? ""));
    $seoBrandVoice = sanitize_text_field((string)($settings["seo_brand_voice"] ?? ""));
    $seoLastUpdatedAt = (int)($settings["seo_last_updated_at"] ?? 0);
    $auditMetrics = [];
    $lastBenchmark = [];
    $benchmarkMetrics = [];
    $sandboxMetrics = [];
    $sandboxOutdatedPlugins = [];
    $sandboxOutdatedCount = 0;
    $schemaSyncedAt = 0;
    $redirectSyncedAt = 0;
    $updateMetaVersion = "";
    $nextAuditSyncAt = 0;
    $nextHardeningAt = 0;
    $objectCacheEnabled = false;
    $optimizationSummary = "";
    $optimizationCloneStatus = "";
    $optimizationCloneSummary = "";
    $optimizationRemoveNow = [];
    $optimizationRemoveAfterR2 = [];
    $mediaOffloadLastRunAt = (int)($settings["media_offload_last_run_at"] ?? 0);
    $mediaOffloadLastStatus = sanitize_text_field((string)($settings["media_offload_last_status"] ?? ""));
    $mediaOffloadLastMessage = sanitize_text_field((string)($settings["media_offload_last_message"] ?? ""));
    $mediaOffloadTotalProcessed = max(0, (int)($settings["media_offload_total_processed"] ?? 0));
    $mediaOffloadTotalFailed = max(0, (int)($settings["media_offload_total_failed"] ?? 0));
    $mediaOffloadCursor = max(0, (int)($settings["media_offload_cursor_attachment_id"] ?? 0));
    $mediaOffloadManifestKey = sanitize_text_field((string)($settings["media_offload_last_manifest_r2_key"] ?? ""));
    $mediaOffloadGithubStatus = sanitize_text_field((string)($settings["media_offload_last_github_status"] ?? ""));
    $mediaOffloadGithubPath = sanitize_text_field((string)($settings["media_offload_last_github_path"] ?? ""));
    $mediaOffloadMappedCount = max(0, (int)($settings["media_offload_last_mapped_count"] ?? 0));
    $licenseExpectedEmail = sanitize_email((string)($settings["license_expected_email"] ?? ""));
    $licenseLastRunAt = (int)($settings["license_hygiene_last_run_at"] ?? 0);
    $licenseLastStatus = sanitize_text_field((string)($settings["license_hygiene_last_status"] ?? ""));
    $licenseLastMessage = sanitize_text_field((string)($settings["license_hygiene_last_message"] ?? ""));
    $licenseLastSummary = sanitize_textarea_field((string)($settings["license_hygiene_last_ai_summary"] ?? ""));
    $licenseLastDeleted = json_decode((string)($settings["license_hygiene_last_deleted_json"] ?? "[]"), true);
    if (!is_array($licenseLastDeleted)) {
        $licenseLastDeleted = [];
    }
    $agentChatHistory = [];
    $agentLastAnswer = sanitize_textarea_field((string)($settings["agent_chat_last_answer"] ?? ""));
    $agentLastQuestion = sanitize_text_field((string)($settings["agent_chat_last_question"] ?? ""));
    $agentLastAskedAt = (int)($settings["agent_chat_last_asked_at"] ?? 0);
    $agentLastProofs = json_decode((string)($settings["agent_chat_last_proofs_json"] ?? "[]"), true);
    $agentLastProofs = ai_webadmin_sanitize_worker_proof_items($agentLastProofs, 10);
    $runtimeLogText = "";
    $pageCacheHealthSnapshot = [];
    $autoloadStats = [];
    if ($activeTab === "audit") {
        $auditMetrics = ai_webadmin_collect_audit_metrics();
        $pageCacheHealthSnapshot = ai_webadmin_collect_page_cache_health_snapshot(false);
        $autoloadStats = ai_webadmin_collect_autoload_option_stats(15);
        $lastBenchmark = ai_webadmin_get_last_benchmark_snapshot();
        $benchmarkMetrics = isset($lastBenchmark["metrics"]) && is_array($lastBenchmark["metrics"]) ? $lastBenchmark["metrics"] : [];
        $schemaSyncedAt = (int)get_option("ai_webadmin_schema_synced_at", 0);
        $redirectSyncedAt = (int)get_option("ai_webadmin_redirect_synced_at", 0);
        $updateMetaCached = get_site_transient(AI_WEBADMIN_UPDATE_META_CACHE_KEY);
        $updateMetaVersion = is_array($updateMetaCached) ? sanitize_text_field((string)($updateMetaCached["version"] ?? "")) : "";
        $nextAuditSyncAt = (int)wp_next_scheduled("ai_webadmin_sync_audit_metrics_event");
        $nextHardeningAt = (int)wp_next_scheduled("ai_webadmin_daily_hardening_event");
        $objectCacheEnabled = function_exists("wp_using_ext_object_cache") && wp_using_ext_object_cache();
        $optimizationSummary = sanitize_text_field((string)($settings["optimization_plan_last_summary"] ?? ""));
        $optimizationCloneStatus = sanitize_text_field((string)($settings["optimization_plan_clone_status"] ?? ""));
        $optimizationCloneSummary = sanitize_text_field((string)($settings["optimization_plan_clone_summary"] ?? ""));
        $optimizationRemoveNow = json_decode((string)($settings["optimization_plan_remove_now_json"] ?? "[]"), true);
        $optimizationRemoveAfterR2 = json_decode((string)($settings["optimization_plan_remove_after_r2_json"] ?? "[]"), true);
        if (!is_array($optimizationRemoveNow)) {
            $optimizationRemoveNow = [];
        }
        if (!is_array($optimizationRemoveAfterR2)) {
            $optimizationRemoveAfterR2 = [];
        }
    }
    if ($activeTab === "logs") {
        $lastBenchmark = ai_webadmin_get_last_benchmark_snapshot();
    }
    if ($activeTab === "sandbox") {
        $sandboxMetrics = ai_webadmin_collect_audit_metrics();
        $sandboxOutdatedPlugins = ai_webadmin_collect_outdated_plugin_updates(25);
        $sandboxOutdatedCount = (int)($sandboxMetrics["outdated_plugin_count"] ?? count($sandboxOutdatedPlugins));
    }
    if ($activeTab === "agent") {
        $agentChatHistory = ai_webadmin_get_agent_chat_history($settings);
    }
    if ($activeTab === "logs") {
        $runtimeLogText = ai_webadmin_build_settings_runtime_log($settings, $lastBenchmark);
    }
    settings_errors("ai_webadmin_messages");
    ?>
    <div class="wrap">
      <h1>AI WebAdmin</h1>
      <p>Connect WordPress to Cloudflare Workers for AI moderation and maintenance workflows.</p>
      <style>
        .ai-webadmin-metric-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(260px,1fr)); gap:12px; margin-top:8px; }
        .ai-webadmin-card { background:#fff; border:1px solid #dcdcde; border-radius:6px; padding:12px; }
        .ai-webadmin-card h4 { margin:0 0 8px; }
        .ai-webadmin-card p { margin:0 0 6px; }
        .ai-webadmin-actions .button { margin-right:8px; margin-bottom:8px; }
        .wrap .nav-tab-wrapper { border-bottom:1px solid #c3c4c7; margin-bottom:14px; }
        .wrap .nav-tab-wrapper .nav-tab {
          font-size:17px;
          font-weight:600;
          padding:12px 18px;
          margin-right:4px;
          border:1px solid #c3c4c7;
          border-bottom-color:#c3c4c7;
          background:#f1f1f1;
          color:#50575e;
        }
        .wrap .nav-tab-wrapper .nav-tab-active {
          background:#fff;
          color:#1d2327;
          border-bottom:1px solid #fff;
        }
      </style>
      <h2 class="nav-tab-wrapper">
        <?php foreach ($tabs as $slug => $label): ?>
          <?php
            $tabUrl = add_query_arg(
                [
                    "tab" => $slug,
                ],
                ai_webadmin_settings_page_url()
            );
            $isActive = ($activeTab === $slug);
          ?>
          <a href="<?php echo esc_url($tabUrl); ?>" class="nav-tab <?php echo $isActive ? "nav-tab-active" : ""; ?>">
            <?php echo esc_html($label); ?>
          </a>
        <?php endforeach; ?>
      </h2>
      <form method="post">
        <?php wp_nonce_field("ai_webadmin_settings_save", "ai_webadmin_nonce"); ?>
        <input type="hidden" name="ai_webadmin_settings_submit" value="1" />
        <table class="form-table" role="presentation">
          <tr<?php echo ai_webadmin_tab_row_attrs($activeTab, ["integrations"]); ?>>
            <th scope="row"><label for="worker_base_url">Worker Base URL</label></th>
            <td><input name="worker_base_url" id="worker_base_url" type="url" class="regular-text" value="<?php echo esc_attr($settings["worker_base_url"]); ?>" /></td>
          </tr>
          <tr<?php echo ai_webadmin_tab_row_attrs($activeTab, ["integrations"]); ?>>
            <th scope="row"><label for="plugin_shared_secret">Plugin Shared Secret</label></th>
            <td>
              <input name="plugin_shared_secret" id="plugin_shared_secret" type="text" class="regular-text" value="<?php echo esc_attr($settings["plugin_shared_secret"]); ?>" />
              <p class="description">Create your own random value and paste the same value in Worker env var <code>WP_PLUGIN_SHARED_SECRET</code>. Worker does not auto-fill this field.</p>
            </td>
          </tr>
          <tr<?php echo ai_webadmin_tab_row_attrs($activeTab, ["integrations"]); ?>>
            <th scope="row"><label for="onboarding_session_id">Onboarding Session ID</label></th>
            <td>
              <input name="onboarding_session_id" id="onboarding_session_id" type="text" class="regular-text" value="<?php echo esc_attr($settings["onboarding_session_id"]); ?>" />
              <p class="description">Optional: link plugin telemetry to the same chat audit session.</p>
            </td>
          </tr>
          <tr<?php echo ai_webadmin_tab_row_attrs($activeTab, ["general"]); ?>>
            <th scope="row">Branding & Favicon</th>
            <td>
              <label><input name="branding_inject_favicon" type="checkbox" value="1" <?php checked((int)$settings["branding_inject_favicon"], 1); ?> /> Inject custom favicon on your site (front-end)</label><br/>
              <label for="branding_favicon_url">Favicon URL (PNG/SVG/ICO)</label><br/>
              <input name="branding_favicon_url" id="branding_favicon_url" type="url" class="regular-text" placeholder="https://cdn.example.com/favicon.png" value="<?php echo esc_attr((string)$settings["branding_favicon_url"]); ?>" /><br/>
              <label for="branding_admin_menu_icon_url">AI WebAdmin admin menu icon URL (optional)</label><br/>
              <input name="branding_admin_menu_icon_url" id="branding_admin_menu_icon_url" type="url" class="regular-text" placeholder="https://cdn.example.com/ai-webadmin-icon.svg" value="<?php echo esc_attr((string)$settings["branding_admin_menu_icon_url"]); ?>" />
              <p class="description">Leave menu icon URL blank to use the built-in AI WebAdmin orange icon. Set favicon to align your brand across browser tabs and generated demos.</p>
              <?php if ($brandingFaviconUrl !== ""): ?>
                <p style="margin-top:8px;">
                  <strong>Preview:</strong><br/>
                  <img src="<?php echo esc_url($brandingFaviconUrl); ?>" alt="Favicon preview" style="width:32px;height:32px;border:1px solid #dcdcde;border-radius:4px;background:#fff;padding:2px;" />
                </p>
              <?php endif; ?>
            </td>
          </tr>
          <tr<?php echo ai_webadmin_tab_row_attrs($activeTab, ["general"]); ?>>
            <th scope="row">Activation Status</th>
            <td>
              <?php if ($pluginActivated): ?>
                <p><strong>Active</strong> — all token and vault requirements are satisfied.</p>
              <?php else: ?>
                <p><strong>Locked</strong> — plugin features remain disabled until all required items are complete.</p>
                <ul>
                  <?php foreach ($missingActivation as $item): ?>
                    <li><?php echo esc_html((string)$item); ?></li>
                  <?php endforeach; ?>
                </ul>
                <p><a class="button" href="<?php echo $tokenGuideUrl; ?>" target="_blank" rel="noopener noreferrer">Open Full Token + Signup Guide</a></p>
              <?php endif; ?>
            </td>
          </tr>
          <tr<?php echo ai_webadmin_tab_row_attrs($activeTab, ["integrations"]); ?>>
            <th scope="row">Cloudflare Connection</th>
            <td>
              <label for="cloudflare_account_id">Cloudflare Account ID (optional)</label><br/>
              <input name="cloudflare_account_id" id="cloudflare_account_id" type="text" class="regular-text" value="<?php echo esc_attr((string)($settings["cloudflare_account_id"] ?? "")); ?>" /><br/>
              <label for="cloudflare_api_token">Cloudflare API Token (paste to verify/connect)</label><br/>
              <input name="cloudflare_api_token" id="cloudflare_api_token" type="password" class="regular-text" value="" autocomplete="new-password" />
              <p class="description">Paste token here and click Save. Token is sent to Worker for verification and not stored in plaintext in WordPress.</p>
              <p class="description"><a href="<?php echo $tokenGuideUrl; ?>" target="_blank" rel="noopener noreferrer">Open step-by-step token guide (with screenshots)</a></p>
              <p>
                Connection status:
                <?php if (!empty($settings["cloudflare_connected"])): ?>
                  <strong>Connected</strong>
                  <?php if (!empty($settings["cloudflare_token_masked"])): ?>
                    (<?php echo esc_html((string)$settings["cloudflare_token_masked"]); ?>)
                  <?php endif; ?>
                  <?php if (!empty($settings["cloudflare_last_connected_at"])): ?>
                    — last verified <?php echo esc_html(gmdate("Y-m-d H:i:s", (int)$settings["cloudflare_last_connected_at"])); ?> UTC
                  <?php endif; ?>
                <?php else: ?>
                  <strong>Not connected</strong>
                <?php endif; ?>
              </p>
              <?php if (!empty($settings["cloudflare_last_error"])): ?>
                <p class="description" style="color:#b32d2e;">Last error: <?php echo esc_html((string)$settings["cloudflare_last_error"]); ?></p>
              <?php endif; ?>
            </td>
          </tr>
          <tr<?php echo ai_webadmin_tab_row_attrs($activeTab, ["general"]); ?>>
            <th scope="row">Features</th>
            <td>
              <label><input name="enable_comment_moderation" type="checkbox" value="1" <?php checked((int)$settings["enable_comment_moderation"], 1); ?> /> Enable comment moderation via Worker</label><br/>
              <label><input name="enable_schema_injection" type="checkbox" value="1" <?php checked((int)$settings["enable_schema_injection"], 1); ?> /> Enable schema JSON-LD injection from chat profile</label><br/>
              <label><input name="enable_broken_link_redirects" type="checkbox" value="1" <?php checked((int)$settings["enable_broken_link_redirects"], 1); ?> /> Enable 301 fallback for audited broken internal links</label><br/>
              <label><input name="require_tolldns" type="checkbox" value="1" <?php checked((int)$settings["require_tolldns"], 1); ?> /> Require TollDNS (free tier requirement)</label>
            </td>
          </tr>
          <tr<?php echo ai_webadmin_tab_row_attrs($activeTab, ["integrations"]); ?>>
            <th scope="row">TollDNS Readiness</th>
            <td>
              <p>
                Status:
                <?php if ($tolldnsActive): ?>
                  <strong>Installed and active</strong>
                <?php else: ?>
                  <strong>Not installed</strong>
                <?php endif; ?>
              </p>
              <p>
                <a class="button button-secondary" href="<?php echo $tolldnsInstallUrl; ?>" target="_blank" rel="noopener noreferrer">Install TollDNS</a>
                <?php if ($tolldnsActive): ?>
                  <a class="button" href="<?php echo esc_url(admin_url("options-general.php?page=tolldns")); ?>">Open TollDNS Settings</a>
                <?php endif; ?>
              </p>
              <p class="description">TollDNS is required for free-tier activation. Install it, configure nameservers, and run a points check before Cloudflare verify.</p>
            </td>
          </tr>
          <tr<?php echo ai_webadmin_tab_row_attrs($activeTab, ["security"]); ?>>
            <th scope="row">Security Hardening</th>
            <td>
              <label><input name="enable_security_hardening" type="checkbox" value="1" <?php checked((int)$settings["enable_security_hardening"], 1); ?> /> Enable hardening controls</label><br/>
              <label><input name="disable_xmlrpc" type="checkbox" value="1" <?php checked((int)$settings["disable_xmlrpc"], 1); ?> /> Disable XML-RPC</label><br/>
              <label><input name="prevent_email_display_name" type="checkbox" value="1" <?php checked((int)$settings["prevent_email_display_name"], 1); ?> /> Prevent email addresses as display names</label><br/>
              <label><input name="enforce_single_admin" type="checkbox" value="1" <?php checked((int)$settings["enforce_single_admin"], 1); ?> /> Keep only one Administrator role (demote others to Editor)</label><br/>
              <label><input name="normalize_editor_generic_emails_to_admin" type="checkbox" value="1" <?php checked((int)$settings["normalize_editor_generic_emails_to_admin"], 1); ?> /> For Google Workspace sites, normalize generic Editor emails (like wordpress@domain) to admin mailbox aliases</label><br/>
              <label><input name="block_file_manager_plugins" type="checkbox" value="1" <?php checked((int)$settings["block_file_manager_plugins"], 1); ?> /> Block risky file-manager plugins</label><br/>
              <label><input name="enable_login_rate_limit" type="checkbox" value="1" <?php checked((int)$settings["enable_login_rate_limit"], 1); ?> /> Limit brute-force login attempts</label><br/>
              <label><input name="enforce_admin_sso" type="checkbox" value="1" <?php checked((int)$settings["enforce_admin_sso"], 1); ?> /> Require SSO header for Administrator logins (non-admin password login remains enabled)</label><br/>
              <label><input name="apply_htaccess_hardening" type="checkbox" value="1" <?php checked((int)$settings["apply_htaccess_hardening"], 1); ?> /> Apply Apache/LiteSpeed `.htaccess` hardening rules</label>
            </td>
          </tr>
          <tr<?php echo ai_webadmin_tab_row_attrs($activeTab, ["security"]); ?>>
            <th scope="row">Login Throttle</th>
            <td>
              <label for="login_rate_limit_attempts">Max attempts</label>
              <input name="login_rate_limit_attempts" id="login_rate_limit_attempts" type="number" min="3" max="20" value="<?php echo esc_attr((string)$settings["login_rate_limit_attempts"]); ?>" />
              <label for="login_rate_limit_window_minutes">Window (minutes)</label>
              <input name="login_rate_limit_window_minutes" id="login_rate_limit_window_minutes" type="number" min="1" max="60" value="<?php echo esc_attr((string)$settings["login_rate_limit_window_minutes"]); ?>" />
              <label for="login_rate_limit_lockout_minutes">Lockout (minutes)</label>
              <input name="login_rate_limit_lockout_minutes" id="login_rate_limit_lockout_minutes" type="number" min="1" max="240" value="<?php echo esc_attr((string)$settings["login_rate_limit_lockout_minutes"]); ?>" />
            </td>
          </tr>
          <tr<?php echo ai_webadmin_tab_row_attrs($activeTab, ["security"]); ?>>
            <th scope="row"><label for="admin_sso_header_name">Admin SSO Header</label></th>
            <td>
              <input name="admin_sso_header_name" id="admin_sso_header_name" type="text" class="regular-text" value="<?php echo esc_attr($settings["admin_sso_header_name"]); ?>" />
              <p class="description">Default for Cloudflare Access: <code>CF-Access-Authenticated-User-Email</code>.</p>
            </td>
          </tr>
          <tr<?php echo ai_webadmin_tab_row_attrs($activeTab, ["security"]); ?>>
            <th scope="row">Unlock Options</th>
            <td>
              <label><input name="require_admin_unlock_factor" type="checkbox" value="1" <?php checked((int)$settings["require_admin_unlock_factor"], 1); ?> /> Force Administrator login to use at least one unlock factor (passcode, passkey, or wallet signature)</label><br/>
              <label><input name="enable_passcode_unlock" type="checkbox" value="1" <?php checked((int)$settings["enable_passcode_unlock"], 1); ?> /> Require passcode unlock on login</label><br/>
              <label><input name="require_hardware_key_unlock" type="checkbox" value="1" <?php checked((int)$settings["require_hardware_key_unlock"], 1); ?> /> Require hardware key/passkey verification (WebAuthn integration)</label><br/>
              <label><input name="require_wallet_signature_unlock" type="checkbox" value="1" <?php checked((int)$settings["require_wallet_signature_unlock"], 1); ?> /> Require Web3 wallet signature unlock</label>
            </td>
          </tr>
          <tr<?php echo ai_webadmin_tab_row_attrs($activeTab, ["security"]); ?>>
            <th scope="row">Passcode Unlock</th>
            <td>
              <label for="unlock_passcode">New passcode (leave blank to keep current)</label><br/>
              <input name="unlock_passcode" id="unlock_passcode" type="password" class="regular-text" value="" autocomplete="new-password" /><br/>
              <label><input name="clear_unlock_passcode" type="checkbox" value="1" /> Clear saved passcode</label>
            </td>
          </tr>
          <tr<?php echo ai_webadmin_tab_row_attrs($activeTab, ["security"]); ?>>
            <th scope="row">Wallet Unlock</th>
            <td>
              <label for="wallet_unlock_message_prefix">Challenge message prefix</label><br/>
              <input name="wallet_unlock_message_prefix" id="wallet_unlock_message_prefix" type="text" class="regular-text" value="<?php echo esc_attr($settings["wallet_unlock_message_prefix"]); ?>" /><br/>
              <label for="wallet_unlock_chain_id">Chain ID</label>
              <input name="wallet_unlock_chain_id" id="wallet_unlock_chain_id" type="number" min="1" max="999999" value="<?php echo esc_attr((string)$settings["wallet_unlock_chain_id"]); ?>" />
              <label for="wallet_unlock_nonce_ttl_minutes">Nonce TTL (minutes)</label>
              <input name="wallet_unlock_nonce_ttl_minutes" id="wallet_unlock_nonce_ttl_minutes" type="number" min="3" max="30" value="<?php echo esc_attr((string)$settings["wallet_unlock_nonce_ttl_minutes"]); ?>" />
              <p class="description">Wallet verification is validated by Worker endpoint <code>/plugin/wp/auth/wallet/verify</code>.</p>
            </td>
          </tr>
          <tr<?php echo ai_webadmin_tab_row_attrs($activeTab, ["sandbox"]); ?>>
            <th scope="row">Sandbox Dry-Run</th>
            <td>
              <label><input name="sandbox_dry_run_enabled" type="checkbox" value="1" <?php checked((int)$settings["sandbox_dry_run_enabled"], 1); ?> /> Enable non-persistent sandbox preflight checks before real plugin updates</label>
              <p>Outdated plugins detected right now: <strong><?php echo esc_html((string)(int)$sandboxOutdatedCount); ?></strong></p>
              <p>
                Site Kit tracking coverage: <strong>
                <?php
                    $siteKitActive = !empty($sandboxMetrics["analytics_site_kit_active"]);
                    $coverage = isset($sandboxMetrics["analytics_tag_coverage_percent"]) && $sandboxMetrics["analytics_tag_coverage_percent"] !== null
                        ? (int)$sandboxMetrics["analytics_tag_coverage_percent"]
                        : null;
                    $checkedCount = (int)($sandboxMetrics["analytics_pages_checked_count"] ?? 0);
                    if (!$siteKitActive) {
                        echo "Site Kit not active";
                    } elseif ($coverage === null) {
                        echo "not available";
                    } else {
                        echo esc_html((string)$coverage . "% across " . (string)$checkedCount . " page(s)");
                    }
                ?>
                </strong><br/>
                High-risk active plugins: <strong><?php echo esc_html((string)(int)($sandboxMetrics["high_risk_plugin_count"] ?? 0)); ?></strong>,
                medium-risk active plugins: <strong><?php echo esc_html((string)(int)($sandboxMetrics["medium_risk_plugin_count"] ?? 0)); ?></strong>.
                <?php
                    $wooActive = !empty($sandboxMetrics["woocommerce_active"]);
                    $wooProducts = (int)($sandboxMetrics["woocommerce_product_count"] ?? 0);
                    $wooCompleted = (int)($sandboxMetrics["woocommerce_completed_order_count"] ?? 0);
                    $wooStaleDays = isset($sandboxMetrics["woocommerce_sales_stale_days"]) && $sandboxMetrics["woocommerce_sales_stale_days"] !== null
                        ? (int)$sandboxMetrics["woocommerce_sales_stale_days"]
                        : null;
                ?>
                <?php if ($wooActive): ?>
                  <br/>WooCommerce snapshot: <strong><?php echo esc_html((string)$wooProducts); ?></strong> product(s), <strong><?php echo esc_html((string)$wooCompleted); ?></strong> completed sale(s).
                  <?php if ($wooProducts > 0 && $wooCompleted === 0): ?>
                    <br/><strong>Store signal:</strong> products exist but no completed sales detected. Consider refreshing product strategy or removing affiliate/store features to streamline the site.
                  <?php elseif ($wooStaleDays !== null && $wooStaleDays >= 365): ?>
                    <br/><strong>Store signal:</strong> last completed sale appears <?php echo esc_html((string)$wooStaleDays); ?> day(s) ago. Consider product refresh or removing low-performing store features.
                  <?php endif; ?>
                <?php endif; ?>
              </p>
              <p>
                Last run: <strong><?php echo esc_html(ai_webadmin_format_utc_timestamp((int)($settings["sandbox_last_run_at"] ?? 0))); ?></strong><br/>
                Last status: <strong><?php echo esc_html((string)($settings["sandbox_last_status"] ?: "not_run")); ?></strong><br/>
                Last risk level: <strong><?php echo esc_html((string)($settings["sandbox_last_risk_level"] ?: "n/a")); ?></strong><br/>
                Last report id: <strong><?php echo esc_html((string)($settings["sandbox_last_report_id"] ?: "n/a")); ?></strong><br/>
                Last summary: <?php echo esc_html((string)($settings["sandbox_last_message"] ?: "No sandbox preflight has run yet.")); ?>
              </p>
              <p>
                <button type="submit" name="ai_webadmin_run_sandbox_preflight_now" class="button button-secondary">Run Sandbox Preflight Now</button>
              </p>
              <?php if (!empty($sandboxOutdatedPlugins)): ?>
                <details>
                  <summary>Preview outdated plugins to test in sandbox</summary>
                  <ul style="margin-top:8px;">
                    <?php foreach ($sandboxOutdatedPlugins as $item): ?>
                      <li><?php echo esc_html((string)($item["name"] ?? $item["plugin_file"] ?? "plugin")); ?> — <?php echo esc_html((string)($item["current_version"] ?? "")); ?> → <?php echo esc_html((string)($item["new_version"] ?? "")); ?></li>
                    <?php endforeach; ?>
                  </ul>
                </details>
              <?php endif; ?>
              <?php
                $riskCandidates = isset($sandboxMetrics["plugin_inventory"]["risk_candidates"]) && is_array($sandboxMetrics["plugin_inventory"]["risk_candidates"])
                    ? array_slice($sandboxMetrics["plugin_inventory"]["risk_candidates"], 0, 10)
                    : [];
              ?>
              <?php if (!empty($riskCandidates)): ?>
                <details style="margin-top:8px;">
                  <summary>Top active plugin risk candidates (sandbox test first)</summary>
                  <ul style="margin-top:8px;">
                    <?php foreach ($riskCandidates as $candidate): ?>
                      <?php
                        $cName = sanitize_text_field((string)($candidate["name"] ?? $candidate["slug"] ?? "plugin"));
                        $cLevel = sanitize_text_field((string)($candidate["risk_level"] ?? "medium"));
                        $cScore = (int)($candidate["risk_score"] ?? 0);
                        $cReason = "";
                        if (isset($candidate["reasons"][0])) {
                            $cReason = sanitize_text_field((string)$candidate["reasons"][0]);
                        }
                      ?>
                      <li>
                        <?php echo esc_html($cName); ?> — <?php echo esc_html($cLevel); ?> risk (score <?php echo esc_html((string)$cScore); ?>)
                        <?php if ($cReason !== ""): ?>
                          : <?php echo esc_html($cReason); ?>
                        <?php endif; ?>
                      </li>
                    <?php endforeach; ?>
                  </ul>
                </details>
              <?php endif; ?>
            </td>
          </tr>
          <tr<?php echo ai_webadmin_tab_row_attrs($activeTab, ["sandbox"]); ?>>
            <th scope="row">Upload Secrets To Worker Vault</th>
            <td>
              <p class="description">Paste secrets below, then click upload. Secrets are encrypted by Worker and stored outside WordPress plaintext.</p>
              <label for="vault_cloudflare_api_token">Cloudflare API Token</label><br/>
              <input name="vault_cloudflare_api_token" id="vault_cloudflare_api_token" type="password" class="regular-text" value="" autocomplete="new-password" /><br/>
              <label for="vault_github_token">GitHub Fine-Grained Token (or classic token)</label><br/>
              <input name="vault_github_token" id="vault_github_token" type="password" class="regular-text" value="" autocomplete="new-password" /><br/>
              <label for="vault_hosting_provider_token">Hosting Provider API Token (optional)</label><br/>
              <input name="vault_hosting_provider_token" id="vault_hosting_provider_token" type="password" class="regular-text" value="" autocomplete="new-password" /><br/>
              <label for="vault_openai_api_token">OpenAI API Key (for AI metadata and AI assistant features)</label><br/>
              <input name="vault_openai_api_token" id="vault_openai_api_token" type="password" class="regular-text" value="" autocomplete="new-password" />
              <p>
                Last vault upload: <strong><?php echo esc_html(ai_webadmin_format_utc_timestamp((int)($settings["worker_secret_vault_last_at"] ?? 0))); ?></strong><br/>
                Vault status: <strong><?php echo esc_html((string)($settings["worker_secret_vault_last_status"] ?: "not_uploaded")); ?></strong><br/>
                Vault message: <?php echo esc_html((string)($settings["worker_secret_vault_last_message"] ?: "No upload yet.")); ?><br/>
                Cloudflare token: <strong><?php echo esc_html((string)($settings["worker_secret_cloudflare_masked"] ?: "not_uploaded")); ?></strong><br/>
                GitHub token: <strong><?php echo esc_html((string)($settings["worker_secret_github_masked"] ?: "not_uploaded")); ?></strong><br/>
                Hosting token: <strong><?php echo esc_html((string)($settings["worker_secret_hosting_masked"] ?: "not_uploaded")); ?></strong><br/>
                OpenAI key: <strong><?php echo esc_html((string)($settings["worker_secret_openai_masked"] ?: "not_uploaded")); ?></strong>
              </p>
              <p>
                <button type="submit" name="ai_webadmin_upload_secrets_now" class="button button-secondary">Upload Secrets To Worker Vault</button>
                <a class="button" href="<?php echo $tokenGuideUrl; ?>" target="_blank" rel="noopener noreferrer">Token Guide (Screenshots)</a>
              </p>
            </td>
          </tr>
          <tr<?php echo ai_webadmin_tab_row_attrs($activeTab, ["automation"]); ?>>
            <th scope="row">Email Forwarding</th>
            <td>
              <label><input name="enable_email_forwarding_via_worker" type="checkbox" value="1" <?php checked((int)$settings["enable_email_forwarding_via_worker"], 1); ?> /> Forward lead-form emails through Cloudflare Worker</label><br/>
              <label><input name="remove_smtp_plugins" type="checkbox" value="1" <?php checked((int)$settings["remove_smtp_plugins"], 1); ?> /> Remove SMTP/email plugins automatically</label><br/>
              <label><input name="suppress_local_lead_mail" type="checkbox" value="1" <?php checked((int)$settings["suppress_local_lead_mail"], 1); ?> /> Suppress local lead-email delivery after Worker accepts the event</label><br/>
              <label for="lead_forward_email">Lead forward destination email (defaults to primary admin)</label><br/>
              <input name="lead_forward_email" id="lead_forward_email" type="email" class="regular-text" value="<?php echo esc_attr((string)$settings["lead_forward_email"]); ?>" />
              <p class="description">If your domain already has MX records, we still sync MX/provider hints so Worker routing can hand off to webhook-based forwarding.</p>
              <p>
                Verification status:
                <strong><?php echo esc_html((string)($settings["lead_forward_verification_status"] ?: "not_started")); ?></strong><br/>
                Verification email: <strong><?php echo esc_html((string)($settings["lead_forward_verification_email"] ?: "not_set")); ?></strong><br/>
                Verification sent: <strong><?php echo esc_html(ai_webadmin_format_utc_timestamp((int)($settings["lead_forward_verification_sent_at"] ?? 0))); ?></strong><br/>
                Verified at: <strong><?php echo esc_html(ai_webadmin_format_utc_timestamp((int)($settings["lead_forward_verification_confirmed_at"] ?? 0))); ?></strong>
                <?php if (!empty($settings["lead_forward_verification_last_error"])): ?>
                  <br/>Last verification error: <strong><?php echo esc_html((string)$settings["lead_forward_verification_last_error"]); ?></strong>
                <?php endif; ?>
                <?php if (!empty($settings["lead_forward_verification_last_link_url"])): ?>
                  <br/>Last verification link: <a href="<?php echo esc_url((string)$settings["lead_forward_verification_last_link_url"]); ?>" target="_blank" rel="noopener noreferrer">Open</a>
                <?php endif; ?>
              </p>
              <p>
                <button type="submit" name="ai_webadmin_send_lead_forward_verification_email" class="button button-secondary">Send Verification Email</button>
                <button type="submit" name="ai_webadmin_refresh_lead_forward_verification" class="button button-secondary">Refresh Verification Status</button>
              </p>
              <p class="description">
                Safety gate: local WordPress lead emails are only suppressed after verification status is <strong>verified</strong>. Until then, your old email delivery path stays active.
              </p>
            </td>
          </tr>
          <tr<?php echo ai_webadmin_tab_row_attrs($activeTab, ["automation"]); ?>>
            <th scope="row">Plugin/User Cleanup</th>
            <td>
              <label><input name="enable_plugin_rationalization" type="checkbox" value="1" <?php checked((int)$settings["enable_plugin_rationalization"], 1); ?> /> Audit plugin inventory and flag unneeded/lazy installs</label><br/>
              <label><input name="license_hygiene_enabled" type="checkbox" value="1" <?php checked((int)$settings["license_hygiene_enabled"], 1); ?> /> Detect and remove canceled/suspicious website-builder license records</label><br/>
              <label for="license_expected_email">Expected license email (optional override)</label><br/>
              <input name="license_expected_email" id="license_expected_email" type="email" class="regular-text" value="<?php echo esc_attr($licenseExpectedEmail); ?>" /><br/>
              <label><input name="remove_migration_replication_plugins" type="checkbox" value="1" <?php checked((int)$settings["remove_migration_replication_plugins"], 1); ?> /> Remove migration/DB replication plugins automatically</label><br/>
              <label><input name="auto_remove_failed_static_export_plugins" type="checkbox" value="1" <?php checked((int)$settings["auto_remove_failed_static_export_plugins"], 1); ?> /> Auto-remove failed static-export plugins after memory-limit errors</label><br/>
              <label><input name="auto_uninstall_inactive_plugins" type="checkbox" value="1" <?php checked((int)$settings["auto_uninstall_inactive_plugins"], 1); ?> /> Auto-uninstall inactive plugins (safe mode)</label><br/>
              <label><input name="auto_uninstall_inactive_themes" type="checkbox" value="1" <?php checked((int)$settings["auto_uninstall_inactive_themes"], 1); ?> /> Auto-uninstall inactive themes (safe mode)</label><br/>
              <label><input name="enable_inactive_user_cleanup" type="checkbox" value="1" <?php checked((int)$settings["enable_inactive_user_cleanup"], 1); ?> /> Delete users with no login for over N days</label>
              <p class="description">
                Static-export guardrail status: <strong><?php echo esc_html((string)($settings["static_export_last_status"] ?: "not_run")); ?></strong>
                <?php if (!empty($settings["static_export_last_error_at"])): ?>
                  (<?php echo esc_html(ai_webadmin_format_utc_timestamp((int)$settings["static_export_last_error_at"])); ?>)
                <?php endif; ?>
                <?php if (!empty($settings["static_export_last_error_message"])): ?>
                  <br/>Last error: <?php echo esc_html((string)$settings["static_export_last_error_message"]); ?>
                <?php endif; ?>
              </p>
            </td>
          </tr>
          <tr<?php echo ai_webadmin_tab_row_attrs($activeTab, ["automation"]); ?>>
            <th scope="row">Media Offload To R2</th>
            <td>
              <label><input name="enable_media_r2_offload" type="checkbox" value="1" <?php checked((int)$settings["enable_media_r2_offload"], 1); ?> /> Enable image offload from WordPress media library to R2</label><br/>
              <label><input name="media_rewrite_attachment_urls" type="checkbox" value="1" <?php checked((int)$settings["media_rewrite_attachment_urls"], 1); ?> /> Serve offloaded media URLs from R2/CDN in WordPress</label><br/>
              <label><input name="media_seo_autofill_enabled" type="checkbox" value="1" <?php checked((int)$settings["media_seo_autofill_enabled"], 1); ?> /> Auto-generate filename slug + Alt/Title/Caption/Description for each image</label><br/>
              <label><input name="media_ai_enrichment_enabled" type="checkbox" value="1" <?php checked((int)$settings["media_ai_enrichment_enabled"], 1); ?> /> Use OpenAI image analysis to generate media metadata (title/alt/caption/description)</label><br/>
              <label><input name="media_force_metadata_refresh" type="checkbox" value="1" <?php checked((int)$settings["media_force_metadata_refresh"], 1); ?> /> Force metadata rewrite every pass (recommended for cleanup migrations)</label><br/>
              <label><input name="media_assign_to_primary_admin" type="checkbox" value="1" <?php checked((int)$settings["media_assign_to_primary_admin"], 1); ?> /> Reassign attachment author to primary Administrator account</label><br/>
              <label><input name="media_optimize_images" type="checkbox" value="1" <?php checked((int)$settings["media_optimize_images"], 1); ?> /> Optimize image dimensions/quality before offload</label><br/>
              <label for="media_public_base_url">Media public base URL (R2 custom domain or CDN)</label><br/>
              <input name="media_public_base_url" id="media_public_base_url" type="url" class="regular-text" placeholder="https://media.example.com" value="<?php echo esc_attr((string)($settings["media_public_base_url"] ?? "")); ?>" /><br/>
              <label for="media_offload_batch_size">Batch size per run</label>
              <input name="media_offload_batch_size" id="media_offload_batch_size" type="number" min="5" max="100" value="<?php echo esc_attr((string)$settings["media_offload_batch_size"]); ?>" />
              <br/><label for="media_max_dimension_px">Max image dimension (pixels)</label>
              <input name="media_max_dimension_px" id="media_max_dimension_px" type="number" min="640" max="4096" value="<?php echo esc_attr((string)$settings["media_max_dimension_px"]); ?>" />
              <label for="media_image_quality">Image quality (40-95)</label>
              <input name="media_image_quality" id="media_image_quality" type="number" min="40" max="95" value="<?php echo esc_attr((string)$settings["media_image_quality"]); ?>" />
              <label for="media_target_max_bytes">Target max bytes per image</label>
              <input name="media_target_max_bytes" id="media_target_max_bytes" type="number" min="262144" max="20971520" step="1024" value="<?php echo esc_attr((string)$settings["media_target_max_bytes"]); ?>" />
              <p class="description">Each run processes the next image attachments, applies SEO metadata + optimization, writes to R2, and maps attachment URLs to your media base URL (example: https://media.rail.golf). You can also use the per-image "AI Optimize + Offload to R2" action directly inside Media Library rows.</p>
            </td>
          </tr>
          <tr<?php echo ai_webadmin_tab_row_attrs($activeTab, ["automation"]); ?>>
            <th scope="row">Inactive Plugin Uninstall</th>
            <td>
              <label for="inactive_plugin_delete_limit">Delete limit per run</label>
              <input name="inactive_plugin_delete_limit" id="inactive_plugin_delete_limit" type="number" min="1" max="100" value="<?php echo esc_attr((string)$settings["inactive_plugin_delete_limit"]); ?>" />
              <p class="description">Guardrail: limits how many inactive plugins are removed on each pass.</p>
              <label for="inactive_plugin_protected_slugs">Protected plugin slugs (one per line)</label><br/>
              <textarea name="inactive_plugin_protected_slugs" id="inactive_plugin_protected_slugs" rows="4" class="large-text code"><?php echo esc_textarea((string)$settings["inactive_plugin_protected_slugs"]); ?></textarea>
              <p class="description">Protected slugs are never auto-uninstalled even if inactive.</p>
            </td>
          </tr>
          <tr<?php echo ai_webadmin_tab_row_attrs($activeTab, ["automation"]); ?>>
            <th scope="row">Inactive User Cleanup</th>
            <td>
              <label for="inactive_user_days">Inactive for (days)</label>
              <input name="inactive_user_days" id="inactive_user_days" type="number" min="30" max="3650" value="<?php echo esc_attr((string)$settings["inactive_user_days"]); ?>" />
              <label for="inactive_user_delete_limit">Delete limit per run</label>
              <input name="inactive_user_delete_limit" id="inactive_user_delete_limit" type="number" min="1" max="500" value="<?php echo esc_attr((string)$settings["inactive_user_delete_limit"]); ?>" />
              <p class="description">Primary admin is protected. Other admin users are handled by single-admin enforcement.</p>
            </td>
          </tr>
          <tr<?php echo ai_webadmin_tab_row_attrs($activeTab, ["automation"]); ?>>
            <th scope="row">Inactive Theme Uninstall</th>
            <td>
              <label for="inactive_theme_delete_limit">Delete limit per run</label>
              <input name="inactive_theme_delete_limit" id="inactive_theme_delete_limit" type="number" min="1" max="20" value="<?php echo esc_attr((string)$settings["inactive_theme_delete_limit"]); ?>" />
              <p class="description">Guardrail: limits how many inactive themes are removed on each pass.</p>
              <label for="inactive_theme_protected_slugs">Protected theme slugs (one per line)</label><br/>
              <textarea name="inactive_theme_protected_slugs" id="inactive_theme_protected_slugs" rows="3" class="large-text code"><?php echo esc_textarea((string)$settings["inactive_theme_protected_slugs"]); ?></textarea>
              <p class="description">Active theme and child/parent template are protected automatically.</p>
            </td>
          </tr>
          <tr<?php echo ai_webadmin_tab_row_attrs($activeTab, ["automation"]); ?>>
            <th scope="row">GitHub Backup Gateway</th>
            <td>
              <label><input name="github_backup_enabled" type="checkbox" value="1" <?php checked((int)$settings["github_backup_enabled"], 1); ?> /> Enable daily worker snapshot backups</label><br/>
              <label for="github_backup_repo">Repo (owner/repo)</label><br/>
              <input name="github_backup_repo" id="github_backup_repo" type="text" class="regular-text" placeholder="owner/repo" value="<?php echo esc_attr($settings["github_backup_repo"]); ?>" /><br/>
              <label for="github_backup_branch">Branch</label>
              <input name="github_backup_branch" id="github_backup_branch" type="text" value="<?php echo esc_attr($settings["github_backup_branch"]); ?>" />
              <label for="github_backup_manifest_max_files">Max files in snapshot manifest</label>
              <input name="github_backup_manifest_max_files" id="github_backup_manifest_max_files" type="number" min="500" max="12000" value="<?php echo esc_attr((string)$settings["github_backup_manifest_max_files"]); ?>" /><br/>
              <label for="github_classic_token">GitHub fine-grained or classic token (submitted to Worker vault, not stored in WP)</label><br/>
              <input name="github_classic_token" id="github_classic_token" type="password" class="regular-text" value="" autocomplete="new-password" />
              <p class="description">Use a classic token with repo write access. We send it to Cloudflare Worker vault and store only masked status in WordPress.</p>
              <p>
                Vault status:
                <?php if (!empty($settings["github_vault_connected"])): ?>
                  <strong>Connected</strong>
                  <?php if (!empty($settings["github_vault_token_masked"])): ?>
                    (<?php echo esc_html($settings["github_vault_token_masked"]); ?>)
                  <?php endif; ?>
                <?php else: ?>
                  <strong>Not connected</strong>
                <?php endif; ?>
              </p>
            </td>
          </tr>
          <tr<?php echo ai_webadmin_tab_row_attrs($activeTab, ["automation"]); ?>>
            <th scope="row"><label for="github_signup_url">GitHub Signup URL</label></th>
            <td>
              <input name="github_signup_url" id="github_signup_url" type="url" class="regular-text" value="<?php echo esc_attr($settings["github_signup_url"]); ?>" />
              <p class="description">Shown as a recommended step for sandbox backups before plugin/theme updates.</p>
              <?php if (!empty($settings["github_signup_url"])): ?>
                <p><a class="button" href="<?php echo esc_url($settings["github_signup_url"]); ?>" target="_blank" rel="noopener noreferrer">Sign up for GitHub</a></p>
              <?php endif; ?>
            </td>
          </tr>
          <tr<?php echo ai_webadmin_tab_row_attrs($activeTab, ["seo"]); ?>>
            <th scope="row">SEO Profile</th>
            <td>
              <p class="description">Define your core keyword and location targets so AI-generated schema/content stays consistent.</p>
              <label for="seo_primary_keywords">Primary keywords (one per line)</label><br/>
              <textarea name="seo_primary_keywords" id="seo_primary_keywords" rows="4" class="large-text"><?php echo esc_textarea($seoPrimaryKeywords); ?></textarea><br/>
              <label for="seo_secondary_keywords">Secondary/supporting keywords</label><br/>
              <textarea name="seo_secondary_keywords" id="seo_secondary_keywords" rows="4" class="large-text"><?php echo esc_textarea($seoSecondaryKeywords); ?></textarea><br/>
              <label for="seo_target_locations">Target locations (city/region, one per line)</label><br/>
              <textarea name="seo_target_locations" id="seo_target_locations" rows="3" class="large-text"><?php echo esc_textarea($seoTargetLocations); ?></textarea><br/>
              <label for="seo_offer_summary">Offer summary (what you sell / unique value)</label><br/>
              <textarea name="seo_offer_summary" id="seo_offer_summary" rows="3" class="large-text"><?php echo esc_textarea($seoOfferSummary); ?></textarea><br/>
              <label for="seo_brand_voice">Brand voice</label>
              <input name="seo_brand_voice" id="seo_brand_voice" type="text" class="regular-text" placeholder="e.g. premium, friendly, technical" value="<?php echo esc_attr($seoBrandVoice); ?>" />
              <p class="description">Last SEO profile update: <strong><?php echo esc_html(ai_webadmin_format_utc_timestamp($seoLastUpdatedAt)); ?></strong></p>
            </td>
          </tr>
          <tr<?php echo ai_webadmin_tab_row_attrs($activeTab, ["audit"]); ?>>
            <th scope="row">Audit, Caching & Monitoring</th>
            <td>
              <p class="description">Use this tab to run live checks, refresh cached profiles, and benchmark your current site performance baseline.</p>
              <div class="ai-webadmin-metric-grid">
                <div class="ai-webadmin-card">
                  <h4>Audit Snapshot (Now)</h4>
                  <p>Outdated plugins: <strong><?php echo esc_html((string)(int)($auditMetrics["outdated_plugin_count"] ?? 0)); ?></strong></p>
                  <p>Inactive plugins: <strong><?php echo esc_html((string)(int)($auditMetrics["inactive_plugin_count"] ?? 0)); ?></strong></p>
                  <p>Pending comments: <strong><?php echo esc_html((string)(int)($auditMetrics["pending_comment_moderation_count"] ?? 0)); ?></strong></p>
                  <p>Redundant plugins: <strong><?php echo esc_html((string)(int)($auditMetrics["redundant_plugin_count"] ?? 0)); ?></strong></p>
                </div>
                <div class="ai-webadmin-card">
                  <h4>Caching Signals</h4>
                  <p>Schema cache synced: <strong><?php echo esc_html(ai_webadmin_format_utc_timestamp($schemaSyncedAt)); ?></strong></p>
                  <p>Redirect cache synced: <strong><?php echo esc_html(ai_webadmin_format_utc_timestamp($redirectSyncedAt)); ?></strong></p>
                  <p>Object cache: <strong><?php echo $objectCacheEnabled ? "Enabled" : "Disabled"; ?></strong></p>
                  <p>Plugin update metadata cache: <strong><?php echo $updateMetaVersion !== "" ? "v" . esc_html($updateMetaVersion) : "Not cached yet"; ?></strong></p>
                </div>
                <div class="ai-webadmin-card">
                  <h4>Page Cache Health</h4>
                  <?php
                    $cacheHealthStatus = sanitize_text_field((string)($pageCacheHealthSnapshot["status"] ?? "unknown"));
                    $cacheHealthLabel = strtoupper($cacheHealthStatus !== "" ? $cacheHealthStatus : "unknown");
                    $cacheMedianTtfb = isset($pageCacheHealthSnapshot["median_ttfb_ms"]) && $pageCacheHealthSnapshot["median_ttfb_ms"] !== null
                        ? (int)$pageCacheHealthSnapshot["median_ttfb_ms"]
                        : null;
                    $cacheHeaderDetected = !empty($pageCacheHealthSnapshot["header_detected"]);
                    $cacheHeaderNames = isset($pageCacheHealthSnapshot["header_names"]) && is_array($pageCacheHealthSnapshot["header_names"])
                        ? array_slice(array_map("sanitize_text_field", $pageCacheHealthSnapshot["header_names"]), 0, 4)
                        : [];
                  ?>
                  <p>Built-in page cache: <strong><?php echo !empty($settings["enable_builtin_page_cache"]) ? "Enabled" : "Disabled"; ?></strong></p>
                  <p>Health status: <strong><?php echo esc_html($cacheHealthLabel); ?></strong></p>
                  <p>Median server response: <strong><?php echo $cacheMedianTtfb !== null ? esc_html((string)$cacheMedianTtfb . " ms") : "unknown"; ?></strong></p>
                  <p>Caching headers detected: <strong><?php echo $cacheHeaderDetected ? "Yes" : "No"; ?></strong></p>
                  <?php if (!empty($cacheHeaderNames)): ?>
                    <p>Header sample: <strong><?php echo esc_html(implode(", ", $cacheHeaderNames)); ?></strong></p>
                  <?php endif; ?>
                  <p>Last cache clear: <strong><?php echo esc_html(ai_webadmin_format_utc_timestamp((int)($settings["page_cache_last_cleared_at"] ?? 0))); ?></strong></p>
                </div>
                <div class="ai-webadmin-card">
                  <h4>Autoload Options Health</h4>
                  <?php
                    $autoloadCount = isset($autoloadStats["autoload_option_count"]) ? max(0, (int)$autoloadStats["autoload_option_count"]) : 0;
                    $autoloadBytes = isset($autoloadStats["autoload_total_bytes"]) ? max(0, (int)$autoloadStats["autoload_total_bytes"]) : 0;
                    $autoloadKb = (int)round($autoloadBytes / 1024);
                    $autoloadStatus = "Good";
                    if ($autoloadKb >= 1200 || $autoloadCount >= 1200) {
                        $autoloadStatus = "Critical";
                    } elseif ($autoloadKb >= 800 || $autoloadCount >= 800) {
                        $autoloadStatus = "Warning";
                    }
                    $autoloadTopOptions = isset($autoloadStats["autoload_top_options"]) && is_array($autoloadStats["autoload_top_options"])
                        ? array_slice($autoloadStats["autoload_top_options"], 0, 3)
                        : [];
                  ?>
                  <p>Autoload status: <strong><?php echo esc_html($autoloadStatus); ?></strong></p>
                  <p>Autoload option count: <strong><?php echo esc_html((string)$autoloadCount); ?></strong></p>
                  <p>Total autoload size: <strong><?php echo esc_html((string)$autoloadKb); ?> KB</strong></p>
                  <p>Last cleanup run: <strong><?php echo esc_html(ai_webadmin_format_utc_timestamp((int)($settings["autoload_last_cleanup_at"] ?? 0))); ?></strong></p>
                  <?php if (!empty($autoloadTopOptions)): ?>
                    <p>Largest autoload entries:</p>
                    <ul style="margin:0 0 0 18px;">
                      <?php foreach ($autoloadTopOptions as $opt): ?>
                        <?php if (!is_array($opt)) continue; ?>
                        <li><code><?php echo esc_html((string)($opt["name"] ?? "")); ?></code> (<?php echo esc_html((string)max(0, (int)($opt["bytes"] ?? 0))); ?> bytes)</li>
                      <?php endforeach; ?>
                    </ul>
                  <?php endif; ?>
                </div>
                <div class="ai-webadmin-card">
                  <h4>VPS + Cache Upsells</h4>
                  <?php
                    $tolldnsPaidEvents24h = is_array($tolldnsSummary) ? max(0, (int)($tolldnsSummary["paid_toll_events_24h"] ?? 0)) : 0;
                    $tolldnsOwnerPoints24h = is_array($tolldnsSummary) ? (int)($tolldnsSummary["owner_points_from_paid_tolls_24h"] ?? 0) : 0;
                  ?>
                  <p>TollDNS installed: <strong><?php echo $tolldnsActive ? "Yes" : "No"; ?></strong></p>
                  <p>TollDNS points balance: <strong><?php echo esc_html((string)$tolldnsPointsTotal); ?></strong></p>
                  <p>Paid-toll visitors (24h): <strong><?php echo esc_html((string)$tolldnsPaidEvents24h); ?></strong></p>
                  <p>Owner points earned from paid tolls (24h): <strong><?php echo esc_html((string)$tolldnsOwnerPoints24h); ?></strong></p>
                  <p>Approx. points value: <strong>$<?php echo esc_html(number_format((float)$tolldnsUsdApprox, 2)); ?></strong></p>
                  <p>VPS upgrade points cost: <strong><?php echo esc_html((string)$tolldnsVpsCost); ?></strong></p>
                  <p>Cache accelerator points cost: <strong><?php echo esc_html((string)$tolldnsCacheCost); ?></strong></p>
                  <p>
                    <a class="button button-secondary" href="<?php echo $vpsUpgradeUrl; ?>" target="_blank" rel="noopener noreferrer">View VPS Upgrade</a>
                    <a class="button button-secondary" href="<?php echo $cacheUpgradeUrl; ?>" target="_blank" rel="noopener noreferrer">View Cache Upgrade</a>
                  </p>
                </div>
                <div class="ai-webadmin-card">
                  <h4>Monitoring Schedule</h4>
                  <p>Next audit sync: <strong><?php echo esc_html(ai_webadmin_format_utc_timestamp($nextAuditSyncAt)); ?></strong></p>
                  <p>Next daily hardening run: <strong><?php echo esc_html(ai_webadmin_format_utc_timestamp($nextHardeningAt)); ?></strong></p>
                  <p>Last backup snapshot: <strong><?php echo esc_html(ai_webadmin_format_utc_timestamp((int)($settings["github_backup_last_snapshot_at"] ?? 0))); ?></strong></p>
                  <p>Last backup status: <strong><?php echo esc_html((string)($settings["github_backup_last_status"] ?: "unknown")); ?></strong></p>
                </div>
                <div class="ai-webadmin-card">
                  <h4>Benchmark Baseline</h4>
                  <p>Last captured: <strong><?php echo esc_html(ai_webadmin_format_utc_timestamp((int)($lastBenchmark["captured_at"] ?? 0))); ?></strong></p>
                  <p>Home fetch: <strong><?php echo esc_html((string)(int)($lastBenchmark["home_fetch_ms"] ?? 0)); ?> ms</strong></p>
                  <p>Home response size: <strong><?php echo esc_html((string)(int)($lastBenchmark["home_body_bytes"] ?? 0)); ?> bytes</strong></p>
                  <p>Snapshot outdated plugins: <strong><?php echo esc_html((string)(int)($benchmarkMetrics["outdated_plugin_count"] ?? 0)); ?></strong></p>
                </div>
                <div class="ai-webadmin-card">
                  <h4>GitHub Clone + Plugin Reduction</h4>
                  <p>Clone status: <strong><?php echo esc_html($optimizationCloneStatus !== "" ? $optimizationCloneStatus : "unknown"); ?></strong></p>
                  <p>Clone note: <strong><?php echo esc_html($optimizationCloneSummary !== "" ? $optimizationCloneSummary : "No clone status yet."); ?></strong></p>
                  <p>Remove now: <strong><?php echo esc_html((string)count($optimizationRemoveNow)); ?></strong></p>
                  <p>After R2/CDN offload: <strong><?php echo esc_html((string)count($optimizationRemoveAfterR2)); ?></strong></p>
                </div>
                <div class="ai-webadmin-card">
                  <h4>Media R2 Offload</h4>
                  <p>Last run: <strong><?php echo esc_html(ai_webadmin_format_utc_timestamp($mediaOffloadLastRunAt)); ?></strong></p>
                  <p>Status: <strong><?php echo esc_html($mediaOffloadLastStatus !== "" ? $mediaOffloadLastStatus : "unknown"); ?></strong></p>
                  <p>Total processed: <strong><?php echo esc_html((string)$mediaOffloadTotalProcessed); ?></strong></p>
                  <p>Last URL mappings: <strong><?php echo esc_html((string)$mediaOffloadMappedCount); ?></strong></p>
                  <p>Total failed: <strong><?php echo esc_html((string)$mediaOffloadTotalFailed); ?></strong></p>
                  <p>Cursor attachment ID: <strong><?php echo esc_html((string)$mediaOffloadCursor); ?></strong></p>
                  <?php if ($mediaOffloadGithubStatus !== ""): ?>
                    <p>GitHub manifest: <strong><?php echo esc_html($mediaOffloadGithubStatus); ?></strong></p>
                  <?php endif; ?>
                </div>
                <div class="ai-webadmin-card">
                  <h4>License Hygiene</h4>
                  <p>Enabled: <strong><?php echo !empty($settings["license_hygiene_enabled"]) ? "Yes" : "No"; ?></strong></p>
                  <p>Last run: <strong><?php echo esc_html(ai_webadmin_format_utc_timestamp($licenseLastRunAt)); ?></strong></p>
                  <p>Last status: <strong><?php echo esc_html($licenseLastStatus !== "" ? $licenseLastStatus : "not_run"); ?></strong></p>
                  <p>Deleted records: <strong><?php echo esc_html((string)count($licenseLastDeleted)); ?></strong></p>
                  <?php if ($licenseExpectedEmail !== ""): ?>
                    <p>Expected email: <strong><?php echo esc_html($licenseExpectedEmail); ?></strong></p>
                  <?php endif; ?>
                </div>
              </div>
              <div class="ai-webadmin-card" style="margin-top:12px;">
                <h4>Built-In Page Cache + Autoload Controls</h4>
                <label>
                  <input name="enable_builtin_page_cache" type="checkbox" value="1" <?php checked((int)$settings["enable_builtin_page_cache"], 1); ?> />
                  Enable built-in HTML page cache for anonymous GET traffic
                </label><br/>
                <label for="page_cache_ttl_seconds">Page cache TTL (seconds)</label>
                <input name="page_cache_ttl_seconds" id="page_cache_ttl_seconds" type="number" min="60" max="86400" value="<?php echo esc_attr((string)$settings["page_cache_ttl_seconds"]); ?>" />
                <p class="description">Recommended: 300-900 seconds for brochure sites. Cart/login/admin paths are excluded automatically.</p>
                <label for="page_cache_excluded_paths">Extra cache-excluded paths (one per line)</label><br/>
                <textarea name="page_cache_excluded_paths" id="page_cache_excluded_paths" rows="4" class="large-text code"><?php echo esc_textarea((string)$settings["page_cache_excluded_paths"]); ?></textarea>
                <label>
                  <input name="autoload_cleanup_enabled" type="checkbox" value="1" <?php checked((int)$settings["autoload_cleanup_enabled"], 1); ?> />
                  Enable safe autoload cleanup (expired transients + nonessential transient autoload flags)
                </label>
                <?php if (!empty($settings["autoload_last_cleanup_summary"])): ?>
                  <p class="description">Last cleanup summary: <?php echo esc_html((string)$settings["autoload_last_cleanup_summary"]); ?></p>
                <?php endif; ?>
              </div>
              <?php if ($optimizationSummary !== ""): ?>
                <p class="description" style="margin-top:10px;"><strong>Worker optimization summary:</strong> <?php echo esc_html($optimizationSummary); ?></p>
              <?php endif; ?>
              <?php if (!empty($optimizationRemoveNow)): ?>
                <p style="margin:8px 0 4px;"><strong>Remove Now (high confidence)</strong></p>
                <ul>
                  <?php foreach (array_slice($optimizationRemoveNow, 0, 12) as $item): ?>
                    <?php if (!is_array($item)) continue; ?>
                    <li>
                      <code><?php echo esc_html((string)($item["slug"] ?? "")); ?></code>
                      <?php if (!empty($item["reason"])): ?> — <?php echo esc_html((string)$item["reason"]); ?><?php endif; ?>
                    </li>
                  <?php endforeach; ?>
                </ul>
              <?php endif; ?>
              <?php if (!empty($optimizationRemoveAfterR2)): ?>
                <p style="margin:8px 0 4px;"><strong>Can Be Reduced After R2/CDN Offload</strong></p>
                <ul>
                  <?php foreach (array_slice($optimizationRemoveAfterR2, 0, 12) as $item): ?>
                    <?php if (!is_array($item)) continue; ?>
                    <li>
                      <code><?php echo esc_html((string)($item["slug"] ?? "")); ?></code>
                      <?php if (!empty($item["reason"])): ?> — <?php echo esc_html((string)$item["reason"]); ?><?php endif; ?>
                    </li>
                  <?php endforeach; ?>
                </ul>
              <?php endif; ?>
              <p class="ai-webadmin-actions" style="margin-top:12px;">
                <button type="submit" name="ai_webadmin_run_audit_now" class="button">Run Audit Sync Now</button>
                <button type="submit" name="ai_webadmin_refresh_page_cache_health_now" class="button">Refresh Page Cache Health</button>
                <button type="submit" name="ai_webadmin_clear_page_cache_now" class="button">Clear Built-In Page Cache</button>
                <button type="submit" name="ai_webadmin_run_autoload_cleanup_now" class="button">Run Autoload Cleanup</button>
                <button type="submit" name="ai_webadmin_refresh_cache_now" class="button">Refresh Schema/Redirect Cache</button>
                <button type="submit" name="ai_webadmin_run_benchmark_now" class="button">Capture Benchmark Baseline</button>
                <button type="submit" name="ai_webadmin_process_comment_queue_now" class="button">Process Comment Queue Now</button>
                <button type="submit" name="ai_webadmin_run_media_offload_now" class="button">Run Media Offload Batch</button>
                <button type="submit" name="ai_webadmin_run_media_offload_full_now" class="button button-primary">Run All Media (Entire Library)</button>
                <button type="submit" name="ai_webadmin_reset_media_offload_cursor" class="button">Reset Media Cursor (Reprocess All)</button>
                <button type="submit" name="ai_webadmin_run_license_hygiene_now" class="button">Run License Cleanup + GitHub Snapshot</button>
                <?php if (!empty($settings["allow_tolldns_points_payment"]) && $tolldnsActive): ?>
                  <button type="submit" name="ai_webadmin_redeem_vps_points_now" class="button">Redeem Points For VPS Upgrade</button>
                  <button type="submit" name="ai_webadmin_redeem_cache_points_now" class="button">Redeem Points For Cache Upgrade</button>
                <?php endif; ?>
                <button type="submit" name="ai_webadmin_run_sync_now" class="button button-secondary">Run Full Worker Sync</button>
              </p>
              <?php if ($licenseLastMessage !== ""): ?>
                <p class="description"><strong>License cleanup:</strong> <?php echo esc_html($licenseLastMessage); ?></p>
              <?php endif; ?>
              <?php if ($licenseLastSummary !== ""): ?>
                <p class="description"><strong>AI summary:</strong> <?php echo esc_html($licenseLastSummary); ?></p>
              <?php endif; ?>
              <?php if (!empty($licenseLastDeleted)): ?>
                <details style="margin-top:8px;">
                  <summary>Deleted license records (last run)</summary>
                  <ul style="margin-top:8px;">
                    <?php foreach (array_slice($licenseLastDeleted, 0, 20) as $item): ?>
                      <?php if (!is_array($item)) continue; ?>
                      <li>
                        <code><?php echo esc_html((string)($item["option_name"] ?? "")); ?></code>
                        <?php if (!empty($item["reasons"]) && is_array($item["reasons"])): ?>
                          — <?php echo esc_html(implode(", ", array_map("sanitize_text_field", $item["reasons"]))); ?>
                        <?php endif; ?>
                      </li>
                    <?php endforeach; ?>
                  </ul>
                </details>
              <?php endif; ?>
              <?php if ($mediaOffloadLastMessage !== ""): ?>
                <p class="description"><strong>Media offload:</strong> <?php echo esc_html($mediaOffloadLastMessage); ?></p>
              <?php endif; ?>
              <?php if ($mediaOffloadManifestKey !== ""): ?>
                <p class="description"><strong>R2 manifest key:</strong> <code><?php echo esc_html($mediaOffloadManifestKey); ?></code></p>
              <?php endif; ?>
              <?php if ($mediaOffloadGithubPath !== ""): ?>
                <p class="description"><strong>GitHub manifest path:</strong> <code><?php echo esc_html($mediaOffloadGithubPath); ?></code></p>
              <?php endif; ?>
            </td>
          </tr>
          <tr<?php echo ai_webadmin_tab_row_attrs($activeTab, ["logs"]); ?>>
            <th scope="row">Runtime Logs</th>
            <td>
              <p class="description">Recent runtime/system log lines from AI WebAdmin tasks. This is useful for troubleshooting before opening support tickets.</p>
              <textarea readonly rows="16" class="large-text code"><?php echo esc_textarea($runtimeLogText); ?></textarea>
              <p class="description">Tip: copy this block when reporting issues with audit sync, sandbox preflight, media offload, or backup workflows.</p>
            </td>
          </tr>
          <tr<?php echo ai_webadmin_tab_row_attrs($activeTab, ["premium"]); ?>>
            <th scope="row">Premium Features</th>
            <td>
              <p class="description">Premium tabs can be enabled account-side. Configure preferred premium behavior here so activation is instant when upgraded.</p>
              <label for="premium_upgrade_url">Upgrade URL</label><br/>
              <input name="premium_upgrade_url" id="premium_upgrade_url" type="url" class="regular-text" value="<?php echo esc_attr((string)($settings["premium_upgrade_url"] ?? "")); ?>" />
              <p style="margin:8px 0 6px;"><strong>Premium feature toggles (activation-gated)</strong></p>
              <label><input name="premium_feature_ai_competitor_monitoring" type="checkbox" value="1" <?php checked((int)($settings["premium_feature_ai_competitor_monitoring"] ?? 0), 1); ?> /> AI competitor monitoring + change alerts</label><br/>
              <label><input name="premium_feature_daily_page_speed_paths" type="checkbox" value="1" <?php checked((int)($settings["premium_feature_daily_page_speed_paths"] ?? 0), 1); ?> /> Daily per-page speed monitoring on selected URLs</label><br/>
              <label><input name="premium_feature_auto_seo_briefs" type="checkbox" value="1" <?php checked((int)($settings["premium_feature_auto_seo_briefs"] ?? 0), 1); ?> /> Automatic SEO brief generation from keyword set</label>
              <hr style="margin:12px 0;"/>
              <p style="margin:8px 0 6px;"><strong>VPS + Caching Upsell Links</strong></p>
              <label for="vps_upgrade_url">VPS upgrade URL</label><br/>
              <input name="vps_upgrade_url" id="vps_upgrade_url" type="url" class="regular-text" value="<?php echo esc_attr((string)($settings["vps_upgrade_url"] ?? "")); ?>" /><br/>
              <label for="cache_accelerator_upgrade_url">Cache accelerator URL</label><br/>
              <input name="cache_accelerator_upgrade_url" id="cache_accelerator_upgrade_url" type="url" class="regular-text" value="<?php echo esc_attr((string)($settings["cache_accelerator_upgrade_url"] ?? "")); ?>" /><br/>
              <label><input name="allow_tolldns_points_payment" type="checkbox" value="1" <?php checked((int)($settings["allow_tolldns_points_payment"] ?? 0), 1); ?> /> Allow TollDNS points redemption for upgrades</label><br/>
              <label for="tolldns_points_per_usd_cents">Points per $1.00 (approx conversion)</label>
              <input name="tolldns_points_per_usd_cents" id="tolldns_points_per_usd_cents" type="number" min="1" max="100000" value="<?php echo esc_attr((string)($settings["tolldns_points_per_usd_cents"] ?? 100)); ?>" /><br/>
              <label for="tolldns_vps_upgrade_points_cost">VPS upgrade points cost</label>
              <input name="tolldns_vps_upgrade_points_cost" id="tolldns_vps_upgrade_points_cost" type="number" min="1" max="1000000" value="<?php echo esc_attr((string)($settings["tolldns_vps_upgrade_points_cost"] ?? 800)); ?>" /><br/>
              <label for="tolldns_cache_upgrade_points_cost">Cache upgrade points cost</label>
              <input name="tolldns_cache_upgrade_points_cost" id="tolldns_cache_upgrade_points_cost" type="number" min="1" max="1000000" value="<?php echo esc_attr((string)($settings["tolldns_cache_upgrade_points_cost"] ?? 500)); ?>" />
              <p class="description">Current TollDNS points: <strong><?php echo esc_html((string)$tolldnsPointsTotal); ?></strong> (about $<?php echo esc_html(number_format((float)$tolldnsUsdApprox, 2)); ?>).</p>
              <p style="margin-top:10px;">
                <a class="button button-primary" href="<?php echo $premiumUpgradeUrl; ?>" target="_blank" rel="noopener noreferrer">Upgrade To Premium</a>
                <a class="button button-secondary" href="<?php echo $vpsUpgradeUrl; ?>" target="_blank" rel="noopener noreferrer">VPS Offer</a>
                <a class="button button-secondary" href="<?php echo $cacheUpgradeUrl; ?>" target="_blank" rel="noopener noreferrer">Cache Offer</a>
              </p>
            </td>
          </tr>
          <tr<?php echo ai_webadmin_tab_row_attrs($activeTab, ["agent"]); ?>>
            <th scope="row">AI Agent Chat (Proof-Backed)</th>
            <td>
              <p class="description">Ask your WebAdmin agent anything about this site. Each answer includes proof items with source paths so you can verify trust.</p>
              <label for="agent_chat_question">Your question</label><br/>
              <textarea name="agent_chat_question" id="agent_chat_question" rows="4" class="large-text" placeholder="Example: Which plugins can I remove now, and which can be removed after R2/CDN offload?"></textarea>
              <p style="margin-top:8px;">
                <button type="submit" name="ai_webadmin_agent_chat_ask" class="button button-primary">Ask AI Agent</button>
                <button type="submit" name="ai_webadmin_run_audit_now" class="button">Refresh Data First</button>
              </p>
              <?php if ($agentLastQuestion !== "" && $agentLastAnswer !== ""): ?>
                <hr/>
                <p><strong>Last question:</strong> <?php echo esc_html($agentLastQuestion); ?></p>
                <p><strong>Last asked:</strong> <?php echo esc_html(ai_webadmin_format_utc_timestamp($agentLastAskedAt)); ?></p>
                <p><strong>Answer:</strong><br/><?php echo nl2br(esc_html($agentLastAnswer)); ?></p>
                <?php if (!empty($agentLastProofs)): ?>
                  <p><strong>Proofs</strong></p>
                  <ul>
                    <?php foreach (array_slice($agentLastProofs, 0, 8) as $proof): ?>
                      <?php if (!is_array($proof)) continue; ?>
                      <li>
                        <strong><?php echo esc_html((string)($proof["title"] ?? "")); ?>:</strong>
                        <?php echo esc_html((string)($proof["value"] ?? "")); ?>
                        <?php if (!empty($proof["source_path"])): ?>
                          <br/><code><?php echo esc_html((string)$proof["source_path"]); ?></code>
                        <?php endif; ?>
                      </li>
                    <?php endforeach; ?>
                  </ul>
                <?php endif; ?>
              <?php endif; ?>
              <?php if (!empty($agentChatHistory)): ?>
                <hr/>
                <p><strong>Recent chat history</strong></p>
                <ol style="margin-left:18px;">
                  <?php foreach (array_slice($agentChatHistory, 0, 6) as $entry): ?>
                    <?php if (!is_array($entry)) continue; ?>
                    <li>
                      <p><strong>Q:</strong> <?php echo esc_html((string)($entry["question"] ?? "")); ?></p>
                      <p><strong>A:</strong> <?php echo nl2br(esc_html((string)($entry["answer"] ?? ""))); ?></p>
                    </li>
                  <?php endforeach; ?>
                </ol>
              <?php endif; ?>
            </td>
          </tr>
        </table>
        <p class="submit">
          <button type="submit" class="button button-primary">Save Changes</button>
        </p>
      </form>
    </div>
    <?php
}

function ai_webadmin_attachment_r2_url($attachmentId) {
    $id = (int)$attachmentId;
    if ($id <= 0) {
        return "";
    }
    $url = esc_url_raw((string)get_post_meta($id, "_ai_webadmin_r2_url", true));
    if ($url === "") {
        return "";
    }
    return $url;
}

function ai_webadmin_filter_attachment_url_to_r2($url, $attachmentId) {
    $settings = ai_webadmin_get_settings();
    if (empty($settings["media_rewrite_attachment_urls"])) {
        return $url;
    }
    $r2Url = ai_webadmin_attachment_r2_url($attachmentId);
    if ($r2Url === "") {
        return $url;
    }
    return $r2Url;
}
add_filter("wp_get_attachment_url", "ai_webadmin_filter_attachment_url_to_r2", 20, 2);

function ai_webadmin_filter_prepare_attachment_for_js_to_r2($response, $attachment, $meta) {
    if (!is_array($response) || empty($response["id"])) {
        return $response;
    }
    $settings = ai_webadmin_get_settings();
    if (empty($settings["media_rewrite_attachment_urls"])) {
        return $response;
    }
    $attachmentId = (int)$response["id"];
    $r2Url = ai_webadmin_attachment_r2_url($attachmentId);
    if ($r2Url === "") {
        return $response;
    }
    $response["url"] = $r2Url;
    $response["link"] = $r2Url;
    return $response;
}
add_filter("wp_prepare_attachment_for_js", "ai_webadmin_filter_prepare_attachment_for_js_to_r2", 20, 3);

function ai_webadmin_filter_attachment_image_src_to_r2($image, $attachmentId) {
    if (!is_array($image) || empty($image[0])) {
        return $image;
    }
    $settings = ai_webadmin_get_settings();
    if (empty($settings["media_rewrite_attachment_urls"])) {
        return $image;
    }
    $r2Url = ai_webadmin_attachment_r2_url($attachmentId);
    if ($r2Url === "") {
        return $image;
    }
    $image[0] = $r2Url;
    return $image;
}
add_filter("wp_get_attachment_image_src", "ai_webadmin_filter_attachment_image_src_to_r2", 20, 2);

function ai_webadmin_filter_attachment_srcset_for_r2($sources, $sizeArray, $imageSrc, $imageMeta, $attachmentId) {
    $settings = ai_webadmin_get_settings();
    if (empty($settings["media_rewrite_attachment_urls"])) {
        return $sources;
    }
    $r2Url = ai_webadmin_attachment_r2_url($attachmentId);
    if ($r2Url === "") {
        return $sources;
    }
    return false;
}
add_filter("wp_calculate_image_srcset", "ai_webadmin_filter_attachment_srcset_for_r2", 20, 5);

function ai_webadmin_filter_content_media_urls_to_r2($content) {
    if (!is_string($content) || $content === "") {
        return $content;
    }
    $settings = ai_webadmin_get_settings();
    if (empty($settings["media_rewrite_attachment_urls"])) {
        return $content;
    }
    $uploads = wp_get_upload_dir();
    $uploadsBase = isset($uploads["baseurl"]) ? rtrim((string)$uploads["baseurl"], "/") : "";
    if ($uploadsBase === "") {
        return $content;
    }
    $quotedBase = preg_quote($uploadsBase, "/");
    if (!preg_match_all('/' . $quotedBase . '[^"\'\s<>()]+/i', $content, $matches)) {
        return $content;
    }
    $urls = array_values(array_unique((array)$matches[0]));
    if (empty($urls)) {
        return $content;
    }
    $replacements = 0;
    foreach ($urls as $localUrl) {
        if ($replacements >= 120) {
            break;
        }
        $attachmentId = (int)attachment_url_to_postid($localUrl);
        if ($attachmentId <= 0) {
            continue;
        }
        $r2Url = ai_webadmin_attachment_r2_url($attachmentId);
        if ($r2Url === "") {
            continue;
        }
        $content = str_replace($localUrl, $r2Url, $content);
        $replacements += 1;
    }
    return $content;
}
add_filter("the_content", "ai_webadmin_filter_content_media_urls_to_r2", 20, 1);

function ai_webadmin_queue_comment($comment_ID, $comment_approved) {
    $settings = ai_webadmin_get_settings();
    if (empty($settings["enable_comment_moderation"])) {
        return;
    }
    if (!in_array((string)$comment_approved, ["0", "1"], true)) {
        return;
    }
    if (!wp_next_scheduled("ai_webadmin_moderate_comment_event", [$comment_ID])) {
        wp_schedule_single_event(time() + 5, "ai_webadmin_moderate_comment_event", [$comment_ID]);
    }
}
add_action("comment_post", "ai_webadmin_queue_comment", 10, 2);

function ai_webadmin_fetch_pending_comment_ids($limit = 100) {
    $number = max(1, min(500, (int)$limit));
    $ids = get_comments([
        "status" => "hold",
        "type" => "comment",
        "fields" => "ids",
        "number" => $number,
        "orderby" => "comment_ID",
        "order" => "ASC",
    ]);
    if (!is_array($ids)) {
        return [];
    }
    $out = [];
    foreach ($ids as $id) {
        $cid = (int)$id;
        if ($cid > 0) {
            $out[] = $cid;
        }
    }
    return $out;
}

function ai_webadmin_schedule_pending_comment_backlog($limit = 80) {
    $settings = ai_webadmin_get_settings();
    if (empty($settings["enable_comment_moderation"]) || !ai_webadmin_features_enabled()) {
        return ["queued" => 0, "already_scheduled" => 0, "total_candidates" => 0];
    }
    $ids = ai_webadmin_fetch_pending_comment_ids($limit);
    $queued = 0;
    $already = 0;
    foreach ($ids as $index => $commentId) {
        if (wp_next_scheduled("ai_webadmin_moderate_comment_event", [$commentId])) {
            $already += 1;
            continue;
        }
        $delay = min(300, max(1, ($index + 1)));
        wp_schedule_single_event(time() + $delay, "ai_webadmin_moderate_comment_event", [$commentId]);
        $queued += 1;
    }
    update_option("ai_webadmin_comment_backlog_last", [
        "mode" => "scheduled",
        "queued" => $queued,
        "already_scheduled" => $already,
        "total_candidates" => count($ids),
        "ran_at" => time(),
    ], false);
    return ["queued" => $queued, "already_scheduled" => $already, "total_candidates" => count($ids)];
}

function ai_webadmin_build_signature($timestamp, $body, $secret) {
    return hash_hmac("sha256", $timestamp . "." . $body, $secret);
}

function ai_webadmin_detect_redundant_plugins($activePluginData) {
    $groups = [
        "seo" => ["seo", "rank math", "yoast", "aioseo"],
        "cache" => ["cache", "litespeed", "wp rocket", "autoptimize", "w3 total cache"],
        "security" => ["security", "wordfence", "sucuri", "ithemes", "solid security"],
        "forms" => ["form", "gravity", "wpforms", "contact form", "ninja forms"],
        "backup" => ["backup", "updraft", "vaultpress", "duplicator"],
        "analytics" => ["analytics", "ga4", "google site kit", "pixel"],
        "booking" => ["booking", "appointments", "calendar"],
    ];
    $bucketCounts = [];
    foreach ($groups as $g => $_) {
        $bucketCounts[$g] = 0;
    }

    foreach ($activePluginData as $pluginData) {
        $name = strtolower((string)($pluginData["Name"] ?? ""));
        if ($name === "") {
            continue;
        }
        foreach ($groups as $group => $needles) {
            foreach ($needles as $needle) {
                if (strpos($name, $needle) !== false) {
                    $bucketCounts[$group] += 1;
                    break;
                }
            }
        }
    }

    $redundant = 0;
    foreach ($bucketCounts as $count) {
        if ($count > 1) {
            $redundant += ($count - 1);
        }
    }
    return max(0, (int)$redundant);
}

function ai_webadmin_detect_sso_plugins($activePluginData) {
    $count = 0;
    foreach ($activePluginData as $pluginData) {
        $name = strtolower((string)($pluginData["Name"] ?? ""));
        if ($name === "") {
            continue;
        }
        if (
            strpos($name, "sso") !== false ||
            strpos($name, "oauth") !== false ||
            strpos($name, "social login") !== false ||
            strpos($name, "nextend") !== false ||
            strpos($name, "miniorange") !== false ||
            strpos($name, "cloudflare access") !== false
        ) {
            $count += 1;
        }
    }
    return max(0, (int)$count);
}

function ai_webadmin_collect_public_smoke_urls($limit = 8) {
    $max = max(1, min(30, (int)$limit));
    $urls = [];
    $seen = [];
    $push = function ($url) use (&$urls, &$seen, $max) {
        if (count($urls) >= $max) {
            return;
        }
        $raw = esc_url_raw((string)$url);
        if ($raw === "") {
            return;
        }
        $parts = wp_parse_url($raw);
        if (!is_array($parts) || empty($parts["host"])) {
            return;
        }
        $key = strtolower($raw);
        if (isset($seen[$key])) {
            return;
        }
        $seen[$key] = true;
        $urls[] = $raw;
    };

    $push(home_url("/"));

    $pages = get_posts([
        "post_type" => "page",
        "post_status" => "publish",
        "numberposts" => $max,
        "orderby" => "modified",
        "order" => "DESC",
        "fields" => "ids",
        "suppress_filters" => true,
    ]);
    if (is_array($pages)) {
        foreach ($pages as $id) {
            $push(get_permalink((int)$id));
        }
    }

    if (count($urls) < $max) {
        $posts = get_posts([
            "post_type" => "post",
            "post_status" => "publish",
            "numberposts" => $max,
            "orderby" => "modified",
            "order" => "DESC",
            "fields" => "ids",
            "suppress_filters" => true,
        ]);
        if (is_array($posts)) {
            foreach ($posts as $id) {
                $push(get_permalink((int)$id));
            }
        }
    }

    return array_slice($urls, 0, $max);
}

function ai_webadmin_fetch_public_html_for_audit($url) {
    $target = esc_url_raw((string)$url);
    if ($target === "") {
        return "";
    }
    $response = wp_remote_get($target, [
        "timeout" => 8,
        "redirection" => 3,
        "headers" => [
            "user-agent" => "AI-WebAdmin-Audit/0.2 (+https://app.cardetailingreno.com)",
            "accept" => "text/html,application/xhtml+xml",
            "cache-control" => "no-cache",
            "pragma" => "no-cache",
        ],
    ]);
    if (is_wp_error($response)) {
        return "";
    }
    $code = (int)wp_remote_retrieve_response_code($response);
    if ($code < 200 || $code >= 400) {
        return "";
    }
    $contentType = strtolower((string)wp_remote_retrieve_header($response, "content-type"));
    if ($contentType !== "" && strpos($contentType, "text/html") === false && strpos($contentType, "application/xhtml+xml") === false) {
        return "";
    }
    $body = (string)wp_remote_retrieve_body($response);
    if ($body === "") {
        return "";
    }
    return substr($body, 0, 500000);
}

function ai_webadmin_extract_tracking_ids_from_html($html) {
    $text = (string)$html;
    $measurementIds = [];
    $gtmIds = [];
    if ($text === "") {
        return [
            "measurement_ids" => [],
            "gtm_ids" => [],
            "has_tracking" => false,
            "has_site_kit_marker" => false,
        ];
    }

    if (preg_match_all('/\b(G-[A-Z0-9]{4,}|AW-[A-Z0-9-]+|DC-[A-Z0-9-]+)\b/i', $text, $m) && !empty($m[1])) {
        foreach ($m[1] as $id) {
            $clean = strtoupper(sanitize_text_field((string)$id));
            if ($clean !== "") {
                $measurementIds[$clean] = true;
            }
        }
    }
    if (preg_match_all('/\b(GTM-[A-Z0-9]+)\b/i', $text, $g) && !empty($g[1])) {
        foreach ($g[1] as $id) {
            $clean = strtoupper(sanitize_text_field((string)$id));
            if ($clean !== "") {
                $gtmIds[$clean] = true;
            }
        }
    }
    $hasTracking = false;
    if (!empty($measurementIds) || !empty($gtmIds)) {
        $hasTracking = true;
    } elseif (
        preg_match('/googletagmanager\.com\/gtag\/js|google-analytics\.com\/analytics\.js|googletagmanager\.com\/gtm\.js/i', $text)
    ) {
        $hasTracking = true;
    }
    $hasSiteKitMarker = preg_match('/googlesitekit|google-site-kit|id=[\"\']googlesitekit/i', $text) ? true : false;
    return [
        "measurement_ids" => array_values(array_keys($measurementIds)),
        "gtm_ids" => array_values(array_keys($gtmIds)),
        "has_tracking" => $hasTracking,
        "has_site_kit_marker" => $hasSiteKitMarker,
    ];
}

function ai_webadmin_collect_site_kit_tracking_snapshot($activePluginSlugs) {
    $activeLookup = [];
    foreach ((array)$activePluginSlugs as $slug) {
        $activeLookup[(string)$slug] = true;
    }
    $siteKitActive = isset($activeLookup["google-site-kit/google-site-kit.php"]);
    $urls = ai_webadmin_collect_public_smoke_urls(8);
    if (empty($urls)) {
        return [
            "analytics_site_kit_active" => $siteKitActive ? 1 : 0,
            "analytics_status" => $siteKitActive ? "no_pages" : "not_installed",
            "analytics_pages_checked_count" => 0,
            "analytics_pages_with_tracking_count" => 0,
            "analytics_pages_missing_tracking_count" => 0,
            "analytics_tag_coverage_percent" => null,
            "analytics_measurement_id_count" => 0,
            "analytics_gtm_container_count" => 0,
            "analytics_missing_urls" => [],
            "analytics_measurement_ids" => [],
            "analytics_gtm_ids" => [],
            "analytics_last_checked_at" => time(),
        ];
    }

    $withTracking = 0;
    $missing = [];
    $unreachable = [];
    $measurementIds = [];
    $gtmIds = [];
    $siteKitMarkerCount = 0;
    $reachableCount = 0;
    foreach ($urls as $url) {
        $html = ai_webadmin_fetch_public_html_for_audit($url);
        if ($html === "") {
            $unreachable[] = $url;
            continue;
        }
        $reachableCount += 1;
        $parsed = ai_webadmin_extract_tracking_ids_from_html($html);
        if (!empty($parsed["has_site_kit_marker"])) {
            $siteKitMarkerCount += 1;
        }
        if (!empty($parsed["has_tracking"])) {
            $withTracking += 1;
        } else {
            $missing[] = $url;
        }
        foreach ((array)($parsed["measurement_ids"] ?? []) as $id) {
            $measurementIds[(string)$id] = true;
        }
        foreach ((array)($parsed["gtm_ids"] ?? []) as $id) {
            $gtmIds[(string)$id] = true;
        }
    }

    $checked = $reachableCount;
    $coverage = ($checked > 0) ? (int)round(($withTracking / $checked) * 100) : null;
    $status = "ok";
    if (!$siteKitActive) {
        $status = "not_installed";
    } elseif (count($urls) === 0) {
        $status = "no_pages";
    } elseif ($checked === 0) {
        $status = "unreachable";
    } elseif ($withTracking === 0) {
        $status = "missing";
    } elseif ($coverage < 80 || $siteKitMarkerCount === 0) {
        $status = "partial";
    }

    return [
        "analytics_site_kit_active" => $siteKitActive ? 1 : 0,
        "analytics_status" => $status,
        "analytics_pages_checked_count" => $checked,
        "analytics_pages_with_tracking_count" => $withTracking,
        "analytics_pages_missing_tracking_count" => max(0, $checked - $withTracking),
        "analytics_tag_coverage_percent" => $coverage,
        "analytics_measurement_id_count" => count($measurementIds),
        "analytics_gtm_container_count" => count($gtmIds),
        "analytics_missing_urls" => array_slice(array_values(array_map("esc_url_raw", $missing)), 0, 12),
        "analytics_measurement_ids" => array_slice(array_values(array_keys($measurementIds)), 0, 15),
        "analytics_gtm_ids" => array_slice(array_values(array_keys($gtmIds)), 0, 15),
        "analytics_unreachable_urls" => array_slice(array_values(array_map("esc_url_raw", $unreachable)), 0, 12),
        "analytics_last_checked_at" => time(),
    ];
}

function ai_webadmin_plugin_risk_catalog() {
    return [
        [
            "id" => "wp-consent-api",
            "pattern" => '/wp[\s_-]*consent[\s_-]*api/i',
            "risk_score" => 4,
            "reason" => "Consent logic can silently block analytics and marketing tags when configured incorrectly.",
            "action" => "Keep only if privacy controls are required; verify consent-mode and tag firing.",
            "checks" => ["Cookie consent banner appears", "Analytics tags fire after consent", "No JavaScript consent errors"],
        ],
        [
            "id" => "wpcode",
            "pattern" => '/wpcode|insert headers and footers|code snippets/i',
            "risk_score" => 7,
            "reason" => "Code-injection plugins increase blast radius from misconfigured snippets.",
            "action" => "Move stable snippets into version-controlled theme/plugin code where possible.",
            "checks" => ["Homepage renders without JS errors", "Header/footer scripts still load", "Form submit and conversion events fire"],
        ],
        [
            "id" => "templately",
            "pattern" => '/templately/i',
            "risk_score" => 6,
            "reason" => "Template-library plugins add asset weight and cross-plugin coupling.",
            "action" => "Keep only active templates; remove if Elementor template packs are no longer used.",
            "checks" => ["Core landing pages layout unchanged", "Global header/footer still render", "No missing template sections"],
        ],
        [
            "id" => "smash-balloon",
            "pattern" => '/smash balloon|instagram feed/i',
            "risk_score" => 6,
            "reason" => "Third-party API dependency plugins frequently fail from token/API changes.",
            "action" => "Test feed render in sandbox and replace with static embeds if unstable.",
            "checks" => ["Instagram feed block loads", "No API/token auth warnings", "Page speed does not regress"],
        ],
        [
            "id" => "site-kit",
            "pattern" => '/site kit|google[-\s]*site[-\s]*kit/i',
            "risk_score" => 6,
            "reason" => "Analytics attribution breaks when Site Kit tags are inconsistent across pages.",
            "action" => "Verify GA/GTM IDs on critical pages before changing or removing.",
            "checks" => ["GA/GTM tags exist on all key pages", "Measurement IDs consistent", "Traffic appears in real-time analytics"],
        ],
        [
            "id" => "woo-custom-variations",
            "pattern" => '/woocommerce.*variations|custom variations/i',
            "risk_score" => 8,
            "reason" => "WooCommerce variation customizers can break cart/checkout behavior after updates.",
            "action" => "Run one-by-one sandbox update with add-to-cart and checkout smoke tests.",
            "checks" => ["Product variation selector works", "Add-to-cart succeeds", "Checkout and payment flow works"],
        ],
        [
            "id" => "extended-wordpress-tools",
            "pattern" => '/extended wordpress tools/i',
            "risk_score" => 6,
            "reason" => "Broad utility plugins often overlap with core/admin features and increase attack surface.",
            "action" => "Review enabled modules and remove if features duplicate existing stack.",
            "checks" => ["Admin settings pages still accessible", "Scheduled tasks still run", "No missing utility-dependent flows"],
        ],
        [
            "id" => "essential-addons-elementor",
            "pattern" => '/essential addons.*elementor|essential-addons-for-elementor/i',
            "risk_score" => 7,
            "reason" => "Elementor addon bundles add large compatibility surface area.",
            "action" => "Keep only widgets in use; test front-end rendering before updates/removal.",
            "checks" => ["Elementor widget sections render", "Animations/interactions work", "Mobile layout remains intact"],
        ],
        [
            "id" => "elementor-pro",
            "pattern" => '/elementor pro/i',
            "risk_score" => 9,
            "reason" => "Core page-builder dependency with high functional impact if changed.",
            "action" => "Always update/remove in sandbox first; snapshot + rollback required.",
            "checks" => ["Homepage hero and key templates load", "Forms/popups still function", "Theme builder templates still apply"],
        ],
        [
            "id" => "elementor-core",
            "pattern" => '/(^|[^a-z])elementor([^a-z]|$)/i',
            "risk_score" => 8,
            "reason" => "Page-builder core plugin with high template and widget dependency risk.",
            "action" => "Canary test one change at a time with visual diff checks.",
            "checks" => ["Primary landing pages render", "No broken layout blocks", "Editor loads and saves successfully"],
        ],
    ];
}

function ai_webadmin_collect_plugin_risk_candidates($allPlugins, $activePluginSlugs, $updates) {
    $activeLookup = [];
    foreach ((array)$activePluginSlugs as $slug) {
        $activeLookup[(string)$slug] = true;
    }
    $catalog = ai_webadmin_plugin_risk_catalog();
    $candidates = [];
    $high = 0;
    $medium = 0;

    foreach ((array)$allPlugins as $slug => $pluginData) {
        $slug = (string)$slug;
        if ($slug === "" || !isset($activeLookup[$slug])) {
            continue;
        }
        $name = sanitize_text_field((string)($pluginData["Name"] ?? $slug));
        $version = sanitize_text_field((string)($pluginData["Version"] ?? ""));
        $hay = strtolower($slug . " " . $name);
        $reasons = [];
        $checks = [];
        $action = "Keep unless duplicate/unused; validate in sandbox before change.";
        $score = 1;

        foreach ($catalog as $rule) {
            $pattern = (string)($rule["pattern"] ?? "");
            if ($pattern === "" || !preg_match($pattern, $hay)) {
                continue;
            }
            $score = max($score, (int)($rule["risk_score"] ?? 1));
            $reason = sanitize_text_field((string)($rule["reason"] ?? ""));
            if ($reason !== "") {
                $reasons[] = $reason;
            }
            $action = sanitize_text_field((string)($rule["action"] ?? $action));
            foreach ((array)($rule["checks"] ?? []) as $check) {
                $safeCheck = sanitize_text_field((string)$check);
                if ($safeCheck !== "") {
                    $checks[] = $safeCheck;
                }
            }
        }

        $isOutdated = is_array($updates) && isset($updates[$slug]);
        if ($isOutdated) {
            $score = min(10, $score + 2);
            $reasons[] = "Plugin has an available update; outdated versions can increase security and compatibility risk.";
        }

        if (stripos($name, "pro") !== false) {
            $score = min(10, $score + 1);
        }
        if (stripos($name, "woocommerce") !== false) {
            $score = min(10, $score + 1);
        }

        if ($score < 4) {
            continue;
        }
        $riskLevel = ($score >= 8) ? "high" : (($score >= 6) ? "medium" : "low");
        if ($riskLevel === "high") {
            $high += 1;
        } elseif ($riskLevel === "medium") {
            $medium += 1;
        }
        $candidates[] = [
            "slug" => sanitize_text_field($slug),
            "name" => $name,
            "version" => $version,
            "risk_score" => $score,
            "risk_level" => $riskLevel,
            "update_available" => $isOutdated ? 1 : 0,
            "reasons" => array_slice(array_values(array_unique(array_map("sanitize_text_field", $reasons))), 0, 3),
            "suggested_action" => $action,
            "functional_checks" => array_slice(array_values(array_unique(array_map("sanitize_text_field", $checks))), 0, 6),
        ];
    }

    usort($candidates, function ($a, $b) {
        return (int)($b["risk_score"] ?? 0) <=> (int)($a["risk_score"] ?? 0);
    });

    return [
        "high_risk_plugin_count" => $high,
        "medium_risk_plugin_count" => $medium,
        "risk_candidates" => array_slice($candidates, 0, 80),
    ];
}

function ai_webadmin_collect_woocommerce_snapshot($activePluginSlugs) {
    $activeLookup = [];
    foreach ((array)$activePluginSlugs as $slug) {
        $activeLookup[(string)$slug] = true;
    }
    $woocommerceActive = isset($activeLookup["woocommerce/woocommerce.php"]);
    $defaults = [
        "active" => $woocommerceActive ? 1 : 0,
        "status" => $woocommerceActive ? "active_unknown" : "not_active",
        "product_count" => 0,
        "completed_order_count" => 0,
        "last_sale_at" => 0,
        "sales_stale_days" => null,
    ];
    if (!$woocommerceActive) {
        return $defaults;
    }

    $productCount = 0;
    if (post_type_exists("product")) {
        $productCounts = wp_count_posts("product");
        if (is_object($productCounts)) {
            $productCount = max(0, (int)($productCounts->publish ?? 0));
        }
    }

    $completedOrderCount = 0;
    if (function_exists("wc_orders_count")) {
        $completedOrderCount = max(0, (int)wc_orders_count("completed"));
    } else {
        $shopOrderCounts = wp_count_posts("shop_order");
        if (is_object($shopOrderCounts)) {
            $completedOrderCount = max(0, (int)($shopOrderCounts->{"wc-completed"} ?? 0));
        }
    }

    $lastSaleAt = 0;
    if (function_exists("wc_get_orders")) {
        $latestIds = wc_get_orders([
            "status" => ["completed"],
            "limit" => 1,
            "orderby" => "date",
            "order" => "DESC",
            "return" => "ids",
        ]);
        if (is_array($latestIds) && !empty($latestIds)) {
            $orderId = (int)$latestIds[0];
            if ($orderId > 0 && function_exists("wc_get_order")) {
                $order = wc_get_order($orderId);
                if ($order && method_exists($order, "get_date_completed")) {
                    $dateObj = $order->get_date_completed();
                    if (!$dateObj && method_exists($order, "get_date_created")) {
                        $dateObj = $order->get_date_created();
                    }
                    if ($dateObj && method_exists($dateObj, "getTimestamp")) {
                        $lastSaleAt = max(0, (int)$dateObj->getTimestamp());
                    }
                }
            }
        }
    }
    if ($lastSaleAt <= 0) {
        $latestCompleted = get_posts([
            "post_type" => "shop_order",
            "post_status" => "wc-completed",
            "numberposts" => 1,
            "orderby" => "date",
            "order" => "DESC",
            "fields" => "ids",
            "suppress_filters" => true,
        ]);
        if (is_array($latestCompleted) && !empty($latestCompleted)) {
            $ts = get_post_time("U", true, (int)$latestCompleted[0]);
            if (is_numeric($ts)) {
                $lastSaleAt = max(0, (int)$ts);
            }
        }
    }

    $salesStaleDays = null;
    if ($lastSaleAt > 0) {
        $salesStaleDays = max(0, (int)floor((time() - $lastSaleAt) / DAY_IN_SECONDS));
    }

    $status = "active_sales";
    if ($completedOrderCount <= 0) {
        $status = "no_sales";
    } elseif ($salesStaleDays !== null && $salesStaleDays >= 365) {
        $status = "stale_sales";
    }

    return [
        "active" => 1,
        "status" => $status,
        "product_count" => $productCount,
        "completed_order_count" => $completedOrderCount,
        "last_sale_at" => $lastSaleAt,
        "sales_stale_days" => $salesStaleDays,
    ];
}

function ai_webadmin_plugin_audit_summary($allPlugins, $activePluginSlugs) {
    $activeLookup = [];
    foreach ((array)$activePluginSlugs as $slug) {
        $activeLookup[(string)$slug] = true;
    }

    $migrationSlugs = ai_webadmin_migration_replication_plugin_slugs();
    $migrationLookup = array_fill_keys($migrationSlugs, true);
    $staticSlugs = ai_webadmin_static_export_plugin_slugs();
    $staticLookup = array_fill_keys($staticSlugs, true);
    $settings = ai_webadmin_get_settings();
    $staticFailureSeen = ((int)($settings["static_export_last_error_at"] ?? 0) > 0);
    $unneeded = [];
    $inactive = [];
    $migration = [];
    $staticExport = [];
    $activeSlugs = [];
    $activePlugins = [];

    foreach ((array)$allPlugins as $slug => $pluginData) {
        $slug = (string)$slug;
        $name = strtolower((string)($pluginData["Name"] ?? ""));
        $isActive = isset($activeLookup[$slug]);
        if ($isActive) {
            $activeSlugs[] = $slug;
            $activePlugins[] = [
                "slug" => sanitize_text_field($slug),
                "name" => sanitize_text_field((string)($pluginData["Name"] ?? $slug)),
                "version" => sanitize_text_field((string)($pluginData["Version"] ?? "")),
            ];
        }
        if (!$isActive) {
            $inactive[] = $slug;
            $unneeded[] = $slug;
        }
        if (isset($migrationLookup[$slug])) {
            $migration[] = $slug;
            if (!in_array($slug, $unneeded, true)) {
                $unneeded[] = $slug;
            }
        }
        if (isset($staticLookup[$slug]) || preg_match('#^(simply-static|wp2static|static-html-output-plugin)/#i', $slug)) {
            $staticExport[] = $slug;
            if ($staticFailureSeen && !in_array($slug, $unneeded, true)) {
                $unneeded[] = $slug;
            }
        }
        if (strpos($name, "hello dolly") !== false || strpos($name, "sample") !== false || strpos($name, "demo") !== false) {
            if (!in_array($slug, $unneeded, true)) {
                $unneeded[] = $slug;
            }
        }
    }

    return [
        "plugin_total_count" => count((array)$allPlugins),
        "active_plugin_count" => count((array)$activePluginSlugs),
        "inactive_plugin_count" => count($inactive),
        "migration_plugin_count" => count($migration),
        "static_export_plugin_count" => count($staticExport),
        "unneeded_plugin_count" => count($unneeded),
        "active_plugin_slugs" => array_slice(array_values(array_unique($activeSlugs)), 0, 400),
        "active_plugins" => array_slice($activePlugins, 0, 400),
        "inactive_plugin_slugs" => array_slice(array_values(array_unique($inactive)), 0, 200),
        "migration_plugin_slugs" => array_slice(array_values(array_unique($migration)), 0, 200),
        "static_export_plugin_slugs" => array_slice(array_values(array_unique($staticExport)), 0, 200),
        "unneeded_plugin_slugs" => array_slice(array_values(array_unique($unneeded)), 0, 200),
    ];
}

function ai_webadmin_collect_audit_metrics() {
    $settings = ai_webadmin_get_settings();
    if (!function_exists("get_plugin_updates") || !function_exists("get_plugins")) {
        require_once ABSPATH . "wp-admin/includes/plugin.php";
        require_once ABSPATH . "wp-admin/includes/update.php";
    }
    $updates = function_exists("get_plugin_updates") ? get_plugin_updates() : [];
    $allPlugins = function_exists("get_plugins") ? get_plugins() : [];
    $activePluginSlugs = (array)get_option("active_plugins", []);
    $activeData = [];
    foreach ($activePluginSlugs as $slug) {
        if (isset($allPlugins[$slug]) && is_array($allPlugins[$slug])) {
            $activeData[] = $allPlugins[$slug];
        }
    }
    $pluginAudit = ai_webadmin_plugin_audit_summary($allPlugins, $activePluginSlugs);
    $pluginRisk = ai_webadmin_collect_plugin_risk_candidates($allPlugins, $activePluginSlugs, $updates);
    $trackingSnapshot = ai_webadmin_collect_site_kit_tracking_snapshot($activePluginSlugs);
    $woocommerceSnapshot = ai_webadmin_collect_woocommerce_snapshot($activePluginSlugs);
    $inactiveCount = (int)$pluginAudit["inactive_plugin_count"];
    $redundantCount = ai_webadmin_detect_redundant_plugins($activeData);
    $ssoPluginCount = ai_webadmin_detect_sso_plugins($activeData);
    $smtpPluginCount = ai_webadmin_count_active_smtp_plugins($activePluginSlugs);

    $pendingComments = (int)get_comments([
        "status" => "hold",
        "count" => true,
        "type" => "comment",
    ]);
    $emailQueue = apply_filters("ai_webadmin_email_queue_count", null);
    $emailQueueCount = is_numeric($emailQueue) ? max(0, (int)$emailQueue) : null;
    $lastCleanup = get_option("ai_webadmin_inactive_user_cleanup_last", []);
    $inactiveDeleted = is_array($lastCleanup) ? max(0, (int)($lastCleanup["deleted_count"] ?? 0)) : 0;
    $inactiveCandidates = is_array($lastCleanup) ? max(0, (int)($lastCleanup["candidate_count"] ?? 0)) : 0;
    $staticExportLastStatus = sanitize_text_field((string)($settings["static_export_last_status"] ?? ""));
    $staticExportErrorMessage = sanitize_text_field((string)($settings["static_export_last_error_message"] ?? ""));
    $staticExportErrorSource = sanitize_text_field((string)($settings["static_export_last_error_source"] ?? ""));
    $staticExportErrorAt = (int)($settings["static_export_last_error_at"] ?? 0);
    $staticExportRemovedJson = (string)($settings["static_export_last_removed_json"] ?? "[]");
    $staticExportRemoved = json_decode($staticExportRemovedJson, true);
    if (!is_array($staticExportRemoved)) {
        $staticExportRemoved = [];
    }
    $staticExportMemoryErrorCount = ($staticExportErrorAt > 0 && $staticExportErrorMessage !== "") ? 1 : 0;
    $autoloadStats = ai_webadmin_collect_autoload_option_stats(20);
    $autoloadTopOptions = isset($autoloadStats["autoload_top_options"]) && is_array($autoloadStats["autoload_top_options"])
        ? $autoloadStats["autoload_top_options"]
        : [];
    $pageCacheSnapshot = ai_webadmin_collect_page_cache_health_snapshot(false);
    $pageCacheHeaderNames = isset($pageCacheSnapshot["header_names"]) && is_array($pageCacheSnapshot["header_names"])
        ? array_slice(array_values(array_unique(array_map("sanitize_text_field", $pageCacheSnapshot["header_names"]))), 0, 20)
        : [];
    $pageCacheStatusCodes = isset($pageCacheSnapshot["status_codes"]) && is_array($pageCacheSnapshot["status_codes"])
        ? array_slice(array_values(array_map("intval", $pageCacheSnapshot["status_codes"])), 0, 3)
        : [];

    return [
        "email_queue_count" => $emailQueueCount,
        "outdated_plugin_count" => is_array($updates) ? count($updates) : 0,
        "inactive_plugin_count" => $inactiveCount,
        "redundant_plugin_count" => $redundantCount,
        "sso_plugin_count" => $ssoPluginCount,
        "pending_comment_moderation_count" => max(0, $pendingComments),
        "plugin_total_count" => (int)$pluginAudit["plugin_total_count"],
        "active_plugin_count" => (int)$pluginAudit["active_plugin_count"],
        "migration_plugin_count" => (int)$pluginAudit["migration_plugin_count"],
        "unneeded_plugin_count" => (int)$pluginAudit["unneeded_plugin_count"],
        "high_risk_plugin_count" => (int)($pluginRisk["high_risk_plugin_count"] ?? 0),
        "medium_risk_plugin_count" => (int)($pluginRisk["medium_risk_plugin_count"] ?? 0),
        "inactive_user_deleted_count" => $inactiveDeleted,
        "inactive_user_candidate_count" => $inactiveCandidates,
        "autoload_option_count" => isset($autoloadStats["autoload_option_count"]) ? max(0, (int)$autoloadStats["autoload_option_count"]) : null,
        "autoload_total_bytes" => isset($autoloadStats["autoload_total_bytes"]) ? max(0, (int)$autoloadStats["autoload_total_bytes"]) : null,
        "autoload_total_kb" => isset($autoloadStats["autoload_total_kb"]) ? max(0, (int)$autoloadStats["autoload_total_kb"]) : null,
        "autoload_last_cleanup_at" => (int)($settings["autoload_last_cleanup_at"] ?? 0),
        "autoload_last_cleanup_summary" => sanitize_text_field((string)($settings["autoload_last_cleanup_summary"] ?? "")),
        "page_cache_builtin_enabled" => !empty($settings["enable_builtin_page_cache"]) ? 1 : 0,
        "page_cache_ttl_seconds" => max(60, min(86400, (int)($settings["page_cache_ttl_seconds"] ?? 600))),
        "page_cache_last_cleared_at" => (int)($settings["page_cache_last_cleared_at"] ?? 0),
        "page_cache_last_clear_reason" => sanitize_text_field((string)($settings["page_cache_last_clear_reason"] ?? "")),
        "page_cache_health_status" => sanitize_text_field((string)($pageCacheSnapshot["status"] ?? "")),
        "page_cache_header_detected" => !empty($pageCacheSnapshot["header_detected"]) ? 1 : 0,
        "page_cache_plugin_detected" => !empty($pageCacheSnapshot["plugin_detected"]) ? 1 : 0,
        "page_cache_median_ttfb_ms" => isset($pageCacheSnapshot["median_ttfb_ms"]) && $pageCacheSnapshot["median_ttfb_ms"] !== null
            ? max(0, (int)$pageCacheSnapshot["median_ttfb_ms"])
            : null,
        "page_cache_checked_at" => (int)($pageCacheSnapshot["checked_at"] ?? 0),
        "smtp_plugin_count" => $smtpPluginCount,
        "static_export_plugin_count" => (int)$pluginAudit["static_export_plugin_count"],
        "static_export_memory_error_count" => $staticExportMemoryErrorCount,
        "static_export_removed_plugin_count" => count($staticExportRemoved),
        "static_export_last_status" => $staticExportLastStatus,
        "static_export_last_error_message" => $staticExportErrorMessage,
        "static_export_last_error_source" => $staticExportErrorSource,
        "static_export_last_error_at" => $staticExportErrorAt,
        "analytics_site_kit_active" => (int)($trackingSnapshot["analytics_site_kit_active"] ?? 0),
        "analytics_pages_checked_count" => (int)($trackingSnapshot["analytics_pages_checked_count"] ?? 0),
        "analytics_pages_with_tracking_count" => (int)($trackingSnapshot["analytics_pages_with_tracking_count"] ?? 0),
        "analytics_pages_missing_tracking_count" => (int)($trackingSnapshot["analytics_pages_missing_tracking_count"] ?? 0),
        "analytics_unreachable_page_count" => isset($trackingSnapshot["analytics_unreachable_urls"])
            ? count((array)$trackingSnapshot["analytics_unreachable_urls"])
            : 0,
        "analytics_tag_coverage_percent" => isset($trackingSnapshot["analytics_tag_coverage_percent"]) && $trackingSnapshot["analytics_tag_coverage_percent"] !== null
            ? max(0, min(100, (int)$trackingSnapshot["analytics_tag_coverage_percent"]))
            : null,
        "analytics_measurement_id_count" => (int)($trackingSnapshot["analytics_measurement_id_count"] ?? 0),
        "analytics_gtm_container_count" => (int)($trackingSnapshot["analytics_gtm_container_count"] ?? 0),
        "analytics_status" => sanitize_text_field((string)($trackingSnapshot["analytics_status"] ?? "")),
        "analytics_last_checked_at" => (int)($trackingSnapshot["analytics_last_checked_at"] ?? 0),
        "woocommerce_active" => (int)($woocommerceSnapshot["active"] ?? 0),
        "woocommerce_status" => sanitize_text_field((string)($woocommerceSnapshot["status"] ?? "")),
        "woocommerce_product_count" => max(0, (int)($woocommerceSnapshot["product_count"] ?? 0)),
        "woocommerce_completed_order_count" => max(0, (int)($woocommerceSnapshot["completed_order_count"] ?? 0)),
        "woocommerce_last_sale_at" => max(0, (int)($woocommerceSnapshot["last_sale_at"] ?? 0)),
        "woocommerce_sales_stale_days" => isset($woocommerceSnapshot["sales_stale_days"]) && $woocommerceSnapshot["sales_stale_days"] !== null
            ? max(0, (int)$woocommerceSnapshot["sales_stale_days"])
            : null,
        "plugin_inventory" => [
            "active_plugin_slugs" => $pluginAudit["active_plugin_slugs"],
            "active_plugins" => $pluginAudit["active_plugins"],
            "inactive_plugin_slugs" => $pluginAudit["inactive_plugin_slugs"],
            "migration_plugin_slugs" => $pluginAudit["migration_plugin_slugs"],
            "static_export_plugin_slugs" => $pluginAudit["static_export_plugin_slugs"],
            "unneeded_plugin_slugs" => $pluginAudit["unneeded_plugin_slugs"],
            "static_export_removed_slugs" => array_slice(array_values(array_unique(array_map("sanitize_text_field", $staticExportRemoved))), 0, 50),
            "risk_candidates" => array_slice((array)($pluginRisk["risk_candidates"] ?? []), 0, 80),
            "analytics_missing_urls" => array_slice((array)($trackingSnapshot["analytics_missing_urls"] ?? []), 0, 12),
            "analytics_unreachable_urls" => array_slice((array)($trackingSnapshot["analytics_unreachable_urls"] ?? []), 0, 12),
            "analytics_measurement_ids" => array_slice((array)($trackingSnapshot["analytics_measurement_ids"] ?? []), 0, 15),
            "analytics_gtm_ids" => array_slice((array)($trackingSnapshot["analytics_gtm_ids"] ?? []), 0, 15),
            "woocommerce_status" => sanitize_text_field((string)($woocommerceSnapshot["status"] ?? "")),
            "autoload_top_options" => array_slice($autoloadTopOptions, 0, 20),
            "page_cache_header_names" => $pageCacheHeaderNames,
            "page_cache_status_codes" => $pageCacheStatusCodes,
        ],
    ];
}

function ai_webadmin_collect_outdated_plugin_updates($limit = 50) {
    if (!function_exists("get_plugins")) {
        require_once ABSPATH . "wp-admin/includes/plugin.php";
    }
    $allPlugins = function_exists("get_plugins") ? get_plugins() : [];
    $updatesTransient = get_site_transient("update_plugins");
    $updates = (is_object($updatesTransient) && is_array($updatesTransient->response)) ? $updatesTransient->response : [];
    $result = [];
    foreach ($updates as $pluginFile => $updateObj) {
        if (!is_string($pluginFile) || $pluginFile === "") {
            continue;
        }
        $name = isset($allPlugins[$pluginFile]["Name"]) ? (string)$allPlugins[$pluginFile]["Name"] : $pluginFile;
        $currentVersion = isset($allPlugins[$pluginFile]["Version"]) ? (string)$allPlugins[$pluginFile]["Version"] : "";
        $newVersion = is_object($updateObj) && isset($updateObj->new_version) ? (string)$updateObj->new_version : "";
        $packageUrl = is_object($updateObj) && isset($updateObj->package) ? (string)$updateObj->package : "";
        $result[] = [
            "plugin_file" => sanitize_text_field($pluginFile),
            "name" => sanitize_text_field($name),
            "current_version" => sanitize_text_field($currentVersion),
            "new_version" => sanitize_text_field($newVersion),
            "has_package" => ($packageUrl !== "") ? 1 : 0,
        ];
        if (count($result) >= max(1, min(200, (int)$limit))) {
            break;
        }
    }
    return $result;
}

function ai_webadmin_extract_first_list_token($raw) {
    $text = sanitize_textarea_field((string)$raw);
    if ($text === "") {
        return "";
    }
    $parts = preg_split('/[\r\n,;|]+/', $text);
    if (!is_array($parts)) {
        return "";
    }
    foreach ($parts as $part) {
        $value = trim((string)$part);
        if ($value !== "") {
            return sanitize_text_field($value);
        }
    }
    return "";
}

function ai_webadmin_guess_attachment_subject($attachmentId, $filePath = "") {
    $id = (int)$attachmentId;
    $title = sanitize_text_field((string)get_the_title($id));
    $subject = $title;
    if ($subject === "" || preg_match('/^(screenshot|image|photo|img|attachment|dsc|pic)[\s\-_0-9]*$/i', $subject)) {
        $path = (string)$filePath;
        if ($path === "") {
            $path = (string)get_attached_file($id);
        }
        $base = sanitize_text_field((string)pathinfo($path, PATHINFO_FILENAME));
        $subject = str_replace(["_", "-"], " ", $base);
    }
    $subject = preg_replace('/\b\d{4}[-_]\d{1,2}[-_]\d{1,2}\b/', "", (string)$subject);
    $subject = preg_replace('/\b\d{1,2}[:.]\d{2}([:.]\d{2})?\s*(am|pm)?\b/i', "", (string)$subject);
    $subject = preg_replace('/\s+/', " ", (string)$subject);
    $subject = trim((string)$subject);
    if ($subject === "") {
        $subject = "service photo";
    }
    return sanitize_text_field(ucwords(strtolower($subject)));
}

function ai_webadmin_sanitize_attachment_filename_slug($raw, $fallback = "") {
    $slug = sanitize_title((string)$raw);
    if ($slug === "") {
        $slug = sanitize_title((string)$fallback);
    }
    if ($slug === "") {
        $slug = "media-asset";
    }
    return substr($slug, 0, 110);
}

function ai_webadmin_sanitize_attachment_seo_meta($meta, $fallback = []) {
    $base = is_array($fallback) ? $fallback : [];
    $candidate = is_array($meta) ? $meta : [];
    return [
        "title" => sanitize_text_field((string)($candidate["title"] ?? $base["title"] ?? "")),
        "alt" => sanitize_text_field((string)($candidate["alt"] ?? $base["alt"] ?? "")),
        "caption" => sanitize_text_field((string)($candidate["caption"] ?? $base["caption"] ?? "")),
        "description" => sanitize_textarea_field((string)($candidate["description"] ?? $base["description"] ?? "")),
        "filename_slug" => ai_webadmin_sanitize_attachment_filename_slug(
            (string)($candidate["filename_slug"] ?? ""),
            (string)($base["filename_slug"] ?? "")
        ),
    ];
}

function ai_webadmin_attachment_requires_media_metadata_refresh($attachmentId, $settings) {
    $id = (int)$attachmentId;
    if ($id <= 0) {
        return false;
    }
    if (!empty($settings["media_force_metadata_refresh"])) {
        return true;
    }
    $alt = sanitize_text_field((string)get_post_meta($id, "_wp_attachment_image_alt", true));
    $title = sanitize_text_field((string)get_the_title($id));
    $caption = sanitize_text_field((string)get_post_field("post_excerpt", $id));
    $description = sanitize_textarea_field((string)get_post_field("post_content", $id));
    return ($alt === "" || $title === "" || $caption === "" || $description === "");
}

function ai_webadmin_generate_ai_media_meta_for_attachment($attachmentId, $settings, $fallbackMeta, $assetUrl = "") {
    $fallback = ai_webadmin_sanitize_attachment_seo_meta($fallbackMeta, $fallbackMeta);
    if (empty($settings["media_ai_enrichment_enabled"])) {
        return ["meta" => $fallback, "source" => "fallback"];
    }
    if (!ai_webadmin_can_use_signed_worker_calls($settings)) {
        return ["meta" => $fallback, "source" => "fallback"];
    }
    if (!ai_webadmin_attachment_requires_media_metadata_refresh($attachmentId, $settings)) {
        return ["meta" => $fallback, "source" => "fallback"];
    }
    $localUrl = esc_url_raw((string)$assetUrl);
    if ($localUrl === "") {
        return ["meta" => $fallback, "source" => "fallback"];
    }

    $context = [
        "brand" => sanitize_text_field((string)get_bloginfo("name")),
        "location" => ai_webadmin_extract_first_list_token((string)($settings["seo_target_locations"] ?? "")),
        "primary_keyword" => ai_webadmin_extract_first_list_token((string)($settings["seo_primary_keywords"] ?? "")),
    ];
    $response = ai_webadmin_signed_post($settings, "plugin/wp/media/enrich", [
        "session_id" => trim((string)($settings["onboarding_session_id"] ?? "")),
        "site_url" => home_url("/"),
        "context" => $context,
        "assets" => [[
            "attachment_id" => (int)$attachmentId,
            "url" => $localUrl,
        ]],
    ], 35);
    if (is_wp_error($response)) {
        return ["meta" => $fallback, "source" => "fallback"];
    }

    $statusCode = (int)wp_remote_retrieve_response_code($response);
    $decoded = json_decode((string)wp_remote_retrieve_body($response), true);
    if ($statusCode < 200 || $statusCode >= 300 || !is_array($decoded) || empty($decoded["ok"])) {
        return ["meta" => $fallback, "source" => "fallback"];
    }
    $items = isset($decoded["items"]) && is_array($decoded["items"]) ? $decoded["items"] : [];
    $first = isset($items[0]) && is_array($items[0]) ? $items[0] : [];
    $meta = isset($first["metadata"]) && is_array($first["metadata"]) ? $first["metadata"] : [];
    if (empty($meta)) {
        return ["meta" => $fallback, "source" => "fallback"];
    }
    return [
        "meta" => ai_webadmin_sanitize_attachment_seo_meta($meta, $fallback),
        "source" => sanitize_key((string)($first["source"] ?? "openai")),
    ];
}

function ai_webadmin_build_attachment_seo_meta($attachmentId, $settings, $filePath = "") {
    $brand = sanitize_text_field((string)get_bloginfo("name"));
    $location = ai_webadmin_extract_first_list_token((string)($settings["seo_target_locations"] ?? ""));
    $primaryKeyword = ai_webadmin_extract_first_list_token((string)($settings["seo_primary_keywords"] ?? ""));
    $subject = ai_webadmin_guess_attachment_subject($attachmentId, $filePath);
    if ($primaryKeyword !== "" && stripos($subject, $primaryKeyword) === false) {
        $subject = sanitize_text_field($subject . " " . $primaryKeyword);
    }
    $titleParts = array_values(array_filter([$subject, $brand, $location], function ($v) {
        return trim((string)$v) !== "";
    }));
    $title = sanitize_text_field(implode(" - ", $titleParts));
    if ($title === "") {
        $title = "Optimized media asset";
    }
    $alt = "Photo of " . $subject;
    if ($brand !== "") {
        $alt .= " by " . $brand;
    }
    if ($location !== "") {
        $alt .= " in " . $location;
    }
    $alt = sanitize_text_field(trim($alt) . ".");
    $caption = $subject;
    if ($brand !== "") {
        $caption .= " - " . $brand;
    }
    if ($location !== "") {
        $caption .= ", " . $location;
    }
    $caption = sanitize_text_field($caption);
    $description = $subject;
    if ($brand !== "") {
        $description .= " for " . $brand;
    }
    if ($location !== "") {
        $description .= " in " . $location;
    }
    $description .= ". Optimized and delivered through Cloudflare R2/CDN by AI WebAdmin.";
    $description = sanitize_textarea_field($description);
    $filenameSeed = sanitize_title(implode(" ", array_filter([$brand, $primaryKeyword, $location, $subject])));
    if ($filenameSeed === "") {
        $filenameSeed = "media-" . (int)$attachmentId;
    }
    $filenameSeed = substr($filenameSeed, 0, 110);
    return [
        "title" => $title,
        "alt" => $alt,
        "caption" => $caption,
        "description" => $description,
        "filename_slug" => sanitize_title($filenameSeed),
    ];
}

function ai_webadmin_get_primary_admin_user_id() {
    $adminEmail = sanitize_email((string)get_option("admin_email", ""));
    if ($adminEmail !== "") {
        $byEmail = get_user_by("email", $adminEmail);
        if ($byEmail && !empty($byEmail->ID)) {
            return (int)$byEmail->ID;
        }
    }
    $admins = get_users([
        "role" => "administrator",
        "number" => 1,
        "orderby" => "registered",
        "order" => "ASC",
        "fields" => ["ID"],
    ]);
    if (is_array($admins) && !empty($admins[0]->ID)) {
        return (int)$admins[0]->ID;
    }
    return 0;
}

function ai_webadmin_maybe_reassign_attachment_author($attachmentId, $settings) {
    if (empty($settings["media_assign_to_primary_admin"])) {
        return false;
    }
    $id = (int)$attachmentId;
    if ($id <= 0) {
        return false;
    }
    $targetAuthor = ai_webadmin_get_primary_admin_user_id();
    if ($targetAuthor <= 0) {
        return false;
    }
    $currentAuthor = (int)get_post_field("post_author", $id);
    if ($currentAuthor === $targetAuthor) {
        return false;
    }
    $updated = wp_update_post([
        "ID" => $id,
        "post_author" => $targetAuthor,
    ], true);
    return !is_wp_error($updated);
}

function ai_webadmin_apply_attachment_seo_meta($attachmentId, $settings, $meta) {
    if (empty($settings["media_seo_autofill_enabled"]) || !is_array($meta)) {
        return false;
    }
    $id = (int)$attachmentId;
    if ($id <= 0) {
        return false;
    }
    $force = !empty($settings["media_force_metadata_refresh"]);
    $title = sanitize_text_field((string)($meta["title"] ?? ""));
    $alt = sanitize_text_field((string)($meta["alt"] ?? ""));
    $caption = sanitize_text_field((string)($meta["caption"] ?? ""));
    $description = sanitize_textarea_field((string)($meta["description"] ?? ""));
    $currentAlt = sanitize_text_field((string)get_post_meta($id, "_wp_attachment_image_alt", true));
    $currentTitle = sanitize_text_field((string)get_the_title($id));
    $currentCaption = sanitize_text_field((string)get_post_field("post_excerpt", $id));
    $currentDescription = sanitize_textarea_field((string)get_post_field("post_content", $id));
    $changed = false;
    if ($alt !== "" && ($force || $currentAlt === "")) {
        update_post_meta($id, "_wp_attachment_image_alt", $alt);
        $changed = true;
    }
    $patch = ["ID" => $id];
    if ($title !== "" && ($force || $currentTitle === "")) {
        $patch["post_title"] = $title;
    }
    if ($caption !== "" && ($force || $currentCaption === "")) {
        $patch["post_excerpt"] = $caption;
    }
    if ($description !== "" && ($force || $currentDescription === "")) {
        $patch["post_content"] = $description;
    }
    if (count($patch) > 1) {
        $updated = wp_update_post($patch, true);
        if (!is_wp_error($updated)) {
            $changed = true;
        }
    }
    return $changed;
}

function ai_webadmin_maybe_rename_attachment_file_for_seo($attachmentId, $settings, $filenameSlug) {
    $id = (int)$attachmentId;
    $slug = sanitize_title((string)$filenameSlug);
    if ($id <= 0 || $slug === "") {
        return ["renamed" => false, "file_path" => (string)get_attached_file($id)];
    }
    $currentFile = (string)get_attached_file($id);
    if ($currentFile === "" || !file_exists($currentFile)) {
        return ["renamed" => false, "file_path" => $currentFile];
    }
    $pathInfo = pathinfo($currentFile);
    $ext = strtolower((string)($pathInfo["extension"] ?? ""));
    $oldBase = sanitize_title((string)($pathInfo["filename"] ?? ""));
    if ($oldBase === $slug) {
        return ["renamed" => false, "file_path" => $currentFile];
    }
    $uploads = wp_get_upload_dir();
    $baseDir = isset($uploads["basedir"]) ? rtrim((string)$uploads["basedir"], "/\\") : "";
    if ($baseDir === "" || strpos($currentFile, $baseDir) !== 0) {
        return ["renamed" => false, "file_path" => $currentFile];
    }
    $relative = (string)get_post_meta($id, "_wp_attached_file", true);
    if ($relative === "") {
        $relative = ltrim(str_replace($baseDir, "", $currentFile), "/\\");
    }
    $dirRel = trim((string)dirname($relative), ".\\/ ");
    $newRelBase = $slug;
    $newRel = ($dirRel !== "" ? $dirRel . "/" : "") . $newRelBase . ($ext !== "" ? "." . $ext : "");
    $newAbs = $baseDir . "/" . $newRel;
    if (file_exists($newAbs)) {
        $newRelBase = $slug . "-" . $id;
        $newRel = ($dirRel !== "" ? $dirRel . "/" : "") . $newRelBase . ($ext !== "" ? "." . $ext : "");
        $newAbs = $baseDir . "/" . $newRel;
    }
    if (!@rename($currentFile, $newAbs)) {
        return ["renamed" => false, "file_path" => $currentFile];
    }
    update_attached_file($id, $newAbs);
    $metadata = wp_get_attachment_metadata($id);
    if (is_array($metadata)) {
        $oldBaseRaw = (string)($pathInfo["filename"] ?? "");
        $currentDirAbs = (string)($pathInfo["dirname"] ?? "");
        $newDirAbs = dirname($newAbs);
        if (!empty($metadata["sizes"]) && is_array($metadata["sizes"])) {
            foreach ($metadata["sizes"] as $sizeKey => $sizeData) {
                if (!is_array($sizeData) || empty($sizeData["file"])) {
                    continue;
                }
                $sizeFile = (string)$sizeData["file"];
                if (strpos($sizeFile, $oldBaseRaw) !== 0) {
                    continue;
                }
                $suffix = substr($sizeFile, strlen($oldBaseRaw));
                $newSizeFile = $newRelBase . $suffix;
                $oldSizeAbs = $currentDirAbs . "/" . $sizeFile;
                $newSizeAbs = $newDirAbs . "/" . $newSizeFile;
                if (file_exists($oldSizeAbs)) {
                    @rename($oldSizeAbs, $newSizeAbs);
                }
                $metadata["sizes"][$sizeKey]["file"] = $newSizeFile;
            }
        }
        $metadata["file"] = $newRel;
        wp_update_attachment_metadata($id, $metadata);
    }
    return ["renamed" => true, "file_path" => $newAbs];
}

function ai_webadmin_maybe_optimize_attachment_image($attachmentId, $settings, $filePath) {
    if (empty($settings["media_optimize_images"])) {
        return ["optimized" => false, "before_bytes" => 0, "after_bytes" => 0];
    }
    $path = (string)$filePath;
    if ($path === "" || !file_exists($path)) {
        return ["optimized" => false, "before_bytes" => 0, "after_bytes" => 0];
    }
    $mime = strtolower((string)get_post_mime_type((int)$attachmentId));
    if (!in_array($mime, ["image/jpeg", "image/jpg", "image/png", "image/webp"], true)) {
        return ["optimized" => false, "before_bytes" => 0, "after_bytes" => 0];
    }
    $beforeBytes = max(0, (int)@filesize($path));
    $sizeInfo = @getimagesize($path);
    $width = is_array($sizeInfo) ? max(0, (int)($sizeInfo[0] ?? 0)) : 0;
    $height = is_array($sizeInfo) ? max(0, (int)($sizeInfo[1] ?? 0)) : 0;
    $maxDimension = max(640, min(4096, (int)($settings["media_max_dimension_px"] ?? 1400)));
    $targetMaxBytes = max(262144, min(20971520, (int)($settings["media_target_max_bytes"] ?? 1572864)));
    $quality = max(40, min(95, (int)($settings["media_image_quality"] ?? 78)));
    $needsResize = ($width > $maxDimension || $height > $maxDimension);
    $needsRecompress = ($beforeBytes > $targetMaxBytes);
    if (!$needsResize && !$needsRecompress) {
        return ["optimized" => false, "before_bytes" => $beforeBytes, "after_bytes" => $beforeBytes];
    }
    if (!function_exists("wp_get_image_editor")) {
        require_once ABSPATH . "wp-admin/includes/image.php";
    }
    $editor = wp_get_image_editor($path);
    if (is_wp_error($editor)) {
        return ["optimized" => false, "before_bytes" => $beforeBytes, "after_bytes" => $beforeBytes];
    }
    if (method_exists($editor, "set_quality")) {
        $editor->set_quality($quality);
    }
    if ($needsResize && $width > 0 && $height > 0) {
        if ($width >= $height) {
            $newWidth = $maxDimension;
            $newHeight = max(1, (int)round(($height / $width) * $maxDimension));
        } else {
            $newHeight = $maxDimension;
            $newWidth = max(1, (int)round(($width / $height) * $maxDimension));
        }
        $editor->resize($newWidth, $newHeight, false);
    }
    $saved = $editor->save($path);
    if (is_wp_error($saved)) {
        return ["optimized" => false, "before_bytes" => $beforeBytes, "after_bytes" => $beforeBytes];
    }
    if (!function_exists("wp_generate_attachment_metadata")) {
        require_once ABSPATH . "wp-admin/includes/image.php";
    }
    $metadata = function_exists("wp_generate_attachment_metadata")
        ? wp_generate_attachment_metadata((int)$attachmentId, $path)
        : null;
    if (is_array($metadata) && !empty($metadata) && function_exists("wp_update_attachment_metadata")) {
        wp_update_attachment_metadata((int)$attachmentId, $metadata);
    }
    clearstatcache(true, $path);
    $afterBytes = max(0, (int)@filesize($path));
    return [
        "optimized" => ($afterBytes > 0 && $afterBytes <= $beforeBytes),
        "before_bytes" => $beforeBytes,
        "after_bytes" => $afterBytes,
    ];
}

function ai_webadmin_attachment_local_upload_url($attachmentId) {
    $id = (int)$attachmentId;
    if ($id <= 0) {
        return "";
    }
    $relative = (string)get_post_meta($id, "_wp_attached_file", true);
    if ($relative === "") {
        return "";
    }
    $uploads = wp_get_upload_dir();
    $baseUrl = isset($uploads["baseurl"]) ? rtrim((string)$uploads["baseurl"], "/") : "";
    if ($baseUrl === "") {
        return "";
    }
    return esc_url_raw($baseUrl . "/" . ltrim($relative, "/"));
}

function ai_webadmin_build_r2_key_for_attachment($attachmentId, $settings, $filePath, $filenameSlug = "") {
    $id = (int)$attachmentId;
    $sessionId = sanitize_text_field(trim((string)($settings["onboarding_session_id"] ?? "")));
    if ($sessionId === "") {
        $sessionId = "media";
    }
    $sessionId = preg_replace('/[^a-zA-Z0-9_-]+/', "-", $sessionId);
    $host = strtolower((string)wp_parse_url(home_url("/"), PHP_URL_HOST));
    if ($host === "") {
        $host = "site";
    }
    $host = preg_replace('/[^a-z0-9.-]+/', "-", $host);
    $ext = strtolower((string)pathinfo((string)$filePath, PATHINFO_EXTENSION));
    if ($ext === "") {
        $ext = "jpg";
    }
    $slug = sanitize_title((string)$filenameSlug);
    if ($slug === "") {
        $slug = "media-" . $id;
    }
    $yearMonth = gmdate("Y/m", max(1, (int)get_post_time("U", true, $id)));
    $key = "wp-media-cache/{$sessionId}/{$host}/{$yearMonth}/{$slug}.{$ext}";
    $key = strtolower((string)$key);
    $key = preg_replace('/[^a-z0-9\/._-]+/', "-", $key);
    $key = preg_replace('/-+/', "-", (string)$key);
    return ltrim((string)$key, "/");
}

function ai_webadmin_prepare_media_attachment_for_offload($attachmentId, $settings) {
    $id = (int)$attachmentId;
    if ($id <= 0) {
        return ["ok" => false, "error" => "invalid_attachment_id"];
    }
    $filePath = (string)get_attached_file($id);
    if ($filePath === "" || !file_exists($filePath)) {
        return ["ok" => false, "error" => "missing_local_file"];
    }
    $localUrlBeforeRename = ai_webadmin_attachment_local_upload_url($id);
    $fallbackSeo = ai_webadmin_build_attachment_seo_meta($id, $settings, $filePath);
    $aiResolved = ai_webadmin_generate_ai_media_meta_for_attachment($id, $settings, $fallbackSeo, $localUrlBeforeRename);
    $seo = isset($aiResolved["meta"]) && is_array($aiResolved["meta"])
        ? ai_webadmin_sanitize_attachment_seo_meta($aiResolved["meta"], $fallbackSeo)
        : ai_webadmin_sanitize_attachment_seo_meta($fallbackSeo, $fallbackSeo);
    $seoSource = sanitize_key((string)($aiResolved["source"] ?? "fallback"));
    $rename = ai_webadmin_maybe_rename_attachment_file_for_seo($id, $settings, (string)($seo["filename_slug"] ?? ""));
    $filePath = (string)($rename["file_path"] ?? $filePath);
    $optimized = ai_webadmin_maybe_optimize_attachment_image($id, $settings, $filePath);
    $seoChanged = ai_webadmin_apply_attachment_seo_meta($id, $settings, $seo);
    $authorChanged = ai_webadmin_maybe_reassign_attachment_author($id, $settings);
    $localUrl = ai_webadmin_attachment_local_upload_url($id);
    if ($localUrl === "") {
        return ["ok" => false, "error" => "missing_local_upload_url"];
    }
    $r2Key = ai_webadmin_build_r2_key_for_attachment($id, $settings, $filePath, (string)($seo["filename_slug"] ?? ""));
    if ($seoSource !== "") {
        update_post_meta($id, "_ai_webadmin_media_meta_source", $seoSource);
    }
    return [
        "ok" => true,
        "attachment_id" => $id,
        "url" => $localUrl,
        "r2_key" => $r2Key,
        "ai_meta_source" => $seoSource,
        "ai_enriched" => ($seoSource === "openai") ? 1 : 0,
        "renamed" => !empty($rename["renamed"]),
        "seo_updated" => $seoChanged ? 1 : 0,
        "author_reassigned" => $authorChanged ? 1 : 0,
        "optimized" => !empty($optimized["optimized"]) ? 1 : 0,
        "before_bytes" => max(0, (int)($optimized["before_bytes"] ?? 0)),
        "after_bytes" => max(0, (int)($optimized["after_bytes"] ?? 0)),
    ];
}

function ai_webadmin_collect_media_attachment_batch($afterAttachmentId = 0, $limit = 25, $settings = null) {
    global $wpdb;
    if (!is_array($settings)) {
        $settings = ai_webadmin_get_settings();
    }
    if (!$wpdb) {
        return [
            "items" => [],
            "max_attachment_id" => max(0, (int)$afterAttachmentId),
            "has_more_candidate" => false,
            "prepared_counts" => [],
        ];
    }
    $afterId = max(0, (int)$afterAttachmentId);
    $batchSize = max(5, min(200, (int)$limit));
    $sql = $wpdb->prepare(
        "SELECT ID FROM {$wpdb->posts} WHERE post_type = 'attachment' AND post_mime_type LIKE %s AND ID > %d ORDER BY ID ASC LIMIT %d",
        "image/%",
        $afterId,
        $batchSize
    );
    $ids = $wpdb->get_col($sql);
    if (!is_array($ids)) {
        $ids = [];
    }
    $items = [];
    $maxId = $afterId;
    $stats = [
        "ai_enriched_count" => 0,
        "renamed_count" => 0,
        "seo_updated_count" => 0,
        "author_reassigned_count" => 0,
        "optimized_count" => 0,
        "before_bytes_total" => 0,
        "after_bytes_total" => 0,
    ];
    foreach ($ids as $rawId) {
        $id = (int)$rawId;
        if ($id <= 0) {
            continue;
        }
        if ($id > $maxId) {
            $maxId = $id;
        }
        $prepared = ai_webadmin_prepare_media_attachment_for_offload($id, $settings);
        if (empty($prepared["ok"])) {
            continue;
        }
        $items[] = [
            "attachment_id" => $id,
            "url" => esc_url_raw((string)($prepared["url"] ?? "")),
            "r2_key" => sanitize_text_field((string)($prepared["r2_key"] ?? "")),
        ];
        $stats["renamed_count"] += !empty($prepared["renamed"]) ? 1 : 0;
        $stats["ai_enriched_count"] += !empty($prepared["ai_enriched"]) ? 1 : 0;
        $stats["seo_updated_count"] += !empty($prepared["seo_updated"]) ? 1 : 0;
        $stats["author_reassigned_count"] += !empty($prepared["author_reassigned"]) ? 1 : 0;
        $stats["optimized_count"] += !empty($prepared["optimized"]) ? 1 : 0;
        $stats["before_bytes_total"] += max(0, (int)($prepared["before_bytes"] ?? 0));
        $stats["after_bytes_total"] += max(0, (int)($prepared["after_bytes"] ?? 0));
    }
    return [
        "items" => $items,
        "max_attachment_id" => $maxId,
        "has_more_candidate" => (count($ids) >= $batchSize),
        "prepared_counts" => $stats,
    ];
}

function ai_webadmin_can_use_signed_worker_calls($settings = null) {
    if (!is_array($settings)) {
        $settings = ai_webadmin_get_settings();
    }
    if (empty($settings["worker_base_url"]) || empty($settings["plugin_shared_secret"])) {
        return false;
    }
    $sessionId = trim((string)($settings["onboarding_session_id"] ?? ""));
    return ($sessionId !== "");
}

function ai_webadmin_normalize_media_public_base_url($raw) {
    $url = trim((string)$raw);
    if ($url === "") {
        return "";
    }
    $url = esc_url_raw($url);
    if ($url === "") {
        return "";
    }
    $parts = wp_parse_url($url);
    if (!is_array($parts) || empty($parts["host"])) {
        return "";
    }
    $scheme = strtolower((string)($parts["scheme"] ?? "https"));
    if (!in_array($scheme, ["https", "http"], true)) {
        return "";
    }
    $host = strtolower((string)$parts["host"]);
    $port = isset($parts["port"]) ? ":" . (int)$parts["port"] : "";
    $path = isset($parts["path"]) ? "/" . trim((string)$parts["path"], "/") : "";
    if ($path === "/") {
        $path = "";
    }
    return rtrim($scheme . "://" . $host . $port . $path, "/");
}

function ai_webadmin_media_offload_sanitize_processed_items($rawItems, $limit = 200) {
    if (!is_array($rawItems)) {
        return [];
    }
    $items = [];
    foreach ($rawItems as $item) {
        if (!is_array($item)) {
            continue;
        }
        $attachmentId = isset($item["attachment_id"]) ? (int)$item["attachment_id"] : 0;
        $key = trim((string)($item["key"] ?? ""));
        if ($attachmentId <= 0 || $key === "") {
            continue;
        }
        $publicUrl = esc_url_raw((string)($item["public_url"] ?? ""));
        $items[] = [
            "attachment_id" => $attachmentId,
            "key" => sanitize_text_field($key),
            "public_url" => $publicUrl,
        ];
        if (count($items) >= max(1, min(1000, (int)$limit))) {
            break;
        }
    }
    return $items;
}

function ai_webadmin_media_public_url_from_key($baseUrl, $key) {
    $base = ai_webadmin_normalize_media_public_base_url($baseUrl);
    $cleanKey = ltrim(trim((string)$key), "/");
    if ($base === "" || $cleanKey === "") {
        return "";
    }
    return esc_url_raw($base . "/" . str_replace("%2F", "/", rawurlencode($cleanKey)));
}

function ai_webadmin_apply_media_offload_mappings($processedItems, $settings = null) {
    if (!is_array($settings)) {
        $settings = ai_webadmin_get_settings();
    }
    $items = ai_webadmin_media_offload_sanitize_processed_items($processedItems, 800);
    if (empty($items)) {
        return ["mapped_count" => 0, "skipped_count" => 0];
    }
    $base = ai_webadmin_normalize_media_public_base_url((string)($settings["media_public_base_url"] ?? ""));
    $mapped = 0;
    $skipped = 0;
    foreach ($items as $item) {
        $attachmentId = (int)$item["attachment_id"];
        $key = (string)$item["key"];
        $publicUrl = esc_url_raw((string)$item["public_url"]);
        if ($publicUrl === "") {
            $publicUrl = ai_webadmin_media_public_url_from_key($base, $key);
        }
        if ($publicUrl === "") {
            $skipped += 1;
            continue;
        }
        update_post_meta($attachmentId, "_ai_webadmin_r2_key", sanitize_text_field($key));
        update_post_meta($attachmentId, "_ai_webadmin_r2_url", $publicUrl);
        $mapped += 1;
    }
    return ["mapped_count" => $mapped, "skipped_count" => $skipped];
}

function ai_webadmin_run_media_r2_offload_batch() {
    $settings = ai_webadmin_get_settings();
    if (empty($settings["enable_media_r2_offload"])) {
        return ["ok" => false, "error" => "Media R2 offload is disabled."];
    }
    if (!ai_webadmin_features_enabled()) {
        return ["ok" => false, "error" => "Activation lock is still enabled. Complete required setup first."];
    }
    if (!ai_webadmin_can_use_signed_worker_calls($settings)) {
        return ["ok" => false, "error" => "Worker URL, Plugin Shared Secret, and Onboarding Session ID are required."];
    }

    $cursor = max(0, (int)($settings["media_offload_cursor_attachment_id"] ?? 0));
    $batchSize = max(5, min(100, (int)($settings["media_offload_batch_size"] ?? 25)));
    $batch = ai_webadmin_collect_media_attachment_batch($cursor, $batchSize, $settings);
    $items = isset($batch["items"]) && is_array($batch["items"]) ? $batch["items"] : [];
    $preparedCounts = isset($batch["prepared_counts"]) && is_array($batch["prepared_counts"]) ? $batch["prepared_counts"] : [];
    $mediaBase = ai_webadmin_normalize_media_public_base_url((string)($settings["media_public_base_url"] ?? ""));
    $batchMaxId = max($cursor, (int)($batch["max_attachment_id"] ?? $cursor));
    if (empty($items)) {
        ai_webadmin_save_runtime_settings_patch([
            "media_offload_last_run_at" => time(),
            "media_offload_last_status" => "complete",
            "media_offload_last_message" => "No new image attachments found for offload.",
            "media_offload_cursor_attachment_id" => $batchMaxId,
            "media_offload_last_mapped_count" => 0,
        ]);
        return [
            "ok" => true,
            "processed_count" => 0,
            "failed_count" => 0,
            "done" => true,
            "message" => "No new image attachments found for offload.",
        ];
    }

    $response = ai_webadmin_signed_post($settings, "plugin/wp/media/offload", [
        "session_id" => trim((string)$settings["onboarding_session_id"]),
        "site_url" => home_url("/"),
        "media_public_base_url" => $mediaBase,
        "assets" => $items,
    ], 70);
    if (is_wp_error($response)) {
        ai_webadmin_save_runtime_settings_patch([
            "media_offload_last_run_at" => time(),
            "media_offload_last_status" => "error",
            "media_offload_last_message" => sanitize_text_field($response->get_error_message()),
            "media_offload_last_mapped_count" => 0,
        ]);
        return ["ok" => false, "error" => $response->get_error_message()];
    }

    $statusCode = (int)wp_remote_retrieve_response_code($response);
    $decoded = json_decode((string)wp_remote_retrieve_body($response), true);
    if ($statusCode < 200 || $statusCode >= 300 || !is_array($decoded) || empty($decoded["ok"])) {
        $errorMsg = is_array($decoded) && !empty($decoded["error"]) ? (string)$decoded["error"] : "media_offload_failed";
        ai_webadmin_save_runtime_settings_patch([
            "media_offload_last_run_at" => time(),
            "media_offload_last_status" => "error",
            "media_offload_last_message" => sanitize_text_field($errorMsg),
            "media_offload_cursor_attachment_id" => $batchMaxId,
            "media_offload_last_mapped_count" => 0,
        ]);
        return ["ok" => false, "error" => $errorMsg];
    }

    $processed = max(0, (int)($decoded["processed_count"] ?? 0));
    $failed = max(0, (int)($decoded["failed_count"] ?? 0));
    $mapped = ai_webadmin_apply_media_offload_mappings($decoded["processed"] ?? [], $settings);
    $mappedCount = max(0, (int)($mapped["mapped_count"] ?? 0));
    $mappedSkipped = max(0, (int)($mapped["skipped_count"] ?? 0));
    $maxAttachmentId = max($batchMaxId, (int)($decoded["max_attachment_id"] ?? $batchMaxId));
    $msg = sanitize_text_field((string)($decoded["message"] ?? "Media offload completed."));
    $aiEnrichedCount = max(0, (int)($preparedCounts["ai_enriched_count"] ?? 0));
    $renamedCount = max(0, (int)($preparedCounts["renamed_count"] ?? 0));
    $seoUpdatedCount = max(0, (int)($preparedCounts["seo_updated_count"] ?? 0));
    $authorReassignedCount = max(0, (int)($preparedCounts["author_reassigned_count"] ?? 0));
    $optimizedCount = max(0, (int)($preparedCounts["optimized_count"] ?? 0));
    $beforeBytesTotal = max(0, (int)($preparedCounts["before_bytes_total"] ?? 0));
    $afterBytesTotal = max(0, (int)($preparedCounts["after_bytes_total"] ?? 0));
    $savedBytesTotal = max(0, $beforeBytesTotal - $afterBytesTotal);
    if ($mappedCount > 0) {
        $msg .= " Mapped {$mappedCount} attachment URL(s) to R2.";
    } elseif ($processed > 0 && $mappedSkipped > 0) {
        $msg .= " Offload succeeded, but CDN URL mapping was skipped because media public base URL is missing.";
    }
    if ($aiEnrichedCount > 0) {
        $msg .= " AI-enriched metadata: {$aiEnrichedCount}.";
    }
    if ($seoUpdatedCount > 0) {
        $msg .= " SEO metadata updated: {$seoUpdatedCount}.";
    }
    if ($renamedCount > 0) {
        $msg .= " Files renamed: {$renamedCount}.";
    }
    if ($authorReassignedCount > 0) {
        $msg .= " Author reassigned: {$authorReassignedCount}.";
    }
    if ($optimizedCount > 0) {
        $msg .= " Optimized images: {$optimizedCount}.";
        if ($savedBytesTotal > 0) {
            $savedKb = (int)round($savedBytesTotal / 1024);
            $msg .= " Bytes saved: {$savedKb} KB.";
        }
    }
    $githubManifest = isset($decoded["github_manifest"]) && is_array($decoded["github_manifest"]) ? $decoded["github_manifest"] : [];
    ai_webadmin_save_runtime_settings_patch([
        "media_offload_last_run_at" => time(),
        "media_offload_last_status" => ($failed > 0 && $processed > 0) ? "partial" : (($failed > 0) ? "error" : "ok"),
        "media_offload_last_message" => $msg,
        "media_offload_last_manifest_r2_key" => sanitize_text_field((string)($decoded["manifest_r2_key"] ?? "")),
        "media_offload_last_github_status" => sanitize_text_field((string)($githubManifest["status"] ?? "")),
        "media_offload_last_github_path" => sanitize_text_field((string)($githubManifest["path"] ?? "")),
        "media_offload_total_processed" => max(0, (int)$settings["media_offload_total_processed"]) + $processed,
        "media_offload_total_failed" => max(0, (int)$settings["media_offload_total_failed"]) + $failed,
        "media_offload_last_mapped_count" => $mappedCount,
        "media_offload_last_max_attachment_id" => $maxAttachmentId,
        "media_offload_cursor_attachment_id" => $maxAttachmentId,
    ]);
    return [
        "ok" => true,
        "processed_count" => $processed,
        "failed_count" => $failed,
        "mapped_count" => $mappedCount,
        "message" => $msg,
        "done" => empty($batch["has_more_candidate"]),
    ];
}

function ai_webadmin_run_media_r2_offload_for_attachment($attachmentId) {
    $settings = ai_webadmin_get_settings();
    if (empty($settings["enable_media_r2_offload"])) {
        return ["ok" => false, "error" => "Media R2 offload is disabled."];
    }
    if (!ai_webadmin_features_enabled()) {
        return ["ok" => false, "error" => "Activation lock is still enabled. Complete required setup first."];
    }
    if (!ai_webadmin_can_use_signed_worker_calls($settings)) {
        return ["ok" => false, "error" => "Worker URL, Plugin Shared Secret, and Onboarding Session ID are required."];
    }
    $id = (int)$attachmentId;
    if ($id <= 0) {
        return ["ok" => false, "error" => "Invalid attachment ID."];
    }
    $mime = strtolower((string)get_post_mime_type($id));
    if (strpos($mime, "image/") !== 0) {
        return ["ok" => false, "error" => "Attachment is not an image."];
    }
    $prepared = ai_webadmin_prepare_media_attachment_for_offload($id, $settings);
    if (empty($prepared["ok"])) {
        return ["ok" => false, "error" => sanitize_text_field((string)($prepared["error"] ?? "prepare_failed"))];
    }
    $mediaBase = ai_webadmin_normalize_media_public_base_url((string)($settings["media_public_base_url"] ?? ""));
    $response = ai_webadmin_signed_post($settings, "plugin/wp/media/offload", [
        "session_id" => trim((string)$settings["onboarding_session_id"]),
        "site_url" => home_url("/"),
        "media_public_base_url" => $mediaBase,
        "assets" => [[
            "attachment_id" => (int)$prepared["attachment_id"],
            "url" => esc_url_raw((string)$prepared["url"]),
            "r2_key" => sanitize_text_field((string)($prepared["r2_key"] ?? "")),
        ]],
    ], 70);
    if (is_wp_error($response)) {
        return ["ok" => false, "error" => $response->get_error_message()];
    }
    $statusCode = (int)wp_remote_retrieve_response_code($response);
    $decoded = json_decode((string)wp_remote_retrieve_body($response), true);
    if ($statusCode < 200 || $statusCode >= 300 || !is_array($decoded) || empty($decoded["ok"])) {
        $errorMsg = is_array($decoded) && !empty($decoded["error"]) ? (string)$decoded["error"] : "media_offload_failed";
        return ["ok" => false, "error" => sanitize_text_field($errorMsg)];
    }

    $processed = max(0, (int)($decoded["processed_count"] ?? 0));
    $failed = max(0, (int)($decoded["failed_count"] ?? 0));
    $mapped = ai_webadmin_apply_media_offload_mappings($decoded["processed"] ?? [], $settings);
    $mappedCount = max(0, (int)($mapped["mapped_count"] ?? 0));
    $msg = sanitize_text_field((string)($decoded["message"] ?? "Media offload completed."));
    if ($mappedCount > 0) {
        $msg .= " Mapped {$mappedCount} attachment URL(s) to R2.";
    }
    ai_webadmin_save_runtime_settings_patch([
        "media_offload_last_run_at" => time(),
        "media_offload_last_status" => ($failed > 0 && $processed > 0) ? "partial" : (($failed > 0) ? "error" : "ok"),
        "media_offload_last_message" => $msg,
        "media_offload_last_manifest_r2_key" => sanitize_text_field((string)($decoded["manifest_r2_key"] ?? "")),
        "media_offload_total_processed" => max(0, (int)$settings["media_offload_total_processed"]) + $processed,
        "media_offload_total_failed" => max(0, (int)$settings["media_offload_total_failed"]) + $failed,
        "media_offload_last_mapped_count" => $mappedCount,
        "media_offload_last_max_attachment_id" => max(0, (int)$prepared["attachment_id"]),
    ]);

    return [
        "ok" => true,
        "processed_count" => $processed,
        "failed_count" => $failed,
        "mapped_count" => $mappedCount,
        "message" => $msg,
        "attachment_id" => (int)$prepared["attachment_id"],
    ];
}

function ai_webadmin_run_media_r2_offload_until_complete($maxBatches = 25, $maxSeconds = 95) {
    $batchLimit = max(1, min(120, (int)$maxBatches));
    $timeLimit = max(15, min(240, (int)$maxSeconds));
    $startedAt = time();
    $passes = 0;
    $processedTotal = 0;
    $failedTotal = 0;
    $mappedTotal = 0;
    $lastMessage = "";

    while ($passes < $batchLimit) {
        if ((time() - $startedAt) >= $timeLimit) {
            break;
        }
        $result = ai_webadmin_run_media_r2_offload_batch();
        $passes += 1;
        if (empty($result["ok"])) {
            return [
                "ok" => false,
                "error" => sanitize_text_field((string)($result["error"] ?? "media_offload_failed")),
                "passes" => $passes,
                "processed_count" => $processedTotal,
                "failed_count" => $failedTotal,
                "mapped_count" => $mappedTotal,
            ];
        }
        $processedTotal += max(0, (int)($result["processed_count"] ?? 0));
        $failedTotal += max(0, (int)($result["failed_count"] ?? 0));
        $mappedTotal += max(0, (int)($result["mapped_count"] ?? 0));
        $lastMessage = sanitize_text_field((string)($result["message"] ?? ""));
        if (!empty($result["done"])) {
            return [
                "ok" => true,
                "complete" => true,
                "passes" => $passes,
                "processed_count" => $processedTotal,
                "failed_count" => $failedTotal,
                "mapped_count" => $mappedTotal,
                "message" => $lastMessage !== "" ? $lastMessage : "Media offload completed for all image attachments.",
            ];
        }
    }

    $summary = "Media offload paused after {$passes} batch run(s). Continue to process remaining images.";
    if ($lastMessage !== "") {
        $summary .= " Last run: " . $lastMessage;
    }
    return [
        "ok" => true,
        "complete" => false,
        "passes" => $passes,
        "processed_count" => $processedTotal,
        "failed_count" => $failedTotal,
        "mapped_count" => $mappedTotal,
        "message" => $summary,
    ];
}

function ai_webadmin_run_sandbox_preflight() {
    $settings = ai_webadmin_get_settings();
    if (!ai_webadmin_can_use_signed_worker_calls($settings)) {
        return ["ok" => false, "error" => "Worker URL, Plugin Shared Secret, and Onboarding Session ID are required."];
    }

    $metrics = ai_webadmin_collect_audit_metrics();
    $outdated = ai_webadmin_collect_outdated_plugin_updates(80);
    $payload = [
        "session_id" => trim((string)$settings["onboarding_session_id"]),
        "site_url" => home_url("/"),
        "outdated_plugins" => $outdated,
        "outdated_plugin_count" => (int)($metrics["outdated_plugin_count"] ?? count($outdated)),
        "active_plugin_count" => (int)($metrics["active_plugin_count"] ?? 0),
        "plugin_total_count" => (int)($metrics["plugin_total_count"] ?? 0),
        "plugin_inventory" => isset($metrics["plugin_inventory"]) && is_array($metrics["plugin_inventory"]) ? $metrics["plugin_inventory"] : [],
        "smoke_urls" => ai_webadmin_collect_public_smoke_urls(8),
        "source" => "wp_admin_sandbox_preflight",
    ];

    $response = ai_webadmin_signed_post($settings, "plugin/wp/sandbox/preflight", $payload, 30);
    if (is_wp_error($response)) {
        ai_webadmin_save_runtime_settings_patch([
            "sandbox_last_run_at" => time(),
            "sandbox_last_status" => "error",
            "sandbox_last_message" => sanitize_text_field($response->get_error_message()),
            "sandbox_last_risk_level" => "",
        ]);
        return ["ok" => false, "error" => $response->get_error_message()];
    }

    $statusCode = (int)wp_remote_retrieve_response_code($response);
    $decoded = json_decode((string)wp_remote_retrieve_body($response), true);
    if ($statusCode < 200 || $statusCode >= 300 || !is_array($decoded) || empty($decoded["ok"])) {
        $errorMsg = is_array($decoded) && !empty($decoded["error"]) ? (string)$decoded["error"] : "sandbox_preflight_failed";
        ai_webadmin_save_runtime_settings_patch([
            "sandbox_last_run_at" => time(),
            "sandbox_last_status" => "error",
            "sandbox_last_message" => sanitize_text_field($errorMsg),
            "sandbox_last_risk_level" => "",
        ]);
        return ["ok" => false, "error" => $errorMsg];
    }

    $report = isset($decoded["sandbox_report"]) && is_array($decoded["sandbox_report"]) ? $decoded["sandbox_report"] : [];
    ai_webadmin_save_runtime_settings_patch([
        "sandbox_last_run_at" => time(),
        "sandbox_last_status" => sanitize_text_field((string)($report["status"] ?? "ok")),
        "sandbox_last_message" => sanitize_text_field((string)($report["summary"] ?? "Sandbox preflight complete.")),
        "sandbox_last_risk_level" => sanitize_text_field((string)($report["risk_level"] ?? "")),
        "sandbox_last_report_id" => sanitize_text_field((string)($report["report_id"] ?? "")),
        "sandbox_last_outdated_count" => max(0, (int)($report["outdated_plugin_count"] ?? count($outdated))),
    ]);

    return [
        "ok" => true,
        "sandbox_report" => $report,
    ];
}

function ai_webadmin_push_secret_to_worker_vault($secretType, $secretValue, $label = "") {
    $type = sanitize_key((string)$secretType);
    $secret = trim((string)$secretValue);
    $safeLabel = sanitize_text_field((string)$label);
    if ($secret === "") {
        return ["ok" => false, "error" => "empty_secret"];
    }
    if (!in_array($type, ["cloudflare_api_token", "github_token", "hosting_provider_api_token", "openai_api_key"], true)) {
        return ["ok" => false, "error" => "unsupported_secret_type"];
    }

    $settings = ai_webadmin_get_settings();
    if (!ai_webadmin_can_use_signed_worker_calls($settings)) {
        return ["ok" => false, "error" => "Worker URL, Plugin Shared Secret, and Onboarding Session ID are required."];
    }

    $response = ai_webadmin_signed_post($settings, "plugin/wp/secrets/vault", [
        "session_id" => trim((string)$settings["onboarding_session_id"]),
        "site_url" => home_url("/"),
        "secret_type" => $type,
        "secret_value" => $secret,
        "secret_label" => $safeLabel,
    ], 25);
    if (is_wp_error($response)) {
        ai_webadmin_save_runtime_settings_patch([
            "worker_secret_vault_last_at" => time(),
            "worker_secret_vault_last_status" => "error",
            "worker_secret_vault_last_message" => sanitize_text_field($response->get_error_message()),
        ]);
        return ["ok" => false, "error" => $response->get_error_message()];
    }

    $statusCode = (int)wp_remote_retrieve_response_code($response);
    $decoded = json_decode((string)wp_remote_retrieve_body($response), true);
    if ($statusCode < 200 || $statusCode >= 300 || !is_array($decoded) || empty($decoded["ok"])) {
        $errorMsg = is_array($decoded) && !empty($decoded["error"]) ? (string)$decoded["error"] : "vault_upload_failed";
        ai_webadmin_save_runtime_settings_patch([
            "worker_secret_vault_last_at" => time(),
            "worker_secret_vault_last_status" => "error",
            "worker_secret_vault_last_message" => sanitize_text_field($errorMsg),
        ]);
        return ["ok" => false, "error" => $errorMsg];
    }

    $masked = sanitize_text_field((string)($decoded["masked"] ?? ""));
    $patch = [
        "worker_secret_vault_last_at" => time(),
        "worker_secret_vault_last_status" => "ok",
        "worker_secret_vault_last_message" => sanitize_text_field((string)($decoded["message"] ?? "Secret uploaded to Worker vault.")),
    ];
    if ($type === "cloudflare_api_token") {
        $patch["worker_secret_cloudflare_masked"] = $masked;
    } elseif ($type === "github_token") {
        $patch["worker_secret_github_masked"] = $masked;
    } elseif ($type === "hosting_provider_api_token") {
        $patch["worker_secret_hosting_masked"] = $masked;
    } elseif ($type === "openai_api_key") {
        $patch["worker_secret_openai_masked"] = $masked;
    }
    ai_webadmin_save_runtime_settings_patch($patch);

    return [
        "ok" => true,
        "masked" => $masked,
        "secret_type" => $type,
    ];
}

function ai_webadmin_signed_post($settings, $path, $payload, $timeout = 8) {
    $body = wp_json_encode($payload);
    if (!$body) {
        return null;
    }

    $timestamp = (string)time();
    $sig = ai_webadmin_build_signature($timestamp, $body, $settings["plugin_shared_secret"]);
    $endpoint = trailingslashit($settings["worker_base_url"]) . ltrim((string)$path, "/");
    return wp_remote_post($endpoint, [
        "method" => "POST",
        "timeout" => max(3, (int)$timeout),
        "headers" => [
            "Content-Type" => "application/json",
            "X-Plugin-Timestamp" => $timestamp,
            "X-Plugin-Signature" => $sig,
        ],
        "body" => $body,
    ]);
}

function ai_webadmin_worker_json_post($settings, $path, $payload, $timeout = 12) {
    $endpoint = trailingslashit((string)($settings["worker_base_url"] ?? "")) . ltrim((string)$path, "/");
    if ($endpoint === "") {
        return new WP_Error("ai_webadmin_worker_missing_url", "Worker base URL is required.");
    }
    $body = wp_json_encode($payload);
    if (!$body) {
        return new WP_Error("ai_webadmin_worker_invalid_payload", "Failed to encode request payload.");
    }
    return wp_remote_post($endpoint, [
        "method" => "POST",
        "timeout" => max(3, (int)$timeout),
        "headers" => [
            "Content-Type" => "application/json",
        ],
        "body" => $body,
    ]);
}

function ai_webadmin_sanitize_worker_plan_items($rawItems, $limit = 40) {
    if (!is_array($rawItems)) {
        return [];
    }
    $items = [];
    foreach ($rawItems as $item) {
        if (!is_array($item)) {
            continue;
        }
        $slug = sanitize_text_field((string)($item["slug"] ?? ""));
        if ($slug === "") {
            continue;
        }
        $items[] = [
            "slug" => $slug,
            "name" => sanitize_text_field((string)($item["name"] ?? $slug)),
            "reason" => sanitize_text_field((string)($item["reason"] ?? "")),
            "confidence" => sanitize_text_field((string)($item["confidence"] ?? "")),
        ];
        if (count($items) >= max(1, min(200, (int)$limit))) {
            break;
        }
    }
    return $items;
}

function ai_webadmin_sanitize_worker_proof_items($rawItems, $limit = 10) {
    if (!is_array($rawItems)) {
        return [];
    }
    $items = [];
    foreach ($rawItems as $item) {
        if (!is_array($item)) {
            continue;
        }
        $title = sanitize_text_field((string)($item["title"] ?? ""));
        $value = sanitize_text_field((string)($item["value"] ?? ""));
        $source = sanitize_text_field((string)($item["source_path"] ?? ""));
        if ($title === "" || $value === "") {
            continue;
        }
        $confidenceRaw = isset($item["confidence"]) ? (float)$item["confidence"] : 0.0;
        $items[] = [
            "title" => $title,
            "value" => $value,
            "source_path" => $source,
            "confidence" => max(0, min(1, $confidenceRaw)),
        ];
        if (count($items) >= max(1, min(50, (int)$limit))) {
            break;
        }
    }
    return $items;
}

function ai_webadmin_get_agent_chat_history($settings = null) {
    if (!is_array($settings)) {
        $settings = ai_webadmin_get_settings();
    }
    $decoded = json_decode((string)($settings["agent_chat_history_json"] ?? "[]"), true);
    if (!is_array($decoded)) {
        return [];
    }
    $items = [];
    foreach ($decoded as $row) {
        if (!is_array($row)) {
            continue;
        }
        $question = sanitize_text_field((string)($row["question"] ?? ""));
        $answer = sanitize_textarea_field((string)($row["answer"] ?? ""));
        if ($question === "" || $answer === "") {
            continue;
        }
        $items[] = [
            "asked_at" => max(0, (int)($row["asked_at"] ?? 0)),
            "question" => $question,
            "answer" => $answer,
            "proofs" => ai_webadmin_sanitize_worker_proof_items($row["proofs"] ?? [], 8),
        ];
        if (count($items) >= 20) {
            break;
        }
    }
    return $items;
}

function ai_webadmin_store_agent_chat_exchange($question, $answer, $proofs, $askedAt = 0) {
    $settings = ai_webadmin_get_settings();
    $history = ai_webadmin_get_agent_chat_history($settings);
    $cleanQuestion = sanitize_text_field((string)$question);
    $cleanAnswer = sanitize_textarea_field((string)$answer);
    $cleanProofs = ai_webadmin_sanitize_worker_proof_items($proofs, 10);
    $entry = [
        "asked_at" => max(0, (int)$askedAt),
        "question" => $cleanQuestion,
        "answer" => $cleanAnswer,
        "proofs" => $cleanProofs,
    ];
    $history = array_slice(array_merge([$entry], $history), 0, 20);
    ai_webadmin_save_runtime_settings_patch([
        "agent_chat_last_question" => $cleanQuestion,
        "agent_chat_last_answer" => $cleanAnswer,
        "agent_chat_last_proofs_json" => wp_json_encode($cleanProofs),
        "agent_chat_last_asked_at" => max(0, (int)$askedAt),
        "agent_chat_history_json" => wp_json_encode($history),
    ]);
}

function ai_webadmin_agent_chat($question) {
    $settings = ai_webadmin_get_settings();
    if (!ai_webadmin_can_use_signed_worker_calls($settings)) {
        return ["ok" => false, "error" => "Worker URL, Plugin Shared Secret, and Onboarding Session ID are required."];
    }
    $cleanQuestion = trim((string)$question);
    if (strlen($cleanQuestion) < 3) {
        return ["ok" => false, "error" => "Please enter a longer question."];
    }
    if (strlen($cleanQuestion) > 1500) {
        return ["ok" => false, "error" => "Question is too long."];
    }

    $response = ai_webadmin_signed_post($settings, "plugin/wp/agent/chat", [
        "session_id" => trim((string)$settings["onboarding_session_id"]),
        "site_url" => home_url("/"),
        "question" => $cleanQuestion,
    ], 25);
    if (is_wp_error($response)) {
        return ["ok" => false, "error" => $response->get_error_message()];
    }
    $statusCode = (int)wp_remote_retrieve_response_code($response);
    $decoded = json_decode((string)wp_remote_retrieve_body($response), true);
    if ($statusCode < 200 || $statusCode >= 300 || !is_array($decoded) || empty($decoded["ok"])) {
        return [
            "ok" => false,
            "error" => is_array($decoded) && !empty($decoded["error"]) ? (string)$decoded["error"] : "agent_chat_failed",
        ];
    }
    $answer = sanitize_textarea_field((string)($decoded["answer"] ?? ""));
    $proofs = ai_webadmin_sanitize_worker_proof_items($decoded["proofs"] ?? [], 10);
    $askedAt = max(0, (int)($decoded["asked_at"] ?? time()));
    ai_webadmin_store_agent_chat_exchange($cleanQuestion, $answer, $proofs, $askedAt);
    return [
        "ok" => true,
        "answer" => $answer,
        "proofs" => $proofs,
        "asked_at" => $askedAt,
    ];
}

function ai_webadmin_send_audit_metrics() {
    $settings = ai_webadmin_get_settings();
    if (!ai_webadmin_features_enabled()) {
        return;
    }
    $sessionId = trim((string)($settings["onboarding_session_id"] ?? ""));
    if ($sessionId === "") {
        return;
    }

    $metrics = ai_webadmin_collect_audit_metrics();
    $response = ai_webadmin_signed_post($settings, "plugin/wp/audit/sync", [
        "session_id" => $sessionId,
        "site_url" => home_url("/"),
        "email_queue_count" => $metrics["email_queue_count"],
        "outdated_plugin_count" => $metrics["outdated_plugin_count"],
        "inactive_plugin_count" => $metrics["inactive_plugin_count"],
        "redundant_plugin_count" => $metrics["redundant_plugin_count"],
        "sso_plugin_count" => $metrics["sso_plugin_count"],
        "pending_comment_moderation_count" => $metrics["pending_comment_moderation_count"],
        "plugin_total_count" => $metrics["plugin_total_count"],
        "active_plugin_count" => $metrics["active_plugin_count"],
        "migration_plugin_count" => $metrics["migration_plugin_count"],
        "unneeded_plugin_count" => $metrics["unneeded_plugin_count"],
        "high_risk_plugin_count" => $metrics["high_risk_plugin_count"],
        "medium_risk_plugin_count" => $metrics["medium_risk_plugin_count"],
        "inactive_user_deleted_count" => $metrics["inactive_user_deleted_count"],
        "inactive_user_candidate_count" => $metrics["inactive_user_candidate_count"],
        "autoload_option_count" => $metrics["autoload_option_count"],
        "autoload_total_bytes" => $metrics["autoload_total_bytes"],
        "autoload_total_kb" => $metrics["autoload_total_kb"],
        "autoload_last_cleanup_at" => $metrics["autoload_last_cleanup_at"],
        "autoload_last_cleanup_summary" => $metrics["autoload_last_cleanup_summary"],
        "page_cache_builtin_enabled" => $metrics["page_cache_builtin_enabled"],
        "page_cache_ttl_seconds" => $metrics["page_cache_ttl_seconds"],
        "page_cache_last_cleared_at" => $metrics["page_cache_last_cleared_at"],
        "page_cache_last_clear_reason" => $metrics["page_cache_last_clear_reason"],
        "page_cache_health_status" => $metrics["page_cache_health_status"],
        "page_cache_header_detected" => $metrics["page_cache_header_detected"],
        "page_cache_plugin_detected" => $metrics["page_cache_plugin_detected"],
        "page_cache_median_ttfb_ms" => $metrics["page_cache_median_ttfb_ms"],
        "page_cache_checked_at" => $metrics["page_cache_checked_at"],
        "smtp_plugin_count" => $metrics["smtp_plugin_count"],
        "static_export_plugin_count" => $metrics["static_export_plugin_count"],
        "static_export_memory_error_count" => $metrics["static_export_memory_error_count"],
        "static_export_removed_plugin_count" => $metrics["static_export_removed_plugin_count"],
        "static_export_last_status" => $metrics["static_export_last_status"],
        "static_export_last_error_message" => $metrics["static_export_last_error_message"],
        "static_export_last_error_source" => $metrics["static_export_last_error_source"],
        "static_export_last_error_at" => $metrics["static_export_last_error_at"],
        "analytics_site_kit_active" => $metrics["analytics_site_kit_active"],
        "analytics_pages_checked_count" => $metrics["analytics_pages_checked_count"],
        "analytics_pages_with_tracking_count" => $metrics["analytics_pages_with_tracking_count"],
        "analytics_pages_missing_tracking_count" => $metrics["analytics_pages_missing_tracking_count"],
        "analytics_unreachable_page_count" => $metrics["analytics_unreachable_page_count"],
        "analytics_tag_coverage_percent" => $metrics["analytics_tag_coverage_percent"],
        "analytics_measurement_id_count" => $metrics["analytics_measurement_id_count"],
        "analytics_gtm_container_count" => $metrics["analytics_gtm_container_count"],
        "analytics_status" => $metrics["analytics_status"],
        "analytics_last_checked_at" => $metrics["analytics_last_checked_at"],
        "woocommerce_active" => $metrics["woocommerce_active"],
        "woocommerce_status" => $metrics["woocommerce_status"],
        "woocommerce_product_count" => $metrics["woocommerce_product_count"],
        "woocommerce_completed_order_count" => $metrics["woocommerce_completed_order_count"],
        "woocommerce_last_sale_at" => $metrics["woocommerce_last_sale_at"],
        "woocommerce_sales_stale_days" => $metrics["woocommerce_sales_stale_days"],
        "plugin_inventory" => $metrics["plugin_inventory"],
    ]);
    if (is_wp_error($response)) {
        return;
    }
    $statusCode = (int)wp_remote_retrieve_response_code($response);
    $decoded = json_decode((string)wp_remote_retrieve_body($response), true);
    if ($statusCode < 200 || $statusCode >= 300 || !is_array($decoded) || empty($decoded["ok"])) {
        return;
    }
    $plan = isset($decoded["optimization_plan"]) && is_array($decoded["optimization_plan"]) ? $decoded["optimization_plan"] : [];
    if (empty($plan)) {
        return;
    }
    $removeNow = ai_webadmin_sanitize_worker_plan_items($plan["remove_now"] ?? [], 60);
    $removeAfterR2 = ai_webadmin_sanitize_worker_plan_items($plan["remove_after_r2_cdn"] ?? [], 60);
    ai_webadmin_save_runtime_settings_patch([
        "optimization_plan_last_generated_at" => time(),
        "optimization_plan_last_summary" => sanitize_text_field((string)($plan["summary"] ?? "")),
        "optimization_plan_clone_status" => sanitize_text_field((string)($plan["clone_status"] ?? "")),
        "optimization_plan_clone_summary" => sanitize_text_field((string)($plan["clone_summary"] ?? "")),
        "optimization_plan_remove_now_json" => wp_json_encode($removeNow),
        "optimization_plan_remove_after_r2_json" => wp_json_encode($removeAfterR2),
    ]);
}

function ai_webadmin_save_runtime_settings_patch($patch) {
    if (!is_array($patch) || empty($patch)) {
        return;
    }
    $current = ai_webadmin_get_settings();
    $next = array_merge($current, $patch);
    update_option(AI_WEBADMIN_OPTION_KEY, $next, false);
}

function ai_webadmin_connect_cloudflare($apiToken) {
    $token = trim((string)$apiToken);
    if ($token === "") {
        return ["ok" => false, "error" => "missing_token"];
    }

    $settings = ai_webadmin_get_settings();
    $sessionId = trim((string)($settings["onboarding_session_id"] ?? ""));
    $workerBase = trim((string)($settings["worker_base_url"] ?? ""));
    if ($sessionId === "") {
        return ["ok" => false, "error" => "missing_session_id"];
    }
    if ($workerBase === "") {
        return ["ok" => false, "error" => "missing_worker_base_url"];
    }

    $startResp = ai_webadmin_worker_json_post($settings, "plugin/connect/start", [
        "session_id" => $sessionId,
    ], 20);
    if (is_wp_error($startResp)) {
        return ["ok" => false, "error" => $startResp->get_error_message()];
    }
    $startCode = (int)wp_remote_retrieve_response_code($startResp);
    $startBody = wp_remote_retrieve_body($startResp);
    $start = json_decode($startBody, true);
    if ($startCode < 200 || $startCode >= 300 || !is_array($start) || empty($start["ok"]) || empty($start["connect_id"])) {
        $errorMsg = is_array($start) && !empty($start["error"]) ? (string)$start["error"] : "connect_start_failed";
        ai_webadmin_save_runtime_settings_patch([
            "cloudflare_connected" => 0,
            "cloudflare_last_error" => sanitize_text_field($errorMsg),
        ]);
        return ["ok" => false, "error" => $errorMsg];
    }

    $tolldnsInstalled = ai_webadmin_is_tolldns_active();
    $verifyPayload = [
        "session_id" => $sessionId,
        "connect_id" => (string)$start["connect_id"],
        "cloudflare_account_id" => sanitize_text_field((string)($settings["cloudflare_account_id"] ?? "")),
        "api_token" => $token,
        "tolldns_installed" => $tolldnsInstalled,
        "github_connected" => !empty($settings["github_vault_connected"]),
        "github_repo" => sanitize_text_field((string)($settings["github_backup_repo"] ?? "")),
    ];
    $verifyResp = ai_webadmin_worker_json_post($settings, "plugin/connect/verify", $verifyPayload, 20);
    if (is_wp_error($verifyResp)) {
        return ["ok" => false, "error" => $verifyResp->get_error_message()];
    }
    $verifyCode = (int)wp_remote_retrieve_response_code($verifyResp);
    $verifyBody = wp_remote_retrieve_body($verifyResp);
    $verify = json_decode($verifyBody, true);
    if ($verifyCode < 200 || $verifyCode >= 300 || !is_array($verify) || empty($verify["ok"])) {
        $errorMsg = is_array($verify) && !empty($verify["error"]) ? (string)$verify["error"] : "connect_verify_failed";
        ai_webadmin_save_runtime_settings_patch([
            "cloudflare_connected" => 0,
            "cloudflare_last_error" => sanitize_text_field($errorMsg),
        ]);
        return ["ok" => false, "error" => $errorMsg];
    }

    $tokenMasked = sanitize_text_field((string)($verify["plugin_connection"]["token_masked"] ?? ""));
    ai_webadmin_save_runtime_settings_patch([
        "cloudflare_connected" => 1,
        "cloudflare_token_masked" => $tokenMasked,
        "cloudflare_last_connected_at" => time(),
        "cloudflare_last_error" => "",
    ]);

    $vaultUpload = ai_webadmin_push_secret_to_worker_vault("cloudflare_api_token", $token, "Cloudflare API Token");
    if (empty($vaultUpload["ok"])) {
        ai_webadmin_save_runtime_settings_patch([
            "worker_secret_vault_last_at" => time(),
            "worker_secret_vault_last_status" => "error",
            "worker_secret_vault_last_message" => sanitize_text_field("Cloudflare token verified but vault upload failed."),
        ]);
    }

    return [
        "ok" => true,
        "token_masked" => $tokenMasked,
        "status" => sanitize_text_field((string)($verify["plugin_connection"]["status"] ?? "connected")),
    ];
}

function ai_webadmin_connect_github_vault($githubToken) {
    $token = trim((string)$githubToken);
    if ($token === "") {
        return ["ok" => false, "error" => "missing_token"];
    }
    $settings = ai_webadmin_get_settings();
    if (!ai_webadmin_can_use_signed_worker_calls($settings)) {
        return ["ok" => false, "error" => "worker_not_configured"];
    }
    $sessionId = trim((string)($settings["onboarding_session_id"] ?? ""));
    $repoSlug = ai_webadmin_parse_repo_slug($settings["github_backup_repo"] ?? "");
    $branch = sanitize_text_field(trim((string)($settings["github_backup_branch"] ?? "main")));
    if ($sessionId === "") {
        return ["ok" => false, "error" => "missing_session_id"];
    }
    if ($repoSlug === null) {
        return ["ok" => false, "error" => "missing_or_invalid_repo"];
    }
    if ($branch === "") {
        $branch = "main";
    }

    $response = ai_webadmin_signed_post($settings, "plugin/wp/github/vault", [
        "session_id" => $sessionId,
        "site_url" => home_url("/"),
        "github_repo" => $repoSlug,
        "github_branch" => $branch,
        "github_token" => $token,
    ], 20);
    if (is_wp_error($response)) {
        return ["ok" => false, "error" => $response->get_error_message()];
    }
    $code = (int)wp_remote_retrieve_response_code($response);
    $body = wp_remote_retrieve_body($response);
    $decoded = json_decode($body, true);
    if ($code < 200 || $code >= 300 || !is_array($decoded) || empty($decoded["ok"])) {
        return [
            "ok" => false,
            "error" => is_array($decoded) && !empty($decoded["error"]) ? (string)$decoded["error"] : "vault_connect_failed",
        ];
    }

    ai_webadmin_save_runtime_settings_patch([
        "github_vault_connected" => 1,
        "github_vault_token_masked" => sanitize_text_field((string)($decoded["token_masked"] ?? "")),
        "github_vault_last_connected_at" => time(),
        "worker_secret_github_masked" => sanitize_text_field((string)($decoded["token_masked"] ?? "")),
        "worker_secret_vault_last_at" => time(),
        "worker_secret_vault_last_status" => "ok",
        "worker_secret_vault_last_message" => "GitHub token cached in Worker vault.",
    ]);

    return [
        "ok" => true,
        "token_masked" => (string)($decoded["token_masked"] ?? ""),
        "repo" => (string)($decoded["github_repo"] ?? $repoSlug),
        "branch" => (string)($decoded["github_branch"] ?? $branch),
    ];
}

function ai_webadmin_send_backup_snapshot() {
    $settings = ai_webadmin_get_settings();
    if (empty($settings["github_backup_enabled"])) {
        return;
    }
    if (!ai_webadmin_features_enabled()) {
        return;
    }
    $sessionId = trim((string)($settings["onboarding_session_id"] ?? ""));
    $repoSlug = ai_webadmin_parse_repo_slug($settings["github_backup_repo"] ?? "");
    if ($sessionId === "" || $repoSlug === null) {
        return;
    }

    $manifest = ai_webadmin_collect_site_manifest((int)$settings["github_backup_manifest_max_files"]);
    $payload = [
        "session_id" => $sessionId,
        "site_url" => home_url("/"),
        "github_repo" => $repoSlug,
        "github_branch" => sanitize_text_field((string)($settings["github_backup_branch"] ?? "main")),
        "snapshot" => $manifest,
    ];
    $response = ai_webadmin_signed_post($settings, "plugin/wp/backup/snapshot", $payload, 45);
    if (is_wp_error($response)) {
        ai_webadmin_save_runtime_settings_patch([
            "github_backup_last_snapshot_at" => time(),
            "github_backup_last_status" => "error",
            "github_backup_last_message" => sanitize_text_field($response->get_error_message()),
        ]);
        return;
    }

    $code = (int)wp_remote_retrieve_response_code($response);
    $body = wp_remote_retrieve_body($response);
    $decoded = json_decode($body, true);
    $ok = ($code >= 200 && $code < 300 && is_array($decoded) && !empty($decoded["ok"]));
    ai_webadmin_save_runtime_settings_patch([
        "github_backup_last_snapshot_at" => time(),
        "github_backup_last_status" => $ok ? "ok" : "error",
        "github_backup_last_message" => $ok
            ? sanitize_text_field((string)($decoded["message"] ?? "snapshot_sent"))
            : sanitize_text_field(is_array($decoded) && !empty($decoded["error"]) ? (string)$decoded["error"] : ("worker_http_" . $code)),
    ]);
}

function ai_webadmin_fetch_schema_profile() {
    $settings = ai_webadmin_get_settings();
    if (!ai_webadmin_features_enabled()) {
        return;
    }
    if (empty($settings["enable_schema_injection"])) {
        return;
    }
    $sessionId = trim((string)($settings["onboarding_session_id"] ?? ""));
    if ($sessionId === "") {
        return;
    }

    $response = ai_webadmin_signed_post($settings, "plugin/wp/schema/profile", [
        "session_id" => $sessionId,
        "site_url" => home_url("/"),
    ]);
    if (is_wp_error($response)) {
        return;
    }

    $code = (int)wp_remote_retrieve_response_code($response);
    if ($code < 200 || $code >= 300) {
        return;
    }
    $body = wp_remote_retrieve_body($response);
    $decoded = json_decode($body, true);
    if (!is_array($decoded) || empty($decoded["ok"])) {
        return;
    }
    $jsonld = isset($decoded["schema_jsonld"]) ? (string)$decoded["schema_jsonld"] : "";
    if ($jsonld === "") {
        return;
    }
    update_option("ai_webadmin_schema_jsonld", $jsonld, false);
    update_option("ai_webadmin_schema_synced_at", time(), false);
}

function ai_webadmin_normalize_redirect_path($rawPath) {
    $path = trim((string)$rawPath);
    if ($path === "") {
        return null;
    }
    if (preg_match("#^https?://#i", $path)) {
        $parsed = wp_parse_url($path);
        if (!is_array($parsed) || empty($parsed["path"])) {
            return null;
        }
        $path = (string)$parsed["path"];
        if (!empty($parsed["query"])) {
            $path .= "?" . (string)$parsed["query"];
        }
    }
    if (strpos($path, "/") !== 0) {
        $path = "/" . $path;
    }
    $path = preg_replace("#/+#", "/", $path);
    if (!is_string($path) || strlen($path) > 240) {
        return null;
    }
    if ($path === "/" || strpos($path, "/wp-admin") === 0 || strpos($path, "/wp-login.php") === 0 || strpos($path, "/wp-json") === 0) {
        return null;
    }
    return $path;
}

function ai_webadmin_fetch_redirect_profile() {
    $settings = ai_webadmin_get_settings();
    if (!ai_webadmin_features_enabled()) {
        return;
    }
    if (empty($settings["enable_broken_link_redirects"])) {
        return;
    }
    $sessionId = trim((string)($settings["onboarding_session_id"] ?? ""));
    if ($sessionId === "") {
        return;
    }

    $response = ai_webadmin_signed_post($settings, "plugin/wp/redirects/profile", [
        "session_id" => $sessionId,
        "site_url" => home_url("/"),
    ]);
    if (is_wp_error($response)) {
        return;
    }

    $code = (int)wp_remote_retrieve_response_code($response);
    if ($code < 200 || $code >= 300) {
        return;
    }
    $body = wp_remote_retrieve_body($response);
    $decoded = json_decode($body, true);
    if (!is_array($decoded) || empty($decoded["ok"])) {
        return;
    }

    $rawPaths = isset($decoded["redirect_paths"]) && is_array($decoded["redirect_paths"]) ? $decoded["redirect_paths"] : [];
    $paths = [];
    foreach ($rawPaths as $rawPath) {
        $norm = ai_webadmin_normalize_redirect_path($rawPath);
        if ($norm === null) {
            continue;
        }
        $paths[$norm] = true;
    }
    $finalPaths = array_slice(array_keys($paths), 0, 200);
    update_option("ai_webadmin_redirect_paths", $finalPaths, false);
    update_option("ai_webadmin_redirect_synced_at", time(), false);
}

function ai_webadmin_sync_worker_data() {
    ai_webadmin_process_pending_comment_backlog_now(80);
    ai_webadmin_schedule_pending_comment_backlog(120);
    ai_webadmin_collect_page_cache_health_snapshot(true);
    ai_webadmin_send_audit_metrics();
    ai_webadmin_sync_email_forwarding_profile();
    ai_webadmin_fetch_schema_profile();
    ai_webadmin_fetch_redirect_profile();
}

function ai_webadmin_activate() {
    if (!wp_next_scheduled("ai_webadmin_sync_audit_metrics_event")) {
        wp_schedule_event(time() + 90, "hourly", "ai_webadmin_sync_audit_metrics_event");
    }
    if (!wp_next_scheduled("ai_webadmin_daily_hardening_event")) {
        wp_schedule_event(time() + 300, "daily", "ai_webadmin_daily_hardening_event");
    }
    ai_webadmin_boot_hardening_hooks();
    ai_webadmin_run_hardening_pass(true);
    ai_webadmin_sweep_email_display_names(500);
    ai_webadmin_sync_worker_data();
    ai_webadmin_send_backup_snapshot();
}
register_activation_hook(__FILE__, "ai_webadmin_activate");

function ai_webadmin_deactivate() {
    $ts = wp_next_scheduled("ai_webadmin_sync_audit_metrics_event");
    if ($ts) {
        wp_unschedule_event($ts, "ai_webadmin_sync_audit_metrics_event");
    }
    $hardeningTs = wp_next_scheduled("ai_webadmin_daily_hardening_event");
    if ($hardeningTs) {
        wp_unschedule_event($hardeningTs, "ai_webadmin_daily_hardening_event");
    }
}
register_deactivation_hook(__FILE__, "ai_webadmin_deactivate");

add_action("ai_webadmin_sync_audit_metrics_event", "ai_webadmin_sync_worker_data");

function ai_webadmin_daily_hardening_runner() {
    ai_webadmin_run_hardening_pass(true);
    ai_webadmin_sweep_email_display_names(500);
    ai_webadmin_purge_inactive_users();
    ai_webadmin_run_safe_autoload_cleanup(300);
    ai_webadmin_collect_page_cache_health_snapshot(true);
    ai_webadmin_send_audit_metrics();
    ai_webadmin_sync_email_forwarding_profile();
    ai_webadmin_send_backup_snapshot();
    ai_webadmin_run_media_r2_offload_batch();
}
add_action("ai_webadmin_daily_hardening_event", "ai_webadmin_daily_hardening_runner");

function ai_webadmin_output_schema_jsonld() {
    $settings = ai_webadmin_get_settings();
    if (empty($settings["enable_schema_injection"])) {
        return;
    }
    $json = get_option("ai_webadmin_schema_jsonld", "");
    if (!is_string($json) || trim($json) === "") {
        return;
    }
    $decoded = json_decode($json, true);
    if (!is_array($decoded) || empty($decoded["@context"]) || empty($decoded["@type"])) {
        return;
    }
    echo "<script type=\"application/ld+json\">" . wp_json_encode($decoded, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "</script>\n";
}
add_action("wp_head", "ai_webadmin_output_schema_jsonld", 5);

function ai_webadmin_apply_broken_link_redirects() {
    $settings = ai_webadmin_get_settings();
    if (empty($settings["enable_broken_link_redirects"])) {
        return;
    }
    if (is_admin()) {
        return;
    }
    if (function_exists("wp_doing_ajax") && wp_doing_ajax()) {
        return;
    }
    if (function_exists("wp_doing_cron") && wp_doing_cron()) {
        return;
    }

    $requestUri = isset($_SERVER["REQUEST_URI"]) ? (string)$_SERVER["REQUEST_URI"] : "/";
    $path = ai_webadmin_normalize_redirect_path($requestUri);
    if ($path === null) {
        return;
    }
    $redirectPaths = get_option("ai_webadmin_redirect_paths", []);
    if (!is_array($redirectPaths) || empty($redirectPaths)) {
        return;
    }
    if (!in_array($path, $redirectPaths, true)) {
        return;
    }
    wp_safe_redirect(home_url("/"), 301);
    exit;
}
add_action("template_redirect", "ai_webadmin_page_cache_serve_or_start_buffer", 0);
add_action("template_redirect", "ai_webadmin_apply_broken_link_redirects", 1);

function ai_webadmin_clear_page_cache_on_deleted_post($postId) {
    ai_webadmin_clear_page_cache_on_content_change($postId);
}
add_action("save_post", "ai_webadmin_clear_page_cache_on_content_change", 20, 1);
add_action("deleted_post", "ai_webadmin_clear_page_cache_on_deleted_post", 10, 1);

function ai_webadmin_clear_page_cache_on_plugin_state_change($plugin = "", $networkWide = false) {
    ai_webadmin_clear_page_cache("plugin_state_change");
}
add_action("activated_plugin", "ai_webadmin_clear_page_cache_on_plugin_state_change", 10, 2);
add_action("deactivated_plugin", "ai_webadmin_clear_page_cache_on_plugin_state_change", 10, 2);

function ai_webadmin_clear_page_cache_on_theme_switch() {
    ai_webadmin_clear_page_cache("theme_switch");
}
add_action("switch_theme", "ai_webadmin_clear_page_cache_on_theme_switch", 10, 0);

function ai_webadmin_comment_payload($comment) {
    return [
        "site_url" => home_url("/"),
        "comment_id" => (int)$comment->comment_ID,
        "content" => (string)$comment->comment_content,
        "author_name" => (string)$comment->comment_author,
        "author_email" => (string)$comment->comment_author_email,
        "author_url" => (string)$comment->comment_author_url,
        "ip" => (string)$comment->comment_author_IP,
        "user_agent" => (string)$comment->comment_agent,
    ];
}

function ai_webadmin_apply_moderation_action($commentId, $action) {
    if ($action === "trash") {
        wp_trash_comment($commentId);
        return "trash";
    }
    if ($action === "spam") {
        wp_spam_comment($commentId);
        return "spam";
    }
    if ($action === "hold") {
        wp_set_comment_status($commentId, "hold");
        return "hold";
    }
    return "approve";
}

function ai_webadmin_handle_comment_moderation($commentId, $skipAuditSync = false) {
    $settings = ai_webadmin_get_settings();
    if (empty($settings["enable_comment_moderation"])) {
        return;
    }
    if (!ai_webadmin_features_enabled()) {
        return;
    }
    if (!$skipAuditSync) {
        ai_webadmin_send_audit_metrics();
    }

    $comment = get_comment((int)$commentId);
    if (!$comment || empty($comment->comment_ID)) {
        return;
    }
    if (in_array($comment->comment_type, ["pingback", "trackback"], true)) {
        return;
    }
    if (in_array($comment->comment_approved, ["spam", "trash"], true)) {
        return;
    }

    $payload = ai_webadmin_comment_payload($comment);
    $body = wp_json_encode($payload);
    if (!$body) {
        return;
    }

    $timestamp = (string)time();
    $sig = ai_webadmin_build_signature($timestamp, $body, $settings["plugin_shared_secret"]);
    $endpoint = trailingslashit($settings["worker_base_url"]) . "plugin/wp/comments/moderate";

    $response = wp_remote_post($endpoint, [
        "method" => "POST",
        "timeout" => 8,
        "headers" => [
            "Content-Type" => "application/json",
            "X-Plugin-Timestamp" => $timestamp,
            "X-Plugin-Signature" => $sig,
        ],
        "body" => $body,
    ]);

    if (is_wp_error($response)) {
        update_comment_meta($comment->comment_ID, "_ai_webadmin_moderation_error", $response->get_error_message());
        return;
    }

    $statusCode = (int)wp_remote_retrieve_response_code($response);
    $responseBody = wp_remote_retrieve_body($response);
    $decoded = json_decode($responseBody, true);
    if ($statusCode < 200 || $statusCode >= 300 || !is_array($decoded) || empty($decoded["ok"])) {
        update_comment_meta($comment->comment_ID, "_ai_webadmin_moderation_error", "worker_error_" . $statusCode);
        return;
    }

    $action = isset($decoded["action"]) ? (string)$decoded["action"] : "keep";
    $appliedStatus = ai_webadmin_apply_moderation_action($comment->comment_ID, $action);
    update_comment_meta($comment->comment_ID, "_ai_webadmin_moderation_action", $appliedStatus);
    update_comment_meta($comment->comment_ID, "_ai_webadmin_moderation_confidence", isset($decoded["confidence"]) ? (string)$decoded["confidence"] : "");
    update_comment_meta($comment->comment_ID, "_ai_webadmin_moderation_reason", isset($decoded["reason"]) ? (string)$decoded["reason"] : "");
}
add_action("ai_webadmin_moderate_comment_event", "ai_webadmin_handle_comment_moderation", 10, 1);

function ai_webadmin_process_pending_comment_backlog_now($limit = 120) {
    $settings = ai_webadmin_get_settings();
    if (empty($settings["enable_comment_moderation"]) || !ai_webadmin_features_enabled()) {
        return ["processed" => 0, "approved" => 0, "spam" => 0, "trash" => 0, "hold" => 0];
    }
    $ids = ai_webadmin_fetch_pending_comment_ids($limit);
    $summary = [
        "processed" => 0,
        "approved" => 0,
        "spam" => 0,
        "trash" => 0,
        "hold" => 0,
    ];
    foreach ($ids as $commentId) {
        ai_webadmin_handle_comment_moderation($commentId, true);
        $updated = get_comment((int)$commentId);
        if (!$updated || empty($updated->comment_ID)) {
            continue;
        }
        $status = (string)$updated->comment_approved;
        $summary["processed"] += 1;
        if ($status === "trash") {
            $summary["trash"] += 1;
        } elseif ($status === "spam") {
            $summary["spam"] += 1;
        } elseif ($status === "1") {
            $summary["approved"] += 1;
        } else {
            $summary["hold"] += 1;
        }
    }
    ai_webadmin_send_audit_metrics();
    update_option("ai_webadmin_comment_backlog_last", array_merge($summary, [
        "mode" => "immediate",
        "ran_at" => time(),
        "candidate_count" => count($ids),
    ]), false);
    return $summary;
}
