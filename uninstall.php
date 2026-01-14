<?php
/**
 * Uninstall Decurse Antispam
 *
 * This file is executed when the plugin is deleted from WordPress.
 * It removes all plugin data if the user has enabled the option.
 *
 * @package Decurse_Antispam
 */

// Exit if accessed directly or not uninstalling.
if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

// Get plugin options.
$decurse_options = get_option('decurse_options', array());

// Check if user wants to delete data on uninstall.
if (empty($decurse_options['delete_data_on_uninstall'])) {
    return;
}

// Delete options.
delete_option('decurse_options');
delete_option('decurse_stats');
delete_option('decurse_version');

// Delete custom table.
global $wpdb;

// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange
$wpdb->query('DROP TABLE IF EXISTS `' . $wpdb->prefix . 'decurse_logs`');

// Clear any cached data.
wp_cache_flush();
