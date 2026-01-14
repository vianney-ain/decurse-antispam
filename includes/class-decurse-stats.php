<?php
/**
 * Classe de gestion des statistiques
 */

if (!defined('ABSPATH')) {
    exit;
}

class Decurse_Stats {

    /**
     * Enregistre un blocage de spam
     */
    public static function log_blocked($reason) {
        $stats = get_option('decurse_stats', array());

        // Incrémenter le total
        $stats['total_blocked'] = isset($stats['total_blocked']) ? $stats['total_blocked'] + 1 : 1;

        // Incrémenter par type
        switch ($reason) {
            case 'honeypot':
                $stats['honeypot_caught'] = isset($stats['honeypot_caught']) ? $stats['honeypot_caught'] + 1 : 1;
                break;
            case 'time':
                $stats['time_caught'] = isset($stats['time_caught']) ? $stats['time_caught'] + 1 : 1;
                break;
            case 'javascript':
                $stats['js_caught'] = isset($stats['js_caught']) ? $stats['js_caught'] + 1 : 1;
                break;
            default:
                // Tout ce qui commence par content_
                if (strpos($reason, 'content_') === 0) {
                    $stats['content_caught'] = isset($stats['content_caught']) ? $stats['content_caught'] + 1 : 1;
                }
                break;
        }

        // Stats journalières
        $today = gmdate('Y-m-d');
        if (!isset($stats['daily_stats'])) {
            $stats['daily_stats'] = array();
        }
        $stats['daily_stats'][$today] = isset($stats['daily_stats'][$today])
            ? $stats['daily_stats'][$today] + 1
            : 1;

        // Garder seulement les 30 derniers jours
        $stats['daily_stats'] = self::cleanup_old_stats($stats['daily_stats'], 30);

        update_option('decurse_stats', $stats);
    }

    /**
     * Nettoie les anciennes statistiques
     */
    private static function cleanup_old_stats($daily_stats, $days_to_keep) {
        $cutoff = gmdate('Y-m-d', strtotime("-{$days_to_keep} days"));

        return array_filter($daily_stats, function($day) use ($cutoff) {
            return $day >= $cutoff;
        }, ARRAY_FILTER_USE_KEY);
    }

    /**
     * Récupère les statistiques
     */
    public static function get_stats() {
        $stats = get_option('decurse_stats', array());

        $defaults = array(
            'total_blocked'   => 0,
            'honeypot_caught' => 0,
            'time_caught'     => 0,
            'js_caught'       => 0,
            'content_caught'  => 0,
            'daily_stats'     => array(),
        );

        $stats = wp_parse_args($stats, $defaults);

        // Préparer les stats des 7 derniers jours
        $stats['last_7_days'] = self::get_last_days($stats['daily_stats'], 7);

        return $stats;
    }

    /**
     * Récupère les stats des X derniers jours
     */
    private static function get_last_days($daily_stats, $days) {
        $result = array();

        for ($i = $days - 1; $i >= 0; $i--) {
            $date = gmdate('Y-m-d', strtotime("-{$i} days"));
            $result[$date] = isset($daily_stats[$date]) ? $daily_stats[$date] : 0;
        }

        return $result;
    }

    /**
     * Réinitialise les statistiques
     */
    public static function reset_stats() {
        $empty_stats = array(
            'total_blocked'   => 0,
            'honeypot_caught' => 0,
            'time_caught'     => 0,
            'js_caught'       => 0,
            'content_caught'  => 0,
            'daily_stats'     => array(),
        );

        update_option('decurse_stats', $empty_stats);

        // Vider aussi la table de logs
        global $wpdb;
        $table_name = $wpdb->prefix . 'decurse_logs';
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $wpdb->query('TRUNCATE TABLE `' . esc_sql($table_name) . '`');
    }

    /**
     * Récupère les derniers logs
     */
    public static function get_recent_logs($limit = 20) {
        global $wpdb;

        $table_name = $wpdb->prefix . 'decurse_logs';

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        return $wpdb->get_results(
            $wpdb->prepare(
                'SELECT * FROM `' . esc_sql($table_name) . '` ORDER BY blocked_at DESC LIMIT %d',
                $limit
            )
        );
    }
}
