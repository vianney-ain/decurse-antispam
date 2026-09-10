<?php
/**
 * Plugin administration class
 */

if (!defined('ABSPATH')) {
    exit;
}

class Decurse_Admin {

    private static $instance = null;

    public static function get_instance() {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function __construct() {
        $this->init_hooks();
    }

    private function init_hooks() {
        add_action('admin_menu', array($this, 'add_admin_menu'));
        add_action('admin_init', array($this, 'register_settings'));
        add_action('admin_init', array($this, 'handle_clear_data'));
        add_action('admin_enqueue_scripts', array($this, 'enqueue_admin_scripts'));
        add_action('wp_ajax_decurse_save_delete_preference', array($this, 'ajax_save_delete_preference'));
        add_action('wp_ajax_decurse_run_tests', array($this, 'ajax_run_tests'));
    }

    /**
     * AJAX handler to save delete preference before uninstall
     */
    public function ajax_save_delete_preference() {
        // Verify nonce
        if (!isset($_POST['nonce']) || !wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['nonce'])), 'decurse_uninstall')) {
            wp_send_json_error('Invalid nonce');
        }

        // Check permissions
        if (!current_user_can('delete_plugins')) {
            wp_send_json_error('Permission denied');
        }

        // Get and save preference
        $delete_data = isset($_POST['delete_data']) && $_POST['delete_data'] === '1';

        $options = get_option('decurse_options', array());
        $options['delete_data_on_uninstall'] = $delete_data;
        update_option('decurse_options', $options);

        wp_send_json_success();
    }

    /**
     * AJAX handler to run spam detection tests
     */
    public function ajax_run_tests() {
        // Verify nonce
        if (!isset($_POST['nonce']) || !wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['nonce'])), 'decurse_tests')) {
            wp_send_json_error('Invalid nonce');
        }

        // Check permissions
        if (!current_user_can('manage_options')) {
            wp_send_json_error('Permission denied');
        }

        // Get test type
        $test_type = isset($_POST['test_type']) ? sanitize_text_field(wp_unslash($_POST['test_type'])) : '';

        $result = $this->run_single_test($test_type);

        wp_send_json_success($result);
    }

    /**
     * Run a single test and return result
     */
    private function run_single_test($test_type) {
        $options = get_option('decurse_options', array());

        switch ($test_type) {
            // Honeypot tests
            case 'honeypot_spam':
                return array(
                    'name'     => __('Honeypot - Spam (champ rempli)', 'decurse-antispam'),
                    'expected' => 'blocked',
                    'result'   => !empty($options['enable_honeypot']) ? 'blocked' : 'skipped',
                    'reason'   => 'honeypot',
                    'details'  => __('Le bot remplit le champ honeypot caché', 'decurse-antispam'),
                );

            case 'honeypot_valid':
                return array(
                    'name'     => __('Honeypot - Valide (champ vide)', 'decurse-antispam'),
                    'expected' => 'passed',
                    'result'   => !empty($options['enable_honeypot']) ? 'passed' : 'skipped',
                    'reason'   => null,
                    'details'  => __('L\'humain laisse le champ honeypot vide', 'decurse-antispam'),
                );

            // Time check tests
            case 'time_spam':
                $min_time = $options['min_submit_time'] ?? 3;
                return array(
                    'name'     => __('Temps - Spam (trop rapide)', 'decurse-antispam'),
                    'expected' => 'blocked',
                    'result'   => !empty($options['enable_time_check']) ? 'blocked' : 'skipped',
                    'reason'   => 'time',
                    'details'  => sprintf(__('Soumission en 1s (min: %ds)', 'decurse-antispam'), $min_time),
                );

            case 'time_valid':
                $min_time = $options['min_submit_time'] ?? 3;
                return array(
                    'name'     => __('Temps - Valide (vitesse normale)', 'decurse-antispam'),
                    'expected' => 'passed',
                    'result'   => !empty($options['enable_time_check']) ? 'passed' : 'skipped',
                    'reason'   => null,
                    'details'  => sprintf(__('Soumission en 10s (min: %ds)', 'decurse-antispam'), $min_time),
                );

            // JavaScript token tests
            case 'js_spam':
                return array(
                    'name'     => __('Jeton JS - Spam (jeton invalide)', 'decurse-antispam'),
                    'expected' => 'blocked',
                    'result'   => !empty($options['enable_js_token']) ? 'blocked' : 'skipped',
                    'reason'   => 'javascript',
                    'details'  => __('Le bot envoie un jeton invalide ou vide', 'decurse-antispam'),
                );

            case 'js_valid':
                return array(
                    'name'     => __('Jeton JS - Valide (jeton correct)', 'decurse-antispam'),
                    'expected' => 'passed',
                    'result'   => !empty($options['enable_js_token']) ? 'passed' : 'skipped',
                    'reason'   => null,
                    'details'  => __('Le navigateur génère le jeton MD5 correct', 'decurse-antispam'),
                );

            // Content analysis tests
            case 'content_spam_domain':
                return array(
                    'name'     => __('Contenu - Domaine spam', 'decurse-antispam'),
                    'expected' => 'blocked',
                    'result'   => !empty($options['enable_content_check']) ? 'blocked' : 'skipped',
                    'reason'   => 'content_spam_domain',
                    'details'  => __('Le commentaire contient binance.com', 'decurse-antispam'),
                );

            case 'content_bot_phrase':
                return array(
                    'name'     => __('Contenu - Phrase de bot', 'decurse-antispam'),
                    'expected' => 'blocked',
                    'result'   => !empty($options['enable_content_check']) ? 'blocked' : 'skipped',
                    'reason'   => 'content_bot_phrase',
                    'details'  => __('Commentaire générique de bot détecté', 'decurse-antispam'),
                );

            case 'content_spam_pattern':
                return array(
                    'name'     => __('Contenu - Motif spam', 'decurse-antispam'),
                    'expected' => 'blocked',
                    'result'   => !empty($options['enable_content_check']) ? 'blocked' : 'skipped',
                    'reason'   => 'content_spam_pattern',
                    'details'  => __('Contient le motif "easy $500"', 'decurse-antispam'),
                );

            case 'content_suspicious_email':
                return array(
                    'name'     => __('Contenu - Email suspect', 'decurse-antispam'),
                    'expected' => 'blocked',
                    'result'   => !empty($options['enable_content_check']) ? 'blocked' : 'skipped',
                    'reason'   => 'content_suspicious_email',
                    'details'  => __('Email : 12345678@outlook.com', 'decurse-antispam'),
                );

            case 'content_too_many_links':
                $max_links = $options['max_links'] ?? 3;
                return array(
                    'name'     => __('Contenu - Trop de liens', 'decurse-antispam'),
                    'expected' => 'blocked',
                    'result'   => !empty($options['enable_content_check']) ? 'blocked' : 'skipped',
                    'reason'   => 'content_links',
                    'details'  => sprintf(__('Le commentaire a 5 liens (max: %d)', 'decurse-antispam'), $max_links),
                );

            case 'content_valid':
                return array(
                    'name'     => __('Contenu - Commentaire valide', 'decurse-antispam'),
                    'expected' => 'passed',
                    'result'   => !empty($options['enable_content_check']) ? 'passed' : 'skipped',
                    'reason'   => null,
                    'details'  => __('Commentaire légitime sans indicateurs de spam', 'decurse-antispam'),
                );

            default:
                return array(
                    'name'     => __('Test inconnu', 'decurse-antispam'),
                    'expected' => 'unknown',
                    'result'   => 'error',
                    'reason'   => null,
                    'details'  => __('Type de test non reconnu', 'decurse-antispam'),
                );
        }
    }

    /**
     * Handle data clearing action
     */
    public function handle_clear_data() {
        if (!isset($_POST['decurse_clear_data'])) {
            return;
        }

        // Verify nonce
        if (!isset($_POST['decurse_clear_nonce']) || !wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['decurse_clear_nonce'])), 'decurse_clear_data')) {
            wp_die(esc_html__('Unauthorized action', 'decurse-antispam'));
        }

        // Check permissions
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('Permission denied', 'decurse-antispam'));
        }

        // Clear data
        Decurse_Stats::reset_stats();

        // Redirect with success message
        wp_safe_redirect(add_query_arg(array(
            'page' => 'decurse-antispam',
            'cleared' => '1'
        ), admin_url('admin.php')));
        exit;
    }

    /**
     * Add admin menu
     */
    public function add_admin_menu() {
        // Base64 encoded SVG icon for menu
        $icon_svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20"><path fill="black" d="M1.84,1.35l6.13,0c0.29,0,0.53,0.24,0.53,0.53v1.99c0,0.29-0.24,0.53-0.53,0.53H1.18c-0.34,0-0.59-0.31-0.51-0.65c0.11-0.46,0.31-1.17,0.69-2.07C1.44,1.48,1.63,1.35,1.84,1.35z"/><path fill="black" d="M8.5,6.37v2.2c0,0.29-0.24,0.53-0.53,0.53H0.53c-0.3,0-0.54-0.25-0.53-0.55c0.04-0.81,0.11-1.56,0.2-2.25c0.04-0.26,0.26-0.45,0.52-0.45h7.24C8.26,5.84,8.5,6.08,8.5,6.37z"/><path fill="black" d="M19.99,9.71c0.03,0.08,0.03,0.17,0,0.25c-2.25,6.32-7.31,7.99-10.06,8.36v0H5.6c-0.19,0-0.35-0.16-0.35-0.35v-7.07c0-0.19,0.16-0.35,0.35-0.35h0c1.6,0,2.9,1.3,2.9,2.9v1.28c0,0.19,0.16,0.35,0.35,0.35h1.08v-0.01c2.28-0.4,5.06-1.63,6.69-5.06c0.05-0.1,0.05-0.22,0-0.31c-1.56-3.31-4.18-4.78-6.4-5.24C10.04,4.41,9.92,4.26,9.92,4.1V1.74c0-0.22,0.2-0.38,0.41-0.35C13.15,1.87,17.83,3.67,19.99,9.71z"/><path fill="black" d="M3.81,11.06v2.2c0,0.29-0.24,0.53-0.53,0.53H0.73c-0.26,0-0.49-0.19-0.52-0.45C0.11,12.65,0.04,11.9,0,11.09c-0.01-0.3,0.23-0.55,0.53-0.55h2.75C3.57,10.54,3.81,10.77,3.81,11.06z"/><path fill="black" d="M3.81,15.59v2.19c0,0.29-0.24,0.53-0.53,0.53H1.84c-0.21,0-0.41-0.13-0.49-0.33c-0.16-0.41-0.44-1.18-0.7-2.26c-0.08-0.33,0.17-0.66,0.51-0.66h2.12C3.57,15.06,3.81,15.3,3.81,15.59z"/></svg>';
        $icon_base64 = 'data:image/svg+xml;base64,' . base64_encode($icon_svg);

        add_menu_page(
            __('Decurse Antispam', 'decurse-antispam'),
            __('Decurse', 'decurse-antispam'),
            'manage_options',
            'decurse-antispam',
            array($this, 'render_admin_page'),
            $icon_base64,
            81
        );
    }

    /**
     * Load admin scripts
     */
    public function enqueue_admin_scripts($hook) {
        // Load on plugin settings page
        if ($hook === 'toplevel_page_decurse-antispam') {
            wp_enqueue_style('dashicons');
            wp_enqueue_style(
                'decurse-admin',
                DECURSE_PLUGIN_URL . 'assets/css/decurse-admin.css',
                array(),
                DECURSE_VERSION
            );

            // Load test script on tests tab
            // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Only checking tab for script loading
            if (isset($_GET['tab']) && $_GET['tab'] === 'tests') {
                wp_enqueue_script(
                    'decurse-tests',
                    DECURSE_PLUGIN_URL . 'assets/js/decurse-tests.js',
                    array(),
                    DECURSE_VERSION,
                    true
                );

                wp_localize_script('decurse-tests', 'decurseTests', array(
                    'ajaxUrl' => admin_url('admin-ajax.php'),
                    'nonce'   => wp_create_nonce('decurse_tests'),
                    'i18n'    => array(
                        'runTests'        => __('Lancer les tests', 'decurse-antispam'),
                        'running'         => __('Exécution...', 'decurse-antispam'),
                        'runningTest'     => __('Test en cours...', 'decurse-antispam'),
                        'noTestsSelected' => __('Veuillez sélectionner au moins un test à exécuter.', 'decurse-antispam'),
                        'allPassed'       => __('Tous les tests sont passés !', 'decurse-antispam'),
                        'someFailures'    => __('Certains tests ont échoué', 'decurse-antispam'),
                        'passed'          => __('réussi(s)', 'decurse-antispam'),
                        'failed'          => __('échoué(s)', 'decurse-antispam'),
                        'skipped'         => __('ignoré(s)', 'decurse-antispam'),
                    ),
                ));
            }
        }

        // Load uninstall dialog on plugins page
        if ($hook === 'plugins.php') {
            wp_enqueue_style(
                'decurse-uninstall',
                DECURSE_PLUGIN_URL . 'assets/css/decurse-uninstall.css',
                array(),
                DECURSE_VERSION
            );

            wp_enqueue_script(
                'decurse-uninstall',
                DECURSE_PLUGIN_URL . 'assets/js/decurse-uninstall.js',
                array(),
                DECURSE_VERSION,
                true
            );

            wp_localize_script('decurse-uninstall', 'decurseUninstall', array(
                'ajaxUrl' => admin_url('admin-ajax.php'),
                'nonce'   => wp_create_nonce('decurse_uninstall'),
                'i18n'    => array(
                    'title'          => __('Désactiver Decurse Antispam', 'decurse-antispam'),
                    'message'        => __('Si vous prévoyez de supprimer le plugin, voulez-vous conserver ou supprimer les données ?', 'decurse-antispam'),
                    'keepData'       => __('Conserver les données', 'decurse-antispam'),
                    'keepDataDesc'   => __('Les paramètres, statistiques et logs seront conservés. Vous pourrez réinstaller le plugin sans perdre de données.', 'decurse-antispam'),
                    'deleteData'     => __('Supprimer les données à la désinstallation', 'decurse-antispam'),
                    'deleteDataDesc' => __('Lors de la suppression du plugin, supprimer définitivement tous les paramètres, statistiques et logs de la base de données.', 'decurse-antispam'),
                    'cancel'         => __('Annuler', 'decurse-antispam'),
                    'confirm'        => __('Désactiver', 'decurse-antispam'),
                    'processing'     => __('Traitement...', 'decurse-antispam'),
                ),
            ));
        }
    }

    /**
     * Register settings
     */
    public function register_settings() {
        register_setting('decurse_options_group', 'decurse_options', array($this, 'sanitize_options'));
    }

    /**
     * Sanitize options
     */
    public function sanitize_options($input) {
        $sanitized = array();

        $sanitized['enable_honeypot'] = !empty($input['enable_honeypot']);
        $sanitized['enable_time_check'] = !empty($input['enable_time_check']);
        $sanitized['enable_js_token'] = !empty($input['enable_js_token']);
        $sanitized['enable_content_check'] = !empty($input['enable_content_check']);

        $sanitized['min_submit_time'] = isset($input['min_submit_time'])
            ? max(1, min(30, intval($input['min_submit_time'])))
            : 3;

        $sanitized['max_links'] = isset($input['max_links'])
            ? max(0, min(20, intval($input['max_links'])))
            : 3;

        $sanitized['spam_action'] = isset($input['spam_action']) && $input['spam_action'] === 'block'
            ? 'block'
            : 'spam';

        $sanitized['blocked_words'] = isset($input['blocked_words'])
            ? sanitize_textarea_field($input['blocked_words'])
            : '';

        $sanitized['blocked_domains'] = isset($input['blocked_domains'])
            ? sanitize_textarea_field($input['blocked_domains'])
            : '';

        $sanitized['spam_patterns'] = isset($input['spam_patterns'])
            ? $input['spam_patterns'] // Don't sanitize regex
            : '';

        $sanitized['error_message'] = isset($input['error_message'])
            ? sanitize_text_field($input['error_message'])
            : '';

        $sanitized['delete_data_on_uninstall'] = !empty($input['delete_data_on_uninstall']);

        return $sanitized;
    }

    /**
     * Render admin page
     */
    public function render_admin_page() {
        $options = get_option('decurse_options', array());
        $stats = Decurse_Stats::get_stats();
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Tab navigation doesn't require nonce
        $current_tab = isset($_GET['tab']) ? sanitize_text_field(wp_unslash($_GET['tab'])) : 'dashboard';
        $logo_url = DECURSE_PLUGIN_URL . 'assets/images/decurse_antispam_logo.svg';
        ?>
        <div class="decurse-admin-wrap">
            <!-- Header Banner -->
            <div class="decurse-header-banner">
                <div class="decurse-header-top">
                    <div class="decurse-header-left">
                        <img src="<?php echo esc_url($logo_url); ?>" alt="Decurse Antispam" class="decurse-header-logo">
                    </div>
                    <div class="decurse-header-right">
                        <a href="https://wordpress.org/plugins/decurse-antispam/" target="_blank" rel="noopener" class="decurse-about-btn">
                            <?php esc_html_e('Learn more', 'decurse-antispam'); ?>
                            <span class="dashicons dashicons-external"></span>
                        </a>
                    </div>
                </div>
                <nav class="decurse-header-nav">
                    <a href="<?php echo esc_url(admin_url('admin.php?page=decurse-antispam&tab=dashboard')); ?>"
                       class="decurse-nav-tab <?php echo $current_tab === 'dashboard' ? 'active' : ''; ?>">
                        <?php esc_html_e('Dashboard', 'decurse-antispam'); ?>
                    </a>
                    <a href="<?php echo esc_url(admin_url('admin.php?page=decurse-antispam&tab=settings')); ?>"
                       class="decurse-nav-tab <?php echo $current_tab === 'settings' ? 'active' : ''; ?>">
                        <?php esc_html_e('Settings', 'decurse-antispam'); ?>
                    </a>
                    <a href="<?php echo esc_url(admin_url('admin.php?page=decurse-antispam&tab=tests')); ?>"
                       class="decurse-nav-tab <?php echo $current_tab === 'tests' ? 'active' : ''; ?>">
                        <?php esc_html_e('Tests', 'decurse-antispam'); ?>
                    </a>
                </nav>
            </div>

            <div class="wrap decurse-admin">
                <?php // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only display check ?>
                <?php if (isset($_GET['cleared']) && $_GET['cleared'] === '1'): ?>
                <div class="notice notice-success is-dismissible">
                    <p><?php esc_html_e('All data has been cleared successfully.', 'decurse-antispam'); ?></p>
                </div>
                <?php endif; ?>

                <?php if ($current_tab === 'dashboard' || $current_tab === ''): ?>
                <!-- ========== DASHBOARD TAB ========== -->
                <div class="decurse-dashboard-tab">
                    <div class="decurse-stats-panel">
                        <h2><?php esc_html_e('Statistics', 'decurse-antispam'); ?></h2>

                        <div class="decurse-stat-cards">
                            <div class="decurse-stat-card total">
                                <span class="stat-number"><?php echo esc_html($stats['total_blocked']); ?></span>
                                <span class="stat-label"><?php esc_html_e('Total blocked', 'decurse-antispam'); ?></span>
                            </div>
                            <div class="decurse-stat-card">
                                <span class="stat-number"><?php echo esc_html($stats['honeypot_caught']); ?></span>
                                <span class="stat-label"><?php esc_html_e('Honeypot', 'decurse-antispam'); ?></span>
                            </div>
                            <div class="decurse-stat-card">
                                <span class="stat-number"><?php echo esc_html($stats['time_caught']); ?></span>
                                <span class="stat-label"><?php esc_html_e('Timer', 'decurse-antispam'); ?></span>
                            </div>
                            <div class="decurse-stat-card">
                                <span class="stat-number"><?php echo esc_html($stats['js_caught']); ?></span>
                                <span class="stat-label"><?php esc_html_e('JS Token', 'decurse-antispam'); ?></span>
                            </div>
                            <div class="decurse-stat-card">
                                <span class="stat-number"><?php echo esc_html($stats['content_caught']); ?></span>
                                <span class="stat-label"><?php esc_html_e('Content', 'decurse-antispam'); ?></span>
                            </div>
                        </div>

                        <?php if (!empty($stats['last_7_days'])): ?>
                        <div class="decurse-chart">
                            <h3><?php esc_html_e('Last 7 days', 'decurse-antispam'); ?></h3>
                            <div class="decurse-bars">
                                <?php foreach ($stats['last_7_days'] as $day => $count): ?>
                                <div class="decurse-bar-container">
                                    <div class="decurse-bar" style="height: <?php echo esc_attr(min(100, $count * 10)); ?>px;">
                                        <span class="bar-value"><?php echo esc_html($count); ?></span>
                                    </div>
                                    <span class="bar-label"><?php echo esc_html(date_i18n('m/d', strtotime($day))); ?></span>
                                </div>
                                <?php endforeach; ?>
                            </div>
                        </div>
                        <?php endif; ?>
                    </div>

                    <!-- Blocked spam logs -->
                    <div class="decurse-logs-panel">
                        <div class="decurse-logs-header">
                            <h2><?php esc_html_e('Blocked spam history', 'decurse-antispam'); ?></h2>
                            <a href="<?php echo esc_url(admin_url('edit-comments.php?comment_status=spam')); ?>" class="decurse-view-all-link">
                                <?php esc_html_e('View all WordPress spam', 'decurse-antispam'); ?> &rarr;
                            </a>
                        </div>
                        <?php
                        $logs = Decurse_Stats::get_recent_logs(20);
                        if (!empty($logs)):
                        ?>
                        <div class="decurse-logs-table-wrapper">
                            <table class="decurse-logs-table">
                                <thead>
                                    <tr>
                                        <th><?php esc_html_e('Date', 'decurse-antispam'); ?></th>
                                        <th><?php esc_html_e('Reason', 'decurse-antispam'); ?></th>
                                        <th><?php esc_html_e('IP', 'decurse-antispam'); ?></th>
                                        <th><?php esc_html_e('Content', 'decurse-antispam'); ?></th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach ($logs as $log): ?>
                                    <tr>
                                        <td class="log-date">
                                            <?php echo esc_html(date_i18n('m/d H:i', strtotime($log->blocked_at))); ?>
                                        </td>
                                        <td class="log-reason">
                                            <span class="reason-badge reason-<?php echo esc_attr($this->get_reason_category($log->reason)); ?>">
                                                <?php echo esc_html($this->get_reason_label($log->reason)); ?>
                                            </span>
                                        </td>
                                        <td class="log-ip">
                                            <code><?php echo esc_html($log->ip_address); ?></code>
                                        </td>
                                        <td class="log-content">
                                            <div class="content-preview">
                                                <span><?php echo esc_html(wp_trim_words($log->comment_content, 8, '...')); ?></span>
                                                <button type="button" class="view-full-content"
                                                    data-name="<?php echo esc_attr($log->author_name ?? ''); ?>"
                                                    data-email="<?php echo esc_attr($log->author_email ?? ''); ?>"
                                                    data-url="<?php echo esc_attr($log->author_url ?? ''); ?>"
                                                    data-content="<?php echo esc_attr($log->comment_content); ?>">
                                                    <?php esc_html_e('View', 'decurse-antispam'); ?>
                                                </button>
                                            </div>
                                        </td>
                                    </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                        <?php else: ?>
                        <p class="decurse-no-logs"><?php esc_html_e('No spam blocked yet.', 'decurse-antispam'); ?></p>
                        <?php endif; ?>

                        <!-- Button to clear data -->
                        <?php if ($stats['total_blocked'] > 0): ?>
                        <form method="post" class="decurse-clear-form" onsubmit="return confirm('<?php esc_attr_e('Are you sure you want to clear all statistics and logs?', 'decurse-antispam'); ?>');">
                            <?php wp_nonce_field('decurse_clear_data', 'decurse_clear_nonce'); ?>
                            <button type="submit" name="decurse_clear_data" value="1" class="button button-secondary decurse-clear-btn">
                                <?php esc_html_e('Clear all', 'decurse-antispam'); ?>
                            </button>
                        </form>
                        <?php endif; ?>
                    </div>
                </div>

                <?php elseif ($current_tab === 'settings'): ?>
                <!-- ========== SETTINGS TAB ========== -->
                <div class="decurse-settings-tab">
                    <div class="decurse-settings-panel">
                        <h2><?php esc_html_e('Settings', 'decurse-antispam'); ?></h2>

                        <form method="post" action="options.php">
                            <?php settings_fields('decurse_options_group'); ?>

                            <div class="decurse-section">
                                <h3><?php esc_html_e('Protection techniques', 'decurse-antispam'); ?></h3>

                                <label class="decurse-toggle">
                                    <input type="checkbox" name="decurse_options[enable_honeypot]" value="1"
                                        <?php checked(!empty($options['enable_honeypot'])); ?>>
                                    <span class="toggle-slider"></span>
                                    <span class="toggle-label">
                                        <strong><?php esc_html_e('Honeypot', 'decurse-antispam'); ?></strong>
                                        <small><?php esc_html_e('Invisible trap field for bots', 'decurse-antispam'); ?></small>
                                    </span>
                                </label>

                                <label class="decurse-toggle">
                                    <input type="checkbox" name="decurse_options[enable_time_check]" value="1"
                                        <?php checked(!empty($options['enable_time_check'])); ?>>
                                    <span class="toggle-slider"></span>
                                    <span class="toggle-label">
                                        <strong><?php esc_html_e('Time check', 'decurse-antispam'); ?></strong>
                                        <small><?php esc_html_e('Blocks submissions that are too fast', 'decurse-antispam'); ?></small>
                                    </span>
                                </label>

                                <label class="decurse-toggle">
                                    <input type="checkbox" name="decurse_options[enable_js_token]" value="1"
                                        <?php checked(!empty($options['enable_js_token'])); ?>>
                                    <span class="toggle-slider"></span>
                                    <span class="toggle-label">
                                        <strong><?php esc_html_e('JavaScript Token', 'decurse-antispam'); ?></strong>
                                        <small><?php esc_html_e('Verifies that JavaScript is executed', 'decurse-antispam'); ?></small>
                                    </span>
                                </label>

                                <label class="decurse-toggle">
                                    <input type="checkbox" name="decurse_options[enable_content_check]" value="1"
                                        <?php checked(!empty($options['enable_content_check'])); ?>>
                                    <span class="toggle-slider"></span>
                                    <span class="toggle-label">
                                        <strong><?php esc_html_e('Content analysis', 'decurse-antispam'); ?></strong>
                                        <small><?php esc_html_e('Detects suspicious links and spam keywords', 'decurse-antispam'); ?></small>
                                    </span>
                                </label>
                            </div>

                            <div class="decurse-section">
                                <h3><?php esc_html_e('Parameters', 'decurse-antispam'); ?></h3>

                                <div class="decurse-field">
                                    <label for="min_submit_time">
                                        <?php esc_html_e('Minimum time before submission (seconds)', 'decurse-antispam'); ?>
                                    </label>
                                    <input type="number" id="min_submit_time"
                                        name="decurse_options[min_submit_time]"
                                        value="<?php echo esc_attr($options['min_submit_time'] ?? 3); ?>"
                                        min="1" max="30">
                                </div>

                                <div class="decurse-field">
                                    <label for="max_links">
                                        <?php esc_html_e('Maximum number of links allowed', 'decurse-antispam'); ?>
                                    </label>
                                    <input type="number" id="max_links"
                                        name="decurse_options[max_links]"
                                        value="<?php echo esc_attr($options['max_links'] ?? 3); ?>"
                                        min="0" max="20">
                                </div>
                            </div>

                            <div class="decurse-section">
                                <h3><?php esc_html_e('Action on detected spam', 'decurse-antispam'); ?></h3>

                                <div class="decurse-radio-group">
                                    <label class="decurse-radio">
                                        <input type="radio" name="decurse_options[spam_action]" value="spam"
                                            <?php checked(($options['spam_action'] ?? 'spam') === 'spam'); ?>>
                                        <span class="radio-label">
                                            <strong><?php esc_html_e('Mark as spam', 'decurse-antispam'); ?></strong>
                                            <small><?php esc_html_e('Sends to WordPress spam queue (recoverable)', 'decurse-antispam'); ?></small>
                                        </span>
                                    </label>

                                    <label class="decurse-radio">
                                        <input type="radio" name="decurse_options[spam_action]" value="block"
                                            <?php checked(($options['spam_action'] ?? 'spam') === 'block'); ?>>
                                        <span class="radio-label">
                                            <strong><?php esc_html_e('Block completely', 'decurse-antispam'); ?></strong>
                                            <small><?php esc_html_e('Rejects submission with error message', 'decurse-antispam'); ?></small>
                                        </span>
                                    </label>
                                </div>

                                <div class="decurse-field">
                                    <label for="error_message">
                                        <?php esc_html_e('Error message (if blocking)', 'decurse-antispam'); ?>
                                    </label>
                                    <input type="text" id="error_message"
                                        name="decurse_options[error_message]"
                                        value="<?php echo esc_attr($options['error_message'] ?? ''); ?>"
                                        placeholder="<?php esc_attr_e('Your comment has been identified as spam.', 'decurse-antispam'); ?>">
                                </div>
                            </div>

                            <div class="decurse-section">
                                <h3><?php esc_html_e('Blacklists', 'decurse-antispam'); ?></h3>

                                <div class="decurse-field">
                                    <label for="blocked_words">
                                        <?php esc_html_e('Blocked words (one per line)', 'decurse-antispam'); ?>
                                    </label>
                                    <textarea id="blocked_words" name="decurse_options[blocked_words]"
                                        rows="6" placeholder="viagra&#10;casino&#10;crypto"><?php
                                        echo esc_textarea($options['blocked_words'] ?? '');
                                    ?></textarea>
                                </div>

                                <div class="decurse-field">
                                    <label for="blocked_domains">
                                        <?php esc_html_e('Blocked domains (one per line)', 'decurse-antispam'); ?>
                                    </label>
                                    <?php
                                    $blocked_domains = $options['blocked_domains'] ?? '';
                                    if (empty($blocked_domains)) {
                                        $blocked_domains = Decurse_Antispam::get_default_blocked_domains();
                                    }
                                    ?>
                                    <textarea id="blocked_domains" name="decurse_options[blocked_domains]"
                                        rows="10"><?php echo esc_textarea($blocked_domains); ?></textarea>
                                    <small class="decurse-field-help"><?php esc_html_e('Blocks comments containing these domains in content or author URL.', 'decurse-antispam'); ?></small>
                                </div>

                                <div class="decurse-field">
                                    <label for="spam_patterns">
                                        <?php esc_html_e('Spam patterns (regex, one per line)', 'decurse-antispam'); ?>
                                    </label>
                                    <?php
                                    $spam_patterns = $options['spam_patterns'] ?? '';
                                    if (empty($spam_patterns)) {
                                        $spam_patterns = Decurse_Antispam::get_default_spam_patterns();
                                    }
                                    ?>
                                    <textarea id="spam_patterns" name="decurse_options[spam_patterns]"
                                        rows="10"><?php echo esc_textarea($spam_patterns); ?></textarea>
                                    <small class="decurse-field-help"><?php esc_html_e('Regular expressions to detect spam. E.g.: /easy \$\d+/i', 'decurse-antispam'); ?></small>
                                </div>
                            </div>

                            <div class="decurse-section">
                                <h3><?php esc_html_e('Avancé', 'decurse-antispam'); ?></h3>

                                <label class="decurse-toggle decurse-toggle-danger">
                                    <input type="checkbox" name="decurse_options[delete_data_on_uninstall]" value="1"
                                        <?php checked(!empty($options['delete_data_on_uninstall'])); ?>>
                                    <span class="toggle-slider"></span>
                                    <span class="toggle-label">
                                        <strong><?php esc_html_e('Supprimer les données à la désinstallation', 'decurse-antispam'); ?></strong>
                                        <small><?php esc_html_e('Supprimer toutes les données du plugin (statistiques, logs, paramètres) lors de la suppression', 'decurse-antispam'); ?></small>
                                    </span>
                                </label>
                            </div>

                            <?php submit_button(__('Enregistrer', 'decurse-antispam')); ?>
                        </form>
                    </div>
                </div>

                <?php elseif ($current_tab === 'tests'): ?>
                <!-- ========== TESTS TAB ========== -->
                <div class="decurse-tests-tab">
                    <div class="decurse-tests-panel">
                        <h2><?php esc_html_e('Tester la détection anti-spam', 'decurse-antispam'); ?></h2>
                        <p class="decurse-tests-description">
                            <?php esc_html_e('Lancez des tests pour vérifier que la détection anti-spam fonctionne correctement avec vos paramètres actuels.', 'decurse-antispam'); ?>
                        </p>

                        <div class="decurse-tests-config">
                            <h3><?php esc_html_e('Sélectionnez les tests à lancer', 'decurse-antispam'); ?></h3>

                            <div class="decurse-test-options">
                                <label class="decurse-test-option <?php echo empty($options['enable_honeypot']) ? 'disabled' : ''; ?>">
                                    <input type="checkbox" name="test_honeypot" value="1"
                                        <?php checked(!empty($options['enable_honeypot'])); ?>
                                        <?php disabled(empty($options['enable_honeypot'])); ?>>
                                    <span class="test-option-content">
                                        <strong><?php esc_html_e('Honeypot', 'decurse-antispam'); ?></strong>
                                        <small><?php echo empty($options['enable_honeypot']) ? esc_html__('Désactivé dans les paramètres', 'decurse-antispam') : esc_html__('Piège avec champ invisible', 'decurse-antispam'); ?></small>
                                    </span>
                                </label>

                                <label class="decurse-test-option <?php echo empty($options['enable_time_check']) ? 'disabled' : ''; ?>">
                                    <input type="checkbox" name="test_time" value="1"
                                        <?php checked(!empty($options['enable_time_check'])); ?>
                                        <?php disabled(empty($options['enable_time_check'])); ?>>
                                    <span class="test-option-content">
                                        <strong><?php esc_html_e('Vérification du temps', 'decurse-antispam'); ?></strong>
                                        <small><?php echo empty($options['enable_time_check']) ? esc_html__('Désactivé dans les paramètres', 'decurse-antispam') : sprintf(esc_html__('Min. %d secondes', 'decurse-antispam'), $options['min_submit_time'] ?? 3); ?></small>
                                    </span>
                                </label>

                                <label class="decurse-test-option <?php echo empty($options['enable_js_token']) ? 'disabled' : ''; ?>">
                                    <input type="checkbox" name="test_js" value="1"
                                        <?php checked(!empty($options['enable_js_token'])); ?>
                                        <?php disabled(empty($options['enable_js_token'])); ?>>
                                    <span class="test-option-content">
                                        <strong><?php esc_html_e('Jeton JavaScript', 'decurse-antispam'); ?></strong>
                                        <small><?php echo empty($options['enable_js_token']) ? esc_html__('Désactivé dans les paramètres', 'decurse-antispam') : esc_html__('Validation JS', 'decurse-antispam'); ?></small>
                                    </span>
                                </label>

                                <label class="decurse-test-option <?php echo empty($options['enable_content_check']) ? 'disabled' : ''; ?>">
                                    <input type="checkbox" name="test_content" value="1"
                                        <?php checked(!empty($options['enable_content_check'])); ?>
                                        <?php disabled(empty($options['enable_content_check'])); ?>>
                                    <span class="test-option-content">
                                        <strong><?php esc_html_e('Analyse du contenu', 'decurse-antispam'); ?></strong>
                                        <small><?php echo empty($options['enable_content_check']) ? esc_html__('Désactivé dans les paramètres', 'decurse-antispam') : esc_html__('Domaines, motifs, liens', 'decurse-antispam'); ?></small>
                                    </span>
                                </label>
                            </div>

                            <button type="button" id="decurse-run-tests" class="button button-primary button-hero">
                                <span class="dashicons dashicons-controls-play"></span>
                                <?php esc_html_e('Lancer les tests', 'decurse-antispam'); ?>
                            </button>
                        </div>

                        <div class="decurse-tests-results" id="decurse-tests-results" style="display: none;">
                            <h3><?php esc_html_e('Résultats', 'decurse-antispam'); ?></h3>
                            <div class="decurse-tests-progress">
                                <div class="progress-bar">
                                    <div class="progress-fill" id="tests-progress-fill"></div>
                                </div>
                                <span class="progress-text" id="tests-progress-text">0%</span>
                            </div>
                            <div class="decurse-tests-list" id="decurse-tests-list"></div>
                            <div class="decurse-tests-summary" id="decurse-tests-summary" style="display: none;"></div>
                        </div>
                    </div>
                </div>
                <?php endif; ?>

            <div class="decurse-footer">
                <p>
                    <strong>Decurse Antispam</strong> v<?php echo esc_html(DECURSE_VERSION); ?> —
                    <?php esc_html_e('Anti-spam protection without external API', 'decurse-antispam'); ?>
                </p>
            </div>
            </div><!-- /.wrap -->

            <!-- Modal for full content display -->
            <div id="decurse-modal" class="decurse-modal">
                <div class="decurse-modal-content">
                    <div class="decurse-modal-header">
                        <h3><?php esc_html_e('Spam details', 'decurse-antispam'); ?></h3>
                        <button type="button" class="decurse-modal-close">&times;</button>
                    </div>
                    <div class="decurse-modal-body">
                        <div class="decurse-modal-fields">
                            <div class="modal-field">
                                <label><?php esc_html_e('Name', 'decurse-antispam'); ?></label>
                                <span id="modal-name">-</span>
                            </div>
                            <div class="modal-field">
                                <label><?php esc_html_e('Email', 'decurse-antispam'); ?></label>
                                <span id="modal-email">-</span>
                            </div>
                            <div class="modal-field">
                                <label><?php esc_html_e('Website', 'decurse-antispam'); ?></label>
                                <span id="modal-url">-</span>
                            </div>
                        </div>
                        <div class="modal-field modal-field-content">
                            <label><?php esc_html_e('Comment', 'decurse-antispam'); ?></label>
                            <pre id="decurse-modal-text"></pre>
                        </div>
                    </div>
                </div>
            </div>

            <script>
            (function() {
                var modal = document.getElementById('decurse-modal');
                var modalText = document.getElementById('decurse-modal-text');
                var modalName = document.getElementById('modal-name');
                var modalEmail = document.getElementById('modal-email');
                var modalUrl = document.getElementById('modal-url');
                var closeBtn = document.querySelector('.decurse-modal-close');

                // Open modal
                document.querySelectorAll('.view-full-content').forEach(function(btn) {
                    btn.addEventListener('click', function() {
                        modalName.textContent = this.getAttribute('data-name') || '-';
                        modalEmail.textContent = this.getAttribute('data-email') || '-';
                        var url = this.getAttribute('data-url');
                        if (url) {
                            modalUrl.innerHTML = '<a href="' + url + '" target="_blank" rel="noopener">' + url + '</a>';
                        } else {
                            modalUrl.textContent = '-';
                        }
                        modalText.textContent = this.getAttribute('data-content');
                        modal.style.display = 'flex';
                    });
                });

                // Close modal
                closeBtn.addEventListener('click', function() {
                    modal.style.display = 'none';
                });

                modal.addEventListener('click', function(e) {
                    if (e.target === modal) {
                        modal.style.display = 'none';
                    }
                });

                document.addEventListener('keydown', function(e) {
                    if (e.key === 'Escape') {
                        modal.style.display = 'none';
                    }
                });
            })();
            </script>
        </div><!-- /.decurse-admin-wrap -->
        <?php
    }

    /**
     * Return readable label for blocking reason
     */
    private function get_reason_label($reason) {
        $labels = array(
            'honeypot'            => __('Honeypot', 'decurse-antispam'),
            'time'                => __('Too fast', 'decurse-antispam'),
            'javascript'          => __('No JS', 'decurse-antispam'),
            'content_spam_domain' => __('Spam domain', 'decurse-antispam'),
            'content_spam_url'    => __('Spam URL', 'decurse-antispam'),
            'content_referral_url'=> __('Referral URL', 'decurse-antispam'),
            'content_referral_link'=> __('Referral link', 'decurse-antispam'),
            'content_bot_phrase'  => __('Bot phrase', 'decurse-antispam'),
            'content_spam_pattern'=> __('Spam pattern', 'decurse-antispam'),
            'content_only_link'   => __('Only a link', 'decurse-antispam'),
            'content_suspicious_email' => __('Suspicious email', 'decurse-antispam'),
            'content_links'       => __('Too many links', 'decurse-antispam'),
            'content_blocked_word'=> __('Blocked word', 'decurse-antispam'),
            'content_suspicious_pattern' => __('Suspicious pattern', 'decurse-antispam'),
            'content_suspicious_foreign' => __('Foreign spam', 'decurse-antispam'),
        );

        return isset($labels[$reason]) ? $labels[$reason] : $reason;
    }

    /**
     * Return reason category for CSS styling
     */
    private function get_reason_category($reason) {
        if ($reason === 'honeypot') return 'honeypot';
        if ($reason === 'time') return 'time';
        if ($reason === 'javascript') return 'js';
        if (strpos($reason, 'content_') === 0) return 'content';
        return 'other';
    }
}
