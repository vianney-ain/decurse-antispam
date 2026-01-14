<?php
/**
 * Plugin Name: Decurse Antispam
 * Plugin URI: https://github.com/vianney-ain/decurse-antispam
 * Description: Comment spam protection for WordPress. Honeypot, time check, JavaScript token and content analysis. No external API required.
 * Version: 1.0.1
 * Author: Vianney Ain
 * Author URI: https://vianneyain.com
 * License: GPL v2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: decurse-antispam
 * Domain Path: /languages
 * Requires at least: 5.0
 * Requires PHP: 7.2
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// Plugin constants
define('DECURSE_VERSION', '1.0.1');
define('DECURSE_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('DECURSE_PLUGIN_URL', plugin_dir_url(__FILE__));
define('DECURSE_PLUGIN_BASENAME', plugin_basename(__FILE__));

/**
 * Main Decurse Antispam plugin class
 */
class Decurse_Antispam {

    /**
     * Singleton instance
     */
    private static $instance = null;

    /**
     * Get the singleton instance
     */
    public static function get_instance() {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    /**
     * Private constructor
     */
    private function __construct() {
        $this->load_dependencies();
        $this->init_hooks();
    }

    /**
     * Load dependencies
     */
    private function load_dependencies() {
        require_once DECURSE_PLUGIN_DIR . 'includes/class-decurse-i18n.php';
        require_once DECURSE_PLUGIN_DIR . 'includes/class-decurse-core.php';
        require_once DECURSE_PLUGIN_DIR . 'includes/class-decurse-admin.php';
        require_once DECURSE_PLUGIN_DIR . 'includes/class-decurse-stats.php';
    }

    /**
     * Initialize hooks
     */
    private function init_hooks() {
        // Activation/Deactivation
        register_activation_hook(__FILE__, array($this, 'activate'));
        register_deactivation_hook(__FILE__, array($this, 'deactivate'));

        // Initialization
        add_action('init', array($this, 'init'));

        // Load frontend scripts
        add_action('wp_enqueue_scripts', array($this, 'enqueue_frontend_scripts'));

        // Plugin action links
        add_filter('plugin_action_links_' . DECURSE_PLUGIN_BASENAME, array($this, 'add_action_links'));
        add_filter('plugin_row_meta', array($this, 'add_row_meta'), 10, 2);

        // Plugin information popup
        add_filter('plugins_api', array($this, 'plugin_info'), 20, 3);
    }

    /**
     * Add action links to plugins page
     */
    public function add_action_links($links) {
        $settings_link = '<a href="' . esc_url(admin_url('admin.php?page=decurse-antispam&tab=settings')) . '">' . esc_html__('Settings', 'decurse-antispam') . '</a>';
        array_unshift($links, $settings_link);
        return $links;
    }

    /**
     * Add row meta to plugins page (View details link)
     */
    public function add_row_meta($links, $file) {
        if (DECURSE_PLUGIN_BASENAME === $file) {
            $links[] = sprintf(
                '<a href="%s" class="thickbox open-plugin-details-modal" aria-label="%s" data-title="%s">%s</a>',
                esc_url(admin_url('plugin-install.php?tab=plugin-information&plugin=decurse-antispam&TB_iframe=true&width=600&height=550')),
                esc_attr__('More information about Decurse Antispam', 'decurse-antispam'),
                esc_attr__('Decurse Antispam', 'decurse-antispam'),
                esc_html__('View details', 'decurse-antispam')
            );
        }
        return $links;
    }

    /**
     * Provide plugin information for the popup
     */
    public function plugin_info($result, $action, $args) {
        if ($action !== 'plugin_information') {
            return $result;
        }

        if (!isset($args->slug) || $args->slug !== 'decurse-antispam') {
            return $result;
        }

        $plugin_data = array(
            'name'              => 'Decurse Antispam',
            'slug'              => 'decurse-antispam',
            'version'           => DECURSE_VERSION,
            'author'            => '<a href="https://vianneyain.com">Vianney Aïn</a>',
            'author_profile'    => 'https://vianneyain.com',
            'requires'          => '5.0',
            'tested'            => '6.9',
            'requires_php'      => '7.2',
            'downloaded'        => 0,
            'last_updated'      => gmdate('Y-m-d'),
            'homepage'          => 'https://github.com/vianney-ain/decurse-antispam',
            'short_description' => esc_html__('Comment spam protection for WordPress. No external API required.', 'decurse-antispam'),
            'sections'          => array(
                'description'  => $this->get_plugin_description(),
                'installation' => $this->get_plugin_installation(),
                'changelog'    => $this->get_plugin_changelog(),
            ),
            'banners'           => array(
                'low'  => DECURSE_PLUGIN_URL . 'assets/images/banner-772x250.png',
                'high' => DECURSE_PLUGIN_URL . 'assets/images/banner-1544x500.png',
            ),
        );

        return (object) $plugin_data;
    }

    /**
     * Get plugin description for popup
     */
    private function get_plugin_description() {
        return '
        <p><strong>Decurse Antispam</strong> ' . esc_html__('protects your WordPress comments from spam using multiple layered detection techniques.', 'decurse-antispam') . '</p>

        <h4>' . esc_html__('Protection Techniques', 'decurse-antispam') . '</h4>
        <ul>
            <li><strong>Honeypot</strong> - ' . esc_html__('Invisible trap field that bots fill out automatically', 'decurse-antispam') . '</li>
            <li><strong>' . esc_html__('Time Check', 'decurse-antispam') . '</strong> - ' . esc_html__('Blocks submissions faster than humanly possible', 'decurse-antispam') . '</li>
            <li><strong>' . esc_html__('JavaScript Token', 'decurse-antispam') . '</strong> - ' . esc_html__('Verifies that JavaScript is executed', 'decurse-antispam') . '</li>
            <li><strong>' . esc_html__('Content Analysis', 'decurse-antispam') . '</strong> - ' . esc_html__('Detects spam domains, bot phrases, and suspicious patterns', 'decurse-antispam') . '</li>
        </ul>

        <h4>' . esc_html__('Why Decurse Antispam?', 'decurse-antispam') . '</h4>
        <ul>
            <li>' . esc_html__('No external API - All processing happens on your server', 'decurse-antispam') . '</li>
            <li>' . esc_html__('No CAPTCHA - Invisible to your visitors', 'decurse-antispam') . '</li>
            <li>' . esc_html__('Privacy-friendly - No data sent to third parties', 'decurse-antispam') . '</li>
            <li>' . esc_html__('Lightweight - Minimal impact on page load', 'decurse-antispam') . '</li>
        </ul>
        ';
    }

    /**
     * Get plugin installation instructions for popup
     */
    private function get_plugin_installation() {
        return '
        <ol>
            <li>' . wp_kses(__('Upload the <code>decurse-antispam</code> folder to <code>/wp-content/plugins/</code>', 'decurse-antispam'), array('code' => array())) . '</li>
            <li>' . esc_html__('Activate the plugin through the "Plugins" menu in WordPress', 'decurse-antispam') . '</li>
            <li>' . wp_kses(__('Go to <strong>Decurse</strong> in the admin menu to configure settings', 'decurse-antispam'), array('strong' => array())) . '</li>
        </ol>
        ';
    }

    /**
     * Get plugin changelog for popup
     */
    private function get_plugin_changelog() {
        return '
        <h4>1.0.0</h4>
        <ul>
            <li>' . esc_html__('Initial release', 'decurse-antispam') . '</li>
            <li>' . esc_html__('Honeypot protection', 'decurse-antispam') . '</li>
            <li>' . esc_html__('Time-based submission check', 'decurse-antispam') . '</li>
            <li>' . esc_html__('JavaScript token validation', 'decurse-antispam') . '</li>
            <li>' . esc_html__('Content analysis with multiple detection methods', 'decurse-antispam') . '</li>
            <li>' . esc_html__('Dashboard with statistics and logs', 'decurse-antispam') . '</li>
            <li>' . esc_html__('Configurable blacklists', 'decurse-antispam') . '</li>
        </ul>
        ';
    }

    /**
     * Plugin activation
     */
    public function activate() {
        // Default options
        $default_options = array(
            'enable_honeypot'      => true,
            'enable_time_check'    => true,
            'enable_js_token'      => true,
            'enable_content_check' => true,
            'min_submit_time'      => 3,
            'max_links'            => 3,
            'spam_action'          => 'spam', // 'spam' or 'block'
            'blocked_words'        => $this->get_default_blocked_words(),
            'blocked_domains'      => "binance.com\nbinance.info\nbybit.com\nkucoin.com\nokx.com\ngate.io\nbitget.com\nmexc.com\nhuobi.com\ncrypto.com\ncoinbase.com\nkraken.com\nfreecash.com\nswagbucks.com\nprizerebell.com\ninboxdollars.com\nsurveyjunkie.com\nmypoints.com\ncashcrate.com\nearnably.com\ngrabpoints.com\nprizerebel.com\ngifthulk.com\nysense.com\ntimebucks.com\nrewards1.com\nclickworker.com\ntoluna.com\nlifepoints.com\nbet365.com\n1xbet.com\nstake.com\n888casino.com\npokerstars.com\nadultfriendfinder.com\nashleymadison.com\nbit.ly\ntinyurl.com\ngoo.gl\nt.co\nis.gd\nbuff.ly\now.ly\nadf.ly\nshorte.st",
            'spam_patterns'        => "/easy \\\$\\d+/i\n/free \\\$\\d+/i\n/earn \\\$\\d+/i\n/make \\\$\\d+/i\n/get \\\$\\d+/i\n/win \\\$\\d+/i\n/claim (your |a )?(free |bonus )?/i\n/signup bonus/i\n/referral (code|link|bonus)/i\n/use (my |this )?(code|link)/i\n/promo code/i\n/free (money|cash|coins|tokens)/i\n/passive income/i\n/make money (online|fast|quick)/i\n/get rich (quick|fast)/i\n/limited time offer/i\n/100% (free|guaranteed)/i\n/double your (money|investment)/i\n/figured it might help/i",
            'error_message'        => '',
        );

        if (!get_option('decurse_options')) {
            add_option('decurse_options', $default_options);
        }

        // Initialize stats
        if (!get_option('decurse_stats')) {
            add_option('decurse_stats', array(
                'total_blocked'    => 0,
                'honeypot_caught'  => 0,
                'time_caught'      => 0,
                'js_caught'        => 0,
                'content_caught'   => 0,
                'daily_stats'      => array(),
            ));
        }

        // Create tables if needed
        $this->create_tables();
    }

    /**
     * Create custom tables
     */
    private function create_tables() {
        global $wpdb;

        $table_name = $wpdb->prefix . 'decurse_logs';
        $charset_collate = $wpdb->get_charset_collate();

        $sql = "CREATE TABLE IF NOT EXISTS $table_name (
            id bigint(20) NOT NULL AUTO_INCREMENT,
            blocked_at datetime DEFAULT CURRENT_TIMESTAMP,
            reason varchar(50) NOT NULL,
            ip_address varchar(45),
            author_name varchar(255),
            author_email varchar(255),
            author_url varchar(255),
            comment_content text,
            PRIMARY KEY (id),
            KEY blocked_at (blocked_at),
            KEY reason (reason)
        ) $charset_collate;";

        require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
        dbDelta($sql);
    }

    /**
     * Plugin deactivation
     */
    public function deactivate() {
        // Cleanup if needed (keep options for reactivation)
    }

    /**
     * Initialization
     */
    public function init() {
        // Compile .po to .mo files if needed
        Decurse_I18n::compile_translations();

        // Load translations
        // phpcs:ignore PluginCheck.CodeAnalysis.DiscouragedFunctions.load_plugin_textdomainFound -- Needed for non-WordPress.org installs
        load_plugin_textdomain('decurse-antispam', false, dirname(DECURSE_PLUGIN_BASENAME) . '/languages');

        // Check for upgrades
        $this->maybe_upgrade();

        // Check if table exists, create if not
        $this->maybe_create_tables();

        // Initialize anti-spam core
        Decurse_Core::get_instance();

        // Initialize admin if in admin area
        if (is_admin()) {
            Decurse_Admin::get_instance();
        }
    }

    /**
     * Create tables if they don't exist (migration)
     */
    private function maybe_create_tables() {
        global $wpdb;

        $table_name = $wpdb->prefix . 'decurse_logs';

        // Check if table exists
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        if ($wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $table_name)) !== $table_name) {
            $this->create_tables();
        } else {
            // Check if new columns exist, add them if not
            // Using $wpdb->prefix directly is recognized as safe by PHPCS
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $columns = $wpdb->get_col('SHOW COLUMNS FROM `' . $wpdb->prefix . 'decurse_logs`');

            if (!in_array('author_name', $columns, true)) {
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.SchemaChange, WordPress.DB.DirectDatabaseQuery.NoCaching
                $wpdb->query('ALTER TABLE `' . $wpdb->prefix . 'decurse_logs` ADD COLUMN author_name varchar(255) AFTER ip_address');
            }
            if (!in_array('author_email', $columns, true)) {
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.SchemaChange, WordPress.DB.DirectDatabaseQuery.NoCaching
                $wpdb->query('ALTER TABLE `' . $wpdb->prefix . 'decurse_logs` ADD COLUMN author_email varchar(255) AFTER author_name');
            }
            if (!in_array('author_url', $columns, true)) {
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.SchemaChange, WordPress.DB.DirectDatabaseQuery.NoCaching
                $wpdb->query('ALTER TABLE `' . $wpdb->prefix . 'decurse_logs` ADD COLUMN author_url varchar(255) AFTER author_email');
            }
        }
    }

    /**
     * Check for plugin upgrades and migrate data if needed
     */
    private function maybe_upgrade() {
        $stored_version = get_option('decurse_version', '0.0.0');

        if (version_compare($stored_version, DECURSE_VERSION, '<')) {
            $options = get_option('decurse_options', array());

            // Upgrade from versions before 1.0.0: add comprehensive blocked words
            if (version_compare($stored_version, '1.0.0', '<')) {
                // Check if blocked_words is empty or has only the old minimal list
                $old_minimal_words = "viagra\ncasino\ncrypto";
                if (empty($options['blocked_words']) || trim($options['blocked_words']) === $old_minimal_words) {
                    $options['blocked_words'] = self::get_default_blocked_words();
                }

                // Also update blocked_domains if empty
                if (empty($options['blocked_domains'])) {
                    $options['blocked_domains'] = self::get_default_blocked_domains();
                }

                // Also update spam_patterns if empty
                if (empty($options['spam_patterns'])) {
                    $options['spam_patterns'] = self::get_default_spam_patterns();
                }

                update_option('decurse_options', $options);
            }

            // Update stored version
            update_option('decurse_version', DECURSE_VERSION);
        }
    }

    /**
     * Load frontend scripts
     */
    public function enqueue_frontend_scripts() {
        // Only on pages with comments
        if (is_singular() && comments_open()) {
            $options = get_option('decurse_options');

            if (!empty($options['enable_js_token'])) {
                wp_enqueue_script(
                    'decurse-frontend',
                    DECURSE_PLUGIN_URL . 'assets/js/decurse-frontend.js',
                    array(),
                    DECURSE_VERSION,
                    true
                );

                // Pass data to script
                wp_localize_script('decurse-frontend', 'decurseData', array(
                    'nonce' => wp_create_nonce('decurse_comment_nonce'),
                    'timestamp' => time(),
                ));
            }
        }
    }

    /**
     * Get plugin options
     */
    public static function get_options() {
        return get_option('decurse_options', array());
    }

    /**
     * Return default blocked domains
     */
    public static function get_default_blocked_domains() {
        return "binance.com
binance.info
bybit.com
kucoin.com
okx.com
gate.io
bitget.com
mexc.com
huobi.com
crypto.com
coinbase.com
kraken.com
freecash.com
swagbucks.com
prizerebell.com
inboxdollars.com
surveyjunkie.com
mypoints.com
cashcrate.com
earnably.com
grabpoints.com
prizerebel.com
gifthulk.com
ysense.com
timebucks.com
rewards1.com
clickworker.com
toluna.com
lifepoints.com
bet365.com
1xbet.com
stake.com
888casino.com
pokerstars.com
adultfriendfinder.com
ashleymadison.com
bit.ly
tinyurl.com
goo.gl
t.co
is.gd
buff.ly
ow.ly
adf.ly
shorte.st";
    }

    /**
     * Return default blocked words
     */
    public static function get_default_blocked_words() {
        return "viagra
cialis
levitra
pharmacy
pills
medications
drugstore
prescription
xanax
valium
ambien
tramadol
phentermine
casino
gambling
poker
blackjack
roulette
slot machine
betting
jackpot
lottery
lotto
sweepstakes
prize winner
million dollars
inheritance
beneficiary
bitcoin
cryptocurrency
crypto trading
forex
binary options
investment opportunity
stock alert
penny stocks
nigerian
prince
barrister
diplomat
consignment
western union
moneygram
wire transfer
loan offer
debt relief
credit repair
payday loan
work from home
home business
mlm
network marketing
pyramid scheme
get rich quick
easy money
fast cash
extra income
financial freedom
weight loss
diet pills
fat burner
lose weight fast
miracle cure
anti-aging
wrinkle cream
enlargement
enhancement
erectile
penis
breast
sex
porn
xxx
adult content
webcam
dating site
hookup
singles
escort
massage parlor
replica watches
fake rolex
designer replica
counterfeit
knockoff
cheap ugg
cheap oakley
ray ban sale
gucci outlet
louis vuitton outlet
seo services
backlinks
link building
page rank
traffic exchange
click here
act now
limited time
order now
buy now
don't delete
this is not spam
congratulations
you've been selected
you have won
dear friend
dear sir
dear madam
dear customer
kindly reply
urgent response
confidential
private message
re: your account";
    }

    /**
     * Return default spam patterns
     */
    public static function get_default_spam_patterns() {
        return "/easy \\\$\\d+/i
/free \\\$\\d+/i
/earn \\\$\\d+/i
/make \\\$\\d+/i
/get \\\$\\d+/i
/win \\\$\\d+/i
/claim (your |a )?(free |bonus )?/i
/signup bonus/i
/referral (code|link|bonus)/i
/use (my |this )?(code|link)/i
/promo code/i
/free (money|cash|coins|tokens)/i
/passive income/i
/make money (online|fast|quick)/i
/get rich (quick|fast)/i
/limited time offer/i
/100% (free|guaranteed)/i
/double your (money|investment)/i
/figured it might help/i";
    }
}

// Start the plugin
function decurse_antispam_init() {
    return Decurse_Antispam::get_instance();
}

// Hook on plugins_loaded to ensure WP is ready
add_action('plugins_loaded', 'decurse_antispam_init');
