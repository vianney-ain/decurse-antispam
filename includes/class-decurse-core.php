<?php
/**
 * Main anti-spam detection class
 */

if (!defined('ABSPATH')) {
    exit;
}

class Decurse_Core {

    private static $instance = null;
    private $options;

    /**
     * Known spam domains (referral, crypto, reward sites, etc.)
     */
    private $spam_domains = array(
        // Crypto exchanges (referral spam)
        'binance.com',
        'binance.info',
        'accounts.binance.com',
        'accounts.binance.info',
        'bybit.com',
        'kucoin.com',
        'okx.com',
        'gate.io',
        'bitget.com',
        'mexc.com',
        'huobi.com',
        'crypto.com',
        'coinbase.com',
        'kraken.com',
        // Reward/GPT sites (referral spam)
        'freecash.com',
        'swagbucks.com',
        'prizerebell.com',
        'inboxdollars.com',
        'surveyjunkie.com',
        'mypoints.com',
        'cashcrate.com',
        'earnably.com',
        'grabpoints.com',
        'prizerebel.com',
        'gifthulk.com',
        'ysense.com',
        'timebucks.com',
        'rewards1.com',
        'clickworker.com',
        'toluna.com',
        'lifepoints.com',
        // Gambling/Casino
        'bet365.com',
        '1xbet.com',
        'stake.com',
        '888casino.com',
        'pokerstars.com',
        // Dating spam
        'adultfriendfinder.com',
        'ashleymadison.com',
        // URL shorteners (often used to hide spam)
        'bit.ly',
        'tinyurl.com',
        'goo.gl',
        't.co',
        'is.gd',
        'buff.ly',
        'ow.ly',
        'adf.ly',
        'shorte.st',
        'shorturl.fm',
        'addlinks.pro',
        'pesnimp3.net',
    );

    /**
     * Generic bot phrases
     */
    private $bot_phrases = array(
        'your point of view caught my eye',
        'thanks for sharing. i read many of your blog posts',
        'your article helped me a lot, is there any more related content',
        'can you be more specific about the content of your article',
        'thank you for your sharing. i am worried that i lack creative ideas',
        'i don\'t think the title of your article matches the content lol',
        'after reading it, i still have some doubts',
        'it is your article that makes me full of hope',
        'but, i have a question, can you help me',
        'cool, your blog is very good',
        'this is really interesting',
        'great post, thanks for sharing',
        'very informative article',
        'i bookmarked it',
        'looking forward to more posts',
    );

    /**
     * Spam regex patterns in content
     */
    private $spam_patterns = array(
        '/easy \$\d+/i',                          // "easy $60", "easy $100"
        '/free \$\d+/i',                          // "free $50"
        '/earn \$\d+/i',                          // "earn $200"
        '/make \$\d+/i',                          // "make $500"
        '/get \$\d+/i',                           // "get $100"
        '/win \$\d+/i',                           // "win $1000"
        '/claim (your |a )?(free |bonus )?/i',    // "claim your free", "claim bonus"
        '/signup bonus/i',
        '/sign up bonus/i',
        '/referral (code|link|bonus)/i',
        '/use (my |this )?(code|link)/i',
        '/promo code/i',
        '/discount code/i',
        '/free (money|cash|coins|tokens)/i',
        '/passive income/i',
        '/work from home/i',
        '/make money (online|fast|quick)/i',
        '/get rich (quick|fast)/i',
        '/limited time offer/i',
        '/act now/i',
        '/don\'t miss (this|out)/i',
        '/100% (free|guaranteed)/i',
        '/no risk/i',
        '/double your (money|investment)/i',
        '/investment opportunity/i',
        '/figured it might help/i',                // freecash spam pattern
    );

    public static function get_instance() {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function __construct() {
        $this->options = get_option('decurse_options', array());
        $this->init_hooks();
    }

    private function init_hooks() {
        // Inject fields into comment form
        add_action('comment_form', array($this, 'add_hidden_fields'));
        add_filter('comment_form_default_fields', array($this, 'add_honeypot_field'));

        // Check comments before processing
        add_filter('preprocess_comment', array($this, 'check_comment'), 1);
    }

    /**
     * Add honeypot field to form
     */
    public function add_honeypot_field($fields) {
        if (empty($this->options['enable_honeypot'])) {
            return $fields;
        }

        $fields['decurse_hp'] = '<p class="comment-form-decurse-hp" style="position:absolute;left:-9999px;opacity:0;height:0;overflow:hidden;">
            <label for="website_url_confirm">' . __('Do not fill in', 'decurse-antispam') . '</label>
            <input type="text" name="website_url_confirm" id="website_url_confirm" value="" tabindex="-1" autocomplete="off" />
        </p>';

        return $fields;
    }

    /**
     * Add hidden fields (timestamp, token)
     */
    public function add_hidden_fields() {
        $timestamp = time();
        $token_base = wp_create_nonce('decurse_token_' . $timestamp);

        echo '<input type="hidden" name="decurse_ts" value="' . esc_attr($timestamp) . '" />';
        echo '<input type="hidden" name="decurse_token" value="' . esc_attr($token_base) . '" />';
        echo '<input type="hidden" name="decurse_js_check" id="decurse_js_check" value="" />';
    }

    /**
     * Check comment before processing
     */
    public function check_comment($commentdata) {
        // Reload options on each check
        $this->options = get_option('decurse_options', array());

        // Don't check admins/editors
        if (current_user_can('moderate_comments')) {
            return $commentdata;
        }

        // Don't check trackbacks/pingbacks
        if (!empty($commentdata['comment_type']) && $commentdata['comment_type'] !== 'comment') {
            return $commentdata;
        }

        $spam_reason = $this->detect_spam($commentdata);

        if ($spam_reason) {
            $this->handle_spam($commentdata, $spam_reason);
        }

        return $commentdata;
    }

    /**
     * Detect if comment is spam
     * @return string|false Spam reason or false if OK
     */
    private function detect_spam($commentdata) {
        // 1. Honeypot check
        if (!empty($this->options['enable_honeypot'])) {
            // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce handled by WordPress comment system
            if (!empty($_POST['website_url_confirm'])) {
                return 'honeypot';
            }
        }

        // 2. Time check
        if (!empty($this->options['enable_time_check'])) {
            $min_time = isset($this->options['min_submit_time']) ? intval($this->options['min_submit_time']) : 3;
            // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce handled by WordPress comment system
            $submitted_ts = isset($_POST['decurse_ts']) ? intval($_POST['decurse_ts']) : 0;

            if ($submitted_ts > 0) {
                $elapsed = time() - $submitted_ts;
                if ($elapsed < $min_time) {
                    return 'time';
                }
            }
        }

        // 3. JavaScript Token check
        if (!empty($this->options['enable_js_token'])) {
            // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce handled by WordPress comment system
            $js_check = isset($_POST['decurse_js_check']) ? sanitize_text_field(wp_unslash($_POST['decurse_js_check'])) : '';
            // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce handled by WordPress comment system
            $token = isset($_POST['decurse_token']) ? sanitize_text_field(wp_unslash($_POST['decurse_token'])) : '';

            $expected_js_check = md5($token . 'decurse_validated');

            if ($js_check !== $expected_js_check) {
                return 'javascript';
            }
        }

        // 4. Content analysis (enhanced)
        if (!empty($this->options['enable_content_check'])) {
            $content_check = $this->check_content($commentdata);
            if ($content_check) {
                return 'content_' . $content_check;
            }
        }

        return false;
    }

    /**
     * Full comment analysis (content, email, author URL)
     * @return string|false Problem type or false if OK
     */
    private function check_content($commentdata) {
        $content = $commentdata['comment_content'];
        $content_lower = strtolower($content);
        $author_url = isset($commentdata['comment_author_url']) ? $commentdata['comment_author_url'] : '';
        $author_email = isset($commentdata['comment_author_email']) ? $commentdata['comment_author_email'] : '';

        // === MERGE BUILT-IN + CUSTOM DOMAINS ===
        $all_domains = $this->spam_domains;
        $custom_domains = isset($this->options['blocked_domains']) ? $this->options['blocked_domains'] : '';
        if (!empty($custom_domains)) {
            $custom_list = array_filter(array_map('trim', explode("\n", $custom_domains)));
            $all_domains = array_unique(array_merge($all_domains, $custom_list));
        }

        // === SPAM DOMAIN CHECK ===
        // In content
        foreach ($all_domains as $domain) {
            if (stripos($content, $domain) !== false) {
                return 'spam_domain';
            }
        }

        // In author URL
        if (!empty($author_url)) {
            foreach ($all_domains as $domain) {
                if (stripos($author_url, $domain) !== false) {
                    return 'spam_url';
                }
            }

            // Detect referral codes in author URL
            if (preg_match('/[?&]ref=/i', $author_url)) {
                return 'referral_url';
            }
        }

        // === BOT PHRASE CHECK ===
        foreach ($this->bot_phrases as $phrase) {
            if (stripos($content_lower, $phrase) !== false) {
                return 'bot_phrase';
            }
        }

        // === MERGE BUILT-IN + CUSTOM PATTERNS ===
        $all_patterns = $this->spam_patterns;
        $custom_patterns = isset($this->options['spam_patterns']) ? $this->options['spam_patterns'] : '';
        if (!empty($custom_patterns)) {
            $custom_regex_list = array_filter(array_map('trim', explode("\n", $custom_patterns)));
            $all_patterns = array_unique(array_merge($all_patterns, $custom_regex_list));
        }

        // === SPAM PATTERN CHECK ===
        foreach ($all_patterns as $pattern) {
            // Verify pattern is valid
            if (@preg_match($pattern, '') === false) {
                continue; // Invalid pattern, skip
            }
            if (preg_match($pattern, $content)) {
                return 'spam_pattern';
            }
        }

        // === SUSPICIOUS EMAIL CHECK ===
        // Pattern 1: pure digits (6-10)@outlook/hotmail/gmail
        // Pattern 2: word+digits@outlook/hotmail/gmail/yahoo (e.g. Zane2126@gmail.com)
        if (preg_match('/^\d{6,10}@(outlook|hotmail|gmail)\.(com|fr)$/i', $author_email)
            || preg_match('/^[a-z]+\d{1,10}@(outlook|hotmail|gmail|yahoo)\.(com|fr|net|ca)$/i', $author_email)) {
            return 'suspicious_email';
        }

        // === REFERRAL CODE CHECK IN CONTENT ===
        if (preg_match('/[?&]ref=[A-Z0-9]{6,}/i', $content)) {
            return 'referral_link';
        }

        // === ONLY-LINK CHECK ===
        // A comment whose entire body reduces to a URL (typical bot payload:
        // <a href="https://x.tld/abc">https://x.tld/abc</a>)
        if (preg_match('/https?:\/\//i', $content)) {
            $stripped = wp_strip_all_tags($content);
            $stripped = preg_replace('/https?:\/\/\S+/i', '', $stripped);
            if (strlen(trim($stripped)) < 5) {
                return 'only_link';
            }
        }

        // === LINK COUNT CHECK ===
        $max_links = isset($this->options['max_links']) ? intval($this->options['max_links']) : 3;
        $link_count = preg_match_all('/(https?:\/\/|www\.|\[url)/i', $content, $matches);

        if ($link_count > $max_links) {
            return 'links';
        }

        // === BLOCKED WORDS CHECK ===
        $blocked_words = isset($this->options['blocked_words']) ? $this->options['blocked_words'] : '';
        if (!empty($blocked_words)) {
            $words = array_filter(array_map('trim', explode("\n", strtolower($blocked_words))));

            foreach ($words as $word) {
                if (!empty($word) && strpos($content_lower, $word) !== false) {
                    return 'blocked_word';
                }
            }
        }

        // === SUSPICIOUS PATTERN CHECK ===
        $suspicious_patterns = array(
            '/\[url[=\]]/',           // BBCode
            '/\[link[=\]]/',          // BBCode variant
            '/href\s*=/i',            // HTML in comment
            '/<script/i',             // XSS attempt
            '/onclick\s*=/i',         // Event handlers
            '/data:text\/html/i',     // Data URI
            '/register\?ref=/i',      // Registration links with referral
            '/register-person\?ref=/i', // Variant
        );

        foreach ($suspicious_patterns as $pattern) {
            if (preg_match($pattern, $content)) {
                return 'suspicious_pattern';
            }
        }

        // === SUSPICIOUS CHARACTER CHECK ===
        // Comments with many Chinese/Cyrillic characters + link = suspicious
        $has_cjk = preg_match('/[\x{4e00}-\x{9fff}\x{0400}-\x{04FF}]/u', $content);
        $has_link = preg_match('/https?:\/\//i', $content);
        if ($has_cjk && $has_link) {
            // Check if link is to a suspicious domain
            if (preg_match('/https?:\/\/[^\s]*?(binance|bybit|crypto|trading|coin)/i', $content)) {
                return 'suspicious_foreign';
            }
        }

        return false;
    }

    /**
     * Handle detected spam comment
     */
    private function handle_spam($commentdata, $reason) {
        // Log to stats
        Decurse_Stats::log_blocked($reason);

        // Log to table
        $this->log_spam($commentdata, $reason);

        $action = isset($this->options['spam_action']) ? $this->options['spam_action'] : 'spam';

        if ($action === 'block') {
            $error_message = isset($this->options['error_message']) && !empty($this->options['error_message'])
                ? $this->options['error_message']
                : __('Your comment has been identified as spam.', 'decurse-antispam');

            wp_die(
                '<p>' . esc_html($error_message) . '</p>',
                esc_html__('Comment blocked', 'decurse-antispam'),
                array('back_link' => true, 'response' => 403)
            );
        } else {
            // Mark as spam
            add_filter('pre_comment_approved', function($approved) {
                return 'spam';
            }, 99);
        }
    }

    /**
     * Log spam to database table
     */
    private function log_spam($commentdata, $reason) {
        global $wpdb;

        $table_name = $wpdb->prefix . 'decurse_logs';

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Custom table for spam logging
        $wpdb->insert(
            $table_name,
            array(
                'reason'          => $reason,
                'ip_address'      => $this->get_client_ip(),
                'author_name'     => isset($commentdata['comment_author']) ? substr($commentdata['comment_author'], 0, 255) : '',
                'author_email'    => isset($commentdata['comment_author_email']) ? substr($commentdata['comment_author_email'], 0, 255) : '',
                'author_url'      => isset($commentdata['comment_author_url']) ? substr($commentdata['comment_author_url'], 0, 255) : '',
                'comment_content' => substr($commentdata['comment_content'], 0, 500),
            ),
            array('%s', '%s', '%s', '%s', '%s', '%s')
        );
    }

    /**
     * Get client IP address
     */
    private function get_client_ip() {
        $ip_keys = array('HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'REMOTE_ADDR');

        foreach ($ip_keys as $key) {
            if (!empty($_SERVER[$key])) {
                // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- IP is validated below with FILTER_VALIDATE_IP
                $ip = sanitize_text_field(wp_unslash($_SERVER[$key]));
                if (strpos($ip, ',') !== false) {
                    $ip = trim(explode(',', $ip)[0]);
                }
                if (filter_var($ip, FILTER_VALIDATE_IP)) {
                    return $ip;
                }
            }
        }

        return 'unknown';
    }
}
