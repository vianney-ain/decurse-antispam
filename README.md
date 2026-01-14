# Decurse Antispam

A lightweight WordPress plugin for comment spam protection. No external API required, no CAPTCHA needed, and completely GDPR-friendly.

## Description

Decurse Antispam protects your WordPress comments from spam using multiple layered detection techniques that work together to stop bots while remaining invisible to your legitimate visitors.

### Features

- **Honeypot Field** - An invisible trap field that bots fill out automatically
- **Time Check** - Blocks submissions that happen faster than humanly possible
- **JavaScript Token** - Verifies that JavaScript is executed (bots often don't run JS)
- **Content Analysis** - Multi-factor content checking including:
  - Blocked domains list (crypto exchanges, URL shorteners, gambling sites)
  - Bot phrase detection (generic spam comments)
  - Regex spam patterns
  - Suspicious email patterns
  - Referral link detection
  - Link count limits

### Why Decurse Antispam?

- **No External API** - All processing happens on your server
- **No CAPTCHA** - No annoying challenges for your visitors
- **Privacy-Friendly** - No data sent to third parties
- **Lightweight** - Minimal impact on page load
- **Configurable** - Fine-tune all protection settings

## Installation

1. Upload the `decurse-antispam` folder to `/wp-content/plugins/`
2. Activate the plugin through the 'Plugins' menu in WordPress
3. Go to **Decurse** in the admin menu to configure settings

## Requirements

- WordPress 5.0 or higher
- PHP 7.2 or higher (8.0+ recommended)
- MySQL 5.5 or higher (8.0+ recommended)

## Configuration

### Protection Techniques

Enable or disable each protection method:

| Technique | Description |
|-----------|-------------|
| Honeypot | Invisible field that bots auto-fill |
| Time Check | Minimum submission time (default: 3 seconds) |
| JavaScript Token | MD5 hash validation proving JS execution |
| Content Analysis | Pattern matching and keyword detection |

### Spam Action

Choose what happens when spam is detected:

- **Mark as Spam** - Sends to WordPress spam queue (recoverable)
- **Block Completely** - Rejects submission with error message

### Blacklists

Customize blocked words, domains, and regex patterns to match your needs.

## Frequently Asked Questions

### Does this work with caching plugins?

Yes, Decurse Antispam is compatible with most caching plugins as it uses JavaScript tokens that are generated dynamically.

### Will this block legitimate comments?

The default settings are conservative and should not block legitimate users. You can adjust the sensitivity through the settings panel.

### Does this send data to external servers?

No, all spam detection happens locally on your server. No data is sent to external APIs or services.

## Changelog

### 1.0.0
- Initial release
- Honeypot protection
- Time-based submission check
- JavaScript token validation
- Content analysis with multiple detection methods
- Dashboard with statistics and logs
- Configurable blacklists (words, domains, patterns)

## Credits

Developed by [Vianney Aïn](https://vianneyain.com)

## License

GPL v2 or later - [https://www.gnu.org/licenses/gpl-2.0.html](https://www.gnu.org/licenses/gpl-2.0.html)
