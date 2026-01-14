=== Decurse Antispam ===
Contributors: vianneyain
Tags: antispam, spam, comments, security, honeypot
Requires at least: 5.0
Tested up to: 6.9
Stable tag: 1.0.0
Requires PHP: 7.2
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Comment spam protection for WordPress using honeypot, time check, JavaScript token and content analysis. No external API required.

== Description ==

**Decurse Antispam** protects your WordPress comments from spam using multiple layered detection techniques. Unlike other solutions, it works entirely on your server without sending data to external services.

= Protection Techniques =

* **Honeypot** - Invisible trap field that bots fill out automatically
* **Time Check** - Blocks submissions faster than humanly possible
* **JavaScript Token** - Verifies that JavaScript is executed (blocks headless bots)
* **Content Analysis** - Detects spam domains, bot phrases, suspicious patterns, and excessive links

= Why Decurse Antispam? =

* **No external API** - All processing happens on your server
* **No CAPTCHA** - Invisible to your visitors
* **Privacy-friendly** - No data sent to third parties
* **Lightweight** - Minimal impact on page load
* **Configurable** - Customize blacklists and detection rules
* **Statistics** - Dashboard with blocking statistics and logs

= Languages =

Decurse Antispam is available in 15 languages:

* English (US, UK, CA)
* French (FR, CA)
* Spanish
* German
* Italian
* Russian
* Japanese
* Chinese (Simplified)
* Portuguese (Brazil)
* Turkish
* Arabic
* Korean

== Installation ==

1. Upload the `decurse-antispam` folder to `/wp-content/plugins/`
2. Activate the plugin through the 'Plugins' menu in WordPress
3. Go to **Decurse** in the admin menu to configure settings

== Frequently Asked Questions ==

= Does this plugin work with caching? =

Yes, Decurse Antispam works with all caching plugins. The JavaScript token is generated dynamically and validated server-side.

= Will this block legitimate comments? =

The default settings are tuned to minimize false positives. The time check (3 seconds) is fast enough for humans but catches most bots. You can adjust settings if needed.

= Does it work without JavaScript? =

If JavaScript is disabled, comments will be marked as spam (configurable). Most legitimate users have JavaScript enabled.

= Can I see what spam was blocked? =

Yes, the dashboard shows statistics and a log of all blocked spam with reasons.

== Screenshots ==

1. Dashboard with statistics
2. Settings page
3. Blocked spam log
4. Spam details popup

== Changelog ==

= 1.0.0 =
* Initial release
* Honeypot protection
* Time-based submission check
* JavaScript token validation
* Content analysis with multiple detection methods
* Dashboard with statistics and logs
* Configurable blacklists (words, domains, regex patterns)
* 15 languages supported

== Upgrade Notice ==

= 1.0.0 =
Initial release of Decurse Antispam.
