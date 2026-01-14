<?php
/**
 * Internationalization helper class
 *
 * Compiles .po files to .mo files automatically
 *
 * @package Decurse_Antispam
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Class Decurse_I18n
 *
 * Handles automatic compilation of .po to .mo files
 */
class Decurse_I18n {

    /**
     * Compile all .po files in the languages directory to .mo files
     */
    public static function compile_translations() {
        $languages_dir = DECURSE_PLUGIN_DIR . 'languages/';

        if (!is_dir($languages_dir)) {
            return;
        }

        $po_files = glob($languages_dir . '*.po');

        if (empty($po_files)) {
            return;
        }

        foreach ($po_files as $po_file) {
            $mo_file = substr($po_file, 0, -3) . '.mo';

            // Only compile if .mo doesn't exist or .po is newer
            if (!file_exists($mo_file) || filemtime($po_file) > filemtime($mo_file)) {
                self::compile_po_to_mo($po_file, $mo_file);
            }
        }
    }

    /**
     * Compile a single .po file to .mo format
     *
     * @param string $po_file Path to .po file
     * @param string $mo_file Path to output .mo file
     * @return bool Success
     */
    public static function compile_po_to_mo($po_file, $mo_file) {
        $entries = self::parse_po_file($po_file);

        if (empty($entries)) {
            return false;
        }

        return self::write_mo_file($mo_file, $entries);
    }

    /**
     * Parse a .po file and extract translations
     *
     * @param string $po_file Path to .po file
     * @return array Associative array of msgid => msgstr
     */
    private static function parse_po_file($po_file) {
        $content = file_get_contents($po_file);

        if ($content === false) {
            return array();
        }

        $entries = array();
        $current_msgid = '';
        $current_msgstr = '';
        $in_msgid = false;
        $in_msgstr = false;

        $lines = explode("\n", $content);

        foreach ($lines as $line) {
            $line = trim($line);

            // Skip comments and empty lines
            if (empty($line) || $line[0] === '#') {
                // Save previous entry if we have one
                if ($in_msgstr && $current_msgid !== '') {
                    $entries[$current_msgid] = $current_msgstr;
                }
                $in_msgid = false;
                $in_msgstr = false;
                continue;
            }

            // msgid line
            if (strpos($line, 'msgid ') === 0) {
                // Save previous entry
                if ($in_msgstr && $current_msgid !== '') {
                    $entries[$current_msgid] = $current_msgstr;
                }

                $current_msgid = self::extract_string($line, 'msgid ');
                $current_msgstr = '';
                $in_msgid = true;
                $in_msgstr = false;
                continue;
            }

            // msgstr line
            if (strpos($line, 'msgstr ') === 0) {
                $current_msgstr = self::extract_string($line, 'msgstr ');
                $in_msgid = false;
                $in_msgstr = true;
                continue;
            }

            // Continuation line (quoted string)
            if ($line[0] === '"') {
                $str = self::extract_quoted_string($line);
                if ($in_msgid) {
                    $current_msgid .= $str;
                } elseif ($in_msgstr) {
                    $current_msgstr .= $str;
                }
            }
        }

        // Don't forget the last entry
        if ($in_msgstr && $current_msgid !== '') {
            $entries[$current_msgid] = $current_msgstr;
        }

        return $entries;
    }

    /**
     * Extract string value from a po line
     *
     * @param string $line The line
     * @param string $prefix The prefix to remove
     * @return string The extracted string
     */
    private static function extract_string($line, $prefix) {
        $value = substr($line, strlen($prefix));
        return self::extract_quoted_string($value);
    }

    /**
     * Extract content from a quoted string
     *
     * @param string $str Quoted string
     * @return string Unquoted content
     */
    private static function extract_quoted_string($str) {
        $str = trim($str);

        if (strlen($str) < 2) {
            return '';
        }

        // Remove surrounding quotes
        if ($str[0] === '"' && substr($str, -1) === '"') {
            $str = substr($str, 1, -1);
        }

        // Unescape special characters
        $str = str_replace(
            array('\\n', '\\r', '\\t', '\\"', '\\\\'),
            array("\n", "\r", "\t", '"', '\\'),
            $str
        );

        return $str;
    }

    /**
     * Write entries to a .mo file
     *
     * @param string $mo_file Path to output file
     * @param array $entries Translations array
     * @return bool Success
     */
    private static function write_mo_file($mo_file, $entries) {
        // Remove empty msgid (header) for sorting, but keep it
        $header = isset($entries['']) ? $entries[''] : '';
        unset($entries['']);

        // Sort entries by msgid
        ksort($entries);

        // Re-add header at the beginning
        $sorted_entries = array('' => $header) + $entries;

        $count = count($sorted_entries);

        // Calculate offsets
        $originals_offset = 28; // Header size
        $translations_offset = $originals_offset + ($count * 8);
        $hash_table_offset = $translations_offset + ($count * 8);
        $strings_offset = $hash_table_offset; // No hash table

        // Build string tables
        $originals_table = '';
        $translations_table = '';
        $originals_offsets = array();
        $translations_offsets = array();

        $current_offset = $strings_offset;

        foreach ($sorted_entries as $original => $translation) {
            $originals_offsets[] = array(
                'length' => strlen($original),
                'offset' => $current_offset,
            );
            $originals_table .= $original . "\0";
            $current_offset += strlen($original) + 1;
        }

        foreach ($sorted_entries as $original => $translation) {
            $translations_offsets[] = array(
                'length' => strlen($translation),
                'offset' => $current_offset,
            );
            $translations_table .= $translation . "\0";
            $current_offset += strlen($translation) + 1;
        }

        // Build the file
        $output = '';

        // Magic number (little-endian)
        $output .= pack('V', 0x950412de);

        // File format revision
        $output .= pack('V', 0);

        // Number of strings
        $output .= pack('V', $count);

        // Offset of original strings table
        $output .= pack('V', $originals_offset);

        // Offset of translation strings table
        $output .= pack('V', $translations_offset);

        // Size of hash table (0 = no hash table)
        $output .= pack('V', 0);

        // Offset of hash table
        $output .= pack('V', $hash_table_offset);

        // Original strings offsets
        foreach ($originals_offsets as $offset_data) {
            $output .= pack('V', $offset_data['length']);
            $output .= pack('V', $offset_data['offset']);
        }

        // Translation strings offsets
        foreach ($translations_offsets as $offset_data) {
            $output .= pack('V', $offset_data['length']);
            $output .= pack('V', $offset_data['offset']);
        }

        // String data
        $output .= $originals_table;
        $output .= $translations_table;

        // Write to file
        $result = file_put_contents($mo_file, $output);

        return $result !== false;
    }
}
