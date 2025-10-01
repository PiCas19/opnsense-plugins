<?php

/*
 * Copyright (C) 2024 OPNsense Validation Core Library
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

namespace OPNsense\ValidationCore\Utils;

/**
 * Validation Helper Utilities
 *
 * Comprehensive collection of validation utilities for common data types
 * and formats used throughout OPNsense configuration validation. This class
 * provides standardized validation methods that ensure consistency across
 * the validation framework while maintaining performance and reliability.
 *
 * Key Features:
 * - Port number validation with range checking
 * - String format validation for various network identifiers
 * - Boolean value validation with flexible input handling
 * - Numeric range validation with boundary checking
 * - Regular expression-based pattern validation
 * - URL and URI validation for web-based configurations
 * - File path validation for configuration file references
 * - Email address validation for notification settings
 * - Domain name validation according to RFC standards
 *
 * All methods in this class are static and stateless, providing
 * thread-safe validation capabilities that can be called from
 * any context within the validation framework.
 *
 * @package OPNsense\ValidationCore\Utils
 * @author Pierpaolo Casati
 * @version 1.0
 */
class ValidationHelper
{
    /**
     * Valid boolean representations in various formats
     */
    private const BOOLEAN_TRUE_VALUES = ['1', 'true', 'yes', 'on', 'enabled', 'enable'];
    private const BOOLEAN_FALSE_VALUES = ['0', 'false', 'no', 'off', 'disabled', 'disable'];

    /**
     * Common port ranges for different services
     */
    private const WELL_KNOWN_PORTS = [
        'min' => 1,
        'max' => 1023
    ];

    private const REGISTERED_PORTS = [
        'min' => 1024,
        'max' => 49151
    ];

    private const DYNAMIC_PORTS = [
        'min' => 49152,
        'max' => 65535
    ];

    /**
     * Regular expressions for common validation patterns
     */
    private const HOSTNAME_PATTERN = '/^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$/';
    private const DOMAIN_PATTERN = '/^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/';
    private const MAC_ADDRESS_PATTERN = '/^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/';
    private const UUID_PATTERN = '/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i';

    /**
     * Validate port number within valid range
     *
     * Checks if a given port number falls within the valid TCP/UDP port range
     * (1-65535) and provides additional context about port type (well-known,
     * registered, or dynamic) for informational purposes.
     *
     * @param int $port Port number to validate
     * @return bool True if port is valid (1-65535)
     *
     * @example
     * ValidationHelper::isValidPort(80);    // Returns true (well-known)
     * ValidationHelper::isValidPort(8080);  // Returns true (registered)
     * ValidationHelper::isValidPort(0);     // Returns false (invalid)
     * ValidationHelper::isValidPort(70000); // Returns false (out of range)
     */
    public static function isValidPort(int $port): bool
    {
        return $port >= 1 && $port <= 65535;
    }

    /**
     * Get port category information
     *
     * Classifies a port number into its IANA-defined category for
     * informational and policy purposes.
     *
     * @param int $port Port number to classify
     * @return string Port category: 'well-known', 'registered', 'dynamic', or 'invalid'
     */
    public static function getPortCategory(int $port): string
    {
        if (!self::isValidPort($port)) {
            return 'invalid';
        }

        if ($port <= self::WELL_KNOWN_PORTS['max']) {
            return 'well-known';
        } elseif ($port <= self::REGISTERED_PORTS['max']) {
            return 'registered';
        } else {
            return 'dynamic';
        }
    }

    /**
     * Validate port range specification
     *
     * Validates port range strings in various formats including single ports,
     * ranges (start-end), and comma-separated lists. Ensures all ports in
     * the specification are valid and ranges are properly ordered.
     *
     * @param string $portSpec Port specification string
     * @return bool True if all ports in specification are valid
     *
     * @example
     * ValidationHelper::isValidPortRange('80');           // Returns true
     * ValidationHelper::isValidPortRange('80-90');        // Returns true
     * ValidationHelper::isValidPortRange('80,443,8080');  // Returns true
     * ValidationHelper::isValidPortRange('90-80');        // Returns false (invalid range)
     */
    public static function isValidPortRange(string $portSpec): bool
    {
        if (empty($portSpec) || trim($portSpec) === '') {
            return false;
        }

        // Handle "any" keyword
        if (strtolower(trim($portSpec)) === 'any') {
            return true;
        }

        $parts = array_map('trim', explode(',', $portSpec));

        foreach ($parts as $part) {
            if (empty($part)) {
                continue;
            }

            if (strpos($part, '-') !== false) {
                // Handle range (e.g., "80-90")
                $rangeParts = explode('-', $part, 2);
                if (count($rangeParts) !== 2) {
                    return false;
                }

                $startPort = (int)trim($rangeParts[0]);
                $endPort = (int)trim($rangeParts[1]);

                if (!self::isValidPort($startPort) || !self::isValidPort($endPort)) {
                    return false;
                }

                if ($startPort > $endPort) {
                    return false; // Invalid range order
                }
            } else {
                // Handle single port
                $port = (int)$part;
                if (!self::isValidPort($port)) {
                    return false;
                }
            }
        }

        return true;
    }

    /**
     * Validate boolean value with flexible input handling
     *
     * Accepts various boolean representations commonly used in configuration
     * files and web forms, providing consistent boolean interpretation across
     * the validation framework.
     *
     * @param mixed $value Value to validate as boolean
     * @return bool True if value represents a valid boolean
     *
     * @example
     * ValidationHelper::isValidBoolean('1');      // Returns true
     * ValidationHelper::isValidBoolean('true');   // Returns true
     * ValidationHelper::isValidBoolean('yes');    // Returns true
     * ValidationHelper::isValidBoolean('maybe');  // Returns false
     */
    public static function isValidBoolean($value): bool
    {
        if (is_bool($value)) {
            return true;
        }

        $stringValue = strtolower((string)$value);
        
        return in_array($stringValue, self::BOOLEAN_TRUE_VALUES, true) ||
               in_array($stringValue, self::BOOLEAN_FALSE_VALUES, true);
    }

    /**
     * Convert value to boolean with flexible input handling
     *
     * @param mixed $value Value to convert
     * @param bool $default Default value if conversion fails
     * @return bool Boolean representation of value
     */
    public static function toBoolean($value, bool $default = false): bool
    {
        if (is_bool($value)) {
            return $value;
        }

        $stringValue = strtolower((string)$value);
        
        if (in_array($stringValue, self::BOOLEAN_TRUE_VALUES, true)) {
            return true;
        }
        
        if (in_array($stringValue, self::BOOLEAN_FALSE_VALUES, true)) {
            return false;
        }
        
        return $default;
    }

    /**
     * Validate numeric value within specified range
     *
     * Checks if a numeric value falls within the specified minimum and
     * maximum bounds (inclusive). Supports both integer and float values.
     *
     * @param mixed $value Value to validate
     * @param float $min Minimum allowed value (inclusive)
     * @param float $max Maximum allowed value (inclusive)
     * @return bool True if value is numeric and within range
     */
    public static function isInRange($value, float $min, float $max): bool
    {
        if (!is_numeric($value)) {
            return false;
        }

        $numericValue = (float)$value;
        return $numericValue >= $min && $numericValue <= $max;
    }

    /**
     * Validate string length within specified bounds
     *
     * @param string $value String to validate
     * @param int $minLength Minimum required length
     * @param int $maxLength Maximum allowed length
     * @return bool True if string length is within bounds
     */
    public static function isValidStringLength(string $value, int $minLength = 0, int $maxLength = PHP_INT_MAX): bool
    {
        $length = mb_strlen($value, 'UTF-8');
        return $length >= $minLength && $length <= $maxLength;
    }

    /**
     * Validate hostname format according to RFC standards
     *
     * Validates hostname format according to RFC 1123 specifications,
     * ensuring proper character usage and length constraints.
     *
     * @param string $hostname Hostname to validate
     * @return bool True if hostname is valid
     */
    public static function isValidHostname(string $hostname): bool
    {
        if (empty($hostname) || strlen($hostname) > 253) {
            return false;
        }

        // Split into labels and validate each
        $labels = explode('.', $hostname);
        
        foreach ($labels as $label) {
            if (empty($label) || strlen($label) > 63) {
                return false;
            }
            
            if (!preg_match(self::HOSTNAME_PATTERN, $label)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Validate domain name format
     *
     * @param string $domain Domain name to validate
     * @return bool True if domain is valid
     */
    public static function isValidDomain(string $domain): bool
    {
        if (empty($domain) || strlen($domain) > 253) {
            return false;
        }

        return preg_match(self::DOMAIN_PATTERN, $domain) === 1;
    }

    /**
     * Validate MAC address format
     *
     * Validates MAC address in common formats (colon or hyphen separated).
     *
     * @param string $macAddress MAC address to validate
     * @return bool True if MAC address is valid
     */
    public static function isValidMacAddress(string $macAddress): bool
    {
        return preg_match(self::MAC_ADDRESS_PATTERN, $macAddress) === 1;
    }

    /**
     * Validate UUID format
     *
     * @param string $uuid UUID string to validate
     * @return bool True if UUID is valid
     */
    public static function isValidUUID(string $uuid): bool
    {
        return preg_match(self::UUID_PATTERN, $uuid) === 1;
    }

    /**
     * Validate email address format
     *
     * Uses PHP's built-in email validation with additional checks for
     * practical email address requirements.
     *
     * @param string $email Email address to validate
     * @return bool True if email is valid
     */
    public static function isValidEmail(string $email): bool
    {
        if (empty($email) || strlen($email) > 254) {
            return false;
        }

        return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
    }

    /**
     * Validate URL format
     *
     * @param string $url URL to validate
     * @param array $allowedSchemes Allowed URL schemes (default: http, https)
     * @return bool True if URL is valid
     */
    public static function isValidURL(string $url, array $allowedSchemes = ['http', 'https']): bool
    {
        if (empty($url)) {
            return false;
        }

        $validatedUrl = filter_var($url, FILTER_VALIDATE_URL);
        if ($validatedUrl === false) {
            return false;
        }

        $scheme = parse_url($url, PHP_URL_SCHEME);
        return in_array(strtolower($scheme), $allowedSchemes, true);
    }

    /**
     * Validate file path format and security
     *
     * Validates file paths for security issues such as directory traversal
     * attempts and ensures paths conform to expected formats.
     *
     * @param string $path File path to validate
     * @param bool $allowAbsolute Whether to allow absolute paths
     * @return bool True if path is valid and safe
     */
    public static function isValidFilePath(string $path, bool $allowAbsolute = false): bool
    {
        if (empty($path)) {
            return false;
        }

        // Check for directory traversal attempts
        if (strpos($path, '..') !== false) {
            return false;
        }

        // Check for null bytes
        if (strpos($path, "\0") !== false) {
            return false;
        }

        // Check absolute path restriction
        if (!$allowAbsolute && (substr($path, 0, 1) === '/' || preg_match('/^[A-Z]:\\/', $path))) {
            return false;
        }

        // Check for invalid characters
        if (preg_match('/[<>:"|?*]/', $path)) {
            return false;
        }

        return true;
    }

    /**
     * Validate regular expression pattern
     *
     * Tests if a string is a valid regular expression by attempting to
     * compile it and checking for errors.
     *
     * @param string $pattern Regular expression pattern to validate
     * @return bool True if pattern is valid
     */
    public static function isValidRegex(string $pattern): bool
    {
        if (empty($pattern)) {
            return false;
        }

        // Suppress errors and warnings
        $result = @preg_match($pattern, '');
        
        // Check if compilation succeeded (result is not false)
        return $result !== false;
    }

    /**
     * Validate hexadecimal string
     *
     * @param string $hex Hexadecimal string to validate
     * @param int $expectedLength Expected length (0 = any length)
     * @return bool True if string is valid hexadecimal
     */
    public static function isValidHex(string $hex, int $expectedLength = 0): bool
    {
        if (empty($hex)) {
            return false;
        }

        // Remove optional 0x prefix
        if (substr($hex, 0, 2) === '0x') {
            $hex = substr($hex, 2);
        }

        // Check if string contains only hexadecimal characters
        if (!ctype_xdigit($hex)) {
            return false;
        }

        // Check expected length if specified
        if ($expectedLength > 0 && strlen($hex) !== $expectedLength) {
            return false;
        }

        return true;
    }

    /**
     * Validate IPv4 address format
     *
     * @param string $ip IP address to validate
     * @return bool True if IP is valid IPv4
     */
    public static function isValidIPv4(string $ip): bool
    {
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false;
    }

    /**
     * Validate IPv6 address format
     *
     * @param string $ip IP address to validate
     * @return bool True if IP is valid IPv6
     */
    public static function isValidIPv6(string $ip): bool
    {
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false;
    }

    /**
     * Validate IP address (IPv4 or IPv6)
     *
     * @param string $ip IP address to validate
     * @return bool True if IP is valid (either IPv4 or IPv6)
     */
    public static function isValidIP(string $ip): bool
    {
        return filter_var($ip, FILTER_VALIDATE_IP) !== false;
    }

    /**
     * Sanitize string for safe output
     *
     * Removes or escapes potentially dangerous characters for safe display
     * in HTML contexts or log files.
     *
     * @param string $input Input string to sanitize
     * @param bool $allowHtml Whether to allow HTML tags
     * @return string Sanitized string
     */
    public static function sanitizeString(string $input, bool $allowHtml = false): string
    {
        if (!$allowHtml) {
            $input = htmlspecialchars($input, ENT_QUOTES, 'UTF-8');
        }

        // Remove null bytes
        $input = str_replace("\0", '', $input);

        // Normalize line endings
        $input = preg_replace('/\r\n|\r|\n/', "\n", $input);

        return $input;
    }

    /**
     * Validate and normalize timeout value
     *
     * Ensures timeout values are within reasonable bounds for network
     * operations and system configurations.
     *
     * @param mixed $timeout Timeout value to validate
     * @param int $minTimeout Minimum allowed timeout (seconds)
     * @param int $maxTimeout Maximum allowed timeout (seconds)
     * @return int|null Normalized timeout value or null if invalid
     */
    public static function validateTimeout($timeout, int $minTimeout = 1, int $maxTimeout = 3600): ?int
    {
        if (!is_numeric($timeout)) {
            return null;
        }

        $timeoutValue = (int)$timeout;
        
        if ($timeoutValue < $minTimeout || $timeoutValue > $maxTimeout) {
            return null;
        }

        return $timeoutValue;
    }

    /**
     * Check if string contains only printable ASCII characters
     *
     * @param string $string String to check
     * @return bool True if string contains only printable ASCII
     */
    public static function isPrintableASCII(string $string): bool
    {
        return ctype_print($string);
    }

    /**
     * Validate interface name format
     *
     * Validates network interface names according to common conventions
     * used in Unix-like systems.
     *
     * @param string $interface Interface name to validate
     * @return bool True if interface name is valid
     */
    public static function isValidInterfaceName(string $interface): bool
    {
        if (empty($interface) || strlen($interface) > 15) {
            return false;
        }

        // Interface names should contain only alphanumeric characters and underscore
        return preg_match('/^[a-zA-Z][a-zA-Z0-9_]*$/', $interface) === 1;
    }

    /**
     * Get validation error message for common validation failures
     *
     * @param string $validationType Type of validation that failed
     * @param mixed $value The value that failed validation
     * @param array $context Additional context for error message
     * @return string Human-readable error message
     */
    public static function getValidationErrorMessage(string $validationType, $value, array $context = []): string
    {
        switch ($validationType) {
            case 'port':
                return sprintf('Invalid port number: %s. Must be between 1 and 65535.', $value);
                
            case 'port_range':
                return sprintf('Invalid port range: %s. Use formats like "80", "80-90", or "80,443".', $value);
                
            case 'boolean':
                return sprintf('Invalid boolean value: %s. Use 1/0, true/false, yes/no, or on/off.', $value);
                
            case 'ip':
                return sprintf('Invalid IP address: %s. Must be a valid IPv4 or IPv6 address.', $value);
                
            case 'hostname':
                return sprintf('Invalid hostname: %s. Must follow RFC 1123 standards.', $value);
                
            case 'email':
                return sprintf('Invalid email address: %s.', $value);
                
            case 'url':
                return sprintf('Invalid URL: %s. Must be a valid HTTP or HTTPS URL.', $value);
                
            case 'range':
                $min = $context['min'] ?? 'minimum';
                $max = $context['max'] ?? 'maximum';
                return sprintf('Value %s is out of range. Must be between %s and %s.', $value, $min, $max);
                
            default:
                return sprintf('Invalid value: %s.', $value);
        }
    }
}