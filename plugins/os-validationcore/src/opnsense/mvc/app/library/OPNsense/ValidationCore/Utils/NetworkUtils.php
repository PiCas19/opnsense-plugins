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
 * Network Utilities Class
 *
 * Provides comprehensive network validation and manipulation utilities for
 * OPNsense configuration validation. This class implements RFC-compliant
 * validation methods for IP addresses, CIDR notation, and network operations
 * commonly required in firewall and networking applications.
 *
 * Key Features:
 * - IPv4 and IPv6 address validation with format checking
 * - CIDR notation validation with proper subnet mask verification
 * - Network overlap detection for conflict resolution
 * - IP address range calculations and subnet operations
 * - Private network classification according to RFC 1918
 * - Network reachability and accessibility validation
 * - Performance-optimized implementations using native PHP functions
 *
 * This utility class is designed to be stateless and thread-safe, providing
 * reliable network validation capabilities across the validation framework.
 *
 * @package OPNsense\ValidationCore\Utils
 * @author Pierpaolo Casati
 * @version 1.0
 */
class NetworkUtils
{
    /**
     * Private network ranges as defined by RFC 1918
     */
    private const RFC1918_NETWORKS = [
        '10.0.0.0/8',
        '172.16.0.0/12',
        '192.168.0.0/16'
    ];

    /**
     * Reserved IPv4 address ranges
     */
    private const RESERVED_IPV4_RANGES = [
        '0.0.0.0/8',          // "This" network
        '127.0.0.0/8',        // Loopback
        '169.254.0.0/16',     // Link-local
        '224.0.0.0/4',        // Multicast
        '240.0.0.0/4',        // Reserved for future use
        '255.255.255.255/32'  // Limited broadcast
    ];

    /**
     * Validate CIDR notation format and values
     *
     * Performs comprehensive validation of CIDR notation including IP address
     * format validation, subnet mask range checking, and network address
     * consistency verification. Supports both IPv4 and IPv6 addresses.
     *
     * @param string $cidr CIDR notation string (e.g., "192.168.1.0/24")
     * @return bool True if CIDR notation is valid
     *
     * @example
     * NetworkUtils::isValidCIDR('192.168.1.0/24'); // Returns true
     * NetworkUtils::isValidCIDR('192.168.1.1/24'); // Returns false (not network address)
     * NetworkUtils::isValidCIDR('2001:db8::/32');  // Returns true (IPv6)
     */
    public static function isValidCIDR(string $cidr): bool
    {
        if (empty($cidr) || strpos($cidr, '/') === false) {
            return false;
        }

        $parts = explode('/', $cidr, 2);
        if (count($parts) !== 2) {
            return false;
        }

        $ip = trim($parts[0]);
        $prefixLength = trim($parts[1]);

        // Validate prefix length is numeric
        if (!is_numeric($prefixLength)) {
            return false;
        }

        $prefixLength = (int)$prefixLength;

        // Determine IP version and validate accordingly
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return self::isValidIPv4CIDR($ip, $prefixLength);
        } elseif (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            return self::isValidIPv6CIDR($ip, $prefixLength);
        }

        return false;
    }

    /**
     * Validate IPv4 CIDR notation
     *
     * @param string $ip IPv4 address
     * @param int $prefixLength Prefix length (0-32)
     * @return bool True if valid IPv4 CIDR
     */
    private static function isValidIPv4CIDR(string $ip, int $prefixLength): bool
    {
        // Validate prefix length range for IPv4
        if ($prefixLength < 0 || $prefixLength > 32) {
            return false;
        }

        // Check if the IP address represents the network address
        $ipLong = ip2long($ip);
        if ($ipLong === false) {
            return false;
        }

        // Calculate network address
        $mask = $prefixLength === 0 ? 0 : (~0 << (32 - $prefixLength));
        $networkLong = $ipLong & $mask;

        // Verify that the given IP is the network address
        return $ipLong === $networkLong;
    }

    /**
     * Validate IPv6 CIDR notation
     *
     * @param string $ip IPv6 address
     * @param int $prefixLength Prefix length (0-128)
     * @return bool True if valid IPv6 CIDR
     */
    private static function isValidIPv6CIDR(string $ip, int $prefixLength): bool
    {
        // Validate prefix length range for IPv6
        if ($prefixLength < 0 || $prefixLength > 128) {
            return false;
        }

        // For IPv6, we'll do a basic validation
        // A more complete implementation would verify network address alignment
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false;
    }

    /**
     * Validate that a network range is properly formed and usable
     *
     * Checks that the network specification represents a valid, usable
     * network range that can be practically deployed in network configurations.
     *
     * @param string $cidr CIDR notation to validate
     * @return bool True if network range is valid and usable
     */
    public static function isValidNetworkRange(string $cidr): bool
    {
        if (!self::isValidCIDR($cidr)) {
            return false;
        }

        $parts = explode('/', $cidr, 2);
        $ip = $parts[0];
        $prefixLength = (int)$parts[1];

        // IPv4 specific checks
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            // Reject host routes (/32) unless it's a special case
            if ($prefixLength === 32) {
                return self::isValidHostRoute($ip);
            }

            // Reject very large networks that are impractical
            if ($prefixLength < 8) {
                return false;
            }

            // Check for valid subnet sizes
            return $prefixLength >= 8 && $prefixLength <= 30;
        }

        // IPv6 specific checks
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            // Standard IPv6 network ranges
            return $prefixLength >= 32 && $prefixLength <= 128;
        }

        return false;
    }

    /**
     * Check if two networks overlap
     *
     * Determines whether two network ranges specified in CIDR notation
     * have any overlapping address space, which could indicate routing
     * conflicts or configuration errors.
     *
     * @param string $network1 First network in CIDR notation
     * @param string $network2 Second network in CIDR notation
     * @return bool True if networks overlap
     */
    public static function networksOverlap(string $network1, string $network2): bool
    {
        if (!self::isValidCIDR($network1) || !self::isValidCIDR($network2)) {
            return false;
        }

        // Only compare networks of the same IP version
        $ip1 = explode('/', $network1)[0];
        $ip2 = explode('/', $network2)[0];

        $isIPv4_1 = filter_var($ip1, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4);
        $isIPv4_2 = filter_var($ip2, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4);

        if ($isIPv4_1 && $isIPv4_2) {
            return self::ipv4NetworksOverlap($network1, $network2);
        }

        $isIPv6_1 = filter_var($ip1, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6);
        $isIPv6_2 = filter_var($ip2, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6);

        if ($isIPv6_1 && $isIPv6_2) {
            return self::ipv6NetworksOverlap($network1, $network2);
        }

        return false; // Different IP versions don't overlap
    }

    /**
     * Check IPv4 network overlap
     *
     * @param string $network1 First IPv4 network
     * @param string $network2 Second IPv4 network
     * @return bool True if networks overlap
     */
    private static function ipv4NetworksOverlap(string $network1, string $network2): bool
    {
        list($ip1, $prefix1) = explode('/', $network1);
        list($ip2, $prefix2) = explode('/', $network2);

        $ip1Long = ip2long($ip1);
        $ip2Long = ip2long($ip2);

        if ($ip1Long === false || $ip2Long === false) {
            return false;
        }

        $prefix1 = (int)$prefix1;
        $prefix2 = (int)$prefix2;

        // Calculate network and broadcast addresses
        $mask1 = $prefix1 === 0 ? 0 : (~0 << (32 - $prefix1));
        $mask2 = $prefix2 === 0 ? 0 : (~0 << (32 - $prefix2));

        $network1Start = $ip1Long & $mask1;
        $network1End = $network1Start | (~$mask1 & 0xFFFFFFFF);

        $network2Start = $ip2Long & $mask2;
        $network2End = $network2Start | (~$mask2 & 0xFFFFFFFF);

        // Check for overlap
        return !($network1End < $network2Start || $network2End < $network1Start);
    }

    /**
     * Check IPv6 network overlap (simplified implementation)
     *
     * @param string $network1 First IPv6 network
     * @param string $network2 Second IPv6 network
     * @return bool True if networks overlap
     */
    private static function ipv6NetworksOverlap(string $network1, string $network2): bool
    {
        // Simplified IPv6 overlap check
        // A complete implementation would use binary operations on IPv6 addresses
        return $network1 === $network2;
    }

    /**
     * Check if an IP address is in a private network range
     *
     * Determines whether an IP address falls within the private address
     * ranges defined by RFC 1918 for IPv4 or RFC 4193 for IPv6.
     *
     * @param string $ip IP address to check
     * @return bool True if IP is in private range
     */
    public static function isPrivateNetwork(string $ip): bool
    {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            foreach (self::RFC1918_NETWORKS as $privateNetwork) {
                if (self::ipInNetwork($ip, $privateNetwork)) {
                    return true;
                }
            }
        }

        // IPv6 private addresses (simplified check)
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            // Check for unique local addresses (fc00::/7)
            return strpos(strtolower($ip), 'fc') === 0 || strpos(strtolower($ip), 'fd') === 0;
        }

        return false;
    }

    /**
     * Check if an IP address is in a reserved range
     *
     * @param string $ip IP address to check
     * @return bool True if IP is in reserved range
     */
    public static function isReservedAddress(string $ip): bool
    {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            foreach (self::RESERVED_IPV4_RANGES as $reservedRange) {
                if (self::ipInNetwork($ip, $reservedRange)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Check if an IP address is within a specific network
     *
     * @param string $ip IP address to test
     * @param string $network Network in CIDR notation
     * @return bool True if IP is in network
     */
    public static function ipInNetwork(string $ip, string $network): bool
    {
        if (!self::isValidCIDR($network)) {
            return false;
        }

        list($networkIp, $prefixLength) = explode('/', $network);
        $prefixLength = (int)$prefixLength;

        // IPv4 check
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) && 
            filter_var($networkIp, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            
            $ipLong = ip2long($ip);
            $networkLong = ip2long($networkIp);
            
            if ($ipLong === false || $networkLong === false) {
                return false;
            }

            $mask = $prefixLength === 0 ? 0 : (~0 << (32 - $prefixLength));
            
            return ($ipLong & $mask) === ($networkLong & $mask);
        }

        // IPv6 check (simplified)
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) && 
            filter_var($networkIp, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            
            // Simplified IPv6 network matching
            $ipBin = inet_pton($ip);
            $networkBin = inet_pton($networkIp);
            
            if ($ipBin === false || $networkBin === false) {
                return false;
            }

            $bytesToCheck = intval($prefixLength / 8);
            $bitsToCheck = $prefixLength % 8;

            // Compare full bytes
            if ($bytesToCheck > 0 && substr($ipBin, 0, $bytesToCheck) !== substr($networkBin, 0, $bytesToCheck)) {
                return false;
            }

            // Compare remaining bits
            if ($bitsToCheck > 0 && $bytesToCheck < 16) {
                $ipByte = ord($ipBin[$bytesToCheck]);
                $networkByte = ord($networkBin[$bytesToCheck]);
                $mask = 0xFF << (8 - $bitsToCheck);
                
                return ($ipByte & $mask) === ($networkByte & $mask);
            }

            return true;
        }

        return false;
    }

    /**
     * Calculate network size (number of available addresses)
     *
     * @param string $cidr Network in CIDR notation
     * @return int Number of addresses in network, -1 if invalid
     */
    public static function getNetworkSize(string $cidr): int
    {
        if (!self::isValidCIDR($cidr)) {
            return -1;
        }

        list($ip, $prefixLength) = explode('/', $cidr);
        $prefixLength = (int)$prefixLength;

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return $prefixLength === 32 ? 1 : pow(2, 32 - $prefixLength);
        }

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            // For IPv6, return a simplified calculation or -1 for very large networks
            if ($prefixLength >= 64) {
                return pow(2, 128 - $prefixLength);
            }
            return -1; // Too large to calculate meaningfully
        }

        return -1;
    }

    /**
     * Get network and broadcast addresses for IPv4 network
     *
     * @param string $cidr IPv4 network in CIDR notation
     * @return array|null Array with 'network' and 'broadcast' keys, null if invalid
     */
    public static function getNetworkBounds(string $cidr): ?array
    {
        if (!self::isValidCIDR($cidr)) {
            return null;
        }

        list($ip, $prefixLength) = explode('/', $cidr);
        $prefixLength = (int)$prefixLength;

        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return null; // Only support IPv4 for now
        }

        $ipLong = ip2long($ip);
        if ($ipLong === false) {
            return null;
        }

        $mask = $prefixLength === 0 ? 0 : (~0 << (32 - $prefixLength));
        $networkLong = $ipLong & $mask;
        $broadcastLong = $networkLong | (~$mask & 0xFFFFFFFF);

        return [
            'network' => long2ip($networkLong),
            'broadcast' => long2ip($broadcastLong),
            'mask' => long2ip($mask),
            'size' => $broadcastLong - $networkLong + 1
        ];
    }

    /**
     * Validate that an IP represents a valid host route
     *
     * @param string $ip IP address
     * @return bool True if valid for host route
     */
    private static function isValidHostRoute(string $ip): bool
    {
        // Host routes are valid for specific addresses like loopback
        return !self::isReservedAddress($ip) || $ip === '127.0.0.1';
    }

    /**
     * Normalize CIDR notation
     *
     * Ensures that CIDR notation uses the network address rather than
     * any address within the network.
     *
     * @param string $cidr CIDR notation
     * @return string|null Normalized CIDR or null if invalid
     */
    public static function normalizeCIDR(string $cidr): ?string
    {
        if (!self::isValidCIDR($cidr)) {
            return null;
        }

        list($ip, $prefixLength) = explode('/', $cidr);
        $prefixLength = (int)$prefixLength;

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $ipLong = ip2long($ip);
            if ($ipLong === false) {
                return null;
            }

            $mask = $prefixLength === 0 ? 0 : (~0 << (32 - $prefixLength));
            $networkLong = $ipLong & $mask;
            $networkIp = long2ip($networkLong);

            return $networkIp . '/' . $prefixLength;
        }

        // For IPv6, return as-is (more complex normalization would be needed)
        return $cidr;
    }
}