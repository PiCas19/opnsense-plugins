<?php

/*
 * Copyright (C) 2024 OPNsense Validation Core Library
 * All rights reserved.
 */

namespace OPNsense\ValidationCore\Validators;

use OPNsense\ValidationCore\Utils\NetworkUtils;

/**
 * Network Configuration Validator
 *
 * Specialized validator for network-related configuration parameters including
 * CIDR validation, IP ranges, interface assignments, and network connectivity
 * requirements. This validator ensures that network configurations are valid,
 * consistent, and operationally feasible.
 *
 * @package OPNsense\ValidationCore\Validators
 * @author Pierpaolo Casati
 * @version 1.0
 */
class NetworkValidator extends AbstractValidator
{
    /**
     * Valid private network ranges according to RFC 1918
     */
    private const PRIVATE_NETWORKS = [
        '10.0.0.0/8',
        '172.16.0.0/12',
        '192.168.0.0/16'
    ];

    /**
     * Reserved IP address ranges that should not be used
     */
    private const RESERVED_RANGES = [
        '127.0.0.0/8',    // Loopback
        '169.254.0.0/16', // Link-local
        '224.0.0.0/4',    // Multicast
        '240.0.0.0/4'     // Reserved
    ];

    /**
     * Perform network-specific validation
     */
    protected function performValidation(): void
    {
        $this->validateServiceDependencies();
        $this->validateHomeNetworks();
        $this->validateInterfaceAssignments();
        $this->validateNetworkAccessibility();
    }

    /**
     * Validate service enablement dependencies
     */
    protected function validateServiceDependencies(): void
    {
        $enabled = $this->getBoolValue('general.enabled', false);
        $interfaces = $this->getStringValue('general.interfaces');

        if ($enabled && empty($interfaces)) {
            $this->addError(
                'At least one interface must be selected when the service is enabled',
                'general.interfaces'
            );
        }

        // Check for valid interface format
        if (!empty($interfaces)) {
            $interfaceList = $this->getArrayValue('general.interfaces');
            foreach ($interfaceList as $interface) {
                if (!$this->isValidInterfaceName($interface)) {
                    $this->addError(
                        sprintf('Invalid interface name format: %s', $interface),
                        'general.interfaces'
                    );
                }
            }
        }
    }

    /**
     * Validate home network specifications
     */
    protected function validateHomeNetworks(): void
    {
        if (!$this->shouldValidateField('general.homenet')) {
            return;
        }

        $homeNetworks = $this->getStringValue('general.homenet');
        
        if (empty($homeNetworks)) {
            $this->addWarning(
                'No home networks defined. All traffic will be processed which may impact performance',
                'general.homenet'
            );
            return;
        }

        $networkList = $this->getArrayValue('general.homenet');
        $validatedNetworks = [];

        foreach ($networkList as $network) {
            $network = trim($network);
            
            if (empty($network)) {
                continue;
            }

            // Validate CIDR format
            if (!$this->isValidCIDR($network)) {
                $this->addError(
                    sprintf('Invalid CIDR format: %s. Expected format: 192.168.1.0/24', $network),
                    'general.homenet'
                );
                continue;
            }

            // Validate IP and subnet mask ranges
            if (!$this->isValidNetworkRange($network)) {
                $this->addError(
                    sprintf('Invalid network range: %s', $network),
                    'general.homenet'
                );
                continue;
            }

            // Check for reserved ranges
            if ($this->isReservedRange($network)) {
                $this->addWarning(
                    sprintf('Network %s is in a reserved range and may cause issues', $network),
                    'general.homenet'
                );
            }

            $validatedNetworks[] = $network;
        }

        // Check for network overlaps
        $this->validateNetworkOverlaps($validatedNetworks);
    }

    /**
     * Validate network interface assignments
     */
    protected function validateInterfaceAssignments(): void
    {
        $interfaces = $this->getArrayValue('general.interfaces');
        
        if (empty($interfaces)) {
            return;
        }

        foreach ($interfaces as $interface) {
            if (!$this->isValidInterfaceName($interface)) {
                $this->addError(
                    sprintf('Invalid interface name: %s', $interface),
                    'general.interfaces'
                );
                continue;
            }
        }
    }

    /**
     * Validate network accessibility requirements
     */
    protected function validateNetworkAccessibility(): void
    {
        $homeNetworks = $this->getArrayValue('general.homenet');
        $interfaces = $this->getArrayValue('general.interfaces');

        if (!empty($homeNetworks) && !empty($interfaces)) {
            $this->validateNetworkReachability($homeNetworks, $interfaces);
        }
    }

    /**
     * Check if string is valid CIDR notation
     *
     * @param string $cidr CIDR string to validate
     * @return bool True if valid CIDR format
     */
    private function isValidCIDR(string $cidr): bool
    {
        return NetworkUtils::isValidCIDR($cidr);
    }

    /**
     * Check if network range is valid and properly formed
     *
     * @param string $cidr CIDR notation to validate
     * @return bool True if network range is valid
     */
    private function isValidNetworkRange(string $cidr): bool
    {
        return NetworkUtils::isValidNetworkRange($cidr);
    }

    /**
     * Check if network is in a reserved range
     *
     * @param string $cidr CIDR notation to check
     * @return bool True if network is reserved
     */
    private function isReservedRange(string $cidr): bool
    {
        foreach (self::RESERVED_RANGES as $reservedRange) {
            if (NetworkUtils::networksOverlap($cidr, $reservedRange)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Validate interface name format
     *
     * @param string $interface Interface name to validate
     * @return bool True if interface name is valid
     */
    private function isValidInterfaceName(string $interface): bool
    {
        return preg_match('/^[a-zA-Z0-9_]+$/', $interface) === 1;
    }

    /**
     * Check for overlapping networks in the list
     *
     * @param array $networks List of CIDR networks to check
     */
    private function validateNetworkOverlaps(array $networks): void
    {
        for ($i = 0; $i < count($networks); $i++) {
            for ($j = $i + 1; $j < count($networks); $j++) {
                if (NetworkUtils::networksOverlap($networks[$i], $networks[$j])) {
                    $this->addWarning(
                        sprintf(
                            'Networks %s and %s overlap, which may cause routing issues',
                            $networks[$i],
                            $networks[$j]
                        ),
                        'general.homenet'
                    );
                }
            }
        }
    }

    /**
     * Validate network reachability through configured interfaces
     *
     * @param array $networks List of home networks
     * @param array $interfaces List of configured interfaces
     */
    private function validateNetworkReachability(array $networks, array $interfaces): void
    {
        if (count($networks) > count($interfaces) * 2) {
            $this->addWarning(
                'Large number of home networks relative to interfaces may impact performance',
                'general.homenet'
            );
        }
    }
}