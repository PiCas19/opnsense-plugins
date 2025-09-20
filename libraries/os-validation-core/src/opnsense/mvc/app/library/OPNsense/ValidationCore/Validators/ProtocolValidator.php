<?php

/*
 * Copyright (C) 2024 OPNsense Validation Core Library
 * All rights reserved.
 */

namespace OPNsense\ValidationCore\Validators;

/**
 * Protocol Validator
 *
 * Specialized validator for protocol-specific configurations and requirements.
 * Validates protocol specifications, protocol-specific parameters, and ensures
 * compatibility between protocol choices and other configuration elements.
 *
 * This validator handles both standard network protocols and specialized
 * industrial automation protocols, providing comprehensive validation for
 * diverse network environments including SCADA, factory automation, and
 * building management systems.
 *
 * @package OPNsense\ValidationCore\Validators
 * @author Pierpaolo Casati
 * @version 1.0
 */
class ProtocolValidator extends AbstractValidator
{
    /**
     * Standard network protocols with their characteristics
     */
    private const STANDARD_PROTOCOLS = [
        'tcp' => [
            'requires_ports' => true,
            'stateful' => true,
            'description' => 'Transmission Control Protocol'
        ],
        'udp' => [
            'requires_ports' => true,
            'stateful' => false,
            'description' => 'User Datagram Protocol'
        ],
        'icmp' => [
            'requires_ports' => false,
            'stateful' => false,
            'description' => 'Internet Control Message Protocol'
        ]
    ];

    /**
     * Industrial automation protocols with their specific requirements
     */
    private const INDUSTRIAL_PROTOCOLS = [
        'modbus_tcp' => [
            'requires_ports' => true,
            'default_port' => 502,
            'stateful' => true,
            'security_level' => 'low',
            'description' => 'Modbus TCP for industrial automation'
        ],
        'dnp3' => [
            'requires_ports' => true,
            'default_port' => 20000,
            'stateful' => true,
            'security_level' => 'medium',
            'description' => 'Distributed Network Protocol for SCADA'
        ],
        'iec104' => [
            'requires_ports' => true,
            'default_port' => 2404,
            'stateful' => true,
            'security_level' => 'medium',
            'description' => 'IEC 60870-5-104 for telecontrol'
        ],
        'iec61850' => [
            'requires_ports' => true,
            'default_port' => 102,
            'stateful' => true,
            'security_level' => 'high',
            'description' => 'IEC 61850 for substation automation'
        ],
        'profinet' => [
            'requires_ports' => true,
            'default_port' => 34962,
            'stateful' => true,
            'security_level' => 'medium',
            'description' => 'PROFINET for factory automation'
        ],
        'ethercat' => [
            'requires_ports' => false,
            'stateful' => true,
            'security_level' => 'low',
            'description' => 'EtherCAT for real-time Ethernet'
        ],
        'opcua' => [
            'requires_ports' => true,
            'default_port' => 4840,
            'stateful' => true,
            'security_level' => 'high',
            'description' => 'OPC UA for industrial communication'
        ],
        'mqtt' => [
            'requires_ports' => true,
            'default_port' => 1883,
            'stateful' => true,
            'security_level' => 'medium',
            'description' => 'MQTT for IoT and telemetry'
        ],
        'bacnet' => [
            'requires_ports' => true,
            'default_port' => 47808,
            'stateful' => false,
            'security_level' => 'low',
            'description' => 'BACnet for building automation'
        ],
        's7comm' => [
            'requires_ports' => true,
            'default_port' => 102,
            'stateful' => true,
            'security_level' => 'low',
            'description' => 'Siemens S7 communication protocol'
        ]
    ];

    /**
     * Perform protocol-specific validation
     */
    protected function performValidation(): void
    {
        $this->validateGeneralProtocolSettings();
        $this->validateRuleProtocols();
        $this->validateProtocolSecurity();
        $this->validateProtocolCompatibility();
    }

    /**
     * Validate general protocol-related settings
     */
    protected function validateGeneralProtocolSettings(): void
    {
        $inspectionMode = $this->getStringValue('general.inspection_mode', 'stateless');
        
        // Validate inspection mode compatibility with protocols
        $this->validateInspectionModeCompatibility($inspectionMode);
    }

    /**
     * Validate protocols used in security rules
     */
    protected function validateRuleProtocols(): void
    {
        $rules = $this->getFieldValue('rules.rule', []);

        foreach ($rules as $uuid => $rule) {
            $this->validateRuleProtocol($rule, $uuid);
        }
    }

    /**
     * Validate security implications of protocol choices
     */
    protected function validateProtocolSecurity(): void
    {
        $rules = $this->getFieldValue('rules.rule', []);
        $securityIssues = [];

        foreach ($rules as $uuid => $rule) {
            $protocol = strtolower($rule['protocol'] ?? '');
            $action = strtolower($rule['action'] ?? '');

            if ($this->isIndustrialProtocol($protocol)) {
                $protocolInfo = self::INDUSTRIAL_PROTOCOLS[$protocol];
                
                // Check for security concerns with industrial protocols
                if ($protocolInfo['security_level'] === 'low' && $action === 'allow') {
                    $securityIssues[] = [
                        'uuid' => $uuid,
                        'protocol' => $protocol,
                        'issue' => 'low_security_protocol'
                    ];
                }
            }
        }

        $this->reportSecurityIssues($securityIssues);
    }

    /**
     * Validate protocol compatibility with system configuration
     */
    protected function validateProtocolCompatibility(): void
    {
        $inspectionMode = $this->getStringValue('general.inspection_mode', 'stateless');
        $ipsMode = $this->getBoolValue('general.ips', false);
        $rules = $this->getFieldValue('rules.rule', []);

        foreach ($rules as $uuid => $rule) {
            $protocol = strtolower($rule['protocol'] ?? '');
            
            if ($this->isIndustrialProtocol($protocol)) {
                $this->validateIndustrialProtocolCompatibility($protocol, $inspectionMode, $ipsMode, $uuid);
            }
        }
    }

    /**
     * Validate individual rule protocol specification
     *
     * @param array $rule Rule data
     * @param string $uuid Rule UUID
     */
    protected function validateRuleProtocol(array $rule, string $uuid): void
    {
        $protocol = strtolower($rule['protocol'] ?? '');
        $port = $rule['port'] ?? '';

        if (empty($protocol)) {
            return; // Already handled by RuleValidator
        }

        // Validate protocol exists and is supported
        if (!$this->isValidProtocol($protocol)) {
            return; // Already handled by RuleValidator
        }

        // Validate protocol-specific requirements
        $this->validateProtocolPortRequirements($protocol, $port, $uuid);
        $this->validateProtocolSpecificRules($protocol, $rule, $uuid);
    }

    /**
     * Validate protocol port requirements
     *
     * @param string $protocol Protocol name
     * @param string $port Port specification
     * @param string $uuid Rule UUID
     */
    protected function validateProtocolPortRequirements(string $protocol, string $port, string $uuid): void
    {
        $protocolInfo = $this->getProtocolInfo($protocol);
        
        if (!$protocolInfo) {
            return;
        }

        // Check if protocol requires ports
        if ($protocolInfo['requires_ports'] && (empty($port) || $port === 'any')) {
            $defaultPort = $protocolInfo['default_port'] ?? 'standard port';
            $this->addWarning(
                sprintf(
                    gettext('Protocol %s typically requires specific port configuration. Consider using port %s'),
                    $protocol,
                    $defaultPort
                ),
                "rules.rule.{$uuid}.port"
            );
        }

        // Check if protocol doesn't use ports but port is specified
        if (!$protocolInfo['requires_ports'] && !empty($port) && $port !== 'any') {
            $this->addWarning(
                sprintf(gettext('Protocol %s does not typically use port specifications'), $protocol),
                "rules.rule.{$uuid}.port"
            );
        }

        // Validate against default ports for industrial protocols
        if (isset($protocolInfo['default_port']) && !empty($port) && $port !== 'any') {
            $defaultPort = $protocolInfo['default_port'];
            if (!$this->portSpecificationContains($port, $defaultPort)) {
                $this->addWarning(
                    sprintf(
                        gettext('Protocol %s typically uses port %d. Current specification may not match standard usage'),
                        $protocol,
                        $defaultPort
                    ),
                    "rules.rule.{$uuid}.port"
                );
            }
        }
    }

    /**
     * Validate protocol-specific configuration rules
     *
     * @param string $protocol Protocol name
     * @param array $rule Rule data
     * @param string $uuid Rule UUID
     */
    protected function validateProtocolSpecificRules(string $protocol, array $rule, string $uuid): void
    {
        switch ($protocol) {
            case 'icmp':
                $this->validateICMPRule($rule, $uuid);
                break;
                
            case 'modbus_tcp':
                $this->validateModbusRule($rule, $uuid);
                break;
                
            case 'opcua':
                $this->validateOPCUARule($rule, $uuid);
                break;
                
            case 'mqtt':
                $this->validateMQTTRule($rule, $uuid);
                break;
                
            default:
                // Generic validation for other protocols
                break;
        }
    }

    /**
     * Validate ICMP-specific rules
     *
     * @param array $rule Rule data
     * @param string $uuid Rule UUID
     */
    protected function validateICMPRule(array $rule, string $uuid): void
    {
        $action = strtolower($rule['action'] ?? '');
        
        // ICMP blocking can interfere with network diagnostics
        if ($action === 'block') {
            $this->addWarning(
                gettext('Blocking ICMP traffic may interfere with network diagnostics and path MTU discovery'),
                "rules.rule.{$uuid}.action"
            );
        }
    }

    /**
     * Validate Modbus TCP-specific rules
     *
     * @param array $rule Rule data
     * @param string $uuid Rule UUID
     */
    protected function validateModbusRule(array $rule, string $uuid): void
    {
        $action = strtolower($rule['action'] ?? '');
        
        if ($action === 'allow') {
            $this->addWarning(
                gettext('Modbus TCP has limited built-in security. Consider additional security measures for industrial networks'),
                "rules.rule.{$uuid}.protocol"
            );
        }
    }

    /**
     * Validate OPC UA-specific rules
     *
     * @param array $rule Rule data
     * @param string $uuid Rule UUID
     */
    protected function validateOPCUARule(array $rule, string $uuid): void
    {
        $port = $rule['port'] ?? '';
        
        // OPC UA can use various ports, standard is 4840
        if (!empty($port) && $port !== 'any' && !$this->portSpecificationContains($port, 4840)) {
            $this->addWarning(
                gettext('OPC UA typically uses port 4840. Ensure the specified port matches your OPC UA server configuration'),
                "rules.rule.{$uuid}.port"
            );
        }
    }

    /**
     * Validate MQTT-specific rules
     *
     * @param array $rule Rule data
     * @param string $uuid Rule UUID
     */
    protected function validateMQTTRule(array $rule, string $uuid): void
    {
        $port = $rule['port'] ?? '';
        
        if (!empty($port) && $port !== 'any') {
            $hasStandardPort = $this->portSpecificationContains($port, 1883);
            $hasSecurePort = $this->portSpecificationContains($port, 8883);
            
            if (!$hasStandardPort && !$hasSecurePort) {
                $this->addWarning(
                    gettext('MQTT typically uses port 1883 (unencrypted) or 8883 (encrypted). Consider using standard ports'),
                    "rules.rule.{$uuid}.port"
                );
            }
            
            if ($hasStandardPort && !$hasSecurePort) {
                $this->addWarning(
                    gettext('MQTT port 1883 is unencrypted. Consider using port 8883 for secure MQTT connections'),
                    "rules.rule.{$uuid}.port"
                );
            }
        }
    }

    /**
     * Validate inspection mode compatibility with protocols
     *
     * @param string $inspectionMode Current inspection mode
     */
    protected function validateInspectionModeCompatibility(string $inspectionMode): void
    {
        $rules = $this->getFieldValue('rules.rule', []);
        $statefulProtocols = [];

        foreach ($rules as $rule) {
            $protocol = strtolower($rule['protocol'] ?? '');
            $protocolInfo = $this->getProtocolInfo($protocol);
            
            if ($protocolInfo && $protocolInfo['stateful']) {
                $statefulProtocols[] = $protocol;
            }
        }

        if (!empty($statefulProtocols) && $inspectionMode === 'stateless') {
            $this->addWarning(
                sprintf(
                    gettext('Stateless inspection mode may not be optimal for stateful protocols: %s'),
                    implode(', ', array_unique($statefulProtocols))
                ),
                'general.inspection_mode'
            );
        }
    }

    /**
     * Validate industrial protocol compatibility
     *
     * @param string $protocol Protocol name
     * @param string $inspectionMode Inspection mode
     * @param bool $ipsMode IPS mode enabled
     * @param string $uuid Rule UUID
     */
    protected function validateIndustrialProtocolCompatibility(string $protocol, string $inspectionMode, bool $ipsMode, string $uuid): void
    {
        $protocolInfo = self::INDUSTRIAL_PROTOCOLS[$protocol] ?? null;
        
        if (!$protocolInfo) {
            return;
        }

        // Real-time industrial protocols may be sensitive to IPS blocking
        if ($ipsMode && in_array($protocol, ['ethercat', 'profinet'])) {
            $this->addWarning(
                sprintf(
                    gettext('Real-time protocol %s may be sensitive to IPS blocking delays. Monitor for timing issues'),
                    $protocol
                ),
                "rules.rule.{$uuid}.protocol"
            );
        }

        // Security recommendations for industrial protocols
        if ($protocolInfo['security_level'] === 'low') {
            $this->addWarning(
                sprintf(
                    gettext('Protocol %s has limited security features. Consider network segmentation and additional security measures'),
                    $protocol
                ),
                "rules.rule.{$uuid}.protocol"
            );
        }
    }

    /**
     * Report security issues found during validation
     *
     * @param array $securityIssues Array of security issues
     */
    protected function reportSecurityIssues(array $securityIssues): void
    {
        foreach ($securityIssues as $issue) {
            switch ($issue['issue']) {
                case 'low_security_protocol':
                    $this->addWarning(
                        sprintf(
                            gettext('Allowing %s protocol which has limited security features. Ensure proper network segmentation'),
                            $issue['protocol']
                        ),
                        "rules.rule.{$issue['uuid']}.protocol"
                    );
                    break;
            }
        }
    }

    /**
     * Check if protocol is a valid supported protocol
     *
     * @param string $protocol Protocol name
     * @return bool True if valid
     */
    protected function isValidProtocol(string $protocol): bool
    {
        return isset(self::STANDARD_PROTOCOLS[$protocol]) || 
               isset(self::INDUSTRIAL_PROTOCOLS[$protocol]);
    }

    /**
     * Check if protocol is an industrial protocol
     *
     * @param string $protocol Protocol name
     * @return bool True if industrial protocol
     */
    protected function isIndustrialProtocol(string $protocol): bool
    {
        return isset(self::INDUSTRIAL_PROTOCOLS[$protocol]);
    }

    /**
     * Get protocol information
     *
     * @param string $protocol Protocol name
     * @return array|null Protocol information array
     */
    protected function getProtocolInfo(string $protocol): ?array
    {
        return self::STANDARD_PROTOCOLS[$protocol] ?? 
               self::INDUSTRIAL_PROTOCOLS[$protocol] ?? 
               null;
    }

    /**
     * Check if port specification contains specific port
     *
     * @param string $portSpec Port specification (can be ranges, lists)
     * @param int $targetPort Port to check for
     * @return bool True if port specification includes target port
     */
    protected function portSpecificationContains(string $portSpec, int $targetPort): bool
    {
        $parts = array_map('trim', explode(',', $portSpec));
        
        foreach ($parts as $part) {
            if (strpos($part, '-') !== false) {
                // Handle range
                list($start, $end) = array_map('intval', explode('-', $part, 2));
                if ($targetPort >= $start && $targetPort <= $end) {
                    return true;
                }
            } else {
                // Handle single port
                if ((int)$part === $targetPort) {
                    return true;
                }
            }
        }
        
        return false;
    }
}