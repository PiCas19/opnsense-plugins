<?php
/*
 * Copyright (C) 2025 OPNsense Validation Core Library
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

namespace OPNsense\ValidationCore\Validators;

/**
 * ProtocolValidator
 *
 * Specialized validator for DeepInspector protocol-specific configurations.
 * Validates protocol inspection settings, ensuring compatibility with general
 * settings (e.g., SSL inspection) and proper configuration of protocol-specific
 * parameters, including standard and industrial protocols.
 *
 * @package OPNsense\ValidationCore\Validators
 * @author Pierpaolo Casati
 * @version 1.1
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
     * Perform protocol validation
     * 
     * @throws \Exception When validation logic encounters critical errors
     */
    protected function performValidation(): void
    {
        $general = $this->data['general'] ?? [];
        $protocols = $this->data['protocols'] ?? [];
        $fieldChanges = $protocols['_field_changes'] ?? [];
        $generalFieldChanges = $general['_field_changes'] ?? [];

        // Validate protocol inspection settings
        if ($this->validateFullModel || ($generalFieldChanges['ssl_inspection'] ?? false) || ($fieldChanges['https_inspection'] ?? false)) {
            $sslEnabled = $general['ssl_inspection'] === "1";
            $httpsEnabled = $protocols['https_inspection'] === "1";

            if ($httpsEnabled && !$sslEnabled) {
                $this->addError(
                    'SSL inspection must be enabled for HTTPS protocol inspection.',
                    'protocols.https_inspection'
                );
            }
        }

        // Validate boolean protocol inspection fields
        $inspectionFields = [
            'http_inspection', 'https_inspection', 'ftp_inspection',
            'smtp_inspection', 'dns_inspection', 'industrial_protocols',
            'p2p_detection', 'voip_inspection'
        ];

        foreach ($inspectionFields as $field) {
            if ($this->validateFullModel || ($fieldChanges[$field] ?? false)) {
                if (!in_array($protocols[$field] ?? '', ['0', '1', ''])) {
                    $this->addError(
                        sprintf('Field %s must be either 0 or 1.', $field),
                        "protocols.$field"
                    );
                }
            }
        }

        // Validate custom_protocols
        if ($this->validateFullModel || ($fieldChanges['custom_protocols'] ?? false)) {
            $customProtocols = $protocols['custom_protocols'] ?? '';
            if (!empty($customProtocols) && !preg_match('/^[a-zA-Z0-9_,-\s]*$/', $customProtocols)) {
                $this->addError(
                    'Custom protocols must contain only alphanumeric characters, commas, dashes, and spaces.',
                    'protocols.custom_protocols'
                );
            }
        }

        // Validate industrial_protocols specific settings
        if ($this->validateFullModel || ($fieldChanges['industrial_protocols'] ?? false)) {
            if ($protocols['industrial_protocols'] === "1") {
                $this->validateIndustrialProtocols($protocols, $general);
            }
        }

        // Validate rule-specific protocols if rules are provided
        if (isset($this->data['rules']['rule']) && ($this->validateFullModel || ($fieldChanges['rules'] ?? false))) {
            $this->validateRuleProtocols($this->data['rules']['rule']);
        }

        // Additional validations
        $this->validateProtocolSecurity();
        $this->validateProtocolCompatibility();
    }

    /**
     * Validate industrial protocols configuration
     *
     * @param array $protocols Protocols configuration
     * @param array $general General configuration
     */
    private function validateIndustrialProtocols(array $protocols, array $general): void
    {
        $inspectionMode = $general['inspection_mode'] ?? 'stateless';
        $enabledIndustrial = $protocols['industrial_protocols'] === "1";

        if ($enabledIndustrial && $inspectionMode === 'stateless') {
            $statefulProtocols = array_filter(self::INDUSTRIAL_PROTOCOLS, fn($p) => $p['stateful']);
            $protocolNames = array_keys($statefulProtocols);
            if (!empty($protocolNames)) {
                $this->addWarning(
                    sprintf(
                        'Stateless inspection mode may not be optimal for stateful industrial protocols: %s',
                        implode(', ', $protocolNames)
                    ),
                    'general.inspection_mode'
                );
            }
        }

        // Check for low-security industrial protocols
        $lowSecurityProtocols = array_filter(self::INDUSTRIAL_PROTOCOLS, fn($p) => $p['security_level'] === 'low');
        if ($enabledIndustrial && !empty($lowSecurityProtocols)) {
            $this->addWarning(
                sprintf(
                    'Enabling industrial protocols includes low-security protocols (%s). Consider additional security measures.',
                    implode(', ', array_keys($lowSecurityProtocols))
                ),
                'protocols.industrial_protocols'
            );
        }
    }

    /**
     * Validate protocols used in security rules
     *
     * @param array $rules Security rules
     */
    protected function validateRuleProtocols(array $rules): void
    {
        foreach ($rules as $uuid => $rule) {
            $this->validateRuleProtocol($rule, $uuid);
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
            return; // Handled by RuleValidator
        }

        if (!$this->isValidProtocol($protocol)) {
            return; // Handled by RuleValidator
        }

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

        if ($protocolInfo['requires_ports'] && (empty($port) || $port === 'any')) {
            $defaultPort = $protocolInfo['default_port'] ?? 'standard port';
            $this->addWarning(
                sprintf(
                    'Protocol %s typically requires specific port configuration. Consider using port %s',
                    $protocol,
                    $defaultPort
                ),
                "rules.rule.{$uuid}.port"
            );
        }

        if (!$protocolInfo['requires_ports'] && !empty($port) && $port !== 'any') {
            $this->addWarning(
                sprintf('Protocol %s does not typically use port specifications', $protocol),
                "rules.rule.{$uuid}.port"
            );
        }

        if (isset($protocolInfo['default_port']) && !empty($port) && $port !== 'any') {
            $defaultPort = $protocolInfo['default_port'];
            if (!$this->portSpecificationContains($port, $defaultPort)) {
                $this->addWarning(
                    sprintf(
                        'Protocol %s typically uses port %d. Current specification may not match standard usage',
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
        
        if ($action === 'block') {
            $this->addWarning(
                'Blocking ICMP traffic may interfere with network diagnostics and path MTU discovery',
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
                'Modbus TCP has limited built-in security. Consider additional security measures for industrial networks',
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
        
        if (!empty($port) && $port !== 'any' && !$this->portSpecificationContains($port, 4840)) {
            $this->addWarning(
                'OPC UA typically uses port 4840. Ensure the specified port matches your OPC UA server configuration',
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
                    'MQTT typically uses port 1883 (unencrypted) or 8883 (encrypted). Consider using standard ports',
                    "rules.rule.{$uuid}.port"
                );
            }
            
            if ($hasStandardPort && !$hasSecurePort) {
                $this->addWarning(
                    'MQTT port 1883 is unencrypted. Consider using port 8883 for secure MQTT connections',
                    "rules.rule.{$uuid}.port"
                );
            }
        }
    }

    /**
     * Validate protocol security implications
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

        if ($ipsMode && in_array($protocol, ['ethercat', 'profinet'])) {
            $this->addWarning(
                sprintf(
                    'Real-time protocol %s may be sensitive to IPS blocking delays. Monitor for timing issues',
                    $protocol
                ),
                "rules.rule.{$uuid}.protocol"
            );
        }

        if ($protocolInfo['security_level'] === 'low') {
            $this->addWarning(
                sprintf(
                    'Protocol %s has limited security features. Consider network segmentation and additional security measures',
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
                            'Allowing %s protocol which has limited security features. Ensure proper network segmentation',
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
                list($start, $end) = array_map('intval', explode('-', $part, 2));
                if ($targetPort >= $start && $targetPort <= $end) {
                    return true;
                }
            } else {
                if ((int)$part === $targetPort) {
                    return true;
                }
            }
        }
        
        return false;
    }
}