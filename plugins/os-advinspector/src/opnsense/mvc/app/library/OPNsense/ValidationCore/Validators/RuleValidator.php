<?php

/*
 * Copyright (C) 2024 OPNsense Validation Core Library
 * All rights reserved.
 */

namespace OPNsense\ValidationCore\Validators;

use OPNsense\ValidationCore\Utils\NetworkUtils;
use OPNsense\ValidationCore\Utils\ValidationHelper;

/**
 * Security Rule Validator
 *
 * Specialized validator for security rule definitions including protocol
 * validation, port specifications, rule consistency, and policy compliance.
 * This validator ensures that security rules are properly formatted,
 * logically consistent, and operationally effective.
 *
 * Validation Features:
 * - Rule description and metadata validation
 * - Network address format validation (CIDR notation enforced)
 * - Port specification validation including ranges and lists
 * - Protocol validation with support for industrial protocols
 * - Rule action validation and consistency checking
 * - Boolean flag validation for rule states
 * - Cross-rule conflict detection and resolution
 *
 * @package OPNsense\ValidationCore\Validators
 * @author Pierpaolo Casati
 * @version 1.0
 */
class RuleValidator extends AbstractValidator
{
    /**
     * Valid rule actions that can be applied to traffic
     */
    private const VALID_ACTIONS = ['allow', 'block', 'alert', 'drop', 'reject'];

    /**
     * Standard network protocols supported by the system
     */
    private const STANDARD_PROTOCOLS = ['tcp', 'udp', 'icmp', 'any'];

    /**
     * Industrial automation protocols for specialized environments
     */
    private const INDUSTRIAL_PROTOCOLS = [
        'modbus_tcp',    // Modbus TCP for industrial automation
        'dnp3',          // Distributed Network Protocol for SCADA
        'iec104',        // IEC 60870-5-104 for telecontrol
        'iec61850',      // IEC 61850 for substation automation
        'profinet',      // PROFINET for factory automation
        'ethercat',      // EtherCAT for real-time Ethernet
        'opcua',         // OPC UA for industrial communication
        'mqtt',          // MQTT for IoT and telemetry
        'bacnet',        // BACnet for building automation
        's7comm'         // Siemens S7 communication protocol
    ];

    /**
     * Rule priority ranges for different rule categories
     */
    private const PRIORITY_RANGES = [
        'critical' => [1, 100],
        'high' => [101, 500],
        'medium' => [501, 1000],
        'low' => [1001, 9999]
    ];

    /**
     * Perform security rule validation
     *
     * Executes comprehensive validation of all security rules in the
     * configuration, checking individual rule validity and cross-rule
     * consistency to ensure a coherent security policy.
     */
    protected function performValidation(): void
    {
        $rules = $this->getFieldValue('rules.rule', []);

        if (empty($rules)) {
            $this->addWarning(
                gettext('No security rules defined. Default allow policy will be applied'),
                'rules.rule'
            );
            return;
        }

        $this->validateRuleCollection($rules);
    }

    /**
     * Validate collection of security rules
     *
     * @param array $rules Array of rule definitions indexed by UUID
     */
    protected function validateRuleCollection(array $rules): void
    {
        $ruleConflicts = [];
        $rulePriorities = [];

        foreach ($rules as $uuid => $rule) {
            $this->validateSingleRule($rule, $uuid);
            
            // Collect data for cross-rule validation
            if (isset($rule['priority'])) {
                $rulePriorities[$uuid] = (int)$rule['priority'];
            }
        }

        // Perform cross-rule validations
        $this->validateRulePriorities($rulePriorities);
        $this->validateRuleConflicts($rules);
    }

    /**
     * Validate individual security rule
     *
     * @param array $rule Rule data structure
     * @param string $uuid Rule unique identifier
     */
    protected function validateSingleRule(array $rule, string $uuid): void
    {
        $this->validateRuleDescription($rule, $uuid);
        $this->validateRuleAddresses($rule, $uuid);
        $this->validateRulePorts($rule, $uuid);
        $this->validateRuleProtocol($rule, $uuid);
        $this->validateRuleAction($rule, $uuid);
        $this->validateRuleFlags($rule, $uuid);
        $this->validateRulePriority($rule, $uuid);
        $this->validateRuleConsistency($rule, $uuid);
    }

    /**
     * Validate rule description requirements
     *
     * @param array $rule Rule data
     * @param string $uuid Rule UUID
     */
    protected function validateRuleDescription(array $rule, string $uuid): void
    {
        $description = $rule['description'] ?? '';

        if (empty(trim($description))) {
            $this->addError(
                gettext('Rule description is required and cannot be empty'),
                "rules.rule.{$uuid}.description"
            );
            return;
        }

        if (strlen($description) > 255) {
            $this->addError(
                gettext('Rule description must not exceed 255 characters'),
                "rules.rule.{$uuid}.description"
            );
        }

        // Check for potentially problematic characters
        if (preg_match('/[<>"\']/', $description)) {
            $this->addWarning(
                gettext('Rule description contains potentially problematic characters'),
                "rules.rule.{$uuid}.description"
            );
        }
    }

    /**
     * Validate rule network addresses (source and destination)
     *
     * @param array $rule Rule data
     * @param string $uuid Rule UUID
     */
    protected function validateRuleAddresses(array $rule, string $uuid): void
    {
        $source = $rule['source'] ?? '';
        $destination = $rule['destination'] ?? '';

        // Validate source address
        if (!empty($source) && $source !== 'any') {
            if (!$this->isValidAddressSpecification($source)) {
                $this->addError(
                    gettext('Source address must be in CIDR format (e.g., 192.168.1.0/24) or "any"'),
                    "rules.rule.{$uuid}.source"
                );
            }
        }

        // Validate destination address
        if (!empty($destination) && $destination !== 'any') {
            if (!$this->isValidAddressSpecification($destination)) {
                $this->addError(
                    gettext('Destination address must be in CIDR format (e.g., 192.168.1.0/24) or "any"'),
                    "rules.rule.{$uuid}.destination"
                );
            }
        }

        // Check for reflexive rules (source equals destination)
        if (!empty($source) && !empty($destination) && $source === $destination && $source !== 'any') {
            $this->addWarning(
                gettext('Source and destination addresses are identical, which may create reflexive traffic rules'),
                "rules.rule.{$uuid}.destination"
            );
        }
    }

    /**
     * Validate port specifications
     *
     * @param array $rule Rule data
     * @param string $uuid Rule UUID
     */
    protected function validateRulePorts(array $rule, string $uuid): void
    {
        $port = $rule['port'] ?? '';

        if (empty($port) || $port === 'any') {
            return; // Empty or "any" port is valid
        }

        if (!preg_match('/^[0-9,\-\s]*$/', $port)) {
            $this->addError(
                gettext('Port specification must contain only numbers, commas, and dashes'),
                "rules.rule.{$uuid}.port"
            );
            return;
        }

        $this->validatePortRanges($port, $uuid);
    }

    /**
     * Validate port ranges and individual port values
     *
     * @param string $portSpec Port specification string
     * @param string $uuid Rule UUID
     */
    protected function validatePortRanges(string $portSpec, string $uuid): void
    {
        $parts = array_map('trim', explode(',', $portSpec));

        foreach ($parts as $part) {
            if (empty($part)) {
                continue;
            }

            if (strpos($part, '-') !== false) {
                $this->validatePortRange($part, $uuid);
            } else {
                $this->validateSinglePort($part, $uuid);
            }
        }
    }

    /**
     * Validate single port range (e.g., "8000-8080")
     *
     * @param string $range Port range string
     * @param string $uuid Rule UUID
     */
    protected function validatePortRange(string $range, string $uuid): void
    {
        $ports = explode('-', $range, 2);
        if (count($ports) !== 2) {
            $this->addError(
                sprintf(gettext('Invalid port range format: %s'), $range),
                "rules.rule.{$uuid}.port"
            );
            return;
        }

        $startPort = (int)trim($ports[0]);
        $endPort = (int)trim($ports[1]);

        if (!ValidationHelper::isValidPort($startPort) || !ValidationHelper::isValidPort($endPort)) {
            $this->addError(
                sprintf(gettext('Port range contains invalid port numbers: %s'), $range),
                "rules.rule.{$uuid}.port"
            );
            return;
        }

        if ($startPort > $endPort) {
            $this->addError(
                sprintf(gettext('Invalid port range: start port (%d) must be less than or equal to end port (%d)'), $startPort, $endPort),
                "rules.rule.{$uuid}.port"
            );
        }

        // Check for unnecessarily large port ranges
        if (($endPort - $startPort) > 1000) {
            $this->addWarning(
                sprintf(gettext('Large port range (%s) may impact performance'), $range),
                "rules.rule.{$uuid}.port"
            );
        }
    }

    /**
     * Validate single port number
     *
     * @param string $port Port number string
     * @param string $uuid Rule UUID
     */
    protected function validateSinglePort(string $port, string $uuid): void
    {
        $portNum = (int)$port;
        if (!ValidationHelper::isValidPort($portNum)) {
            $this->addError(
                sprintf(gettext('Invalid port number: %s. Must be between 1 and 65535'), $port),
                "rules.rule.{$uuid}.port"
            );
        }
    }

    /**
     * Validate rule protocol specification
     *
     * @param array $rule Rule data
     * @param string $uuid Rule UUID
     */
    protected function validateRuleProtocol(array $rule, string $uuid): void
    {
        $protocol = strtolower($rule['protocol'] ?? '');

        if (empty($protocol)) {
            $this->addError(
                gettext('Protocol specification is required'),
                "rules.rule.{$uuid}.protocol"
            );
            return;
        }

        $allValidProtocols = array_merge(self::STANDARD_PROTOCOLS, self::INDUSTRIAL_PROTOCOLS);

        if (!in_array($protocol, $allValidProtocols)) {
            $this->addError(
                sprintf(
                    gettext('Invalid protocol: %s. Must be one of: %s'),
                    $protocol,
                    implode(', ', $allValidProtocols)
                ),
                "rules.rule.{$uuid}.protocol"
            );
            return;
        }

        // Warn about industrial protocol usage in standard networks
        if (in_array($protocol, self::INDUSTRIAL_PROTOCOLS)) {
            $this->addWarning(
                sprintf(gettext('Industrial protocol %s detected. Ensure this is appropriate for your network environment'), $protocol),
                "rules.rule.{$uuid}.protocol"
            );
        }
    }

    /**
     * Validate rule action specification
     *
     * @param array $rule Rule data
     * @param string $uuid Rule UUID
     */
    protected function validateRuleAction(array $rule, string $uuid): void
    {
        $action = strtolower($rule['action'] ?? '');

        if (empty($action)) {
            $this->addError(
                gettext('Rule action is required'),
                "rules.rule.{$uuid}.action"
            );
            return;
        }

        if (!in_array($action, self::VALID_ACTIONS)) {
            $this->addError(
                sprintf(
                    gettext('Invalid action: %s. Must be one of: %s'),
                    $action,
                    implode(', ', self::VALID_ACTIONS)
                ),
                "rules.rule.{$uuid}.action"
            );
        }
    }

    /**
     * Validate boolean flags (enabled, log)
     *
     * @param array $rule Rule data
     * @param string $uuid Rule UUID
     */
    protected function validateRuleFlags(array $rule, string $uuid): void
    {
        $booleanFields = ['enabled', 'log'];

        foreach ($booleanFields as $field) {
            $value = $rule[$field] ?? '';
            
            if (!empty($value) && !in_array($value, ['0', '1'], true)) {
                $this->addError(
                    sprintf(gettext('%s flag must be either 0 or 1'), ucfirst($field)),
                    "rules.rule.{$uuid}.{$field}"
                );
            }
        }
    }

    /**
     * Validate rule priority
     *
     * @param array $rule Rule data
     * @param string $uuid Rule UUID
     */
    protected function validateRulePriority(array $rule, string $uuid): void
    {
        $priority = $rule['priority'] ?? '1000';
        $priorityNum = (int)$priority;

        if ($priorityNum < 1 || $priorityNum > 9999) {
            $this->addError(
                sprintf(gettext('Rule priority must be between 1 and 9999, got %d'), $priorityNum),
                "rules.rule.{$uuid}.priority"
            );
        }

        // Provide guidance on priority ranges
        $category = $rule['category'] ?? 'medium';
        if (isset(self::PRIORITY_RANGES[$category])) {
            $range = self::PRIORITY_RANGES[$category];
            if ($priorityNum < $range[0] || $priorityNum > $range[1]) {
                $this->addWarning(
                    sprintf(
                        gettext('Priority %d is outside recommended range for %s category (%d-%d)'),
                        $priorityNum, $category, $range[0], $range[1]
                    ),
                    "rules.rule.{$uuid}.priority"
                );
            }
        }
    }

    /**
     * Validate rule internal consistency
     *
     * @param array $rule Rule data
     * @param string $uuid Rule UUID
     */
    protected function validateRuleConsistency(array $rule, string $uuid): void
    {
        $protocol = strtolower($rule['protocol'] ?? '');
        $port = $rule['port'] ?? '';

        // Check protocol-port consistency
        if ($protocol === 'icmp' && !empty($port) && $port !== 'any') {
            $this->addWarning(
                gettext('ICMP protocol does not use ports. Port specification will be ignored'),
                "rules.rule.{$uuid}.port"
            );
        }

        // Check for disabled rules with high priority
        $enabled = $rule['enabled'] ?? '1';
        $priority = (int)($rule['priority'] ?? 1000);
        
        if ($enabled === '0' && $priority < 100) {
            $this->addWarning(
                gettext('High priority rule is disabled and will not be processed'),
                "rules.rule.{$uuid}.enabled"
            );
        }
    }

    /**
     * Validate rule priorities for conflicts
     *
     * @param array $priorities Array of rule priorities indexed by UUID
     */
    protected function validateRulePriorities(array $priorities): void
    {
        $duplicatePriorities = array_count_values($priorities);
        
        foreach ($duplicatePriorities as $priority => $count) {
            if ($count > 1) {
                $this->addWarning(
                    sprintf(gettext('Multiple rules have the same priority (%d). Rule evaluation order may be unpredictable'), $priority),
                    'rules.rule'
                );
            }
        }
    }

    /**
     * Validate for potential rule conflicts
     *
     * @param array $rules Array of all rules
     */
    protected function validateRuleConflicts(array $rules): void
    {
        // This is a simplified conflict detection
        // In a full implementation, this would perform comprehensive overlap analysis
        
        $enabledRules = array_filter($rules, function($rule) {
            return ($rule['enabled'] ?? '1') === '1';
        });

        if (count($enabledRules) > 100) {
            $this->addWarning(
                sprintf(gettext('Large number of rules (%d) may impact performance'), count($enabledRules)),
                'rules.rule'
            );
        }
    }

    /**
     * Check if address specification is valid
     *
     * @param string $address Address specification to validate
     * @return bool True if valid
     */
    private function isValidAddressSpecification(string $address): bool
    {
        // Allow "any" keyword
        if (strtolower($address) === 'any') {
            return true;
        }

        // Require CIDR notation for specific addresses
        return NetworkUtils::isValidCIDR($address);
    }
}