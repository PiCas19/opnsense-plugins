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
 *
 * @package OPNsense\ValidationCore\Validators
 * @author Pierpaolo Casati
 * @version 1.0
 */
class RuleValidator extends AbstractValidator
{
    private const VALID_ACTIONS = ['allow', 'block', 'alert', 'drop', 'reject'];
    private const STANDARD_PROTOCOLS = ['tcp', 'udp', 'icmp', 'any'];
    private const INDUSTRIAL_PROTOCOLS = [
        'modbus_tcp', 'dnp3', 'iec104', 'iec61850', 'profinet',
        'ethercat', 'opcua', 'mqtt', 'bacnet', 's7comm'
    ];
    private const PRIORITY_RANGES = [
        'critical' => [1, 100],
        'high' => [101, 500],
        'medium' => [501, 1000],
        'low' => [1001, 9999]
    ];

    /**
     * Perform security rule validation
     */
    protected function performValidation(): void
    {
        $rules = $this->getFieldValue('rules.rule', []);

        if (empty($rules)) {
            $this->addWarning(
                'No security rules defined. Default allow policy will be applied',
                'rules.rule'
            );
            return;
        }

        $this->validateRuleCollection($rules);
    }

    /**
     * Validate collection of security rules
     */
    protected function validateRuleCollection(array $rules): void
    {
        $rulePriorities = [];

        foreach ($rules as $uuid => $rule) {
            $this->validateSingleRule($rule, $uuid);
            
            if (isset($rule['priority'])) {
                $rulePriorities[$uuid] = (int)$rule['priority'];
            }
        }

        $this->validateRulePriorities($rulePriorities);
        $this->validateRuleConflicts($rules);
    }

    /**
     * Validate individual security rule
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
     * Validate rule description
     */
    protected function validateRuleDescription(array $rule, string $uuid): void
    {
        $description = $rule['description'] ?? '';

        if (empty(trim($description))) {
            $this->addError(
                'Rule description is required and cannot be empty',
                "rules.rule.{$uuid}.description"
            );
            return;
        }

        if (strlen($description) > 255) {
            $this->addError(
                'Rule description must not exceed 255 characters',
                "rules.rule.{$uuid}.description"
            );
        }

        if (preg_match('/[<>"\']/', $description)) {
            $this->addWarning(
                'Rule description contains potentially problematic characters',
                "rules.rule.{$uuid}.description"
            );
        }
    }

    /**
     * Validate rule addresses
     */
    protected function validateRuleAddresses(array $rule, string $uuid): void
    {
        $source = $rule['source'] ?? '';
        $destination = $rule['destination'] ?? '';

        if (!empty($source) && $source !== 'any') {
            if (!$this->isValidAddressSpecification($source)) {
                $this->addError(
                    'Source address must be in CIDR format (e.g., 192.168.1.0/24) or "any"',
                    "rules.rule.{$uuid}.source"
                );
            }
        }

        if (!empty($destination) && $destination !== 'any') {
            if (!$this->isValidAddressSpecification($destination)) {
                $this->addError(
                    'Destination address must be in CIDR format (e.g., 192.168.1.0/24) or "any"',
                    "rules.rule.{$uuid}.destination"
                );
            }
        }

        if (!empty($source) && !empty($destination) && $source === $destination && $source !== 'any') {
            $this->addWarning(
                'Source and destination addresses are identical, which may create reflexive traffic rules',
                "rules.rule.{$uuid}.destination"
            );
        }
    }

    /**
     * Validate port specifications
     */
    protected function validateRulePorts(array $rule, string $uuid): void
    {
        $port = $rule['port'] ?? '';

        if (empty($port) || $port === 'any') {
            return;
        }

        if (!preg_match('/^[0-9,\-\s]*$/', $port)) {
            $this->addError(
                'Port specification must contain only numbers, commas, and dashes',
                "rules.rule.{$uuid}.port"
            );
            return;
        }

        $this->validatePortRanges($port, $uuid);
    }

    /**
     * Validate port ranges
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
     * Validate single port range
     */
    protected function validatePortRange(string $range, string $uuid): void
    {
        $ports = explode('-', $range, 2);
        if (count($ports) !== 2) {
            $this->addError(
                sprintf('Invalid port range format: %s', $range),
                "rules.rule.{$uuid}.port"
            );
            return;
        }

        $startPort = (int)trim($ports[0]);
        $endPort = (int)trim($ports[1]);

        if (!ValidationHelper::isValidPort($startPort) || !ValidationHelper::isValidPort($endPort)) {
            $this->addError(
                sprintf('Port range contains invalid port numbers: %s', $range),
                "rules.rule.{$uuid}.port"
            );
            return;
        }

        if ($startPort > $endPort) {
            $this->addError(
                sprintf('Invalid port range: start port (%d) must be less than or equal to end port (%d)', $startPort, $endPort),
                "rules.rule.{$uuid}.port"
            );
        }

        if (($endPort - $startPort) > 1000) {
            $this->addWarning(
                sprintf('Large port range (%s) may impact performance', $range),
                "rules.rule.{$uuid}.port"
            );
        }
    }

    /**
     * Validate single port
     */
    protected function validateSinglePort(string $port, string $uuid): void
    {
        $portNum = (int)$port;
        if (!ValidationHelper::isValidPort($portNum)) {
            $this->addError(
                sprintf('Invalid port number: %s. Must be between 1 and 65535', $port),
                "rules.rule.{$uuid}.port"
            );
        }
    }

    /**
     * Validate rule protocol
     */
    protected function validateRuleProtocol(array $rule, string $uuid): void
    {
        $protocol = strtolower($rule['protocol'] ?? '');

        if (empty($protocol)) {
            $this->addError(
                'Protocol specification is required',
                "rules.rule.{$uuid}.protocol"
            );
            return;
        }

        $allValidProtocols = array_merge(self::STANDARD_PROTOCOLS, self::INDUSTRIAL_PROTOCOLS);

        if (!in_array($protocol, $allValidProtocols)) {
            $this->addError(
                sprintf('Invalid protocol: %s. Must be one of: %s', $protocol, implode(', ', $allValidProtocols)),
                "rules.rule.{$uuid}.protocol"
            );
            return;
        }

        if (in_array($protocol, self::INDUSTRIAL_PROTOCOLS)) {
            $this->addWarning(
                sprintf('Industrial protocol %s detected. Ensure this is appropriate for your network environment', $protocol),
                "rules.rule.{$uuid}.protocol"
            );
        }
    }

    /**
     * Validate rule action
     */
    protected function validateRuleAction(array $rule, string $uuid): void
    {
        $action = strtolower($rule['action'] ?? '');

        if (empty($action)) {
            $this->addError(
                'Rule action is required',
                "rules.rule.{$uuid}.action"
            );
            return;
        }

        if (!in_array($action, self::VALID_ACTIONS)) {
            $this->addError(
                sprintf('Invalid action: %s. Must be one of: %s', $action, implode(', ', self::VALID_ACTIONS)),
                "rules.rule.{$uuid}.action"
            );
        }
    }

    /**
     * Validate boolean flags
     */
    protected function validateRuleFlags(array $rule, string $uuid): void
    {
        $booleanFields = ['enabled', 'log'];

        foreach ($booleanFields as $field) {
            $value = $rule[$field] ?? '';
            
            if (!empty($value) && !in_array($value, ['0', '1'], true)) {
                $this->addError(
                    sprintf('%s flag must be either 0 or 1', ucfirst($field)),
                    "rules.rule.{$uuid}.{$field}"
                );
            }
        }
    }

    /**
     * Validate rule priority
     */
    protected function validateRulePriority(array $rule, string $uuid): void
    {
        $priority = $rule['priority'] ?? '1000';
        $priorityNum = (int)$priority;

        if ($priorityNum < 1 || $priorityNum > 9999) {
            $this->addError(
                sprintf('Rule priority must be between 1 and 9999, got %d', $priorityNum),
                "rules.rule.{$uuid}.priority"
            );
        }

        $category = $rule['category'] ?? 'medium';
        if (isset(self::PRIORITY_RANGES[$category])) {
            $range = self::PRIORITY_RANGES[$category];
            if ($priorityNum < $range[0] || $priorityNum > $range[1]) {
                $this->addWarning(
                    sprintf('Priority %d is outside recommended range for %s category (%d-%d)', $priorityNum, $category, $range[0], $range[1]),
                    "rules.rule.{$uuid}.priority"
                );
            }
        }
    }

    /**
     * Validate rule consistency
     */
    protected function validateRuleConsistency(array $rule, string $uuid): void
    {
        $protocol = strtolower($rule['protocol'] ?? '');
        $port = $rule['port'] ?? '';

        if ($protocol === 'icmp' && !empty($port) && $port !== 'any') {
            $this->addWarning(
                'ICMP protocol does not use ports. Port specification will be ignored',
                "rules.rule.{$uuid}.port"
            );
        }

        $enabled = $rule['enabled'] ?? '1';
        $priority = (int)($rule['priority'] ?? 1000);
        
        if ($enabled === '0' && $priority < 100) {
            $this->addWarning(
                'High priority rule is disabled and will not be processed',
                "rules.rule.{$uuid}.enabled"
            );
        }
    }

    /**
     * Validate rule priorities
     */
    protected function validateRulePriorities(array $priorities): void
    {
        $duplicatePriorities = array_count_values($priorities);
        
        foreach ($duplicatePriorities as $priority => $count) {
            if ($count > 1) {
                $this->addWarning(
                    sprintf('Multiple rules have the same priority (%d). Rule evaluation order may be unpredictable', $priority),
                    'rules.rule'
                );
            }
        }
    }

    /**
     * Validate rule conflicts
     */
    protected function validateRuleConflicts(array $rules): void
    {
        $enabledRules = array_filter($rules, function($rule) {
            return ($rule['enabled'] ?? '1') === '1';
        });

        if (count($enabledRules) > 100) {
            $this->addWarning(
                sprintf('Large number of rules (%d) may impact performance', count($enabledRules)),
                'rules.rule'
            );
        }
    }

    /**
     * Check if address specification is valid
     */
    private function isValidAddressSpecification(string $address): bool
    {
        if (strtolower($address) === 'any') {
            return true;
        }

        return NetworkUtils::isValidCIDR($address);
    }
}