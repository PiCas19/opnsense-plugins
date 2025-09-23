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

namespace OPNsense\ValidationCore;

use OPNsense\ValidationCore\Validators\NetworkValidator;
use OPNsense\ValidationCore\Validators\RuleValidator;
use OPNsense\ValidationCore\Validators\ProtocolValidator;
use OPNsense\Base\Messages\MessageCollection;

/**
 * Class ValidationEngine
 *
 * Central orchestrator for the OPNsense Validation Core library that coordinates
 * multiple specialized validators to provide comprehensive configuration validation.
 * This engine implements the Chain of Responsibility and Strategy patterns to
 * enable flexible and extensible validation workflows.
 *
 * The ValidationEngine serves as the primary entry point for validation operations,
 * managing validator registration, scope-based execution, and result aggregation.
 * It provides a clean interface for integrating validation logic into OPNsense
 * models while maintaining separation of concerns and promoting code reuse.
 *
 * Key Features:
 * - Centralized validator orchestration and management
 * - Scope-based validation for efficient partial configuration checking
 * - Dynamic validator registration for extensibility
 * - Comprehensive error aggregation and reporting
 * - Performance optimization through conditional execution
 * - Thread-safe operation for concurrent validation scenarios
 *
 * Validation Scopes:
 * - 'network': Network configuration and connectivity validation
 * - 'rules': Security rules and policy validation
 * - 'protocols': Protocol-specific validation for various network protocols
 * - 'all': Complete validation across all registered validators
 * - Custom scopes: Plugin-specific validation categories
 *
 * @package OPNsense\ValidationCore
 * @author Pierpaolo Casati
 * @version 1.0
 */
class ValidationEngine
{
    /**
     * Registry of available validators indexed by name
     *
     * @var array<string, AbstractValidator> Validator instances
     */
    private $validators = [];

    /**
     * Mapping of validation scopes to their corresponding validators
     *
     * @var array<string, array<string>> Scope to validator name mappings
     */
    private $scopeMapping = [];

    /**
     * Validation execution statistics for performance monitoring
     *
     * @var array<string, mixed> Performance metrics
     */
    private $executionStats = [];

    /**
     * Initialize ValidationEngine with default validators
     *
     * Sets up the validation engine with core validators and establishes
     * default scope mappings for common validation scenarios. The engine
     * is designed to be immediately usable while remaining extensible
     * for custom validation requirements.
     */
    public function __construct()
    {
        $this->initializeExecutionStats();
        $this->registerDefaultValidators();
        $this->configureScopeMappings();
    }

    /**
     * Execute validation process with scope-based validator selection
     *
     * Orchestrates the validation process by selecting appropriate validators
     * based on the specified scope and executing them against the provided
     * configuration data. Results from all validators are aggregated into
     * a unified message collection for comprehensive error reporting.
     *
     * The validation process follows these steps:
     * 1. Determine validators to execute based on scope
     * 2. Execute each validator against the configuration data
     * 3. Aggregate validation messages from all validators
     * 4. Update execution statistics for performance monitoring
     * 5. Return comprehensive validation results
     *
     * @param array $configurationData Configuration data to validate
     * @param bool $validateFullModel Whether to perform full model validation
     * @param string $scope Validation scope to control validator selection
     *
     * @return MessageCollection Aggregated validation messages from all validators
     *
     * @throws \InvalidArgumentException When validation scope is not recognized
     * @throws \RuntimeException When validator execution fails critically
     *
     * @example
     * // Validate network configuration only
     * $messages = $engine->validate($config, false, 'network');
     *
     * @example
     * // Full validation across all validators
     * $messages = $engine->validate($config, true, 'all');
     */
    public function validate(array $configurationData, bool $validateFullModel = false, string $scope = 'all'): MessageCollection
    {
        $startTime = microtime(true);
        $allMessages = new MessageCollection();

        try {
            // Determine which validators to execute based on scope
            $validatorsToExecute = $this->getValidatorsForScope($scope);

            if (empty($validatorsToExecute)) {
                throw new \InvalidArgumentException("Unknown validation scope: {$scope}");
            }

            // Execute each validator and aggregate results
            foreach ($validatorsToExecute as $validatorName => $validator) {
                $validatorStartTime = microtime(true);

                try {
                    $validatorMessages = $validator->validate($configurationData, $validateFullModel);
                    
                    // Merge validator messages into main collection
                    foreach ($validatorMessages as $message) {
                        $allMessages->appendMessage($message);
                    }

                    // Track validator execution time
                    $this->updateValidatorStats($validatorName, microtime(true) - $validatorStartTime, true);

                } catch (\Exception $e) {
                    // Log validator-specific errors but continue with other validators
                    error_log("ValidationCore: Validator '{$validatorName}' failed: " . $e->getMessage());
                    $this->updateValidatorStats($validatorName, microtime(true) - $validatorStartTime, false);
                }
            }

            // Update overall execution statistics
            $this->executionStats['total_executions']++;
            $this->executionStats['total_execution_time'] += microtime(true) - $startTime;

        } catch (\Exception $e) {
            $this->executionStats['execution_errors']++;
            throw new \RuntimeException("Validation engine execution failed: " . $e->getMessage());
        }

        return $allMessages;
    }

    /**
     * Register a new validator with the validation engine
     *
     * Allows dynamic registration of custom validators for specialized validation
     * requirements. Registered validators can be assigned to specific scopes
     * and will be automatically included in validation workflows.
     *
     * @param string $name Unique identifier for the validator
     * @param AbstractValidator $validator Validator instance to register
     * @param array $scopes Optional list of scopes to associate with this validator
     *
     * @throws \InvalidArgumentException When validator name already exists
     * @throws \TypeError When validator is not of correct type
     *
     * @example
     * // Register custom compliance validator
     * $engine->registerValidator('compliance', new ComplianceValidator(), ['security', 'audit']);
     */
    public function registerValidator(string $name, $validator, array $scopes = []): void
    {
        if (isset($this->validators[$name])) {
            throw new \InvalidArgumentException("Validator '{$name}' is already registered");
        }

        if (!($validator instanceof \OPNsense\ValidationCore\Validators\AbstractValidator)) {
            throw new \TypeError("Validator must extend AbstractValidator");
        }

        $this->validators[$name] = $validator;

        // Associate validator with specified scopes
        foreach ($scopes as $scope) {
            if (!isset($this->scopeMapping[$scope])) {
                $this->scopeMapping[$scope] = [];
            }
            $this->scopeMapping[$scope][] = $name;
        }

        // Initialize statistics for new validator
        $this->executionStats['validators'][$name] = [
            'executions' => 0,
            'total_time' => 0.0,
            'errors' => 0
        ];
    }

    /**
     * Remove a registered validator from the engine
     *
     * @param string $name Name of validator to unregister
     * @return bool True if validator was removed, false if not found
     */
    public function unregisterValidator(string $name): bool
    {
        if (!isset($this->validators[$name])) {
            return false;
        }

        unset($this->validators[$name]);

        // Remove from scope mappings
        foreach ($this->scopeMapping as $scope => $validatorNames) {
            $this->scopeMapping[$scope] = array_filter($validatorNames, function($validatorName) use ($name) {
                return $validatorName !== $name;
            });
        }

        // Remove statistics
        unset($this->executionStats['validators'][$name]);

        return true;
    }

    /**
     * Get list of registered validators
     *
     * @return array<string> List of validator names
     */
    public function getRegisteredValidators(): array
    {
        return array_keys($this->validators);
    }

    /**
     * Get validation execution statistics for performance monitoring
     *
     * @return array<string, mixed> Comprehensive execution metrics
     */
    public function getExecutionStatistics(): array
    {
        $stats = $this->executionStats;
        
        // Calculate average execution time
        if ($stats['total_executions'] > 0) {
            $stats['average_execution_time'] = $stats['total_execution_time'] / $stats['total_executions'];
        } else {
            $stats['average_execution_time'] = 0.0;
        }

        return $stats;
    }

    /**
     * Initialize default validators for common validation scenarios
     *
     * Sets up core validators that provide comprehensive validation coverage
     * for typical OPNsense configuration scenarios. These validators form
     * the foundation of the validation system and can be supplemented with
     * custom validators as needed.
     */
    private function registerDefaultValidators(): void
    {
        // Register network configuration validator
        $this->validators['network'] = new NetworkValidator();
        
        // Register security rules validator
        $this->validators['rules'] = new RuleValidator();
        
        // Register protocol-specific validator
        $this->validators['protocols'] = new ProtocolValidator();

        // Initialize execution statistics for default validators
        foreach ($this->validators as $name => $validator) {
            $this->executionStats['validators'][$name] = [
                'executions' => 0,
                'total_time' => 0.0,
                'errors' => 0
            ];
        }
    }

    /**
     * Configure default scope mappings for validator selection
     *
     * Establishes the relationship between validation scopes and their
     * corresponding validators, enabling efficient scope-based validation
     * workflows while maintaining flexibility for custom configurations.
     */
    private function configureScopeMappings(): void
    {
        $this->scopeMapping = [
            'general' => ['network'],
            'network' => ['network'],
            'rules' => ['rules', 'protocols'],
            'protocols' => ['protocols'],
            'security' => ['rules', 'protocols'],
            'all' => ['network', 'rules', 'protocols']
        ];
    }

    /**
     * Determine validators to execute based on validation scope
     *
     * @param string $scope Validation scope identifier
     * @return array<string, AbstractValidator> Validators to execute
     */
    private function getValidatorsForScope(string $scope): array
    {
        $validatorsToExecute = [];

        if (!isset($this->scopeMapping[$scope])) {
            // If scope is not predefined, treat it as a validator name
            if (isset($this->validators[$scope])) {
                $validatorsToExecute[$scope] = $this->validators[$scope];
            }
        } else {
            // Get validators mapped to the scope
            foreach ($this->scopeMapping[$scope] as $validatorName) {
                if (isset($this->validators[$validatorName])) {
                    $validatorsToExecute[$validatorName] = $this->validators[$validatorName];
                }
            }
        }

        return $validatorsToExecute;
    }

    /**
     * Initialize execution statistics tracking
     */
    private function initializeExecutionStats(): void
    {
        $this->executionStats = [
            'total_executions' => 0,
            'total_execution_time' => 0.0,
            'execution_errors' => 0,
            'validators' => []
        ];
    }

    /**
     * Update validator-specific execution statistics
     *
     * @param string $validatorName Name of validator
     * @param float $executionTime Time taken for execution
     * @param bool $success Whether execution was successful
     */
    private function updateValidatorStats(string $validatorName, float $executionTime, bool $success): void
    {
        if (!isset($this->executionStats['validators'][$validatorName])) {
            $this->executionStats['validators'][$validatorName] = [
                'executions' => 0,
                'total_time' => 0.0,
                'errors' => 0
            ];
        }

        $this->executionStats['validators'][$validatorName]['executions']++;
        $this->executionStats['validators'][$validatorName]['total_time'] += $executionTime;

        if (!$success) {
            $this->executionStats['validators'][$validatorName]['errors']++;
        }
    }
}