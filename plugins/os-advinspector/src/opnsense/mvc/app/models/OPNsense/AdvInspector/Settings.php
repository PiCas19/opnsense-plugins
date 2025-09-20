<?php

/*
 * Copyright (C) 2024 Advanced Network Inspector
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

namespace OPNsense\AdvInspector;

use OPNsense\Base\BaseModel;
use OPNsense\ValidationCore\ValidationEngine;
use OPNsense\Base\Messages\Message;

/**
 * Class Settings
 *
 * Configuration model for the Advanced Network Inspector that implements clean
 * validation architecture using the ValidationCore library. This model serves as the
 * data layer for system configuration while delegating validation logic to
 * specialized validator classes for maintainability and extensibility.
 *
 * The model integrates with the OPNsense framework for configuration persistence
 * while providing advanced validation capabilities through a dedicated validation
 * engine that orchestrates multiple domain-specific validators.
 *
 * Architecture Benefits:
 * - Clean separation between data model and validation logic
 * - Modular validation system that can be extended independently
 * - Improved testability through isolated validation components
 * - Reusable validation logic across different contexts
 * - Centralized validation orchestration with scope support
 *
 * Validation Capabilities:
 * - Scoped validation for efficient partial configuration checking
 * - Field change detection for optimized incremental validation
 * - Multi-domain validation (network, security rules, protocols)
 * - Industrial protocol support with specialized validation
 * - Comprehensive error reporting with field-specific feedback
 *
 * @package OPNsense\AdvInspector
 * @author Pierpaolo Casati
 * @version 1.0
 */
class Settings extends BaseModel
{
    /**
     * Validation engine instance for orchestrating validation logic
     *
     * @var ValidationEngine Centralized validation coordinator
     */
    private $validationEngine;

    /**
     * Initialize the Settings model and validation engine
     *
     * Sets up the model with the OPNsense framework integration and
     * initializes the validation engine with all required validators
     * for comprehensive configuration validation.
     */
    public function __construct()
    {
        // Initialize parent BaseModel for OPNsense framework integration
        parent::__construct();
        
        // Initialize validation engine with registered validators
        $this->validationEngine = new ValidationEngine();
    }

    /**
     * Perform comprehensive configuration validation using the ValidationCore library
     *
     * This method implements a clean validation architecture by delegating
     * validation logic to specialized validator classes while maintaining
     * integration with the OPNsense validation framework. The validation
     * engine orchestrates multiple validators based on the specified scope.
     *
     * The validation process follows these steps:
     * 1. Execute base model validation from OPNsense framework
     * 2. Convert model data to array format for validator consumption
     * 3. Execute domain-specific validators based on scope
     * 4. Merge validation results from all sources
     * 5. Return comprehensive validation message collection
     *
     * Validation Scopes:
     * - 'general': Validates core system settings and operational parameters
     * - 'network': Validates network configuration and connectivity
     * - 'rules': Validates security rule definitions and consistency
     * - 'protocols': Validates protocol-specific configurations
     * - 'all': Performs complete validation of all configuration sections
     *
     * @param bool $validateFullModel Whether to validate entire model or only changed fields
     * @param string $scope Validation scope to control which validators are executed
     *
     * @return \OPNsense\Base\Messages\MessageCollection Complete validation results
     *
     * @throws \RuntimeException When validation engine initialization fails
     * @throws \InvalidArgumentException When validation scope is not recognized
     *
     * @example
     * // Validate only general settings after user changes interface configuration
     * $messages = $model->performValidation(false, 'general');
     * if ($messages->hasErrors()) {
     *     // Handle validation errors in UI
     * }
     *
     * @example
     * // Full model validation before applying configuration changes
     * $messages = $model->performValidation(true, 'all');
     * if (!$messages->hasErrors()) {
     *     $model->serializeToConfig();
     *     Config::getInstance()->save();
     * }
     */
    public function performValidation($validateFullModel = false, $scope = 'all')
    {
        // Execute base model validation from OPNsense framework
        // This handles basic field type validation and framework-level constraints
        $messages = parent::performValidation($validateFullModel);

        try {
            // Convert OPNsense model data to array format for validator consumption
            // This transformation allows validators to work with clean data structures
            $configurationData = $this->extractConfigurationData();

            // Execute validation engine with specified scope and parameters
            // The engine coordinates multiple validators and aggregates results
            $validationMessages = $this->validationEngine->validate(
                $configurationData,
                $validateFullModel,
                $scope
            );

            // Merge validation results from custom validators with base validation
            // This ensures comprehensive validation coverage from all sources
            foreach ($validationMessages as $validationMessage) {
                $messages->appendMessage($validationMessage);
            }

        } catch (\Exception $e) {
            // Handle validation engine errors gracefully
            // Log error for debugging while providing user-friendly feedback
            error_log("AdvInspector validation engine error: " . $e->getMessage());
            
            $messages->appendMessage(new Message(
                gettext('Internal validation error occurred. Please check configuration and try again.'),
                'general.validation_engine'
            ));
        }

        return $messages;
    }

    /**
     * Extract configuration data from OPNsense model for validator consumption
     *
     * Transforms the OPNsense model structure into a clean array format that
     * validators can process efficiently. This method handles the complexity
     * of extracting data from the OPNsense model framework while providing
     * validators with a consistent and predictable data structure.
     *
     * The extraction process includes:
     * - Converting model fields to appropriate data types
     * - Handling empty and null values consistently
     * - Extracting nested rule structures with proper UUID mapping
     * - Preserving field change tracking information for incremental validation
     *
     * @return array Structured configuration data for validation
     *
     * @throws \RuntimeException When model data extraction fails
     */
    private function extractConfigurationData(): array
    {
        try {
            return [
                // General system configuration section
                'general' => [
                    'enabled' => (string)$this->general->enabled,
                    'interfaces' => (string)$this->general->interfaces,
                    'homenet' => (string)$this->general->homenet,
                    'inspection_mode' => (string)$this->general->inspection_mode,
                    'verbosity' => (string)$this->general->verbosity,
                    'promisc' => (string)$this->general->promisc,
                    'ips' => (string)$this->general->ips,
                    // Track field changes for incremental validation
                    '_field_changes' => $this->extractFieldChanges()
                ],
                
                // Security rules configuration section
                'rules' => [
                    'rule' => $this->extractSecurityRules()
                ]
            ];

        } catch (\Exception $e) {
            throw new \RuntimeException(
                'Failed to extract configuration data for validation: ' . $e->getMessage()
            );
        }
    }

    /**
     * Extract field change information for incremental validation
     *
     * @return array Field change tracking data
     */
    private function extractFieldChanges(): array
    {
        $changes = [];
        
        try {
            // Check if methods exist before calling them
            if (method_exists($this->general->enabled, 'isFieldChanged')) {
                $changes['enabled'] = $this->general->enabled->isFieldChanged();
            }
            if (method_exists($this->general->interfaces, 'isFieldChanged')) {
                $changes['interfaces'] = $this->general->interfaces->isFieldChanged();
            }
            if (method_exists($this->general->homenet, 'isFieldChanged')) {
                $changes['homenet'] = $this->general->homenet->isFieldChanged();
            }
            if (method_exists($this->general->inspection_mode, 'isFieldChanged')) {
                $changes['inspection_mode'] = $this->general->inspection_mode->isFieldChanged();
            }
            if (method_exists($this->general->ips, 'isFieldChanged')) {
                $changes['ips'] = $this->general->ips->isFieldChanged();
            }
        } catch (\Exception $e) {
            // If field change detection fails, assume all fields changed
            error_log("Field change detection failed: " . $e->getMessage());
        }
        
        return $changes;
    }

    /**
     * Extract security rules data with proper UUID mapping and validation context
     *
     * Processes the complex rule structure from the OPNsense model and converts
     * it into a format suitable for validation. Each rule is extracted with its
     * UUID for proper error reporting and field mapping.
     *
     * Rule Extraction Features:
     * - Preserves rule UUIDs for accurate error reporting
     * - Converts all field values to strings for consistent validation
     * - Handles missing or empty rule fields gracefully
     * - Maintains rule order for priority-based validation
     *
     * @return array Structured rules data indexed by UUID
     *
     * @throws \RuntimeException When rule data extraction fails
     */
    private function extractSecurityRules(): array
    {
        $extractedRules = [];

        try {
            // Check if rules exist and are iterable
            if (!isset($this->rules) || !isset($this->rules->rule)) {
                return $extractedRules;
            }

            // Iterate through all configured security rules
            foreach ($this->rules->rule->iterateItems() as $ruleModel) {
                // Extract or generate UUID for error reporting
                $attributes = $ruleModel->getAttributes();
                $ruleUuid = isset($attributes["uuid"]) ? $attributes["uuid"] : uniqid('rule_');

                // Extract all rule fields with type conversion and null safety
                $extractedRules[$ruleUuid] = [
                    'uuid' => $ruleUuid,
                    'description' => (string)($ruleModel->description ?? ''),
                    'source' => (string)($ruleModel->source ?? ''),
                    'destination' => (string)($ruleModel->destination ?? ''),
                    'port' => (string)($ruleModel->port ?? ''),
                    'protocol' => (string)($ruleModel->protocol ?? ''),
                    'action' => (string)($ruleModel->action ?? ''),
                    'log' => (string)($ruleModel->log ?? '0'),
                    'enabled' => (string)($ruleModel->enabled ?? '1'),
                    'priority' => (string)($ruleModel->priority ?? '1000'),
                    'category' => (string)($ruleModel->category ?? 'general'),
                ];
            }

        } catch (\Exception $e) {
            throw new \RuntimeException(
                'Failed to extract security rules data: ' . $e->getMessage()
            );
        }

        return $extractedRules;
    }

    /**
     * Get validation engine instance for external access
     *
     * Provides access to the validation engine for advanced use cases
     * such as custom validation scenarios, testing, or integration
     * with external validation systems.
     *
     * @return ValidationEngine The validation engine instance
     */
    public function getValidationEngine(): ValidationEngine
    {
        return $this->validationEngine;
    }

    /**
     * Register custom validator with the validation engine
     *
     * Allows registration of additional validators for specialized
     * validation requirements or custom business rules that may
     * be specific to particular deployments or use cases.
     *
     * @param string $name Unique validator name for identification
     * @param \OPNsense\ValidationCore\Validators\AbstractValidator $validator Validator instance
     * @param array $scopes Optional list of scopes to associate with validator
     *
     * @throws \InvalidArgumentException When validator name already exists
     * @throws \TypeError When validator is not of correct type
     *
     * @example
     * // Register custom compliance validator
     * $complianceValidator = new ComplianceValidator();
     * $model->registerCustomValidator('compliance', $complianceValidator, ['security', 'audit']);
     */
    public function registerCustomValidator(string $name, $validator, array $scopes = []): void
    {
        $this->validationEngine->registerValidator($name, $validator, $scopes);
    }

    /**
     * Validate specific configuration section with custom parameters
     *
     * Provides fine-grained validation control for specific configuration
     * sections or custom validation scenarios. Useful for real-time
     * validation in user interfaces or partial configuration updates.
     *
     * @param string $section Configuration section to validate
     * @param array $customData Optional custom data to validate
     * @param bool $fullValidation Whether to perform full validation
     *
     * @return \OPNsense\Base\Messages\MessageCollection Validation results
     *
     * @example
     * // Validate only network configuration with custom data
     * $networkConfig = ['general' => ['homenet' => '192.168.1.0/24,10.0.0.0/8']];
     * $messages = $model->validateSection('network', $networkConfig);
     */
    public function validateSection(string $section, array $customData = [], bool $fullValidation = false)
    {
        $dataToValidate = empty($customData) ? $this->extractConfigurationData() : $customData;
        
        return $this->validationEngine->validate($dataToValidate, $fullValidation, $section);
    }

    /**
     * Get validation statistics for performance monitoring
     *
     * @return array Validation execution statistics
     */
    public function getValidationStatistics(): array
    {
        return $this->validationEngine->getExecutionStatistics();
    }

    /**
     * Validate configuration before serialization
     *
     * Override to ensure validation is performed before configuration
     * is written to the system.
     *
     * @param bool $validateFullModel Whether to validate full model
     * @param string $scope Validation scope
     * @return bool True if validation passed
     */
    public function validateBeforeSave(bool $validateFullModel = true, string $scope = 'all'): bool
    {
        $messages = $this->performValidation($validateFullModel, $scope);
        
        if ($messages->hasErrors()) {
            // Log validation errors for debugging
            foreach ($messages as $message) {
                error_log("Validation error: " . $message->getMessage() . " (Field: " . $message->getField() . ")");
            }
            return false;
        }
        
        return true;
    }
}