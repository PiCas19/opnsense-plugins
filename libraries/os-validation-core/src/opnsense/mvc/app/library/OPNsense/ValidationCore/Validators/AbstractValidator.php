<?php

/*
 * Copyright (C) 2024 OPNsense Validation Core Library
 * All rights reserved.
 */

namespace OPNsense\ValidationCore\Validators;

use OPNsense\Base\Messages\Message;
use OPNsense\Base\Messages\MessageCollection;

/**
 * Abstract Validator Base Class
 *
 * Provides common validation infrastructure and pattern for all OPNsense
 * validation components. Implements the Template Method pattern to ensure
 * consistent validation behavior while allowing specialized validators to
 * focus on their domain-specific logic.
 *
 * This base class establishes the foundation for the validation framework,
 * providing common utilities, error handling, and execution patterns that
 * all concrete validators inherit. It promotes code reuse and ensures
 * consistent behavior across the validation system.
 *
 * Key Features:
 * - Template method pattern for consistent validation workflow
 * - Common error handling and message management utilities
 * - Field change detection for optimized incremental validation
 * - Safe data access methods with null checking and type conversion
 * - Extensible validation state management for complex scenarios
 *
 * @package OPNsense\ValidationCore\Validators
 * @author Pierpaolo Casati
 * @version 1.0
 */
abstract class AbstractValidator
{
    /**
     * Collection of validation messages generated during execution
     *
     * @var MessageCollection Validation error and warning messages
     */
    protected $messages;

    /**
     * Configuration data being validated
     *
     * @var array Configuration structure for validation
     */
    protected $data;

    /**
     * Flag indicating whether to validate entire model or only changed fields
     *
     * @var bool Full model validation mode
     */
    protected $validateFullModel;

    /**
     * Validation execution context and metadata
     *
     * @var array Context information for validation execution
     */
    protected $validationContext;

    /**
     * Initialize validator with empty message collection and context
     */
    public function __construct()
    {
        $this->messages = new MessageCollection();
        $this->validationContext = [];
    }

    /**
     * Main validation entry point implementing Template Method pattern
     *
     * Orchestrates the validation process by setting up the execution context,
     * calling the specialized validation logic, and returning the results.
     * This method provides the consistent framework while allowing concrete
     * validators to implement their specific validation logic.
     *
     * @param array $data Configuration data to validate
     * @param bool $validateFullModel Whether to perform full model validation
     * @return MessageCollection Collection of validation messages
     *
     * @throws \InvalidArgumentException When data format is invalid
     * @throws \RuntimeException When validation execution fails
     */
    public function validate(array $data, bool $validateFullModel = false): MessageCollection
    {
        // Initialize validation state
        $this->data = $data;
        $this->validateFullModel = $validateFullModel;
        $this->messages = new MessageCollection();
        $this->validationContext = [
            'start_time' => microtime(true),
            'validator_name' => get_class($this),
            'full_model' => $validateFullModel
        ];

        try {
            // Execute specialized validation logic
            $this->performValidation();

            // Update execution context
            $this->validationContext['end_time'] = microtime(true);
            $this->validationContext['execution_time'] = 
                $this->validationContext['end_time'] - $this->validationContext['start_time'];

        } catch (\Exception $e) {
            $this->addError(
                "Validation execution failed: " . $e->getMessage(),
                "validator.execution_error"
            );
        }

        return $this->messages;
    }

    /**
     * Abstract method that concrete validators must implement
     *
     * This method contains the core validation logic specific to each
     * validator implementation. Concrete validators should implement
     * their domain-specific validation rules within this method.
     *
     * @throws \Exception When validation logic encounters critical errors
     */
    abstract protected function performValidation(): void;

    /**
     * Add validation error message with field path mapping
     *
     * Provides a convenient method for validators to report errors with
     * proper field path mapping for UI feedback. The field path enables
     * precise error highlighting in user interfaces.
     *
     * @param string $message Human-readable error message
     * @param string $fieldPath Dot-notation path to the problematic field
     */
    protected function addError(string $message, string $fieldPath): void
    {
        $this->messages->appendMessage(new Message($message, $fieldPath));
    }

    /**
     * Add validation warning message
     *
     * Warnings indicate potential issues that don't prevent configuration
     * from being applied but may cause problems or suboptimal behavior.
     *
     * @param string $message Human-readable warning message
     * @param string $fieldPath Dot-notation path to the field
     */
    protected function addWarning(string $message, string $fieldPath): void
    {
        // OPNsense framework doesn't distinguish warnings from errors in Message class
        // This could be extended with custom message types if needed
        $this->messages->appendMessage(new Message("Warning: " . $message, $fieldPath));
    }

    /**
     * Check if field should be validated based on change detection
     *
     * Implements intelligent validation optimization by checking whether
     * a field has changed since the last validation. This enables efficient
     * incremental validation for large configuration structures.
     *
     * @param string $fieldPath Dot-notation path to field
     * @return bool True if field should be validated
     */
    protected function shouldValidateField(string $fieldPath): bool
    {
        // In full model validation, validate all fields
        if ($this->validateFullModel) {
            return true;
        }

        // Check if field change information is available
        $changeTrackingPath = str_replace('.', '.', $fieldPath) . '_changed';
        if ($this->hasFieldValue($changeTrackingPath)) {
            return (bool)$this->getFieldValue($changeTrackingPath, false);
        }

        // Default to validation if change tracking unavailable
        return true;
    }

    /**
     * Safely retrieve field value with null checking and type conversion
     *
     * Provides safe access to configuration data with support for nested
     * paths, default values, and type conversion. This method handles
     * missing fields gracefully and prevents validation errors from
     * malformed configuration data.
     *
     * @param string $path Dot-notation path to field (e.g., "general.enabled")
     * @param mixed $default Default value if field not found
     * @return mixed Field value or default
     */
    protected function getFieldValue(string $path, $default = '')
    {
        $keys = explode('.', $path);
        $value = $this->data;

        foreach ($keys as $key) {
            if (!is_array($value) || !isset($value[$key])) {
                return $default;
            }
            $value = $value[$key];
        }

        return $value;
    }

    /**
     * Check if field exists in configuration data
     *
     * @param string $path Dot-notation path to field
     * @return bool True if field exists
     */
    protected function hasFieldValue(string $path): bool
    {
        $keys = explode('.', $path);
        $value = $this->data;

        foreach ($keys as $key) {
            if (!is_array($value) || !isset($value[$key])) {
                return false;
            }
            $value = $value[$key];
        }

        return true;
    }

    /**
     * Get field value as string with null safety
     *
     * @param string $path Dot-notation path to field
     * @param string $default Default value
     * @return string Field value as string
     */
    protected function getStringValue(string $path, string $default = ''): string
    {
        return (string)$this->getFieldValue($path, $default);
    }

    /**
     * Get field value as integer with validation
     *
     * @param string $path Dot-notation path to field
     * @param int $default Default value
     * @return int Field value as integer
     */
    protected function getIntValue(string $path, int $default = 0): int
    {
        $value = $this->getFieldValue($path, $default);
        return is_numeric($value) ? (int)$value : $default;
    }

    /**
     * Get field value as boolean with flexible conversion
     *
     * Handles various boolean representations commonly used in OPNsense
     * configuration, including "1"/"0", "true"/"false", "yes"/"no".
     *
     * @param string $path Dot-notation path to field
     * @param bool $default Default value
     * @return bool Field value as boolean
     */
    protected function getBoolValue(string $path, bool $default = false): bool
    {
        $value = strtolower((string)$this->getFieldValue($path, $default));
        
        return in_array($value, ['1', 'true', 'yes', 'on', 'enabled'], true);
    }

    /**
     * Get array of values from comma-separated string
     *
     * Common utility for processing configuration fields that contain
     * comma-separated lists such as network interfaces or IP addresses.
     *
     * @param string $path Dot-notation path to field
     * @param array $default Default array value
     * @return array Array of trimmed values
     */
    protected function getArrayValue(string $path, array $default = []): array
    {
        $value = $this->getStringValue($path);
        
        if (empty($value)) {
            return $default;
        }

        return array_map('trim', explode(',', $value));
    }

    /**
     * Validate that a value is not empty
     *
     * @param mixed $value Value to check
     * @return bool True if value is not empty
     */
    protected function isNotEmpty($value): bool
    {
        if (is_string($value)) {
            return trim($value) !== '';
        }
        
        return !empty($value);
    }

    /**
     * Get validation execution context
     *
     * @return array Validation context information
     */
    protected function getValidationContext(): array
    {
        return $this->validationContext;
    }

    /**
     * Set validation context information
     *
     * @param string $key Context key
     * @param mixed $value Context value
     */
    protected function setValidationContext(string $key, $value): void
    {
        $this->validationContext[$key] = $value;
    }
}